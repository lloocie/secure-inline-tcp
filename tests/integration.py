"""Run with sudo make integration-test inside a disposable Linux VM.

Creates a temporary fifth namespace as a transparent test relay. Original
application packets still use the exact required tag-only wire format.
No external Python packages are needed. Only processes started here are killed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tests" / "network_helpers.py"
NAMES = ("pc1", "dev1", "dev2", "pc2", "inline-test")


def run(*arguments, **options):
    return subprocess.run([str(value) for value in arguments], check=True, **options)


def wait_for(predicate, processes, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("process exited while waiting for " + description)
        time.sleep(0.1)
    raise TimeoutError(description)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def execute_case(mode, results, credentials):
    folder = results / mode
    folder.mkdir()
    processes, handles = [], []

    def start(namespace, label, *arguments):
        handle = (folder / (label + ".log")).open("w", encoding="utf-8")
        handles.append(handle)
        process = subprocess.Popen(["ip", "netns", "exec", namespace, *map(str, arguments)],
                                   stdout=handle, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    try:
        relay_ready, relay_result = folder / "relay.ready", folder / "relay.json"
        relay = start("inline-test", "relay", sys.executable, HELPER, "relay", "--mode", mode,
                      "--ready", relay_ready, "--result", relay_result)
        wait_for(relay_ready.exists, [relay], "relay ready")
        certificate = lambda name, suffix: credentials / (name + suffix)
        device2 = start("dev2", "dev2", ROOT / "inline-secure", "server", "d2-pc2", "d2-d1", "10.0.2.2",
                        certificate("dev2", ".crt"), certificate("dev2", ".key"), credentials / "ca.crt",
                        "dev1", "02:00:00:00:03:02", "02:00:00:00:02:01", "10.0.3.2", "10.0.1.1", "8080")
        # Wait for a listening socket, not a fixed sleep or an extra TLS probe.
        def listening():
            output = subprocess.check_output(["ip", "netns", "exec", "dev2", "ss", "-ltnH"], text=True)
            return "10.0.2.2:9443" in output
        wait_for(listening, [device2, relay], "Device2 listener")
        device1 = start("dev1", "dev1", ROOT / "inline-secure", "client", "d1-pc1", "d1-d2", "10.0.2.2",
                        certificate("dev1", ".crt"), certificate("dev1", ".key"), credentials / "ca.crt",
                        "dev2", "02:00:00:00:01:01", "02:00:00:00:02:02", "10.0.1.1", "10.0.3.2", "8080")
        devices = [device1, device2, relay]
        def sessions_ready():
            return all("Authenticated DH session ready" in (folder / (name + ".log")).read_text()
                       for name in ("dev1", "dev2"))
        wait_for(sessions_ready, devices, "mutually authenticated DH sessions")
        source = folder / "sent.bin"
        source.write_bytes(os.urandom(65536))
        server_ready = folder / "server.ready"
        server = start("pc2", "server", sys.executable, HELPER, "server", "--ready", server_ready,
                       "--output", folder / "received.bin")
        wait_for(server_ready.exists, [server, *devices], "TCP server ready")
        with (folder / "client.log").open("w") as handle:
            run("ip", "netns", "exec", "pc1", sys.executable, HELPER, "client", "--input", source,
                "--output", folder / "reply.bin", stdout=handle, stderr=subprocess.STDOUT, timeout=65)
        if server.wait(timeout=10) != 0:
            raise RuntimeError("TCP server failed")
        original, received = source.read_bytes(), (folder / "received.bin").read_bytes()
        if original != received or (folder / "reply.bin").read_bytes() != original[::-1]:
            raise RuntimeError("end-to-end file mismatch")

        if mode == "pass":
            # A real listening server on a disallowed port must be unreachable.
            # Waiting for readiness excludes 'no server was listening' as a pass.
            blocked_ready = folder / "blocked.ready"
            blocked = start("pc2", "blocked", sys.executable, HELPER, "server", "--port", "8081",
                            "--ready", blocked_ready, "--output", folder / "blocked.bin")
            wait_for(blocked_ready.exists, [blocked, *devices], "disallowed-port listener")
            probe = "import socket; socket.create_connection(('10.0.3.2',8081),timeout=2)"
            result = subprocess.run(["ip", "netns", "exec", "pc1", sys.executable, "-c", probe],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or "TimeoutError" not in result.stderr or blocked.poll() is not None:
                raise RuntimeError("disallowed port did not time out against a live listener")
            stop(blocked)

        # Tampered frames have a mismatching fingerprint and expire unmatched.
        # Lost frames leave their authentic records behind until expiration.
        if mode in ("tamper", "loss"):
            deadline = time.monotonic() + 11.5
            while time.monotonic() < deadline:
                if any(process.poll() is not None for process in devices):
                    raise RuntimeError("device/relay exited during expiration test")
                time.sleep(0.1)
        stats = {}
        for name, device in (("dev1", device1), ("dev2", device2)):
            log = folder / (name + ".log")
            before = log.read_text().count("stats ")
            device.send_signal(signal.SIGUSR1)
            wait_for(lambda: log.read_text().count("stats ") > before, devices, "device statistics")
            line = [line for line in log.read_text().splitlines() if line.startswith("stats ")][-1]
            stats[name] = {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", line)}
        if mode == "pass" and stats["dev1"]["policy"] == 0:
            raise RuntimeError("disallowed port did not exercise policy rejection")
        if mode == "replay" and stats["dev2"]["replay"] == 0:
            raise RuntimeError("replay did not exercise device replay rejection")
        if mode == "tamper" and stats["dev2"]["unmatched"] == 0:
            raise RuntimeError("tampering did not exercise unmatched-frame rejection")
        if mode == "loss" and stats["dev2"]["expired_records"] == 0:
            raise RuntimeError("packet loss did not leave expired nonce records")
        stop(relay)
        attack = json.loads(relay_result.read_text())
        expected_actions = {"pass": 0, "replay": 1, "tamper": 1, "loss": 3}[mode]
        if attack["actions"] != expected_actions:
            raise RuntimeError("requested attack did not actually happen")
        result = {"mode": mode, "status": "PASS", "request_sha256": hashlib.sha256(original).hexdigest(),
                  "received_sha256": hashlib.sha256(received).hexdigest(), "relay": attack, "devices": stats}
        (folder / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print("PASS: " + mode + " (matching files in both directions; expected rejection counters)", flush=True)
        return result
    finally:
        for process in reversed(processes):
            stop(process)
        for handle in handles:
            handle.close()


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Run this test as root in your Linux VM: sudo make integration-test")
    for command in ("ip", "ethtool", "openssl", "ss", "bash"):
        if not shutil.which(command):
            raise SystemExit("Missing dependency: " + command)
    existing = {line.split()[0] for line in subprocess.check_output(["ip", "netns", "list"], text=True).splitlines()}
    if existing.intersection(NAMES):
        raise SystemExit("Existing lab namespaces found. Stop your manual lab and run its cleanup first; nothing changed.")
    results_root = ROOT / "test-results"
    results_root.mkdir(exist_ok=True)
    results = Path(tempfile.mkdtemp(prefix="run-", dir=results_root))
    print("Logs and results: " + str(results), flush=True)
    # Fresh temporary identities avoid depending on the manual lab's secrets
    # or certificate expiry. The generator creates a certs subdirectory.
    run("bash", ROOT / "scripts" / "certificates.sh", cwd=results,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        run("bash", ROOT / "scripts" / "lab.sh", "up")
        run("ip", "netns", "add", "inline-test")
        # Insert a transparent attack relay in the middle link, preserving
        # all four original namespaces, host IPs and device command arguments.
        run("ip", "-n", "dev2", "addr", "flush", "dev", "d2-d1")
        run("ip", "-n", "dev2", "link", "set", "d2-d1", "netns", "inline-test")
        run("ip", "-n", "inline-test", "link", "set", "d2-d1", "name", "left")
        run("ip", "link", "add", "right", "netns", "inline-test", "type", "veth", "peer", "name", "d2-d1", "netns", "dev2")
        run("ip", "-n", "dev2", "addr", "add", "10.0.2.2/24", "dev", "d2-d1")
        run("ip", "-n", "dev2", "link", "set", "d2-d1", "address", "02:00:00:00:02:02", "mtu", "1500", "up")
        for namespace, interface in (("inline-test", "left"), ("inline-test", "right"), ("dev2", "d2-d1")):
            run("ip", "-n", namespace, "link", "set", interface, "up")
            # Some veth drivers have fixed RX features. Do not let those mask
            # requests to disable segmentation/aggregation and TX offloading.
            for feature in ("gro", "gso", "tso", "tx"):
                outcome = subprocess.run(["ip", "netns", "exec", namespace, "ethtool", "-K", interface,
                                          feature, "off"], capture_output=True, text=True)
                if outcome.returncode:
                    print("Offload warning: " + namespace + "/" + interface + " " + feature + ": " + outcome.stderr.strip(), flush=True)
        run("ip", "netns", "exec", "inline-test", "sysctl", "-qw", "net.ipv4.ip_forward=0")
        summary = [execute_case(mode, results, results / "certs") for mode in ("pass", "replay", "tamper", "loss")]
        (results / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print("ALL FOUR LINUX INTEGRATION CASES PASSED", flush=True)
    finally:
        # The harness refused preexisting namespaces, so these names belong to
        # this run. Never use a global pkill or terminate unrelated tcpdump jobs.
        for name in reversed(NAMES):
            subprocess.run(["ip", "netns", "del", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
