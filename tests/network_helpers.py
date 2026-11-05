"""Linux integration-test helpers; standard library only, no Scapy required.

The relay exists only in the test topology. It forwards ARP and TLS unchanged,
and attacks only protected application-data frames for the selected host pair.
It never learns AES keys or nonce records from the TLS control connection.
"""
import argparse
import hashlib
import json
from pathlib import Path
import select
import signal
import socket
import struct


def protected_data(frame):
    """Return IP-exclusive frame end for eligible frames, otherwise None."""
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    if frame[14] >> 4 != 4 or frame[23] != 6:
        return None
    if frame[26:30] != socket.inet_aton("10.0.1.1") or frame[30:34] != socket.inet_aton("10.0.3.2"):
        return None
    ip_length = (frame[14] & 15) * 4
    total = int.from_bytes(frame[16:18], "big")
    tcp = 14 + ip_length
    if ip_length < 20 or total + 14 > len(frame) or total < ip_length + 20:
        return None
    tcp_length = (frame[tcp + 12] >> 4) * 4
    if tcp_length < 20 or total < ip_length + tcp_length:
        return None
    if int.from_bytes(frame[tcp + 2:tcp + 4], "big") != 8080:
        return None
    # A protected empty segment contains only its 16-byte tag. Leave the TCP
    # handshake/ACKs alone and attack frames with actual ciphertext bytes.
    return 14 + total if total - ip_length - tcp_length > 16 else None


def relay(arguments):
    sockets = []
    for name in ("left", "right"):
        descriptor = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        descriptor.bind((name, 0))
        # See transit MACs without rewriting them. Linux packet_mreq is
        # interface index + membership type + address length + 8-byte address.
        membership = struct.pack("IHH8s", socket.if_nametoindex(name), 1, 0, bytes(8))
        descriptor.setsockopt(263, 1, membership)
        sockets.append(descriptor)
    running = True
    counts = {"eligible": 0, "actions": 0, "forwarded": 0}

    def stop(_number, _context):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    Path(arguments.ready).touch()
    try:
        while running:
            readable, _, _ = select.select(sockets, [], [], 0.2)
            for incoming in readable:
                frame, address = incoming.recvfrom(65536)
                if address[2] == socket.PACKET_OUTGOING:
                    continue
                outgoing = sockets[1 - sockets.index(incoming)]
                end = protected_data(frame) if incoming is sockets[0] else None
                if end:
                    counts["eligible"] += 1
                attack = end and counts["actions"] < (3 if arguments.mode == "loss" else 1)
                if attack and arguments.mode == "loss":
                    counts["actions"] += 1
                    continue
                if attack and arguments.mode == "tamper":
                    changed = bytearray(frame)
                    changed[end - 1] ^= 1  # change a GCM tag byte; withhold original
                    frame = bytes(changed)
                    counts["actions"] += 1
                if attack and arguments.mode == "replay":
                    outgoing.send(frame)
                    counts["actions"] += 1
                outgoing.send(frame)
                counts["forwarded"] += 1
    finally:
        for descriptor in sockets:
            descriptor.close()
        Path(arguments.result).write_text(json.dumps(counts), encoding="utf-8")


def server(arguments):
    # A deliberately ordinary TCP application. The returned bytes differ from
    # the request, so both encryption directions must work for a passing test.
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(60)
        listener.bind(("10.0.3.2", arguments.port))
        listener.listen(1)
        Path(arguments.ready).touch()
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(60)
            data = bytearray()
            while True:
                block = connection.recv(16384)
                if not block:
                    break
                data.extend(block)
                if len(data) > 1024 * 1024:
                    raise RuntimeError("unexpectedly large test request")
            Path(arguments.output).write_bytes(data)
            connection.sendall(bytes(data)[::-1])
        print("received_sha256=" + hashlib.sha256(data).hexdigest(), flush=True)


def client(arguments):
    data = Path(arguments.input).read_bytes()
    with socket.create_connection(("10.0.3.2", arguments.port), timeout=arguments.timeout) as connection:
        connection.settimeout(arguments.timeout)
        connection.sendall(data)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            block = connection.recv(16384)
            if not block:
                break
            response.extend(block)
        Path(arguments.output).write_bytes(response)
    if response != data[::-1]:
        raise RuntimeError("reverse-direction file content mismatch")
    print("reply_sha256=" + hashlib.sha256(response).hexdigest(), flush=True)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    relay_parser = commands.add_parser("relay")
    relay_parser.add_argument("--mode", choices=("pass", "replay", "tamper", "loss"), required=True)
    relay_parser.add_argument("--ready", required=True)
    relay_parser.add_argument("--result", required=True)
    server_parser = commands.add_parser("server")
    server_parser.add_argument("--port", type=int, default=8080)
    server_parser.add_argument("--ready", required=True)
    server_parser.add_argument("--output", required=True)
    client_parser = commands.add_parser("client")
    client_parser.add_argument("--port", type=int, default=8080)
    client_parser.add_argument("--timeout", type=float, default=45)
    client_parser.add_argument("--input", required=True)
    client_parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    {"relay": relay, "server": server, "client": client}[arguments.command](arguments)


if __name__ == "__main__":
    main()
