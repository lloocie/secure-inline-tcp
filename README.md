# Secure inline TCP channel in C

> **Updated filtering and security tests:** both device commands now require the remote host IP and an allowed TCP service port. For the demo, allow only `10.0.1.1 ↔ 10.0.3.2` on port `8080`. Other transit traffic is dropped. Run `make test` for portable checks and `sudo make integration-test` for the complete Linux attack harness. See [the test guide](tests/README.md).

New commented modules: `src/policy.c` implements host-pair/port selection; `src/pending.c` implements bounded receive associations and replay rejection. Both modules are used by the executable and its C security tests. [CHANGES.md](CHANGES.md) lists the update and CLI differences.

The source, unit tests, setup scripts, Makefile and Dockerfile contain explanatory comments. Start with `src/main.c` for the device/session workflow, `src/packet.c` for packet layout and AES-GCM, and `src/packet.h` for the shared interfaces. Script comments explain the network and certificate setup. Comments describe the existing prototype; they do not change its behavior. `docs/design.md` is the earlier design proposal and differs from this implementation in topology, AAD and control-record handling; use this README and the commented source for the executable behavior.

A Linux teaching prototype for `PC1 → Device1 → Device2 → PC2`. Only TCP/IPv4 payload bytes are encrypted. The middle-link format is:

```text
[Ethernet][original IPv4 header][original TCP header][AES-GCM ciphertext][16-byte tag]
```

There is no UDP encapsulation, outer IP packet, or custom header on protected packets. Original connection fields remain visible. IPv4 length and IP/TCP checksums necessarily change when the tag is added; they are restored on decryption. Sequence and ACK numbers stay in plaintext byte space. The program behaves as a transparent packet transformer and preserves TTL rather than implementing ordinary IP router hop semantics.

## Requirements and build

Use a disposable Linux VM with root privileges, GCC/Clang, Make, OpenSSL 3 development headers, iproute2, ethtool and tcpdump. Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install build-essential libssl-dev openssl iproute2 ethtool tcpdump python3
make
make test
bash scripts/certificates.sh
sudo bash scripts/lab.sh up
```

The scripts reserve namespace names `pc1`, `dev1`, `dev2`, `pc2`; use a fresh lab. Certificate generation deliberately refuses to overwrite an existing `certs` directory. Keys are private lab credentials, valid for 30 days. Do not commit or share them.

macOS cannot run AF_PACKET or Linux namespaces natively. Use a Linux VM; the Dockerfile can build and run unit tests, but network experiments require a suitably privileged Linux environment. Docker Desktop is not a substitute for verifying the complete namespace lab.

## Run the devices

Run these from the project directory in separate terminals. Start Device2 first; it waits for Device1. Both print an authenticated-session-ready message before data processing starts.

```sh
sudo ip netns exec dev2 ./inline-secure server d2-pc2 d2-d1 10.0.2.2 certs/dev2.crt certs/dev2.key certs/ca.crt dev1 02:00:00:00:03:02 02:00:00:00:02:01 10.0.3.2 10.0.1.1 8080
```

```sh
sudo ip netns exec dev1 ./inline-secure client d1-pc1 d1-d2 10.0.2.2 certs/dev1.crt certs/dev1.key certs/ca.crt dev2 02:00:00:00:01:01 02:00:00:00:02:02 10.0.1.1 10.0.3.2 8080
```

Arguments are role, host-facing interface, peer-facing interface, control IP, certificate, private key, trusted CA, expected peer DNS identity, host destination MAC, peer destination MAC, local host IPv4 address, remote host IPv4 address, and allowed TCP service port. Configure the same host pair and port on both devices, swapping local/remote addresses. MAC addresses match the lab script. The control TCP port is 9443 and is separate from the allowed host service port.

## Follow each project step

1. **Build the network.** `scripts/lab.sh` creates four namespaces and three veth pairs with the original 10.0.1/2/3 subnets. Hosts use the adjacent device as gateway. Kernel forwarding stays disabled, preventing plaintext bypass and preventing the kernel from interpreting transformed TCP segments. ARP and the device-local control socket still work normally.
2. **Create ordinary TCP traffic.** Host applications use normal sockets. Selected traffic is untagged TCP/IPv4 with both configured host addresses in the correct ingress direction and the allowed service port as either source or destination. This includes empty SYN/ACK/FIN/RST packets. Incorrect host addresses, wrong ports and other transit traffic are dropped; there is no plaintext fallback. The filter is an address/port policy, not an application-aware or stateful TCP firewall.
3. **Intercept.** `src/main.c` binds AF_PACKET sockets to both interfaces, ignores outgoing copies and rejects malformed frames. `src/packet.c` respects IPv4 IHL and TCP data offset, including options, and ignores Ethernet padding.
4. **Establish keys.** Devices use mutually authenticated TLS 1.3, restricted to finite-field Diffie–Hellman `ffdhe2048`. OpenSSL handles DH group/public-value validation, transcript signatures and Finished key confirmation. Both devices verify the CA and expected peer identity. No manually implemented cryptography is used. TLS's HKDF-SHA-384 schedule and the exporter derive fresh session material, with separate 256-bit AES keys and 32-bit nonce prefixes for each direction. This uses HKDF-SHA-384, rather than the earlier notes' HKDF-SHA-256; the requested DH/AES-GCM requirements do not prescribe a KDF hash.
5. **Allocate unique nonces.** Each new encryption increments a 64-bit direction counter. Nonce = 32-bit session direction prefix + big-endian counter. Retransmitted host packets are freshly encrypted with fresh counters. Counter exhaustion terminates the process. Restart both devices to establish fresh session keys; never reuse saved keys/counters.
6. **Encrypt the payload.** AES-256-GCM encrypts only payload bytes, including zero bytes for pure ACK/SYN/FIN/RST packets. AAD binds the IPv4/TCP headers with TTL and both checksum fields zeroed. IPv4 total length already includes the appended tag. Header structure, addresses, ports, sequence/ACK, flags, window and options remain intact.
7. **Handle length.** Add exactly 16 bytes, update IPv4 total length, recalculate both checksums. Host-facing MTU is 1484 and middle-link MTU is 1500. Oversized selected frames are dropped. Tags disappear before endpoint TCP processing, so sequence translation is unnecessary on this private middle link.
8. **Forward directly.** Send the transformed Ethernet frame to the peer MAC. The original host IP addresses remain. No host data packet is sent inside the control stream.
9. **Receive and find the nonce.** A separate authenticated TLS control stream sends a fixed 44-byte record: nonce (12 bytes) + SHA-256 fingerprint of canonical protected IP/TCP headers and ciphertext/tag (32 bytes). This is control metadata, not an on-packet custom header. Up to 256 pending records and 256 frames tolerate either arrival order and expire after 10 monotonic seconds. Control records arrive in strictly increasing counter order; data frames can arrive out of order. A bounded cache immediately rejects recently accepted duplicates, including duplicates queued before their first copy was accepted. Older duplicates still lack a usable nonce record. This implementation buffers both arrival orders instead of requiring an acknowledgement per frame.
10. **Authenticate and decrypt.** Match the fingerprint, verify GCM using the direction key/nonce and AAD, and only then copy plaintext into the packet. Remove the tag, decrease IPv4 length, recompute checksums and consume the record. Failed authentication never forwards plaintext. A repeated frame has no reusable record. New host retransmissions use new records.
11. **Deliver.** Emit the restored packet with the destination host's Ethernet MAC. The reverse direction runs the same logic concurrently in the event loop.

## Try a transfer

With both devices running, start a server:

```sh
sudo ip netns exec pc2 python3 -m http.server 8080 --bind 10.0.3.2
```

From another terminal, use Python's normal TCP client to fetch it:

```sh
sudo ip netns exec pc1 python3 -c 'import urllib.request; print(urllib.request.urlopen("http://10.0.3.2:8080", timeout=20).status)'
```

Expected result: HTTP status 200. Capture the protected path:

```sh
sudo ip netns exec dev1 tcpdump -ni d1-d2 -s0 -XX 'ip proto 6 and (host 10.0.1.1 or host 10.0.3.2)'
```

The host flow still shows TCP and the original host addresses. Its payload is ciphertext followed by a tag, including tagged empty TCP segments. Capture `d1-pc1` or `d2-pc2` to compare plaintext. Control traffic is device-to-device TCP/9443, separate from host packets. Wireshark/tcpdump can interpret protected segments as TCP inconsistencies because tag bytes do not belong to the endpoints' sequence space; the device software removes them first.

## Verification and limits

`make test` runs the original packet tests and the new security tests. The security tests exercise the actual host-pair/port filter and receive-association code: source/destination spoofing, disallowed ports, reply direction, empty ACK selection, replay before/after acceptance, tampering, GCM rejection, loss/reordering, expiration and queue saturation. These checks run without root or network setup.

`sudo make integration-test` builds the device and creates a temporary Linux lab with an additional transparent test relay. It runs four independent cases: normal transfer and blocked-port check, replay, tag tampering, and deterministic packet loss. Each case must transfer a 64 KiB random request and its reversed reply correctly, and attack cases must report the expected injected action and device rejection/expiration counters. Results and hashes are written to a new `test-results/run-*/` directory. A failure returns a nonzero status; printing hashes alone is not considered a pass.

The integration harness refuses to start if any of its namespace names already exist. Stop and clean up your manual lab first. It creates fresh temporary test certificates and automatically removes only its own lab namespaces/processes. It does not use JavaScript, Scapy, or globally kill unrelated processes. The device remains C; Python is used only for test applications, attack injection, and orchestration.

With this fingerprint-indexed protocol, changing a tag/ciphertext usually prevents nonce lookup, so the raw tampered frame expires as `unmatched` before GCM is attempted. This is a valid rejection, not a `bad_tag` event. Unit tests separately force a matching record with the wrong nonce to check GCM rejection itself. The Linux harness is provided for verification in your VM; its presence is not a claim that it has already passed there. Sustained random loss, very high load, multiple simultaneous flows, and session restart remain further validation work.

Device counters print on normal shutdown, or on demand via `sudo kill -USR1 DEVICE_PID`: `enc`, `dec`, `policy`, `replay`, `unmatched`, `expired_records`, `bad_tag`, and `full`. Use the actual PID of the specific device process, not a global kill command.

This is a bounded, fail-closed prototype: no reconnection/rekey daemon, VLAN/IPv6 support, IP reassembly, transparent forwarding of unselected protocols, or production resource-hardening. Matching IPv4 fragments are dropped rather than leaked. Supported headers/options are authenticated but advanced TCP mechanisms that rewrite packets between devices are outside the direct-link assumption. The middle link must not contain a normal TCP proxy/firewall that treats tags as TCP stream bytes. Checksum offloads are disabled where supported by the setup script; inspect tool warnings/features if captures behave unexpectedly. Control timeout or disconnect terminates the device; kernel forwarding remains off. Bounded queues may drop traffic under load; host TCP retransmission provides recovery, but sustained overload needs capacity tuning.

The TLS control channel is a necessary explicit protocol choice for nonce coordination with the required header-free protected format. If your assignment also forbids a separate control connection or requires a hand-written DH handshake, this implementation needs a different agreed protocol design.

## Cleanup

Stop test processes, then run:

```sh
sudo bash scripts/lab.sh down
make clean
```

Cleanup terminates processes in these four lab namespaces before deleting them. It leaves generated certificates on disk.

OpenSSL API references: [DH group configuration](https://docs.openssl.org/3.0/man3/SSL_CTX_set1_groups/), [key exporter](https://docs.openssl.org/3.0/man3/SSL_export_keying_material/).
