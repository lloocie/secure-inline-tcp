# Secure inline TCP/IPv4 — version 1 design

> Historical proposal, retained for reference. The executable follows the current README and commented source, not every choice below. In particular, it uses certificate-authenticated TLS-managed DH, an explicit two-host/one-service-port policy, canonical protected-length header AAD, and bounded record/frame buffering without per-packet acknowledgements. See `tests/README.md` for current verification commands.

Status: implementation baseline for checklist step 1. These are project design decisions, not a standardized secure transport protocol. The separate control connection is an explicit assumption requiring acceptance by the project requirements owner.

## 1. Topology and interfaces

```text
 namespace pc1       namespace dev1        namespace dev2       namespace pc2
     pc1-eth <------> d1-host  d1-link <--> d2-link  d2-host <------> pc2-eth
  10.10.0.1/24                                                    10.10.0.2/24
                         192.0.2.1/30    192.0.2.2/30
                         control IPs on the device-link interfaces
```

Each arrow is one veth pair. All interfaces initially use MTU 1500, except pc1-eth and pc2-eth, which use MTU 1484. The devices forward Ethernet frames in user space with AF_PACKET; they are neither Linux bridges nor IP routers. Kernel IPv4/IPv6 forwarding is disabled. No kernel bridge connects the interfaces. The host-side device interfaces have no IP addresses. Disable IPv6 and relevant segmentation/aggregation/checksum offloads for this initial lab.

Assign fixed locally administered MAC addresses:

| Interface | MAC address |
|---|---|
| pc1-eth | 02:00:00:00:01:01 |
| d1-host | 02:00:00:00:01:02 |
| d1-link | 02:00:00:00:02:01 |
| d2-link | 02:00:00:00:02:02 |
| d2-host | 02:00:00:00:03:01 |
| pc2-eth | 02:00:00:00:03:02 |

PC1 has a permanent neighbor entry mapping 10.10.0.2 to PC2's MAC; PC2 has the reverse entry. Their connected /24 routes suffice. The two devices have permanent neighbor entries for their control IPs using d1-link/d2-link MACs. No ARP forwarding is required. The AF_PACKET sockets must receive frames addressed to the remote endpoint MAC, using promiscuous membership where necessary. Ethernet source/destination addresses of host data remain unchanged across the inline path. Control frames use the devices' own MACs.

## 2. Traffic policy

PC2 runs a TCP service on port 5000. PC1 initiates connections using ephemeral source ports. Select exactly:

| Direction | Source | Destination | TCP port condition |
|---|---|---|---|
| PC1 → PC2 | 10.10.0.1 | 10.10.0.2 | destination port = 5000 |
| PC2 → PC1 | 10.10.0.2 | 10.10.0.1 | source port = 5000 |

This permits application data in both directions over connections initiated by PC1. Ingress interface and addresses determine direction; do not infer it from TCP flags. Outbound host-side selected packets are always encrypted. Inbound link-side selected packets are always verified and decrypted. Never fall back to plaintext interpretation after a verification failure.

Drop all unselected transit traffic, including other TCP ports, UDP, ICMP, IPv6, ARP, VLAN frames and unknown EtherTypes. Locally addressed control traffic is handled separately: Device1 connects from 192.0.2.1 to Device2 at 192.0.2.2 TCP port 4444. Permit only this connection and its replies on the interdevice interfaces. Do not forward it to hosts or apply the data transformation to it. Restrict local control access using interface/address/port rules. Other local services are outside this lab.

When the secure session is unavailable, drop selected host traffic. TCP will retry. Processing failures never enable kernel forwarding or plaintext bypass. Ignore outgoing packet-socket captures to avoid forwarding loops.

## 3. Empty payloads, fragments and supported headers

Protect every selected TCP segment, including SYN, SYN-ACK, ACK, FIN and RST, even with zero payload. AES-GCM authenticates the header AAD and generates a 16-byte tag for an empty plaintext. The tag is removed before an endpoint receives the segment.

Version 1 supports Ethernet II and IPv4 with IHL = 5 only. Reject IPv4 options. Parse TCP data offset and support ordinary TCP options, including MSS, timestamps, window scaling and SACK; authenticate the exact option bytes. Validate all lengths before reading ports/options. Reject malformed headers, invalid input checksums, invalid TCP data offsets and nonzero reserved TCP bits.

Reject IPv4 packets with MF set or nonzero fragment offset on either side, before traffic selection. No fragmentation or reassembly occurs in the devices. Preserve DF and the IPv4 Identification value. A packet exceeding the configured size limit is dropped with a diagnostic counter. This fixed-MTU lab does not implement general path-MTU discovery or ICMP forwarding.

## 4. Packet layouts and lengths

```text
Host input:      [Ethernet][IPv4: 20][TCP: 20..60][plaintext: P]
Protected link:  [Ethernet][IPv4: 20][TCP: 20..60][ciphertext: P][tag: 16]
Host output:     [Ethernet][IPv4: 20][TCP: 20..60][plaintext: P]
```

There is no outer IP header, UDP encapsulation, nonce field or custom data header. IPv4 Total Length excludes Ethernet headers/padding. Derive plaintext length from the original IPv4 length and TCP header length; never treat Ethernet padding as payload. On receive, subtract the 16-byte tag before deriving original payload length.

Use AES-256-GCM with a 32-byte directional key, 12-byte nonce and full 16-byte tag. Protected IPv4 Total Length is original length + 16. Recompute TCP checksum over the protected TCP header, ciphertext and tag, with the protected pseudoheader length; recompute IPv4 checksum. Decryption reverses these steps and recomputes both checksums. Preserve TCP sequence/acknowledgment numbers, flags, ports, windows and options. The tag consumes no endpoint TCP sequence space because it is removed before delivery.

Original IPv4 length must be at most 1484; protected length must be at most 1500. With a 20-byte TCP header the maximum original payload is 1444 bytes; with options it is smaller. The endpoint MTUs establish the corresponding TCP sizing without rewriting MSS options.

Protected packets are an internal wire representation. Their apparent TCP data length includes the tag, while their sequence numbers describe the original stream. No TCP proxy, NAT or sequence-validating middlebox is supported between devices. AF_PACKET must intercept and restore them before delivery to host TCP stacks.

## 5. Exact GCM additional authenticated data (AAD)

AAD is the following concatenation, with no separators or implicit padding:

```text
ASCII("INLINE-TCP-v1")                  13 bytes
session_id                             32 bytes
direction                              1 byte (0 = D1→D2; 1 = D2→D1)
counter                                8 bytes, unsigned big-endian
canonical_original_ipv4_header          20 bytes
canonical_tcp_header                   TCP data-offset × 4 bytes
```

The session ID is the SHA-256 digest of the canonical signed handshake transcript. Bind the protocol version, device identities, roles, fresh randomness, ephemeral public shares, selected traffic policy, algorithms, tag length, MTUs and AAD format into that transcript. Exact handshake message serialization belongs to step 5 and must be specified before implementing cryptography.

IPv4 canonicalization: retain every original header byte except set DSCP/ECN, TTL and header checksum to zero. Total Length is the **original** value (protected value minus 16 at the receiver). Thus AAD authenticates version/IHL, original length, Identification, flags/fragment offset, protocol and source/destination addresses. Excluded fields may change without GCM detection; the initial transparent lab nevertheless leaves DSCP/ECN and TTL unchanged. No routing TTL decrement occurs.

TCP canonicalization: retain the complete TCP header and options byte-for-byte, except set its checksum to zero. This authenticates both ports, sequence and acknowledgment numbers, data offset, flags, window, urgent pointer and all options. Neither TCP timestamps nor ACK/window fields are normalized: they must remain unchanged for this individual packet. Checksums are excluded because the protected and restored representations require different values. Ethernet headers and padding are not AAD.

Build AAD from a copy; do not zero fields in the forwarded packet. Sender canonicalizes the original header; receiver reconstructs original length in a temporary header before canonicalizing. Never authenticate the protected length on one side and original length on the other.

## 6. Separate control connection and nonce associations

The control TCP connection carries the signed ephemeral-DH handshake and, after key confirmation, authenticated association messages. TCP reliability alone provides no cryptographic authentication. The initial handshake uses trusted peer signing keys; established control messages require separate directional MAC keys and strictly checked sequence numbers. All message types need bounded, unambiguous framing before implementation.

Each direction owns a monotonically increasing unsigned 64-bit encryption counter starting at zero. Construct the nonce as a session-derived directional 4-byte prefix followed by the counter encoded in 8-byte big-endian form. Use distinct directional traffic keys. Allocate a counter exactly once per encryption operation, never reuse it after failure, and use a fresh counter for every TCP retransmission that is encrypted again. Restart always requires fresh session keys. Counter exhaustion stops transmission before wraparound.

For each packet: encrypt; fingerprint SHA-256(ciphertext || tag); announce (session ID, direction, counter, fingerprint); await an authenticated storage acknowledgment; then send the protected frame. The receiver indexes associations by (session ID, direction, fingerprint). The fingerprint is an index, not proof of authenticity. Its lookup must never replace GCM verification.

Initial bounded policy: at most 4096 pending associations per direction, 10-second association lifetime, 2-second announcement acknowledgment timeout, and no buffering of data without an association. On saturation or timeout, drop the host packet and let TCP retransmit with a new counter. An acknowledgment means the association is stored; expiration or control failure can still cause a later packet to be dropped.

Use a 65,536-counter sliding replay bitmap per direction. Reject counters older than the window or already accepted. Advance/mark this window only after successful tag verification, atomically with acceptance; an invalid packet must not consume its association or counter. Expired and evicted associations are never recreated from unauthenticated data. A delayed valid packet outside these bounds is dropped; TCP retransmission recovers. Duplicate control announcements are idempotent only when all association fields match; conflicting reuse of a counter terminates the session.

Control failure immediately invalidates the session and clears pending associations. Reestablishment uses a fresh handshake; no live rekey overlap is supported in version 1. Old packets then lack a valid association and are dropped. Detailed key-usage limits and coordinated rekey are step 9 work, required before calling the complete system finished.

## 7. Security boundary and acceptance checks

The interdevice attacker can observe headers, alter/drop/reorder frames and replay recordings. The design aims to authenticate selected TCP headers and protect payloads, including empty-payload control segments. It does not hide traffic metadata, authenticate mutable excluded fields, prevent denial of service, or protect compromised endpoints/devices. Static neighbors avoid ARP handling in this controlled experiment; they are not a general network deployment solution.

Step 1 is documented when all of the following match this baseline:

- [x] Topology and every interface labeled.
- [x] Addresses, ports and bidirectional selection defined.
- [x] Unselected transit traffic explicitly dropped.
- [x] Empty TCP payloads authenticated with a tag.
- [x] Fragmented IPv4 explicitly unsupported and dropped.
- [x] Separate authenticated control connection assumption recorded.
- [x] Exact AAD byte layout and field treatment defined.
- [x] Mutable/checksum fields normalized explicitly.
- [x] Original, protected and restored layouts documented.

The implementation must demonstrate empty-ACK restoration, TCP-option AAD agreement, 1484→1500 byte growth, rejection of modified authenticated fields, no plaintext bypass, and replay rejection. These are future verification criteria, not tests already performed.

## References

- RFC 5116, AEAD interface, nonce uniqueness and zero-length plaintext: https://www.rfc-editor.org/rfc/rfc5116.html
- RFC 9293, TCP header, options and sequence-space behavior: https://www.rfc-editor.org/rfc/rfc9293.html
