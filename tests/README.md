# 🔬 Verify the secure inline channel

**Two layers of evidence:** portable C tests check precise rejection behavior; a Linux attack lab checks the complete device path and end-to-end file contents.

## 1. Build and run portable tests

From the project directory in your Linux VM:

```bash
make
make test
```

The new test reports:

```text
PASS: host-pair/port policy, replay, tampering, GCM rejection, loss/reordering, expiration and capacity
```

| Test | What must happen |
|---|---|
| Correct host pair + port | Accept in the correct direction |
| Wrong source, destination, port or direction | Reject |
| Reply traffic + empty ACK | Apply the same explicit policy |
| Invalid port argument | Reject; never silently truncate |
| Replay queued before record arrival | Deliver exactly one authenticated copy |
| Replay after acceptance | Reject immediately |
| Modified ciphertext, tag or sequence field | No plaintext output; expire unmatched |
| Matching lookup record with incorrect nonce | GCM verification fails |
| Lost packet + reordered later packets | Deliver valid later packets using their own records |
| Full queue / missing or expired association | Drop safely without releasing plaintext |

The tests use the real `policy.c` and `pending.c` modules linked into the device. They are not separate copies of the device's logic. The test-only fixed key/nonce fixtures must never be copied into live session configuration.

## 2. Run the Linux integration harness

Use a disposable Linux VM with root/network-namespace privileges. Install the same dependencies as the main README. No additional Python packages are required.

If your manual lab is still running, stop its applications and devices, then:

```bash
sudo bash scripts/lab.sh down
```

Start the automated tests:

```bash
sudo make integration-test
```

The test creates the standard four namespaces plus `inline-test`, a transparent relay inserted between Device1 and Device2. It leaves the protected packet format unchanged. Control TLS and ARP pass through the relay without deliberate modification.

| Case | Injected behavior | Required evidence |
|---|---|---|
| `pass` | No attack | Exact request/reply contents; a live server on disallowed port 8081 is unreachable |
| `replay` | Duplicate one protected data frame | Correct files; device `replay` count increases |
| `tamper` | Change one protected tag byte and withhold the original | Correct files after retransmission; `unmatched` count increases |
| `loss` | Drop the first three protected application-data frames | Correct files after TCP recovery; missing frames leave `expired_records` |

Each case uses a new device session and a 64 KiB random request. The PC2 application returns the reversed bytes, exercising encryption and decryption in both directions. The harness asserts exact byte equality and writes matching request hashes to JSON. It also checks the relay actually performed the requested attack, so a transfer with no attack is not a passing attack test.

Successful output ends with:

```text
PASS: pass (matching files in both directions; expected rejection counters)
PASS: replay (matching files in both directions; expected rejection counters)
PASS: tamper (matching files in both directions; expected rejection counters)
PASS: loss (matching files in both directions; expected rejection counters)
ALL FOUR LINUX INTEGRATION CASES PASSED
```

Allow a few minutes: tamper/loss cases deliberately wait for ten-second association expiration. A failed assertion or process returns a nonzero status, keeps diagnostic logs, and cleans up the test namespaces. Existing lab namespaces cause a refusal before network changes. If the harness is forcibly killed or your VM crashes, inspect namespace ownership before manual cleanup.

## 3. Inspect evidence

The harness prints its unique result directory, for example `test-results/run-abc123/`. Each case contains:

```text
dev1.log / dev2.log      Session readiness and device counters
relay.json              Number of eligible frames and injected actions
sent.bin                Original request
received.bin            Request received at PC2
reply.bin               Reversed response received at PC1
result.json             PASS result, matching hashes and counters
```

`summary.json` exists only after all four cases pass. Logs/files created under sudo may require sudo to read.

## What rejection means here

The nonce record is authenticated over TLS and contains the protected packet fingerprint. A tampered packet normally cannot find that record; it is held within bounded limits and expires without any plaintext being forwarded. Therefore `unmatched`, rather than `bad_tag`, is expected in the raw tampering test. A separate C test reaches GCM with a wrong nonce and verifies tag-check failure.

Exact recent replays are counted using a bounded accepted-fingerprint cache. Safety does not depend on retaining every fingerprint forever: the corresponding authenticated nonce association is consumed once and cannot be reannounced with an old control counter. Frames that cannot match an association are never delivered.

These tests establish specific prototype behaviors, not production readiness. The deterministic loss case is not a throughput benchmark or a proof of operation under every loss pattern. Wider stress, rekey/restart, random loss and concurrent-flow tests remain useful follow-up work.
