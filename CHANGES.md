# Filtering and security-test update

## What's new

- An explicit local/remote IPv4 host pair and TCP service port are now required on each device command line. Wrong host addresses, wrong direction and other ports are dropped. Requests and replies are allowed; empty selected TCP segments remain protected.
- Portable receive-association handling is shared between the device and security tests. A bounded cache rejects recent replays immediately; consumed nonce records and strictly ordered authenticated control counters continue to prevent reuse after cache eviction.
- Pending-frame/record expiration uses monotonic time.
- Device statistics distinguish policy drops, replay, unmatched expiration, record expiration, bad tags and queue capacity drops. Print counters with SIGUSR1 or normal shutdown.
- C tests cover policy selection, replay, tampering, wrong-nonce GCM verification, packet loss/reordering, queue bounds, expiration and old-replay behavior after cache eviction.
- A Linux integration harness injects replay, tag corruption and deterministic loss through a test-only middle relay. It checks files in both directions, hashes, actual attack counts and device rejection counters. A normal case also checks that a listening unselected service cannot be reached.
- README commands and the test guide explain the new CLI and expected results. The old design proposal is explicitly marked historical.

## CLI change

Append `REMOTE_HOST_IP SERVICE_PORT` to each previous device command:

```text
Device1: ... 10.0.1.1 10.0.3.2 8080
Device2: ... 10.0.3.2 10.0.1.1 8080
```

There is deliberately no default allowing all hosts/ports. Existing commands without these two arguments now show usage instead of opening an overly broad policy.

## Unchanged

The device implementation is C. The protected data format remains `[IP][TCP][ciphertext][16-byte tag]`, with no UDP wrapper, custom header or nonce trailer. DH/TLS authentication, separate direction keys and the authenticated nonce-control stream remain the existing architecture. Python is only a test/development tool, not a dependency of the compiled device executable.

## Verification status

The portable C tests and attack-helper unit tests can be run with `make test`. Complete namespace/AF_PACKET tests require `sudo make integration-test` on Linux. Do not infer a passing Linux run merely from the included test scripts; inspect the VM-generated `summary.json` and per-case logs.
