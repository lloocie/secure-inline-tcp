# Use the system C compiler unless the caller overrides CC.
CC ?= cc
# Tell the compiler where the shared packet.h header lives.
CPPFLAGS += -Isrc
# Keep symbols for debugging while enabling optimization by default.
CFLAGS ?= -O2 -g
# Use C11 and strict diagnostics; warnings fail the build.
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
# libssl supplies TLS; libcrypto supplies AES-GCM, SHA-256 and key operations.
# These libraries come from the OpenSSL development package (libssl-dev).
LDLIBS += -lssl -lcrypto

# Default target: build the Linux raw-packet device executable.
all: inline-secure
# Both C files are linked into one binary; the header is a rebuild dependency.
# $@ expands to the target filename. Recipe indentation must stay as a tab.
inline-secure: src/main.c src/packet.c src/packet.h src/policy.c src/policy.h src/pending.c src/pending.h
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c src/packet.c src/policy.c src/pending.c -o $@ $(LDLIBS)
# Unit tests link only portable packet code, not Linux AF_PACKET code.
packet-test: tests/packet_test.c src/packet.c src/packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/packet_test.c src/packet.c -o $@ $(LDLIBS)
# Build and run byte-level tests without root or Linux namespaces.
security-test: tests/security_test.c src/packet.c src/packet.h src/policy.c src/policy.h src/pending.c src/pending.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/security_test.c src/packet.c src/policy.c src/pending.c -o $@ $(LDLIBS)
test: packet-test security-test
	./packet-test
	./security-test
	python3 -m unittest discover -s tests -p 'test_*.py'
# Runs only on Linux as root. The harness refuses existing lab namespaces.
integration-test: inline-secure
	python3 tests/integration.py
# Remove generated executables, leaving sources and certificates untouched.
clean:
	rm -f inline-secure packet-test security-test
# These are command targets, not files that Make should consider up to date.
.PHONY: all test integration-test clean
