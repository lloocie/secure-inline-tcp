#!/usr/bin/env bash
# Create development identities for mutual TLS; stop if any command fails.
set -euo pipefail
# New files are owner-only by default, particularly unencrypted private keys.
umask 077
# Deliberately refuse an existing directory to avoid replacing live identities.
mkdir certs
# Create a local RSA CA valid for 30 days. CA:TRUE and keyCertSign allow it
# to sign device certificates. RSA authenticates devices; ephemeral finite-field
# DH inside TLS creates the session secret. These serve different purposes.
openssl req -x509 -newkey rsa:3072 -nodes -keyout certs/ca.key -out certs/ca.crt -days 30 -subj /CN=inline-lab-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
# Issue one identity for each role. The CSR contains the device public key;
# its private key stays in the corresponding .key file.
for device in dev1 dev2; do
    openssl req -newkey rsa:3072 -nodes -keyout "certs/$device.key" -out "certs/$device.csr" -subj "/CN=$device"
    # DNS SANs match the expected peer names passed to SSL_set1_host.
    # Allow clientAuth and serverAuth because both roles present identities;
    # CA:FALSE prevents a device certificate from acting as a signing CA.
    printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n' "$device" > "certs/$device.ext"
    # Sign the request using the CA; the C program trusts ca.crt, never ca.key.
    # -nodes above leaves keys without passphrases for unattended lab startup.
    # Protect the directory and do not distribute these private keys.
    openssl x509 -req -in "certs/$device.csr" -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out "certs/$device.crt" -days 30 -extfile "certs/$device.ext"
done
