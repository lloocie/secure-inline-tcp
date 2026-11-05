#!/usr/bin/env bash
# Fail on command errors, undefined variables, and failed pipeline stages.
# This script creates a disposable Linux network lab; it does not run on macOS.
set -euo pipefail
# Namespace/interface administration requires root privileges.
if [[ ${EUID} -ne 0 ]]; then echo 'Run with sudo'; exit 1; fi
# Use 'down' to stop processes inside the four reserved lab namespaces and
# delete them. Do not reuse these namespace names for unrelated workloads.
if [[ ${1:-up} == down ]]; then
    for namespace in pc1 dev1 dev2 pc2; do
    # Stop namespace processes before removing their network interfaces.
        # Missing namespaces/processes are tolerated during cleanup.
        ip netns pids "$namespace" 2>/dev/null | xargs -r kill || true
        ip netns del "$namespace" 2>/dev/null || true
    done
    exit
fi
# Step 1: four independent network stacks, each with its own interfaces/routes.
for namespace in pc1 dev1 dev2 pc2; do ip netns add "$namespace"; done
# Create three virtual cables: PC1--Device1--Device2--PC2.
# Each veth endpoint is then moved into the namespace that owns it.
ip link add pc1-d1 type veth peer name d1-pc1
ip link add d1-d2 type veth peer name d2-d1
ip link add d2-pc2 type veth peer name pc2-d2
ip link set pc1-d1 netns pc1
ip link set d1-pc1 netns dev1
ip link set d1-d2 netns dev1
ip link set d2-d1 netns dev2
ip link set d2-pc2 netns dev2
ip link set pc2-d2 netns pc2
# Arguments: namespace, interface, IPv4/prefix, fixed MAC, MTU.
# Fixed MACs match the device commands in README.md, avoiding next-hop discovery
# in the C program. Linux still answers ARP for its assigned interface IPs.
configure() {
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$1" link set "$2" address "$4" mtu "$5" up
    # Disable segmentation, aggregation and checksum offloads so AF_PACKET sees
    # complete wire-like segments with checksums rather than deferred work.
    # Some veth features are fixed/unsupported; those ethtool failures are ignored.
    ip netns exec "$1" ethtool -K "$2" gro off gso off tso off rx off tx off >/dev/null 2>&1 || true
}
# Host links use 1484-byte MTUs, reserving 16 tag bytes on the 1500-byte
# protected middle link. IP addresses are in three separate /24 subnets.
configure pc1 pc1-d1 10.0.1.1/24 02:00:00:00:01:01 1484
configure dev1 d1-pc1 10.0.1.2/24 02:00:00:00:01:02 1484
configure dev1 d1-d2 10.0.2.1/24 02:00:00:00:02:01 1500
configure dev2 d2-d1 10.0.2.2/24 02:00:00:00:02:02 1500
configure dev2 d2-pc2 10.0.3.1/24 02:00:00:00:03:01 1484
configure pc2 pc2-d2 10.0.3.2/24 02:00:00:00:03:02 1484
# Enable loopback independently in each namespace.
for namespace in pc1 dev1 dev2 pc2; do ip -n "$namespace" link set lo up; done
# Only the C program may forward selected packets. Kernel forwarding off
# prevents an unencrypted duplicate from bypassing the AF_PACKET transformer.
# Disable reverse-path filtering settings here for the asymmetric raw path.
for namespace in dev1 dev2; do
    ip netns exec "$namespace" sysctl -qw net.ipv4.ip_forward=0
    ip netns exec "$namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$namespace" sysctl -qw net.ipv4.conf.default.rp_filter=0
done
# Hosts send remote-host traffic to their adjacent device's gateway address.
# No device route to the remote host subnet is needed for raw Ethernet sends.
ip -n pc1 route add 10.0.3.0/24 via 10.0.1.2
ip -n pc2 route add 10.0.1.0/24 via 10.0.3.1
echo 'Lab ready. Kernel forwarding is disabled; start both devices before host TCP traffic.'
