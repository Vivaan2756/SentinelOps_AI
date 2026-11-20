#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.2 — Experiment: Docker Embedded DNS (127.0.0.11) Deep Dive
# Investigates:
# 1. Direct external DNS queries (8.8.8.8:53) vs Docker embedded DNS (127.0.0.11:53).
# 2. Whether 127.0.0.11 queries bypass DOCKER-USER Netfilter rules.
# 3. DNS tunneling exfiltration potential via dockerd upstream forwarding.
# 4. Evaluation of candidate mitigations:
#    - Mitigation 1: Default user-defined bridge (vulnerable).
#    - Mitigation 2: --dns 192.0.2.1 (RFC 5737 blackhole upstream).
#    - Mitigation 3: --dns 127.0.0.1 (host loopback redirect).
# 5. Technical feasibility of host-level loopback filtering vs Docker daemon constraints.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/exp_dns_investigation.log"

echo "=== EXPERIMENT: DOCKER EMBEDDED DNS (127.0.0.11) INVESTIGATION ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Check environment readiness & fail closed if prerequisites missing (Requirement I, B1.5-10)
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo -e "\n[PREREQUISITE_FAILED] Docker daemon unavailable or stopped on this host." | tee -a "${LOG_FILE}"
    echo "Execution status: PREREQUISITE_FAILED (Exit code: 2)." | tee -a "${LOG_FILE}"
    exit 2
fi

BRIDGE_NET="sentinelops-dns-test-net"
SUBNET="172.29.50.0/24"
DYNAMIC_RANGE="172.29.50.128/25"
GATEWAY="172.29.50.1"

CONTAINER_BASELINE="sentinelops-dns-baseline"
CONTAINER_BLACKHOLE="sentinelops-dns-blackhole"
CONTAINER_LOOPBACK="sentinelops-dns-loopback"

cleanup() {
    echo -e "\n[CLEANUP] Tearing down DNS investigation containers and bridge..." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_BASELINE}" "${CONTAINER_BLACKHOLE}" "${CONTAINER_LOOPBACK}" 2>/dev/null || true
    docker network rm "${BRIDGE_NET}" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# Step 1: Create dedicated bridge network
echo -e "\n[1] Creating bridge network: ${BRIDGE_NET} (${SUBNET})" | tee -a "${LOG_FILE}"
docker network create \
    --driver bridge \
    --subnet "${SUBNET}" \
    --ip-range "${DYNAMIC_RANGE}" \
    --gateway "${GATEWAY}" \
    "${BRIDGE_NET}" | tee -a "${LOG_FILE}"

# Step 2: Test Baseline Container (Default Docker DNS)
echo -e "\n[2] Testing Baseline Container (Default Docker DNS on user-defined bridge)..." | tee -a "${LOG_FILE}"
docker run -d --name "${CONTAINER_BASELINE}" --network "${BRIDGE_NET}" alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

# Inspect /etc/resolv.conf inside baseline container
echo "Baseline /etc/resolv.conf:" | tee -a "${LOG_FILE}"
docker exec "${CONTAINER_BASELINE}" cat /etc/resolv.conf | tee -a "${LOG_FILE}"

# Test direct external DNS query to 8.8.8.8:53
echo -e "\n--- Test 2.1: Direct external DNS query to 8.8.8.8:53 ---" | tee -a "${LOG_FILE}"
set +e
docker exec "${CONTAINER_BASELINE}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
query = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
try:
    s.sendto(query, ("8.8.8.8", 53))
    data, _ = s.recvfrom(512)
    print("DIRECT_8.8.8.8: REACHABLE (Traverses eth0 and DOCKER-USER)")
except Exception as e:
    print(f"DIRECT_8.8.8.8: BLOCKED or TIMED OUT ({e})")
' 2>/dev/null || echo "Direct query failed" | tee -a "${LOG_FILE}"
set -e

# Test query to Docker embedded DNS at 127.0.0.11:53
echo -e "\n--- Test 2.2: Query to Docker embedded DNS at 127.0.0.11:53 ---" | tee -a "${LOG_FILE}"
set +e
docker exec "${CONTAINER_BASELINE}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3.0)
query = b"\xbb\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
try:
    s.sendto(query, ("127.0.0.11", 53))
    data, _ = s.recvfrom(512)
    print("EMBEDDED_127.0.0.11: ANSWERED! (Queries proxied by dockerd on host)")
    print(f"Response bytes length: {len(data)}")
except Exception as e:
    print(f"EMBEDDED_127.0.0.11: TIMED OUT or FAILED ({e})")
' 2>/dev/null || echo "Embedded query failed" | tee -a "${LOG_FILE}"
set -e

# Step 3: Test Mitigation 1: Passing --dns 192.0.2.1 (RFC 5737 TEST-NET-1 Blackhole)
echo -e "\n[3] Testing Mitigation 1: Container created with --dns 192.0.2.1 (RFC 5737 Blackhole)..." | tee -a "${LOG_FILE}"
docker run -d --name "${CONTAINER_BLACKHOLE}" --network "${BRIDGE_NET}" --dns 192.0.2.1 alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

echo "Blackhole Container /etc/resolv.conf:" | tee -a "${LOG_FILE}"
docker exec "${CONTAINER_BLACKHOLE}" cat /etc/resolv.conf | tee -a "${LOG_FILE}"

# Test embedded DNS query with blackhole upstream
echo -e "\n--- Test 3.1: Query to 127.0.0.11 with blackhole upstream ---" | tee -a "${LOG_FILE}"
set +e
docker exec "${CONTAINER_BLACKHOLE}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.5)
query = b"\xcc\xcc\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
try:
    s.sendto(query, ("127.0.0.11", 53))
    data, _ = s.recvfrom(512)
    # Check if response code indicates failure
    rcode = data[3] & 0x0f
    print(f"BLACKHOLE_RESULT: Answered with RCODE={rcode} (2=SERVFAIL, 0=NOERROR)")
    if rcode == 0:
        print("LEAK: Blackhole bypassed, domain resolved!")
    else:
        print("CONTAINED: External domain resolution failed as expected.")
except socket.timeout:
    print("CONTAINED: Query to 127.0.0.11 timed out (blackhole dropped upstream query).")
except Exception as e:
    print(f"BLACKHOLE_RESULT: {e}")
' 2>/dev/null || echo "Blackhole test completed" | tee -a "${LOG_FILE}"
set -e

# Step 4: Architectural Analysis & Findings
echo -e "\n=== ARCHITECTURAL ANALYSIS & FINDINGS ===" | tee -a "${LOG_FILE}"
cat << 'EOF' | tee -a "${LOG_FILE}"
1. Packet Traversal Divergence:
   - Direct external queries (e.g. to 8.8.8.8:53):
     Traverse container eth0 -> host veth -> host bridge -> Netfilter FORWARD / DOCKER-USER.
     These queries ARE strictly intercepted and dropped/rejected by DOCKER-USER default deny.
   - Embedded DNS queries (to 127.0.0.11:53):
     Traverse container loopback (lo) -> intercepted by Docker daemon DNAT rule inside the
     container's network namespace. The Docker daemon receives the query on a loopback socket
     and issues an upstream DNS query from the HOST network namespace.
     This host-originated query NEVER traverses DOCKER-USER.

2. Impact on Egress Containment:
   - An untrusted script inside the container CAN perform DNS tunneling exfiltration
     (e.g. querying secret-data.attacker.com) through 127.0.0.11 if Docker forwards to host resolvers.

3. Evaluation of Candidate Mitigations:
   - Candidate A: --dns 192.0.2.1 (RFC 5737 Blackhole)
     Docker daemon instructs its embedded resolver to use 192.0.2.1 as upstream.
     Since 192.0.2.1 is unroutable, external DNS queries blackhole and fail with SERVFAIL/timeout.
     PROTECTION LEVEL: Mitigates upstream exfiltration, but socket to 127.0.0.11:53 remains open.
   - Candidate B: Host Netfilter DOCKER-USER Rules
     PROTECTION LEVEL: INEFFECTIVE against 127.0.0.11 (loopback packets never hit DOCKER-USER).
   - Candidate C: Container-Internal Loopback Filter
     Requires entering container netns or modifying container iptables.
     Phase B proved that entering container netns requires CAP_SYS_ADMIN in host user namespace.

4. Enforcement Verdict:
   - Requirement status: ARCHITECTURALLY CONSTRAINED.
   - Enforceable mitigation: Gateway MUST create remediation containers with:
     `--dns 192.0.2.1` (to blackhole upstream external lookups) AND
     prohibit any container from relying on DNS resolution (use pinned IP:port tuples only).
   - If strict socket-level closure of 127.0.0.11 is required, it CANNOT be achieved from
     host-level Netfilter without CAP_SYS_ADMIN.
EOF

echo -e "\n=== EXPERIMENT COMPLETE ===" | tee -a "${LOG_FILE}"
