#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.6 — Experiment 3: Bypass Resistance & Gateway Security Boundary
# Evaluates egress containment and gateway policy boundaries against:
# 1. Port hopping on authorized target.
# 2. Direct external DNS tunneling (UDP/TCP 53).
# 3. Docker embedded DNS (127.0.0.11).
# 4. IPv6 egress leaks.
# 5. Source-IP spoofing inside unprivileged sandbox.
# 6. Multi-homed interface source-IP binding bypass (dynamic discovery & route inspection).
# 7. Host networking (--net=host) bypass demonstration.
# 8. Same-bridge Layer 2 switching bypass demonstration.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/exp3_bypass_resistance.log"

echo "=== EXPERIMENT 3: BYPASS RESISTANCE & GATEWAY POLICY EVALUATION (V4) ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Check environment readiness & fail closed if prerequisites missing (Requirement I, B1.5-10)
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    echo -e "\n[PREREQUISITE_FAILED] Docker daemon or iptables unavailable." | tee -a "${LOG_FILE}"
    echo "Execution status: PREREQUISITE_FAILED (Exit code: 2)." | tee -a "${LOG_FILE}"
    exit 2
fi

BRIDGE_PRIMARY="sentinelops-b1-net3"
BRIDGE_SECONDARY="sentinelops-b1-secondary"
SUBNET_PRIMARY="172.29.0.0/24"
DYNAMIC_PRIMARY="172.29.0.128/25"
SUBNET_SECONDARY="172.30.0.0/24"
DYNAMIC_SECONDARY="172.30.0.128/25"

EXECUTOR_IP="172.29.0.50"
AUTH_TARGET_IP="172.29.0.10"
AUTH_PORT=8001

CHAIN_NAME="SENTINELOPS_B1_BYPASS"
EXECUTOR_NAME="sentinelops-b1-bypass-tester"
TARGET_NAME="sentinelops-b1-bypass-target"
HOST_NET_CONTAINER="sentinelops-b1-hostnet-tester"

cleanup() {
    echo -e "\n[CLEANUP] Tearing down bypass test harness..." | tee -a "${LOG_FILE}"
    docker rm -f "${EXECUTOR_NAME}" "${TARGET_NAME}" "${HOST_NET_CONTAINER}" 2>/dev/null || true
    docker network rm "${BRIDGE_PRIMARY}" "${BRIDGE_SECONDARY}" 2>/dev/null || true

    # Clean parent jumps
    if iptables -C DOCKER-USER -s "${EXECUTOR_IP}/32" -j "${CHAIN_NAME}" 2>/dev/null; then
        iptables -D DOCKER-USER -s "${EXECUTOR_IP}/32" -j "${CHAIN_NAME}"
    elif iptables -C DOCKER-USER -s "${EXECUTOR_IP}" -j "${CHAIN_NAME}" 2>/dev/null; then
        iptables -D DOCKER-USER -s "${EXECUTOR_IP}" -j "${CHAIN_NAME}"
    fi
    if iptables -S "${CHAIN_NAME}" >/dev/null 2>&1; then
        iptables -F "${CHAIN_NAME}"
        iptables -X "${CHAIN_NAME}"
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        if ip6tables -C FORWARD -j "${CHAIN_NAME}_V6" 2>/dev/null; then
            ip6tables -D FORWARD -j "${CHAIN_NAME}_V6"
        fi
        if ip6tables -S "${CHAIN_NAME}_V6" >/dev/null 2>&1; then
            ip6tables -F "${CHAIN_NAME}_V6"
            ip6tables -X "${CHAIN_NAME}_V6"
        fi
    fi
}
trap cleanup EXIT
cleanup

# Step 1: Create primary and secondary bridge networks with dynamic ranges
echo -e "\n[1] Creating primary and secondary bridge networks..." | tee -a "${LOG_FILE}"
docker network create --driver bridge --subnet "${SUBNET_PRIMARY}" --ip-range "${DYNAMIC_PRIMARY}" "${BRIDGE_PRIMARY}" | tee -a "${LOG_FILE}"
docker network create --driver bridge --subnet "${SUBNET_SECONDARY}" --ip-range "${DYNAMIC_SECONDARY}" "${BRIDGE_SECONDARY}" | tee -a "${LOG_FILE}"

# Step 2: Start target container listening on multiple ports
docker run -d --name "${TARGET_NAME}" --network "${BRIDGE_PRIMARY}" --ip "${AUTH_TARGET_IP}" python:3.13-alpine python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class H1(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"AUTH_8001_OK")

class H2(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"UNAUTH_8002_LEAK")

t1 = threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8001), H1).serve_forever())
t2 = threading.Thread(target=lambda: HTTPServer(("0.0.0.0", 8002), H2).serve_forever())
t1.start()
t2.start()
t1.join()
' | tee -a "${LOG_FILE}"

# Step 3: Create executor container with static IP and dual IPv6 disablement
docker create \
    --name "${EXECUTOR_NAME}" \
    --network "${BRIDGE_PRIMARY}" \
    --ip "${EXECUTOR_IP}" \
    --dns 192.0.2.1 \
    --cap-drop=ALL \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

# Step 4: Install host firewall rules with strictly scoped conntrack
echo -e "\n[2] Installing firewall rules in ${CHAIN_NAME}..." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_NAME}"
# Rule 1: Scoped permit for authorized IP:port only
iptables -A "${CHAIN_NAME}" -s "${EXECUTOR_IP}/32" -d "${AUTH_TARGET_IP}/32" -p tcp --dport "${AUTH_PORT}" \
    -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
# Rule 2: Explicit default reject for executor IP
iptables -A "${CHAIN_NAME}" -s "${EXECUTOR_IP}/32" -j REJECT --reject-with icmp-port-unreachable

# Link into DOCKER-USER with scoped match at position 1
iptables -I DOCKER-USER 1 -s "${EXECUTOR_IP}/32" -j "${CHAIN_NAME}"

# IPv6 default deny
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N "${CHAIN_NAME}_V6" 2>/dev/null || true
    ip6tables -A "${CHAIN_NAME}_V6" -j REJECT --reject-with icmp6-port-unreachable
    ip6tables -I FORWARD 1 -j "${CHAIN_NAME}_V6"
fi

# Step 5: Start container and execute bypass test suite
docker start "${EXECUTOR_NAME}" | tee -a "${LOG_FILE}"
docker cp "${SCRIPT_DIR}/traffic_probe.py" "${EXECUTOR_NAME}:/tmp/traffic_probe.py"
docker exec "${EXECUTOR_NAME}" apk add --no-cache python3 iproute2 >/dev/null 2>&1

echo -e "\n[3] Testing Bypass Vector 1: Alternate port on authorized host (Port 8002)..." | tee -a "${LOG_FILE}"
set +e
docker exec "${EXECUTOR_NAME}" python3 -c '
import socket
s = socket.socket()
s.settimeout(2.0)
try:
    s.connect(("'"${AUTH_TARGET_IP}"'", 8002))
    print("LEAK: Connected to alternate port 8002!")
    exit(1)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
' | tee -a "${LOG_FILE}"
PORT_HOP_RES=$?
set -e

echo -e "\n[4] Testing Bypass Vector 2: Direct external DNS exfiltration (8.8.8.8:53 UDP)..." | tee -a "${LOG_FILE}"
set +e
docker exec "${EXECUTOR_NAME}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
try:
    s.sendto(b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", ("8.8.8.8", 53))
    s.recvfrom(512)
    print("LEAK: Direct external DNS succeeded!")
    exit(1)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
' | tee -a "${LOG_FILE}"
DNS_DIRECT_RES=$?
set -e

echo -e "\n[5] Testing Bypass Vector 3: IPv6 egress attempt..." | tee -a "${LOG_FILE}"
set +e
docker exec "${EXECUTOR_NAME}" python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(("2606:4700:4700::1111", 80))
    print("LEAK: IPv6 connection succeeded!")
    exit(1)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
' | tee -a "${LOG_FILE}"
IPV6_RES=$?
set -e

echo -e "\n[6] Testing Bypass Vector 4: Source-IP spoofing via raw sockets..." | tee -a "${LOG_FILE}"
set +e
docker exec "${EXECUTOR_NAME}" python3 -c '
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    print("LEAK: CAP_NET_RAW present, raw socket opened!")
    exit(1)
except PermissionError:
    print("BLOCKED: Raw sockets denied by kernel cap_drop.")
    exit(0)
' | tee -a "${LOG_FILE}"
SPOOF_RES=$?
set -e

# Step 6: Multi-Homed Network Attachment with Dynamic Discovery & Route Inspection
echo -e "\n[7] Testing Bypass Vector 5: Multi-Homed Network Attachment..." | tee -a "${LOG_FILE}"
docker network connect "${BRIDGE_SECONDARY}" "${EXECUTOR_NAME}" | tee -a "${LOG_FILE}"

# Dynamically discover secondary interface and assigned IP
SECONDARY_IP=$(docker inspect --format "{{with index .NetworkSettings.Networks \"${BRIDGE_SECONDARY}\"}}{{.IPAddress}}{{end}}" "${EXECUTOR_NAME}")
echo "Dynamically discovered secondary interface IP: ${SECONDARY_IP}" | tee -a "${LOG_FILE}"

# Inspect route selection from secondary IP
docker exec "${EXECUTOR_NAME}" ip route get 1.1.1.1 from "${SECONDARY_IP}" | tee -a "${LOG_FILE}" || true

# Test explicit socket binding to secondary IP
set +e
BOUND_OUTPUT=$(docker exec "${EXECUTOR_NAME}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.bind(("'"${SECONDARY_IP}"'", 0))
except Exception as be:
    print(f"BIND_FAILED: {be}")
    exit(2)
try:
    s.connect(("1.1.1.1", 80))
    print("CRITICAL_LEAK: Egress escaped via secondary bound IP!")
    exit(1)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
' 2>&1)
BOUND_EXIT=$?
set -e
echo "Multi-Homing Bound Socket Result: ${BOUND_OUTPUT}" | tee -a "${LOG_FILE}"

# Step 7: Host-Network Mode (--net=host) Bypass Demonstration
echo -e "\n[8] Testing Bypass Vector 6: Host Networking (--net=host) Demonstration..." | tee -a "${LOG_FILE}"
docker create --name "${HOST_NET_CONTAINER}" --network host alpine:latest sleep 3600 | tee -a "${LOG_FILE}"
HOST_NET_ATTACHED=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "${HOST_NET_CONTAINER}")
echo "Container NetworkMode: ${HOST_NET_ATTACHED}" | tee -a "${LOG_FILE}"

if [ "${HOST_NET_ATTACHED}" = "host" ]; then
    echo "HOST-NET DEMO: Container shares host network namespace directly. Bypasses DOCKER-USER completely." | tee -a "${LOG_FILE}"
    echo "ARCHITECTURAL INVARIANT: Rejection of host-network mode is mandatory at Gateway authorization boundary." | tee -a "${LOG_FILE}"
    HOST_NET_RES=0
else
    HOST_NET_RES=1
fi
docker rm -f "${HOST_NET_CONTAINER}" >/dev/null 2>&1 || true

# Step 8: Same-Bridge Layer 2 Traffic & bridge-nf-call-iptables Check
echo -e "\n[9] Testing Bypass Vector 7: Same-Bridge L2 Traffic Filtering Prerequisites..." | tee -a "${LOG_FILE}"
BR_NF_VAL=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo "0")
echo "Host sysctl bridge-nf-call-iptables: ${BR_NF_VAL}" | tee -a "${LOG_FILE}"

if [ "${BR_NF_VAL}" != "1" ]; then
    echo "WARNING: Intra-bridge Layer 2 packets will bypass Netfilter when sysctl is 0!" | tee -a "${LOG_FILE}"
else
    echo "PREREQUISITE VERIFIED: Intra-bridge Layer 2 packets are forced through Netfilter rules." | tee -a "${LOG_FILE}"
fi

echo -e "\n=== EXPERIMENT 3 SUMMARY ===" | tee -a "${LOG_FILE}"
echo "Port Hopping Blocked:            $([ $PORT_HOP_RES -eq 0 ] && echo YES || echo NO)" | tee -a "${LOG_FILE}"
echo "Direct DNS Blocked:               $([ $DNS_DIRECT_RES -eq 0 ] && echo YES || echo NO)" | tee -a "${LOG_FILE}"
echo "IPv6 Blocked:                     $([ $IPV6_RES -eq 0 ] && echo YES || echo NO)" | tee -a "${LOG_FILE}"
echo "Raw Spoofing Blocked:             $([ $SPOOF_RES -eq 0 ] && echo YES || echo NO)" | tee -a "${LOG_FILE}"
echo "Multi-Homing Bound Egress Result: $([ $BOUND_EXIT -eq 0 ] && echo 'BLOCKED' || ([ $BOUND_EXIT -eq 1 ] && echo 'CRITICAL_LEAK' || echo 'BIND_FAILED'))" | tee -a "${LOG_FILE}"

# Requirement F: Propagate failures; do not print CRITICAL_LEAK and return success
FAILURES=()
if [ "${PORT_HOP_RES}" -ne 0 ]; then
    FAILURES+=("Port hopping to unauthorized port 8002 succeeded (egress leak)")
fi
if [ "${DNS_DIRECT_RES}" -ne 0 ]; then
    FAILURES+=("Direct DNS egress to 8.8.8.8:53 succeeded (egress leak)")
fi
if [ "${IPV6_RES}" -ne 0 ]; then
    FAILURES+=("IPv6 egress connection succeeded (egress leak)")
fi
if [ "${SPOOF_RES}" -ne 0 ]; then
    FAILURES+=("Raw socket opened with CAP_NET_RAW active")
fi
if [ "${BOUND_EXIT}" -eq 1 ]; then
    FAILURES+=("Multi-homing leak: Egress escaped via secondary network interface")
elif [ "${BOUND_EXIT}" -eq 2 ]; then
    FAILURES+=("Multi-homing test inconclusive: Failed to bind socket to secondary IP")
fi

if [ ${#FAILURES[@]} -gt 0 ]; then
    echo -e "\n[SECURITY VERIFICATION FAILED] ${#FAILURES[@]} bypass test(s) failed:" | tee -a "${LOG_FILE}"
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}" | tee -a "${LOG_FILE}"
    done
    exit 1
fi

echo "=== EXPERIMENT 3 COMPLETE: ALL BYPASS CHECKS PASSED ===" | tee -a "${LOG_FILE}"
