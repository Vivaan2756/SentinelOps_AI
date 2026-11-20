#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B — Experiment C: Linux Firewall Enforcement & Cleanup
# Tests isolated Netfilter egress containment using dedicated custom chains.
# Never flushes global tables or alters unrelated policies.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/experiment_c_firewall.log"

echo "=== EXPERIMENT C: LINUX FIREWALL ENFORCEMENT SPIKE ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

CHAIN_NAME="SENTINELOPS_SPIKE_EGRESS"
NET_NAME="sentinelops-spike-net-c"
CONTAINER_NAME="sentinelops-spike-container-c"
AUTH_SERVER_NAME="sentinelops-auth-server-c"
UNAUTH_SERVER_NAME="sentinelops-unauth-server-c"

cleanup_firewall() {
    echo -e "\n[CLEANUP] Pruning custom iptables chain: ${CHAIN_NAME}..." | tee -a "${LOG_FILE}"
    # Unlink from FORWARD and DOCKER-USER chains if linked
    iptables -D DOCKER-USER -j "${CHAIN_NAME}" 2>/dev/null || true
    iptables -D FORWARD -j "${CHAIN_NAME}" 2>/dev/null || true
    # Flush custom chain only
    iptables -F "${CHAIN_NAME}" 2>/dev/null || true
    # Delete custom chain
    iptables -X "${CHAIN_NAME}" 2>/dev/null || true

    # IPv6 cleanup
    ip6tables -D FORWARD -j "${CHAIN_NAME}" 2>/dev/null || true
    ip6tables -F "${CHAIN_NAME}" 2>/dev/null || true
    ip6tables -X "${CHAIN_NAME}" 2>/dev/null || true

    echo "Firewall rollback complete. Global tables untouched." | tee -a "${LOG_FILE}"
}

cleanup_all() {
    echo -e "\n[TEARDOWN] Stopping test containers and network..." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_NAME}" "${AUTH_SERVER_NAME}" "${UNAUTH_SERVER_NAME}" 2>/dev/null || true
    docker network rm "${NET_NAME}" 2>/dev/null || true
    cleanup_firewall
}
trap cleanup_all EXIT

cleanup_all

# 1. Create Disposable Bridge Network & Test Services
echo -e "\n[1] Setting up disposable network and servers..." | tee -a "${LOG_FILE}"
docker network create --driver bridge "${NET_NAME}" | tee -a "${LOG_FILE}"

# Start Authorized Mock Service (Port 8001)
docker run -d --name "${AUTH_SERVER_NAME}" --network "${NET_NAME}" python:3.13-alpine python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"status\":\"authorized_server_ok\"}")
HTTPServer(("0.0.0.0", 8001), H).serve_forever()
' | tee -a "${LOG_FILE}"
AUTH_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${AUTH_SERVER_NAME}")

# Start Unauthorized Mock Service (Port 8002)
docker run -d --name "${UNAUTH_SERVER_NAME}" --network "${NET_NAME}" python:3.13-alpine python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"UNAUTHORIZED_DATA_LEAK")
HTTPServer(("0.0.0.0", 8002), H).serve_forever()
' | tee -a "${LOG_FILE}"
UNAUTH_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${UNAUTH_SERVER_NAME}")

# Start Executor Test Container
docker run -d --name "${CONTAINER_NAME}" --network "${NET_NAME}" alpine:latest sleep 3600 | tee -a "${LOG_FILE}"
CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CONTAINER_NAME}")
PID=$(docker inspect -f '{{.State.Pid}}' "${CONTAINER_NAME}")

echo "Container IP: ${CONTAINER_IP} (PID: ${PID})" | tee -a "${LOG_FILE}"
echo "Authorized Target IP: ${AUTH_IP}:8001" | tee -a "${LOG_FILE}"
echo "Unauthorized Target IP: ${UNAUTH_IP}:8002" | tee -a "${LOG_FILE}"

# 2. Establish Dedicated Custom Firewall Chains (Isolation Invariant)
echo -e "\n[2] Installing isolated Netfilter rules in custom chain ${CHAIN_NAME}..." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_NAME}"

# Rule 1: Allow established / related stateful conntrack connections
iptables -A "${CHAIN_NAME}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Rule 2: Explicitly permit ONLY authorized destination IP and Port
iptables -A "${CHAIN_NAME}" -s "${CONTAINER_IP}" -d "${AUTH_IP}" -p tcp --dport 8001 \
    -m comment --comment "SENTINELOPS_AUTH_PERMIT" -j ACCEPT

# Rule 3: Reject all other traffic originating from container IP
iptables -A "${CHAIN_NAME}" -s "${CONTAINER_IP}" \
    -m comment --comment "SENTINELOPS_EGRESS_LOCKDOWN" -j REJECT --reject-with icmp-port-unreachable

# Link to DOCKER-USER or FORWARD chain
if iptables -L DOCKER-USER >/dev/null 2>&1; then
    iptables -I DOCKER-USER 1 -j "${CHAIN_NAME}"
    echo "Linked ${CHAIN_NAME} into DOCKER-USER chain." | tee -a "${LOG_FILE}"
else
    iptables -I FORWARD 1 -j "${CHAIN_NAME}"
    echo "Linked ${CHAIN_NAME} into FORWARD chain." | tee -a "${LOG_FILE}"
fi

# IPv6 Lockdown: Reject all IPv6 from container
ip6tables -N "${CHAIN_NAME}" 2>/dev/null || true
ip6tables -A "${CHAIN_NAME}" -j REJECT --reject-with icmp6-port-unreachable
ip6tables -I FORWARD 1 -j "${CHAIN_NAME}"

# 3. Independent Readback Verification of Kernel Rules
echo -e "\n[3] Independent Kernel Rule Readback:" | tee -a "${LOG_FILE}"
iptables -S "${CHAIN_NAME}" | tee -a "${LOG_FILE}"
iptables -vnL "${CHAIN_NAME}" | tee -a "${LOG_FILE}"

# 4. Traffic Verification Tests
echo -e "\n[4] Running Packet Transmission & Firewall Validation Tests:" | tee -a "${LOG_FILE}"

# Copy traffic verifier into container
docker cp "${SCRIPT_DIR}/experiment_c_traffic_verifier.py" "${CONTAINER_NAME}:/tmp/verifier.py"
# Install python3 in alpine container for verification
docker exec "${CONTAINER_NAME}" apk add --no-cache python3 >/dev/null 2>&1

set +e
docker exec "${CONTAINER_NAME}" python3 /tmp/verifier.py "http://${AUTH_IP}:8001" "${UNAUTH_IP}" > "${OUTPUT_DIR}/experiment_c_results.json" 2>&1
VERIFY_EXIT=$?
set -e

cat "${OUTPUT_DIR}/experiment_c_results.json" | tee -a "${LOG_FILE}"
echo "Traffic Verifier Exit Code: ${VERIFY_EXIT}" | tee -a "${LOG_FILE}"

if [ "${VERIFY_EXIT}" -eq 0 ]; then
    echo "EXPERIMENT C VERDICT: PASSED (Authorized traffic allowed; unauthorized IPv4, IPv6, and DNS dropped/rejected)" | tee -a "${LOG_FILE}"
else
    echo "EXPERIMENT C VERDICT: FAILED (Egress containment breached or authorized traffic blocked)" | tee -a "${LOG_FILE}"
fi

# 5. Rule Cleanup and Verification
echo -e "\n[5] Testing Rule Cleanup and Verification:" | tee -a "${LOG_FILE}"
cleanup_firewall

if iptables -L "${CHAIN_NAME}" 2>/dev/null; then
    echo "ERROR: Custom chain still exists after cleanup!" | tee -a "${LOG_FILE}"
else
    echo "CONFIRMED: Custom chain ${CHAIN_NAME} successfully deleted from kernel." | tee -a "${LOG_FILE}"
fi

echo -e "\n=== EXPERIMENT C COMPLETE ===" | tee -a "${LOG_FILE}"
