#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.6 — Experiment 2: Pre-Start Firewall Gate & Multi-Vector Lockdown
# Evaluates:
# 1. Atomic Netfilter rule construction via iptables-restore --noflush.
# 2. Strict scoping of connection tracking (no unscoped ESTABLISHED,RELATED).
# 3. Exact bidirectional readback (exact rule counts, strict rule ordering, no unexpected rules).
# 4. Host-Local traffic containment via scoped INPUT chain gate (-i bridge_dev).
# 5. Positional verification of parent jumps (DOCKER-USER pos 1 & 2, INPUT pos 1).
# 6. Comprehensive IPv6 lockdown (both all and default disable_ipv6, FORWARD & INPUT gates).
# 7. Fail-closed rollback: container never starts if verification fails.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/exp2_prestart_firewall_gate.log"

echo "=== EXPERIMENT 2: PRE-START FIREWALL GATE (CORRECTED V5) ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Check environment readiness & fail closed if prerequisites missing (Requirement I, B1.5-10, B1.7-05)
PREREQ_FAILED=false
PREREQ_MSG=()
if grep -qi microsoft /proc/version 2>/dev/null; then
    PREREQ_FAILED=true
    PREREQ_MSG+=("Host is WSL2 (requires native Ubuntu 22.04 LTS host)")
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    PREREQ_FAILED=true
    PREREQ_MSG+=("Docker daemon is unavailable or stopped")
fi
if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-restore >/dev/null 2>&1; then
    PREREQ_FAILED=true
    PREREQ_MSG+=("iptables or iptables-restore is not installed")
fi
if [ -f /proc/net/if_inet6 ] && (! command -v ip6tables >/dev/null 2>&1 || ! command -v ip6tables-restore >/dev/null 2>&1); then
    PREREQ_FAILED=true
    PREREQ_MSG+=("Host kernel has IPv6 active but ip6tables/ip6tables-restore is missing")
fi

if [ "${PREREQ_FAILED}" = true ]; then
    echo -e "\n[PREREQUISITE_FAILED] Environment prerequisites not met for Experiment 2:" | tee -a "${LOG_FILE}"
    for m in "${PREREQ_MSG[@]}"; do
        echo "  - ${m}" | tee -a "${LOG_FILE}"
    done
    echo "Execution status: PREREQUISITE_FAILED (Exit code: 2)." | tee -a "${LOG_FILE}"
    exit 2
fi

BRIDGE_NET="sentinelops-b1-net2"
SUBNET="172.29.0.0/24"
DYNAMIC_RANGE="172.29.0.128/25"
GATEWAY="172.29.0.1"
EXECUTOR_IP="172.29.0.50"
AUTH_TARGET_IP="172.29.0.10"
AUTH_TARGET_PORT=8001

CHAIN_EGRESS="SENTINELOPS_B1_EGRESS"
CHAIN_INGRESS="SENTINELOPS_B1_INGRESS"
CHAIN_INPUT="SENTINELOPS_B1_INPUT"
CHAIN_V6="SENTINELOPS_B1_V6"
CHAIN_V6_INPUT="SENTINELOPS_B1_V6_INPUT"

EXECUTOR_NAME="sentinelops-b1-executor"
AUTH_SERVER_NAME="sentinelops-b1-auth-server"
UNAUTH_SERVER_NAME="sentinelops-b1-unauth-server"

BRIDGE_DEV=""

# Fail-safe cleanup and state tracking (Requirements B1.7-03)
cleanup_firewall() {
    echo -e "\n[CLEANUP] Tearing down Netfilter chains and clearing conntrack..." | tee -a "${LOG_FILE}"
    local cleanup_status="SUCCESS"

    # 1. Discover and remove parent jumps from DOCKER-USER
    if command -v iptables >/dev/null 2>&1; then
        while IFS= read -r rule; do
            if [ -n "${rule}" ]; then
                del_cmd=$(echo "${rule}" | sed 's/^-A/-D/')
                echo "Removing parent DOCKER-USER reference: iptables ${del_cmd}" | tee -a "${LOG_FILE}"
                iptables ${del_cmd}
            fi
        done < <(iptables -S DOCKER-USER 2>/dev/null | grep -E -- "-j (${CHAIN_EGRESS}|${CHAIN_INGRESS})(\s|$)" || true)

        # 2. Discover and remove host-local INPUT jump
        while IFS= read -r rule; do
            if [ -n "${rule}" ]; then
                del_cmd=$(echo "${rule}" | sed 's/^-A/-D/')
                echo "Removing parent INPUT reference: iptables ${del_cmd}" | tee -a "${LOG_FILE}"
                iptables ${del_cmd}
            fi
        done < <(iptables -S INPUT 2>/dev/null | grep -E -- "-j ${CHAIN_INPUT}(\s|$)" || true)

        # Verify no parent references remain in DOCKER-USER or INPUT before deleting chains
        DU_REFS=$(iptables -S DOCKER-USER 2>/dev/null | grep -c -E -- "-j (${CHAIN_EGRESS}|${CHAIN_INGRESS})(\s|$)" || true)
        IN_REFS=$(iptables -S INPUT 2>/dev/null | grep -c -E -- "-j ${CHAIN_INPUT}(\s|$)" || true)
        if [ "${DU_REFS}" -ne 0 ] || [ "${IN_REFS}" -ne 0 ]; then
            echo "CLEANUP ERROR: Residual parent references remain in IPv4 tables (DOCKER-USER: ${DU_REFS}, INPUT: ${IN_REFS})! Preserving custom chains." | tee -a "${LOG_FILE}"
            cleanup_status="FAILED"
        else
            # 3. Flush and delete custom IPv4 chains
            for c in "${CHAIN_EGRESS}" "${CHAIN_INGRESS}" "${CHAIN_INPUT}"; do
                if iptables -S "${c}" >/dev/null 2>&1; then
                    iptables -F "${c}"
                    iptables -X "${c}"
                    if iptables -S "${c}" >/dev/null 2>&1; then
                        echo "CLEANUP ERROR: Custom IPv4 chain ${c} still exists after deletion attempt!" | tee -a "${LOG_FILE}"
                        cleanup_status="FAILED"
                    fi
                fi
            done
        fi
    fi

    # 4. Remove IPv6 jumps and chains via readback discovery (Requirement B1.7-03)
    if command -v ip6tables >/dev/null 2>&1; then
        # Dynamically discover and remove all rules in FORWARD referencing CHAIN_V6
        while IFS= read -r rule; do
            if [ -n "${rule}" ]; then
                del_cmd=$(echo "${rule}" | sed 's/^-A/-D/')
                echo "Removing parent IPv6 FORWARD reference: ip6tables ${del_cmd}" | tee -a "${LOG_FILE}"
                ip6tables ${del_cmd}
            fi
        done < <(ip6tables -S FORWARD 2>/dev/null | grep -E -- "-j ${CHAIN_V6}(\s|$)" || true)

        # Dynamically discover and remove all rules in INPUT referencing CHAIN_V6_INPUT
        while IFS= read -r rule; do
            if [ -n "${rule}" ]; then
                del_cmd=$(echo "${rule}" | sed 's/^-A/-D/')
                echo "Removing parent IPv6 INPUT reference: ip6tables ${del_cmd}" | tee -a "${LOG_FILE}"
                ip6tables ${del_cmd}
            fi
        done < <(ip6tables -S INPUT 2>/dev/null | grep -E -- "-j ${CHAIN_V6_INPUT}(\s|$)" || true)

        # Verify that NO parent references remain in FORWARD or INPUT before attempting chain deletion
        V6_FWD_REFS=$(ip6tables -S FORWARD 2>/dev/null | grep -c -E -- "-j ${CHAIN_V6}(\s|$)" || true)
        V6_IN_REFS=$(ip6tables -S INPUT 2>/dev/null | grep -c -E -- "-j ${CHAIN_V6_INPUT}(\s|$)" || true)

        if [ "${V6_FWD_REFS}" -ne 0 ] || [ "${V6_IN_REFS}" -ne 0 ]; then
            echo "CLEANUP ERROR: Residual parent references remain in IPv6 tables (FORWARD: ${V6_FWD_REFS}, INPUT: ${V6_IN_REFS})! Preserving custom chains to prevent corrupted state." | tee -a "${LOG_FILE}"
            cleanup_status="FAILED"
        else
            for c6 in "${CHAIN_V6}" "${CHAIN_V6_INPUT}"; do
                if ip6tables -S "${c6}" >/dev/null 2>&1; then
                    ip6tables -F "${c6}"
                    ip6tables -X "${c6}"
                    if ip6tables -S "${c6}" >/dev/null 2>&1; then
                        echo "CLEANUP ERROR: Custom IPv6 chain ${c6} still exists after deletion attempt!" | tee -a "${LOG_FILE}"
                        cleanup_status="FAILED"
                    fi
                fi
            done
        fi
    fi

    # 5. Flush conntrack entries specifically for this executor IP
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -s "${EXECUTOR_IP}" 2>/dev/null || true
        conntrack -D -d "${EXECUTOR_IP}" 2>/dev/null || true
    fi

    if [ "${cleanup_status}" != "SUCCESS" ]; then
        echo "[CLEANUP STATE: FAILED] Cleanup completed with errors: residual rules or custom chains remain." | tee -a "${LOG_FILE}"
        return 1
    else
        echo "[CLEANUP STATE: SUCCESS] All custom chains and parent references verified removed." | tee -a "${LOG_FILE}"
        return 0
    fi
}

cleanup_all() {
    echo -e "\n[TEARDOWN] Stopping test containers and bridge..." | tee -a "${LOG_FILE}"
    docker rm -f "${EXECUTOR_NAME}" "${AUTH_SERVER_NAME}" "${UNAUTH_SERVER_NAME}" 2>/dev/null || true
    docker network rm "${BRIDGE_NET}" 2>/dev/null || true
    cleanup_firewall
}
trap cleanup_all EXIT
cleanup_all

# Step 1: Create dedicated bridge network with dynamic range carve-out
echo -e "\n[1] Creating bridge network: ${BRIDGE_NET} (${SUBNET}, dynamic range: ${DYNAMIC_RANGE})" | tee -a "${LOG_FILE}"
docker network create \
    --driver bridge \
    --subnet "${SUBNET}" \
    --ip-range "${DYNAMIC_RANGE}" \
    --gateway "${GATEWAY}" \
    "${BRIDGE_NET}" | tee -a "${LOG_FILE}"

# Discover exact bridge interface name on host
NETWORK_ID=$(docker network inspect --format '{{.Id}}' "${BRIDGE_NET}")
BRIDGE_DEV=$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' "${BRIDGE_NET}" 2>/dev/null || true)
if [ -z "${BRIDGE_DEV}" ] || [ "${BRIDGE_DEV}" = "<no value>" ]; then
    BRIDGE_DEV="br-${NETWORK_ID:0:12}"
fi
echo "Bridge Device on Host: ${BRIDGE_DEV}" | tee -a "${LOG_FILE}"

# Step 2: Start Mock Target Services
echo -e "\n[2] Starting mock target services..." | tee -a "${LOG_FILE}"
docker run -d --name "${AUTH_SERVER_NAME}" --network "${BRIDGE_NET}" --ip "${AUTH_TARGET_IP}" python:3.13-alpine python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"status\":\"authorized_success\"}")
HTTPServer(("0.0.0.0", 8001), H).serve_forever()
' | tee -a "${LOG_FILE}"

docker run -d --name "${UNAUTH_SERVER_NAME}" --network "${BRIDGE_NET}" --ip "172.29.0.20" python:3.13-alpine python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"LEAK_UNAUTHORIZED")
HTTPServer(("0.0.0.0", 8001), H).serve_forever()
' | tee -a "${LOG_FILE}"

# Step 3: Create executor container WITHOUT starting
# Enforces: static IP, drop all capabilities, blackhole DNS, and dual IPv6 disablement
echo -e "\n[3] Creating executor container with static IP ${EXECUTOR_IP} in 'Created' state..." | tee -a "${LOG_FILE}"
docker create \
    --name "${EXECUTOR_NAME}" \
    --network "${BRIDGE_NET}" \
    --ip "${EXECUTOR_IP}" \
    --dns 192.0.2.1 \
    --cap-drop=ALL \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

STATUS_BEFORE=$(docker inspect --format '{{.State.Status}}' "${EXECUTOR_NAME}")
PID_BEFORE=$(docker inspect --format '{{.State.Pid}}' "${EXECUTOR_NAME}")
SYSCTLS_CONFIG=$(docker inspect --format '{{json .HostConfig.Sysctls}}' "${EXECUTOR_NAME}")
echo "Container Status: ${STATUS_BEFORE}, PID: ${PID_BEFORE}" | tee -a "${LOG_FILE}"
echo "Container Sysctls: ${SYSCTLS_CONFIG}" | tee -a "${LOG_FILE}"

if [ "${STATUS_BEFORE}" != "created" ] || [ "${PID_BEFORE}" -ne 0 ]; then
    echo "ERROR: Container is not in Created (PID=0) state!" | tee -a "${LOG_FILE}"
    exit 1
fi

if ! echo "${SYSCTLS_CONFIG}" | grep -q "net.ipv6.conf.all.disable_ipv6=1" || \
   ! echo "${SYSCTLS_CONFIG}" | grep -q "net.ipv6.conf.default.disable_ipv6=1"; then
    echo "ERROR: Required dual IPv6 disablement sysctls missing from container configuration!" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 4: Inspect Existing Host Netfilter State & Validate Prerequisites
echo -e "\n[4] Inspecting Host Netfilter state and preparing atomic installation..." | tee -a "${LOG_FILE}"

# Verify DOCKER-USER exists
if ! iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    echo "CRITICAL: DOCKER-USER chain not present! Docker daemon iptables integration required. Failing closed." | tee -a "${LOG_FILE}"
    exit 1
fi

# Requirement B: Inspect existing INPUT chain before installation
EXISTING_INPUT_RULES=$(iptables -S INPUT 2>/dev/null | grep -v '^-N' | grep -v '^-P' || true)
echo "--- Existing Host INPUT Rules (Before Installation) ---" | tee -a "${LOG_FILE}"
echo "${EXISTING_INPUT_RULES:-[No custom rules in INPUT]}" | tee -a "${LOG_FILE}"

# Host IPv6 State Assessment (Requirement C)
IPV6_HOST_ENABLED=false
if [ -f /proc/net/if_inet6 ]; then
    IPV6_HOST_ENABLED=true
    echo "IPv6: Detected in host kernel (/proc/net/if_inet6 present)." | tee -a "${LOG_FILE}"
    if ! command -v ip6tables >/dev/null 2>&1; then
        echo "CRITICAL: IPv6 is active in host kernel, but ip6tables CLI is missing! Cannot enforce IPv6 policy. Failing closed." | tee -a "${LOG_FILE}"
        exit 1
    fi
else
    echo "IPv6: Disabled in host kernel." | tee -a "${LOG_FILE}"
fi

# Step 5: Atomic Netfilter Rule Installation via iptables-restore
echo -e "\n[5] Installing Host Netfilter rules atomically via iptables-restore --noflush..." | tee -a "${LOG_FILE}"

iptables-restore --noflush << EOF
*filter
:${CHAIN_EGRESS} - [0:0]
:${CHAIN_INGRESS} - [0:0]
:${CHAIN_INPUT} - [0:0]
-A ${CHAIN_EGRESS} -s ${EXECUTOR_IP}/32 -d ${AUTH_TARGET_IP}/32 -p tcp -m tcp --dport ${AUTH_TARGET_PORT} -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "SENTINELOPS_AUTH_PERMIT" -j ACCEPT
-A ${CHAIN_EGRESS} -s ${EXECUTOR_IP}/32 -m comment --comment "SENTINELOPS_DEFAULT_DENY" -j REJECT --reject-with icmp-port-unreachable
-A ${CHAIN_INGRESS} -s ${AUTH_TARGET_IP}/32 -d ${EXECUTOR_IP}/32 -p tcp -m tcp --sport ${AUTH_TARGET_PORT} -m conntrack --ctstate ESTABLISHED -m comment --comment "SENTINELOPS_AUTH_RETURN" -j ACCEPT
-A ${CHAIN_INGRESS} -d ${EXECUTOR_IP}/32 -m comment --comment "SENTINELOPS_INBOUND_DROP" -j DROP
-A ${CHAIN_INPUT} -s ${EXECUTOR_IP}/32 -m comment --comment "SENTINELOPS_HOST_LOCAL_DENY" -j REJECT --reject-with icmp-port-unreachable
-I DOCKER-USER 1 -s ${EXECUTOR_IP}/32 -j ${CHAIN_EGRESS}
-I DOCKER-USER 2 -d ${EXECUTOR_IP}/32 -j ${CHAIN_INGRESS}
-I INPUT 1 -i ${BRIDGE_DEV} -s ${EXECUTOR_IP}/32 -j ${CHAIN_INPUT}
COMMIT
EOF

# Install complete IPv6 containment in both FORWARD and INPUT (Requirement C)
if [ "${IPV6_HOST_ENABLED}" = true ]; then
    ip6tables-restore --noflush << EOF
*filter
:${CHAIN_V6} - [0:0]
:${CHAIN_V6_INPUT} - [0:0]
-A ${CHAIN_V6} -i ${BRIDGE_DEV} -j REJECT --reject-with icmp6-port-unreachable
-A ${CHAIN_V6_INPUT} -i ${BRIDGE_DEV} -j REJECT --reject-with icmp6-port-unreachable
-I FORWARD 1 -i ${BRIDGE_DEV} -j ${CHAIN_V6}
-I INPUT 1 -i ${BRIDGE_DEV} -j ${CHAIN_V6_INPUT}
COMMIT
EOF
    echo "IPv6 containment rules installed in FORWARD and INPUT for bridge ${BRIDGE_DEV}." | tee -a "${LOG_FILE}"
fi

echo "Atomic rule installation completed." | tee -a "${LOG_FILE}"

# Step 6: Exact Positional Readback Verification (Requirements A, B, C)
echo -e "\n[6] Exact Positional Readback Verification:" | tee -a "${LOG_FILE}"

normalize_rule() {
    echo "$1" | tr -s ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# 6.1 Exact Verification of Custom Egress Chain
set +e
EGRESS_RAW=$(iptables -S "${CHAIN_EGRESS}" 2>&1)
EGRESS_CMD_STATUS=$?
set -e

EGRESS_EXACT_MATCH=false
if [ "${EGRESS_CMD_STATUS}" -eq 0 ]; then
    EGRESS_RULES=$(echo "${EGRESS_RAW}" | grep -E '^-A' || true)
    EGRESS_COUNT=$(echo "${EGRESS_RULES}" | grep -c '^-A' || true)

    EXP_EGRESS_1="-A ${CHAIN_EGRESS} -s ${EXECUTOR_IP}/32 -d ${AUTH_TARGET_IP}/32 -p tcp -m tcp --dport ${AUTH_TARGET_PORT} -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment \"SENTINELOPS_AUTH_PERMIT\" -j ACCEPT"
    EXP_EGRESS_2="-A ${CHAIN_EGRESS} -s ${EXECUTOR_IP}/32 -m comment --comment \"SENTINELOPS_DEFAULT_DENY\" -j REJECT --reject-with icmp-port-unreachable"

    ACT_EGRESS_1=$(normalize_rule "$(echo "${EGRESS_RULES}" | sed -n '1p')")
    ACT_EGRESS_2=$(normalize_rule "$(echo "${EGRESS_RULES}" | sed -n '2p')")

    if [ "${EGRESS_COUNT}" -eq 2 ] && \
       [ "${ACT_EGRESS_1}" = "$(normalize_rule "${EXP_EGRESS_1}")" ] && \
       [ "${ACT_EGRESS_2}" = "$(normalize_rule "${EXP_EGRESS_2}")" ]; then
        EGRESS_EXACT_MATCH=true
    fi
fi

# 6.2 Exact Verification of Custom Ingress Chain
set +e
INGRESS_RAW=$(iptables -S "${CHAIN_INGRESS}" 2>&1)
INGRESS_CMD_STATUS=$?
set -e

INGRESS_EXACT_MATCH=false
if [ "${INGRESS_CMD_STATUS}" -eq 0 ]; then
    INGRESS_RULES=$(echo "${INGRESS_RAW}" | grep -E '^-A' || true)
    INGRESS_COUNT=$(echo "${INGRESS_RULES}" | grep -c '^-A' || true)

    EXP_INGRESS_1="-A ${CHAIN_INGRESS} -s ${AUTH_TARGET_IP}/32 -d ${EXECUTOR_IP}/32 -p tcp -m tcp --sport ${AUTH_TARGET_PORT} -m conntrack --ctstate ESTABLISHED -m comment --comment \"SENTINELOPS_AUTH_RETURN\" -j ACCEPT"
    EXP_INGRESS_2="-A ${CHAIN_INGRESS} -d ${EXECUTOR_IP}/32 -m comment --comment \"SENTINELOPS_INBOUND_DROP\" -j DROP"

    ACT_INGRESS_1=$(normalize_rule "$(echo "${INGRESS_RULES}" | sed -n '1p')")
    ACT_INGRESS_2=$(normalize_rule "$(echo "${INGRESS_RULES}" | sed -n '2p')")

    if [ "${INGRESS_COUNT}" -eq 2 ] && \
       [ "${ACT_INGRESS_1}" = "$(normalize_rule "${EXP_INGRESS_1}")" ] && \
       [ "${ACT_INGRESS_2}" = "$(normalize_rule "${EXP_INGRESS_2}")" ]; then
        INGRESS_EXACT_MATCH=true
    fi
fi

# 6.3 Exact Verification of Custom Host INPUT Chain
set +e
INPUT_RAW=$(iptables -S "${CHAIN_INPUT}" 2>&1)
INPUT_CMD_STATUS=$?
set -e

INPUT_EXACT_MATCH=false
if [ "${INPUT_CMD_STATUS}" -eq 0 ]; then
    INPUT_RULES=$(echo "${INPUT_RAW}" | grep -E '^-A' || true)
    INPUT_COUNT=$(echo "${INPUT_RULES}" | grep -c '^-A' || true)

    EXP_INPUT_1="-A ${CHAIN_INPUT} -s ${EXECUTOR_IP}/32 -m comment --comment \"SENTINELOPS_HOST_LOCAL_DENY\" -j REJECT --reject-with icmp-port-unreachable"
    ACT_INPUT_1=$(normalize_rule "$(echo "${INPUT_RULES}" | sed -n '1p')")

    if [ "${INPUT_COUNT}" -eq 1 ] && [ "${ACT_INPUT_1}" = "$(normalize_rule "${EXP_INPUT_1}")" ]; then
        INPUT_EXACT_MATCH=true
    fi
fi

# 6.4 Exact Parent Chain Verification in DOCKER-USER (Positions 1 and 2, exact counts) (Requirement B1.7-01)
set +e
DU_RAW=$(iptables -S DOCKER-USER 2>&1)
DU_CMD_STATUS=$?
set -e

PARENT_DU_EXACT_MATCH=false
if [ "${DU_CMD_STATUS}" -eq 0 ]; then
    DOCKER_USER_RULES=$(echo "${DU_RAW}" | grep -E '^-A' || true)
    DU_EGRESS_COUNT=$(echo "${DOCKER_USER_RULES}" | grep -c -- "-j ${CHAIN_EGRESS}" || true)
    DU_INGRESS_COUNT=$(echo "${DOCKER_USER_RULES}" | grep -c -- "-j ${CHAIN_INGRESS}" || true)

    EXP_DU_1="-A DOCKER-USER -s ${EXECUTOR_IP}/32 -j ${CHAIN_EGRESS}"
    EXP_DU_2="-A DOCKER-USER -d ${EXECUTOR_IP}/32 -j ${CHAIN_INGRESS}"

    ACT_DU_1=$(normalize_rule "$(echo "${DOCKER_USER_RULES}" | sed -n '1p')")
    ACT_DU_2=$(normalize_rule "$(echo "${DOCKER_USER_RULES}" | sed -n '2p')")

    # Enforce:
    # 1. Total jumps to CHAIN_EGRESS in DOCKER-USER is exactly 1 (no duplicates anywhere in chain)
    # 2. Total jumps to CHAIN_INGRESS in DOCKER-USER is exactly 1 (no duplicates anywhere in chain)
    # 3. Position 1 is exactly EXP_DU_1
    # 4. Position 2 is exactly EXP_DU_2
    if [ "${DU_EGRESS_COUNT}" -eq 1 ] && [ "${DU_INGRESS_COUNT}" -eq 1 ] && \
       [ "${ACT_DU_1}" = "$(normalize_rule "${EXP_DU_1}")" ] && \
       [ "${ACT_DU_2}" = "$(normalize_rule "${EXP_DU_2}")" ]; then
        PARENT_DU_EXACT_MATCH=true
    fi
fi

# 6.5 Exact Parent Chain Verification in host INPUT (Position 1 strictly scoped to bridge, exact count)
set +e
HOST_INPUT_RAW=$(iptables -S INPUT 2>&1)
HOST_INPUT_CMD_STATUS=$?
set -e

PARENT_INPUT_EXACT_MATCH=false
if [ "${HOST_INPUT_CMD_STATUS}" -eq 0 ]; then
    HOST_INPUT_RULES=$(echo "${HOST_INPUT_RAW}" | grep -E '^-A' || true)
    INPUT_PARENT_COUNT=$(echo "${HOST_INPUT_RULES}" | grep -c -- "-j ${CHAIN_INPUT}" || true)

    EXP_HI_1="-A INPUT -i ${BRIDGE_DEV} -s ${EXECUTOR_IP}/32 -j ${CHAIN_INPUT}"
    ACT_HI_1=$(normalize_rule "$(echo "${HOST_INPUT_RULES}" | sed -n '1p')")

    if [ "${INPUT_PARENT_COUNT}" -eq 1 ] && [ "${ACT_HI_1}" = "$(normalize_rule "${EXP_HI_1}")" ]; then
        PARENT_INPUT_EXACT_MATCH=true
    fi
fi

# 6.6 Exact Verification of IPv6 Policies (if host IPv6 active)
V6_EXACT_MATCH=false
if [ "${IPV6_HOST_ENABLED}" = true ]; then
    set +e
    V6_FWD_CHAIN_RAW=$(ip6tables -S "${CHAIN_V6}" 2>&1)
    V6_FWD_CHAIN_STATUS=$?
    V6_IN_CHAIN_RAW=$(ip6tables -S "${CHAIN_V6_INPUT}" 2>&1)
    V6_IN_CHAIN_STATUS=$?
    V6_PARENT_FWD_RAW=$(ip6tables -S FORWARD 2>&1)
    V6_PARENT_FWD_STATUS=$?
    V6_PARENT_IN_RAW=$(ip6tables -S INPUT 2>&1)
    V6_PARENT_IN_STATUS=$?
    set -e

    if [ "${V6_FWD_CHAIN_STATUS}" -eq 0 ] && [ "${V6_IN_CHAIN_STATUS}" -eq 0 ] && \
       [ "${V6_PARENT_FWD_STATUS}" -eq 0 ] && [ "${V6_PARENT_IN_STATUS}" -eq 0 ]; then

        V6_FWD_LINES=$(echo "${V6_FWD_CHAIN_RAW}" | grep -E '^-A' || true)
        V6_IN_LINES=$(echo "${V6_IN_CHAIN_RAW}" | grep -E '^-A' || true)
        V6_PARENT_FWD_RULES=$(echo "${V6_PARENT_FWD_RAW}" | grep -E '^-A' || true)
        V6_PARENT_IN_RULES=$(echo "${V6_PARENT_IN_RAW}" | grep -E '^-A' || true)

        V6_FWD_PARENT_COUNT=$(echo "${V6_PARENT_FWD_RULES}" | grep -c -- "-j ${CHAIN_V6}" || true)
        V6_IN_PARENT_COUNT=$(echo "${V6_PARENT_IN_RULES}" | grep -c -- "-j ${CHAIN_V6_INPUT}" || true)

        EXP_V6_FWD="-A ${CHAIN_V6} -i ${BRIDGE_DEV} -j REJECT --reject-with icmp6-port-unreachable"
        EXP_V6_IN="-A ${CHAIN_V6_INPUT} -i ${BRIDGE_DEV} -j REJECT --reject-with icmp6-port-unreachable"

        ACT_P_V6_FWD=$(normalize_rule "$(echo "${V6_PARENT_FWD_RULES}" | sed -n '1p')")
        ACT_P_V6_IN=$(normalize_rule "$(echo "${V6_PARENT_IN_RULES}" | sed -n '1p')")

        EXP_P_V6_FWD="-A FORWARD -i ${BRIDGE_DEV} -j ${CHAIN_V6}"
        EXP_P_V6_IN="-A INPUT -i ${BRIDGE_DEV} -j ${CHAIN_V6_INPUT}"

        if [ "$(echo "${V6_FWD_LINES}" | grep -c '^-A' || true)" -eq 1 ] && \
           [ "$(echo "${V6_IN_LINES}" | grep -c '^-A' || true)" -eq 1 ] && \
           [ "${V6_FWD_PARENT_COUNT}" -eq 1 ] && \
           [ "${V6_IN_PARENT_COUNT}" -eq 1 ] && \
           [ "$(normalize_rule "$(echo "${V6_FWD_LINES}" | sed -n '1p')")" = "$(normalize_rule "${EXP_V6_FWD}")" ] && \
           [ "$(normalize_rule "$(echo "${V6_IN_LINES}" | sed -n '1p')")" = "$(normalize_rule "${EXP_V6_IN}")" ] && \
           [ "${ACT_P_V6_FWD}" = "$(normalize_rule "${EXP_P_V6_FWD}")" ] && \
           [ "${ACT_P_V6_IN}" = "$(normalize_rule "${EXP_P_V6_IN}")" ]; then
            V6_EXACT_MATCH=true
        fi
    fi
else
    V6_EXACT_MATCH=true
fi

echo -e "\nExact Readback Checklist (Normalized String Matching):" | tee -a "${LOG_FILE}"
echo "  [1] Egress Chain Exact Match (Rules=2, Order=1:Permit, 2:Deny): ${EGRESS_EXACT_MATCH}" | tee -a "${LOG_FILE}"
echo "  [2] Ingress Chain Exact Match (Rules=2, Order=1:Return, 2:Drop): ${INGRESS_EXACT_MATCH}" | tee -a "${LOG_FILE}"
echo "  [3] Host INPUT Chain Exact Match (Rules=1, Deny Only):         ${INPUT_EXACT_MATCH}" | tee -a "${LOG_FILE}"
echo "  [4] DOCKER-USER Positions 1 & 2 Exact Match:                   ${PARENT_DU_EXACT_MATCH}" | tee -a "${LOG_FILE}"
echo "  [5] Host INPUT Position 1 Scoped Bridge Match:                 ${PARENT_INPUT_EXACT_MATCH}" | tee -a "${LOG_FILE}"
echo "  [6] IPv6 Lockdown (FORWARD pos 1 + INPUT pos 1):               ${V6_EXACT_MATCH}" | tee -a "${LOG_FILE}"

ALL_EXACT_VERIFIED=false
if [ "${EGRESS_EXACT_MATCH}" = true ] && [ "${INGRESS_EXACT_MATCH}" = true ] && \
   [ "${INPUT_EXACT_MATCH}" = true ] && [ "${PARENT_DU_EXACT_MATCH}" = true ] && \
   [ "${PARENT_INPUT_EXACT_MATCH}" = true ] && [ "${V6_EXACT_MATCH}" = true ]; then
    ALL_EXACT_VERIFIED=true
fi

if [ "${ALL_EXACT_VERIFIED}" = true ]; then
    echo -e "\nPRE-START FIREWALL VERDICT: FULLY VERIFIED (Fail-closed gate confirmed active BEFORE start)" | tee -a "${LOG_FILE}"
else
    echo -e "\nCRITICAL ERROR: Exact independent readback verification failed! Executing fail-closed abort." | tee -a "${LOG_FILE}"
    cleanup_firewall
    docker rm -f "${EXECUTOR_NAME}"
    echo "Fail-closed abort complete: container destroyed and rules purged. Never started." | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 7: Start Container and Validate Egress Enforcement
echo -e "\n[7] Starting executor container now that firewall is confirmed active..." | tee -a "${LOG_FILE}"
docker start "${EXECUTOR_NAME}" | tee -a "${LOG_FILE}"

# Setup probe inside container
docker cp "${SCRIPT_DIR}/traffic_probe.py" "${EXECUTOR_NAME}:/tmp/traffic_probe.py"
docker exec "${EXECUTOR_NAME}" apk add --no-cache python3 >/dev/null 2>&1

echo -e "\n[8] Running traffic probe from within container:" | tee -a "${LOG_FILE}"
set +e
docker exec "${EXECUTOR_NAME}" python3 /tmp/traffic_probe.py \
    "http://${AUTH_TARGET_IP}:${AUTH_TARGET_PORT}" \
    "${AUTH_TARGET_IP}" "${AUTH_TARGET_PORT}" \
    "172.29.0.20" 8001 > "${OUTPUT_DIR}/exp2_probe_results.json" 2>&1
PROBE_EXIT=$?
set -e

cat "${OUTPUT_DIR}/exp2_probe_results.json" | tee -a "${LOG_FILE}"
echo "Probe Exit Code: ${PROBE_EXIT}" | tee -a "${LOG_FILE}"

if [ "${PROBE_EXIT}" -eq 0 ]; then
    echo "EXPERIMENT 2 FINAL VERDICT: PASSED (Fail-closed pre-start firewall gate proven)" | tee -a "${LOG_FILE}"
else
    echo "EXPERIMENT 2 FINAL VERDICT: FAILED (Egress leak detected or authorized traffic failed)" | tee -a "${LOG_FILE}"
    exit 1
fi

echo -e "\n=== EXPERIMENT 2 COMPLETE ===" | tee -a "${LOG_FILE}"
