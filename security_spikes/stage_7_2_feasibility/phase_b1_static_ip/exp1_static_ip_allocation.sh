#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.2 — Experiment 1: Static IP Allocation & IPAM Carve-Out
# Evaluates:
# 1. Deterministic IP reservation via --ip at container create time (PID=0).
# 2. Strict separation of dynamic IPAM range from reserved executor IP range.
# 3. Collision handling and duplicate IP rejection.
# 4. Safe deallocation upon container removal and subsequent clean reuse.
# 5. Network ownership verification (single network attachment).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/exp1_static_ip_allocation.log"

echo "=== EXPERIMENT 1: STATIC IP ALLOCATION & RESERVATION ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Check environment readiness & fail closed if prerequisites missing (Requirement I, B1.5-10)
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo -e "\n[PREREQUISITE_FAILED] Docker daemon unavailable or stopped on this host." | tee -a "${LOG_FILE}"
    echo "Execution status: PREREQUISITE_FAILED (Exit code: 2)." | tee -a "${LOG_FILE}"
    exit 2
fi

BRIDGE_NET="sentinelops-b1-bridge"
SUBNET="172.29.0.0/24"
DYNAMIC_IP_RANGE="172.29.0.128/25"   # Dynamic containers allocated in .128-.254
GATEWAY="172.29.0.1"
STATIC_EXECUTOR_IP="172.29.0.50"    # Reserved static IP in .2-.127 carve-out

CONTAINER_DYNAMIC="sentinelops-b1-dyn"
CONTAINER_PRIMARY="sentinelops-b1-primary"
CONTAINER_DUPLICATE="sentinelops-b1-duplicate"
CONTAINER_REUSE="sentinelops-b1-reuse"

cleanup() {
    echo -e "\n[CLEANUP] Removing test containers and bridge network..." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_DYNAMIC}" "${CONTAINER_PRIMARY}" "${CONTAINER_DUPLICATE}" "${CONTAINER_REUSE}" 2>/dev/null || true
    docker network rm "${BRIDGE_NET}" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# Step 1: Create dedicated bridge network with explicit dynamic IP carve-out
echo -e "\n[1] Creating dedicated Docker bridge: ${BRIDGE_NET}" | tee -a "${LOG_FILE}"
echo "    Subnet: ${SUBNET}, Dynamic Range: ${DYNAMIC_IP_RANGE}, Gateway: ${GATEWAY}" | tee -a "${LOG_FILE}"
docker network create \
    --driver bridge \
    --subnet "${SUBNET}" \
    --ip-range "${DYNAMIC_IP_RANGE}" \
    --gateway "${GATEWAY}" \
    "${BRIDGE_NET}" | tee -a "${LOG_FILE}"

# Verify network configuration via inspect
INSPECT_SUBNET=$(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${BRIDGE_NET}")
INSPECT_RANGE=$(docker network inspect --format '{{range .IPAM.Config}}{{.IPRange}}{{end}}' "${BRIDGE_NET}")
INSPECT_GW=$(docker network inspect --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "${BRIDGE_NET}")

if [ "${INSPECT_SUBNET}" = "${SUBNET}" ] && [ "${INSPECT_RANGE}" = "${DYNAMIC_IP_RANGE}" ] && [ "${INSPECT_GW}" = "${GATEWAY}" ]; then
    echo "NETWORK CONFIG VERIFICATION: PASSED (Subnet, IP-Range, and Gateway verified)" | tee -a "${LOG_FILE}"
else
    echo "NETWORK CONFIG VERIFICATION: FAILED (Config mismatch: ${INSPECT_SUBNET}, ${INSPECT_RANGE}, ${INSPECT_GW})" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 2: Verify dynamic pool separation
echo -e "\n[2] Testing dynamic allocation isolation (container without explicit --ip)..." | tee -a "${LOG_FILE}"
docker create --name "${CONTAINER_DYNAMIC}" --network "${BRIDGE_NET}" alpine:latest sleep 3600 | tee -a "${LOG_FILE}"
DYN_IP=$(docker inspect --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "${CONTAINER_DYNAMIC}")
echo "Dynamic container assigned IP: ${DYN_IP}" | tee -a "${LOG_FILE}"

# Verify DYN_IP is in .128-.254 range
DYN_OCTET=$(echo "${DYN_IP}" | cut -d. -f4)
if [ "${DYN_OCTET}" -ge 128 ]; then
    echo "DYNAMIC CARVE-OUT VERIFICATION: PASSED (${DYN_IP} >= 172.29.0.128, cannot collide with static range)" | tee -a "${LOG_FILE}"
else
    echo "DYNAMIC CARVE-OUT VERIFICATION: FAILED (${DYN_IP} allocated inside reserved static range!)" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 3: Create executor container with static IP without starting
echo -e "\n[3] Creating executor container with static IP ${STATIC_EXECUTOR_IP} in 'Created' state..." | tee -a "${LOG_FILE}"
docker create \
    --name "${CONTAINER_PRIMARY}" \
    --network "${BRIDGE_NET}" \
    --ip "${STATIC_EXECUTOR_IP}" \
    alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

STATE_STATUS=$(docker inspect --format '{{.State.Status}}' "${CONTAINER_PRIMARY}")
STATE_PID=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER_PRIMARY}")
ASSIGNED_IP=$(docker inspect --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "${CONTAINER_PRIMARY}")
ATTACHED_NETS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${CONTAINER_PRIMARY}")

echo "Status: ${STATE_STATUS}" | tee -a "${LOG_FILE}"
echo "PID: ${STATE_PID}" | tee -a "${LOG_FILE}"
echo "Assigned IP: ${ASSIGNED_IP}" | tee -a "${LOG_FILE}"
echo "Attached Networks: ${ATTACHED_NETS}" | tee -a "${LOG_FILE}"

# Validate single network attachment and correct IP
if [ "${ASSIGNED_IP}" = "${STATIC_EXECUTOR_IP}" ] && [ "${STATE_STATUS}" = "created" ] && [ "${STATE_PID}" -eq 0 ]; then
    echo "STATIC IP RESERVATION VERDICT: PASSED (Reserved at create time with PID=0)" | tee -a "${LOG_FILE}"
else
    echo "STATIC IP RESERVATION VERDICT: FAILED" | tee -a "${LOG_FILE}"
    exit 1
fi

if [ "$(echo ${ATTACHED_NETS} | wc -w)" -eq 1 ] && echo "${ATTACHED_NETS}" | grep -q "${BRIDGE_NET}"; then
    echo "NETWORK OWNERSHIP VERDICT: PASSED (Strictly single-network attached)" | tee -a "${LOG_FILE}"
else
    echo "NETWORK OWNERSHIP VERDICT: FAILED (Unexpected network attachments: ${ATTACHED_NETS})" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 4: Test collision and duplicate allocation rejection
echo -e "\n[4] Attempting duplicate allocation of ${STATIC_EXECUTOR_IP} with second container..." | tee -a "${LOG_FILE}"
set +e
DUPLICATE_OUTPUT=$(docker create \
    --name "${CONTAINER_DUPLICATE}" \
    --network "${BRIDGE_NET}" \
    --ip "${STATIC_EXECUTOR_IP}" \
    alpine:latest sleep 3600 2>&1)
DUPLICATE_EXIT=$?
set -e

echo "Exit Code: ${DUPLICATE_EXIT}" | tee -a "${LOG_FILE}"
echo "Docker Daemon Output: ${DUPLICATE_OUTPUT}" | tee -a "${LOG_FILE}"

if [ "${DUPLICATE_EXIT}" -ne 0 ] && echo "${DUPLICATE_OUTPUT}" | grep -qiE '(already in use|Address already allocated)'; then
    echo "COLLISION REJECTION VERDICT: PASSED (Docker IPAM strictly prevented duplicate IP assignment)" | tee -a "${LOG_FILE}"
else
    echo "COLLISION REJECTION VERDICT: FAILED (Duplicate IP was not rejected!)" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 5: Start primary container and verify IP persistence across start
echo -e "\n[5] Starting primary container to verify IP persistence across start:" | tee -a "${LOG_FILE}"
docker start "${CONTAINER_PRIMARY}" | tee -a "${LOG_FILE}"
RUNNING_IP=$(docker inspect --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "${CONTAINER_PRIMARY}")
echo "Running IP: ${RUNNING_IP}" | tee -a "${LOG_FILE}"

if [ "${RUNNING_IP}" = "${STATIC_EXECUTOR_IP}" ]; then
    echo "IP PERSISTENCE VERDICT: PASSED" | tee -a "${LOG_FILE}"
else
    echo "IP PERSISTENCE VERDICT: FAILED" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 6: Test IP deallocation upon removal and safe subsequent reuse
echo -e "\n[6] Testing IP release and reuse lifecycle:" | tee -a "${LOG_FILE}"
echo "Removing primary container..." | tee -a "${LOG_FILE}"
docker rm -f "${CONTAINER_PRIMARY}" | tee -a "${LOG_FILE}"

# Re-allocate same IP to new container
echo "Creating new container with same IP ${STATIC_EXECUTOR_IP}..." | tee -a "${LOG_FILE}"
docker create \
    --name "${CONTAINER_REUSE}" \
    --network "${BRIDGE_NET}" \
    --ip "${STATIC_EXECUTOR_IP}" \
    alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

REUSE_IP=$(docker inspect --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "${CONTAINER_REUSE}")
echo "Reallocated IP: ${REUSE_IP}" | tee -a "${LOG_FILE}"

if [ "${REUSE_IP}" = "${STATIC_EXECUTOR_IP}" ]; then
    echo "IP RELEASE & REUSE VERDICT: PASSED (Clean IPAM deallocation and reallocation)" | tee -a "${LOG_FILE}"
else
    echo "IP RELEASE & REUSE VERDICT: FAILED" | tee -a "${LOG_FILE}"
    exit 1
fi

echo -e "\n=== EXPERIMENT 1 COMPLETE: ALL VERIFICATIONS PASSED ===" | tee -a "${LOG_FILE}"
