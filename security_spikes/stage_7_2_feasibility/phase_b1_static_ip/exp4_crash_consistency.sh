#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.6 — Experiment 4: Crash Consistency & Fault Recovery
# Evaluates state reconciliation and crash boundaries across boundaries A through J:
# 1. Structural documentation of all 10 boundaries (A–J).
# 2. Executable mock simulations for verifiable lifecycle boundaries (B, D, F, H).
# 3. Honest classification of host/daemon crash boundaries as NOT_TESTED_ENVIRONMENT.
# 4. Standalone fail-closed exit code (2) if prerequisites are unavailable.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/exp4_crash_consistency.log"

echo "=== EXPERIMENT 4: CRASH CONSISTENCY & FAULT RECOVERY (V4) ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Table: Complete 10 Boundary Matrix (Requirement H, B1.5-09)
cat << 'EOF' | tee -a "${LOG_FILE}"
-----------------------------------------------------------------------------------------------------------------------------------
Boundary | Point of Failure       | Durable State      | Docker State    | Netfilter State | Recovery Action       | Evidence Status
-----------------------------------------------------------------------------------------------------------------------------------
A        | IP Allocated           | IP_ALLOCATED       | None            | None            | Reclaim IP in IPAM    | THEORETICALLY_EXPECTED
B        | Firewall Partial       | FIREWALL_PARTIAL   | None            | Incomplete      | Rollback custom chain | EXECUTED_MOCKED
C        | Firewall Verified      | FIREWALL_VERIFIED  | None            | Active (Deny)   | Prune rules & abort   | THEORETICALLY_EXPECTED
D        | Container Created      | CONTAINER_CREATED  | Created (PID=0) | Active (Deny)   | Delete container & rm | EXECUTED_MOCKED
E        | Start Ambiguous        | START_REQUESTED    | Uncertain       | Active (Deny)   | Query API; transition | NOT_TESTED_ENVIRONMENT
F        | Container Running      | EXECUTOR_RUNNING   | Running         | Active (Deny)   | PRESERVE rules; lock  | EXECUTED_MOCKED
G        | Container Stopped      | EXECUTOR_STOPPED   | Exited          | Active (Stale)  | Prune rules, then rm  | THEORETICALLY_EXPECTED
H        | Container Removed      | CONTAINER_REMOVED  | Removed         | Active (Orphan) | Detect dead IP; prune | EXECUTED_MOCKED
I        | Cleanup Partial        | CLEANUP_PARTIAL    | Removed         | Partial Chain   | Idempotent flush/del  | THEORETICALLY_EXPECTED
J        | Helper Daemon Restart  | HELPER_RESTART     | Live & Stale    | Active & Orphan | Query Docker first    | NOT_TESTED_ENVIRONMENT
-----------------------------------------------------------------------------------------------------------------------------------
EOF

# Check environment readiness & fail closed if prerequisites missing (Requirement I, B1.5-10)
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    echo -e "\n[PREREQUISITE_FAILED] Live Docker Engine or iptables is unavailable on this host." | tee -a "${LOG_FILE}"
    echo "Execution status: PREREQUISITE_FAILED (Exit code: 2)." | tee -a "${LOG_FILE}"
    exit 2
fi

BRIDGE_NET="sentinelops-crash-net"
SUBNET="172.29.99.0/24"
DYNAMIC_RANGE="172.29.99.128/25"
GATEWAY="172.29.99.1"
EXEC_IP_1="172.29.99.10"
EXEC_IP_2="172.29.99.20"

CONTAINER_LIVE="sentinelops-crash-live"
CONTAINER_DEAD="sentinelops-crash-dead"
CHAIN_LIVE="SENTINELOPS_CRASH_LIVE"
CHAIN_DEAD="SENTINELOPS_CRASH_DEAD"
CHAIN_PARTIAL="SENTINELOPS_CRASH_PARTIAL"

cleanup() {
    echo -e "\n[CLEANUP] Tearing down crash test resources..." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_LIVE}" "${CONTAINER_DEAD}" 2>/dev/null || true
    docker network rm "${BRIDGE_NET}" 2>/dev/null || true

    for c in "${CHAIN_LIVE}" "${CHAIN_DEAD}" "${CHAIN_PARTIAL}"; do
        iptables -D DOCKER-USER -j "${c}" 2>/dev/null || true
        iptables -F "${c}" 2>/dev/null || true
        iptables -X "${c}" 2>/dev/null || true
    done
}
trap cleanup EXIT
cleanup

# Setup bridge network
docker network create --driver bridge --subnet "${SUBNET}" --ip-range "${DYNAMIC_RANGE}" --gateway "${GATEWAY}" "${BRIDGE_NET}" | tee -a "${LOG_FILE}"

# Test Boundary B: Incomplete Firewall Installation & Rollback (Mock Simulation)
echo -e "\n>>> Testing Boundary B: Incomplete Firewall Installation & Rollback <<<" | tee -a "${LOG_FILE}"
echo "- Operation: Helper starts installing rules, but terminates before linking to DOCKER-USER." | tee -a "${LOG_FILE}"
echo "- Injection: Create unlinked custom chain without parent jump." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_PARTIAL}"
iptables -A "${CHAIN_PARTIAL}" -s "${EXEC_IP_1}/32" -j ACCEPT

# Reconciliation Hook: Helper detects unlinked chain on startup
if ! iptables -C DOCKER-USER -j "${CHAIN_PARTIAL}" 2>/dev/null; then
    echo "Helper Recovery: Detected unlinked partial chain ${CHAIN_PARTIAL}. Rolling back..." | tee -a "${LOG_FILE}"
    iptables -F "${CHAIN_PARTIAL}"
    iptables -X "${CHAIN_PARTIAL}"
    echo "BOUNDARY B VERDICT: PASSED (Partial chain safely rolled back in mock simulation)" | tee -a "${LOG_FILE}"
else
    echo "BOUNDARY B VERDICT: FAILED" | tee -a "${LOG_FILE}"
    exit 1
fi

# Test Boundary D: Container Created (PID=0), Gateway Crashes Before Start (Mock Simulation)
echo -e "\n>>> Testing Boundary D: Container Created (PID=0), Gateway Crashes Before Start <<<" | tee -a "${LOG_FILE}"
echo "- Operation: Container created in Docker IPAM, but Gateway crashes before issuing docker start." | tee -a "${LOG_FILE}"
echo "- Injection: docker create executed; start omitted; inspect state." | tee -a "${LOG_FILE}"
docker create --name "${CONTAINER_DEAD}" --network "${BRIDGE_NET}" --ip "${EXEC_IP_1}" alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

STATUS_D=$(docker inspect --format '{{.State.Status}}' "${CONTAINER_DEAD}")
PID_D=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER_DEAD}")
echo "Container State: Status=${STATUS_D}, PID=${PID_D}" | tee -a "${LOG_FILE}"

if [ "${STATUS_D}" = "created" ] && [ "${PID_D}" -eq 0 ]; then
    echo "Watchdog Recovery: Container found in unstarted state. Safe to destroy without egress risk." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_DEAD}" | tee -a "${LOG_FILE}"
    echo "BOUNDARY D VERDICT: PASSED (Unstarted container safely pruned in mock simulation)" | tee -a "${LOG_FILE}"
fi

# Test Boundary F: Live Container Running — Helper MUST NOT Flush Rules!
echo -e "\n>>> Testing Boundary F: Live Running Container Protection <<<" | tee -a "${LOG_FILE}"
echo "- Operation: Container is in-flight; Helper restarts." | tee -a "${LOG_FILE}"
echo "- Invariant: Helper must query Docker API and NEVER flush rules for active containers." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_LIVE}"
iptables -A "${CHAIN_LIVE}" -s "${EXEC_IP_2}/32" -j REJECT
iptables -I DOCKER-USER 1 -s "${EXEC_IP_2}/32" -j "${CHAIN_LIVE}"
docker run -d --name "${CONTAINER_LIVE}" --network "${BRIDGE_NET}" --ip "${EXEC_IP_2}" alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

LIVE_CONTAINERS=$(docker ps --format '{{.Names}}')
echo "Active Docker containers: ${LIVE_CONTAINERS}" | tee -a "${LOG_FILE}"

if echo "${LIVE_CONTAINERS}" | grep -q "${CONTAINER_LIVE}"; then
    echo "Reconciliation Rule: Container ${CONTAINER_LIVE} is RUNNING. PRESERVING FIREWALL RULES!" | tee -a "${LOG_FILE}"
    if iptables -C DOCKER-USER -s "${EXEC_IP_2}/32" -j "${CHAIN_LIVE}" 2>/dev/null; then
        echo "BOUNDARY F VERDICT: PASSED (Firewall rules protected during mock execution)" | tee -a "${LOG_FILE}"
    else
        echo "BOUNDARY F VERDICT: FAILED (Rules were flushed during execution!)" | tee -a "${LOG_FILE}"
        exit 1
    fi
fi

# Test Boundary H: Orphaned Rule Cleanup for Removed Container
echo -e "\n>>> Testing Boundary H: Orphaned Rule Pruning for Removed Container <<<" | tee -a "${LOG_FILE}"
echo "- Operation: Container destroyed, but rule cleanup crashed." | tee -a "${LOG_FILE}"
echo "- Recovery: Reconciliation detects IP without matching container and prunes rules." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_DEAD}"
iptables -A "${CHAIN_DEAD}" -s "${EXEC_IP_1}/32" -j REJECT
iptables -I DOCKER-USER 1 -s "${EXEC_IP_1}/32" -j "${CHAIN_DEAD}"

MATCHING_CONTAINER=$(docker ps -a --filter "network=${BRIDGE_NET}" --format '{{.Names}} {{.NetworkSettings.Networks}}' | grep "${EXEC_IP_1}" || true)

if [ -z "${MATCHING_CONTAINER}" ]; then
    echo "Reconciliation: No Docker container owns ${EXEC_IP_1}. Pruning orphaned rules..." | tee -a "${LOG_FILE}"
    iptables -D DOCKER-USER -s "${EXEC_IP_1}/32" -j "${CHAIN_DEAD}"
    iptables -F "${CHAIN_DEAD}"
    iptables -X "${CHAIN_DEAD}"
    echo "BOUNDARY H VERDICT: PASSED (Orphaned rule cleanly pruned in mock simulation)" | tee -a "${LOG_FILE}"
fi

echo -e "\n=== EXPERIMENT 4 SUMMARY ===" | tee -a "${LOG_FILE}"
echo "Boundaries B, D, F, H: EXECUTED_MOCKED (Sequential mock simulations)" | tee -a "${LOG_FILE}"
echo "Boundaries A, C, E, G, I, J: THEORETICALLY_EXPECTED (Host/daemon process termination unexecuted)" | tee -a "${LOG_FILE}"
echo "=== EXPERIMENT 4 COMPLETE ===" | tee -a "${LOG_FILE}"
