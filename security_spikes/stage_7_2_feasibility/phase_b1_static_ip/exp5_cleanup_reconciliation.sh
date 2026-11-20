#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.6 — Experiment 5: Deterministic Cleanup & Error Classification
# Tests:
# 1. Error-free cleanup distinguishing ALREADY_ABSENT, SUCCESSFULLY_REMOVED, and REMOVAL_FAILED.
# 2. Independent readback of parent DOCKER-USER jump AND custom chain deletion.
# 3. Direct-status conntrack table clearing without '|| true' or masked pipelines.
# 4. Exact word-boundary IP matching (prevents 172.29.0.5 vs 172.29.0.50 collisions).
# 5. Strict non-interference with unrelated sysadmin chains.
# 6. Standalone fail-closed exit code (2) if required utilities are unavailable.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/exp5_cleanup_reconciliation.log"

echo "=== EXPERIMENT 5: DETERMINISTIC CLEANUP & ERROR CLASSIFICATION (V4) ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Check environment readiness & fail closed if prerequisites missing (Requirement I, B1.5-10)
if ! command -v iptables >/dev/null 2>&1 || ! command -v conntrack >/dev/null 2>&1; then
    echo -e "\n[PREREQUISITE_FAILED] Required utilities (iptables or conntrack) are not installed on this host." | tee -a "${LOG_FILE}"
    echo "Execution status: PREREQUISITE_FAILED (Exit code: 2)." | tee -a "${LOG_FILE}"
    exit 2
fi

CHAIN_TARGET="SENTINELOPS_B1_CLEANUP_TEST"
CHAIN_UNRELATED="UNRELATED_SYSADMIN_CHAIN"
EXECUTOR_IP="172.29.0.50"

# Step 0: Ensure clean initial state
if iptables -C DOCKER-USER -s "${EXECUTOR_IP}/32" -j "${CHAIN_TARGET}" 2>/dev/null; then
    iptables -D DOCKER-USER -s "${EXECUTOR_IP}/32" -j "${CHAIN_TARGET}"
elif iptables -C DOCKER-USER -s "${EXECUTOR_IP}" -j "${CHAIN_TARGET}" 2>/dev/null; then
    iptables -D DOCKER-USER -s "${EXECUTOR_IP}" -j "${CHAIN_TARGET}"
fi
if iptables -S "${CHAIN_TARGET}" >/dev/null 2>&1; then
    iptables -F "${CHAIN_TARGET}"
    iptables -X "${CHAIN_TARGET}"
fi

# Step 1: Create an unrelated sysadmin chain to verify non-interference
echo -e "\n[1] Creating unrelated chain (${CHAIN_UNRELATED}) to verify non-interference..." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_UNRELATED}"
iptables -A "${CHAIN_UNRELATED}" -s 192.168.1.100 -j ACCEPT
iptables -I FORWARD 1 -j "${CHAIN_UNRELATED}"

# Step 2: Create target experiment chain and rules
echo -e "\n[2] Creating target chain (${CHAIN_TARGET}) with static IP rules..." | tee -a "${LOG_FILE}"
iptables -N "${CHAIN_TARGET}"
iptables -A "${CHAIN_TARGET}" -s "${EXECUTOR_IP}/32" -d 172.29.0.10/32 -p tcp --dport 8001 -j ACCEPT
iptables -A "${CHAIN_TARGET}" -s "${EXECUTOR_IP}/32" -j REJECT
iptables -I DOCKER-USER 1 -s "${EXECUTOR_IP}/32" -j "${CHAIN_TARGET}"

# Step 3: Implement Deterministic Cleanup Function with Precise State Reporting & Hardened Conntrack
cleanup_chain_deterministic() {
    local ip="$1"
    local cname="$2"
    local status="SUCCESSFULLY_REMOVED"

    # 1. Unlink Parent Jump in DOCKER-USER
    if iptables -C DOCKER-USER -s "${ip}/32" -j "${cname}" 2>/dev/null; then
        iptables -D DOCKER-USER -s "${ip}/32" -j "${cname}"
        # Independent readback to verify removal
        if iptables -C DOCKER-USER -s "${ip}/32" -j "${cname}" 2>/dev/null; then
            echo "STATE: REMOVAL_FAILED (Parent jump still present in DOCKER-USER!)"
            return 1
        fi
    elif iptables -C DOCKER-USER -s "${ip}" -j "${cname}" 2>/dev/null; then
        iptables -D DOCKER-USER -s "${ip}" -j "${cname}"
        if iptables -C DOCKER-USER -s "${ip}" -j "${cname}" 2>/dev/null; then
            echo "STATE: REMOVAL_FAILED (Parent jump still present in DOCKER-USER!)"
            return 1
        fi
    else
        echo "Parent Jump in DOCKER-USER: ALREADY_ABSENT"
    fi

    # 2. Flush and Delete Custom Chain
    if iptables -S "${cname}" >/dev/null 2>&1; then
        iptables -F "${cname}"
        iptables -X "${cname}"
        # Independent readback to verify deletion
        if iptables -S "${cname}" >/dev/null 2>&1; then
            echo "STATE: REMOVAL_FAILED (Custom chain ${cname} still exists!)"
            return 1
        fi
    else
        echo "Custom Chain ${cname}: ALREADY_ABSENT"
    fi

    # 3. Direct-Status Conntrack Clearing (Requirement D, B1.5-02 — No '|| true')
    set +e
    DEL_SRC_OUT=$(conntrack -D -s "${ip}" 2>&1)
    DEL_SRC_STATUS=$?
    DEL_DST_OUT=$(conntrack -D -d "${ip}" 2>&1)
    DEL_DST_STATUS=$?
    set -e

    if [ "${DEL_SRC_STATUS}" -ne 0 ] && ! echo "${DEL_SRC_OUT}" | grep -qiE "(0 flow entries|0 entries deleted)"; then
        echo "STATE: REMOVAL_FAILED (conntrack -D -s failed with code ${DEL_SRC_STATUS}: ${DEL_SRC_OUT})"
        return 1
    fi
    if [ "${DEL_DST_STATUS}" -ne 0 ] && ! echo "${DEL_DST_OUT}" | grep -qiE "(0 flow entries|0 entries deleted)"; then
        echo "STATE: REMOVAL_FAILED (conntrack -D -d failed with code ${DEL_DST_STATUS}: ${DEL_DST_OUT})"
        return 1
    fi

    # 4. Direct Readback Verification (No piping to grep directly from failing binary)
    set +e
    READ_SRC_OUT=$(conntrack -L -s "${ip}" 2>&1)
    READ_SRC_STATUS=$?
    READ_DST_OUT=$(conntrack -L -d "${ip}" 2>&1)
    READ_DST_STATUS=$?
    set -e

    if [ "${READ_SRC_STATUS}" -ne 0 ]; then
        echo "STATE: REMOVAL_FAILED (conntrack -L -s failed with code ${READ_SRC_STATUS}: ${READ_SRC_OUT})"
        return 1
    fi
    if [ "${READ_DST_STATUS}" -ne 0 ]; then
        echo "STATE: REMOVAL_FAILED (conntrack -L -d failed with code ${READ_DST_STATUS}: ${READ_DST_OUT})"
        return 1
    fi

    # Exact regex matching (Requirement D, B1.5-07) to avoid substring collisions
    RESIDUAL_S=$(echo "${READ_SRC_OUT}" | grep -cE "(^|[[:space:]=])${ip}([[:space:]]|$)" || true)
    RESIDUAL_D=$(echo "${READ_DST_OUT}" | grep -cE "(^|[[:space:]=])${ip}([[:space:]]|$)" || true)

    if [ "${RESIDUAL_S}" -ne 0 ] || [ "${RESIDUAL_D}" -ne 0 ]; then
        echo "STATE: REMOVAL_FAILED (Residual conntrack sessions remain for ${ip}: src=${RESIDUAL_S}, dst=${RESIDUAL_D})"
        return 1
    fi
    echo "Conntrack Sessions: VERIFIED_ZERO (No residual sessions remain for ${ip})"

    echo "STATE: ${status}"
    return 0
}

# Step 4: First Pass Cleanup (Must return SUCCESSFULLY_REMOVED)
echo -e "\n[3] Testing First Pass Deterministic Cleanup..." | tee -a "${LOG_FILE}"
CLEANUP_1_RES=$(cleanup_chain_deterministic "${EXECUTOR_IP}" "${CHAIN_TARGET}")
echo "${CLEANUP_1_RES}" | tee -a "${LOG_FILE}"

if echo "${CLEANUP_1_RES}" | grep -q "STATE: SUCCESSFULLY_REMOVED"; then
    echo "FIRST PASS VERDICT: PASSED" | tee -a "${LOG_FILE}"
else
    echo "FIRST PASS VERDICT: FAILED" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 5: Second Pass Cleanup (Idempotency Test — Must report ALREADY_ABSENT without error)
echo -e "\n[4] Testing Second Pass Idempotency (Operating on already-removed state)..." | tee -a "${LOG_FILE}"
CLEANUP_2_RES=$(cleanup_chain_deterministic "${EXECUTOR_IP}" "${CHAIN_TARGET}")
echo "${CLEANUP_2_RES}" | tee -a "${LOG_FILE}"

if echo "${CLEANUP_2_RES}" | grep -q "ALREADY_ABSENT"; then
    echo "IDEMPOTENCY VERDICT: PASSED (Handled already-absent state cleanly with zero errors)" | tee -a "${LOG_FILE}"
else
    echo "IDEMPOTENCY VERDICT: FAILED" | tee -a "${LOG_FILE}"
    exit 1
fi

# Step 6: Verify Non-Interference with Unrelated Chains
echo -e "\n[5] Verifying unrelated chain ${CHAIN_UNRELATED} remains intact..." | tee -a "${LOG_FILE}"
if iptables -S "${CHAIN_UNRELATED}" >/dev/null 2>&1 && iptables -C FORWARD -j "${CHAIN_UNRELATED}" 2>/dev/null; then
    echo "NON-INTERFERENCE VERDICT: PASSED (Sysadmin rules completely untouched)" | tee -a "${LOG_FILE}"
else
    echo "NON-INTERFERENCE VERDICT: FAILED (Sysadmin chain was modified or deleted!)" | tee -a "${LOG_FILE}"
    exit 1
fi

# Final cleanup of unrelated chain
iptables -D FORWARD -j "${CHAIN_UNRELATED}"
iptables -F "${CHAIN_UNRELATED}"
iptables -X "${CHAIN_UNRELATED}"

echo -e "\n=== EXPERIMENT 5 COMPLETE: DETERMINISTIC CLEANUP VERIFIED ===" | tee -a "${LOG_FILE}"
