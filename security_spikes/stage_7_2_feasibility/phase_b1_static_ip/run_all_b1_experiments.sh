#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.6 — Master Static-IP Experiment Orchestrator
# Runs all Phase B1 experimental spikes on a dedicated Ubuntu 22.04 LTS host:
#   Step 0: Comprehensive Host Environment & Kernel Prerequisite Check
#   Step 1: Exp 1 — Static IP Allocation & IPAM Carve-Out
#   Step 2: Exp 2 — Pre-Start Firewall Gate & Atomic Installation
#   Step 3: Exp 3 — Bypass Resistance & Gateway Policy Evaluation
#   Step 4: Exp DNS — Docker Embedded DNS (127.0.0.11) Deep Dive
#   Step 5: Exp 4 — Executable Crash Consistency & Fault Injection
#   Step 6: Exp 5 — Deterministic Cleanup & Error Classification
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
SUMMARY_FILE="${OUTPUT_DIR}/b1_master_summary.txt"

echo "========================================================================" | tee "${SUMMARY_FILE}"
echo "    SENTINELOPS PHASE B1.6 STATIC-IP FIREWALL FEASIBILITY SUITE (V4)    " | tee -a "${SUMMARY_FILE}"
echo "========================================================================" | tee -a "${SUMMARY_FILE}"
date -u +"Start Time: %Y-%m-%dT%H:%M:%SZ" | tee -a "${SUMMARY_FILE}"

# Step 0: Environment Check
echo -e "\n>>> STEP 0: CHECKING TEST ENVIRONMENT & PREREQUISITES <<<" | tee -a "${SUMMARY_FILE}"
set +e
"${SCRIPT_DIR}/harness_env_check.sh"
ENV_STATUS=$?
set -e

if [ "${ENV_STATUS}" -ne 0 ]; then
    echo -e "\n[PREREQUISITE FAILURE] Genuine Ubuntu 22.04 LTS Linux host running Docker Engine is UNAVAILABLE." | tee -a "${SUMMARY_FILE}"
    echo "Per strict safety rules:" | tee -a "${SUMMARY_FILE}"
    echo "  - Experiments are NOT executed on non-qualifying environments." | tee -a "${SUMMARY_FILE}"
    echo "  - Test harness is statically verified, but live kernel tests were SKIPPED." | tee -a "${SUMMARY_FILE}"
    echo "  - Exit code 2 returned to prevent automated systems from mistaking skipped runs for success." | tee -a "${SUMMARY_FILE}"
    echo "Summary completed with PREREQUISITE_FAILED status." | tee -a "${SUMMARY_FILE}"
    exit 2
fi

# Step 1: Run Experiment 1 (Static IP Allocation)
echo -e "\n>>> STEP 1: RUNNING EXPERIMENT 1: STATIC IP ALLOCATION <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/exp1_static_ip_allocation.sh" | tee -a "${SUMMARY_FILE}"

# Step 2: Run Experiment 2 (Pre-Start Firewall Gate)
echo -e "\n>>> STEP 2: RUNNING EXPERIMENT 2: PRE-START FIREWALL GATE <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/exp2_prestart_firewall_gate.sh" | tee -a "${SUMMARY_FILE}"

# Step 3: Run Experiment 3 (Bypass Resistance)
echo -e "\n>>> STEP 3: RUNNING EXPERIMENT 3: BYPASS RESISTANCE <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/exp3_bypass_resistance.sh" | tee -a "${SUMMARY_FILE}"

# Step 4: Run Experiment DNS (Embedded DNS Investigation)
echo -e "\n>>> STEP 4: RUNNING EXPERIMENT DNS: EMBEDDED DNS INVESTIGATION <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/exp_dns_investigation.sh" | tee -a "${SUMMARY_FILE}"

# Step 5: Run Experiment 4 (Crash Consistency & Fault Injection)
echo -e "\n>>> STEP 5: RUNNING EXPERIMENT 4: CRASH CONSISTENCY <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/exp4_crash_consistency.sh" | tee -a "${SUMMARY_FILE}"

# Step 6: Run Experiment 5 (Deterministic Cleanup & Reconciliation)
echo -e "\n>>> STEP 6: RUNNING EXPERIMENT 5: CLEANUP & RECONCILIATION <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/exp5_cleanup_reconciliation.sh" | tee -a "${SUMMARY_FILE}"

echo -e "\n========================================================================" | tee -a "${SUMMARY_FILE}"
echo "                 ALL PHASE B1.6 EXPERIMENTS COMPLETED                   " | tee -a "${SUMMARY_FILE}"
echo "========================================================================" | tee -a "${SUMMARY_FILE}"
date -u +"Completion Time: %Y-%m-%dT%H:%M:%SZ" | tee -a "${SUMMARY_FILE}"
