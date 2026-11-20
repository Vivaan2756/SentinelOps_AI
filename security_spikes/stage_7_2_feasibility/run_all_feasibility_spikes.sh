#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B — Master Feasibility Spike Orchestrator
# Runs all Phase B experimental spikes on a dedicated Ubuntu 22.04 LTS host.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
SUMMARY_FILE="${OUTPUT_DIR}/master_feasibility_summary.txt"

echo "========================================================================" | tee "${SUMMARY_FILE}"
echo "    SENTINELOPS STAGE 7.2 LINUX ENGINEERING FEASIBILITY SPIKE SUITE     " | tee -a "${SUMMARY_FILE}"
echo "========================================================================" | tee -a "${SUMMARY_FILE}"
date -u +"Start Time: %Y-%m-%dT%H:%M:%SZ" | tee -a "${SUMMARY_FILE}"

# Step 1: Environment Assessment Probe
echo -e "\n>>> RUNNING ENVIRONMENT ASSESSMENT PROBE <<<" | tee -a "${SUMMARY_FILE}"
"${SCRIPT_DIR}/harness_env_probe.sh" || echo "Environment probe exited with error."

# Step 2: Experiment A - Network Namespace Lifecycle
echo -e "\n>>> RUNNING EXPERIMENT A (NETNS LIFECYCLE) <<<" | tee -a "${SUMMARY_FILE}"
if "${SCRIPT_DIR}/experiment_a_netns_lifecycle.sh"; then
    echo "Experiment A Status: SUCCESS" | tee -a "${SUMMARY_FILE}"
else
    echo "Experiment A Status: FAILED" | tee -a "${SUMMARY_FILE}"
fi

# Step 3: Experiment B - Seccomp Compatibility
echo -e "\n>>> RUNNING EXPERIMENT B (SECCOMP RESTRICTIONS) <<<" | tee -a "${SUMMARY_FILE}"
if "${SCRIPT_DIR}/experiment_b_seccomp_test.sh"; then
    echo "Experiment B Status: SUCCESS" | tee -a "${SUMMARY_FILE}"
else
    echo "Experiment B Status: FAILED" | tee -a "${SUMMARY_FILE}"
fi

# Step 4: Experiment C - Firewall Enforcement
echo -e "\n>>> RUNNING EXPERIMENT C (FIREWALL ENFORCEMENT) <<<" | tee -a "${SUMMARY_FILE}"
if "${SCRIPT_DIR}/experiment_c_firewall_enforcement.sh"; then
    echo "Experiment C Status: SUCCESS" | tee -a "${SUMMARY_FILE}"
else
    echo "Experiment C Status: FAILED" | tee -a "${SUMMARY_FILE}"
fi

# Step 5: Experiment D - Crash and Lifecycle Behavior
echo -e "\n>>> RUNNING EXPERIMENT D (CRASH & LIFECYCLE BOUNDARIES) <<<" | tee -a "${SUMMARY_FILE}"
if "${SCRIPT_DIR}/experiment_d_crash_lifecycle.sh"; then
    echo "Experiment D Status: SUCCESS" | tee -a "${SUMMARY_FILE}"
else
    echo "Experiment D Status: FAILED" | tee -a "${SUMMARY_FILE}"
fi

echo -e "\n========================================================================" | tee -a "${SUMMARY_FILE}"
echo "                   ALL FEASIBILITY SPIKES COMPLETED                     " | tee -a "${SUMMARY_FILE}"
echo "========================================================================" | tee -a "${SUMMARY_FILE}"
date -u +"Completion Time: %Y-%m-%dT%H:%M:%SZ" | tee -a "${SUMMARY_FILE}"
echo "Detailed logs available in: ${OUTPUT_DIR}/" | tee -a "${SUMMARY_FILE}"
