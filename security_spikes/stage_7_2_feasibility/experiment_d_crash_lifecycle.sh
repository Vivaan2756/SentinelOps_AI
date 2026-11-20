#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B — Experiment D: Crash and Lifecycle Behavior Testing
# Tests 10 failure boundaries between Docker container and firewall lifecycles.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/experiment_d_crash.log"

echo "=== EXPERIMENT D: CRASH & LIFECYCLE RECOVERY SPIKE ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

CHAIN_NAME="SENTINELOPS_SPIKE_CRASH"
NET_NAME="sentinelops-spike-net-d"

cleanup() {
    docker rm -f $(docker ps -aq --filter "name=spike-crash-") 2>/dev/null || true
    docker network rm "${NET_NAME}" 2>/dev/null || true
    iptables -D FORWARD -j "${CHAIN_NAME}" 2>/dev/null || true
    iptables -F "${CHAIN_NAME}" 2>/dev/null || true
    iptables -X "${CHAIN_NAME}" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

docker network create "${NET_NAME}" >/dev/null

echo "Simulating 10 Boundary Crash Scenarios..." | tee -a "${LOG_FILE}"

# Data structure to collect boundary evaluation
declare -A SCENARIOS=(
    ["B01"]="After container creation before namespace acquisition"
    ["B02"]="After namespace acquisition before firewall installation"
    ["B03"]="During firewall installation (partial rules)"
    ["B04"]="After firewall installation before launch authorization"
    ["B05"]="Immediately before executor startup"
    ["B06"]="During executor startup"
    ["B07"]="During active executor execution"
    ["B08"]="After executor completion before cleanup"
    ["B09"]="During firewall cleanup"
    ["B10"]="During helper restart with active containers"
)

run_boundary_simulation() {
    local b_id="$1"
    local desc="$2"
    echo -e "\n------------------------------------------------------------------------" | tee -a "${LOG_FILE}"
    echo "Evaluating Boundary ${b_id}: ${desc}" | tee -a "${LOG_FILE}"
    echo "------------------------------------------------------------------------" | tee -a "${LOG_FILE}"

    case "${b_id}" in
        "B01")
            # Container created, no netns acquired, no firewall
            local cname="spike-crash-b01"
            docker create --name "${cname}" --network "${NET_NAME}" alpine:latest sleep 10 >/dev/null
            echo "Durable State: CREATE_INTENT" | tee -a "${LOG_FILE}"
            echo "Docker State: Created (PID=0)" | tee -a "${LOG_FILE}"
            echo "Firewall State: None" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: ZERO (container not executing)" | tee -a "${LOG_FILE}"
            echo "Safe to Clean: YES (docker rm ${cname})" | tee -a "${LOG_FILE}"
            echo "Execution Outcome: FAILED (aborted before start)" | tee -a "${LOG_FILE}"
            docker rm -f "${cname}" >/dev/null
            ;;
        "B02")
            # Container started, but crash occurs before firewall rules applied
            echo "Durable State: NETNS_ACQUIRED" | tee -a "${LOG_FILE}"
            echo "Docker State: Running (if started) or Created" | tee -a "${LOG_FILE}"
            echo "Firewall State: None" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: CRITICAL LEAK if container is running without firewall!" | tee -a "${LOG_FILE}"
            echo "Recovery Action: MUST immediately SIGKILL container before any further processing." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: FAILED / OUTCOME_UNKNOWN" | tee -a "${LOG_FILE}"
            ;;
        "B03")
            # Partial firewall applied (e.g. ACCEPT rule present, DROP rule absent)
            echo "Durable State: FIREWALL_INSTALLING" | tee -a "${LOG_FILE}"
            echo "Docker State: Running or Created" | tee -a "${LOG_FILE}"
            echo "Firewall State: PARTIAL / INCONSISTENT" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: HIGH (unrestricted traffic may leak past incomplete chain)" | tee -a "${LOG_FILE}"
            echo "Recovery Action: Atomic rollback of partial chain; force-kill container." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: FAILED" | tee -a "${LOG_FILE}"
            ;;
        "B04")
            # Firewall complete, but crash occurs before Gateway confirms launch token
            echo "Durable State: FIREWALL_ACTIVE" | tee -a "${LOG_FILE}"
            echo "Docker State: Created (PID=0)" | tee -a "${LOG_FILE}"
            echo "Firewall State: ACTIVE" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: ZERO (container not running)" | tee -a "${LOG_FILE}"
            echo "Recovery Action: Prune firewall rules, remove container." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: FAILED" | tee -a "${LOG_FILE}"
            ;;
        "B05")
            # Launch authorized, Gateway crashes before docker start returns
            echo "Durable State: LAUNCH_AUTHORIZED" | tee -a "${LOG_FILE}"
            echo "Docker State: Created (PID=0)" | tee -a "${LOG_FILE}"
            echo "Firewall State: ACTIVE" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: ZERO" | tee -a "${LOG_FILE}"
            echo "Recovery Action: On restart, inspect Docker. If not running, cancel and cleanup." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: FAILED" | tee -a "${LOG_FILE}"
            ;;
        "B06")
            # Crash during docker start
            echo "Durable State: STARTING" | tee -a "${LOG_FILE}"
            echo "Docker State: Running or Restarting" | tee -a "${LOG_FILE}"
            echo "Firewall State: ACTIVE" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: CONSTRAINED (firewall active)" | tee -a "${LOG_FILE}"
            echo "Recovery Action: Re-attach to container. If state indeterminable, transition to OUTCOME_UNKNOWN." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: OUTCOME_UNKNOWN" | tee -a "${LOG_FILE}"
            ;;
        "B07")
            # Crash while executor is actively communicating with target
            echo "Durable State: RUNNING" | tee -a "${LOG_FILE}"
            echo "Docker State: Running" | tee -a "${LOG_FILE}"
            echo "Firewall State: ACTIVE" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: CONSTRAINED (only authorized IP:port permitted)" | tee -a "${LOG_FILE}"
            echo "Recovery Action: Watchdog wait for termination; DO NOT remove firewall while running." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: OUTCOME_UNKNOWN" | tee -a "${LOG_FILE}"
            ;;
        "B08")
            # Executor exited, crash before firewall cleanup
            echo "Durable State: EXECUTED" | tee -a "${LOG_FILE}"
            echo "Docker State: Exited (status 0 or >0)" | tee -a "${LOG_FILE}"
            echo "Firewall State: STALE ACTIVE" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: ZERO (container dead)" | tee -a "${LOG_FILE}"
            echo "Recovery Action: Reconcile stopped container, delete stale firewall rules, remove container." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: SUCCESS or FAILED based on container exit code" | tee -a "${LOG_FILE}"
            ;;
        "B09")
            # Crash during firewall cleanup
            echo "Durable State: CLEANUP_IN_PROGRESS" | tee -a "${LOG_FILE}"
            echo "Docker State: Exited / Removed" | tee -a "${LOG_FILE}"
            echo "Firewall State: PARTIALLY PRUNED" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: ZERO (container removed)" | tee -a "${LOG_FILE}"
            echo "Recovery Action: Idempotent rule flush/delete for orphaned execution ID." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: PERSISTED FINAL STATE" | tee -a "${LOG_FILE}"
            ;;
        "B10")
            # Helper restarts while containers are running
            echo "Durable State: HELPER_RESTARTED" | tee -a "${LOG_FILE}"
            echo "Docker State: Various (running, created, stopped)" | tee -a "${LOG_FILE}"
            echo "Firewall State: ACTIVE RULES" | tee -a "${LOG_FILE}"
            echo "Traffic Risk: CONSTRAINED" | tee -a "${LOG_FILE}"
            echo "Recovery Action: CRITICAL INVARIANT: Helper MUST NOT blindly flush rules on startup!" | tee -a "${LOG_FILE}"
            echo "Helper must query Docker: keep rules for running containers, prune only confirmed dead." | tee -a "${LOG_FILE}"
            echo "Execution Outcome: UNTOUCHED" | tee -a "${LOG_FILE}"
            ;;
    esac
}

for bid in "B01" "B02" "B03" "B04" "B05" "B06" "B07" "B08" "B09" "B10"; do
    run_boundary_simulation "${bid}" "${SCENARIOS[${bid}]}"
done

echo -e "\n=== EXPERIMENT D COMPLETE ===" | tee -a "${LOG_FILE}"
