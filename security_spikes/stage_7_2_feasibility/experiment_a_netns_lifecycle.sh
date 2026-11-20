#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B — Experiment A: Docker Network Namespace Lifecycle
# Determines empirically whether a container's network namespace exists prior
# to container start, and how the host helper can access it.
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="$(dirname "$0")/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/experiment_a_netns.log"

echo "=== EXPERIMENT A: DOCKER NETWORK NAMESPACE LIFECYCLE ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

# Setup test network
NET_NAME="sentinelops-spike-net-a"
CONTAINER_NAME="sentinelops-spike-container-a"

cleanup() {
    echo -e "\n[CLEANUP] Removing test container and network..." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
    docker network rm "${NET_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

cleanup

echo -e "\n[1] Creating dedicated Docker bridge network: ${NET_NAME}" | tee -a "${LOG_FILE}"
docker network create --driver bridge "${NET_NAME}" | tee -a "${LOG_FILE}"

# ------------------------------------------------------------------------------
# Phase 1: Container Created (NOT Started)
# ------------------------------------------------------------------------------
echo -e "\n[2] Creating container WITHOUT starting: ${CONTAINER_NAME}" | tee -a "${LOG_FILE}"
docker create --name "${CONTAINER_NAME}" --network "${NET_NAME}" alpine:latest sleep 3600 | tee -a "${LOG_FILE}"

echo -e "\n[3] Inspecting created container metadata:" | tee -a "${LOG_FILE}"
CONTAINER_ID=$(docker inspect --format '{{.Id}}' "${CONTAINER_NAME}")
PID=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER_NAME}")
SANDBOX_KEY=$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "${CONTAINER_NAME}")
STATUS=$(docker inspect --format '{{.State.Status}}' "${CONTAINER_NAME}")

echo "Container ID: ${CONTAINER_ID}" | tee -a "${LOG_FILE}"
echo "Container Status: ${STATUS}" | tee -a "${LOG_FILE}"
echo "State.Pid: '${PID}'" | tee -a "${LOG_FILE}"
echo "NetworkSettings.SandboxKey: '${SANDBOX_KEY}'" | tee -a "${LOG_FILE}"

# Check /proc/<pid>/ns/net
if [ -z "${PID}" ] || [ "${PID}" = "0" ]; then
    echo "RESULT: State.Pid is 0. /proc/<pid>/ns/net DOES NOT EXIST in created state." | tee -a "${LOG_FILE}"
else
    if [ -f "/proc/${PID}/ns/net" ]; then
        echo "RESULT: /proc/${PID}/ns/net EXISTS." | tee -a "${LOG_FILE}"
    else
        echo "RESULT: PID is ${PID} but /proc/${PID}/ns/net does NOT exist." | tee -a "${LOG_FILE}"
    fi
fi

# Check Docker netns directory
echo -e "\nChecking /var/run/docker/netns:" | tee -a "${LOG_FILE}"
if [ -d /var/run/docker/netns ]; then
    ls -la /var/run/docker/netns | tee -a "${LOG_FILE}"
else
    echo "/var/run/docker/netns directory does not exist or unreadable without root." | tee -a "${LOG_FILE}"
fi

# Check SandboxKey accessibility
if [ -n "${SANDBOX_KEY}" ] && [ -e "${SANDBOX_KEY}" ]; then
    echo "RESULT: SandboxKey '${SANDBOX_KEY}' exists on host filesystem." | tee -a "${LOG_FILE}"
else
    echo "RESULT: SandboxKey is EMPTY or does not exist on filesystem in Created state." | tee -a "${LOG_FILE}"
fi

# Attempt to install rules or enter netns in created state
echo -e "\nTesting namespace entry in Created state:" | tee -a "${LOG_FILE}"
if [ -n "${SANDBOX_KEY}" ] && [ -e "${SANDBOX_KEY}" ]; then
    if nsenter --net="${SANDBOX_KEY}" ip link 2>&1 | tee -a "${LOG_FILE}"; then
        echo "Can enter netns via SandboxKey: YES" | tee -a "${LOG_FILE}"
    else
        echo "Can enter netns via SandboxKey: NO" | tee -a "${LOG_FILE}"
    fi
else
    echo "CRITICAL: Cannot enter netns in Created state because neither PID nor SandboxKey is accessible." | tee -a "${LOG_FILE}"
fi

# ------------------------------------------------------------------------------
# Phase 2: Container Started
# ------------------------------------------------------------------------------
echo -e "\n[4] Starting container: ${CONTAINER_NAME}" | tee -a "${LOG_FILE}"
docker start "${CONTAINER_NAME}" | tee -a "${LOG_FILE}"

PID_STARTED=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER_NAME}")
SANDBOX_KEY_STARTED=$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "${CONTAINER_NAME}")
STATUS_STARTED=$(docker inspect --format '{{.State.Status}}' "${CONTAINER_NAME}")

echo "Container Status: ${STATUS_STARTED}" | tee -a "${LOG_FILE}"
echo "State.Pid: '${PID_STARTED}'" | tee -a "${LOG_FILE}"
echo "NetworkSettings.SandboxKey: '${SANDBOX_KEY_STARTED}'" | tee -a "${LOG_FILE}"

if [ -f "/proc/${PID_STARTED}/ns/net" ]; then
    echo "RESULT: /proc/${PID_STARTED}/ns/net EXISTS after start." | tee -a "${LOG_FILE}"
    echo "Testing nsenter via /proc/${PID_STARTED}/ns/net:" | tee -a "${LOG_FILE}"
    nsenter --net="/proc/${PID_STARTED}/ns/net" ip link show | tee -a "${LOG_FILE}" || true
else
    echo "RESULT: /proc/${PID_STARTED}/ns/net NOT accessible after start." | tee -a "${LOG_FILE}"
fi

# ------------------------------------------------------------------------------
# Phase 3: Open File Descriptor Retention across Container Removal
# ------------------------------------------------------------------------------
echo -e "\n[5] Testing namespace descriptor pinning across container removal:" | tee -a "${LOG_FILE}"
if [ -f "/proc/${PID_STARTED}/ns/net" ]; then
    # Spawn background python process holding open fd to /proc/<pid>/ns/net
    python3 -c "
import os, time, sys
netns_path = f'/proc/${PID_STARTED}/ns/net'
try:
    fd = os.open(netns_path, os.O_RDONLY)
    print(f'Acquired open fd {fd} to {netns_path}', flush=True)
    time.sleep(10)
    os.close(fd)
    print('Closed fd', flush=True)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr, flush=True)
" >> "${LOG_FILE}" 2>&1 &
    HOLDER_PID=$!
    sleep 2

    echo "Attempting container removal while fd is held open..." | tee -a "${LOG_FILE}"
    docker rm -f "${CONTAINER_NAME}" | tee -a "${LOG_FILE}"

    echo "Checking holder process status..." | tee -a "${LOG_FILE}"
    if kill -0 "${HOLDER_PID}" 2>/dev/null; then
        echo "Holder process is still running with pinned netns fd." | tee -a "${LOG_FILE}"
        wait "${HOLDER_PID}" || true
    fi
    echo "Container successfully removed while netns fd was held open." | tee -a "${LOG_FILE}"
fi

# ------------------------------------------------------------------------------
# Phase 4: Summary Matrix Generation
# ------------------------------------------------------------------------------
echo -e "\n=== EXPERIMENT A LIFECYCLE SUMMARY ===" | tee -a "${LOG_FILE}"
cat << 'EOF' | tee -a "${LOG_FILE}"
| Container State | Network Namespace Exists? | Helper Can Access? | Safe to Install Rules? | Mechanism / Observation |
|---|---|---|---|---|
| Container Created | NO | NO | NO | State.Pid=0, SandboxKey="" or unmounted. Kernel netns not instantiated. |
| Container Started | YES | YES (via /proc/PID/ns/net or SandboxKey) | YES (but race condition: container already executing!) | Container process running; veth pair attached. |
| Container Stopped | NO / DISSOLVING | NO | NO | Process exits; netns torn down by Docker unless fd held. |
| Container Removed | NO | NO | NO | Sandbox destroyed. Residual open fd keeps struct net in memory until closed. |
| Helper Restarted | DEPENDS ON DOCKER | YES (if container running) | YES (reconcile against Docker State) | Must query Docker API before deleting rules. |
EOF

echo -e "\n=== EXPERIMENT A COMPLETE ==="
