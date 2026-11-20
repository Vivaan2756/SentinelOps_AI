#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B — Experiment B: Functional Seccomp Compatibility Test
# Tests real executor container with the minimal restrictive seccomp profile.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/experiment_b_seccomp.log"

SECCOMP_STRICT="${SCRIPT_DIR}/seccomp_profile_strict.json"
SECCOMP_AUDIT="${SCRIPT_DIR}/seccomp_profile_audit.json"

echo "=== EXPERIMENT B: FUNCTIONAL SECCOMP PROFILE TESTING ===" | tee "${LOG_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${LOG_FILE}"

IMAGE_NAME="sentinelops-executor:spike"
MOCK_SERVER_NAME="sentinelops-mock-target"
MOCK_NET="sentinelops-spike-net-b"

cleanup() {
    echo -e "\n[CLEANUP] Stopping mock server and test networks..." | tee -a "${LOG_FILE}"
    docker rm -f "${MOCK_SERVER_NAME}" 2>/dev/null || true
    docker network rm "${MOCK_NET}" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# 1. Build Executor Image
echo -e "\n[1] Building Executor Image from services/executor/Dockerfile..." | tee -a "${LOG_FILE}"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/services/executor/Dockerfile" "${REPO_ROOT}/services/executor" | tee -a "${LOG_FILE}"

# 2. Setup Isolated Network & Disposable Mock HTTP Service
echo -e "\n[2] Setting up disposable test network and mock service..." | tee -a "${LOG_FILE}"
docker network create "${MOCK_NET}" | tee -a "${LOG_FILE}"

# Run a lightweight python HTTP mock service in background
docker run -d --name "${MOCK_SERVER_NAME}" --network "${MOCK_NET}" python:3.13-alpine python3 -c '
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "restored", "message": "demo service healthy"}).encode())

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "healthy"}).encode())

server = HTTPServer(("0.0.0.0", 8001), Handler)
server.serve_forever()
' | tee -a "${LOG_FILE}"

# Determine Mock Service IP
MOCK_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${MOCK_SERVER_NAME}")
echo "Mock Target Service IP: ${MOCK_IP}:8001" | tee -a "${LOG_FILE}"

# 3. Test 1: restore_order_api_demo with Strict Seccomp Profile
echo -e "\n[3] Testing 'restore_order_api_demo' under STRICT seccomp profile..." | tee -a "${LOG_FILE}"
set +e
docker run --rm \
    --network "${MOCK_NET}" \
    --security-opt "seccomp=${SECCOMP_STRICT}" \
    -e ACTION_ID="restore_order_api_demo" \
    -e TARGET_URL="http://${MOCK_IP}:8001/demo/restore" \
    -e PINNED_IP="${MOCK_IP}" \
    -e TARGET_HOST="${MOCK_IP}" \
    -e TARGET_PORT="8001" \
    -e TARGET_SCHEME="http" \
    -e TARGET_PATH="/demo/restore" \
    -e ENVIRONMENT="development" \
    "${IMAGE_NAME}" > "${OUTPUT_DIR}/restore_demo_output.json" 2>&1
RESTORE_EXIT=$?
set -e

echo "Exit Code: ${RESTORE_EXIT}" | tee -a "${LOG_FILE}"
cat "${OUTPUT_DIR}/restore_demo_output.json" | tee -a "${LOG_FILE}"
if [ "${RESTORE_EXIT}" -eq 0 ]; then
    echo "TEST 1 VERDICT: PASSED (restore_order_api_demo compatible with strict seccomp)" | tee -a "${LOG_FILE}"
else
    echo "TEST 1 VERDICT: FAILED (syscall blocked or unexpected exit)" | tee -a "${LOG_FILE}"
fi

# 4. Test 2: inspect_service_health with Strict Seccomp Profile
echo -e "\n[4] Testing 'inspect_service_health' under STRICT seccomp profile..." | tee -a "${LOG_FILE}"
set +e
docker run --rm \
    --network "${MOCK_NET}" \
    --security-opt "seccomp=${SECCOMP_STRICT}" \
    -e ACTION_ID="inspect_service_health" \
    -e TARGET_URL="http://${MOCK_IP}:8001/health" \
    -e PINNED_IP="${MOCK_IP}" \
    -e TARGET_HOST="${MOCK_IP}" \
    -e TARGET_PORT="8001" \
    -e TARGET_SCHEME="http" \
    -e TARGET_PATH="/health" \
    -e ENVIRONMENT="development" \
    -e PARAMETERS_JSON='{"health_path": "/health", "is_demo_service": false}' \
    "${IMAGE_NAME}" > "${OUTPUT_DIR}/inspect_health_output.json" 2>&1
INSPECT_EXIT=$?
set -e

echo "Exit Code: ${INSPECT_EXIT}" | tee -a "${LOG_FILE}"
cat "${OUTPUT_DIR}/inspect_health_output.json" | tee -a "${LOG_FILE}"
if [ "${INSPECT_EXIT}" -eq 0 ]; then
    echo "TEST 2 VERDICT: PASSED (inspect_service_health compatible with strict seccomp)" | tee -a "${LOG_FILE}"
else
    echo "TEST 2 VERDICT: FAILED (syscall blocked or unexpected exit)" | tee -a "${LOG_FILE}"
fi

# 5. Test 3: Prohibited Operation Under Strict Seccomp (fork / execve / shell)
echo -e "\n[5] Testing Prohibited Operation (attempting execve / /bin/sh override)..." | tee -a "${LOG_FILE}"
set +e
docker run --rm \
    --network "${MOCK_NET}" \
    --security-opt "seccomp=${SECCOMP_STRICT}" \
    --entrypoint "/bin/sh" \
    "${IMAGE_NAME}" -c "echo 'BREACH: shell executed'" > "${OUTPUT_DIR}/prohibited_output.txt" 2>&1
PROHIBITED_EXIT=$?
set -e

echo "Exit Code: ${PROHIBITED_EXIT}" | tee -a "${LOG_FILE}"
cat "${OUTPUT_DIR}/prohibited_output.txt" | tee -a "${LOG_FILE}"
if [ "${PROHIBITED_EXIT}" -ne 0 ]; then
    echo "TEST 3 VERDICT: PASSED (execve / shell invocation blocked by seccomp as required)" | tee -a "${LOG_FILE}"
else
    echo "TEST 3 VERDICT: FAILED (prohibited shell execution succeeded!)" | tee -a "${LOG_FILE}"
fi

echo -e "\n=== EXPERIMENT B COMPLETE ===" | tee -a "${LOG_FILE}"
