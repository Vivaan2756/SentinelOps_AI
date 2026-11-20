#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B — Environment Assessment Probe
# Inspects and records all kernel, Docker, netfilter, and namespace parameters.
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="$(dirname "$0")/output"
mkdir -p "${OUTPUT_DIR}"
REPORT_FILE="${OUTPUT_DIR}/env_assessment.txt"

echo "=== SENTINELOPS ENVIRONMENT ASSESSMENT ===" | tee "${REPORT_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${REPORT_FILE}"
echo "----------------------------------------" | tee -a "${REPORT_FILE}"

# 1. Linux Distribution and Version
echo "[1] OS / Distribution:" | tee -a "${REPORT_FILE}"
if [ -f /etc/os-release ]; then
    cat /etc/os-release | grep -E '^(PRETTY_NAME|NAME|VERSION|ID)=' | tee -a "${REPORT_FILE}"
else
    uname -s | tee -a "${REPORT_FILE}"
fi

# 2. Kernel Version
echo -e "\n[2] Kernel Version:" | tee -a "${REPORT_FILE}"
uname -r -v -m | tee -a "${REPORT_FILE}"

# 3. Environment Classification (Dedicated Linux Host vs WSL2 vs Container)
echo -e "\n[3] Host Environment Classification:" | tee -a "${REPORT_FILE}"
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "CLASSIFICATION: WSL2 (Windows Subsystem for Linux)" | tee -a "${REPORT_FILE}"
    echo "WARNING: WSL2 environment detected. Experiments here DO NOT satisfy dedicated Ubuntu 22.04 LTS host acceptance criteria." | tee -a "${REPORT_FILE}"
elif [ -f /.dockerenv ]; then
    echo "CLASSIFICATION: Containerized Environment (Docker-in-Docker / Container)" | tee -a "${REPORT_FILE}"
elif systemd-detect-virt -q 2>/dev/null; then
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    echo "CLASSIFICATION: Virtualized Linux Host (${VIRT_TYPE})" | tee -a "${REPORT_FILE}"
else
    echo "CLASSIFICATION: Dedicated Bare-Metal Linux Host" | tee -a "${REPORT_FILE}"
fi

# 4. Docker Engine Version & Status
echo -e "\n[4] Docker Engine:" | tee -a "${REPORT_FILE}"
if command -v docker >/dev/null 2>&1; then
    docker version 2>&1 | tee -a "${REPORT_FILE}" || echo "Docker CLI found but daemon unreachable." | tee -a "${REPORT_FILE}"
    echo -e "\nDocker Info Security Profile:" | tee -a "${REPORT_FILE}"
    docker info 2>/dev/null | grep -E '(Security Options|Cgroup Driver|Storage Driver|Server Version|Runtimes)' | tee -a "${REPORT_FILE}" || true
else
    echo "Docker CLI not found." | tee -a "${REPORT_FILE}"
fi

# 5. Linux Capabilities
echo -e "\n[5] Available Capabilities:" | tee -a "${REPORT_FILE}"
if command -v capsh >/dev/null 2>&1; then
    capsh --print | grep -E '(Bounding set|Current|Securebits|uid)' | tee -a "${REPORT_FILE}"
else
    echo "capsh not available; current UID: $(id -u)" | tee -a "${REPORT_FILE}"
fi

# 6. iptables & ip6tables Versions
echo -e "\n[6] iptables & ip6tables:" | tee -a "${REPORT_FILE}"
if command -v iptables >/dev/null 2>&1; then
    iptables --version | tee -a "${REPORT_FILE}"
else
    echo "iptables not installed." | tee -a "${REPORT_FILE}"
fi
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables --version | tee -a "${REPORT_FILE}"
else
    echo "ip6tables not installed." | tee -a "${REPORT_FILE}"
fi

# 7. nftables Availability
echo -e "\n[7] nftables:" | tee -a "${REPORT_FILE}"
if command -v nft >/dev/null 2>&1; then
    nft --version | tee -a "${REPORT_FILE}"
else
    echo "nftables (nft) not installed." | tee -a "${REPORT_FILE}"
fi

# 8. Netfilter Modules & br_netfilter Status
echo -e "\n[8] Netfilter Kernel Modules:" | tee -a "${REPORT_FILE}"
lsmod | grep -E '(ip_tables|iptable_filter|nf_|netfilter|br_netfilter|bridge)' | tee -a "${REPORT_FILE}" || echo "No netfilter modules found in lsmod." | tee -a "${REPORT_FILE}"

echo -e "\nbr_netfilter sysctl status:" | tee -a "${REPORT_FILE}"
sysctl net.bridge.bridge-nf-call-iptables 2>/dev/null || echo "net.bridge.bridge-nf-call-iptables unavailable." | tee -a "${REPORT_FILE}"
sysctl net.bridge.bridge-nf-call-ip6tables 2>/dev/null || echo "net.bridge.bridge-nf-call-ip6tables unavailable." | tee -a "${REPORT_FILE}"

# 9. Namespace Capabilities
echo -e "\n[9] Network & Mount Namespace Support:" | tee -a "${REPORT_FILE}"
if [ -d /proc/$$/ns ]; then
    ls -l /proc/$$/ns | grep -E '(net|mnt|user|pid)' | tee -a "${REPORT_FILE}"
else
    echo "/proc/$$/ns not available." | tee -a "${REPORT_FILE}"
fi

echo -e "\n=== ASSESSMENT COMPLETE. Saved to ${REPORT_FILE} ==="
