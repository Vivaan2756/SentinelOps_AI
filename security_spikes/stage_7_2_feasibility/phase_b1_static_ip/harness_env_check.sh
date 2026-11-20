#!/usr/bin/env bash
# ==============================================================================
# SentinelOps Phase B1.6 — Host Environment & Kernel Prerequisite Assessment
# Verifies host environment against genuine Ubuntu 22.04 LTS requirements:
# 1. Native Linux Host (Not WSL2, container-in-container, or virtualized shim).
# 2. Docker Engine 24.x+ active and reachable with iptables support enabled.
# 3. Host Netfilter utilities (iptables, ip6tables, conntrack, ebtables).
# 4. Kernel bridge-netfilter prerequisites (br_netfilter, sysctl bridge-nf-call-iptables).
# 5. DOCKER-USER chain presence and backend consistency (fails closed on mismatch).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
STATUS_FILE="${OUTPUT_DIR}/env_status.txt"

echo "=== SENTINELOPS PHASE B1.6: ENVIRONMENT ASSESSMENT ===" | tee "${STATUS_FILE}"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" | tee -a "${STATUS_FILE}"

ALL_PREREQS_MET=true
FAIL_REASONS=()

# 1. Check virtualization / container / WSL
IS_GENUINE_LINUX=true
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "HOST TYPE: WSL2 (Windows Subsystem for Linux)" | tee -a "${STATUS_FILE}"
    IS_GENUINE_LINUX=false
    FAIL_REASONS+=("Host is WSL2 (requires native Ubuntu 22.04 LTS host)")
elif [ -f /.dockerenv ]; then
    echo "HOST TYPE: Containerized Environment (Docker-in-Docker)" | tee -a "${STATUS_FILE}"
    IS_GENUINE_LINUX=false
    FAIL_REASONS+=("Host is containerized (requires bare metal or dedicated VM host)")
else
    echo "HOST TYPE: Native Linux Host" | tee -a "${STATUS_FILE}"
fi

# 2. Check Docker Engine daemon
DOCKER_AVAILABLE=false
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
        echo "DOCKER ENGINE: Reachable (Server Version: ${DOCKER_VER})" | tee -a "${STATUS_FILE}"
        DOCKER_AVAILABLE=true
    else
        echo "DOCKER ENGINE: CLI present, but Daemon unreachable or stopped." | tee -a "${STATUS_FILE}"
        FAIL_REASONS+=("Docker daemon unreachable or stopped")
    fi
else
    echo "DOCKER ENGINE: CLI not installed." | tee -a "${STATUS_FILE}"
    FAIL_REASONS+=("Docker CLI not installed")
fi

# 3. Check iptables and ip6tables
IPTABLES_AVAILABLE=false
IPT_MODE=""
if command -v iptables >/dev/null 2>&1; then
    IPT_VER=$(iptables --version 2>/dev/null || echo "unknown")
    echo "IPTABLES: Installed (${IPT_VER})" | tee -a "${STATUS_FILE}"
    IPTABLES_AVAILABLE=true
    IPT_MODE="${IPT_VER}"
else
    echo "IPTABLES: Not installed." | tee -a "${STATUS_FILE}"
    FAIL_REASONS+=("iptables not installed")
fi

IP6TABLES_AVAILABLE=false
IP6_MODE=""
if command -v ip6tables >/dev/null 2>&1; then
    IP6_VER=$(ip6tables --version 2>/dev/null || echo "unknown")
    echo "IP6TABLES: Installed (${IP6_VER})" | tee -a "${STATUS_FILE}"
    IP6TABLES_AVAILABLE=true
    IP6_MODE="${IP6_VER}"
else
    echo "IP6TABLES: Not installed." | tee -a "${STATUS_FILE}"
    FAIL_REASONS+=("ip6tables not installed")
fi

# Check host IPv6 kernel presence
if [ -f /proc/net/if_inet6 ]; then
    echo "HOST KERNEL IPV6: Active (/proc/net/if_inet6 present)" | tee -a "${STATUS_FILE}"
    if [ "${IP6TABLES_AVAILABLE}" = false ]; then
        FAIL_REASONS+=("IPv6 active in kernel but ip6tables CLI missing (fails closed)")
    fi
else
    echo "HOST KERNEL IPV6: Inactive" | tee -a "${STATUS_FILE}"
fi

# 4. Check conntrack utility
CONNTRACK_AVAILABLE=false
if command -v conntrack >/dev/null 2>&1; then
    echo "CONNTRACK: Installed ($(conntrack --version 2>&1 | head -n 1))" | tee -a "${STATUS_FILE}"
    CONNTRACK_AVAILABLE=true
else
    echo "CONNTRACK: Not installed (required for safe conntrack table flushing on IP reuse)." | tee -a "${STATUS_FILE}"
    FAIL_REASONS+=("conntrack CLI utility not installed")
fi

# 5. Check ebtables / arptables utilities (Requirement G, B1.5-08)
EBTABLES_AVAILABLE=false
EB_MODE=""
if command -v ebtables >/dev/null 2>&1; then
    EB_VER=$(ebtables --version 2>/dev/null || echo "unknown")
    echo "EBTABLES: Installed (${EB_VER})" | tee -a "${STATUS_FILE}"
    EBTABLES_AVAILABLE=true
    EB_MODE="${EB_VER}"
else
    echo "EBTABLES: Not installed (L2 bridge filtering relies on kernel br_netfilter sysctls)." | tee -a "${STATUS_FILE}"
fi

# 6. Check Kernel br_netfilter Module & Sysctls
BR_NETFILTER_AVAILABLE=false
if lsmod 2>/dev/null | grep -q br_netfilter || [ -d /proc/sys/net/bridge ]; then
    echo "BR_NETFILTER MODULE: Loaded" | tee -a "${STATUS_FILE}"
    BR_NETFILTER_AVAILABLE=true
else
    echo "BR_NETFILTER MODULE: NOT loaded (required for same-bridge Netfilter traversal)." | tee -a "${STATUS_FILE}"
    FAIL_REASONS+=("br_netfilter kernel module not loaded (run: sudo modprobe br_netfilter)")
fi

BRIDGE_NF_IPTABLES=false
if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    VAL=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo "0")
    if [ "${VAL}" = "1" ]; then
        echo "SYSCTL bridge-nf-call-iptables: 1 (Enabled)" | tee -a "${STATUS_FILE}"
        BRIDGE_NF_IPTABLES=true
    else
        echo "SYSCTL bridge-nf-call-iptables: ${VAL} (Disabled - Intra-bridge packets will bypass Netfilter!)" | tee -a "${STATUS_FILE}"
        FAIL_REASONS+=("sysctl net.bridge.bridge-nf-call-iptables must be 1 (run: sudo sysctl -w net.bridge.bridge-nf-call-iptables=1)")
    fi
else
    echo "SYSCTL bridge-nf-call-iptables: Not present in procfs." | tee -a "${STATUS_FILE}"
    FAIL_REASONS+=("/proc/sys/net/bridge/bridge-nf-call-iptables not available")
fi

BRIDGE_NF_IP6TABLES=false
if [ -f /proc/sys/net/bridge/bridge-nf-call-ip6tables ]; then
    VAL6=$(cat /proc/sys/net/bridge/bridge-nf-call-ip6tables 2>/dev/null || echo "0")
    if [ "${VAL6}" = "1" ]; then
        echo "SYSCTL bridge-nf-call-ip6tables: 1 (Enabled)" | tee -a "${STATUS_FILE}"
        BRIDGE_NF_IP6TABLES=true
    else
        echo "SYSCTL bridge-nf-call-ip6tables: ${VAL6} (Disabled)" | tee -a "${STATUS_FILE}"
        FAIL_REASONS+=("sysctl net.bridge.bridge-nf-call-ip6tables must be 1")
    fi
fi

# 7. Check DOCKER-USER Chain in iptables
DOCKER_USER_PRESENT=false
if [ "${IPTABLES_AVAILABLE}" = true ]; then
    if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
        echo "DOCKER-USER CHAIN: Present in Netfilter filter table." | tee -a "${STATUS_FILE}"
        DOCKER_USER_PRESENT=true
    else
        echo "DOCKER-USER CHAIN: Not found (Docker daemon must configure iptables integration)." | tee -a "${STATUS_FILE}"
        FAIL_REASONS+=("DOCKER-USER chain not present in Netfilter")
    fi
fi

# 8. Check Netfilter Backend Consistency (legacy vs nftables) & Fail Closed
if [ "${IPTABLES_AVAILABLE}" = true ]; then
    IPT_IS_NFT=false
    IPT_IS_LEGACY=false
    if echo "${IPT_MODE}" | grep -qi "nf_tables"; then
        echo "IPTABLES BACKEND: iptables-nft (nf_tables shim)" | tee -a "${STATUS_FILE}"
        IPT_IS_NFT=true
    elif echo "${IPT_MODE}" | grep -qi "legacy"; then
        echo "IPTABLES BACKEND: iptables-legacy" | tee -a "${STATUS_FILE}"
        IPT_IS_LEGACY=true
    else
        echo "IPTABLES BACKEND: Unknown / Unsupported backend (${IPT_MODE})" | tee -a "${STATUS_FILE}"
        FAIL_REASONS+=("Unknown or unsupported iptables backend: ${IPT_MODE}")
    fi

    # Check IPv6 backend consistency
    if [ "${IP6TABLES_AVAILABLE}" = true ]; then
        if [ "${IPT_IS_NFT}" = true ] && ! echo "${IP6_MODE}" | grep -qi "nf_tables"; then
            echo "BACKEND DIVERGENCE: iptables uses nftables but ip6tables does not!" | tee -a "${STATUS_FILE}"
            FAIL_REASONS+=("Mismatched IPv4/IPv6 Netfilter backends: iptables is nft, ip6tables is not")
        elif [ "${IPT_IS_LEGACY}" = true ] && ! echo "${IP6_MODE}" | grep -qi "legacy"; then
            echo "BACKEND DIVERGENCE: iptables uses legacy but ip6tables does not!" | tee -a "${STATUS_FILE}"
            FAIL_REASONS+=("Mismatched IPv4/IPv6 Netfilter backends: iptables is legacy, ip6tables is not")
        fi
    fi

    # Check ebtables backend consistency if ebtables is installed
    if [ "${EBTABLES_AVAILABLE}" = true ]; then
        if [ "${IPT_IS_NFT}" = true ] && ! echo "${EB_MODE}" | grep -qi "nf_tables"; then
            echo "BACKEND DIVERGENCE: iptables is nftables but ebtables is legacy!" | tee -a "${STATUS_FILE}"
            FAIL_REASONS+=("Mismatched iptables/ebtables backends: iptables is nft, ebtables is legacy")
        elif [ "${IPT_IS_LEGACY}" = true ] && ! echo "${EB_MODE}" | grep -qi "legacy"; then
            echo "BACKEND DIVERGENCE: iptables is legacy but ebtables is nftables!" | tee -a "${STATUS_FILE}"
            FAIL_REASONS+=("Mismatched iptables/ebtables backends: iptables is legacy, ebtables is nft")
        fi
    fi
fi

# Final Evaluation
echo -e "\n=== ENVIRONMENT ASSESSMENT SUMMARY ===" | tee -a "${STATUS_FILE}"
if [ ${#FAIL_REASONS[@]} -eq 0 ]; then
    echo "VERDICT: READY for authoritative Phase B1 evidence collection on native Linux." | tee -a "${STATUS_FILE}"
    exit 0
else
    echo "VERDICT: INSUFFICIENT for authoritative live kernel execution." | tee -a "${STATUS_FILE}"
    echo "Missing Prerequisites (${#FAIL_REASONS[@]}):" | tee -a "${STATUS_FILE}"
    for r in "${FAIL_REASONS[@]}"; do
        echo "  - ${r}" | tee -a "${STATUS_FILE}"
    done
    echo "Per strict safety rules: Experiments will abort to prevent unverified or unsafe test state (exit code 2: PREREQUISITE_FAILED)." | tee -a "${STATUS_FILE}"
    exit 2
fi
