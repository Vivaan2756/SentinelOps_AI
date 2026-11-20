# SentinelOps Phase B: Stage 7.2 Linux Engineering Feasibility Spike

**Target Acceptance Environment:** Dedicated Ubuntu 22.04 LTS Linux Host with Docker Engine 24.x+
**Execution Mode:** Isolated Proof-of-Concept Experiments Only
**Authorization Status:** Stage 7.2 Architecture Revision 8 remains **BLOCKED**. Production implementation is **NOT AUTHORIZED**.

---

## Overview

This directory contains the complete, reproducible engineering feasibility spike test harness for SentinelOps Stage 7.2. It provides empirical verification for four unresolved technical areas:

1. **Experiment A:** Docker container network namespace access before executor startup (`experiment_a_netns_lifecycle.sh`, `experiment_a_netns_probe.py`).
2. **Experiment B:** Functional seccomp profile restrictions compatible with Python 3.13 executor runtime (`seccomp_profile_strict.json`, `experiment_b_seccomp_test.sh`).
3. **Experiment C:** Linux Netfilter host-level firewall enforcement and cleanup (`experiment_c_firewall_enforcement.sh`, `experiment_c_traffic_verifier.py`).
4. **Experiment D:** Crash and lifecycle coordination across container and firewall state boundaries (`experiment_d_crash_lifecycle.sh`).

---

## Directory Structure

```
security_spikes/stage_7_2_feasibility/
├── README.md                           # This documentation
├── harness_env_probe.sh                # Inspects host OS, kernel, netfilter, capabilities, Docker
├── experiment_a_netns_lifecycle.sh     # Tests Docker container creation vs network namespace presence
├── experiment_a_netns_probe.py         # Python ctypes probe testing setns(2) and CAP_SYS_ADMIN vs CAP_NET_ADMIN
├── seccomp_profile_strict.json         # Strict whitelist seccomp profile for executor
├── seccomp_profile_audit.json          # Audit mode profile (SCMP_ACT_LOG) for syscall profiling
├── experiment_b_seccomp_test.sh        # Executes real executor under strict seccomp
├── experiment_c_firewall_enforcement.sh# Isolated Netfilter iptables/nftables egress containment test
├── experiment_c_traffic_verifier.py    # Generates authorized vs unauthorized network packets
├── experiment_d_crash_lifecycle.sh     # Simulates 10 crash boundaries and tests recovery
└── run_all_feasibility_spikes.sh       # Master runner orchestrating all experiments on Ubuntu 22.04
```

---

## Prerequisites for Genuine Ubuntu 22.04 LTS Test Host

To run this test harness on the target environment:

```bash
# 1. Dedicated Ubuntu 22.04 LTS host (bare metal or dedicated Linux VM, NOT WSL/Docker Desktop)
sudo apt-get update && sudo apt-get install -y \
    docker.io \
    iptables \
    iproute2 \
    net-tools \
    tcpdump \
    python3 \
    python3-pip \
    libcap2-bin \
    seccomp \
    curl

# 2. Ensure docker service is running
sudo systemctl start docker

# 3. Ensure Netfilter bridge module is loaded
sudo modprobe br_netfilter
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
```

---

## Execution Instructions

```bash
# Make all scripts executable
chmod +x security_spikes/stage_7_2_feasibility/*.sh

# Run the complete spike suite (requires sudo for namespace and firewall operations)
cd security_spikes/stage_7_2_feasibility
sudo ./run_all_feasibility_spikes.sh
```

All test outputs, iptables states, and audit logs are recorded under:
`security_spikes/stage_7_2_feasibility/output/`
