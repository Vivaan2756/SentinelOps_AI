# SentinelOps Phase B1.8: Static-IP Bridge Network Firewall Feasibility Spike (Hardened & Audited)

**Target Acceptance Environment:** Dedicated Ubuntu 22.04 LTS Linux Host with Docker Engine 24.x+
**Execution Mode:** Isolated Proof-of-Concept Experiments Only
**Architecture Status:** Stage 7.2 Architecture Revision 8 remains **BLOCKED**. Production implementation is **NOT AUTHORIZED**.

---

## Overview

Following the Phase B1.7 Independent Security Audit (`SENTINELOPS_PHASE_B1_7_INDEPENDENT_SECURITY_AUDIT.md`), this hardened feasibility harness resolves all audit findings (B1.7-01, B1.7-02, B1.7-03, B1.7-05, B1.7-06, B1.7-07):

1. **Exact Parent Jump Count & Command Status (B1.7-01):** `exp2_prestart_firewall_gate.sh` enforces that parent jumps in `DOCKER-USER` occur exactly once (`egress_count=1`, `ingress_count=1`) in addition to verifying positions 1 and 2, and captures command exit codes directly to fail closed on readback errors.
2. **Dynamic Cleanup Discovery & Parent Unlinking (B1.7-03):** `cleanup_firewall()` discovers actual parent-chain references in `FORWARD`, `INPUT`, and `DOCKER-USER` via kernel readback, deleting the exact installed rules even if `BRIDGE_DEV` is unset or empty, and verifies zero references before attempting chain deletion.
3. **Exp 2 Standalone Prerequisite Guard (B1.7-05):** `exp2_prestart_firewall_gate.sh` enforces standalone fail-closed behavior, exiting with code `2` (`PREREQUISITE_FAILED`) if Docker, iptables, or native Linux prerequisites are unmet.
4. **Harmonized Environment-Check Exit Code (B1.7-06):** `harness_env_check.sh` returns exit code `2` on prerequisite failures when invoked directly.
5. **Framed TCP DNS Query & Strict Aggregation (B1.7-07):** `traffic_probe.py` implements RFC 1035 length-prefixed DNS-over-TCP framing, removes the inert `pass` branch on Invariant 7, distinguishes connection to local embedded resolver (`127.0.0.11`) from external resolvers, and fails closed on `INCONCLUSIVE` or `RESOLVER_REJECTED`.

---

## Mandatory IPv6 Bridge Restriction & Architectural Limitations (B1.7-02)

> [!CAUTION]
> **EXPERIMENTAL CONTAINMENT NOTICE — DEDICATED BRIDGE ONLY:**
> The IPv6 drop rules in `exp2_prestart_firewall_gate.sh` operate interface-wide on the bridge (`ip6tables -I FORWARD 1 -i ${BRIDGE_DEV} -j ${CHAIN_V6}`).
>
> - **Exclusively Dedicated Bridge:** The test bridge (`sentinelops-b1-net2`) must be dedicated exclusively to this experiment.
> - **No Shared Infrastructure:** The harness must **NEVER** be executed against a shared Docker bridge, default bridge, or a network carrying unrelated containers.
> - **Collateral Impact:** Bridge-wide IPv6 dropping blocks ICMPv6 Neighbor Discovery Protocol (NDP: Neighbor Solicitation / Advertisement, Router Solicitation / Advertisement) across the entire bridge.
> - **Not an Approved Production Design:** This implementation provides experimental containment for this isolated feasibility spike only. Production IPv6 egress enforcement requires a separately reviewed architecture (such as per-container MAC address filtering `-m mac` or non-bridge network namespace virtualization). This limitation is **NOT SOLVED** in this spike.

---

## Directory Structure

```
security_spikes/stage_7_2_feasibility/phase_b1_static_ip/
├── README.md                                            # This document
├── harness_env_check.sh                                 # Kernel, br_netfilter, backend & Docker checks
├── exp1_static_ip_allocation.sh                         # Exp 1: Deterministic allocation & IPAM carve-out
├── exp2_prestart_firewall_gate.sh                       # Exp 2: Pre-start atomic gate & exact readback
├── exp3_bypass_resistance.sh                            # Exp 3: Bypass tests (bound multi-homing, IPv6, raw)
├── exp_dns_investigation.sh                             # Exp DNS: Deep dive into 127.0.0.11 and blackholing
├── exp4_crash_consistency.sh                            # Exp 4: Lifecycle boundaries (mocked & theoretical)
├── exp5_cleanup_reconciliation.sh                       # Exp 5: Hardened conntrack & deterministic cleanup
├── traffic_probe.py                                     # Python packet-level verification probe
├── run_all_b1_experiments.sh                            # Master runner for dedicated Ubuntu 22.04 LTS host
├── SENTINELOPS_PHASE_B1_STATIC_IP_FEASIBILITY_REPORT.md # Base Phase B1 feasibility report (standardized)
├── SENTINELOPS_PHASE_B1_1_HARNESS_AUDIT_REPORT.md       # Phase B1.1 independent audit report
├── SENTINELOPS_PHASE_B1_2_HARNESS_CORRECTION_REPORT.md  # Phase B1.2 harness correction deliverable
├── SENTINELOPS_PHASE_B1_3_INDEPENDENT_AUDIT_REPORT.md   # Phase B1.3 independent audit report
├── SENTINELOPS_PHASE_B1_4_CORRECTION_REPORT.md          # Phase B1.4 correction report
├── SENTINELOPS_PHASE_B1_5_INDEPENDENT_SECURITY_AUDIT.md # Phase B1.5 independent audit report
├── SENTINELOPS_PHASE_B1_6_CORRECTION_REPORT.md          # Phase B1.6 correction report & verification
├── SENTINELOPS_PHASE_B1_7_INDEPENDENT_SECURITY_AUDIT.md # Phase B1.7 independent audit report
└── SENTINELOPS_PHASE_B1_8_CORRECTION_REPORT.md          # Phase B1.8 correction report & verification
```

---

## Execution Instructions (Dedicated Ubuntu 22.04 LTS Host)

```bash
# 1. Install prerequisites on dedicated Ubuntu 22.04 LTS host
sudo apt-get update && sudo apt-get install -y docker.io iptables iproute2 net-tools python3 conntrack ebtables

# 2. Configure kernel bridge-netfilter prerequisites
sudo modprobe br_netfilter
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1

# 3. Make all harness files executable
chmod +x security_spikes/stage_7_2_feasibility/phase_b1_static_ip/*.sh
chmod +x security_spikes/stage_7_2_feasibility/phase_b1_static_ip/*.py

# 4. Execute master test harness with root privileges
cd security_spikes/stage_7_2_feasibility/phase_b1_static_ip
sudo ./run_all_b1_experiments.sh
```
