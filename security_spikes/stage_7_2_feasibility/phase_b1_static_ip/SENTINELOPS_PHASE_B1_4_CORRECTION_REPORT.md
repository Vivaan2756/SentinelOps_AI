# SentinelOps AI — Phase B1.4: B1.3 Audit Finding Corrections & Harness Hardening Report

**Project:** SentinelOps AI (`D:\Sentinal_AI`)
**Phase:** Phase B1.4 — Static-IP Harness Security Corrections & Evidence Integrity
**Target:** `security_spikes/stage_7_2_feasibility/phase_b1_static_ip/`
**Date:** 2026-11-09
**Architecture Revision Loop Status:** **CLOSED** (No Revision 9 created)
**Stage 7.2 Implementation Authorization:** **STRICTLY NONE** (Feasibility Spike Only)

---

## Executive Summary

Phase B1.4 successfully resolves all eleven findings (**F-01 through F-11**) identified in the Phase B1.3 Independent Read-Only Security Audit of the Static-IP Bridge Pre-Start Firewall harness.

Every shell script, the Python packet probe, the master runner, and the base feasibility documentation have been corrected and hardened. All harness scripts have been validated for syntax via `bash -n`, `traffic_probe.py` has been compiled and verified with Python 3, and the master runner was tested on the local WSL2 host to verify clean fail-closed behavior (exiting with code `2: PREREQUISITE_FAILED`).

> [!CAUTION]
> **MANDATORY ENVIRONMENT & EVIDENCE INTEGRITY STATEMENT:**
> **Linux security tests have NOT passed.**authoritative live kernel packet filtering, conntrack table manipulation, and Docker network bridge isolation cannot be executed or proven on the local WSL2 host (which lacks native Docker Engine daemon, iptables, ip6tables, and conntrack utilities).
> In strict compliance with instructions:
> 1. No live Linux security tests are claimed to have passed.
> 2. Zero test results have been fabricated.
> 3. The architecture revision loop remains **CLOSED**.
> 4. Stage 7.2 production implementation remains **STRICTLY NOT AUTHORIZED**.
> 5. All production code (`backend/`, `frontend/`, `services/`, docker-compose, migrations) is **100% UNTOUCHED**.

---

## 1. Inventory of Files Modified

All modifications were strictly confined to `security_spikes/stage_7_2_feasibility/phase_b1_static_ip/`:

| File | Type | Nature of Exact Changes |
| :--- | :---: | :--- |
| `harness_env_check.sh` | Shell | Added `iptables-nft` vs `iptables-legacy` detection and consistency checks across IPv4, IPv6, and ARP; fails closed on backend mismatches. |
| `run_all_b1_experiments.sh` | Shell | Replaced prerequisite exit code `0` with `2` (`PREREQUISITE_FAILED`); updated header and summary diagnostics. |
| `exp2_prestart_firewall_gate.sh` | Shell | Fixed `iptables -L` syntax bug using `iptables -S` and `sed`; added `SENTINELOPS_B1_INPUT` host gateway filtering; added IPv6 disablement (`--sysctl`) and `ip6tables` drop rules; added atomic rollback on failure. |
| `traffic_probe.py` | Python | Replaced ambiguous pass/fail booleans with explicit security statuses (`ALLOWED`, `BLOCKED`, `INCONCLUSIVE`, `NOT_APPLICABLE`, `NOT_TESTED`); included DNS tunneling and multi-homing leaks in `core_passed`; verified socket binding. |
| `exp3_bypass_resistance.sh` | Shell | Added dynamic secondary IP discovery via `docker inspect`; added route table verification; implemented host networking (`--net=host`) bypass demonstration; tested `bridge-nf-call-iptables`. |
| `exp4_crash_consistency.sh` | Shell | Replaced blanket proof assertions with honest 10-boundary taxonomy; executed isolated tests for mockable boundaries (B, D, F, H); classified daemon crash boundaries (A, C, E, G, I, J) as `THEORETICALLY_EXPECTED` / `NOT_TESTED_ENVIRONMENT`. |
| `exp5_cleanup_reconciliation.sh` | Shell | Eliminated `|| true` on `conntrack -D`; added independent post-deletion verification via `conntrack -L -s` and `-d`; fails with `REMOVAL_FAILED` if sessions remain. |
| `SENTINELOPS_PHASE_B1_STATIC_IP_FEASIBILITY_REPORT.md` | Markdown | Cleaned up stale "PROVEN" assertions in Sections 3, 5, and 7 to align with Phase B1.4 evidence classifications. |
| `README.md` | Markdown | Updated overview, directory layout, execution instructions, and prerequisite requirements. |

---

## 2. Audit Findings Resolution Matrix (F-01 through F-11)

### Finding F-01: Invalid `iptables -L DOCKER-USER 1` Syntax in `exp2_prestart_firewall_gate.sh`
- **Status:** **CORRECTED**
- **File & Lines:** `exp2_prestart_firewall_gate.sh` (lines 92–104)
- **Explanation:** In standard Linux `iptables`, the `-L` command does not accept a numeric rule position argument (`iptables -L DOCKER-USER 1` fails with `iptables: No chain/target/match by that name` or syntax error). This caused `POSITION_VERIFIED` to evaluate to `false` on all Linux distributions, triggering an unintended fail-closed abort.
  *Correction:* Replaced with POSIX-compatible rule inspection:
  ```bash
  RULE1=$(iptables -S DOCKER-USER 2>/dev/null | grep -v '^-N' | grep -v '^-P' | sed -n '1p')
  RULE2=$(iptables -S DOCKER-USER 2>/dev/null | grep -v '^-N' | grep -v '^-P' | sed -n '2p')
  if echo "${RULE1}" | grep -q -- "-j ${CHAIN_EGRESS}" && echo "${RULE2}" | grep -q -- "-j ${CHAIN_INGRESS}"; then
      POSITION_VERIFIED=true
  fi
  ```
- **Verification:** Verified with `bash -n` and validated regex parsing against standard `iptables -S` specification.

---

### Finding F-02: Zero Exit Code Masking in `run_all_b1_experiments.sh` on Prerequisite Failure
- **Status:** **CORRECTED**
- **File & Lines:** `run_all_b1_experiments.sh` (lines 35–45)
- **Explanation:** In B1.2, when `harness_env_check.sh` returned non-zero, the master runner printed a warning but called `exit 0`. Automated CI/CD runners or test harnesses would record the run as successful even though zero experiments ran.
  *Correction:* Changed exit code to `2` (`PREREQUISITE_FAILED`), outputting explicit diagnostic failure details.
- **Verification:** Executed `run_all_b1_experiments.sh` in WSL2; confirmed exit code was exactly `2`.

---

### Finding F-03: Missing Detection of `iptables-nft` vs `iptables-legacy` Inconsistencies
- **Status:** **CORRECTED**
- **File & Lines:** `harness_env_check.sh` (lines 75–115)
- **Explanation:** Modern Linux systems (Ubuntu 22.04+) often have mixed backends where `iptables` points to `iptables-nft` while Docker or legacy scripts install into `iptables-legacy`. Rules installed in one backend are invisible to the other.
  *Correction:* Added explicit backend detection checking `iptables -V`, `ip6tables -V`, and `ebtables -V` for `(nf_tables)` vs `(legacy)`. If backends are inconsistent across protocols, the check records a critical failure reason and marks the environment unviable.
- **Verification:** Validated syntax with `bash -n` and verified fallback logic in absent-tool scenarios.

---

### Finding F-04: Host Gateway INPUT Boundary Bypass (`172.29.0.1`)
- **Status:** **CORRECTED**
- **Files & Lines:** `exp2_prestart_firewall_gate.sh` (lines 70–88, 115–130), `exp3_bypass_resistance.sh` (lines 140–165), `exp5_cleanup_reconciliation.sh` (lines 65–80)
- **Explanation:** In Linux bridge networking, packets sent by a container to the bridge gateway IP (`172.29.0.1`) are locally delivered to the host and enter the Netfilter `INPUT` chain, **not** the `FORWARD` or `DOCKER-USER` chain. Rules placed solely in `DOCKER-USER` do not protect host-local services (e.g. host SSH, Docker daemon socket proxy, local databases).
  *Correction:* Added a dedicated `SENTINELOPS_B1_INPUT` chain linked into `INPUT` at position 1. The chain drops/rejects all unauthorized traffic targeting `172.29.0.1`. Added full readback and cleanup routines for this chain.
- **Verification:** Verified with `bash -n` and verified that atomic restore manifests include `*filter` rules for both `INPUT` and `DOCKER-USER`.

---

### Finding F-05: Incomplete IPv6 Isolation and Egress Gate
- **Status:** **CORRECTED**
- **Files & Lines:** `exp2_prestart_firewall_gate.sh` (lines 55–65, 135–150), `exp3_bypass_resistance.sh` (lines 170–190)
- **Explanation:** Containers on dual-stack hosts could attempt IPv6 egress (e.g., link-local `fe80::` or ULA) to bypass IPv4 rules.
  *Correction:* Hardened both container instantiation and kernel firewall:
  1. Container created with `--sysctl net.ipv6.conf.all.disable_ipv6=1` (kernel disables IPv6 stack inside container namespace).
  2. `ip6tables` installs `SENTINELOPS_B1_IPV6_DENY` chain linked into `FORWARD` with a default `DROP` rule.
- **Verification:** Syntax verified with `bash -n`.

---

### Finding F-06: Asymmetric / Incomplete Rollback on Gate Failure in `exp2`
- **Status:** **CORRECTED**
- **File & Lines:** `exp2_prestart_firewall_gate.sh` (lines 155–185)
- **Explanation:** If position verification or readback failed during pre-start gate installation, the abort handler left orphaned chains or partial rules in the kernel.
  *Correction:* Implemented `rollback_firewall()` that systematically unlinks parent rules from `DOCKER-USER` and `INPUT`, flushes custom chains (`SENTINELOPS_B1_EGRESS`, `SENTINELOPS_B1_INGRESS`, `SENTINELOPS_B1_INPUT`, `SENTINELOPS_B1_IPV6_DENY`), and deletes the chains before terminating with an error.
- **Verification:** Syntax verified; rollback sequence verified to be strictly inverse of installation.

---

### Finding F-07: Masked Failures and Ambiguous Status in `traffic_probe.py`
- **Status:** **CORRECTED**
- **File & Lines:** `traffic_probe.py` (lines 40–180)
- **Explanation:** In B1.2, `traffic_probe.py` used crude booleans where a blocked connection and an internal socket creation failure looked identical. Furthermore, `core_passed` excluded DNS tunneling and multi-homing leaks.
  *Correction:* Refactored `traffic_probe.py`:
  1. Each check returns an explicit security status: `ALLOWED`, `BLOCKED`, `INCONCLUSIVE`, `NOT_APPLICABLE`, or `NOT_TESTED`.
  2. `core_passed` now explicitly requires `8_dns_tunneling_probe` to be `BLOCKED` and `11_multi_homing_leak` to be `BLOCKED` or `NOT_APPLICABLE`.
  3. Added socket bind validation before attempting transmission.
- **Verification:** Compiled cleanly with `python3 -m py_compile traffic_probe.py`.

---

### Finding F-08: Incomplete Secondary IP Discovery & Host Networking Test in `exp3`
- **Status:** **CORRECTED**
- **File & Lines:** `exp3_bypass_resistance.sh` (lines 100–140, 210–235)
- **Explanation:** B1.2 used hardcoded secondary IP assumptions that failed if Docker assigned a different IP. It also omitted host networking verification.
  *Correction:*
  1. Dynamically detects secondary IP via `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'`.
  2. Inspects `ip route get` to verify routing table egress interface selection.
  3. Added explicit demonstration test for `--net=host`, documenting that containers created with host networking bypass bridge firewalls entirely and must be forbidden by the Execution Gateway.
- **Verification:** Syntax verified with `bash -n`.

---

### Finding F-09: Unverified Daemon Crash Claims Across Lifecycle Boundaries in `exp4`
- **Status:** **CORRECTED**
- **File & Lines:** `exp4_crash_consistency.sh` (lines 35–220)
- **Explanation:** B1.2 presented a table claiming boundaries were tested when daemon crashes or kernel panics cannot be executed from a user-space test script.
  *Correction:* Partitioned boundaries into:
  - **Executable Tests:** Boundaries B (partial firewall rollback), D (unstarted container cleanup), F (running executor firewall rule preservation), and H (container removed orphan rule cleanup).
  - **Theoretically Modeled Boundaries:** Boundaries A, C, E, G, I, and J requiring Docker daemon crashes or power failures are honestly marked `THEORETICALLY_EXPECTED` / `NOT_TESTED_ENVIRONMENT`.
- **Verification:** Script syntax verified with `bash -n`; output format explicitly delineates executed boundaries from theoretical models.

---

### Finding F-10: Masked Conntrack Deletion Errors in `exp5_cleanup_reconciliation.sh`
- **Status:** **CORRECTED**
- **File & Lines:** `exp5_cleanup_reconciliation.sh` (lines 85–125)
- **Explanation:** B1.2 executed `conntrack -D ... || true`, ignoring deletion failures. If active state table entries persisted, an attacker could resume TCP sessions after IP deallocation.
  *Correction:* Removed `|| true`. Added mandatory post-deletion readback:
  ```bash
  RESIDUAL_SRC=$(conntrack -L -s "${CONTAINER_IP}" 2>/dev/null | wc -l)
  RESIDUAL_DST=$(conntrack -L -d "${CONTAINER_IP}" 2>/dev/null | wc -l)
  if [ "${RESIDUAL_SRC}" -gt 0 ] || [ "${RESIDUAL_DST}" -gt 0 ]; then
      echo "CONNTRACK_FLUSH_FAILED: Residual sessions remain"
      exit 1
  fi
  ```
- **Verification:** Syntax verified with `bash -n`.

---

### Finding F-11: Stale "PROVEN" Claims in Feasibility Documentation
- **Status:** **CORRECTED**
- **File & Lines:** `SENTINELOPS_PHASE_B1_STATIC_IP_FEASIBILITY_REPORT.md` (lines 120, 153, 174, 195, 222)
- **Explanation:** While the executive summary in B1.2 had added a caution addendum, the body text in Sections 3, 4, 5, 6, and 7 still retained unearned "PROVEN" claims.
  *Correction:* Systematically updated all section verdicts:
  - Exp 1: `FEASIBLE (STATICALLY VERIFIED / ENVIRONMENT LIMITED)`
  - Exp 2: `ARCHITECTURALLY SOUND (PENDING NATIVE UBUNTU RUN)`
  - Exp 3: `PARTIALLY FEASIBLE (STATICALLY VERIFIED / PENDING NATIVE UBUNTU RUN)`
  - Exp 4: `FEASIBLE (STATICALLY VERIFIED / SIMULATED CRASH MODEL)`
  - Exp 5: `FEASIBLE (STATICALLY VERIFIED / CORRECTED IN B1.4)`
- **Verification:** Inspected file; confirmed zero occurrences of unearned "PROVEN" labels.

---

## 3. Test Execution Commands & Outputs

### 3.1 Python Syntax Compilation (`traffic_probe.py`)
```bash
wsl bash -c "cd /mnt/d/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip && python3 -m py_compile traffic_probe.py && echo 'Python syntax check PASSED'"
```
**Output:**
```text
Python syntax check PASSED
(Exit code: 0)
```

### 3.2 Bash Syntax Verification (`bash -n`) on All Harness Scripts
```bash
wsl --cd /mnt/d/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip bash -c "bash -n harness_env_check.sh && bash -n exp1_static_ip_allocation.sh && bash -n exp2_prestart_firewall_gate.sh && bash -n exp3_bypass_resistance.sh && bash -n exp_dns_investigation.sh && bash -n exp4_crash_consistency.sh && bash -n exp5_cleanup_reconciliation.sh && bash -n run_all_b1_experiments.sh && echo ALL_8_SCRIPTS_SYNTAX_PASSED"
```
**Output:**
```text
ALL_8_SCRIPTS_SYNTAX_PASSED
(Exit code: 0)
```

### 3.3 Environment Check Execution on Current Host (`harness_env_check.sh`)
```bash
wsl --cd /mnt/d/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip bash ./harness_env_check.sh
```
**Output:**
```text
=== SENTINELOPS PHASE B1.4: ENVIRONMENT ASSESSMENT ===
Timestamp: 2026-11-09T10:30:05Z
HOST TYPE: WSL2 (Windows Subsystem for Linux)
DOCKER ENGINE: CLI present, but Daemon unreachable or stopped.
IPTABLES: Not installed.
IP6TABLES: Not installed.
CONNTRACK: Not installed (required for safe conntrack table flushing on IP reuse).
BR_NETFILTER MODULE: Loaded
SYSCTL bridge-nf-call-iptables: 1 (Enabled)
SYSCTL bridge-nf-call-ip6tables: 1 (Enabled)

=== ENVIRONMENT ASSESSMENT SUMMARY ===
VERDICT: INSUFFICIENT for authoritative live kernel execution.
Missing Prerequisites (5):
  - Host is WSL2 (requires native Ubuntu 22.04 LTS host)
  - Docker daemon unreachable or stopped
  - iptables not installed
  - ip6tables not installed
  - conntrack CLI utility not installed
Per strict safety rules: Experiments will abort to prevent unverified or unsafe test state.
(Exit code: 1)
```

### 3.4 Master Suite Prerequisite Gate Verification (`run_all_b1_experiments.sh`)
```bash
powershell -Command "wsl --cd /mnt/d/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip bash ./run_all_b1_experiments.sh; echo `"EXIT_CODE: `$LASTEXITCODE`""
```
**Output:**
```text
========================================================================
    SENTINELOPS PHASE B1.4 STATIC-IP FIREWALL FEASIBILITY SUITE (V3)
========================================================================
Start Time: 2026-11-09T10:30:18Z

>>> STEP 0: CHECKING TEST ENVIRONMENT & PREREQUISITES <<<
=== SENTINELOPS PHASE B1.4: ENVIRONMENT ASSESSMENT ===
Timestamp: 2026-11-09T10:30:18Z
HOST TYPE: WSL2 (Windows Subsystem for Linux)
DOCKER ENGINE: CLI present, but Daemon unreachable or stopped.
IPTABLES: Not installed.
IP6TABLES: Not installed.
CONNTRACK: Not installed (required for safe conntrack table flushing on IP reuse).
BR_NETFILTER MODULE: Loaded
SYSCTL bridge-nf-call-iptables: 1 (Enabled)
SYSCTL bridge-nf-call-ip6tables: 1 (Enabled)

=== ENVIRONMENT ASSESSMENT SUMMARY ===
VERDICT: INSUFFICIENT for authoritative live kernel execution.
Missing Prerequisites (5):
  - Host is WSL2 (requires native Ubuntu 22.04 LTS host)
  - Docker daemon unreachable or stopped
  - iptables not installed
  - ip6tables not installed
  - conntrack CLI utility not installed
Per strict safety rules: Experiments will abort to prevent unverified or unsafe test state.

[PREREQUISITE FAILURE] Genuine Ubuntu 22.04 LTS Linux host running Docker Engine is UNAVAILABLE.
Per strict safety rules:
  - Experiments are NOT executed on non-qualifying environments.
  - Test harness is statically verified, but live kernel tests were SKIPPED.
  - Exit code 2 returned to prevent automated systems from mistaking skipped runs for success.
Summary completed with PREREQUISITE_FAILED status.
EXIT_CODE: 2
```

---

## 4. Evidence Classification Table

Every claim in this report adheres strictly to the five-tier evidence standard:

| Claim / Component | Evidence Classification | Justification |
| :--- | :---: | :--- |
| **Harness Shell Scripts Syntax** | **PROVEN BY EXECUTION** | All 8 shell scripts passed `bash -n` with exit code 0. |
| **Python Probe Syntax** | **PROVEN BY EXECUTION** | `traffic_probe.py` compiled successfully via `python3 -m py_compile`. |
| **Prerequisite Rejection & Exit Code 2** | **PROVEN BY EXECUTION** | `run_all_b1_experiments.sh` executed on WSL2, detected missing prerequisites, and exited 2. |
| **WSL2 Environment Inadequacy** | **PROVEN BY EXECUTION** | `harness_env_check.sh` inspected local system, identified missing daemons/binaries, exited 1. |
| **Static IP Allocation Semantics** | **STATICALLY VERIFIED** | Semantics verified against Docker Engine IPAM specifications; live runs pending native Linux. |
| **Pre-Start Netfilter Gating & INPUT Chain** | **STATICALLY VERIFIED** | Atomic rules and chain linkages verified by static analysis; kernel packet tests pending. |
| **Bypass Resistance (DNS, IPv6, Multi-Homing)** | **STATICALLY VERIFIED** | Mitigation rules and probe code verified; empirical packet drop verification pending. |
| **Crash Consistency Boundaries B, D, F, H** | **STATICALLY VERIFIED** | Logic tested in isolated mock scripts; real daemon crash injection pending dedicated host. |
| **Daemon Crash Boundaries A, C, E, G, I, J** | **THEORETICALLY SUPPORTED** | Documented lifecycle state invariants; unexecuted due to host requirements. |
| **Conntrack Table Flushing on IP Reuse** | **STATICALLY VERIFIED** | Readback verification code statically verified; kernel conntrack tests pending. |
| **Authoritative Linux Firewall Enforcement** | **NOT TESTED (UNPROVEN)** | Dedicated Ubuntu 22.04 LTS Linux host is required before live claims can be made. |

---

## 5. Scope Boundary Compliance Confirmation

We explicitly confirm that:
1. **Zero files outside `security_spikes/stage_7_2_feasibility/phase_b1_static_ip/` were modified.**
   Timestamps for `backend/`, `frontend/`, `services/`, `demo_services/`, `monitoring/`, `docs/`, and `docker-compose.yml` confirm no changes were made.
2. **Stage 7.2 remains STRICTLY NOT IMPLEMENTED.**
   Neither the Execution Gateway nor the Host Firewall Helper has been implemented in production code.
3. **The Architecture Revision Loop remains CLOSED.**
   No Architecture Revision 9 was created.
4. **No Linux security tests have passed.**
   Testing was conducted on a non-qualifying Windows/WSL2 host; authoritative verification remains pending execution on dedicated Linux hardware.

---

## 6. Recommendation for Phase B1.5

To transition from static verification to authoritative empirical evidence, **Phase B1.5** should be executed on a dedicated Linux host meeting the following criteria:

### Host Prerequisites
1. **Operating System:** Ubuntu 22.04.4 LTS (or later) running native Linux kernel (`5.15+` or `6.x`).
2. **Container Engine:** Docker Engine CE `24.0+` or `26.x+` with active `systemd` daemon.
3. **Networking Utilities:** `iptables`, `ip6tables`, `conntrack`, `iproute2`, and `net-tools`.
4. **Kernel Modules & Sysctls:**
   ```bash
   sudo modprobe br_netfilter
   sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
   sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1
   ```

### Execution Procedure
```bash
# Clone repository to dedicated Ubuntu 22.04 LTS host
cd security_spikes/stage_7_2_feasibility/phase_b1_static_ip

# Grant execution permissions
chmod +x *.sh *.py

# Execute the complete automated suite with root privileges
sudo ./run_all_b1_experiments.sh
```

Upon completion, capture the resulting `output/` directory, iptables packet counters (`iptables -L -n -v`), conntrack session dumps, and `traffic_probe.py` JSON results as the authoritative proof artifacts.
