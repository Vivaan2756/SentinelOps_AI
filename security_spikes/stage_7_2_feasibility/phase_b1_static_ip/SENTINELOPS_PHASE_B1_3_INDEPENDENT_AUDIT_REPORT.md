# SentinelOps AI — Phase B1.3: Independent Read-Only Harness Security Audit Report

**Target:** `D:\Sentinal_AI\security_spikes\stage_7_2_feasibility\phase_b1_static_ip\`
**Audit Role:** Independent Adversarial Security & Systems Auditor
**Authorization:** STRICTLY READ-ONLY AUDIT
**Architecture Revision Loop Status:** **CLOSED** (No Revision 9 created)
**Stage 7.2 Implementation Authorization:** **STRICTLY NOT AUTHORIZED**
**Audit Date:** 2026-11-09

---

## 1. Executive Summary

This audit is an independent, adversarial security assessment of the SentinelOps Phase B1.2 static-IP feasibility experiment harness.

The preceding Phase B1.2 report claimed that all security defects, conntrack overreach, verification blindspots, and crash recovery gaps identified in Phase B1.1 were fully resolved. This audit verified those claims line-by-line against actual source files without relying on author assertions, comments, or purported test outputs.

### Key Audit Findings

1. **Fatal CLI Syntax Error in Firewall Readback (`exp2_prestart_firewall_gate.sh` Lines 193–194):**
   The script invokes `iptables -L DOCKER-USER 1 -n --line-numbers`. The Linux `iptables` utility does not accept a rule number argument for `-L`; this command is syntactically invalid and returns an error on any Linux host. Because `2>/dev/null || true` was appended, the syntax error is silenced, the rule string evaluates to empty, `POSITION_VERIFIED` evaluates to `false`, and the script triggers a fail-closed abort every time. On a live Ubuntu host, `exp2` **will fail immediately and abort container startup**.
2. **Traffic Probe Exit Code Excludes DNS & Multi-Homing Leaks (`traffic_probe.py` Lines 224–232):**
   While `traffic_probe.py` records probes for embedded DNS (`127.0.0.11:53`) and multi-homed secondary interface leaks in its JSON payload, its exit code assertion `core_passed` **specifically excludes these checks**. As a result, `traffic_probe.py` exits `0` (Success) even if DNS queries to `127.0.0.11` succeed and data is exfiltrated! Any test harness evaluating `$?` will falsely report egress lockdown as `PASSED`.
3. **Master Runner Misleading Exit Code 0 on Prerequisite Failure (`run_all_b1_experiments.sh` Line 39):**
   When `harness_env_check.sh` fails, the orchestrator prints a notice and executes `exit 0`. In automated CI/CD pipelines, this reports successful execution despite 100% of the experiments being skipped.
4. **Crash Injection Suite Omits 6 of 10 Boundaries (`exp4_crash_consistency.sh`):**
   `exp4` tests only boundaries B, D, F, and H. Boundaries A, C, E, G, I, and J are completely missing from the code. Furthermore, no processes are killed, no daemons are restarted, and no `OUTCOME_UNKNOWN` states are simulated; it is an inline sequential script testing simple `if` blocks.
5. **Conntrack Teardown Retains Swallowed Errors (`exp5_cleanup_reconciliation.sh` Lines 89–90):**
   `conntrack -D` commands still append `2>/dev/null || true`. If conntrack deletion fails, the failure is ignored, no readback verifies session removal, and IP reuse is allowed.
6. **Host Gateway Traffic Bypasses `DOCKER-USER`:**
   Packets destined for the host gateway (`172.29.0.1`) enter the Netfilter `INPUT` chain on the host, not `FORWARD`. Because SentinelOps only links into `DOCKER-USER` (in `FORWARD`), any host-local daemon (SSH, dockerd, local databases, metadata services) is completely exposed to the container.

---

## 2. Audit Scope and Absolute Restrictions

- **Authorized Scope:** Static code inspection, syntax verification, and diagnostic tracing of files under `security_spikes/stage_7_2_feasibility/phase_b1_static_ip/`.
- **Modifications:** ZERO modifications made to application code (`backend/`, `frontend/`, `services/`), Docker Compose files, migrations, or database models.
- **Harness Preservation:** No harness files were modified, created, deleted, or reformatted during this audit (with the sole exception of this audit report).
- **Destructive Commands:** Zero Docker containers created/mutated; zero firewall rules created/mutated; zero sysctls changed.
- **Evidence Honesty:** All findings are evaluated against actual code; unexecuted live kernel behaviors are strictly classified.

---

## 3. Exact Inspected File List

| File Path | Version / Status | Inspected Line Count |
| :--- | :---: | :---: |
| [`harness_env_check.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/harness_env_check.sh) | Phase B1.2 | 159 lines |
| [`exp1_static_ip_allocation.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp1_static_ip_allocation.sh) | Phase B1.2 | 167 lines |
| [`exp2_prestart_firewall_gate.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp2_prestart_firewall_gate.sh) | Phase B1.2 | 254 lines |
| [`traffic_probe.py`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/traffic_probe.py) | Phase B1.2 | 238 lines |
| [`exp_dns_investigation.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp_dns_investigation.sh) | Phase B1.2 (New) | 163 lines |
| [`exp3_bypass_resistance.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp3_bypass_resistance.sh) | Phase B1.2 | 244 lines |
| [`exp4_crash_consistency.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp4_crash_consistency.sh) | Phase B1.2 | 133 lines |
| [`exp5_cleanup_reconciliation.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp5_cleanup_reconciliation.sh) | Phase B1.2 | 136 lines |
| [`run_all_b1_experiments.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/run_all_b1_experiments.sh) | Phase B1.2 | 69 lines |
| [`README.md`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/README.md) | Phase B1.2 | 63 lines |
| [`SENTINELOPS_PHASE_B1_STATIC_IP_FEASIBILITY_REPORT.md`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/SENTINELOPS_PHASE_B1_STATIC_IP_FEASIBILITY_REPORT.md) | Phase B1.2 | 260 lines |
| [`SENTINELOPS_PHASE_B1_2_HARNESS_CORRECTION_REPORT.md`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/SENTINELOPS_PHASE_B1_2_HARNESS_CORRECTION_REPORT.md) | Phase B1.2 Deliverable | 280 lines |

---

## 4. Environment and Execution Limitations

The actual environment was inspected and verified via non-destructive read commands:
- **Host OS:** Windows 11 Build 10.0.26100 running WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`.
- **WSL Linux Subsystem:** Ubuntu 26.04.1 LTS without native `iptables`, `ip6tables`, or `conntrack` CLI packages installed.
- **Docker Engine:** Docker Desktop 4.97.0 (Engine 29.9.2) active on Windows host, but unrouted in default WSL distro.
- **Execution Reality:** In compliance with audit restrictions, no live container experiments were executed on WSL2. Claims of successful execution on Ubuntu 22.04 LTS remain strictly prospective.

---

## 5. Adversarial Audit Findings

### Finding 1: Fatal CLI Syntax Error in Jump Position Verification
- **Severity:** **HIGH**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`exp2_prestart_firewall_gate.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp2_prestart_firewall_gate.sh#L193-L198) (Lines 193–198)
- **Detailed Mechanism:**
  ```bash
  TOP_RULE_1=$(iptables -L DOCKER-USER 1 -n --line-numbers 2>/dev/null | grep -E "${CHAIN_EGRESS}" || true)
  TOP_RULE_2=$(iptables -L DOCKER-USER 2 -n --line-numbers 2>/dev/null | grep -E "${CHAIN_INGRESS}" || true)
  POSITION_VERIFIED=false
  if [ -n "${TOP_RULE_1}" ] && [ -n "${TOP_RULE_2}" ]; then
      POSITION_VERIFIED=true
  fi
  ```
  The Linux `iptables` CLI command `iptables -L [chain]` does **not** accept a rule number argument. When invoked with `iptables -L DOCKER-USER 1`, `iptables` interprets `1` as a second chain name, returning:
  `iptables: Too many links or extra arguments on command line` or `No chain/target/match by that name`.
- **Security Impact:** Because errors are piped to `2>/dev/null || true`, the syntax failure is masked. `TOP_RULE_1` and `TOP_RULE_2` are permanently empty strings. Consequently, `POSITION_VERIFIED` is always `false`, `ALL_VERIFIED` is always `false`, and `exp2` triggers a fail-closed abort every time. This script **cannot execute successfully on any Linux host**.
- **Required Correction:** Use `iptables -S DOCKER-USER` or `iptables -L DOCKER-USER -n --line-numbers | awk '$1=="1"{print}'`.

---

### Finding 2: `traffic_probe.py` Exit Code Ignores DNS and Multi-Homed Leaks
- **Severity:** **HIGH**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`traffic_probe.py`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/traffic_probe.py#L224-L235) (Lines 224–235)
- **Detailed Mechanism:**
  ```python
  core_passed = (
      results["1_authorized_http"]["success"]
      and results["2_unauthorized_host_same_port"]["blocked"]
      and results["3_authorized_host_unauthorized_port"]["blocked"]
      and results["4_dns_direct_external_udp_53"]["blocked"]
      and results["5_dns_direct_external_tcp_53"]["blocked"]
      and results["9_ipv6_egress"]["blocked"]
      and not results["10_raw_socket_spoofing"]["raw_socket_permitted"]
  )
  sys.exit(0 if core_passed else 1)
  ```
  Notice that:
  - `results["6_docker_embedded_dns_127_0_0_11_udp"]` is **OMITTED**.
  - `results["7_docker_embedded_dns_127_0_0_11_tcp"]` is **OMITTED**.
  - `results["8_dns_tunneling_probe"]` is **OMITTED**.
  - `results["11_multi_homing_leak"]` is **OMITTED**.
- **Security Impact:** If a container successfully resolves domains or exfiltrates data via `127.0.0.11:53`, or leaks traffic via a secondary bound interface, `traffic_probe.py` still exits with code `0`. Any orchestrator evaluating `if [ $? -eq 0 ]` (such as `exp2` line 247) will declare that egress lockdown "PASSED", generating dangerously false validation evidence.

---

### Finding 3: Master Runner Exits 0 on Environment Qualification Failure
- **Severity:** **MEDIUM**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`run_all_b1_experiments.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/run_all_b1_experiments.sh#L32-L40) (Lines 32–40)
- **Detailed Mechanism:**
  ```bash
  if [ "${ENV_STATUS}" -ne 0 ]; then
      echo -e "\n[NOTICE] Genuine Ubuntu 22.04 LTS Linux host running Docker Engine is UNAVAILABLE." ...
      exit 0
  fi
  ```
- **Security Impact:** In continuous integration and automated test harnesses, returning `exit 0` when prerequisites are absent masks the fact that 100% of security experiments were aborted. The master orchestrator must return a non-zero exit status (e.g., `exit 1` or `exit 2`) when experiments cannot be executed.

---

### Finding 4: Host Gateway / Host-Local Services Egress Bypass
- **Severity:** **HIGH**
- **Classification:** `THEORETICALLY_EXPECTED`
- **File Reference:** [`exp2_prestart_firewall_gate.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp2_prestart_firewall_gate.sh#L132-L143)
- **Detailed Mechanism:**
  Netfilter's `DOCKER-USER` chain is linked exclusively from the `FORWARD` chain. In the Linux network stack, packets originating from a container interface destined for the bridge gateway IP (`172.29.0.1`) or any IP assigned to the host's local interfaces are routed locally into the host's `INPUT` chain.
  **They never enter the `FORWARD` chain or `DOCKER-USER`.**
- **Security Impact:** The container can connect to any host-local daemon listening on `0.0.0.0` or `172.29.0.1` (e.g., Docker daemon socket on TCP, host metrics, cloud-init / metadata proxies, SSH, local PostgreSQL/Redis instances) completely bypassing the pre-start firewall gate. SentinelOps currently installs no rules in the host's `INPUT` chain.

---

### Finding 5: Complete Absence of IPv6 Rules in `exp2_prestart_firewall_gate.sh`
- **Severity:** **HIGH**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`exp2_prestart_firewall_gate.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp2_prestart_firewall_gate.sh)
- **Detailed Mechanism:**
  A static search across `exp2_prestart_firewall_gate.sh` reveals zero occurrences of `ip6tables`.
  While `exp3` contains basic `ip6tables` rules, `exp2` (the primary pre-start firewall gate script) contains zero IPv6 chain definitions, zero IPv6 restore blocks, and zero IPv6 readbacks.
- **Security Impact:** If a host has IPv6 enabled and Docker configures an IPv6 bridge or allows link-local / ULA addresses, the container can establish outbound IPv6 connections completely unhindered by `exp2`.

---

### Finding 6: Incomplete Crash-Injection Coverage and Lack of Real Fault Injection
- **Severity:** **MEDIUM**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`exp4_crash_consistency.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp4_crash_consistency.sh#L56-L131)
- **Detailed Mechanism:**
  `exp4` claims to be an executable crash-consistency test suite across boundaries A through J. However:
  1. Only 4 boundaries (B, D, F, H) have code blocks. Boundaries A, C, E, G, I, and J are completely omitted.
  2. For the 4 boundaries that exist, no actual crash injection occurs: no background processes are killed (`kill -9`), no services are stopped, no durable state files are tested, and no Docker API timeouts are injected.
  3. The script is an inline sequential shell script that creates resources and immediately calls recovery logic in the next line.
- **Security Impact:** Crash consistency and recovery under ambiguous Docker states (`OUTCOME_UNKNOWN`) remain unverified by execution.

---

### Finding 7: Swallowed Errors in Conntrack Deletion (`exp5_cleanup_reconciliation.sh`)
- **Severity:** **MEDIUM**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`exp5_cleanup_reconciliation.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp5_cleanup_reconciliation.sh#L88-L93) (Lines 88–93)
- **Detailed Mechanism:**
  ```bash
  if command -v conntrack >/dev/null 2>&1; then
      conntrack -D -s "${ip}" 2>/dev/null || true
      conntrack -D -d "${ip}" 2>/dev/null || true
      echo "Conntrack Sessions: CLEARED for ${ip}"
  fi
  ```
  The script claims to eliminate masked errors, yet `conntrack -D` commands retain `2>/dev/null || true`.
- **Security Impact:** If conntrack session deletion fails due to permission errors or locked tables, the error is discarded, no readback (`conntrack -L`) verifies deletion, and the script falsely echoes that conntrack sessions were cleared. A new container reusing this IP could inherit lingering established connection states.

---

### Finding 8: Missing Test Implementations in `exp3_bypass_resistance.sh`
- **Severity:** **MEDIUM**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`exp3_bypass_resistance.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/exp3_bypass_resistance.sh#L11-L12)
- **Detailed Mechanism:**
  The script header explicitly advertises:
  `# 7. Host networking (--net=host) bypass.`
  `# 8. Same-bridge Layer 2 switching bypass.`
  However, in the body of the script:
  - There is no test creating a container with `--net=host` and probing egress.
  - There is no test verifying whether intra-bridge L2 traffic bypasses Netfilter when `br_netfilter` is disabled.
  - Step 8 merely prints an `echo` statement describing the Gateway policy.
- **Security Impact:** Two critical threat vectors claimed to be evaluated in Phase B1.2 have zero test implementations in code.

---

### Finding 9: Passive Firewall Backend Inspection in `harness_env_check.sh`
- **Severity:** **LOW**
- **Classification:** `STATICALLY_VERIFIED`
- **File Reference:** [`harness_env_check.sh`](file:///d:/Sentinal_AI/security_spikes/stage_7_2_feasibility/phase_b1_static_ip/harness_env_check.sh#L135-L144)
- **Detailed Mechanism:**
  The script inspects `iptables -V` and reports whether `iptables-nft` or `iptables-legacy` is in use. However, it does not abort if the backend is unknown, nor does it verify that the Docker daemon's internal iptables driver is using the same backend as the host's userspace CLI.
- **Security Impact:** On hosts where Docker uses legacy iptables and userspace tools use `iptables-nft`, rules inserted by the harness may be placed in a different table than Docker's `DOCKER-USER` chain, causing complete rule desynchronization.

---

## 6. Audit Assessment of B1.1 Defect Corrections

| B1.1 Audit Defect | B1.2 Claimed Status | Actual Code Verification | Audit Finding |
| :--- | :---: | :---: | :--- |
| **IPAM Carve-Out** | Fixed via `--ip-range` | Verified in `exp1` (Line 46) | **GENUINELY FIXED:** Dynamic containers allocated in `.128–.254`, static IPs reserved in `.2–.127`. |
| **Atomic Installation** | Fixed via `iptables-restore` | Verified in `exp2` (Line 132) | **GENUINELY FIXED:** Uses single `iptables-restore --noflush` transaction. |
| **Unscoped Conntrack** | Fixed by scoped chains | Verified in `exp2` & `exp3` | **GENUINELY FIXED:** Separate egress and return chains scoped by IP, port, and state. |
| **Parent Jump Readback** | Fixed by verifying `DOCKER-USER` | Attempted in `exp2` (Line 193) | **BROKEN IMPLEMENTATION (HIGH):** Invalid CLI syntax (`iptables -L DOCKER-USER 1`) causes unconditional abort. |
| **Embedded DNS Bypass** | Investigated in `exp_dns` | Verified in `exp_dns_investigation.sh` | **PARTIALLY ADDRESSED:** Demonstrated bypass; blackholing evaluated. Excluded from `traffic_probe.py` exit code! |
| **Multi-Homing Leak** | Tested via bound socket | Implemented in `exp3` (Line 219) | **PARTIALLY ADDRESSED:** Tested, but omitted from `traffic_probe.py` exit code. Secondary IP hardcoded. |
| **Bridge Netfilter Check** | Added to environment check | Verified in `harness_env_check.sh` | **GENUINELY FIXED:** Checks `br_netfilter` and sysctls. |
| **Cleanup Masked Errors** | Removed `|| true` | Implemented in `exp5` | **PARTIALLY FIXED (MEDIUM):** Removed from chain deletion, but retained on `conntrack -D`. |
| **Crash Injection** | Converted to executable test | Attempted in `exp4` | **UNVERIFIED / INCOMPLETE (MEDIUM):** Omitted 6 boundaries; uses inline sequential logic without real fault injection. |
| **Evidence Integrity** | Corrected in Phase B1 report | Addendum added to report top | **PARTIALLY FIXED (LOW):** Top table corrected, but body text (Sections 3, 5, 7) still claims "PROVEN". |

---

## 7. Deep-Dive Evaluations

### 7.1 DNS Mitigation Assessment (`exp_dns_investigation.sh`)
- **Control Flow Analysis:** The script correctly demonstrates that `127.0.0.11:53` loopback queries do not cross `veth*` or `DOCKER-USER`, and that `dockerd` handles queries from the host namespace.
- **The `--dns 192.0.2.1` Blackhole:** Passing `--dns 192.0.2.1` instructs `dockerd` to send upstream queries to TEST-NET-1 (RFC 5737). In theory, upstream domain lookups blackhole and fail.
- **Unverified Assumptions:**
  1. No packet capture was executed on the host interface to verify whether `dockerd` transmits UDP packets to `192.0.2.1`. If an attacker encodes data in domain queries (`secret.attacker.com`), the query is still emitted onto the host's physical network path!
  2. The script does not verify whether `dockerd` falls back to host `/etc/resolv.conf` when the blackhole times out.
  3. The container's socket connection to `127.0.0.11:53` remains open.
- **Verdict:** **THEORETICALLY_EXPECTED / UNVERIFIED**. It is not proven that data cannot leave via dockerd DNS forwarding.

### 7.2 Crash-Injection Authenticity Assessment (`exp4_crash_consistency.sh`)
- **Analysis:** Real fault injection requires asynchronous process termination (e.g., `kill -9` sent to a running Gateway or Helper), simulated host crashes, or Docker Engine daemon restarts while containers are running.
- **Code Reality:** `exp4` runs entirely in a single synchronous shell script. For Boundary B, it simply omits the jump command and checks an `if` condition. For Boundary D, it creates a container and immediately calls `docker rm -f`. For Boundary F, it calls `docker ps` and checks if the name is present.
- **Verdict:** **THEORETICALLY_EXPECTED**. The script does not execute genuine crash testing or test ambiguous state transitions (`OUTCOME_UNKNOWN`).

### 7.3 Cleanup and Conntrack Assessment (`exp5_cleanup_reconciliation.sh`)
- **Analysis:** `cleanup_chain_deterministic` correctly unlinks parent jumps and deletes custom chains with state reporting (`SUCCESSFULLY_REMOVED`, `ALREADY_ABSENT`, `REMOVAL_FAILED`).
- **Remaining Defect:** Lines 89–90 retain `|| true` on `conntrack -D`. Conntrack deletion failures are ignored, and no readback (`conntrack -L`) confirms that connection tracking tables are clear before address reuse.
- **Verdict:** **STATICALLY_VERIFIED WITH DEFECTS**.

---

## 8. Corrected Evidence Matrix

Every experiment and claim is classified under the mandatory 5 categories:

| Spike Component | Target File | Claimed Status | Audited Classification | Audit Justification |
| :--- | :--- | :---: | :---: | :--- |
| **Prerequisite Check** | `harness_env_check.sh` | Verified | **EXECUTED_LIVE** | Executed in WSL2; accurately evaluated prerequisites and exited `1`. |
| **Master Orchestrator** | `run_all_b1_experiments.sh` | Verified | **EXECUTED_LIVE (DEFECTIVE)** | Executed in WSL2; caught `ENV_STATUS=1`, but misleadingly exited `0`. |
| **Static IP Allocation** | `exp1_static_ip_allocation.sh` | Feasible | **STATICALLY_VERIFIED** | Code is syntactically sound and correctly isolates dynamic pool; unexecuted on Linux. |
| **Pre-Start Firewall Gate** | `exp2_prestart_firewall_gate.sh` | Sound | **STATICALLY_VERIFIED (BROKEN)** | Contains fatal syntax error on line 193; omits IPv6 entirely; unexecuted on Linux. |
| **Traffic Probe Suite** | `traffic_probe.py` | Complete | **STATICALLY_VERIFIED (DEFECTIVE)** | Python compiles; however, exit code specifically ignores DNS & multi-homing leaks. |
| **DNS Deep Dive** | `exp_dns_investigation.sh` | Mitigated | **THEORETICALLY_EXPECTED** | Correctly identifies loopback bypass, but `--dns 192.0.2.1` packet containment is unproven. |
| **Bypass Resistance** | `exp3_bypass_resistance.sh` | Evaluated | **STATICALLY_VERIFIED (INCOMPLETE)** | Omitted `--net=host` and same-bridge L2 test implementations. |
| **Crash Consistency** | `exp4_crash_consistency.sh` | Executable | **THEORETICALLY_EXPECTED** | Omitted 6 boundaries; sequential bash logic without real process termination. |
| **Deterministic Cleanup** | `exp5_cleanup_reconciliation.sh` | Verified | **STATICALLY_VERIFIED (DEFECTIVE)** | Retains `|| true` on `conntrack -D`; omits conntrack readback verification. |

---

## 9. Final Independent Verdict

### **Verdict: B. AUDIT PASS WITH LIMITATIONS — SPECIFIC CORRECTIONS REQUIRED BEFORE LIVE TESTING**

#### Justification
The architectural foundation of Phase B1 (user-defined bridge + static IPAM carve-out + pre-start Netfilter gating in `DOCKER-USER`) is fundamentally sound and successfully eliminates the fatal `setns()` / `CAP_SYS_ADMIN` blockers of Stage 7.2 Revision 8.

However, the Phase B1.2 harness **cannot be taken directly to a live Ubuntu 22.04 LTS host in its current state** due to specific implementation errors that will cause either false aborts (Finding 1) or false passes (Finding 2).

### Specific Mandatory Corrections Required Before Live Testing:

1. **Fix CLI Syntax Error in `exp2_prestart_firewall_gate.sh`:**
   Replace `iptables -L DOCKER-USER 1` with `iptables -S DOCKER-USER | head -n 3` or `iptables -L DOCKER-USER -n --line-numbers | grep -E '^1 '`.
2. **Fix Assertion in `traffic_probe.py`:**
   Include `results["6_docker_embedded_dns_127_0_0_11_udp"]`, `results["8_dns_tunneling_probe"]`, and `results["11_multi_homing_leak"]` in the `core_passed` exit-code assertion so that leaks trigger a non-zero exit code.
3. **Fix Master Orchestrator Exit Code in `run_all_b1_experiments.sh`:**
   Change `exit 0` to `exit 1` when `harness_env_check.sh` fails.
4. **Implement Missing IPv6 Rules in `exp2_prestart_firewall_gate.sh`:**
   Add corresponding `ip6tables` default deny rules in `FORWARD` to prevent IPv6 egress bypass.
5. **Protect Host Gateway in Netfilter:**
   Add rules in the host `INPUT` chain to reject packets from `${EXECUTOR_IP}` destined for host-local services.
6. **Eliminate `|| true` on Conntrack in `exp5_cleanup_reconciliation.sh`:**
   Remove `|| true` and add readback verification (`conntrack -L -s ${ip}`).
7. **Implement Missing Tests in `exp3` and Boundaries in `exp4`:**
   Implement `--net=host` test in `exp3`, and implement remaining boundaries (A, C, E, G, I, J) in `exp4`.

---

## 10. Audit Verification Statement

In strict adherence to instructions:
- No production files in `backend/`, `frontend/`, or `services/` were modified.
- No Docker Compose files, migrations, or database configurations were modified.
- No harness files in `security_spikes/` were modified (with the sole exception of creating this report).
- Zero containers, networks, or firewall rules were created or mutated during this audit.
- Stage 7.2 production implementation remains **STRICTLY NOT AUTHORIZED**.
- The architecture revision loop remains **CLOSED**.
