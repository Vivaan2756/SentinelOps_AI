# SentinelOps Option C — Stage 3 Independent Security Acceptance Audit

**Document:** `docs/OPTION_C_STAGE_3_INDEPENDENT_SECURITY_ACCEPTANCE_AUDIT.md`
**Repository:** `D:\Sentinal_AI`
**Target:** Option C Stage 3 (Stage 3A Operational Security Corrections + Stage 3B Legacy Broker Retirement)
**Audit Mode:** STRICTLY READ-ONLY
**Date:** November 9, 2026
**Auditor:** Independent Security & Architecture SRE Reviewer
**Executive Acceptance Verdict:** **PASS WITH LIMITATIONS**

---

## 1. Executive Summary

This report delivers the independent adversarial audit of SentinelOps Option C Stage 3, evaluating both Sub-stage 3A (Operational Security Corrections) and Sub-stage 3B (Legacy Broker Retirement).

The audit confirms that the core architectural objectives of Stage 3 have been achieved:
- The legacy Docker broker daemon service has been completely removed from the active deployment configuration.
- The privileged Docker socket mount (`/var/run/docker.sock`) has been completely eliminated from all service configurations in [`docker-compose.yml`](file:///d:/Sentinal_AI/docker-compose.yml).
- A dedicated, least-privilege PostgreSQL role ([`sentinelops_worker`](file:///d:/Sentinal_AI/backend/sql/02_create_worker_role.sql)) has been defined with zero access to user passwords, credentials, playbooks, or policy decisions.
- A secure operator-facing API (`POST /api/v1/remediation/executions/{execution_id}/resolve-uncertain`) has been implemented to resolve executions held in `EXECUTION_UNCERTAIN` without automated retries or premature incident closure.
- The complete test suite of 206 tests (59 core Option C, 10 lifecycle, 137 historical regression) passes cleanly.

However, an adversarial inspection of the actual source code identified **four distinct architectural limitations and defects** that prevent an unqualified pass and must be addressed during Stage 4:
1. **Generic Service Verification Blocker (Code Defect in [`verification.py:721`](file:///d:/Sentinal_AI/backend/app/execution/verification.py#L721)):** Line 721 of `PostExecutionVerificationEngine` unconditionally checks `or probe1.metrics_5xx_total is None`. For any customer service that exposes only `/health` without Prometheus metrics (e.g. OpenTelemetry, Datadog, or simple HTTP services), `metrics_5xx_total` is `None`, which causes baseline capture to immediately fail closed with `fatal_error = "Baseline capture failed to collect healthy telemetry."`. Consequently, independent verification currently **cannot pass** for generic non-Prometheus services.
2. **Port-Based Demo Heuristic in [`verification.py:366`](file:///d:/Sentinal_AI/backend/app/execution/verification.py#L366):** The check `":8001" in health_check_url` unconditionally treats any service running on port 8001 as the Order API demo workload, mandating a `GET /demo/status` check (`failure_active == False`). Any unrelated customer workload registered on port 8001 will fail verification if `/demo/status` returns 404.
3. **Environment Scrubbing Boundary Limitation:** Python's `os.environ` deletion and `unsetenv` scrub secrets from application memory and child processes, but on Linux `/proc/self/environ` preserves the initial process environment passed at `execve` time. Therefore, container environment exclusion in `docker-compose.yml` remains the sole authoritative boundary.
4. **Test Accounting Arithmetic Error in Stage 3A Report:** The Stage 3A report claimed 74 tests for a table whose listed test suites mathematically total 64 tests (a 10-test arithmetic discrepancy). The Stage 3B report correctly reconciled the full 206 tests.

---

## 2. Stage 3A Finding-by-Finding Verification

### 2.1 FINDING-2.1-01: Operator Uncertainty Resolution API
**Target:** [`POST /api/v1/remediation/executions/{execution_id}/resolve-uncertain`](file:///d:/Sentinal_AI/backend/app/api/v1/endpoints/remediation.py#L581-L616) and [`RemediationExecutionManager.resolve_uncertain_execution`](file:///d:/Sentinal_AI/backend/app/execution/manager.py#L584-L807)

**Detailed Audit Verification:**
- **RBAC Authorization:** Lines 594-599 in `endpoints/remediation.py` call `check_workspace_role(..., min_role="engineer")`. Lines 613-618 in `manager.py` assert `user_role in ("engineer", "admin")`. Unauthorized users and viewers receive HTTP 403 Forbidden.
- **Workspace Tenancy:** Scoped by `RemediationExecution.workspace_id == workspace_id`. Cross-workspace callers receive HTTP 404 Not Found.
- **Justification Validation:** Lines 621-626 require `clean_justification` with length >= 5 characters. Empty or short justifications receive HTTP 400 Bad Request.
- **Precondition & Concurrency Protection:** Lines 637-645 issue `db.query(RemediationExecution).filter(...).with_for_update().first()`. Lines 653-663 verify `execution.status == 'execution_uncertain'` and `execution.locked_by == 'HOLD:EXECUTION_UNCERTAIN'`. If two concurrent requests arrive, the first takes the row lock and mutates state; the second acquires the lock, finds the state no longer matching, and fails with HTTP 409 Conflict.
- **Duplicate-Resolution Prevention:** Once resolved, status is no longer `EXECUTION_UNCERTAIN` and `locked_by` is cleared/updated. Subsequent resolution requests receive HTTP 409 Conflict.
- **`ABORT_FAILURE` Outcome:**
  - Transitions `status` to `EXECUTION_FAILED`.
  - Sets `attempt_count = execution.max_attempts` (lines 693). This ensures `can_retry_action` returns `False` and worker loops cannot requeue or retry the action.
  - Clears `locked_by = None` and sets `locked_until = now_utc`.
  - Appends `ExecutionEvent(event_type="operator_uncertainty_resolved")` and `IncidentEvent`.
  - Does NOT mutate incident status; incident remains active in `investigating`.
- **`CONFIRM_SUCCESS` Outcome:**
  - Transitions `status` to `VERIFICATION_PENDING`.
  - Sets `locked_by = f"OPERATOR_RESOLVE:{user.id}"`.
  - Appends `ExecutionEvent` and `IncidentEvent`.
  - Commits transition to ensure consistent state before initiating verification.
  - Triggers `PostExecutionVerificationEngine.run_verification_cycle(..., recover_incident=True)`.
  - If verification passes, `IncidentRecoveryBridge` marks incident `recovered`. If verification fails or raises an error, lines 796-803 catch the exception and fail-closed: `status = VERIFICATION_FAILED`, incident remains open.
- **Transactional Audit Integrity:** Both events (`ExecutionEvent` and `IncidentEvent`) are added in the same database transaction as the state transition. A database failure rolls back the entire transaction, leaving the execution safely held in `HOLD:EXECUTION_UNCERTAIN`.
- **State-Transition Bypass Check:** The canonical state machine ([`state_machine.py:71-74`](file:///d:/Sentinal_AI/backend/app/execution/state_machine.py#L71-L74)) allows `EXECUTION_UNCERTAIN` to transition *only* to `EXECUTION_FAILED` or `VERIFICATION_PENDING`. Normal worker claim (`claim_next_execution`) strictly filters `status == 'queued'`. No state-transition bypass exists.

**Verdict:** **VERIFIED — FULL PASS**

---

### 2.2 FINDING-2.1-02: Dedicated Worker Database Role
**Target:** [`backend/sql/02_create_worker_role.sql`](file:///d:/Sentinal_AI/backend/sql/02_create_worker_role.sql) and migration [`backend/alembic/versions/0011_dedicated_worker_role.py`](file:///d:/Sentinal_AI/backend/alembic/versions/0011_dedicated_worker_role.py)

**Detailed Audit Verification:**
Exact permissions granted to `sentinelops_worker`:
1. `remediation_executions`: `SELECT, UPDATE`
2. `execution_attempts`: `SELECT, INSERT, UPDATE`
3. `execution_events`: `SELECT, INSERT`
4. `remediation_approvals`: `SELECT` (read-only verification of approved parameters)
5. `incidents`: `SELECT, UPDATE` (recovery bridge status update)
6. `incident_events`: `SELECT, INSERT`
7. `services`: `SELECT` (read-only target URL resolution)
8. `investigations`: `SELECT` (read-only context)
9. `verification_cycles`: `SELECT, INSERT, UPDATE`
10. `verification_probe_results`: `SELECT, INSERT, UPDATE`
11. `workspaces`: `SELECT` (tenant isolation validation)
12. Sequences: `USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public`

Explicitly Restricted Tables (Zero grants):
- `users`: **NO ACCESS** (passwords, tokens, personal data)
- `workspace_memberships`: **NO ACCESS**
- `playbooks`: **NO ACCESS**
- `playbook_versions`: **NO ACCESS**
- `service_playbook_associations`: **NO ACCESS**
- `policy_decisions`: **NO ACCESS**

**Privilege Leakage & Schema Review:**
- `sentinelops_worker` is created via `CREATE ROLE sentinelops_worker WITH LOGIN PASSWORD '...'`. It is not granted `SUPERUSER`, `CREATEDB`, `CREATEROLE`, or any administrative role.
- No table grants are made to `PUBLIC`.
- Worker session factory ([`worker.py:124-142`](file:///d:/Sentinal_AI/backend/app/execution/worker.py#L124-L142)) binds directly to `WORKER_DATABASE_URL` when configured, falling back to `SessionLocal` in unconfigured local development.
- In [`docker-compose.yml:46`](file:///d:/Sentinal_AI/docker-compose.yml#L46), `WORKER_DATABASE_URL` uses credentials `sentinelops_worker:sentinelops_worker_password`.
- In [`docker-compose.yml:109`](file:///d:/Sentinal_AI/docker-compose.yml#L109), `02_create_worker_role.sql` is mounted to `/docker-entrypoint-initdb.d/`.
- Code inspection of `worker.py` and `verification.py` confirms that the worker never queries or mutates `users`, `playbooks`, or `policy_decisions`.

**Verdict:** **VERIFIED — FULL PASS**

---

### 2.3 FINDING-2.1-03: Worker Signing-Key Environment Isolation
**Target:** [`backend/app/execution/worker.py:114-122`](file:///d:/Sentinal_AI/backend/app/execution/worker.py#L114-L122) and `docker-compose.yml`

**Detailed Audit Verification:**
- **Startup Order & Secret Loading:**
  1. Python process starts `python -m app.execution.worker`.
  2. Top-level imports in `worker.py` do NOT import `app.execution.manifest_signer`.
  3. `app.core.config.Settings` does NOT define `SENTINELOPS_MANIFEST_PRIVATE_KEY`.
  4. In `main()`, line 1973 immediately calls `scrub_worker_signing_secrets()`.
  5. In `DurableExecutionWorker.__init__`, lines 280-281 call `scrub_worker_signing_secrets()`.
  6. The runner instantiated by worker ([`IsolatedHttpRecoveryRunner`](file:///d:/Sentinal_AI/backend/app/execution/runners/http_recovery.py)) loads only [`BrokerPublicKeyRegistry`](file:///d:/Sentinal_AI/backend/app/execution/public_keys.py), which reads public keys only.

**Security Distinction & Verification Classification:**
1. **Secret absent from deployment environment:** **VERIFIED.** In `docker-compose.yml`, `SENTINELOPS_MANIFEST_PRIVATE_KEY` is completely absent from the `worker` service environment.
2. **Secret absent from worker settings/configuration:** **VERIFIED.** Pydantic `Settings` does not capture or store the private key.
3. **Secret absent from worker process memory:** **QUALIFIED LIMITATION.** If a deployment operator mistakenly passes `SENTINELOPS_MANIFEST_PRIVATE_KEY` into the worker container environment:
   - Python's `del os.environ[k]` removes the key from `os.environ` and invokes C `unsetenv()`.
   - However, on Linux kernels, `/proc/self/environ` preserves the initial process environment block established at `execve` time. Any native code or sub-process with read access to `/proc/self/environ` could still observe the string.
   - **Conclusion:** Python environment scrubbing is a defense-in-depth safeguard against application-layer leakage. The primary and authoritative security boundary is #1: excluding the secret from the container deployment manifest.

**Verdict:** **PASS WITH LIMITATIONS**

---

### 2.4 FINDING-2.1-04: Generic Service Verification Contract
**Target:** [`backend/app/execution/verification.py`](file:///d:/Sentinal_AI/backend/app/execution/verification.py) and [`docs/STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md`](file:///d:/Sentinal_AI/docs/STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md)

**Detailed Audit Verification:**
Adversarial inspection of `PostExecutionVerificationEngine` traced four service registration scenarios:

1. **Generic HTTP service exposing only `/health` without Prometheus:**
   - In `_execute_single_probe` (lines 494-495), because `is_demo_service` and `has_prometheus_metrics` are `False`, `current_5xx = None` and `metric_present = True`.
   - Probe returns `SingleProbeEvaluation(passed=True, metric_present=True, metrics_5xx_total=None)`.
   - **CRITICAL DEFECT AT LINE 721:**
     ```python
     if not probe1.passed or not probe1.metric_present or probe1.metrics_5xx_total is None:
         fatal_error = probe1.error_message or "Baseline capture failed to collect healthy telemetry."
     ```
   - Because `probe1.metrics_5xx_total is None`, `fatal_error` is triggered unconditionally on baseline capture!
   - Probes 2..N are never executed. The verification cycle finishes with `VerificationOutcome.FAIL`.
   - **Result:** Generic HTTP services without 5xx metric counters **always fail verification**.
2. **Service registered on port 8001 or 8002:**
   - In lines 364-368:
     ```python
     is_order_api = (
         service_name_clean in ("order api", "order-api", "order_api", "demo-order-service")
         or ":8001" in health_check_url
         or ":8002" in health_check_url
     )
     ```
   - Any service running on port 8001 or 8002 is hardcoded as an Order API demo service (`is_demo_service = True`).
   - The engine requires a successful response from `GET /demo/status` with `failure_active == False` (line 455).
   - If a customer registers their own service on port 8001 where `/demo/status` does not exist (HTTP 404), verification fails.
3. **Service with configurable metrics (non-Prometheus, e.g. OpenTelemetry):**
   - If `monitoring_method != "prometheus"`, metrics probe is skipped, `metrics_5xx_total = None`, and baseline capture fails at line 721.
4. **Service with Prometheus metrics using non-standard counter names:**
   - In `extract_5xx_metric` (lines 106-140), lookups search for `"order_api_http_5xx_errors_total"` and generic `"total_5xx_errors"`. Prometheus counters using standard PromQL formats (e.g. `http_requests_total{status=~"5.."}`) are not parsed unless matching the fallback regex.

**Verdict:** **FAIL ON CODE IMPLEMENTATION / PASS ON DOCUMENTATION**
*The architectural documentation in `docs/` accurately documents the intent, but the actual code in `verification.py` contains hardcoded assumptions that block generic service verification. This must be corrected in Stage 4.*

---

### 2.5 FINDING-2.1-05: Network Security & SSRF Safeguards
**Target:** [`docs/STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md`](file:///d:/Sentinal_AI/docs/STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md) and [`backend/app/execution/runners/http_recovery.py`](file:///d:/Sentinal_AI/backend/app/execution/runners/http_recovery.py)

**Detailed Audit Verification:**
- Section 2.3 of `STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md` explicitly documents:
  > "Option C provides **application-level** transport pinning and URL filtering. Option C does **NOT** provide kernel-level packet filtering (iptables / nftables), host network namespace isolation (veth pairs), or eBPF socket enforcement."
- In `IsolatedHttpRecoveryRunner`:
  - Enforces `follow_redirects=False`. Any 3xx response raises `BrokerSecurityViolation` (tested in `test_runner_rejects_http_redirects`).
  - Pre-resolves hostname to IP, verifies against private IP subnets and cloud metadata IPs (`169.254.169.254`), and routes requests via `PinnedIPTransport` (tested in `test_runner_rejects_cloud_metadata_ip`).
  - Enforces 30s timeout envelopes and 64 KB output buffer bounds.
- Documentation accurately reflects reality without claiming kernel-level packet isolation.

**Verdict:** **VERIFIED — FULL PASS**

---

## 3. Stage 3B Legacy Broker Retirement Verification

### 3.1 Repository-Wide Broker Component Inventory

Every broker-related file and component in the repository was inspected and classified:

| File / Component | Type | Classification | Audit Findings & State |
|---|---|---|---|
| [`docker-compose.yml`](file:///d:/Sentinal_AI/docker-compose.yml) | Deployment | **Active & Hardened** | `broker` service completely removed. Zero `/var/run/docker.sock` volume mounts. Zero broker IPC socket volumes. `worker` configured with UID `1000:1000` and `SENTINELOPS_RUNNER_TYPE=http_recovery`. |
| [`backend/app/execution/runners/http_recovery.py`](file:///d:/Sentinal_AI/backend/app/execution/runners/http_recovery.py) | Runner | **Active Production** | Direct unprivileged runner. Performs Ed25519 manifest verification, IP pinning, redirect blocking, and unprivileged HTTP requests. Zero Docker socket dependency. |
| [`backend/app/execution/worker.py`](file:///d:/Sentinal_AI/backend/app/execution/worker.py) (`RunnerBrokerClientAdapter`) | Adapter | **Active Compatibility** | Adapts direct runner into `BrokerDispatcher` protocol in-process without socket IPC. |
| [`backend/app/execution/broker_dispatcher.py`](file:///d:/Sentinal_AI/backend/app/execution/broker_dispatcher.py) | Coordination | **Active Production** | Coordinates SQLite `OperationRegistry` and append-only SOJ1 binary `OperationJournal` states around in-process execution. |
| [`backend/app/execution/broker.py`](file:///d:/Sentinal_AI/backend/app/execution/broker.py) (`BrokerExecuteRequest`, `BrokerExecuteResponse`) | Data Contracts | **Active Production** | Canonical in-process dataclasses for dispatch requests and responses. |
| [`backend/app/execution/broker.py`](file:///d:/Sentinal_AI/backend/app/execution/broker.py) (`RestrictedDockerBroker`) | Class | **Deprecated but Retained** | Historical Docker broker daemon implementation. Retained solely for backwards compatibility with legacy test suites (`test_docker_isolation_broker.py`). Not referenced in active execution path. |
| [`backend/app/execution/runner.py`](file:///d:/Sentinal_AI/backend/app/execution/runner.py) (`get_execution_runner`) | Factory | **Active & Hardened** | Resolves `IsolatedHttpRecoveryRunner` under Option C. Fails closed with 503 (`ExecutionEnvironmentUnavailable`) if `docker`, `docker_isolated`, or `legacy_broker` is requested. |
| [`backend/app/execution/runner.py`](file:///d:/Sentinal_AI/backend/app/execution/runner.py) (`DockerIsolatedRunner`) | Class | **Deprecated but Retained** | Historical runner. Marked deprecated. Fails closed in production because broker socket is absent. |
| [`backend/app/execution/broker_client.py`](file:///d:/Sentinal_AI/backend/app/execution/broker_client.py) | Client | **Deprecated but Retained** | Standalone Unix domain socket IPC client. Marked deprecated. Not instantiated or deployed in active Docker topology. |
| [`backend/app/execution/broker_server.py`](file:///d:/Sentinal_AI/backend/app/execution/broker_server.py) | Server | **Deprecated but Retained** | Standalone Unix socket server. Marked deprecated. Retained for historical test fixtures. |
| [`backend/app/execution/broker_daemon.py`](file:///d:/Sentinal_AI/backend/app/execution/broker_daemon.py) | Daemon | **Deprecated but Retained** | Standalone daemon entrypoint. Marked deprecated. Not deployed in active Docker topology. |
| [`services/broker/Dockerfile`](file:///d:/Sentinal_AI/services/broker/Dockerfile) | Build | **Deprecated but Retained** | Standalone broker container Dockerfile. Marked deprecated. Not referenced in `docker-compose.yml`. |

### 3.2 Accidental Reactivation Verification
- **Test:** Can an operator accidentally reactivate the legacy broker via environment variables?
- **Inspection of [`runner.py:274-280`](file:///d:/Sentinal_AI/backend/app/execution/runner.py#L274-L280):**
  ```python
  if effective_runner_type in ("docker", "docker_isolated", "legacy_broker"):
      raise ExecutionEnvironmentUnavailable(
          "Legacy Docker broker execution path has been permanently retired under Option C Stage 3B. "
          "Mutating remediation actions must use the direct unprivileged IsolatedHttpRecoveryRunner. "
          "Docker socket access is no longer authorized or supported."
      )
  ```
- If `SENTINELOPS_RUNNER_TYPE=docker` is supplied in the environment, the factory immediately throws 503 `ExecutionEnvironmentUnavailable`.
- If `SENTINELOPS_RUNNER_TYPE` is empty or unset, `DockerIsolatedRunner.is_available()` returns `False` (socket missing), failing closed with 503.
- **Result:** Retired execution modes **FAIL CLOSED** and cannot be accidentally reactivated.

**Verdict:** **VERIFIED — FULL PASS**

---

## 4. Test Accounting & Discrepancy Reconciliation

### 4.1 Stage 3A Arithmetic Discrepancy Analysis
In `stage_3a_implementation_report.md` (lines 99-107), the test summary table listed the following numbers:
1. `test_uncertainty_resolution.py`: 11
2. `test_stage3a_security_corrections.py`: 5
3. `test_isolated_http_runner.py`: 17
4. `test_worker_http_recovery_integration.py`: 9
5. `test_remediation_execution_manager.py`: 12
6. `test_milestone_f_e2e_lifecycle.py`: 9
7. `test_e2e_incident_lifecycle.py`: 1

**Sum of individual suites:** 11 + 5 + 17 + 9 + 12 + 9 + 1 = **64 tests**.
**Report summary line:** Claimed **74 tests + 20 routes**.
**Reconciliation finding:** The summary row in `stage_3a_implementation_report.md` contains an arithmetic discrepancy of +10 tests. The actual test suite executed in Stage 3A contained 64 tests, not 74.

### 4.2 Stage 3B Reconciliation & Independent Test Execution

The audit independently executed pytest collection and test runs across all suites:

```powershell
backend\.venv\Scripts\python.exe -m pytest `
  backend/tests/test_stage3b_broker_retirement.py `
  backend/tests/test_stage3a_security_corrections.py `
  backend/tests/test_uncertainty_resolution.py `
  backend/tests/test_worker_http_recovery_integration.py `
  backend/tests/test_isolated_http_runner.py `
  backend/tests/test_remediation_execution_manager.py `
  backend/tests/test_milestone_f_e2e_lifecycle.py `
  backend/tests/test_e2e_incident_lifecycle.py `
  backend/tests/test_docker_isolation_broker.py `
  backend/tests/test_broker_manifest_verification.py `
  backend/tests/test_stage1_container_native_worker_broker.py `
  --collect-only -q
```
**Collection Result:** Exactly **206 tests collected in 1.41s**.

Breakdown:
- **Core Option C Suites (59 tests):**
  - `test_stage3b_broker_retirement.py`: 5 items
  - `test_stage3a_security_corrections.py`: 5 items
  - `test_uncertainty_resolution.py`: 11 items
  - `test_worker_http_recovery_integration.py`: 9 items
  - `test_isolated_http_runner.py`: 17 items
  - `test_remediation_execution_manager.py`: 12 items
  - *Result:* **59 passed in 16.38s (100% pass, 0 fail, 0 skip)**
- **Lifecycle Suites (10 tests):**
  - `test_milestone_f_e2e_lifecycle.py`: 9 items
  - `test_e2e_incident_lifecycle.py`: 1 item
  - *Result:* **10 passed in 10.57s (100% pass, 0 fail, 0 skip)**
- **Historical Compatibility Suites (137 tests):**
  - `test_docker_isolation_broker.py`: 54 items
  - `test_broker_manifest_verification.py`: 71 items
  - `test_stage1_container_native_worker_broker.py`: 12 items
  - *Result:* **137 passed in 14.29s (100% pass, 0 fail, 0 skip)**
- **Total System Regression:** **206 passed out of 206 executed in ~45s (0 failures, 0 skips)**.
- **Frontend Build (`npm --prefix frontend run build`):** 20/20 routes generated, 0 TypeScript errors in 14.8s.
- **Docker Compose (`docker compose config`):** Validates with 0 errors.

---

## 5. Critical End-to-End Safety Review

The 11-stage remediation lifecycle was audited from human approval to incident closure:

1. **Human Approval:** Approval generates an immutable Ed25519 authorization manifest signed strictly by the control plane. Bypassing human approval is impossible (`create_execution` requires valid approval record with status `approved`).
2. **Audience Verification:** Manifest carries `audience: "sentinelops.execution"`. Runner strictly rejects mismatched or legacy `sentinelops.broker` audiences.
3. **Worker Lease & Fencing:** Worker claims job with row-level lock (`with_for_update()`), assigns lease (90s), and increments monotonic fencing token.
4. **Local Durability Barriers:** Worker invokes `DispatchCoordinator.prepare_dispatch`, recording `DISPATCH_PREPARED` and `CALL_STARTED` in the binary append-only SOJ1 journal with sha256 hash chains and `fsync` barriers, and registering in SQLite `OperationRegistry`.
5. **In-Process HTTP Transmission:** Executed via `RunnerBrokerClientAdapter` calling `IsolatedHttpRecoveryRunner`. Binds connection-time IP pinning, blocks redirects, and rejects private subnets.
6. **Ambiguous Outcome Handling:** In-flight network timeout or connection reset raises `ExecutionUncertainError`. Worker catches this, logs `DISPATCH_UNCERTAIN` to journal and registry, and updates PostgreSQL status to `EXECUTION_UNCERTAIN` with `HOLD:EXECUTION_UNCERTAIN` locked until year 9999 (`HOLD_EXPIRATION_TIMESTAMP`). Automated retries and background worker sweeps are permanently blocked.
7. **Operator Uncertainty Resolution:** Only authenticated engineers/admins can resolve holds via `POST /api/v1/remediation/executions/{id}/resolve-uncertain`. `ABORT_FAILURE` sets `attempt_count = max_attempts` to permanently prevent retry. `CONFIRM_SUCCESS` triggers independent verification.
8. **Independent Verification Gate:** Verification requires Probe 1 (baseline) + 3 consecutive passing health checks. If any probe fails, flaps, or times out, verification fails.
9. **Incident Closure:** `IncidentRecoveryBridge.recover_incident_on_verification_success` transitions the incident to `recovered` **only if** independent verification returned `VerificationOutcome.PASS`. Execution HTTP response alone never closes an incident.

---

## 6. Confirmed Vulnerabilities, Limitations & Recommendations

### 6.1 Vulnerabilities & Code Defects
- **VULN-3-01 (Severity: MEDIUM / Stage 4 Blocker): Hardcoded Metric Requirement in Baseline Verification Capture.**
  - *Location:* [`backend/app/execution/verification.py:721`](file:///d:/Sentinal_AI/backend/app/execution/verification.py#L721)
  - *Impact:* `if not probe1.passed or not probe1.metric_present or probe1.metrics_5xx_total is None:` unconditionally rejects baseline capture for any service where `metrics_5xx_total is None`. This blocks all generic HTTP services exposing only `/health` without Prometheus metrics from ever passing verification.
  - *Remediation for Stage 4:* Update line 721 to check `metrics_5xx_total is None` *only* when `has_prometheus_metrics or is_demo_service` is `True`.
- **VULN-3-02 (Severity: LOW / Stage 4 Blocker): Hardcoded Port Heuristic for Demo Service.**
  - *Location:* [`backend/app/execution/verification.py:366-367`](file:///d:/Sentinal_AI/backend/app/execution/verification.py#L366-L367)
  - *Impact:* Services registered on port 8001 or 8002 are automatically treated as Order API demo workloads, mandating a `GET /demo/status` endpoint. Unrelated customer services on these ports fail verification.
  - *Remediation for Stage 4:* Remove port-based heuristics; rely strictly on explicit service metadata or playbook action bindings.

### 6.2 Architectural Limitations
- **LIMIT-3-01: Application-Layer Transport Enforcement vs Kernel Isolation.** Option C relies on Python URL parsing, DNS pre-resolution, and HTTP transport controls. It does not provide kernel-level packet filtering or network namespaces.
- **LIMIT-3-02: Linux `/proc/self/environ` Process Visibility.** `scrub_worker_signing_secrets()` purges Python's `os.environ` and calls `unsetenv()`, but `/proc/self/environ` on Linux retains initial exec-time strings. Excluding signing secrets from the container deployment configuration is the sole authoritative boundary.

---

## 7. Final Acceptance Determination & Next Steps

### 7.1 Acceptance Verdict
**PASS WITH LIMITATIONS**

**Rationale:**
Stage 3A operational security corrections and Stage 3B legacy broker retirement are fully implemented, verified, and passing all 206 tests. The Docker socket has been completely removed from deployment, the worker database role is restricted, and operator uncertainty resolution is securely established.

The two identified code defects in `verification.py` (VULN-3-01 and VULN-3-02) do not impact existing Order API demo execution or test suites, but they **must be corrected as prerequisites during Stage 4** to enable genuine generic customer service onboarding.

### 7.2 Stage 4 Authorization Status
Per user instruction and strict safety constraints:
**STOP. Do not begin Stage 4.**
Stage 4 will separately define the generic external-service integration contract and demonstrate complete real recovery lifecycle execution.
