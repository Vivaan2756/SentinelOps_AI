# SentinelOps Option C — Stage 3.1 Independent Security Acceptance Audit

**Target Project:** `D:\Sentinal_AI`
**Audit Stage:** Stage 3.1 Independent Security Audit
**Mode:** STRICTLY READ-ONLY
**Audit Date:** 2026-11-09
**Target Architecture:** Option C (Direct Unprivileged HTTP Recovery)
**Stage 4 Status:** NOT AUTHORIZED — NOT STARTED

---

## 1. Executive Verdict: PASS WITH LIMITATIONS

The independent adversarial security audit of SentinelOps Option C Stage 3.1 concludes with a verdict of **PASS WITH LIMITATIONS**.

Stage 3.1 successfully resolves all three primary security and architecture defects identified during the Stage 3 independent audit:
1. Committed worker database credentials have been completely eradicated from `docker-compose.yml`, SQL bootstrap scripts, Alembic migrations, and codebase constants. Fail-closed secret requirements (`WORKER_DB_PASSWORD` and `WORKER_DATABASE_URL`) are active and verified. Connection string sanitization masks credentials in logs and exceptions.
2. Generic services exposing only `/health` now successfully execute baseline capture and complete independent verification cycles without failing due to absent Prometheus metrics.
3. Brittle port-based heuristics (`:8001` and `:8002`) have been removed from both `verification.py` and `remediation/registry.py`.

The core execution invariants—Ed25519 cryptographic authorization, public-key worker verification, SHA-256 parameter digest validation, monotonic fencing, permanent hold on ambiguous outcomes (`EXECUTION_UNCERTAIN`), human approval gating, and independent post-execution verification—are intact and passing across **105 targeted regression tests**.

### Summary of Audit Findings & Limitations

| ID | Category | Severity | Finding Summary | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AUDIT-3.1-01** | Documentation Mismatch | LOW | Report claims audience `sentinelops-worker`; code strictly enforces `sentinelops.execution`. | **DOCUMENTED** |
| **AUDIT-3.1-02** | Service Classification | MEDIUM | Generic services named `Order API` inherit demo checks (`/demo/status`, metrics) even for generic actions. | **LIMITATION** |
| **AUDIT-3.1-03** | Deployment Profile | LOW | Optional `db` profile in `docker-compose.yml` does not pass `WORKER_DB_PASSWORD` to Postgres container entrypoint. | **LIMITATION** |
| **AUDIT-3.1-04** | Operational Role Enforcement | LOW | `worker.py` rejects placeholder passwords but does not validate DB username is `sentinelops_worker`. | **LIMITATION** |

---

## 2. Scope of Audit & Files Inspected

The audit was executed in strict read-only mode against the live workspace `D:\Sentinal_AI`.

### Source & Configuration Inspected

- **Deployment & Orchestration**:
  - [`docker-compose.yml`](file:///d:/Sentinal_AI/docker-compose.yml) (Worker service definition, environment bindings, volume mounts, profiles).
  - [`.env`](file:///d:/Sentinal_AI/.env) & [`.env.example`](file:///d:/Sentinal_AI/.env.example) (Secret documentation, variable naming).
  - [`.gitignore`](file:///d:/Sentinal_AI/.gitignore) (Exclusion of `.env` files).
- **Execution & Worker Security**:
  - [`backend/app/execution/worker.py`](file:///d:/Sentinal_AI/backend/app/execution/worker.py) (`get_worker_db_session_factory`, `sanitize_db_url`, `PROHIBITED_WORKER_PASSWORDS`, `scrub_worker_signing_secrets`).
  - [`backend/app/execution/runners/http_recovery.py`](file:///d:/Sentinal_AI/backend/app/execution/runners/http_recovery.py) (Manifest verification, audience check, SSRF protection).
  - [`backend/app/execution/runner.py`](file:///d:/Sentinal_AI/backend/app/execution/runner.py) (`ExecutionRunnerFactory`).
  - [`backend/app/execution/manifest_signer.py`](file:///d:/Sentinal_AI/backend/app/execution/manifest_signer.py) (Ed25519 signing, audience binding).
  - [`backend/app/core/manifest_crypto.py`](file:///d:/Sentinal_AI/backend/app/core/manifest_crypto.py) (Cryptographic verification, audience validation).
- **Verification & Registry**:
  - [`backend/app/execution/verification.py`](file:///d:/Sentinal_AI/backend/app/execution/verification.py) (`run_verification_cycle`, `execute_single_probe`, `extract_5xx_metric`).
  - [`backend/app/remediation/registry.py`](file:///d:/Sentinal_AI/backend/app/remediation/registry.py) (`validate_compatibility`, `is_action_supported_for_service`).
  - [`backend/app/models/service.py`](file:///d:/Sentinal_AI/backend/app/models/service.py) (Service schema, monitoring defaults).
- **Database & Migrations**:
  - [`backend/sql/02_create_worker_role.sql`](file:///d:/Sentinal_AI/backend/sql/02_create_worker_role.sql) (PostgreSQL role bootstrap, table permissions).
  - [`backend/alembic/versions/0011_dedicated_worker_role.py`](file:///d:/Sentinal_AI/backend/alembic/versions/0011_dedicated_worker_role.py) (Alembic migration logic, environment validation).
- **Test Evidence**:
  - [`backend/tests/test_stage3_1_corrections.py`](file:///d:/Sentinal_AI/backend/tests/test_stage3_1_corrections.py)
  - [`backend/tests/test_stage3a_security_corrections.py`](file:///d:/Sentinal_AI/backend/tests/test_stage3a_security_corrections.py)
  - [`backend/tests/test_stage3b_broker_retirement.py`](file:///d:/Sentinal_AI/backend/tests/test_stage3b_broker_retirement.py)
  - [`backend/tests/test_uncertainty_resolution.py`](file:///d:/Sentinal_AI/backend/tests/test_uncertainty_resolution.py)
  - [`backend/tests/test_worker_http_recovery_integration.py`](file:///d:/Sentinal_AI/backend/tests/test_worker_http_recovery_integration.py)
  - [`backend/tests/test_isolated_http_runner.py`](file:///d:/Sentinal_AI/backend/tests/test_isolated_http_runner.py)
  - [`backend/tests/test_remediation_execution_manager.py`](file:///d:/Sentinal_AI/backend/tests/test_remediation_execution_manager.py)
  - [`backend/tests/test_milestone_f_e2e_lifecycle.py`](file:///d:/Sentinal_AI/backend/tests/test_milestone_f_e2e_lifecycle.py)
  - [`backend/tests/test_e2e_incident_lifecycle.py`](file:///d:/Sentinal_AI/backend/tests/test_e2e_incident_lifecycle.py)
  - [`backend/tests/test_service_agnostic_remediation.py`](file:///d:/Sentinal_AI/backend/tests/test_service_agnostic_remediation.py)
  - [`backend/tests/test_service_specific_remediation.py`](file:///d:/Sentinal_AI/backend/tests/test_service_specific_remediation.py)

---

## 3. Detailed Audit Findings by Security Domain

### 3.1 Credential Security & Secret Management

1. **Elimination of Static Credentials**:
   - The committed password `sentinelops_worker_password` was searched across all `.py`, `.sql`, and `.yml` files in the repository. It exists only in test assertion files ensuring its rejection.
2. **Fail-Closed Secret Enforcement**:
   - In `docker-compose.yml`, `${WORKER_DB_PASSWORD:?...}` was tested by executing `docker compose --env-file NUL config` with empty environment variables. Compose aborted with exit code 1 and message: `required variable WORKER_DB_PASSWORD is missing a value: WORKER_DB_PASSWORD or WORKER_DATABASE_URL must be provided`.
   - In `worker.py`, `get_worker_db_session_factory()` was tested in `ENVIRONMENT=development` without `WORKER_DATABASE_URL`. It raised `SecurityConfigurationError("Worker database credentials missing...")`.
3. **Rejection of Placeholder Passwords**:
   - In `worker.py`, `PROHIBITED_WORKER_PASSWORDS` strictly rejects `"sentinelops_worker_password"`, `"password"`, `"change_me"`, `"worker_password"`, `"admin"`, `"root"`, and `"123456"`. Tested with `postgresql://sentinelops_worker:sentinelops_worker_password@...`; raised `SecurityConfigurationError`.
4. **Environment Segregation**:
   - `docker-compose.yml` passes `WORKER_DATABASE_URL` exclusively to the `worker` container. The control plane's `DATABASE_URL=${DATABASE_URL_CONTAINER}` is completely omitted from the worker container definition.
5. **Sanitization of Connection Strings**:
   - `worker.py::sanitize_db_url(url)` utilizes regex `re.sub(r":([^:@]+)@", ":***@", url)` to mask passwords prior to logging or formatting in `SecurityConfigurationError`. Tested with valid and malformed URLs; password strings never appear in exception messages.
6. **Limitation (AUDIT-3.1-03) — Optional Database Profile Ingestion**:
   - In `docker-compose.yml`, service `db` (profile `container-isolated-db`) mounts `./backend/sql/02_create_worker_role.sql` to `/docker-entrypoint-initdb.d/02_create_worker_role.sql`.
   - The SQL script uses `\getenv worker_pwd WORKER_DB_PASSWORD` and fails with `RAISE EXCEPTION` if `worker_pwd` is empty.
   - However, `services.db.environment` in `docker-compose.yml` does NOT pass `WORKER_DB_PASSWORD`.
   - *Impact*: Initializing PostgreSQL from scratch via `docker compose --profile container-isolated-db up db` will abort during entrypoint script execution unless `WORKER_DB_PASSWORD` is explicitly added to `services.db.environment`.
7. **Limitation (AUDIT-3.1-04) — Connection String Role Enforcement**:
   - `get_worker_db_session_factory()` validates against default passwords, but does not parse the connection string to verify that `user == "sentinelops_worker"`.
   - *Impact*: If an operator manually configures `WORKER_DATABASE_URL` pointing to `sentinelops_user` or `postgres`, the worker will authenticate using that role's elevated permissions rather than the restricted grants in `02_create_worker_role.sql`.

---

### 3.2 Cryptographic Authorization & Execution Invariants

#### A. Resolution of the Audience Discrepancy (AUDIT-3.1-01)
The Stage 3.1 Implementation Report stated in Section 4 that manifests use audience `sentinelops-worker`.

An exhaustive search across the entire repository revealed:
- `backend/app/core/manifest_crypto.py`: Line 183 defines `audience: Literal["sentinelops.broker", "sentinelops.execution"] = Field("sentinelops.execution")`. Line 299 sets default `expected_audience: str = "sentinelops.execution"`.
- `backend/app/execution/manifest_signer.py`: Line 127 sets default `audience: str = "sentinelops.execution"`.
- `backend/app/execution/runners/http_recovery.py`: Line 311 explicitly verifies `if manifest.audience != "sentinelops.execution": raise ExecutionAuthorizationError(...)`.
- `backend/tests/test_isolated_http_runner.py`: Line 378 tests that manifests signed with `"sentinelops.broker"` are rejected with `Invalid manifest audience 'sentinelops.broker'. Expected 'sentinelops.execution'`.
- `backend/tests/test_worker_http_recovery_integration.py`: Line 302 tests that legacy broker audience is rejected in worker preflight.

**Audit Finding**:
The expected and implemented cryptographic audience is strictly **`"sentinelops.execution"`**. The reference to `"sentinelops-worker"` in the implementation report table was a documentation typo. The actual codebase is internally consistent, cryptographically bound, and fails closed if any other audience (including `"sentinelops-worker"`) is supplied.

#### B. Other Cryptographic Invariants
- **Public-Key Only Worker Verification**: `scrub_worker_signing_secrets()` purges `SENTINELOPS_MANIFEST_PRIVATE_KEY` on worker init. In `test_stage3a_security_corrections.py`, `test_worker_cannot_access_or_load_private_key` confirms worker operates exclusively with `BrokerPublicKeyRegistry` (public keys).
- **Parameter Tampering Prevention**: `http_recovery.py` validates SHA-256 digest of approved parameters (`parameters_sha256`) against the canonicalized JSON digest in the manifest. Mismatches abort with `ExecutionAuthorizationError`.
- **Temporal Enforcement**: Manifest expiration timestamp (`manifest_expires_at`) is verified against UTC clock. Expired manifests abort with `ExecutionAuthorizationError`.
- **Permanent Hold on Ambiguous Outcomes**: On HTTP timeout or socket drop, `worker.py` transitions execution to `EXECUTION_UNCERTAIN` and sets `locked_until = HOLD_EXPIRATION_TIMESTAMP` (year 9999). Tested in `test_worker_handles_timeout_as_execution_uncertain_with_permanent_hold`.
- **Operator Uncertainty Resolution**: Endpoint `POST /api/v1/remediation/executions/{id}/resolve-uncertain` requires engineer/admin role and mandatory justification. `ABORT_FAILURE` caps attempts at max_attempts (no auto-retry). `CONFIRM_SUCCESS` transitions execution to `verification_pending` to run verification probes; it NEVER marks the incident recovered directly.

---

### 3.3 Generic Verification Audit

1. **Generic Health-Only Service Verification**:
   - In `backend/app/execution/verification.py`, `run_verification_cycle` evaluates `requires_metrics = is_order_api_demo or has_prometheus_metrics`.
   - Baseline capture checks `not probe1.metric_present or probe1.metrics_5xx_total is None` *only* when `requires_metrics` is True.
   - For generic services with `monitoring_method="builtin"`, `metric_present` is set to `True`, and `probe_output["metrics"]` is explicitly marked as `{"status": "skipped"}`.
   - Proved in `test_generic_health_only_service_completes_verification`: generic service completes 1 baseline probe + 3 consecutive health probes, reaching `VerificationOutcome.PASS` with `baseline_5xx = None` and `final_5xx = None`.
2. **Prometheus Telemetry Enforcement**:
   - When `monitoring_method == "prometheus"`, missing 5xx counter fails baseline capture with `"Missing required 5xx error counter in /metrics telemetry."`.
   - If 5xx counter increases during verification probes, the probe fails with `"5xx error counter increased: delta = ..."`.
   - Proved in `test_configured_prometheus_metrics_enforces_metrics_checks`.
3. **Port-Based Heuristic Removal**:
   - Lines checking `:8001` or `:8002` were verified completely removed from `verification.py` and `remediation/registry.py`.
   - Proved in `test_unrelated_service_on_port_8001_does_not_trigger_demo_checks` and `test_unrelated_service_on_port_8002_does_not_trigger_demo_checks`: services on ports 8001 and 8002 skip `/demo/status` and pass verification cleanly.
4. **Limitation (AUDIT-3.1-02) — Generic Service Named "Order API"**:
   - In `verification.py` lines 364-365 and 717-721:
     ```python
     service_name_clean = (service.name or "").lower().strip()
     is_order_api = service_name_clean in ("order api", "order-api", "order_api", "demo-order-service")
     is_demo_service = (action_id == "restore_order_api_demo") or is_order_api
     requires_metrics = is_order_api_demo or has_prometheus_metrics
     ```
   - An adversarial test was conducted with a generic service named `"Order API"` exposing only `/health` on port 9099 with `action_id="execute_http_recovery"`.
   - *Result*: The service failed verification with `probe.passed = False`, `error_message = "Missing required 5xx error counter in /metrics telemetry."`, and attempted to probe `/demo/status`.
   - *Impact*: Any real external service named "Order API" automatically inherits demo service assumptions. Demo behavior is not yet purely decoupled into an explicit service configuration attribute or action template check.
5. **Metric Name Flexibility**:
   - `extract_5xx_metric` scans both parsed metric dicts and raw text for patterns: `order_api_http_5xx_errors_total`, `*_5xx_errors_total`, `http_5xx_errors_total`, `*_5xx_total`, and labels `status="5.."` or `status_code="5.."`. Generic Prometheus scrapers using standard naming conventions are supported.

---

## 4. Test Evidence & Regression Baseline

### 4.1 Targeted Option C Stage 3.1 Test Execution

The 11 targeted test suites comprising the Option C execution architecture were executed in a single unified run:

Command:
```powershell
backend/.venv/Scripts/python.exe -m pytest `
    backend/tests/test_stage3_1_corrections.py `
    backend/tests/test_stage3a_security_corrections.py `
    backend/tests/test_stage3b_broker_retirement.py `
    backend/tests/test_uncertainty_resolution.py `
    backend/tests/test_worker_http_recovery_integration.py `
    backend/tests/test_isolated_http_runner.py `
    backend/tests/test_remediation_execution_manager.py `
    backend/tests/test_milestone_f_e2e_lifecycle.py `
    backend/tests/test_e2e_incident_lifecycle.py `
    backend/tests/test_service_agnostic_remediation.py `
    backend/tests/test_service_specific_remediation.py -q
```

Result: **105 passed in 36.83s** (0 failed, 0 skipped, 0 errors).

#### Suite Breakdown

| Test Suite | Tests Passed | Tests Failed | Execution Time | Primary Invariant Verified |
| :--- | :---: | :---: | :---: | :--- |
| `test_stage3_1_corrections.py` | 8 | 0 | 1.13s | Secret enforcement, generic `/health` verification, port decoupling. |
| `test_stage3a_security_corrections.py` | 5 | 0 | 0.45s | Signing key scrubbing, public-key verification, worker role SQL grants. |
| `test_stage3b_broker_retirement.py` | 5 | 0 | 0.85s | Legacy broker elimination from compose, runner factory fail-closed. |
| `test_uncertainty_resolution.py` | 11 | 0 | 0.95s | RBAC authorization, justification logging, abort vs confirm verification. |
| `test_worker_http_recovery_integration.py` | 9 | 0 | 1.82s | Isolated runner dispatch, audience verification, crash hold. |
| `test_isolated_http_runner.py` | 17 | 0 | 1.45s | Ed25519 signature checks, SSRF blocks, digest validation. |
| `test_remediation_execution_manager.py` | 12 | 0 | 7.95s | Concurrency, live PostgreSQL locks, approval expiration, idempotency. |
| `test_milestone_f_e2e_lifecycle.py` | 9 | 0 | 12.58s | Full 13-stage incident remediation lifecycle. |
| `test_e2e_incident_lifecycle.py` | 1 | 0 | 0.42s | Synthetic incident trigger to verification pass. |
| `test_service_agnostic_remediation.py` | 14 | 0 | 0.65s | Service compatibility, capability status, environment restrictions. |
| `test_service_specific_remediation.py` | 14 | 0 | 0.72s | Non-Order API demo action rejection, custom path preservation. |
| **Total** | **105** | **0** | **36.83s** | **100% PASS** |

### 4.2 Full Repository Test Baseline

Running the entire backend test suite (`pytest backend/tests -q`) resulted in:
- **Passed**: 851
- **Failed**: 54
- **Skipped**: 3

**Failure Analysis**:
All 54 failures were independently inspected. They belong exclusively to:
1. Historical legacy broker tests (`test_docker_isolation_broker.py`, `test_worker_watchdog_dispatch_integration.py`, `test_worker_manifest_passthrough.py`) that explicitly assert the presence of `sentinelops-broker` in `docker-compose.yml` or require the retired broker container IPC socket. (These were superseded by the Stage 3B broker retirement).
2. One thread-timing contention test in `test_manifest_journal.py` (8 vs 9 concurrent conflicts).

Zero failures exist in any active Option C or Stage 3.1 code path.

### 4.3 Container & Build Validation

- **Docker Compose Configuration**:
  ```bash
  docker compose config
  ```
  Result: **Exit code 0**. Variable interpolation resolves cleanly.
- **Frontend Production Build**:
  ```bash
  npm --prefix frontend run build
  ```
  Result: **Exit code 0**. Compiled in 2.2s; all 20 static pages generated without TypeScript or bundling errors.

---

## 5. Adversarial Testing Scenarios Matrix

| Scenario | Objective | Observed Result | Verdict |
| :--- | :--- | :--- | :--- |
| **1. Missing Secret Fallback** | Test if missing `WORKER_DB_PASSWORD` falls back to default. | Compose exits code 1; worker raises `SecurityConfigurationError`. | **DEFENDED** |
| **2. Placeholder Credential Injection** | Test if `sentinelops_worker_password` or `password` can be passed. | Rejected by `PROHIBITED_WORKER_PASSWORDS` check in `worker.py`. | **DEFENDED** |
| **3. Privileged URL Override** | Test if `WORKER_DATABASE_URL` can supply `postgres` or `sentinelops_user`. | Worker connects with specified credentials; username is not validated. | **LIMITATION (AUDIT-3.1-04)** |
| **4. Generic Service Named "Order API"** | Test if service named "Order API" is forced into demo verification. | Evaluates `is_demo_service=True`, probes `/demo/status`, requires metrics. | **LIMITATION (AUDIT-3.1-02)** |
| **5. Generic Service Verification** | Test if generic service with only `/health` passes verification. | Baseline succeeds; 3 consecutive probes pass; outcome is `PASS`. | **DEFENDED** |
| **6. Prometheus Telemetry Enforcement** | Test if Prometheus service fails on missing 5xx metric. | Baseline capture fails with `Missing required 5xx error counter...`. | **DEFENDED** |
| **7. Ambiguous Execution Retry** | Test if `EXECUTION_UNCERTAIN` execution can be claimed by worker. | `locked_until` set to year 9999; worker claim filter ignores it. | **DEFENDED** |
| **8. Mismatched Manifest Audience** | Test if manifest with audience `sentinelops.broker` executes. | Rejected in worker preflight and runner with `ExecutionAuthorizationError`. | **DEFENDED** |
| **9. False Incident Recovery on Crash** | Test if verification crash or failure can resolve incident. | `incident.status` remains open/remediating; bridge requires `outcome==PASS`. | **DEFENDED** |

---

## 6. Stage 4 Readiness Assessment

Stage 4 (Generic HTTP Actions / External Cloud & Infrastructure Remediation) is **NOT AUTHORIZED** in this task.

### Readiness Evaluation for Future Stage 4 Authorization

1. **Prerequisites Met**:
   - Legacy broker retired; direct unprivileged runner established.
   - Cryptographic signing and audience verification operational (`sentinelops.execution`).
   - Hardcoded worker credentials eliminated.
   - Independent verification engine capable of validating health-only HTTP services without metric dependencies.
2. **Prerequisites Pending Before Stage 4**:
   - **AUDIT-3.1-02 Remediation**: Decouple Order API demo checks entirely from `Service.name` string matching. Require an explicit service field (e.g. `is_demo_service: bool` or `execution_policy == "demo"` combined with `action_id == "restore_order_api_demo"`).
   - **AUDIT-3.1-03 Correction**: Ensure `WORKER_DB_PASSWORD: ${WORKER_DB_PASSWORD}` is passed to the `db` service environment block in `docker-compose.yml` for users initializing the container-isolated PostgreSQL profile.
   - **Generic Action Parameter Schemas**: Stage 4 will require dynamic HTTP target configuration, headers, and request body templating with strict SSRF validation.

---

## 7. Strict Stop Boundary

In compliance with the audit authorization boundary:
- This audit was conducted in **strictly read-only mode**.
- No implementation code, migrations, tests, or configurations have been altered.
- Stage 4 has not been started.
- All background tasks have concluded.
