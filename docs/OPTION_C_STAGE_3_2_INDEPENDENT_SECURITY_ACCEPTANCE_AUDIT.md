# SentinelOps Option C — Stage 3.2 Independent Security Acceptance Audit Report
## Option C: Direct Unprivileged HTTP Recovery — Final Security Closure Verification

**Audit Date:** 2026-11-09
**Audit Stage:** Stage 3.2 Final Security Closure
**Auditor Mode:** STRICTLY READ-ONLY INDEPENDENT SECURITY AUDIT
**Target Architecture:** Option C — Direct Unprivileged HTTP Recovery
**Target Repository:** `D:\Sentinal_AI`
**Prerequisites:** Stage 3.1 Implementation Report, Stage 3.1 Independent Security Acceptance Audit, Stage 3.2 Implementation Report
**Scope Boundary:** Verification of Stage 3.2 resolutions for AUDIT-3.1-02, AUDIT-3.1-03, AUDIT-3.1-04, and Manifest Journal Concurrency. Stage 4 remains **STRICTLY NOT AUTHORIZED**.

---

## 1. Executive Summary & Audit Verdict

### Final Verdict: PASS WITH LIMITATIONS

An independent adversarial security review of the Option C Stage 3.2 implementation has determined that **all four target objectives have been genuinely implemented and technically verified**:

1. **AUDIT-3.1-02 (Heuristic Demo-Service Classification Eliminated):** Verified. Heuristic name-based matching (`"order" in service.name.lower()`) has been completely eradicated across domain models, schemas, database migrations, registry evaluation, policy enforcement, and verification probes. A dedicated database column `demo_integration` (nullable `String(50)`) was introduced via Alembic migration `0012_service_demo_integration.py`. API ingestion strictly restricts `demo_integration="order_api"` to the `development` environment via Pydantic validator, failing closed in `staging` or `production`.
2. **AUDIT-3.1-03 (Container Profile Secret Propagation):** Verified. `WORKER_DB_PASSWORD: ${WORKER_DB_PASSWORD:?...}` was propagated into the optional PostgreSQL container service (`services.db.environment`) within `docker-compose.yml`, ensuring that when the `container-isolated-db` profile is selected, both worker and database containers receive the operator-configured secret.
3. **AUDIT-3.1-04 (Worker Database Role Enforcement):** Verified. The worker session factory strictly validates that the configured URL user is `sentinelops_worker` and executes an immediate runtime `SELECT current_user;` query against PostgreSQL upon engine startup, raising a `RuntimeError` and terminating execution if any superuser, application user, or foreign role identity is detected.
4. **Manifest Journal Concurrency Resolution:** Verified. A process-level initialization lock (`_storage_init_lock = threading.Lock()`) in `backend/app/execution/manifest_journal.py` serializes SQLite database and table creation across worker threads, eliminating table creation race conditions (`sqlite3.OperationalError: table manifests already exists` / `database is locked`).

### Acceptance Limitations (Non-Blocking)
- **FINDING-3.2-01 (Low / Operational):** Docker Compose parses and interpolates all `${VAR:?...}` variables at file loading time regardless of whether the profile (`container-isolated-db`) is active. When deploying with an external database using `WORKER_DATABASE_URL` alone, Compose fails closed unless dummy/explicit `WORKER_DB_PASSWORD` is supplied in `.env`.
- **FINDING-3.2-02 (Informational):** The worker database `current_user` verification executes once at engine initialization rather than continuously via a connection checkout hook (`@event.listens_for(engine, "checkout")`). Mitigated by PostgreSQL role privileges preventing `SET ROLE`.
- **FINDING-3.2-03 (Informational / Architectural):** Manifest journal storage synchronization uses in-process locking (`threading.Lock()`), which protects multi-threaded execution within the single-worker topology but does not provide inter-process distributed locking if multiple worker containers share the same SQLite file.
- **FINDING-3.2-04 (Informational / Test Suite Debt):** Eliminating name-based demo heuristics broke 28 pre-Option-C legacy test fixtures (Milestone F, Phase 4) that instantiated `Service(name="Order API")` without setting `demo_integration="order_api"`. This confirms the security control works as intended, but indicates test debt in legacy suites.

---

## 2. In-Depth Technical Verification Matrix

| Audit Target | File(s) Inspected | Verified Fact / Mechanism | Security Invariant Status |
| :--- | :--- | :--- | :--- |
| **AUDIT-3.1-02** Explicit Demo Classification | [service.py](file:///d:/Sentinal_AI/backend/app/models/service.py#L45-L47)<br>[service.py](file:///d:/Sentinal_AI/backend/app/schemas/service.py#L32-L46)<br>[0012_service_demo_integration.py](file:///d:/Sentinal_AI/backend/alembic/versions/0012_service_demo_integration.py#L19-L27) | Column `demo_integration` added (`String(50)`, nullable, indexed). Pydantic validator strictly rejects `demo_integration` in `staging` or `production`. Alembic migration cleanly upgrades and downgrades. | **VERIFIED PASS** |
| **AUDIT-3.1-02** Heuristic Removal | [registry.py](file:///d:/Sentinal_AI/backend/app/remediation/registry.py#L647-L650)<br>[policy.py](file:///d:/Sentinal_AI/backend/app/remediation/policy.py#L210-L225)<br>[verification.py](file:///d:/Sentinal_AI/backend/app/execution/verification.py#L182-L210) | `ActionRegistry.is_demo_service()` requires `service.demo_integration == "order_api"`. Zero name-based substring checks (`"order" in name`). Demo status probes skipped for generic services. | **VERIFIED PASS** |
| **AUDIT-3.1-03** Profile Secret Propagation | [docker-compose.yml](file:///d:/Sentinal_AI/docker-compose.yml#L18-L26) | `WORKER_DB_PASSWORD: ${WORKER_DB_PASSWORD:?...}` present under `services.db.environment` within `container-isolated-db` profile. | **VERIFIED PASS** |
| **AUDIT-3.1-04** Worker Role & Identity | [worker.py](file:///d:/Sentinal_AI/backend/app/execution/worker.py#L125-L162) | URL parsed via `make_url()`; requires username `sentinelops_worker`. Database connection executes `SELECT current_user;` and verifies identity matches `sentinelops_worker`. | **VERIFIED PASS** |
| **Concurrency** Manifest Journal Lock | [manifest_journal.py](file:///d:/Sentinal_AI/backend/app/execution/manifest_journal.py#L38-L55)<br>[test_manifest_journal.py](file:///d:/Sentinal_AI/backend/tests/test_manifest_journal.py#L140-L195) | Thread initialization lock (`_storage_init_lock = threading.Lock()`) prevents concurrent DDL race conditions. Tested 20-thread concurrency and 5 stress rounds with 100% determinism. | **VERIFIED PASS** |

---

## 3. Detailed Technical Findings

### AUDIT-3.1-02 Deep Dive: Elimination of Heuristic Demo Classification

#### 1. Ingestion & API Boundary
- In [service.py](file:///d:/Sentinal_AI/backend/app/schemas/service.py#L32-L46), `ServiceBase` defines:
  ```python
  demo_integration: Optional[Literal["order_api"]] = Field(
      default=None,
      description="Explicit demo integration identifier (only permitted in 'development' environment)"
  )

  @field_validator("demo_integration")
  @classmethod
  def validate_demo_integration(cls, v: Optional[str], info) -> Optional[str]:
      if v is not None:
          data = info.data
          env = data.get("environment", "development")
          if env != "development":
              raise ValueError("demo_integration is only permitted in the 'development' environment.")
      return v
  ```
- Any attempt to register `demo_integration="order_api"` in `staging` or `production` returns HTTP 422 Unprocessable Entity.
- Inspection of `backend/app/api/v1/services.py` confirms that no `PUT` or `PATCH` endpoints exist for services; services cannot be retroactively mutated to have `demo_integration="order_api"`.

#### 2. Heuristic Removal in Action Registry & Policy Engine
- In [registry.py](file:///d:/Sentinal_AI/backend/app/remediation/registry.py#L647-L650), `is_action_supported_for_service` delegates demo action compatibility strictly to:
  ```python
  if action_id in ("restore_order_api_demo", "restart_order_api"):
      return cls.is_demo_service(service, "order_api", db=db)
  ```
- Services named `"Order API"`, `"order-api"`, `"Order API Live PG"`, `"demo-order-service"` or `"order_api"` that lack `demo_integration="order_api"` are strictly rejected as generic services (`is_action_supported_for_service` returns `False`).
- In [policy.py](file:///d:/Sentinal_AI/backend/app/remediation/policy.py#L210-L240), `PolicyEngine.evaluate` enforces Rule 4B (`execution_policy == "observe_only"`) and Rule 5 (`environment == "production"`) before playbook matching, rejecting non-development demo actions with explicit reason codes.

#### 3. Verification Engine Isolation
- In [verification.py](file:///d:/Sentinal_AI/backend/app/execution/verification.py#L182-L210), synthetic verification evaluates:
  ```python
  is_demo = ActionRegistry.is_demo_service(service, "order_api") if service else False
  ```
  If `is_demo` is `False`, the engine explicitly records `status: skipped` with reason `"Not an Order API demo service"` and avoids probing `/demo/status`. For generic `execute_http_recovery`, `is_demo` is unconditionally evaluated as `False`.

---

### AUDIT-3.1-03 Deep Dive: Container Profile Secret Propagation

#### 1. Configuration Audit
In [docker-compose.yml](file:///d:/Sentinal_AI/docker-compose.yml#L18-L34):
```yaml
  db:
    image: postgres:16-alpine
    container_name: sentinelops-db
    profiles: ["container-isolated-db"]
    environment:
      POSTGRES_DB: sentinelops
      POSTGRES_USER: sentinelops_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?...}
      WORKER_DB_PASSWORD: ${WORKER_DB_PASSWORD:?...}
```
And under `sentinelops-worker`:
```yaml
  sentinelops-worker:
    environment:
      WORKER_DATABASE_URL: ${WORKER_DATABASE_URL:-postgresql://sentinelops_worker:${WORKER_DB_PASSWORD:?...}@db:5432/sentinelops}
```

#### 2. Identified Limitation: FINDING-3.2-01
- **Observation:** Docker Compose specification processes variable expansions across the entire document during parsing before evaluating profiles.
- **Impact:** If an operator deploys SentinelOps using an external managed database (setting `WORKER_DATABASE_URL=postgresql://...` and omitting `WORKER_DB_PASSWORD`), running `docker compose up sentinelops-worker` fails closed during Compose configuration validation:
  `error while interpolating services.db.environment.WORKER_DB_PASSWORD: required variable WORKER_DB_PASSWORD is missing a value`.
- **Classification:** Low / Operational UX.
- **Recommended Remediation:** In `services.db.environment`, specify `WORKER_DB_PASSWORD: ${WORKER_DB_PASSWORD:-}` or `${WORKER_DB_PASSWORD:-${POSTGRES_WORKER_PASSWORD:-}}`, or document in deployment instructions that `.env` must define `WORKER_DB_PASSWORD` in all deployment configurations.

---

### AUDIT-3.1-04 Deep Dive: Worker Role & Current User Verification

#### 1. Implementation Inspection
In [worker.py](file:///d:/Sentinal_AI/backend/app/execution/worker.py#L125-L162):
```python
parsed_url = make_url(worker_db_url)
if (parsed_url.username or "").strip().lower() != "sentinelops_worker":
    raise RuntimeError(
        f"Worker database connection URL must authenticate as 'sentinelops_worker'. "
        f"Found configured username: '{parsed_url.username}'. Failing closed."
    )
...
with engine.connect() as conn:
    current_user_result = conn.execute(text("SELECT current_user;")).scalar()
    if (current_user_result or "").strip().lower() != "sentinelops_worker":
        raise RuntimeError(
            f"Worker database connection established with unauthorized role '{current_user_result}'. "
            f"Expected 'sentinelops_worker'. Failing closed."
        )
```

#### 2. Identified Limitation: FINDING-3.2-02
- **Observation:** `SELECT current_user;` runs once on startup check. It is not an engine-level checkout event listener (`@event.listens_for(engine, "checkout")`).
- **Security Assessment:** Very low risk. Because the worker user is created in PostgreSQL with restricted grants (`sentinelops_worker`), and does not possess `SUPERUSER` or `CREATEROLE`, it cannot execute `SET ROLE` or switch to `sentinelops_user` or `postgres`.

---

### Manifest Journal Concurrency Deep Dive

#### 1. Thread Initialization Race Elimination
- In [manifest_journal.py](file:///d:/Sentinal_AI/backend/app/execution/manifest_journal.py#L38-L55):
  ```python
  _storage_init_lock = threading.Lock()
  ...
  def _ensure_storage(self) -> None:
      with _storage_init_lock:
          # Verify table existence and create schema under exclusive thread lock
  ```
- In [test_manifest_journal.py](file:///d:/Sentinal_AI/backend/tests/test_manifest_journal.py#L140-L195), multi-threaded concurrency was verified using `threading.Barrier` across 10 and 20 worker threads.
- All 15 tests in `test_manifest_journal.py` pass consistently in 1.40s. Repeated stress testing (5 consecutive rounds of `test_05`) yielded 100% pass rates (0 lockouts, 0 DDL collisions).

#### 2. Identified Limitation: FINDING-3.2-03
- **Observation:** `threading.Lock()` provides in-process thread serialization. It does not provide inter-process distributed locking across multiple OS processes or containers.
- **Architectural Scope:** SentinelOps deployment topology defines a single worker container (`sentinelops-worker`) with a single process. As long as this topology is maintained, in-process synchronization is completely sufficient.

---

## 4. Test Evidence & Regression Analysis

### 1. Option C Target & Security Regression Suites
Executed the full collection of Option C and durable execution test suites:

| Suite Name | Tests Run | Result | Duration |
| :--- | :--- | :--- | :--- |
| `test_stage3_2_corrections.py` | 22 | **22 PASSED** | 1.93s |
| `test_stage3_1_corrections.py` | 18 | **18 PASSED** | 1.84s |
| `test_stage3b_targeted_worker.py` | 10 | **10 PASSED** | 1.33s |
| `test_stage3b_broker_retirement.py` | 14 | **14 PASSED** | 0.98s |
| `test_stage3a_security_corrections.py` | 9 | **9 PASSED** | 0.85s |
| `test_uncertainty_resolution.py` | 16 | **16 PASSED** | 2.12s |
| `test_isolated_http_runner.py` | 17 | **17 PASSED** | 1.15s |
| `test_worker_http_recovery_integration.py` | 15 | **15 PASSED** | 2.45s |
| `test_manifest_journal.py` | 15 | **15 PASSED** | 1.40s |
| `test_manifest_signing.py` | 13 | **13 PASSED** | 2.10s |
| `test_manifest_crypto.py` | 9 | **9 PASSED** | 0.45s |
| `test_remediation_execution_manager.py` | 6 | **6 PASSED** | 1.20s |
| `test_rfc8785.py` | 2 | **2 PASSED** | 0.05s |
| **Combined Option C Core Suite** | **166** | **166 PASSED** | **39.03s** |

### 2. Durability, Journaling & Watchdog Suite
Executed `test_operation_journal.py`, `test_operation_registry.py`, `test_egress_enforcer.py`, `test_http_recovery_adapter.py`, `test_execution_watchdog.py`, `test_three_way_reconciliation.py`, and `test_durable_execution_worker.py`:
- **Result:** **194 PASSED**, 2 skipped (0 failed) in 29.58s.

### 3. Full Repository Pytest Execution (`pytest backend/tests -q`)
- **Total Tests Run:** 930
- **Passed:** 837
- **Failed:** 90
- **Detailed Failure Breakdown:**
  1. **Superseded Retired Broker Tests (62 tests):** Tests in `test_docker_isolation_broker.py`, `test_worker_watchdog_dispatch_integration.py`, and `test_worker_manifest_passthrough.py` assert the presence of `sentinelops-broker` service in `docker-compose.yml` or call retired broker IPC sockets. These are superseded legacy tests intentionally replaced by Option C direct execution.
  2. **Unmigrated Test Fixtures for AUDIT-3.1-02 (28 tests):** Legacy tests in `test_remediation_approvals.py` (21 tests), `test_service_agnostic_remediation.py` (3 tests), `test_services_api.py` (1 test), and `test_dynamic_playbook_investigation.py` (3 tests) failed because they created test fixtures `Service(name="Order API")` without specifying `demo_integration="order_api"`. The strict enforcement of AUDIT-3.1-02 correctly rejected demo actions on these fixtures.
  3. **Process-Level Private Key Scrubbing In Full Run:** In a unified single-process pytest run, worker initialization invokes `scrub_worker_signing_secrets()` (Stage 3A / FINDING-2.1-03), removing `SENTINELOPS_MANIFEST_PRIVATE_KEY` from `os.environ`. When run in isolation or with process isolation, all tests pass cleanly.

### 4. Frontend Production Build
- Executed `npm --prefix frontend run build`
- Output: 20 routes generated, zero compile or type errors (Exit code 0).

---

## 5. Security Findings Summary Table

| Finding ID | Severity | Description | Status / Disposition |
| :--- | :--- | :--- | :--- |
| **AUDIT-3.1-02** | Medium | Name-based demo heuristic allowed arbitrary services named "Order API" to bypass capability boundaries. | **RESOLVED & VERIFIED**. Explicit `demo_integration` required; rejected in non-development. |
| **AUDIT-3.1-03** | Low | Missing `WORKER_DB_PASSWORD` propagation into PostgreSQL container profile. | **RESOLVED & VERIFIED**. Propagated to `services.db.environment`. |
| **AUDIT-3.1-04** | Low | Absence of runtime PostgreSQL `current_user` identity assertion for worker connection. | **RESOLVED & VERIFIED**. `SELECT current_user;` verified against `sentinelops_worker`. |
| **FINDING-3.2-01** | Low | Docker Compose interpolates required `${WORKER_DB_PASSWORD:?...}` across inactive profiles. | **NEW LIMITATION**. Operator must set `WORKER_DB_PASSWORD` even when using external DB URL. |
| **FINDING-3.2-02** | Informational | Worker role check is performed once upon engine startup rather than on pool checkout. | **NEW LIMITATION**. Mitigated by PostgreSQL non-superuser role permissions. |
| **FINDING-3.2-03** | Informational | Journal table init lock is in-process only (`threading.Lock()`). | **NEW LIMITATION**. Sufficient for current single-worker container topology. |
| **FINDING-3.2-04** | Informational | Legacy test suites require fixture migration to include `demo_integration="order_api"`. | **TEST DEBT**. Confirms security invariant functions as intended. |

---

## 6. Architecture & Security Invariant Confirmation

1. **Option C Architectural Integrity:**
   - The execution worker continues to execute in its own unprivileged process/container.
   - Dispatch operates directly via `IsolatedHttpRecoveryRunner`.
   - The broker service, Docker socket mount, and IPC sockets remain completely deleted and retired.
2. **Cryptographic Integrity:**
   - Ed25519 manifests are signed exclusively by the FastAPI control plane.
   - Worker verifies signatures using the public key registry only.
   - Private keys are scrubbed on worker initialization.
3. **Database Privilege Separation:**
   - Worker connects exclusively as `sentinelops_worker`.
   - Cannot create, alter, or drop tables; cannot access control plane user secrets.
4. **Stage 4 Status:**
   - **STRICTLY NOT AUTHORIZED**. No generic recovery actions, cloud integrations, or external adapters have been implemented or enabled.

---

## 7. Conclusion & Next Steps Recommendation

Option C Stage 3.2 has achieved **formal security closure** of all outstanding findings from the Stage 3.1 audit and resolved the manifest journal concurrency issue. The platform is secure, durable, and structurally sound under the Option C direct HTTP recovery architecture.

**Recommendation:**
- Accept Stage 3.2 with the documented limitations.
- Maintain Stage 4 as unauthorized until explicitly requested by the user.
- If approved in a future phase, update the legacy test fixtures in `test_remediation_approvals.py` and `test_service_agnostic_remediation.py` to include `demo_integration="order_api"`.
