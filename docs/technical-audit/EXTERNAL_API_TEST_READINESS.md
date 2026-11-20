# SentinelOps AI — Focused Technical Audit: External API Recovery Readiness

**Audited Target:** External Disposable Service (e.g., Payment API)
**Document Path:** `docs/technical-audit/EXTERNAL_API_TEST_READINESS.md`
**Date:** November 7, 2026
**Status:** Complete Audit

---

## Executive Summary & Direct Answers

| Question | Answer | Details & Exact Code Location |
| :--- | :---: | :--- |
| **Can we register a new Payment API?** | **YES** | Implemented via `POST /api/v1/services` and UI Modal on `/services`. Requires workspace `engineer` or `admin` role. |
| **Can we configure its playbook through the UI?** | **YES** | Implemented via 8-step wizard on `/playbooks/new`. Can link to newly registered service ID and `execute_http_recovery`. |
| **Can SentinelOps detect its failure?** | **YES** | Implemented via deterministic evaluator `POST /api/v1/detector/evaluate/{service_id}` probing `/health` and evaluating `HealthStatusRule`. |
| **Can it invoke a recovery endpoint on that API?** | **YES** | Implemented via `execute_http_recovery` using `HttpRecoveryModel` in containerized runner `run_http_recovery` via HTTP POST. |
| **Can it verify the recovery?** | **YES** | Implemented via `PostExecutionVerificationEngine` performing 1 baseline + 3 consecutive passing probes against `/health`. |
| **Are there critical limitations/conditions?** | **YES** | Requires specific port/host allowlisting in dev, exact relative recovery path format, and Prometheus/health endpoint conventions. |

---

## 1. Service Registration

### 1.1 How Users Register a Service
Users register services either via the Dashboard Web UI or direct REST API:
- **Frontend Page:** [`frontend/src/app/(dashboard)/services/page.tsx`](file:///D:/Sentinal_AI/frontend/src/app/(dashboard)/services/page.tsx#L89-L115) (`handleCreateService` modal trigger)
- **Backend API Endpoint:** `POST /api/v1/services` defined in [`backend/app/api/v1/endpoints/services.py`](file:///D:/Sentinal_AI/backend/app/api/v1/endpoints/services.py#L100-L147)
- **Authorization Requirement:** Caller must have at least `engineer` role in the targeted `workspace_id` (enforced by `check_workspace_role`).

### 1.2 Required Fields and Schema
Validation is governed by Pydantic schema `ServiceCreate` in [`backend/app/schemas/service.py`](file:///D:/Sentinal_AI/backend/app/schemas/service.py#L8-L47):

| Field | Type / Enum | Required | Default | Validation & Rules |
| :--- | :--- | :---: | :---: | :--- |
| `workspace_id` | `str` (UUID) | **Yes** | - | Must match an existing workspace where user has engineer/admin permissions. |
| `name` | `str` (2-100 chars) | **Yes** | - | Unique per workspace. Duplicates trigger `HTTP 409 Conflict`. |
| `environment` | `Literal["development", "staging", "production"]` | No | `"development"` | Controls runtime execution policies and SSRF network boundary rules. |
| `health_check_url` | `str` | **Yes** | - | Must start with `http://` or `https://`. Validated by `validate_url_format`. Not probed on creation. |
| `monitoring_method` | `Literal["prometheus", "opentelemetry", "builtin"]` | No | `"prometheus"` | Determines whether `/metrics` scraper runs during detection and verification. |
| `execution_policy` | `Literal["demo", "approval_required", "observe_only"]` | No | `"demo"` | `"observe_only"` blocks all remediation. `"demo"` requires `environment="development"`. |

### 1.3 Supported Health-Check URL Formats & Network Rules
- **Scheme:** Must strictly be `http` or `https` (regex checked in [`backend/app/schemas/service.py`](file:///D:/Sentinal_AI/backend/app/schemas/service.py#L38)).
- **SSRF Validation Rules:** Evaluated at detection/execution runtime via `validate_target_url` in [`backend/app/detector/validator.py`](file:///D:/Sentinal_AI/backend/app/detector/validator.py#L33-L102) and `resolve_safe_target_url` in [`backend/app/execution/network.py`](file:///D:/Sentinal_AI/backend/app/execution/network.py#L113-L200):
  - **Forbidden Hostnames:** `169.254.169.254`, `metadata.google.internal`, link-local ranges (`fe80::/10`), embedded credentials (`http://user:pass@host`).
  - **Local Development Exception:** When `environment="development"`, loopback hostnames (`127.0.0.1`, `localhost`, `host.docker.internal`) are permitted.
  - **Port Allowlist:** In `development`, loopback/local targets are permitted on ports `1024-65535` or demo ports `8001, 8002, 9000` ([`backend/app/execution/network.py`](file:///D:/Sentinal_AI/backend/app/execution/network.py#L167)).
  - **Custom Subpaths:** Paths like `http://127.0.0.1:9200/health` or `http://127.0.0.1:9200/api/v1/health` are fully supported.

---

## 2. Remediation Playbooks

### 2.1 Creation Process & Backend Flow
- **Frontend Page:** 8-step wizard in [`frontend/src/app/(dashboard)/playbooks/new/page.tsx`](file:///D:/Sentinal_AI/frontend/src/app/(dashboard)/playbooks/new/page.tsx).
- **Backend Endpoint:** `POST /api/v1/playbooks` in [`backend/app/api/v1/endpoints/playbooks.py`](file:///D:/Sentinal_AI/backend/app/api/v1/endpoints/playbooks.py#L36-L61).
- **Service Handler:** `PlaybookService.create_playbook` in [`backend/app/remediation/playbook_service.py`](file:///D:/Sentinal_AI/backend/app/remediation/playbook_service.py#L65-L158).
- **Storage Models:**
  - `Playbook` (Metadata, current version pointer, active toggle) in [`backend/app/models/playbook.py`](file:///D:/Sentinal_AI/backend/app/models/playbook.py#L34-L78).
  - `PlaybookVersion` (Immutable versioned spec: `action_template_id`, `supported_scenarios`, `parameter_schema`, `verification_criteria`) in [`backend/app/models/playbook.py`](file:///D:/Sentinal_AI/backend/app/models/playbook.py#L81-L153).
  - `ServicePlaybookAssociation` (Many-to-many service binding with priority ranking) in [`backend/app/models/playbook.py`](file:///D:/Sentinal_AI/backend/app/models/playbook.py#L156-L208).

### 2.2 Supported Triggers / Scenarios
Deterministic scenario matching is implemented via `SCENARIO_SPEC_REGISTRY` in [`backend/app/agents/nodes/playbooks.py`](file:///D:/Sentinal_AI/backend/app/agents/nodes/playbooks.py#L115-L210):
- `*` or `all`: Universal trigger (matches any incident on the associated service).
- `http_5xx_rate_exceeded`: Matches when trigger or title mentions `5xx`, HTTP status `500, 502, 503, 504`, or rule `Prometheus_5xx_Error_Rule` / `HTTP_Health_Status_Rule`.
- `health_check_failure`: Matches when probe to `/health` fails, times out, or triggers `HTTP_Health_Status_Rule`.
- `high_latency` / `latency_spike`: Matches `High_Latency_Rule` or latency alerts.
- `demo_failure`: Matches simulated failure states.
- `worker_process_failure`: Matches background consumer alerts.

### 2.3 Associating Playbooks with a Newly Registered Service
- **Can a playbook be bound to a new service?** **YES.**
- In Step 2 of the wizard, any active service in the workspace can be selected via `selectedServiceIds`.
- The backend persists this via `ServicePlaybookAssociation(workspace_id=..., service_id=..., playbook_id=..., priority=10, is_active=True)`.

---

## 3. Available Remediation Actions Catalog

Below is the verified inventory of all actions in [`backend/app/remediation/registry.py`](file:///D:/Sentinal_AI/backend/app/remediation/registry.py#L48-L322):

| Action ID | Status | Category | Supported Services | Approval Required | Broker Permitted? | Executor Implementation |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `inspect_service_health` | **EXECUTABLE** | Diagnostics | `*` (Any service with `health_check_url`) | No (Low Risk) | Yes | Probes `/health`, `/demo/status`, `/metrics` via `run_inspect_service_health`. |
| `execute_http_recovery` | **EXECUTABLE** | Service Recovery | `*` (Any service with active playbook) | **Yes** (Medium Risk) | Yes | POSTs to derived relative recovery URL via `run_http_recovery`. |
| `restore_order_api_demo` | **EXECUTABLE** | Service Recovery | `Order API` only (Restricted port 8001/8002) | **Yes** (Medium Risk) | Yes | POSTs to `/demo/restore` via `run_restore_order_api_demo`. |
| `restart_order_api` | **EXECUTABLE** | Service Recovery | `Order API` only | **Yes** (Medium Risk) | Yes | Simulates process restart for Order API demo. |
| `disable_service_monitoring` | **PARTIAL** | Monitoring | `*` (Any service ID) | **Yes** (High Risk) | No | DB state change only (`is_active=False`); no container runner needed. |
| `restart_service` | **UNSUPPORTED** | Service Recovery | `*` (`REQUIRES_ADAPTER`) | Yes (High Risk) | No | Missing Docker/Kubernetes host lifecycle daemon. |
| `rollback_deployment` | **UNSUPPORTED** | Service Recovery | `*` (`REQUIRES_ADAPTER`) | Yes (High Risk) | No | Missing K8s / ArgoCD deployment orchestrator adapter. |
| `clear_application_cache` | **UNSUPPORTED** | Service Recovery | `*` (`REQUIRES_ADAPTER`) | Yes (Medium Risk) | No | Missing Redis / Memcached client adapter. |

---

## 4. Generic HTTP Recovery (`execute_http_recovery`)

### 4.1 Invoking External Services
- **Can it call any registered service?** **YES.**
- It does not contain service name hardcoding. It targets any registered service provided:
  1. The service has an active `health_check_url`.
  2. The service is associated with an active playbook specifying `execute_http_recovery`.
  3. The request parameters satisfy `HttpRecoveryParams`.

### 4.2 Parameter Validation & Schema
Enforced by Pydantic model `HttpRecoveryParams` in [`backend/app/remediation/schemas.py`](file:///D:/Sentinal_AI/backend/app/remediation/schemas.py#L131-L185):

```json
{
  "service_id": "535f04e0-f1ff-4096-9011-e4e2c7234398",
  "recovery_path": "/admin/recovery/reset",
  "payload": null,
  "expected_status_codes": [200],
  "timeout_seconds": 10
}
```

- `service_id` (`str`, UUID): Target service UUID. Must match the execution target service.
- `recovery_path` (`str`): Relative recovery path starting with `/`. Validated by `validate_relative_recovery_path`:
  - Must start with `/`.
  - Must NOT be root `/` alone.
  - Prohibits scheme injection (`http://`, `https://`, `://`).
  - Prohibits directory traversal (`..`).
  - Prohibits double slashes (`//`).
  - Prohibits query strings (`?`), fragments (`#`), credentials (`@`), backslashes (`\`), or percent encoding (`%`).
  - Regex whitelist: `^/[a-zA-Z0-9_./-]*$`.
- `payload` (`Optional[Dict[str, Any]]`): Optional JSON body. Scanned against arbitrary code/script injection patterns via `_scan_for_arbitrary_code`.
- `expected_status_codes` (`List[int]`): List of acceptable 2xx HTTP response codes (default `[200]`). Codes outside 200–299 are rejected at schema validation time.
- `timeout_seconds` (`int`): Bounded between `1` and `60` seconds (default `30`).
- Model enforces `extra="forbid"`.

### 4.3 URL Construction & Security Restrictions
- **URL Derivation:** Handled by `build_recovery_url` in [`backend/app/remediation/schemas.py`](file:///D:/Sentinal_AI/backend/app/remediation/schemas.py#L82-L115):
  - Takes `service.health_check_url` (e.g., `http://127.0.0.1:9000/health`) and extracts scheme, host, and port.
  - Appends `recovery_path` (e.g., `/admin/recovery/reset`).
  - Result: `http://127.0.0.1:9000/admin/recovery/reset`.
  - Absolute target URLs can **never** be supplied by user input, preventing arbitrary network egress.
- **HTTP Method:** Strictly restricted to **`POST`** only in `run_http_recovery` ([`services/executor/runner.py`](file:///D:/Sentinal_AI/services/executor/runner.py#L442)).
- **Redirects:** Strictly prohibited (`follow_redirects=False`). HTTP 301/302/303/307/308 responses raise an immediate runtime security error.
- **DNS / IP Pinning:** Handled by `PinnedIPTransport` in [`services/executor/runner.py`](file:///D:/Sentinal_AI/services/executor/runner.py#L432) to prevent DNS rebinding attacks.

---

## 5. End-to-End Incident & Playbook Workflow

The complete path is fully wired across the following stages:

```mermaid
sequenceDiagram
    autonumber
    participant Ext as External Payment API
    participant Det as Detector Engine
    participant Graph as LangGraph Investigation
    participant Play as Playbook Matcher
    participant User as SRE Engineer (UI)
    participant Exec as Execution Manager & Worker
    participant Cont as Isolated Docker Executor
    participant Ver as Verification Engine

    Ext->>Det: GET /health returns 503 Service Unavailable
    Det->>Det: HealthStatusRule triggers alert
    Det->>Graph: Incident created (state: detected)
    Graph->>Ext: Diagnostic probe (GET /health, /metrics)
    Graph->>Play: discover_active_playbooks + evaluate_playbook_compatibility
    Play->>Graph: Matches 'execute_http_recovery' playbook (Scenario match)
    Graph-->>User: Proposes RemediationRecommendation (Awaiting Approval)
    User->>Exec: POST /approvals/{id}/approve & POST /executions
    Exec->>Cont: Dispatches execute_http_recovery (POST /admin/recovery/reset)
    Cont->>Ext: POST /admin/recovery/reset -> HTTP 200 OK
    Exec->>Ver: PostExecutionVerificationEngine.run_verification_cycle
    Ver->>Ext: 1 Baseline + 3 Consecutive Passing Probes (GET /health)
    Ver-->>Exec: Verification PASS
    Exec-->>Det: Incident transitions to 'recovered'
```

### Trace of Individual Stages:
1. **Failure Detection:** `run_evaluation_for_service` ([`backend/app/detector/runner.py`](file:///D:/Sentinal_AI/backend/app/detector/runner.py#L46-L92)) probes `service.health_check_url`. If HTTP 503 is returned, `process_detection_lifecycle` creates an `Incident` in state `detected`.
2. **Investigation & Playbook Discovery:** `start_incident_investigation` ([`backend/app/api/v1/endpoints/investigations.py`](file:///D:/Sentinal_AI/backend/app/api/v1/endpoints/investigations.py#L30-L95)) triggers `run_investigation`:
   - `discover_active_playbooks` queries active playbooks associated with `service_id`.
   - `evaluate_playbook_compatibility` evaluates triggers using `SCENARIO_SPEC_REGISTRY`. An alert of `Elevated 5xx error: HTTP 503` matches `http_5xx_rate_exceeded` and `health_check_failure` ([`backend/app/agents/nodes/playbooks.py`](file:///D:/Sentinal_AI/backend/app/agents/nodes/playbooks.py#L210)).
   - `rank_compatible_playbooks` ranks eligible playbooks.
   - `generate_remediation_recommendation` outputs Outcome A: actionable recommendation.
   - `persist_investigation_results` transitions incident to `awaiting_approval`.
3. **Approval:** Engineer calls `POST /api/v1/remediation/approvals/{id}/approve` ([`backend/app/api/v1/endpoints/remediation.py`](file:///D:/Sentinal_AI/backend/app/api/v1/endpoints/remediation.py#L200-L245)).
4. **Execution Initiation:** Calling `POST /api/v1/remediation/executions` triggers `RemediationExecutionManager.trigger_execution` ([`backend/app/execution/manager.py`](file:///D:/Sentinal_AI/backend/app/execution/manager.py#L215-L350)), validating parameters and queueing the execution.
5. **Worker & Broker Dispatch:** `DurableExecutionWorker` claims the job ([`backend/app/execution/worker.py`](file:///D:/Sentinal_AI/backend/app/execution/worker.py#L650-L750)), derives `target_url` using `build_recovery_url`, and dispatches via `RestrictedDockerBroker`.
6. **Containerized Execution:** Ephemeral container runs `run_http_recovery` ([`services/executor/runner.py`](file:///D:/Sentinal_AI/services/executor/runner.py#L412)), issuing `POST http://<host>:<port>/<recovery_path>`.
7. **Verification:** `PostExecutionVerificationEngine` probes `/health` until 3 consecutive passes occur, marking execution `verified` and recovering the incident.

---

## 6. Verification Mechanics for External Generic Services

Implemented in [`backend/app/execution/verification.py`](file:///D:/Sentinal_AI/backend/app/execution/verification.py#L350-L560):

1. **Protocol:** Verification does not make raw backend network calls. It dispatches read-only action `inspect_service_health` through the broker into an isolated verification container.
2. **Endpoints Probed:**
   - **`GET /health` (Mandatory):** Probed at `service.health_check_url`. Must return HTTP 200 with JSON containing `{"status": "healthy"}` or `{"status": "ok"}` (or empty body with HTTP 200).
   - **`GET /demo/status` (Service-specific):** Only evaluated if `service.name` contains `"order api"` or action is `restore_order_api_demo`. For generic external services (e.g. Payment API), **this check is automatically skipped** ([`backend/app/execution/verification.py`](file:///D:/Sentinal_AI/backend/app/execution/verification.py#L365,L511-L514)).
   - **`GET /metrics` (Conditional on `monitoring_method`):**
     - If `monitoring_method="prometheus"`, it probes `<origin>/metrics` and expects valid Prometheus text exposition with an `http_5xx_errors_total` counter. The counter must not increase above baseline.
     - If `monitoring_method="builtin"` or `"opentelemetry"`, the Prometheus scrape is **skipped** and does not block verification pass ([`backend/app/execution/verification.py`](file:///D:/Sentinal_AI/backend/app/execution/verification.py#L490,L527)).
3. **Pass Criteria:**
   - Exactly **1 baseline probe** (Probe #1) is captured immediately following execution.
   - Followed by **3 consecutive passing probes** (Probes #2, #3, #4) without intermediate failures.
   - Any single probe failure resets the consecutive pass counter to zero.
   - Must complete within the 45-second cycle deadline (`DEFAULT_CYCLE_DEADLINE_SECONDS = 45`).

---

## 7. Test Requirements for a Disposable External Payment API

To ensure complete, out-of-the-box compatibility with SentinelOps AI detection, investigation, execution, and verification, a disposable Payment API should implement the following specifications:

### 7.1 Networking & Bind Address
- **Host / IP:** `127.0.0.1` (or `localhost`).
- **Port:** Any port between `1024` and `65535` (e.g. `9200`). *Port 9000, 9100, 9200 are standard demo ports*.
- **Service Environment in SentinelOps:** Register service with `environment="development"` and `execution_policy="demo"` or `"approval_required"`.

### 7.2 Required Endpoints

#### A. Health Endpoint: `GET /health`
- **When Operational:** Return HTTP 200 OK.
  ```json
  {
    "status": "healthy",
    "service": "Payment API",
    "timestamp": "2026-11-07T10:00:00Z"
  }
  ```
- **When Failure Injected:** Return HTTP 503 Service Unavailable.
  ```json
  {
    "status": "unhealthy",
    "service": "Payment API",
    "failure_active": true,
    "failure_reason": "Payment gateway gateway timeout"
  }
  ```

#### B. Recovery Endpoint: `POST /admin/recovery/reset` (or similar relative path)
- **Method:** `POST` strictly.
- **Request Body:** Accepts optional JSON payload or empty body.
- **Behavior:** Resets internal failure state so `/health` immediately returns HTTP 200.
- **Response:** Return HTTP 200 OK.
  ```json
  {
    "success": true,
    "message": "Payment API simulated failure cleared"
  }
  ```

#### C. Optional Failure Injection Endpoint: `POST /demo/simulate-failure`
- Allows manual triggering of simulated 503 state for repeatable automated testing.

#### D. Metrics Endpoint: `GET /metrics` (Conditional)
- **Option 1 (Recommended — Zero Telemetry Setup):** When registering the service in SentinelOps, set `monitoring_method: "builtin"`. The verification engine will skip Prometheus scraping and rely entirely on `GET /health`.
- **Option 2 (Prometheus Telemetry Scrape):** If `monitoring_method: "prometheus"`, expose standard Prometheus text exposition format on `/metrics` with standard counter metric:
  ```prometheus
  # HELP http_5xx_errors_total Total 5xx server errors
  # TYPE http_5xx_errors_total counter
  http_5xx_errors_total{endpoint="/health"} 0.0
  ```

---

## Conclusion & Operational Checklist

SentinelOps AI **is ready** to test onboarding and autonomous recovery of a fresh, disposable external Payment API:

1. **Register Service:** Name: `Payment API`, Environment: `development`, URL: `http://127.0.0.1:9200/health`, Monitoring: `builtin` (or `prometheus`), Policy: `approval_required`.
2. **Create Playbook:** Action: `execute_http_recovery`, Scenarios: `["health_check_failure", "http_5xx_rate_exceeded"]`, Path: `/admin/recovery/reset`, Expected Status: `[200]`, Associated Service: `Payment API`.
3. **Simulate Outage:** Trigger 503 on the Payment API and invoke `POST /api/v1/detector/evaluate/{service_id}`.
4. **Investigate & Remediate:** LangGraph automatically selects the Payment API recovery playbook, prompts human approval, dispatches `POST /admin/recovery/reset`, verifies recovery via 3 consecutive health probes, and marks the incident resolved.
