# SentinelOps AI — System Architecture & Incident Lifecycle Specification

This document details the architectural implementation of SentinelOps AI, covering detection, autonomous background polling, incident lifecycle state machines, role-based security controls, and documented operational limitations.

---

## 1. Autonomous Background Detection & Polling Architecture

### 1.1 Overview
SentinelOps AI implements continuous, deterministic health and telemetry monitoring without relying on external task queues (e.g., Celery, Redis) or manual user polling. The architecture leverages native asynchronous I/O (`asyncio`) managed via the FastAPI application `lifespan` context.

```
                    FastAPI Lifespan Startup
                              │
                              ▼
                 [BackgroundDetectorPoller]
                              │
        ┌─────────────────────┴─────────────────────┐
        │ Interval loop (DETECTOR_POLL_INTERVAL)     │
        │                                           │
        ▼                                           ▼
[Query Active Services]                  [Bounded Concurrency]
  Service.is_active == True               asyncio.Semaphore(max_concurrency)
  Workspace-isolated                      Overlap Set: in-flight service IDs
        │                                           │
        └─────────────────────┬─────────────────────┘
                              ▼
                [Guarded Service Evaluation]
               ┌──────────────┴──────────────┐
               ▼                             ▼
       /health Probing              /metrics (Prometheus)
       HTTP status & latency        5xx totals (strict regex)
               │                             │
               └──────────────┬──────────────┘
                              ▼
                [Deterministic Rules Engine]
                - Health status != 200
                - Elevated 5xx error rate
                - Latency threshold exceeded
                              │
                              ▼
              [Incident Lifecycle Manager]
         (Creation / Deduplication / Recovery)
```

### 1.2 Core Components
- **`BackgroundDetectorPoller` (`app.detector.poller`)**:
  - Encapsulates the background evaluation loop, bounded concurrency semaphore (`DETECTOR_MAX_CONCURRENCY`), in-flight overlap tracking set (`_evaluating_services`), and shared connection-pooled `httpx.AsyncClient`.
  - **FastAPI Lifespan Integration**: Automatically starts on server startup (`await detector_poller.start()`) and cancels/awaits task termination on shutdown (`await detector_poller.stop()`).
  - **Active Target Selection**: Loads only services with `is_active == True` from PostgreSQL using isolated per-evaluation database sessions (`SessionLocal`).
  - **Error Isolation**: Individual service network errors, timeouts, or DNS failures are safely caught and logged without terminating the polling cycle or affecting other targets.
  - **Overlap Prevention**: Before evaluating a service, an atomic check acquires an `asyncio.Lock` and verifies `service_id` is not already in `_evaluating_services`. If an evaluation for that service is already running (e.g. slow target), subsequent evaluation passes skip the service until completion.

### 1.3 Target Validation & SSRF Safeguards
All service endpoints are validated by `validate_safe_url` before connection attempts:
- Allowed schemes: `http://` and `https://` only.
- Embedded credentials in URLs are strictly rejected (`user:pass@host`).
- Cloud metadata IP addresses (`169.254.169.254`, `metadata.google.internal`) are blocked.
- Loopback addresses (`127.0.0.1`, `localhost`) are permitted only when `ALLOW_LOCAL_PROBES=True` (development/demo mode).

---

## 2. Incident Lifecycle State Machine

### 2.1 Defined States
Incidents progress through deterministic states tracked in the PostgreSQL `incidents` table:

| State | Description | Active / Deduplicated? |
|---|---|---|
| `detected` | Incident newly opened by a deterministic alert rule. | Yes |
| `investigating` | Agentic AI investigation is actively in progress. | Yes |
| `awaiting_approval` | Investigation successfully completed; root-cause diagnosis and evidence prepared. | Yes |
| `investigation_failed` | Investigation encountered a timeout or unhandled graph exception; available for safe retry. | Yes |
| `remediating` | Remediation plan approved and undergoing execution (Phase 4). | Yes |
| `verifying` | Post-remediation verification probe running. | Yes |
| `recovered` | Service health probes and telemetry confirmed healthy. | No (Closed) |
| `closed` | Incident manually acknowledged and closed by operator. | No (Closed) |

### 2.2 Lifecycle Rules & Deduplication Window
`ACTIVE_INCIDENT_STATUSES = ["detected", "investigating", "awaiting_approval", "investigation_failed", "remediating", "verifying"]`

1. **Failure with No Active Incident**: A new `Incident` record is created with `status="detected"`, and an initial detection event is appended to `incident_events`.
2. **Repeated Failure with Active Incident**: If an incident is already in any active state (`detected`, `investigating`, `awaiting_approval`, or `investigation_failed`), subsequent background poll failures deduplicate against the existing incident without creating duplicates.
3. **Recovery Detection**: When health probes and metrics confirm a failing service is restored to normal:
   - The active incident transitions to `recovered`.
   - `recovered_at` timestamp is set to UTC now.
   - A verification timeline event is committed to `incident_events`.
4. **Preservation of Recovered Incidents**: An incident marked `recovered` or `closed` is immune to being overwritten by subsequent investigation graph completions or failures.

---

## 3. Investigation Execution Architecture

### 3.1 LangGraph State Machine
```
START ──► [context] ──► [check status]
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
        (failed)                      (running)
             │                           │
             ▼                           ▼
     [persistence] ◄── [summary] ◄── [evaluation] ◄── [hypotheses] ◄── [evidence]
             │
            END
```

### 3.2 Concurrency Control & Race Prevention
1. **Pre-persisted Lock**: When an engineer triggers `POST /api/v1/incidents/{incident_id}/investigate`, an `Investigation` record is immediately committed to PostgreSQL with `status="running"`. Any concurrent requests hitting the endpoint are immediately rejected with `HTTP 409 Conflict`.
2. **Safe Retry After Failure**: If an investigation previously failed, the incident rests in `investigation_failed` and the prior investigation is marked `status="failed"`. Subsequent trigger requests succeed without requiring `force_refresh`.
3. **Timeout & Exception Safety**: All graph execution passes through `asyncio.wait_for(app.ainvoke(initial_state), timeout=settings.INVESTIGATION_TIMEOUT_SECONDS)`. If a timeout or unhandled exception occurs:
   - `Investigation` record is updated to `status="failed"` with sanitized error messages.
   - `Incident` status updates to `investigation_failed` (preserving recovered/closed status).
   - An audit event is persisted to `incident_events`.

---

## 4. Security & Access Control

### 4.1 Role-Based Permissions (RBAC)
- **Admin**: Full access across workspace resources, user provisioning, evaluation execution, and investigation triggering.
- **Engineer**: Authorized to register/manage services, trigger evaluations (`POST /evaluate`), trigger AI investigations, and inspect telemetry.
- **Viewer**: Read-only access to dashboard, service catalog, incidents, and investigation reports. Explicitly rejected (HTTP 403) from triggering evaluations or investigations.

### 4.2 Multi-Tenant Workspace Isolation
Every service evaluation (`POST /api/v1/detector/evaluate/{service_id}`) and investigation (`POST /api/v1/incidents/{incident_id}/investigate`) verifies that:
1. The user has an active membership in the workspace owning the target service/incident.
2. Cross-workspace attempts return HTTP 403 Forbidden.
3. Non-existent targets return HTTP 404 Not Found.

### 4.3 Demo Seeding Endpoint Hardening
`POST /api/v1/auth/seed-demo` is strictly restricted to development and test environments:
- Allowed environments: `development`, `dev`, `test`, `testing`, `local`.
- If requested under `production` or `staging`, returns `HTTP 403 Forbidden` with zero credential disclosure.

---

## 5. Remediation Foundation Architecture (Phase 4.1)

### 5.1 Allowlisted Action Registry
Remediation actions in SentinelOps AI are governed by an explicit, modular action registry (`app.remediation.registry`).
- **Explicit Allowlist**: Unknown action IDs are rejected unconditionally.
- **Strict Parameter Schemas**: Each allowlisted action defines a dedicated Pydantic parameter schema with `extra="forbid"`, preventing injection of arbitrary commands, shell strings, raw code, or untrusted URLs.
- **Initial Catalog (MVP)**:
  - `restart_order_api`: Category `service_recovery`, Risk `medium`, requires human approval, target port localhost:8001.
  - `inspect_service_health`: Category `diagnostics`, Risk `low`, pre-approved without human approval, read-only.
  - `disable_service_monitoring`: Category `monitoring`, Risk `high`, requires human approval, deactivates active detector polling.

### 5.2 Risk Classification & Approval Rules
Actions are classified into three immutable risk levels:
- **`LOW`**: Read-only diagnostic actions. Can execute without human approval when explicitly pre-approved by policy.
- **`MEDIUM`**: Actions affecting service availability or runtime state. Require human approval unless explicitly configured otherwise.
- **`HIGH`**: Actions significantly altering operational or monitoring state. **Strictly require human approval at all times.**

### 5.3 Independent Backend Policy Engine
The backend policy engine (`app.remediation.policy`) is the final and sole authority on action authorization:
- **AI Separation**: The AI agent can propose actions from the catalog, but **cannot authorize or execute them**.
- **Immutable Risk & Approval**: AI-supplied risk downgrades or approval override flags are strictly ignored by the policy engine; canonical values are always enforced from the backend registry.
- **Multi-Tenant Workspace Scoping**: Cross-workspace service references are rejected (`decision="rejected"`). Workspace IDs supplied by callers or AI proposals are never trusted; target services must be verified in the caller's authorized workspace.
- **Role Enforcement (RBAC)**: Users with the `viewer` role are strictly prohibited from authorizing operational actions (`medium` or `high` risk, or recovery/monitoring actions). Viewers may only inspect the catalog and evaluate low-risk read-only diagnostics.
- **Preconditions**: Ensures services exist and satisfy operational state prerequisites (e.g. inactive services cannot be restarted).

### 5.4 Auditability & Persistence
Every policy evaluation evaluated via `POST /api/v1/remediation/policy/evaluate` persists an immutable audit record in PostgreSQL (`policy_decisions` table):
- Records `workspace_id`, `user_id`, `action_id`, `target_service_id`, `risk_level`, `decision`, `decision_reason`, `policy_version`, `validated_parameters`, and UTC timestamp.
- Available for compliance inspection via `GET /api/v1/remediation/policy/decisions`.

### 5.5 Connection to Future Stages (Phase 4.3)
Phase 4.1 provided the foundational policy, registry, and audit boundary. Decisions returning `decision="approval_required"` are promoted into Phase 4.2 Human Approvals.
- **Phase 4.3 (Isolated Execution & Verification)**: An isolated execution worker will run only pre-approved, parameterized actions against sandboxed targets with post-execution verification probes.

---

## 6. Human Approval Workflow Architecture (Phase 4.2)

### 6.1 Approval Data Model & Lifecycle
The human approval system (`app.models.remediation.RemediationApproval`) establishes an immutable, auditable gate between policy decisions and future remediation execution:
- **Statuses**:
  - `pending`: Awaiting human review by an authorized Engineer or Admin.
  - `approved`: Formally authorized by a human reviewer. Becomes eligible for Phase 4.3 execution.
  - `rejected`: Explicitly declined by a human reviewer with a mandatory rationale.
  - `expired`: Deadline elapsed (`expires_at <= now_utc`); cannot be approved.
  - `cancelled`: Retracted by the original requester or a workspace Admin.
- **Audited Fields**:
  `approval_id`, `workspace_id`, `incident_id`, `investigation_id`, `action_id`, `target_service_id`, `validated_parameters`, `risk_level`, `policy_version`, `policy_decision_id`, `requested_by`, `requested_at`, `reviewed_by`, `reviewed_at`, `rejection_reason`, and `expires_at`.

### 6.2 Immutability, Tamper Resistance & Tenant Revalidation
- **Strict Parameter & Action Binding**: An approval is bound to the exact `action_id`, `target_service_id`, and `validated_parameters` validated during policy evaluation. The reviewer cannot alter these fields during approval. Any attempt to modify parameters requires creating a new policy evaluation.
- **Untrusted Override Rejection**: `ai_proposed_risk` and `ai_proposed_approval` have been excised from public evaluation schemas with `extra="forbid"`. AI agents or clients cannot manipulate risk tiers or bypass approvals.
- **Precondition & Tenant Revalidation**: When an approval is requested, the system verifies that the target service exists, is active, and belongs to both the approval's workspace and the currently authorized workspace (`service.workspace_id == approval.workspace_id == caller_workspace_id`). If the service has been deactivated or reassigned across workspaces between proposal and approval, the approval is rejected with `HTTP 400 Bad Request`.
- **Database-Level Duplicate Prevention**: Beyond application-level validation, a PostgreSQL/SQLite partial unique index `uq_pending_policy_decision` enforces that only one `pending` approval request can exist for a given `policy_decision_id`. Concurrent creation attempts trigger an `IntegrityError`, which is rolled back and returns `HTTP 409 Conflict`.
- **Non-Pending Proposal Re-creation**: Proposals with status `approved`, `rejected`, `expired`, or `cancelled` do not collide with the partial unique index, allowing authorized users to create a new pending proposal if required.

### 6.3 Two-Person Integrity (Four-Eyes Principle) & RBAC
- **Role Enforcement**:
  - `Admin` & `Engineer`: Authorized to inspect, create, approve, reject, and cancel proposals.
  - `Viewer`: Read-only access. Strictly forbidden from creating, approving, or rejecting approvals.
- **Two-Person Integrity**:
  - For `HIGH` risk actions (e.g., `disable_service_monitoring`), self-approval by the original requester (`requested_by == reviewer.id`) is strictly rejected with `HTTP 403 Forbidden` (`settings.ALLOW_SELF_APPROVAL=False`). A separate Engineer or Admin must conduct the review.

### 6.4 Expiration Safety, Read-Only GETs & Concurrency Control
- **Expiration Policy**: Approvals carry a finite lifetime (`expires_at`, default 24 hours).
- **Strictly Read-Only GET Endpoints**: `GET /api/v1/remediation/approvals` and `GET /api/v1/remediation/approvals/{id}` are strictly read-only and never mutate or commit records in the database. Expired pending approvals are dynamically evaluated in memory so they are never presented as actionable.
- **Explicit Cleanup Operations**: Persisted status updates for expired approvals occur either during action transitions or via explicit cleanup operations (`ApprovalService.expire_overdue_approvals`).
- **Atomic Transitions & Race Prevention**: Transitions use database transactions with `SELECT ... FOR UPDATE` row locks where supported. Approved, rejected, expired, or cancelled requests cannot be approved or double-approved.

### 6.5 Incident Timeline Integration
- **Approval Lifecycle Events**: When an approval request is associated with an incident (`incident_id`), every workflow transition records an `IncidentEvent` in the same atomic database transaction:
  - `approval_requested`: proposal created and pending review.
  - `approval_approved`: proposal authorized by human reviewer.
  - `approval_rejected`: proposal declined with reason.
  - `approval_cancelled`: proposal retracted.
  - `approval_expired`: proposal expired without review.
- **Audit Metadata**: Timeline events record `approval_id`, `action_id`, `risk_level`, `requester_id`, and `reviewer_id` in `event_metadata` without exposing credentials.
- **Transaction Atomicity**: Failed state transitions roll back and never emit orphan timeline events.

### 6.6 Absolute Separation from Remediation Execution
- **Strict Boundary**: Approval **strictly does NOT execute** any remediation action.
- Approval updates `approval_status = "approved"`, records the reviewer and timestamp, and leaves the proposal in an authorized state for Phase 4.3.
- No subprocesses, shell commands, Docker operations, or worker queues are spawned.

---

## 7. Documented Security & Operational Limitations

1. **Remediation Execution Boundary**:
   - In accordance with Phase 4.1 and Phase 4.2 specifications, remediation actions are evaluated and approved as governance proposals only. Execution runners, shell subprocesses, and automated container mutators are strictly prohibited and not implemented.
2. **Stateless JWT Tokens**:
   - Access tokens use stateless HS256 JWTs with a 12-hour expiration window. There is currently no token revocation blacklist or Redis session store; token invalidation relies on expiration or secret rotation.
3. **Production Secret Management**:
   - While `.env` is used for native local development, production deployments should source `SECRET_KEY`, `DATABASE_URL`, and `GEMINI_API_KEY` from external secret management solutions (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
