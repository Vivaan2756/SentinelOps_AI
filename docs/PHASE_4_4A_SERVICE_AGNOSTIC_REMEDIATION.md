# SentinelOps — Phase 4.4A: Service-Agnostic Remediation Architecture Documentation

**Document:** `docs/PHASE_4_4A_SERVICE_AGNOSTIC_REMEDIATION.md`
**Phase:** 4.4A — Service-Agnostic Remediation Architecture
**Status:** Completed
**Last Updated:** 2026-11-03

---

## 1. Executive Summary & Architectural Motivation

Previously in SentinelOps, remediation actions were coupled to specific service implementations:
- The Order API demo had a dedicated `restore_order_api_demo` action calling `POST /demo/restore`.
- Adding or registering a new service (such as the Inventory Management API) previously risked either:
  1. A hardcoded service-specific action being mistakenly recommended for a different service, or
  2. Requiring application code changes and new custom actions for every single newly registered microservice.

Phase 4.4A separates the remediation platform into three decoupled, orthogonal layers:
1. **Action Capability (Authoritative Registry):** Defines *what* operation can be performed, its execution mechanism, required parameters, supported environments, and whether an infrastructure adapter is required.
2. **Service Compatibility (Dynamic Discovery):** Evaluates *which* registered services satisfy the prerequisites for each capability, considering environment constraints, service configuration attributes, and adapter availability.
3. **Playbook Configuration (User-Configurable Binding):** Binds compatible action templates to services, incident trigger scenarios, parameter payloads, human approval policies, and verification criteria through the dashboard without requiring backend code changes.

```
+-------------------------------------------------------------------------------+
|                        SentinelOps Architecture Separation                     |
+-------------------------------------------------------------------------------+
| 1. Action Capability Registry (Authoritative, Fixed, Secure)                  |
|    - inspect_service_health (HTTP diagnostic, fully executable)               |
|    - disable_service_monitoring (Platform control, fully executable)          |
|    - restore_order_api_demo (Legacy/demo reset, fully executable)             |
|    - restart_service (Container lifecycle, requires adapter)                 |
|    - rollback_deployment (Deployment rollback, requires adapter)             |
|    - clear_application_cache (Cache management, requires adapter)             |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| 2. Service Compatibility Engine (Deterministic Assessment)                     |
|    - Service Environment Check (dev vs staging vs prod)                       |
|    - Service Attributes Completeness (health URL, container metadata)         |
|    - SSRF & Network Boundary Validation (reject metadata IPs)                 |
|    - Infrastructure Adapter Availability (fail closed if adapter unmounted)   |
|    - Service Specificity Constraints (prevent demo actions on wrong service)  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| 3. Dynamic Playbooks (Dashboard-Configurable, Scoped, Versioned)              |
|    - Workspace Isolation & RBAC (Engineer/Admin management)                   |
|    - Immutable Version Snapshots (v1, v2...)                                  |
|    - Incident Scenario Trigger Matching (*, http_5xx_rate_exceeded)           |
|    - Parameter Schemas & Pre-flight Dry-Run Validation                        |
+-------------------------------------------------------------------------------+
```

---

## 2. Capability Registry Specification

The `ActionRegistry` (`backend/app/remediation/registry.py`) remains the single authoritative source of allowlisted capabilities. Playbooks and LLMs are strictly barred from defining arbitrary executable code.

Each capability is defined with the following core properties:

```python
class ActionDefinition(BaseModel):
    action_id: str
    name: str
    description: str
    category: ActionCategory              # SERVICE_RECOVERY, DIAGNOSTICS, MONITORING
    risk_level: RiskLevel                # LOW, MEDIUM, HIGH
    execution_mechanism: ExecutionMechanism
    status: CapabilityStatus              # EXECUTABLE vs REQUIRES_ADAPTER vs DISABLED
    is_executable: bool                   # True only if current runner implements execution
    parameter_schema: Dict[str, Any]      # JSON Schema with extra='forbid'
    supported_environments: List[str]     # ["development", "staging", "production"]
    approval_required: bool               # Enforced by PolicyEngine
    preconditions: List[str]              # Runtime prerequisites
    required_service_attributes: List[str]# ["health_check_url", "container_id", etc.]
    security_restrictions: List[str]      # Enforced safety controls
    target_resource_type: str             # http_endpoint, container, monitoring, etc.
    verification_criteria: str
    timeout_seconds: int
    enabled: bool
    supported_services: Optional[List[str]] # ["*"] for universal, or allowlist of services
```

### 2.1. Execution Mechanisms (`ExecutionMechanism`)
- `http_diagnostic`: Read-only HTTP diagnostic inspection via isolated runner container.
- `monitoring_control`: Platform-internal background polling and detector lifecycle control.
- `demo_service_reset`: Specialized in-memory reset endpoint for demo services.
- `container_lifecycle`: Process or container graceful restart via container supervisor.
- `deployment_rollback`: Orchestrator revision rollback via Kubernetes or GitOps controller.
- `cache_management`: Targeted cache partition invalidation or key flush.

### 2.2. Capability Status (`CapabilityStatus`)
- `executable`: Fully implemented, security-reviewed, and supported by the current runner sandbox.
- `requires_adapter`: Formally defined capability specification with strict Pydantic schemas, but requires an external infrastructure adapter (e.g., Docker daemon socket, Kubernetes credentials, Redis client) that is not currently mounted in the runner container.
- `disabled`: Administratively deactivated capability.

---

## 3. Supported and Adapter-Dependent Capabilities

| Action ID | Name | Category | Risk | Mechanism | Status | Is Executable |
|---|---|---|---|---|---|---|
| `inspect_service_health` | Inspect Service Diagnostic Health | `DIAGNOSTICS` | `LOW` | `http_diagnostic` | `EXECUTABLE` | **Yes** |
| `disable_service_monitoring` | Disable Service Monitoring | `MONITORING` | `HIGH` | `monitoring_control` | `EXECUTABLE` | **Yes** |
| `restore_order_api_demo` | Restore Order API Demo Service | `SERVICE_RECOVERY` | `MEDIUM` | `demo_service_reset` | `EXECUTABLE` | **Yes** (Order API only) |
| `restart_service` | Restart Service Container/Process | `SERVICE_RECOVERY` | `HIGH` | `container_lifecycle` | `REQUIRES_ADAPTER` | **No** (Needs Docker/K8s adapter) |
| `restart_order_api` | Restart Order API Service (Legacy) | `SERVICE_RECOVERY` | `MEDIUM` | `container_lifecycle` | `REQUIRES_ADAPTER` | **No** (Legacy alias) |
| `rollback_deployment` | Rollback Service Deployment | `SERVICE_RECOVERY` | `HIGH` | `deployment_rollback` | `REQUIRES_ADAPTER` | **No** (Needs K8s adapter) |
| `clear_application_cache` | Clear Application Cache | `SERVICE_RECOVERY` | `MEDIUM` | `cache_management` | `REQUIRES_ADAPTER` | **No** (Needs Cache adapter) |

### 3.1. Reusable Capabilities Actually Implemented & Executable
1. **`inspect_service_health`**:
   - Genuinely universal and service-agnostic.
   - Dispatched to isolated Docker container runner with DNS/IP pinning.
   - Probes `/health` (or custom `health_path`), collects status code, latency, and parses metrics.
   - Read-only; zero mutation. Safe across all environments (`development`, `staging`, `production`).
2. **`disable_service_monitoring`**:
   - Universal monitoring management.
   - Safely deactivates active detector polling for flapping or decommissioned services.
   - Workspace-scoped database state change; high risk; requires human approval.
3. **`restore_order_api_demo`**:
   - Preserved as a service-specific legacy capability strictly for the Order API demo container on port 8001/8002 in development.
   - Cannot be associated with or executed on other services (e.g. Inventory API).

### 3.2. Integration-Dependent Capabilities & Prerequisites
The following actions are defined with strict Pydantic schemas, risk levels, and preconditions, but are **NOT executable** in the current runtime environment because they require infrastructure adapters:

1. **`restart_service`**:
   - **Execution Mechanism:** `container_lifecycle`
   - **Prerequisites:**
     - A trusted Docker socket, Kubernetes API token, or systemd process supervisor mounted securely into the runner environment.
     - Service entity must register a valid `container_id` or `pod_name`.
     - Fencing and lease validation to prevent conflicting concurrent restarts.
   - **Current Behavior:** Rejects execution with `CapabilityStatus.REQUIRES_ADAPTER` and policy decision `REJECTED: Action requires an infrastructure adapter (container_lifecycle)`.
2. **`rollback_deployment`**:
   - **Execution Mechanism:** `deployment_rollback`
   - **Prerequisites:**
     - Kubernetes Deployment Controller, Helm, or ArgoCD API credentials.
     - Target service must maintain revision history metadata.
     - Role-based authorization for production rollbacks.
   - **Current Behavior:** Rejects execution with `CapabilityStatus.REQUIRES_ADAPTER`.
3. **`clear_application_cache`**:
   - **Execution Mechanism:** `cache_management`
   - **Prerequisites:**
     - Redis / Memcached client configured within private VPC network boundaries.
     - Scoped cache partition key matching (zero arbitrary `FLUSHALL` commands).
   - **Current Behavior:** Rejects execution with `CapabilityStatus.REQUIRES_ADAPTER`.

---

## 4. Service Compatibility Model

When a service is registered or inspected, SentinelOps evaluates its capability compatibility via `ActionRegistry.evaluate_service_capability` and `discover_service_capabilities`:

### 4.1. Deterministic Evaluation Rules
1. **Enabled Verification:** Inactive actions return `status=DISABLED`, `is_compatible=False`.
2. **Environment Permission:** `service.environment` must be in `action.supported_environments`. If a service is in `production`, development-only actions are rejected.
3. **Execution Policy Enforcement:** If `service.execution_policy == "observe_only"`, all `SERVICE_RECOVERY` actions are rejected.
4. **Service Configuration Completeness:**
   - Actions requiring `health_check_url` verify that the URL is present, well-formed, and uses `http`/`https`.
   - SSRF Protection: Target URLs pointing to cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`) are rejected immediately.
5. **Service Specificity Constraints:**
   - Actions with restricted `supported_services` (e.g. `restore_order_api_demo`) match only authorized service names.
   - Any other service (such as `Inventory Management API`) is strictly rejected with explicit reason:
     `"Action template 'restore_order_api_demo' is service-specific and does not support service 'Inventory Management API'."`
6. **Adapter Requirement Constraint:**
   - Actions requiring an unmounted adapter return `status=REQUIRES_ADAPTER`, `is_compatible=False`, `is_executable=False`.
7. **Execution Eligibility:**
   - An action is `is_executable = True` **only** if it passes all checks AND its underlying handler is implemented in the runner sandbox.

---

## 5. Case Study: Inventory API vs Order API

| Evaluation Criterion | Order API (`8001`) | Inventory Management API (`7000`) |
|---|---|---|
| Service Name | `Order API` | `Inventory Management API` |
| Environment | `development` | `development` |
| Health URL | `http://localhost:8001/health` | `http://localhost:7000/api/v1/health` |
| `inspect_service_health` | **Compatible & Executable** | **Compatible & Executable** |
| `disable_service_monitoring` | **Compatible & Executable** | **Compatible & Executable** |
| `restore_order_api_demo` | **Compatible & Executable** | **Incompatible** (`restore_order_api_demo is service-specific to Order API`) |
| `restart_service` | **Requires Adapter** (`container_lifecycle` adapter not configured) | **Requires Adapter** (`container_lifecycle` adapter not configured) |
| `rollback_deployment` | **Requires Adapter** (`deployment_rollback` adapter not configured) | **Requires Adapter** (`deployment_rollback` adapter not configured) |
| `clear_application_cache` | **Requires Adapter** (`cache_management` adapter not configured) | **Requires Adapter** (`cache_management` adapter not configured) |

**Key Architectural Invariant:**
SentinelOps **never** infers that a service supports an operation simply because its health check URL returns HTTP 200. The Inventory API works on port 7000, but cannot be targeted by `restore_order_api_demo`.

---

## 6. Service Capabilities REST API

### `GET /api/v1/services/{service_id}/capabilities`
- **Scoping:** Workspace-isolated (`workspace_id` query parameter required).
- **Authorization:** `RequireWorkspaceRole()` (Viewer, Engineer, Admin).
- **Response Model:** `ServiceCapabilitiesResponse`

```json
{
  "service_id": "5aec4a29-be82-407e-a376-b3407b328cc3",
  "service_name": "Inventory Management API",
  "environment": "development",
  "execution_policy": "demo",
  "compatible_count": 2,
  "executable_count": 2,
  "total_count": 7,
  "capabilities": [
    {
      "action_id": "inspect_service_health",
      "action_name": "Inspect Service Diagnostic Health",
      "description": "Performs read-only diagnostic inspection of service endpoints...",
      "category": "diagnostics",
      "risk_level": "low",
      "execution_mechanism": "http_diagnostic",
      "status": "executable",
      "is_compatible": true,
      "is_executable": true,
      "approval_required": false,
      "reasons": ["Service 'Inventory Management API' satisfies all capability prerequisites and environment constraints."],
      "prerequisites": ["Service exists in the target workspace", "Service is marked active", "Service has configured health_check_url"],
      "parameter_schema": { ... },
      "verification_criteria": "Diagnostic telemetry and health state are collected...",
      "target_resource_type": "http_endpoint",
      "supported_environments": ["development", "staging", "production"]
    },
    {
      "action_id": "restore_order_api_demo",
      "action_name": "Restore Order API Demo Service",
      "description": "Resets simulated in-memory failure mode...",
      "category": "service_recovery",
      "risk_level": "medium",
      "execution_mechanism": "demo_service_reset",
      "status": "executable",
      "is_compatible": false,
      "is_executable": false,
      "approval_required": true,
      "reasons": ["Action template 'restore_order_api_demo' is service-specific and does not support service 'Inventory Management API' (supported services: ['Order API', 'order-api', 'order_api', 'demo-order-service'])."],
      "prerequisites": ["Service exists in the target workspace", "Service is marked active", "Service environment is development", "Service health check URL matches registered Order API host and port"],
      "parameter_schema": { ... },
      "verification_criteria": "GET /demo/status confirms failure_active == False...",
      "target_resource_type": "demo_http_endpoint",
      "supported_environments": ["development"]
    },
    {
      "action_id": "restart_service",
      "action_name": "Restart Service Container/Process",
      "description": "Gracefully restarts the container or process...",
      "category": "service_recovery",
      "risk_level": "high",
      "execution_mechanism": "container_lifecycle",
      "status": "requires_adapter",
      "is_compatible": false,
      "is_executable": false,
      "approval_required": true,
      "reasons": ["Action requires infrastructure adapter (container_lifecycle) which is not configured in current execution runtime."],
      "prerequisites": ["Requires trusted Docker/Kubernetes container management adapter configured in runner", "Service has registered container_id or pod_name", "Target environment permits container restart"],
      "parameter_schema": { ... },
      "verification_criteria": "Service container restarts, passes synthetic health probe within 60s.",
      "target_resource_type": "container",
      "supported_environments": ["development", "staging"]
    }
  ]
}
```

---

## 7. Frontend User Experience

1. **Service Detail Page (`/services/[serviceId]`):**
   - New **Remediation & Diagnostic Capabilities** panel.
   - Displays all evaluated capabilities for the service, categorized by `Executable` (green), `Requires Adapter` (amber), or `Incompatible` (neutral).
   - Shows execution mechanism, target resource, and detailed evaluation assessment.
   - Includes a direct **Configure Playbook** action button linking to `/playbooks/new?service_id=...`.
2. **Playbook Creation Wizard (`/playbooks/new`):**
   - Automatically pre-selects the service if launched from the service detail view.
   - Step 3 (Action Template) displays capability badges (`Executable` vs `Requires Adapter`).
   - If an action requires an adapter, an infrastructure prerequisite warning banner explains the missing integration adapter.
   - If selected services are not allowlisted for the chosen action, clear warning alerts are displayed prior to validation.

---

## 8. LangGraph Integration & Safety Invariants

In the LangGraph AI investigation workflow (`backend/app/agents/nodes/playbooks.py`):
1. **Dynamic Discovery (`discover_active_playbooks`):** Queries only active playbooks associated with the target service in the incident's workspace.
2. **Compatibility Evaluation (`evaluate_playbook_compatibility`):**
   - Calls `ActionRegistry.evaluate_service_capability` for each candidate playbook.
   - If the candidate action has `status == REQUIRES_ADAPTER`, it is rejected with reason: `"Action requires infrastructure adapter ({mechanism}) which is not configured in current execution runtime."`
   - If the candidate action is service-specific (e.g. `restore_order_api_demo` on Inventory API), it is rejected with reason: `"Action template 'restore_order_api_demo' is service-specific and does not support service 'Inventory Management API'."`
3. **Escalation (Outcome C):**
   - If no compatible, executable playbook is available, LangGraph formulates an escalation notice for human SRE review.
   - The LLM is strictly prohibited from inventing arbitrary shell commands or recovery endpoints.

---

## 9. Security & Governance Invariants

- **No Arbitrary HTTP Endpoints:** A user cannot configure an arbitrary webhook or HTTP URL as a remediation action. Recovery endpoints must be governed by allowlisted templates and validated against registered service boundaries.
- **SSRF Prevention:** Targets must pass pre-flight network validation (`validate_safe_target_url`) and connection-time DNS/IP pinning (`PinnedIPTransport`) inside the runner sandbox.
- **Strict Parameter Schemas:** All parameter payloads are validated with Pydantic (`ConfigDict(extra="forbid")`). Unknown fields or command injections are rejected immediately.
- **PolicyEngine Rule 2B:** Actions requiring unconfigured adapters are rejected deterministically before any proposal or approval request can be created.
- **Human Approval:** High-risk actions (`disable_service_monitoring`, `restart_service`, `rollback_deployment`) mandate human approval.
- **Three-Probe Verification:** Automated incident recovery requires 3 consecutive passing verification probes after remediation execution.

---

## 10. Future Infrastructure Adapter Extension Process

To promote an adapter-dependent capability (e.g. `restart_service`) to `executable`:
1. **Implement Trusted Adapter:** Mount the trusted adapter (e.g. Docker Engine socket via Docker broker IPC, or Kubernetes service account token) into the isolated runner container.
2. **Implement Runner Handler:** Add a dedicated handler in `services/executor/runner.py` with strict timeout bounds, DNS/IP pinning, and structured JSON output.
3. **Update Status in Registry:** In `backend/app/remediation/registry.py`, set:
   ```python
   status=CapabilityStatus.EXECUTABLE,
   is_executable=True,
   ```
4. **Rebuild Executor Image:** Rebuild `sentinelops/remediation-executor:dev-local`.
5. **Run Integration Tests:** Execute isolated integration tests verifying container restart lifecycle and synthetic verification probes.
