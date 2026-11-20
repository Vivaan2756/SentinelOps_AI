"""Typed Pydantic schemas for Remediation Actions, Parameter Validation, and Policy Decisions.

Blueprint Section 8 & Phase 4.1:
- Strict validation with extra='forbid'
- Reject unknown fields, invalid UUIDs, arbitrary shell commands or code
- Separate action definitions from parameter validation models
- Risk levels: LOW, MEDIUM, HIGH
"""

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import unquote, urlparse
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(str, Enum):
    """Canonical risk classification defined by backend registry."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionCategory(str, Enum):
    """Categorization for allowlisted remediation actions."""
    SERVICE_RECOVERY = "service_recovery"
    DIAGNOSTICS = "diagnostics"
    MONITORING = "monitoring"


class PolicyDecisionType(str, Enum):
    """Outcomes from deterministic policy evaluation."""
    ALLOWED = "allowed"
    APPROVAL_REQUIRED = "approval_required"
    REJECTED = "rejected"


class ExecutionMechanism(str, Enum):
    """Execution mechanism required to carry out the remediation action."""
    HTTP_DIAGNOSTIC = "http_diagnostic"
    MONITORING_CONTROL = "monitoring_control"
    DEMO_SERVICE_RESET = "demo_service_reset"
    CONTAINER_LIFECYCLE = "container_lifecycle"
    DEPLOYMENT_ROLLBACK = "deployment_rollback"
    CACHE_MANAGEMENT = "cache_management"
    HTTP_RECOVERY = "http_recovery"


class CapabilityStatus(str, Enum):
    """Operational availability status of an action capability in current runtime."""
    EXECUTABLE = "executable"
    REQUIRES_ADAPTER = "requires_adapter"
    DISABLED = "disabled"


# ============================================================================
# Action Parameter Schemas (Strict, Typed, No Unknown Fields)
# ============================================================================

def validate_uuid_format(val: str, field_name: str = "service_id") -> str:
    """Validate that value is a well-formed UUID string."""
    if not isinstance(val, str):
        raise ValueError(f"{field_name} must be a string representation of a UUID.")
    val_clean = val.strip()
    try:
        parsed = uuid.UUID(val_clean)
        return str(parsed)
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"{field_name} must be a valid 36-character UUID.")


def validate_relative_recovery_path(path: str) -> str:
    """
    Validate that recovery endpoint path is strictly relative and secure (Phase 5A).
    - Must start with '/'
    - Rejects absolute URLs, schemes ('://'), double slashes ('//')
    - Rejects query strings ('?'), fragments ('#'), user credentials ('@')
    - Rejects path traversal ('..', backslashes '\\')
    - Rejects percent-encoded sequences (%2e, %2f, %5c, etc.)
    - Rejects root path '/' alone
    - Enforces safe alphanumeric, underscore, dot, slash, dash characters
    """
    if not isinstance(path, str):
        raise ValueError("recovery_path must be a string.")
    p = path.strip()
    if not p:
        raise ValueError("recovery_path cannot be empty.")
    if "://" in p:
        raise ValueError("Absolute URLs and URI schemes are strictly prohibited in recovery_path.")
    if not p.startswith("/"):
        raise ValueError("recovery_path must be a relative path starting with '/'.")
    if p == "/":
        raise ValueError("recovery_path cannot be root '/' alone; specify a specific operational endpoint.")
    if "//" in p:
        raise ValueError("Malformed path: double slashes ('//') are prohibited in recovery_path.")
    if "\\" in p:
        raise ValueError("Backslashes are prohibited in recovery_path.")
    if "?" in p or "#" in p or "@" in p:
        raise ValueError("Query strings, fragments, and credentials are prohibited in recovery_path.")
    if ".." in p:
        raise ValueError("Directory traversal ('..') is strictly prohibited in recovery_path.")
    if "%" in p:
        raise ValueError("Percent-encoded characters and sequences are strictly prohibited in recovery_path.")
    if not re.match(r"^/[a-zA-Z0-9_./-]*$", p):
        raise ValueError(f"recovery_path contains invalid characters: '{p}'.")
    return p


def build_recovery_url(service_health_check_url: str, recovery_path: str) -> str:
    """
    Derive complete recovery URL strictly from registered service origin and relative path.
    Guarantees no arbitrary external hostnames or port substitution.
    """
    if not service_health_check_url or not isinstance(service_health_check_url, str):
        raise ValueError("Service has no configured health check URL to derive origin.")
    parsed = urlparse(service_health_check_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid service health URL scheme '{parsed.scheme}'. Must be 'http' or 'https'.")
    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise ValueError("Service health URL is missing a valid hostname.")
    if hostname in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "metadata.google.internal"):
        raise ValueError(f"Service health check URL targets forbidden cloud metadata endpoint: {hostname}")

    clean_path = validate_relative_recovery_path(recovery_path)
    return f"{parsed.scheme}://{parsed.netloc}{clean_path}"


class HttpRecoveryParams(BaseModel):
    """Validated parameters for execute_http_recovery action (Phase 5A)."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")
    recovery_path: str = Field(
        ...,
        description="Relative recovery endpoint path (e.g. /admin/recovery/reset)",
    )
    payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional JSON request body strictly validated against arbitrary code patterns",
    )
    expected_status_codes: List[int] = Field(
        default_factory=lambda: [200],
        description="Expected 2xx HTTP response status codes",
    )
    timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=60,
        description="HTTP request timeout bound in seconds",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")

    @field_validator("recovery_path")
    @classmethod
    def check_recovery_path(cls, v: str) -> str:
        return validate_relative_recovery_path(v)

    @field_validator("expected_status_codes")
    @classmethod
    def check_status_codes(cls, v: List[int]) -> List[int]:
        if not v:
            return [200]
        for code in v:
            if not isinstance(code, int) or code < 200 or code > 299:
                raise ValueError(f"Invalid status code '{code}'. Only 2xx HTTP success codes are permitted.")
        return sorted(list(set(v)))

    @field_validator("payload")
    @classmethod
    def check_payload(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        from app.remediation.playbook_service import _scan_for_arbitrary_code
        err = _scan_for_arbitrary_code(v)
        if err:
            raise ValueError(f"Payload security validation failed: {err}")
        return v


class RestartOrderApiParams(BaseModel):
    """Validated parameters for restart_order_api action."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")


class RestoreOrderApiDemoParams(BaseModel):
    """Validated parameters for restore_order_api_demo action (Phase 4.3)."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")


class InspectServiceHealthParams(BaseModel):
    """Validated parameters for inspect_service_health action."""
    service_id: Optional[str] = Field(
        default=None,
        description="Target service UUID belonging to current workspace",
    )
    health_path: Optional[str] = Field(
        default="/health",
        description="Target health check path component (e.g. /health or /api/v1/health)",
    )
    is_demo_service: bool = Field(
        default=False,
        description="Whether target is an in-memory demo service requiring /demo/status verification",
    )
    has_prometheus_metrics: bool = Field(
        default=False,
        description="Whether target exports Prometheus metrics requiring /metrics verification",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_uuid_format(v, "service_id")

    @field_validator("health_path")
    @classmethod
    def validate_health_path(cls, v: Optional[str]) -> str:
        if v is None:
            return "/health"
        v = v.strip()
        if not v.startswith("/"):
            v = f"/{v}"
        if ".." in v or "?" in v or "#" in v:
            raise ValueError(
                "health_path must be a clean relative path without query strings or directory traversal"
            )
        if not re.match(r"^/[a-zA-Z0-9_./-]*$", v):
            raise ValueError(f"health_path contains invalid path characters: {v}")
        return v


class DisableServiceMonitoringParams(BaseModel):
    """Validated parameters for disable_service_monitoring action."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")


class RestartServiceParams(BaseModel):
    """Validated parameters for restart_service capability (requires container/process adapter)."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")
    grace_period_seconds: int = Field(
        default=10, ge=1, le=120, description="Grace period before container/process SIGKILL"
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")


class RollbackDeploymentParams(BaseModel):
    """Validated parameters for rollback_deployment capability (requires orchestrator adapter)."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")
    target_revision: Optional[str] = Field(
        default=None, description="Specific revision tag to rollback to, or prior stable revision if omitted"
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")

    @field_validator("target_revision")
    @classmethod
    def check_revision_format(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
                raise ValueError("target_revision contains invalid characters")
        return v


class ClearApplicationCacheParams(BaseModel):
    """Validated parameters for clear_application_cache capability (requires cache adapter)."""
    service_id: str = Field(..., description="Target service UUID belonging to current workspace")
    cache_partition: str = Field(
        default="all", description="Cache partition or namespace to invalidate"
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("service_id")
    @classmethod
    def check_service_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "service_id")

    @field_validator("cache_partition")
    @classmethod
    def check_partition_format(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[a-zA-Z0-9_*:-]+$", v):
            raise ValueError("cache_partition contains invalid characters")
        return v


# ============================================================================
# Action Definition & Catalog Schemas
# ============================================================================

class ActionDefinition(BaseModel):
    """Allowlisted remediation action definition metadata."""
    action_id: str = Field(..., description="Stable unique identifier for allowlisted action")
    name: str = Field(..., description="Human-readable action name")
    description: str = Field(..., description="Operational purpose and effects")
    category: ActionCategory = Field(..., description="Action classification category")
    risk_level: RiskLevel = Field(..., description="Canonical risk level assigned by registry")
    execution_mechanism: ExecutionMechanism = Field(
        default=ExecutionMechanism.HTTP_DIAGNOSTIC,
        description="Execution mechanism required for action",
    )
    status: CapabilityStatus = Field(
        default=CapabilityStatus.EXECUTABLE,
        description="Availability status in current runtime (executable vs requires_adapter)",
    )
    is_executable: bool = Field(
        default=True,
        description="Whether action is executable by current runner without additional infrastructure adapters",
    )
    parameter_schema: Dict[str, Any] = Field(..., description="JSON Schema for required parameters")
    supported_environments: List[str] = Field(..., description="Environments permitted for action")
    approval_required: bool = Field(..., description="Whether human approval is mandatory")
    preconditions: List[str] = Field(..., description="Prerequisites required prior to execution")
    required_service_attributes: List[str] = Field(
        default_factory=list,
        description="Service attributes required by capability (e.g. health_check_url)",
    )
    security_restrictions: List[str] = Field(
        default_factory=list,
        description="Security restrictions enforced on capability",
    )
    target_resource_type: str = Field(
        default="http_endpoint",
        description="Resource type targeted by action (e.g. http_endpoint, container, monitoring)",
    )
    verification_criteria: str = Field(..., description="Criteria required to verify success")
    timeout_seconds: int = Field(default=30, ge=5, le=300, description="Execution timeout bound")
    enabled: bool = Field(default=True, description="Whether action is currently active in registry")
    supported_services: Optional[List[str]] = Field(
        default=None,
        description="Allowlisted services permitted for action, or ['*'] for all services",
    )

    model_config = ConfigDict(from_attributes=True)


class ServiceActionCapability(BaseModel):
    """Evaluated capability compatibility assessment for a specific service."""
    action_id: str
    action_name: str
    description: str
    category: ActionCategory
    risk_level: RiskLevel
    execution_mechanism: ExecutionMechanism
    status: CapabilityStatus
    is_compatible: bool
    is_executable: bool
    approval_required: bool
    reasons: List[str]
    prerequisites: List[str]
    parameter_schema: Dict[str, Any]
    verification_criteria: str
    target_resource_type: str
    supported_environments: List[str]

    model_config = ConfigDict(from_attributes=True)


class ServiceCapabilitiesResponse(BaseModel):
    """Workspace-scoped response catalog of evaluated capabilities for a service."""
    service_id: str
    service_name: str
    environment: str
    execution_policy: str
    capabilities: List[ServiceActionCapability]
    compatible_count: int
    executable_count: int
    total_count: int

    model_config = ConfigDict(from_attributes=True)


class ActionCatalogResponse(BaseModel):
    """Response catalog for allowlisted remediation actions."""
    actions: List[ActionDefinition]
    total: int


# ============================================================================
# Policy Engine Request & Response Schemas
# ============================================================================

class PolicyEvaluationRequest(BaseModel):
    """Request payload to evaluate an action proposal against the policy engine."""
    workspace_id: str = Field(..., description="Target workspace ID for tenant scoping")
    action_id: str = Field(..., description="Allowlisted action ID")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Typed parameters for action")
    environment: str = Field(default="development", description="Execution target environment")
    playbook_id: Optional[str] = Field(None, description="Optional UUID of referenced dynamic playbook")
    playbook_version: Optional[int] = Field(None, description="Optional active version number of referenced playbook")

    model_config = ConfigDict(extra="forbid")

    @field_validator("workspace_id")
    @classmethod
    def check_workspace_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "workspace_id")

    @field_validator("playbook_id")
    @classmethod
    def check_playbook_uuid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_uuid_format(v, "playbook_id")
        return None


class PolicyDecisionResponse(BaseModel):
    """Structured decision returned by the deterministic policy engine."""
    id: str = Field(..., description="Policy decision record UUID")
    workspace_id: str = Field(..., description="Workspace ID")
    user_id: Optional[str] = Field(None, description="User ID who initiated evaluation")
    action_id: str = Field(..., description="Action evaluated")
    target_service_id: Optional[str] = Field(None, description="Target service UUID if applicable")
    risk_level: str = Field(..., description="Canonical risk level (low, medium, high)")
    decision: PolicyDecisionType = Field(..., description="Decision: allowed, approval_required, rejected")
    decision_reason: str = Field(..., description="Detailed rationale for policy decision")
    policy_version: str = Field(default="v1.0", description="Policy engine version applied")
    approval_required: bool = Field(..., description="Whether execution requires human approval")
    validated_parameters: Dict[str, Any] = Field(default_factory=dict, description="Sanitized parameters")
    evaluated_at: datetime = Field(..., description="Timestamp of evaluation")
    timestamp: Optional[datetime] = Field(None, description="Database audit timestamp")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ============================================================================
# Human Approval Workflow Schemas (Phase 4.2)
# ============================================================================

class ApprovalStatus(str, Enum):
    """Allowed states for human remediation approvals."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalCreateRequest(BaseModel):
    """Request payload to create a pending approval request from a policy decision."""
    workspace_id: str = Field(..., description="Target workspace ID for tenant scoping")
    policy_decision_id: str = Field(..., description="UUID of policy decision that returned approval_required")
    incident_id: Optional[str] = Field(None, description="Optional incident ID linked to this remediation")
    investigation_id: Optional[str] = Field(None, description="Optional investigation ID recommending this action")
    expires_in_hours: int = Field(default=24, ge=1, le=168, description="Expiration window in hours (1-168)")

    model_config = ConfigDict(extra="forbid")

    @field_validator("workspace_id")
    @classmethod
    def check_workspace_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "workspace_id")

    @field_validator("policy_decision_id")
    @classmethod
    def check_decision_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "policy_decision_id")

    @field_validator("incident_id")
    @classmethod
    def check_incident_uuid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_uuid_format(v, "incident_id")
        return None

    @field_validator("investigation_id")
    @classmethod
    def check_investigation_uuid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_uuid_format(v, "investigation_id")
        return None


class ApprovalApproveRequest(BaseModel):
    """Request payload for approving a pending remediation request."""
    notes: Optional[str] = Field(None, max_length=1000, description="Optional approval notes")

    model_config = ConfigDict(extra="forbid")


class ApprovalRejectRequest(BaseModel):
    """Request payload for rejecting a pending remediation request."""
    rejection_reason: str = Field(
        ..., min_length=3, max_length=1000, description="Mandatory rationale for rejection"
    )

    model_config = ConfigDict(extra="forbid")


class ApprovalCancelRequest(BaseModel):
    """Request payload for cancelling a pending remediation request."""
    cancellation_reason: Optional[str] = Field(None, max_length=1000, description="Optional cancellation notes")

    model_config = ConfigDict(extra="forbid")


class ApprovalResponse(BaseModel):
    """Detailed presentation model for remediation approval requests."""
    id: str
    workspace_id: str
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None
    policy_decision_id: str
    action_id: str
    action_name: Optional[str] = None
    action_description: Optional[str] = None
    target_service_id: Optional[str] = None
    target_service_name: Optional[str] = None
    validated_parameters: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    policy_version: str
    approval_status: ApprovalStatus
    requested_by: Optional[str] = None
    requested_by_email: Optional[str] = None
    requested_at: datetime
    reviewed_by: Optional[str] = None
    reviewed_by_email: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    expires_at: datetime
    verification_criteria: Optional[str] = None
    is_expired: bool = False

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ============================================================================
# Execution Request & Response Schemas (Phase 4.3)
# ============================================================================

class ExecutionCreateRequest(BaseModel):
    """Request payload to trigger execution of an approved remediation proposal."""
    approval_id: str = Field(..., description="UUID of the approved RemediationApproval record")
    idempotency_key: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Client-generated unique idempotency token for this request",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("approval_id")
    @classmethod
    def check_approval_uuid(cls, v: str) -> str:
        return validate_uuid_format(v, "approval_id")


class ExecutionCancelRequest(BaseModel):
    """Request payload for cancelling an execution job in queued status."""
    cancellation_reason: Optional[str] = Field(
        None, max_length=1000, description="Optional cancellation notes"
    )

    model_config = ConfigDict(extra="forbid")


class UncertaintyResolutionDecision(str, Enum):
    """Explicit decision options for resolving an uncertain execution hold."""
    ABORT_FAILURE = "ABORT_FAILURE"
    CONFIRM_SUCCESS = "CONFIRM_SUCCESS"


class ExecutionResolveUncertainRequest(BaseModel):
    """Request payload for an authorized operator resolving an execution stuck in EXECUTION_UNCERTAIN."""
    decision: UncertaintyResolutionDecision = Field(
        ..., description="Resolution decision: ABORT_FAILURE or CONFIRM_SUCCESS"
    )
    justification: str = Field(
        ...,
        min_length=5,
        max_length=2000,
        description="Mandatory operator justification explaining out-of-band verification and resolution reasoning",
    )
    evidence: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional structured evidence metadata (e.g. ticket ID, curl response, log trace)",
    )

    model_config = ConfigDict(extra="forbid")


class ExecutionAttemptResponse(BaseModel):
    """Presentation model for an individual worker execution attempt."""
    id: str
    execution_id: str
    attempt_number: int
    status: str
    worker_id: Optional[str] = None
    fencing_token: int = 0
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    exit_code: Optional[int] = None
    stdout_sample: Optional[str] = None
    stderr_sample: Optional[str] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ExecutionEventResponse(BaseModel):
    """Presentation model for an execution audit timeline event."""
    id: str
    execution_id: str
    workspace_id: str
    event_type: str
    message: str
    metadata_json: Optional[Dict[str, Any]] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class ExecutionResponse(BaseModel):
    """Detailed presentation model for a RemediationExecution record."""
    id: str
    workspace_id: str
    approval_id: str
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None
    action_id: str
    target_service_id: Optional[str] = None
    approved_parameters: Dict[str, Any] = Field(default_factory=dict)
    status: str
    idempotency_key: str
    locked_by: Optional[str] = None
    locked_until: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    fencing_token: int = 0
    retry_policy: str = "idempotent"
    triggered_by: str
    triggered_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: int = 30
    attempt_count: int = 0
    max_attempts: int = 1
    execution_output: Optional[Dict[str, Any]] = None
    verification_status: Optional[str] = None
    verification_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None
    uncertain_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    attempts: List[ExecutionAttemptResponse] = Field(default_factory=list)
    events: List[ExecutionEventResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ExecutionListResponse(BaseModel):
    """Paginated response model for execution listing."""
    executions: List[ExecutionResponse]
    total: int
    limit: int
    offset: int


# ============================================================================
# Verification Presentation Schemas (Phase 4.3.6 / UI Integration)
# ============================================================================

class VerificationProbeResponse(BaseModel):
    """Detailed result of an individual synthetic probe."""
    id: str
    cycle_id: str
    execution_id: str
    workspace_id: str
    probe_number: int
    probe_type: str
    target_url: str
    status: str
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    passed: bool
    probe_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    executed_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VerificationCycleResponse(BaseModel):
    """Durable verification cycle presentation schema."""
    id: str
    execution_id: str
    workspace_id: str
    cycle_number: int
    status: str
    started_at: datetime
    deadline_at: datetime
    completed_at: Optional[datetime] = None
    fencing_token: int
    verifying_worker_id: Optional[str] = None
    probes_required: int
    probes_passed: int
    probes_failed: int
    cycle_metadata: Optional[Dict[str, Any]] = None
    probes: List[VerificationProbeResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    # Contextual metadata resolved from parent entities
    action_id: Optional[str] = None
    execution_status: Optional[str] = None
    incident_id: Optional[str] = None
    incident_title: Optional[str] = None
    service_id: Optional[str] = None
    service_name: Optional[str] = None
    recovery_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class VerificationCycleListResponse(BaseModel):
    """List response for verification cycles."""
    cycles: List[VerificationCycleResponse]
    total: int
