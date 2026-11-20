"""Remediation Execution Manager for Phase 4.3.

Controls execution lifecycle between approved remediation proposals and execution runners:
- Validates human approvals, expiry, and tenant boundaries
- Strictly preserves exact approved parameter snapshots (caller cannot tamper)
- Enforces single execution per approval and workspace idempotency
- Records execution and incident audit events atomically
- Manages worker leases, monotonic fencing tokens, and legal state transitions
- Prevents database connection holding during long-running execution operations
"""

import copy
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.execution.exceptions import (
    ApprovalAlreadyExecutedError,
    IdempotencyConflictError,
    IllegalStateTransitionError,
    PreconditionFailedError,
    StaleWorkerFencingError,
)
from app.execution.manifest_signer import (
    ManifestSigningError,
    generate_and_sign_execution_manifest,
)
from app.execution.state_machine import (
    ExecutionState,
    is_terminal_state,
    validate_state_transition,
)
from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.remediation.registry import ActionRegistry

logger = logging.getLogger("sentinelops.execution.manager")

FORBIDDEN_METADATA_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "secret",
    "token",
    "credential",
    "api_key",
    "bearer",
}


def sanitize_metadata(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively scrub credentials, authorization headers, and secrets from event metadata."""
    if not data:
        return {}
    sanitized = {}
    for k, v in data.items():
        k_lower = str(k).lower()
        if any(bad in k_lower for bad in FORBIDDEN_METADATA_KEYS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_metadata(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_metadata(item) if isinstance(item, dict) else item for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def _is_expired(expires_at: Optional[datetime], now_utc: Optional[datetime] = None) -> bool:
    """Safely check if an expiration datetime is in the past."""
    if not expires_at:
        return False
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)
    return now_utc > expires_at


class RemediationExecutionManager:
    """Orchestrator for controlled remediation executions."""

    @classmethod
    def create_execution(
        cls,
        *,
        db: Session,
        workspace_id: str,
        approval_id: str,
        idempotency_key: str,
        triggered_by: User,
        user_role: str,
    ) -> RemediationExecution:
        """
        Accept an approved proposal and enqueue a durable execution record.

        Invariants enforced:
        1. RBAC: Only 'engineer' or 'admin' can trigger execution.
        2. Idempotency: Duplicate (workspace, idempotency_key) with same approval returns existing record.
        3. No Idempotency Collision: Duplicate key with different approval raises 409.
        4. One Execution per Approval: Consumed approval replay raises 409.
        5. Exact Parameter Snapshot: Parameters copied strictly from approval; caller input forbidden.
        6. JIT Pre-Flight: Service active, environment valid, SSRF check.
        7. Atomic Audit: ExecutionEvent and IncidentEvent persisted in same transaction.
        """
        # 1. RBAC enforcement
        normalized_role = (user_role or "").strip().lower()
        if normalized_role not in ("engineer", "admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role}' is not authorized to trigger remediation executions. "
                "Execution requires 'engineer' or 'admin' role.",
            )

        # 2. Validate idempotency key format
        clean_key = (idempotency_key or "").strip()
        if not clean_key or len(clean_key) > 64:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="idempotency_key must be non-empty and at most 64 characters.",
            )

        # 3. Check for existing execution by (workspace_id, idempotency_key)
        existing_by_key = (
            db.query(RemediationExecution)
            .filter(
                RemediationExecution.workspace_id == workspace_id,
                RemediationExecution.idempotency_key == clean_key,
            )
            .first()
        )
        if existing_by_key:
            if existing_by_key.approval_id == approval_id:
                # Valid idempotent retry -> return existing execution directly
                return existing_by_key
            else:
                # Conflicting approval for same idempotency key
                raise IdempotencyConflictError(
                    f"Idempotency key '{clean_key}' is already used for another execution "
                    f"'{existing_by_key.id}' in workspace '{workspace_id}'."
                )

        # 4. Check if approval has already been consumed by any execution
        existing_by_approval = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.approval_id == approval_id)
            .first()
        )
        if existing_by_approval:
            raise ApprovalAlreadyExecutedError(
                f"Remediation approval '{approval_id}' has already been executed "
                f"(execution ID: '{existing_by_approval.id}'). Replay is prohibited."
            )

        # 5. Load and lock approval row
        approval = (
            db.query(RemediationApproval)
            .filter(RemediationApproval.id == approval_id)
            .with_for_update()
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Remediation approval '{approval_id}' not found.",
            )

        # Tenant isolation check
        if approval.workspace_id != workspace_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-workspace violation: Approval belongs to another workspace.",
            )

        # 6. Verify approval status
        now_utc = datetime.now(timezone.utc)
        if approval.approval_status == "pending":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Remediation approval '{approval_id}' is pending and has not been approved.",
            )
        if approval.approval_status == "rejected":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Remediation proposal was rejected: {approval.rejection_reason}",
            )
        if approval.approval_status == "cancelled":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Remediation proposal was cancelled.",
            )
        if approval.approval_status == "expired" or _is_expired(approval.expires_at, now_utc):
            if approval.approval_status != "expired":
                approval.approval_status = "expired"
                db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Remediation proposal approval has expired.",
            )
        if approval.approval_status != "approved":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot execute approval in state '{approval.approval_status}'.",
            )

        # 7. Action Registry & Pre-flight verification
        action_def = ActionRegistry.get_action(approval.action_id)
        if not action_def:
            raise PreconditionFailedError(
                f"Action '{approval.action_id}' is not in allowlisted registry."
            )
        if not action_def.enabled:
            raise PreconditionFailedError(
                f"Action '{approval.action_id}' is currently disabled in registry."
            )

        # Action-specific authorization checks
        if approval.action_id == "restore_order_api_demo":
            if not action_def.approval_required:
                raise PreconditionFailedError("Integrity check failed: restore_order_api_demo must require approval.")
            if not approval.reviewed_by:
                raise PreconditionFailedError("Human approval signature missing on approved proposal.")

        # Service existence and runtime active check
        target_service = None
        if approval.target_service_id:
            target_service = (
                db.query(Service)
                .filter(Service.id == approval.target_service_id)
                .first()
            )
            if not target_service:
                raise PreconditionFailedError(
                    f"Target service '{approval.target_service_id}' no longer exists in database."
                )
            if target_service.workspace_id != workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-workspace violation: Target service belongs to another workspace.",
                )
            if not target_service.is_active:
                raise PreconditionFailedError(
                    f"Precondition failed: Target service '{target_service.name}' is currently inactive."
                )
            if (target_service.environment or "").lower() not in [
                env.lower() for env in action_def.supported_environments
            ]:
                raise PreconditionFailedError(
                    f"Target service environment '{target_service.environment}' not supported for action '{action_def.action_id}'."
                )

            # JIT authoritative check on target service execution_policy
            raw_policy = target_service.execution_policy
            if raw_policy is None or not str(raw_policy).strip():
                raise PreconditionFailedError(
                    f"Execution rejected: Target service '{target_service.name}' has null or missing execution policy. Failing closed."
                )
            svc_policy = str(raw_policy).strip().lower()
            if svc_policy not in ("demo", "approval_required", "observe_only"):
                raise PreconditionFailedError(
                    f"Execution rejected: Target service '{target_service.name}' has invalid or unsupported execution policy '{raw_policy}'. Failing closed."
                )
            if svc_policy == "observe_only":
                raise PreconditionFailedError(
                    f"Execution rejected: Target service '{target_service.name}' execution policy is 'observe_only'. Operational remediation cannot be dispatched."
                )
            if svc_policy == "demo" and (target_service.environment or "").strip().lower() != "development":
                raise PreconditionFailedError(
                    f"Execution rejected: Target service '{target_service.name}' execution policy is 'demo', which is restricted to the development environment (current environment: '{target_service.environment}')."
                )
            if not ActionRegistry.is_action_supported_for_service(approval.action_id, target_service, db=db):
                raise PreconditionFailedError("No approved remediation playbook is configured for this service.")
        else:
            raise PreconditionFailedError(
                "Remediation execution requires a valid target service with a registered health check origin."
            )

        if not target_service or not (target_service.health_check_url or "").strip():
            raise PreconditionFailedError(
                "Remediation execution requires a valid target service with a registered health check origin."
            )

        # Incident existence and ownership check if present
        if approval.incident_id:
            incident = (
                db.query(Incident)
                .filter(Incident.id == approval.incident_id)
                .first()
            )
            if not incident:
                raise PreconditionFailedError(
                    f"Precondition failed: Linked incident '{approval.incident_id}' no longer exists in database."
                )
            if incident.workspace_id != workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-workspace violation: Incident belongs to another workspace.",
                )
            if approval.target_service_id and incident.service_id != approval.target_service_id:
                raise PreconditionFailedError(
                    f"Precondition failed: Incident service '{incident.service_id}' does not match target service '{approval.target_service_id}'."
                )

        # Investigation existence and ownership check if present
        if approval.investigation_id:
            investigation = (
                db.query(Investigation)
                .filter(Investigation.id == approval.investigation_id)
                .first()
            )
            if not investigation:
                raise PreconditionFailedError(
                    f"Precondition failed: Linked investigation '{approval.investigation_id}' no longer exists in database."
                )
            if investigation.workspace_id != workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-workspace violation: Investigation belongs to another workspace.",
                )
            if approval.incident_id and investigation.incident_id != approval.incident_id:
                raise PreconditionFailedError(
                    f"Precondition failed: Investigation '{approval.investigation_id}' does not belong to incident '{approval.incident_id}'."
                )

        # Service binding check: reject approval bound to another service in parameters
        if target_service and approval.validated_parameters:
            param_svc_id = approval.validated_parameters.get("service_id")
            if param_svc_id and param_svc_id != target_service.id:
                raise PreconditionFailedError(
                    f"Parameter service_id '{param_svc_id}' does not match target service '{target_service.id}'."
                )

        # Validate parameters snapshot against schema
        is_valid, _, err_msg = ActionRegistry.validate_parameters(
            approval.action_id, approval.validated_parameters or {}
        )
        if not is_valid:
            raise PreconditionFailedError(f"Approved parameter validation failed: {err_msg}")

        # 8. Create RemediationExecution record with EXACT parameter snapshot and signed manifest
        execution_id = str(uuid.uuid4())
        approved_params_snapshot = copy.deepcopy(approval.validated_parameters or {})

        try:
            manifest, manifest_signature, manifest_digest = generate_and_sign_execution_manifest(
                execution_id=execution_id,
                approval=approval,
                service=target_service,
            )
        except ManifestSigningError as e:
            logger.error("Failed to generate and sign execution manifest for execution %s: %s", execution_id, e)
            raise PreconditionFailedError(f"Control-plane manifest signing failed: {e}")

        execution = RemediationExecution(
            id=execution_id,
            workspace_id=workspace_id,
            approval_id=approval.id,
            incident_id=approval.incident_id,
            investigation_id=approval.investigation_id,
            action_id=approval.action_id,
            target_service_id=approval.target_service_id,
            approved_parameters=approved_params_snapshot,
            status=ExecutionState.QUEUED.value,
            idempotency_key=clean_key,
            locked_by=None,
            locked_until=None,
            heartbeat_at=None,
            fencing_token=0,
            retry_policy="idempotent",
            triggered_by=triggered_by.id,
            triggered_at=now_utc,
            timeout_seconds=action_def.timeout_seconds or 30,
            attempt_count=0,
            max_attempts=1,
            created_at=now_utc,
            updated_at=now_utc,
            manifest_id=manifest.manifest_id,
            authorization_manifest=manifest.model_dump(),
            manifest_signature=manifest_signature,
            manifest_digest=manifest_digest,
            manifest_key_id=manifest.key_id,
            manifest_expires_at=datetime.fromtimestamp(manifest.expires_at, tz=timezone.utc),
        )
        db.add(execution)

        # 9. Atomic ExecutionEvent
        exec_event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution_id,
            workspace_id=workspace_id,
            event_type="queued",
            message=f"Remediation execution queued for action '{approval.action_id}' (approval: {approval.id})",
            metadata_json=sanitize_metadata({
                "action_id": approval.action_id,
                "approval_id": approval.id,
                "idempotency_key": clean_key,
                "target_service_id": approval.target_service_id,
                "timeout_seconds": execution.timeout_seconds,
                "manifest_id": manifest.manifest_id,
                "manifest_digest": manifest_digest,
            }),
            timestamp=now_utc,
        )
        db.add(exec_event)

        # 10. Atomic IncidentEvent if linked to an incident
        if approval.incident_id:
            inc_event = IncidentEvent(
                incident_id=approval.incident_id,
                event_type="action",
                message=f"Remediation execution queued for action '{approval.action_id}'",
                metadata_json=json.dumps(
                    sanitize_metadata({
                        "execution_id": execution_id,
                        "approval_id": approval.id,
                        "action_id": approval.action_id,
                        "status": ExecutionState.QUEUED.value,
                    })
                ),
                timestamp=now_utc,
            )
            db.add(inc_event)

        # Commit durable queue entry atomically
        db.commit()
        db.refresh(execution)
        return execution

    @classmethod
    def get_execution(
        cls,
        *,
        execution_id: str,
        workspace_id: str,
        db: Session,
    ) -> RemediationExecution:
        """Fetch an execution record scoped to the authorized workspace."""
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .first()
        )
        if not execution:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{execution_id}' not found.",
            )
        if execution.workspace_id != workspace_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-workspace violation: Execution belongs to another workspace.",
            )
        return execution

    @classmethod
    def list_executions(
        cls,
        *,
        workspace_id: str,
        db: Session,
        status_filter: Optional[str] = None,
        action_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[RemediationExecution], int]:
        """List executions for workspace with pagination and filters."""
        query = db.query(RemediationExecution).filter(
            RemediationExecution.workspace_id == workspace_id
        )
        if status_filter:
            query = query.filter(RemediationExecution.status == status_filter.strip().lower())
        if action_id:
            query = query.filter(RemediationExecution.action_id == action_id.strip())

        total = query.count()
        executions = (
            query.order_by(RemediationExecution.triggered_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return executions, total

    @classmethod
    def cancel_execution(
        cls,
        *,
        execution_id: str,
        workspace_id: str,
        user: User,
        user_role: str,
        db: Session,
        cancellation_reason: Optional[str] = None,
    ) -> RemediationExecution:
        """Cancel an execution job if still in queued state."""
        normalized_role = (user_role or "").strip().lower()
        if normalized_role not in ("engineer", "admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cancellation requires 'engineer' or 'admin' role.",
            )

        execution = (
            db.query(RemediationExecution)
            .filter(
                RemediationExecution.id == execution_id,
                RemediationExecution.workspace_id == workspace_id,
            )
            .with_for_update()
            .first()
        )
        if not execution:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{execution_id}' not found in this workspace.",
            )

        if execution.status != ExecutionState.QUEUED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot cancel execution in state '{execution.status}'. "
                "Only jobs in 'queued' status can be cancelled prior to worker claim.",
            )

        now_utc = datetime.now(timezone.utc)
        validate_state_transition(execution.status, ExecutionState.CANCELLED.value)
        execution.status = ExecutionState.CANCELLED.value
        execution.completed_at = now_utc
        execution.updated_at = now_utc

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=workspace_id,
            event_type="cancelled",
            message=f"Execution cancelled by user {user.email or user.id}: {cancellation_reason or 'No reason provided'}",
            metadata_json=sanitize_metadata({
                "cancelled_by": user.id,
                "reason": cancellation_reason,
            }),
            timestamp=now_utc,
        )
        db.add(event)

        if execution.incident_id:
            inc_event = IncidentEvent(
                incident_id=execution.incident_id,
                event_type="action",
                message=f"Remediation execution '{execution.id}' cancelled by operator.",
                metadata_json=json.dumps({
                    "execution_id": execution.id,
                    "action_id": execution.action_id,
                    "status": ExecutionState.CANCELLED.value,
                }),
                timestamp=now_utc,
            )
            db.add(inc_event)

        db.commit()
        db.refresh(execution)
        return execution

    @classmethod
    def resolve_uncertain_execution(
        cls,
        *,
        execution_id: str,
        workspace_id: str,
        user: User,
        user_role: str,
        decision: str,
        justification: str,
        evidence: Optional[Dict[str, Any]] = None,
        db: Session,
        verification_engine: Optional[Any] = None,
    ) -> RemediationExecution:
        """
        Administratively resolve an execution held in EXECUTION_UNCERTAIN (FINDING-2.1-01).

        Enforces:
        1. RBAC: Only 'engineer' or 'admin' role can resolve uncertainty.
        2. Workspace tenancy: Execution must belong to the caller's workspace.
        3. Precondition: Execution must be in 'execution_uncertain' status with 'HOLD:EXECUTION_UNCERTAIN'.
        4. Row lock: with_for_update prevents concurrent duplicate resolution.
        5. Justification: Non-empty operator justification (>= 5 chars) is mandatory.
        6. Immutable audit: Records ExecutionEvent and IncidentEvent with operator details.
        7. Decision outcomes:
           - ABORT_FAILURE: Marks execution failed without auto-retry (attempt_count=max_attempts).
           - CONFIRM_SUCCESS: Transitions to verification_pending and triggers independent verification.
             Incident is NEVER recovered without passing independent verification.
        """
        # 1. RBAC
        normalized_role = (user_role or "").strip().lower()
        if normalized_role not in ("engineer", "admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Resolving execution uncertainty requires 'engineer' or 'admin' role.",
            )

        # 2. Validate justification
        clean_justification = (justification or "").strip()
        if not clean_justification or len(clean_justification) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A non-empty justification of at least 5 characters is required to resolve uncertainty.",
            )

        # 3. Validate decision
        decision_upper = (decision or "").strip().upper()
        if decision_upper not in ("ABORT_FAILURE", "CONFIRM_SUCCESS"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid resolution decision '{decision}'. Must be 'ABORT_FAILURE' or 'CONFIRM_SUCCESS'.",
            )

        # 4. Fetch and lock execution row
        execution = (
            db.query(RemediationExecution)
            .filter(
                RemediationExecution.id == execution_id,
                RemediationExecution.workspace_id == workspace_id,
            )
            .with_for_update()
            .first()
        )
        if not execution:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{execution_id}' not found in workspace '{workspace_id}'.",
            )

        # 5. Verify state precondition
        if (
            execution.status != ExecutionState.EXECUTION_UNCERTAIN.value
            or execution.locked_by != "HOLD:EXECUTION_UNCERTAIN"
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Execution '{execution_id}' is not in a resolvable uncertainty hold. "
                    f"Current status: '{execution.status}', locked_by: '{execution.locked_by}'."
                ),
            )

        now_utc = datetime.now(timezone.utc)
        prev_status = execution.status
        prev_locked_by = execution.locked_by

        # Build operator resolution metadata
        resolution_metadata = {
            "decision": decision_upper,
            "operator_user_id": user.id,
            "operator_email": getattr(user, "email", user.id),
            "justification": clean_justification,
            "evidence": evidence or {},
            "resolved_at": now_utc.isoformat(),
            "previous_status": prev_status,
            "previous_locked_by": prev_locked_by,
        }

        output_meta = dict(execution.execution_output or {})
        output_meta["operator_resolution"] = resolution_metadata
        execution.execution_output = sanitize_metadata(output_meta)
        flag_modified(execution, "execution_output")
        execution.updated_at = now_utc

        if decision_upper == "ABORT_FAILURE":
            validate_state_transition(execution.status, ExecutionState.EXECUTION_FAILED.value)
            execution.status = ExecutionState.EXECUTION_FAILED.value
            execution.error_category = "operator_aborted"
            execution.error_message = f"Administratively aborted by operator: {clean_justification}"
            # Strictly prevent automatic retry
            execution.attempt_count = execution.max_attempts
            execution.locked_by = None
            execution.locked_until = now_utc
            execution.completed_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="operator_uncertainty_resolved",
                message=f"Operator resolved uncertainty with ABORT_FAILURE: {clean_justification}",
                metadata_json=sanitize_metadata(resolution_metadata),
                timestamp=now_utc,
            )
            db.add(event)

            if execution.incident_id:
                inc_event = IncidentEvent(
                    incident_id=execution.incident_id,
                    event_type="action",
                    message="Remediation action administratively aborted by operator. Incident remains active.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "decision": "ABORT_FAILURE",
                        "operator_id": user.id,
                        "status": ExecutionState.EXECUTION_FAILED.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)

            db.commit()
            db.refresh(execution)
            return execution

        elif decision_upper == "CONFIRM_SUCCESS":
            validate_state_transition(execution.status, ExecutionState.VERIFICATION_PENDING.value)
            execution.status = ExecutionState.VERIFICATION_PENDING.value
            execution.verification_status = "pending"
            execution.locked_by = f"OPERATOR_RESOLVE:{user.id}"
            execution.locked_until = now_utc + timedelta(seconds=120)

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="operator_uncertainty_resolved",
                message=f"Operator confirmed success: {clean_justification}. Triggering independent verification.",
                metadata_json=sanitize_metadata(resolution_metadata),
                timestamp=now_utc,
            )
            db.add(event)

            if execution.incident_id:
                inc_event = IncidentEvent(
                    incident_id=execution.incident_id,
                    event_type="action",
                    message="Operator confirmed remediation success. Initiating independent verification.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "decision": "CONFIRM_SUCCESS",
                        "operator_id": user.id,
                        "status": ExecutionState.VERIFICATION_PENDING.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)

            db.commit()
            db.refresh(execution)

            # Trigger independent verification
            try:
                from app.execution.verification import PostExecutionVerificationEngine
                from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner

                engine = verification_engine or PostExecutionVerificationEngine(
                    runner=IsolatedHttpRecoveryRunner(allow_unauthenticated_probes=True)
                )
                v_runner = getattr(engine, "_runner", None) or IsolatedHttpRecoveryRunner(
                    allow_unauthenticated_probes=True
                )
                summary = engine.run_verification_cycle(
                    db=db,
                    execution_id=execution.id,
                    workspace_id=workspace_id,
                    worker_id=execution.locked_by,
                    fencing_token=execution.fencing_token,
                    runner=v_runner,
                    recover_incident=True,
                )
                logger.info(
                    "Post-resolution verification cycle finished for execution '%s': %s",
                    execution_id,
                    summary.outcome.value,
                )
            except Exception as ver_err:
                logger.error(
                    "Post-resolution verification cycle failed/inconclusive for execution '%s': %s",
                    execution_id,
                    ver_err,
                )
                # Fail-closed: execution remains in verification_failed; incident NEVER marked recovered
                if execution.status == ExecutionState.VERIFICATION_PENDING.value:
                    execution.status = ExecutionState.VERIFICATION_FAILED.value
                    execution.verification_status = "failed"
                    execution.error_message = f"Post-resolution verification failed: {ver_err}"
                    execution.locked_by = None
                    execution.locked_until = now_utc
                    db.commit()
                    db.refresh(execution)

            db.refresh(execution)
            return execution

    # ========================================================================
    # Worker Lease & Fencing Token Management
    # ========================================================================

    @classmethod
    def claim_next_execution(
        cls,
        *,
        worker_id: str,
        lease_seconds: int = 90,
        workspace_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        db: Session,
    ) -> Optional[RemediationExecution]:
        """
        Poll and claim the next eligible execution job using PostgreSQL SKIP LOCKED.

        Eligible jobs:
        1. status == 'queued' (fresh job)
        2. status in ('validating', 'executing') AND locked_until < :now_utc (stale lease recovery)

        Targeted Execution Invariant:
        - If execution_id is specified, claims ONLY that exact execution via SQL filter.
        - If the target is unavailable, invalid, or locked, returns None (never falls back).

        Crash Recovery Invariants:
        - If previous worker crashed during 'validating' (pre-dispatch):
          re-acquires lease, increments fencing token, allows execution to proceed.
        - If previous worker crashed during 'executing' (post-dispatch):
          marks execution as 'execution_uncertain' to strictly prevent duplicate container execution,
          bumps fencing token, records incident/audit events, and commits.
        """
        now_utc = datetime.now(timezone.utc)
        query = db.query(RemediationExecution).filter(
            or_(
                RemediationExecution.status == ExecutionState.QUEUED.value,
                and_(
                    RemediationExecution.status.in_([
                        ExecutionState.VALIDATING.value,
                        ExecutionState.EXECUTING.value,
                    ]),
                    RemediationExecution.locked_until < now_utc,
                ),
            )
        )
        if workspace_id:
            query = query.filter(RemediationExecution.workspace_id == workspace_id)
        if execution_id:
            query = query.filter(RemediationExecution.id == execution_id)

        query = query.order_by(RemediationExecution.triggered_at.asc())

        # PostgreSQL supports SKIP LOCKED; SQLite uses standard FOR UPDATE
        try:
            if db.bind and db.bind.dialect.name == "postgresql":
                execution = query.with_for_update(skip_locked=True).first()
            else:
                execution = query.with_for_update().first()
        except Exception:
            execution = query.with_for_update().first()

        if not execution:
            return None

        # Case 1: Fresh queued job
        if execution.status == ExecutionState.QUEUED.value:
            validate_state_transition(execution.status, ExecutionState.VALIDATING.value)
            execution.status = ExecutionState.VALIDATING.value
            execution.locked_by = worker_id
            execution.locked_until = now_utc + timedelta(seconds=lease_seconds)
            execution.heartbeat_at = now_utc
            execution.started_at = now_utc if not execution.started_at else execution.started_at
            execution.fencing_token += 1
            execution.attempt_count += 1
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                event_type="lease_acquired",
                message=f"Worker '{worker_id}' claimed execution lease (fencing token: {execution.fencing_token}).",
                metadata_json=sanitize_metadata({
                    "worker_id": worker_id,
                    "fencing_token": execution.fencing_token,
                    "locked_until": execution.locked_until.isoformat(),
                    "attempt_count": execution.attempt_count,
                }),
                timestamp=now_utc,
            )
            db.add(event)
            db.commit()
            db.refresh(execution)
            return execution

        # Case 2: Stale worker crashed before container dispatch (in validating state)
        elif execution.status == ExecutionState.VALIDATING.value:
            previous_worker = execution.locked_by
            execution.locked_by = worker_id
            execution.locked_until = now_utc + timedelta(seconds=lease_seconds)
            execution.heartbeat_at = now_utc
            execution.fencing_token += 1
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                event_type="lease_recovery_pre_dispatch",
                message=f"Worker '{worker_id}' recovered expired lease from crashed worker '{previous_worker}' in validating state.",
                metadata_json=sanitize_metadata({
                    "recovered_from_worker": previous_worker,
                    "worker_id": worker_id,
                    "fencing_token": execution.fencing_token,
                    "locked_until": execution.locked_until.isoformat(),
                }),
                timestamp=now_utc,
            )
            db.add(event)
            db.commit()
            db.refresh(execution)
            return execution

        # Case 3: Stale worker crashed AFTER container dispatch (in executing state)
        elif execution.status == ExecutionState.EXECUTING.value:
            previous_worker = execution.locked_by
            validate_state_transition(execution.status, ExecutionState.EXECUTION_UNCERTAIN.value)
            execution.status = ExecutionState.EXECUTION_UNCERTAIN.value
            execution.fencing_token += 1
            execution.locked_by = None
            execution.locked_until = None
            execution.completed_at = now_utc
            execution.updated_at = now_utc
            execution.error_category = "worker_crash_after_dispatch"
            execution.uncertain_reason = (
                f"Worker '{previous_worker}' lease expired while execution was in-flight ('executing' state). "
                "Container dispatch outcome is uncertain; blind duplicate execution prevented."
            )

            # Update active attempt to uncertain
            active_attempt = (
                db.query(ExecutionAttempt)
                .filter(
                    ExecutionAttempt.execution_id == execution.id,
                    ExecutionAttempt.attempt_number == execution.attempt_count,
                )
                .first()
            )
            if active_attempt and active_attempt.status == "running":
                active_attempt.status = "uncertain"
                active_attempt.completed_at = now_utc
                active_attempt.error_category = "worker_crash_after_dispatch"
                active_attempt.error_message = execution.uncertain_reason

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                event_type="lease_recovery_post_dispatch_uncertain",
                message=execution.uncertain_reason,
                metadata_json=sanitize_metadata({
                    "recovered_from_worker": previous_worker,
                    "worker_id": worker_id,
                    "fencing_token": execution.fencing_token,
                    "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                }),
                timestamp=now_utc,
            )
            db.add(event)

            if execution.incident_id:
                inc_event = IncidentEvent(
                    incident_id=execution.incident_id,
                    event_type="action",
                    message=f"Remediation execution '{execution.id}' marked uncertain after worker '{previous_worker}' lease expired.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "action_id": execution.action_id,
                        "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)

            db.commit()
            return None

        return None

    @classmethod
    def claim_execution_lease(
        cls,
        *,
        execution_id: str,
        worker_id: str,
        expected_fencing_token: int,
        lease_seconds: int = 90,
        db: Session,
    ) -> RemediationExecution:
        """
        Claim a queued execution job with monotonic fencing token increment.
        Rejects stale worker updates if expected_fencing_token does not match.
        """
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .with_for_update()
            .first()
        )
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found.")

        if execution.fencing_token != expected_fencing_token:
            raise StaleWorkerFencingError(
                f"Stale worker lease claim rejected: current fencing token {execution.fencing_token} "
                f"does not match expected {expected_fencing_token}."
            )

        validate_state_transition(execution.status, ExecutionState.VALIDATING.value)

        now_utc = datetime.now(timezone.utc)
        execution.status = ExecutionState.VALIDATING.value
        execution.locked_by = worker_id
        execution.locked_until = now_utc + timedelta(seconds=lease_seconds)
        execution.heartbeat_at = now_utc
        execution.started_at = now_utc
        execution.fencing_token += 1
        execution.attempt_count += 1
        execution.updated_at = now_utc

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="lease_acquired",
            message=f"Worker '{worker_id}' claimed execution lease (fencing token: {execution.fencing_token}).",
            metadata_json=sanitize_metadata({
                "worker_id": worker_id,
                "fencing_token": execution.fencing_token,
                "locked_until": execution.locked_until.isoformat(),
            }),
            timestamp=now_utc,
        )
        db.add(event)
        db.commit()
        db.refresh(execution)
        return execution

    @classmethod
    def heartbeat_lease(
        cls,
        *,
        execution_id: str,
        worker_id: str,
        expected_fencing_token: int,
        lease_seconds: int = 90,
        db: Session,
    ) -> RemediationExecution:
        """Extend worker lease liveness. Rejects stale or non-owning workers."""
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .with_for_update()
            .first()
        )
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found.")

        if execution.locked_by != worker_id:
            raise StaleWorkerFencingError(
                f"Heartbeat rejected: execution locked by '{execution.locked_by}', not '{worker_id}'."
            )
        if execution.fencing_token != expected_fencing_token:
            raise StaleWorkerFencingError(
                f"Heartbeat rejected: fencing token mismatch ({execution.fencing_token} != {expected_fencing_token})."
            )
        if execution.status not in (
            ExecutionState.QUEUED.value,
            ExecutionState.VALIDATING.value,
            ExecutionState.EXECUTING.value,
            ExecutionState.VERIFICATION_PENDING.value,
        ):
            raise StaleWorkerFencingError(
                f"Heartbeat rejected: execution '{execution_id}' is in non-active status '{execution.status}'."
            )

        now_utc = datetime.now(timezone.utc)
        execution.locked_until = now_utc + timedelta(seconds=lease_seconds)
        execution.heartbeat_at = now_utc
        execution.updated_at = now_utc

        db.commit()
        db.refresh(execution)
        return execution

    @classmethod
    def transition_execution_state(
        cls,
        *,
        execution_id: str,
        new_state: str,
        expected_fencing_token: int,
        db: Session,
        execution_output: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        error_category: Optional[str] = None,
        uncertain_reason: Optional[str] = None,
    ) -> RemediationExecution:
        """
        Transition execution state while enforcing state machine rules and fencing tokens.
        """
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .with_for_update()
            .first()
        )
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found.")

        if execution.fencing_token != expected_fencing_token:
            raise StaleWorkerFencingError(
                f"State transition rejected: fencing token mismatch ({execution.fencing_token} != {expected_fencing_token})."
            )

        validate_state_transition(execution.status, new_state)

        now_utc = datetime.now(timezone.utc)
        old_state = execution.status
        execution.status = new_state
        execution.updated_at = now_utc

        if execution_output is not None:
            execution.execution_output = sanitize_metadata(execution_output)
        if error_message is not None:
            execution.error_message = error_message
        if error_category is not None:
            execution.error_category = error_category
        if uncertain_reason is not None:
            execution.uncertain_reason = uncertain_reason

        # Release lease if entering terminal state
        if is_terminal_state(new_state):
            execution.locked_by = None
            execution.locked_until = None
            execution.completed_at = now_utc

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type=f"state_transition_{new_state}",
            message=f"Execution state transitioned from '{old_state}' to '{new_state}'.",
            metadata_json=sanitize_metadata({
                "old_state": old_state,
                "new_state": new_state,
                "fencing_token": execution.fencing_token,
                "error_category": error_category,
            }),
            timestamp=now_utc,
        )
        db.add(event)
        db.commit()
        db.refresh(execution)
        return execution
