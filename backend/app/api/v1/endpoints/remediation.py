"""Remediation Foundation & Human Approval Workflow API endpoints.

Blueprint Section 8 & Phases 4.1 & 4.2:
- GET /actions: List allowlisted remediation actions catalog
- POST /policy/evaluate: Evaluate an action proposal deterministically against backend policy
- GET /policy/decisions: Retrieve immutable audit records of policy decisions
- POST /approvals: Create pending human approval request from eligible policy decision
- GET /approvals: List approval requests scoped to workspace
- GET /approvals/{approval_id}: View detailed approval request with rich metadata
- POST /approvals/{approval_id}/approve: Approve pending request (Engineer/Admin)
- POST /approvals/{approval_id}/reject: Reject pending request with reason (Engineer/Admin)
- POST /approvals/{approval_id}/cancel: Cancel pending request (Requester/Admin)
- Execution of remediation actions is strictly NOT implemented in this phase
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import RequireWorkspaceRole, check_workspace_role, get_current_user
from app.db.session import get_db
from app.execution.manager import RemediationExecutionManager
from app.models.remediation import PolicyDecision, RemediationExecution
from app.models.user import User
from app.remediation.approval_service import ApprovalService, build_approval_response
from app.remediation.policy import PolicyEngine
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import (
    ActionCatalogResponse,
    ApprovalApproveRequest,
    ApprovalCancelRequest,
    ApprovalCreateRequest,
    ApprovalRejectRequest,
    ApprovalResponse,
    ExecutionAttemptResponse,
    ExecutionCancelRequest,
    ExecutionCreateRequest,
    ExecutionEventResponse,
    ExecutionListResponse,
    ExecutionResolveUncertainRequest,
    ExecutionResponse,
    PolicyDecisionResponse,
    PolicyDecisionType,
    PolicyEvaluationRequest,
    VerificationCycleListResponse,
    VerificationCycleResponse,
    VerificationProbeResponse,
)
from app.models.verification import VerificationCycle, VerificationProbeResult
from app.models.incident import Incident
from app.models.service import Service

router = APIRouter()


# ============================================================================
# Action Catalog & Policy Endpoints (Phase 4.1)
# ============================================================================

@router.get(
    "/actions",
    response_model=ActionCatalogResponse,
    summary="List allowlisted remediation action catalog",
    description="Returns the bounded catalog of allowlisted remediation actions visible to authorized workspace members.",
)
def list_remediation_actions(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    membership=Depends(RequireWorkspaceRole()),
) -> ActionCatalogResponse:
    """Retrieve catalog of allowlisted remediation actions."""
    actions = ActionRegistry.list_actions(include_disabled=False)
    return ActionCatalogResponse(actions=actions, total=len(actions))


@router.post(
    "/policy/evaluate",
    response_model=PolicyDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate action proposal against backend policy",
    description="Evaluates a proposed action against allowlist, risk boundaries, parameters, and workspace constraints. Persists audit decision.",
)
def evaluate_remediation_policy(
    payload: PolicyEvaluationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PolicyDecisionResponse:
    """
    Deterministically evaluates an action proposal against backend policies.
    Records immutable PolicyDecision audit log.
    """
    # Verify caller's membership in the target workspace
    membership = check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
    )

    # Evaluate action proposal deterministically
    eval_result = PolicyEngine.evaluate(
        workspace_id=payload.workspace_id,
        user_role=membership.role,
        action_id=payload.action_id,
        parameters=payload.parameters,
        environment=payload.environment,
        db=db,
        user_id=current_user.id,
        playbook_id=payload.playbook_id,
        playbook_version=payload.playbook_version,
    )

    # Persist immutable policy decision audit record
    decision_record = PolicyDecision(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        action_id=eval_result.action_id,
        target_service_id=eval_result.target_service_id,
        risk_level=eval_result.risk_level,
        decision=eval_result.decision.value,
        decision_reason=eval_result.decision_reason,
        policy_version=eval_result.policy_version,
        validated_parameters=eval_result.validated_parameters,
        timestamp=eval_result.evaluated_at,
    )
    db.add(decision_record)
    db.commit()
    db.refresh(decision_record)

    return PolicyDecisionResponse(
        id=decision_record.id,
        workspace_id=decision_record.workspace_id,
        user_id=decision_record.user_id,
        action_id=decision_record.action_id,
        target_service_id=decision_record.target_service_id,
        risk_level=decision_record.risk_level,
        decision=eval_result.decision,
        decision_reason=decision_record.decision_reason,
        policy_version=decision_record.policy_version,
        approval_required=eval_result.approval_required,
        validated_parameters=decision_record.validated_parameters,
        evaluated_at=decision_record.timestamp,
        timestamp=decision_record.timestamp,
    )


@router.get(
    "/policy/decisions",
    response_model=List[PolicyDecisionResponse],
    summary="List policy decision audit records",
    description="Returns immutable audit trail of policy evaluations scoped to the authorized workspace.",
)
def list_policy_decisions(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    action_id: Optional[str] = Query(None, description="Filter by action ID"),
    target_service_id: Optional[str] = Query(None, description="Filter by target service ID"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[PolicyDecisionResponse]:
    """Retrieve policy evaluation audit trail for workspace."""
    query = db.query(PolicyDecision).filter(PolicyDecision.workspace_id == workspace_id)

    if action_id:
        query = query.filter(PolicyDecision.action_id == action_id.strip())
    if target_service_id:
        query = query.filter(PolicyDecision.target_service_id == target_service_id.strip())

    decisions = (
        query.order_by(PolicyDecision.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        PolicyDecisionResponse(
            id=d.id,
            workspace_id=d.workspace_id,
            user_id=d.user_id,
            action_id=d.action_id,
            target_service_id=d.target_service_id,
            risk_level=d.risk_level,
            decision=PolicyDecisionType(d.decision),
            decision_reason=d.decision_reason,
            policy_version=d.policy_version,
            approval_required=(d.decision == "approval_required"),
            validated_parameters=d.validated_parameters or {},
            evaluated_at=d.timestamp,
            timestamp=d.timestamp,
        )
        for d in decisions
    ]


# ============================================================================
# Human Approval Workflow Endpoints (Phase 4.2)
# ============================================================================

@router.post(
    "/approvals",
    response_model=ApprovalResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a pending remediation approval request",
    description="Creates a pending human approval request from an eligible policy decision returning 'approval_required'. Requires engineer role or higher.",
)
def create_remediation_approval(
    payload: ApprovalCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApprovalResponse:
    """Create a pending approval request."""
    # Verify caller's membership with minimum engineer role
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    approval = ApprovalService.create_approval_request(
        db=db,
        workspace_id=payload.workspace_id,
        policy_decision_id=payload.policy_decision_id,
        requested_by=current_user,
        incident_id=payload.incident_id,
        investigation_id=payload.investigation_id,
        expires_in_hours=payload.expires_in_hours,
    )
    return build_approval_response(approval)


@router.get(
    "/approvals",
    response_model=List[ApprovalResponse],
    summary="List remediation approval requests",
    description="Returns all remediation approval requests for the authorized workspace, with optional status and action filters.",
)
def list_remediation_approvals(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    status: Optional[str] = Query(None, description="Filter by status (pending, approved, rejected, expired, cancelled)"),
    action_id: Optional[str] = Query(None, description="Filter by action ID"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[ApprovalResponse]:
    """List approval requests for workspace."""
    approvals = ApprovalService.list_approvals(
        db=db,
        workspace_id=workspace_id,
        status_filter=status,
        action_id=action_id,
        limit=limit,
        offset=offset,
    )
    return [build_approval_response(a) for a in approvals]


@router.get(
    "/approvals/{approval_id}",
    response_model=ApprovalResponse,
    summary="Get remediation approval request details",
    description="Returns complete approval details, parameters, risk metadata, and expiration.",
)
def get_remediation_approval(
    approval_id: str,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> ApprovalResponse:
    """Retrieve single approval details."""
    approval = ApprovalService.get_approval(
        db=db,
        approval_id=approval_id,
        workspace_id=workspace_id,
    )
    return build_approval_response(approval)


@router.post(
    "/approvals/{approval_id}/approve",
    response_model=ApprovalResponse,
    summary="Approve a pending remediation request",
    description="Approves a pending remediation proposal. Does NOT execute the action. Requires engineer role or higher.",
)
def approve_remediation_request(
    approval_id: str,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    payload: Optional[ApprovalApproveRequest] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApprovalResponse:
    """Approve a pending remediation proposal."""
    membership = check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    approval = ApprovalService.approve_request(
        db=db,
        approval_id=approval_id,
        workspace_id=workspace_id,
        reviewer=current_user,
        user_role=membership.role,
        notes=payload.notes if payload else None,
    )
    return build_approval_response(approval)


@router.post(
    "/approvals/{approval_id}/reject",
    response_model=ApprovalResponse,
    summary="Reject a pending remediation request",
    description="Rejects a pending remediation proposal with mandatory rationale. Requires engineer role or higher.",
)
def reject_remediation_request(
    approval_id: str,
    payload: ApprovalRejectRequest,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApprovalResponse:
    """Reject a pending remediation proposal."""
    membership = check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    approval = ApprovalService.reject_request(
        db=db,
        approval_id=approval_id,
        workspace_id=workspace_id,
        reviewer=current_user,
        user_role=membership.role,
        rejection_reason=payload.rejection_reason,
    )
    return build_approval_response(approval)


@router.post(
    "/approvals/{approval_id}/cancel",
    response_model=ApprovalResponse,
    summary="Cancel a pending remediation request",
    description="Cancels a pending remediation proposal. Permitted for original requester or workspace Admin.",
)
def cancel_remediation_request(
    approval_id: str,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    payload: Optional[ApprovalCancelRequest] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApprovalResponse:
    """Cancel a pending remediation proposal."""
    membership = check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    approval = ApprovalService.cancel_request(
        db=db,
        approval_id=approval_id,
        workspace_id=workspace_id,
        user=current_user,
        user_role=membership.role,
        cancellation_reason=payload.cancellation_reason if payload else None,
    )
    return build_approval_response(approval)


@router.post(
    "/approvals/cleanup-expired",
    summary="Maintenance: Expire overdue pending approvals",
    description="Explicit maintenance operation to sweep and persist overdue pending approvals as expired in the database.",
)
def cleanup_expired_remediation_approvals(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Explicit administrative maintenance task to transition overdue approvals."""
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="admin",
    )
    count = ApprovalService.expire_overdue_approvals(
        db=db,
        workspace_id=workspace_id,
    )
    return {
        "status": "success",
        "workspace_id": workspace_id,
        "expired_count": count,
    }


# ============================================================================
# Execution Orchestration Endpoints (Phase 4.3)
# ============================================================================

def build_execution_response(execution: RemediationExecution) -> ExecutionResponse:
    """Helper to convert a RemediationExecution ORM entity into ExecutionResponse."""
    return ExecutionResponse(
        id=execution.id,
        workspace_id=execution.workspace_id,
        approval_id=execution.approval_id,
        incident_id=execution.incident_id,
        investigation_id=execution.investigation_id,
        action_id=execution.action_id,
        target_service_id=execution.target_service_id,
        approved_parameters=execution.approved_parameters or {},
        status=execution.status,
        idempotency_key=execution.idempotency_key,
        locked_by=execution.locked_by,
        locked_until=execution.locked_until,
        heartbeat_at=execution.heartbeat_at,
        fencing_token=execution.fencing_token,
        retry_policy=execution.retry_policy,
        triggered_by=execution.triggered_by,
        triggered_at=execution.triggered_at,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        timeout_seconds=execution.timeout_seconds,
        attempt_count=execution.attempt_count,
        max_attempts=execution.max_attempts,
        execution_output=execution.execution_output,
        verification_status=execution.verification_status,
        verification_output=execution.verification_output,
        error_message=execution.error_message,
        error_category=execution.error_category,
        uncertain_reason=execution.uncertain_reason,
        created_at=execution.created_at,
        updated_at=execution.updated_at,
        attempts=[ExecutionAttemptResponse.model_validate(att) for att in execution.attempts] if execution.attempts else [],
        events=[ExecutionEventResponse.model_validate(ev) for ev in execution.events] if execution.events else [],
    )


@router.post(
    "/executions",
    response_model=ExecutionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger execution of an approved remediation proposal",
    description="Validates an approved remediation proposal and enqueues a durable execution job. Requires 'engineer' or 'admin' role.",
)
def create_remediation_execution(
    payload: ExecutionCreateRequest,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExecutionResponse:
    """
    Ingest approved remediation proposal into durable execution queue.
    Client cannot supply or modify action parameters.
    """
    membership = check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    execution = RemediationExecutionManager.create_execution(
        db=db,
        workspace_id=workspace_id,
        approval_id=payload.approval_id,
        idempotency_key=payload.idempotency_key,
        triggered_by=current_user,
        user_role=membership.role,
    )
    return build_execution_response(execution)


@router.get(
    "/executions",
    response_model=ExecutionListResponse,
    summary="List remediation executions",
    description="Returns executions in workspace with optional filters and pagination.",
)
def list_remediation_executions(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    status: Optional[str] = Query(None, description="Filter by execution status"),
    action_id: Optional[str] = Query(None, description="Filter by action ID"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExecutionListResponse:
    """List execution records scoped to workspace."""
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="viewer",
    )
    executions, total = RemediationExecutionManager.list_executions(
        workspace_id=workspace_id,
        db=db,
        status_filter=status,
        action_id=action_id,
        limit=limit,
        offset=offset,
    )
    return ExecutionListResponse(
        executions=[build_execution_response(e) for e in executions],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/executions/{execution_id}",
    response_model=ExecutionResponse,
    summary="Get remediation execution details",
    description="Retrieve execution state, attempt history, and audit timeline.",
)
def get_remediation_execution(
    execution_id: str,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExecutionResponse:
    """Retrieve full execution record."""
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="viewer",
    )
    execution = RemediationExecutionManager.get_execution(
        execution_id=execution_id,
        workspace_id=workspace_id,
        db=db,
    )
    return build_execution_response(execution)


@router.post(
    "/executions/{execution_id}/cancel",
    response_model=ExecutionResponse,
    summary="Cancel queued remediation execution",
    description="Cancel an execution job prior to worker lease claim. Requires 'engineer' or 'admin' role.",
)
def cancel_remediation_execution(
    execution_id: str,
    payload: Optional[ExecutionCancelRequest] = None,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExecutionResponse:
    """Cancel a queued execution job before worker claims it."""
    membership = check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    execution = RemediationExecutionManager.cancel_execution(
        execution_id=execution_id,
        workspace_id=workspace_id,
        user=current_user,
        user_role=membership.role,
        db=db,
        cancellation_reason=payload.cancellation_reason if payload else None,
    )
    return build_execution_response(execution)


@router.post(
    "/executions/{execution_id}/resolve-uncertain",
    response_model=ExecutionResponse,
    summary="Administratively resolve an uncertain execution hold",
    description="Resolves an execution held in EXECUTION_UNCERTAIN under HOLD:EXECUTION_UNCERTAIN. Requires 'engineer' or 'admin' role, mandatory non-empty justification, and records an immutable audit event.",
)
def resolve_uncertain_remediation_execution(
    execution_id: str,
    payload: ExecutionResolveUncertainRequest,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExecutionResponse:
    """
    Administratively resolve an uncertain execution (FINDING-2.1-01).
    Decisions:
    - ABORT_FAILURE: Mark failed without auto-retry; incident remains active.
    - CONFIRM_SUCCESS: Trigger independent verification; incident only marked recovered if verification passes.
    """
    membership = check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    decision_val = (
        payload.decision.value
        if hasattr(payload.decision, "value")
        else str(payload.decision)
    )
    execution = RemediationExecutionManager.resolve_uncertain_execution(
        execution_id=execution_id,
        workspace_id=workspace_id,
        user=current_user,
        user_role=membership.role,
        decision=decision_val,
        justification=payload.justification,
        evidence=payload.evidence,
        db=db,
    )
    return build_execution_response(execution)


# ============================================================================
# Verification Presentation Endpoints (Phase 4.3.6 / UI Integration)
# ============================================================================

def _build_cycle_response(cycle: VerificationCycle, db: Session) -> VerificationCycleResponse:
    """Helper to convert a VerificationCycle ORM entity into a rich presentation model."""
    execution = db.query(RemediationExecution).filter(RemediationExecution.id == cycle.execution_id).first()
    incident = None
    service = None
    if execution and execution.incident_id:
        incident = db.query(Incident).filter(Incident.id == execution.incident_id).first()
    if execution and execution.target_service_id:
        service = db.query(Service).filter(Service.id == execution.target_service_id).first()

    probes = (
        db.query(VerificationProbeResult)
        .filter(VerificationProbeResult.cycle_id == cycle.id)
        .order_by(VerificationProbeResult.probe_number.asc())
        .all()
    )

    probe_responses = [
        VerificationProbeResponse(
            id=p.id,
            cycle_id=p.cycle_id,
            execution_id=p.execution_id,
            workspace_id=p.workspace_id,
            probe_number=p.probe_number,
            probe_type=p.probe_type,
            target_url=p.target_url,
            status=p.status,
            status_code=p.status_code,
            latency_ms=p.latency_ms,
            passed=p.passed,
            probe_output=p.probe_output,
            error_message=p.error_message,
            executed_at=p.executed_at,
            created_at=p.created_at,
        )
        for p in probes
    ]

    # Authoritative cycle-level recovery status:
    # An incident is only recovered through this cycle if the cycle passed and the incident is recovered or closed.
    if cycle.status == "passed" and incident and incident.status in ("recovered", "closed"):
        recovery_status = "recovered"
    elif cycle.status == "failed":
        recovery_status = "failed"
    elif cycle.status in ("uncertain", "timed_out"):
        recovery_status = "uncertain"
    elif cycle.status in ("running", "in_progress"):
        recovery_status = "in_progress"
    else:
        recovery_status = "pending"

    return VerificationCycleResponse(
        id=cycle.id,
        execution_id=cycle.execution_id,
        workspace_id=cycle.workspace_id,
        cycle_number=cycle.cycle_number,
        status=cycle.status,
        started_at=cycle.started_at,
        deadline_at=cycle.deadline_at,
        completed_at=cycle.completed_at,
        fencing_token=cycle.fencing_token,
        verifying_worker_id=cycle.verifying_worker_id,
        probes_required=cycle.probes_required,
        probes_passed=cycle.probes_passed,
        probes_failed=cycle.probes_failed,
        cycle_metadata=cycle.cycle_metadata,
        probes=probe_responses,
        created_at=cycle.created_at,
        updated_at=cycle.updated_at,
        action_id=execution.action_id if execution else None,
        execution_status=execution.status if execution else None,
        incident_id=incident.id if incident else None,
        incident_title=incident.title if incident else None,
        service_id=service.id if service else None,
        service_name=service.name if service else None,
        recovery_status=recovery_status,
    )


@router.get(
    "/verification/cycles",
    response_model=VerificationCycleListResponse,
    summary="List verification cycles scoped to workspace",
    description="Retrieve all synthetic verification cycles and granular probe results for the workspace.",
)
def list_verification_cycles(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    status: Optional[str] = Query(None, description="Filter by cycle status"),
    execution_id: Optional[str] = Query(None, description="Filter by parent execution ID"),
    limit: int = Query(50, ge=1, le=100),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> VerificationCycleListResponse:
    """List verification cycles with probe evaluations and incident recovery context."""
    query = db.query(VerificationCycle).filter(VerificationCycle.workspace_id == workspace_id)
    if status:
        query = query.filter(VerificationCycle.status == status)
    if execution_id:
        query = query.filter(VerificationCycle.execution_id == execution_id)

    total = query.count()
    cycles = query.order_by(VerificationCycle.started_at.desc()).limit(limit).all()

    return VerificationCycleListResponse(
        cycles=[_build_cycle_response(c, db) for c in cycles],
        total=total,
    )


@router.get(
    "/executions/{execution_id}/verification",
    response_model=VerificationCycleListResponse,
    summary="Get verification records for an execution",
    description="Retrieve verification cycles and granular probe results for a specific execution job.",
)
def get_execution_verification(
    execution_id: str,
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> VerificationCycleListResponse:
    """Retrieve all verification cycles associated with a specific remediation execution."""
    execution = (
        db.query(RemediationExecution)
        .filter(
            RemediationExecution.id == execution_id,
            RemediationExecution.workspace_id == workspace_id,
        )
        .first()
    )
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution '{execution_id}' not found in workspace '{workspace_id}'.",
        )

    cycles = (
        db.query(VerificationCycle)
        .filter(
            VerificationCycle.execution_id == execution_id,
            VerificationCycle.workspace_id == workspace_id,
        )
        .order_by(VerificationCycle.cycle_number.asc())
        .all()
    )

    return VerificationCycleListResponse(
        cycles=[_build_cycle_response(c, db) for c in cycles],
        total=len(cycles),
    )
