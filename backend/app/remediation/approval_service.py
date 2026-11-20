"""Human Approval Workflow Service for Remediation Proposals.

Blueprint Section 8 & Phase 4.2:
- Binds exact action, target service, and validated parameters
- Enforces multi-tenant isolation, service active status, and RBAC
- Atomic status transitions (pending -> approved | rejected | expired | cancelled)
- Self-approval restrictions for high-risk actions
- Strictly separates authorization from execution (Phase 4.3)
"""

import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
from app.models.remediation import PolicyDecision, RemediationApproval
from app.models.service import Service
from app.models.user import User
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import ApprovalResponse, ApprovalStatus


def _is_expired(expires_at: Optional[datetime], now_utc: Optional[datetime] = None) -> bool:
    """Safely check if an expiration datetime is in the past, handling naive/aware datetimes."""
    if not expires_at:
        return False
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)
    return now_utc > expires_at


def build_approval_response(approval: RemediationApproval) -> ApprovalResponse:
    """Helper to convert a RemediationApproval ORM entity into ApprovalResponse with rich metadata."""
    action_def = ActionRegistry.get_action(approval.action_id)
    action_name = action_def.name if action_def else approval.action_id
    action_description = action_def.description if action_def else None
    verification_criteria = action_def.verification_criteria if action_def else None

    target_service_name = approval.target_service.name if approval.target_service else None
    requested_by_email = approval.requester.email if approval.requester else None
    reviewed_by_email = approval.reviewer.email if approval.reviewer else None

    # Check expiration dynamically
    is_expired = approval.approval_status == "pending" and _is_expired(approval.expires_at)

    return ApprovalResponse(
        id=approval.id,
        workspace_id=approval.workspace_id,
        incident_id=approval.incident_id,
        investigation_id=approval.investigation_id,
        policy_decision_id=approval.policy_decision_id,
        action_id=approval.action_id,
        action_name=action_name,
        action_description=action_description,
        target_service_id=approval.target_service_id,
        target_service_name=target_service_name,
        validated_parameters=approval.validated_parameters or {},
        risk_level=approval.risk_level,
        policy_version=approval.policy_version,
        approval_status=ApprovalStatus(approval.approval_status),
        requested_by=approval.requested_by,
        requested_by_email=requested_by_email,
        requested_at=approval.requested_at,
        reviewed_by=approval.reviewed_by,
        reviewed_by_email=reviewed_by_email,
        reviewed_at=approval.reviewed_at,
        rejection_reason=approval.rejection_reason,
        expires_at=approval.expires_at,
        verification_criteria=verification_criteria,
        is_expired=is_expired,
    )


class ApprovalService:
    """Service encapsulating safety invariants and lifecycle for human approvals."""

    @classmethod
    def create_approval_request(
        cls,
        *,
        db: Session,
        workspace_id: str,
        policy_decision_id: str,
        requested_by: User,
        incident_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        expires_in_hours: int = 24,
    ) -> RemediationApproval:
        """
        Create a pending approval request from an eligible policy decision.
        """
        # 1. Fetch original PolicyDecision
        decision = (
            db.query(PolicyDecision)
            .filter(PolicyDecision.id == policy_decision_id)
            .first()
        )
        if not decision:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy decision '{policy_decision_id}' not found.",
            )

        # 2. Verify workspace ownership
        if decision.workspace_id != workspace_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-workspace violation: Policy decision belongs to another workspace.",
            )

        # 3. Policy decision must have returned 'approval_required'
        if decision.decision == "rejected":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot create approval request for a rejected policy decision: {decision.decision_reason}",
            )
        if decision.decision == "allowed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Policy decision is already allowed; human approval is not required.",
            )
        if decision.decision != "approval_required":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Policy decision status '{decision.decision}' is not eligible for human approval.",
            )

        # 4. Verify target service still exists, is active, and conforms to execution policy
        if decision.target_service_id:
            service = (
                db.query(Service)
                .filter(Service.id == decision.target_service_id)
                .first()
            )
            if not service:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target service '{decision.target_service_id}' no longer exists in database.",
                )
            if service.workspace_id != workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-workspace violation: Target service belongs to another workspace.",
                )
            if not service.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' is currently inactive.",
                )

            # Correction A: Enforce service execution policy
            raw_policy = service.execution_policy
            if raw_policy is None or not str(raw_policy).strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target service '{service.name}' has null or missing execution policy. Failing closed.",
                )
            svc_policy = str(raw_policy).strip().lower()
            if svc_policy not in ("demo", "approval_required", "observe_only"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target service '{service.name}' has invalid or unsupported execution policy '{raw_policy}'. Failing closed.",
                )
            if svc_policy == "observe_only":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target service '{service.name}' execution policy is 'observe_only'. Operational remediation proposals cannot be created.",
                )
            if svc_policy == "demo" and (service.environment or "").strip().lower() != "development":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target service '{service.name}' has execution policy 'demo' which is not permitted in environment '{service.environment}'.",
                )

            # Service-specific playbook authorization check
            if not ActionRegistry.is_action_supported_for_service(decision.action_id, service, db=db):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No approved remediation playbook is configured for this service.",
                )

        # 4B. Correction B: Validate incident and investigation ownership
        if investigation_id and not incident_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot bind investigation '{investigation_id}' without a corresponding incident_id.",
            )

        if incident_id:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if not incident:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Incident '{incident_id}' not found.",
                )
            if incident.workspace_id != workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-workspace violation: Incident belongs to another workspace.",
                )
            if decision.target_service_id and incident.service_id != decision.target_service_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Incident service '{incident.service_id}' does not match target service '{decision.target_service_id}'.",
                )

        if investigation_id:
            investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
            if not investigation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation '{investigation_id}' not found.",
                )
            if investigation.workspace_id != workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-workspace violation: Investigation belongs to another workspace.",
                )
            if incident_id and investigation.incident_id != incident_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Investigation '{investigation_id}' does not belong to incident '{incident_id}'.",
                )

            # Recommendation integrity check (Phase 4.3 Section 6)
            rec = investigation.remediation_recommendation
            if rec and rec.get("playbook_id"):
                rec_pb_id = rec.get("playbook_id")
                rec_pb_ver = rec.get("playbook_version")
                rec_act = rec.get("action_template_id")
                if rec_act and decision.action_id != rec_act:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Proposed action '{decision.action_id}' does not match recommended action '{rec_act}'.",
                    )
                from app.models.playbook import Playbook, ServicePlaybookAssociation
                pb = db.query(Playbook).filter(Playbook.id == rec_pb_id, Playbook.workspace_id == workspace_id).first()
                if not pb or not pb.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Recommended playbook '{rec.get('playbook_name')}' is no longer active in workspace.",
                    )
                if rec_pb_ver is not None and pb.current_version != rec_pb_ver:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"Playbook version mismatch: Recommended version was v{rec_pb_ver}, but active playbook "
                            f"is now at version v{pb.current_version}. Stale recommendations cannot be proposed without re-investigation."
                        ),
                    )
                if decision.target_service_id:
                    assoc = (
                        db.query(ServicePlaybookAssociation)
                        .filter(
                            ServicePlaybookAssociation.workspace_id == workspace_id,
                            ServicePlaybookAssociation.service_id == decision.target_service_id,
                            ServicePlaybookAssociation.playbook_id == rec_pb_id,
                            ServicePlaybookAssociation.is_active == True,
                        )
                        .first()
                    )
                    if not assoc:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Recommended playbook is no longer actively associated with service '{decision.target_service_id}'.",
                        )

        # 5. Prevent duplicate pending approvals for same policy decision
        now_utc = datetime.now(timezone.utc)
        existing_pendings = (
            db.query(RemediationApproval)
            .filter(
                RemediationApproval.policy_decision_id == decision.id,
                RemediationApproval.approval_status == "pending",
            )
            .all()
        )
        for existing in existing_pendings:
            if not _is_expired(existing.expires_at, now_utc):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"A pending approval request (ID: {existing.id}) already exists for this proposal.",
                )

        # 6. Calculate expiration
        effective_hours = expires_in_hours or settings.APPROVAL_EXPIRY_HOURS
        expires_at = now_utc + timedelta(hours=effective_hours)

        # 7. Create approval record
        approval = RemediationApproval(
            workspace_id=workspace_id,
            incident_id=incident_id,
            investigation_id=investigation_id,
            policy_decision_id=decision.id,
            action_id=decision.action_id,
            target_service_id=decision.target_service_id,
            validated_parameters=decision.validated_parameters,
            risk_level=decision.risk_level,
            policy_version=decision.policy_version,
            requested_by=requested_by.id,
            approval_status="pending",
            requested_at=now_utc,
            expires_at=expires_at,
        )
        db.add(approval)

        # 8. Record initial incident timeline event if linked to an incident
        if approval.incident_id:
            metadata = {
                "approval_id": approval.id,
                "action_id": approval.action_id,
                "risk_level": approval.risk_level,
                "policy_decision_id": decision.id,
                "requested_by": requested_by.id,
                "expires_at": expires_at.isoformat(),
            }
            req_event = IncidentEvent(
                incident_id=approval.incident_id,
                event_type="approval",
                message=f"Remediation approval requested for action '{approval.action_id}' ({approval.risk_level} risk).",
                metadata_json=json.dumps(metadata),
                timestamp=now_utc,
            )
            db.add(req_event)

        try:
            db.commit()
            db.refresh(approval)
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A pending approval request already exists for policy decision '{decision.id}'.",
            )

        return approval

    @classmethod
    def get_approval(
        cls,
        *,
        db: Session,
        approval_id: str,
        workspace_id: str,
    ) -> RemediationApproval:
        """Fetch approval (strictly read-only, does not commit mutations)."""
        approval = (
            db.query(RemediationApproval)
            .filter(
                RemediationApproval.id == approval_id,
                RemediationApproval.workspace_id == workspace_id,
            )
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Remediation approval request '{approval_id}' not found in this workspace.",
            )

        return approval

    @classmethod
    def list_approvals(
        cls,
        *,
        db: Session,
        workspace_id: str,
        status_filter: Optional[str] = None,
        action_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[RemediationApproval]:
        """List approvals for workspace (strictly read-only)."""
        query = db.query(RemediationApproval).filter(
            RemediationApproval.workspace_id == workspace_id
        )
        if status_filter:
            query = query.filter(RemediationApproval.approval_status == status_filter.strip().lower())
        if action_id:
            query = query.filter(RemediationApproval.action_id == action_id.strip())

        approvals = (
            query.order_by(RemediationApproval.requested_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return approvals

    @classmethod
    def expire_overdue_approvals(
        cls,
        *,
        db: Session,
        workspace_id: Optional[str] = None,
    ) -> int:
        """Explicit maintenance operation to persist overdue pending approvals as expired."""
        now_utc = datetime.now(timezone.utc)
        query = db.query(RemediationApproval).filter(
            RemediationApproval.approval_status == "pending"
        )
        if workspace_id:
            query = query.filter(RemediationApproval.workspace_id == workspace_id)
        pending_list = query.all()
        expired_count = 0
        for p in pending_list:
            if _is_expired(p.expires_at, now_utc):
                p.approval_status = "expired"
                if p.incident_id:
                    exp_event = IncidentEvent(
                        incident_id=p.incident_id,
                        event_type="approval",
                        message=f"Remediation proposal '{p.action_id}' expired past deadline.",
                        metadata_json=json.dumps({
                            "approval_id": p.id,
                            "action_id": p.action_id,
                            "risk_level": p.risk_level,
                            "expired_at": now_utc.isoformat(),
                        }),
                        timestamp=now_utc,
                    )
                    db.add(exp_event)
                expired_count += 1
        if expired_count > 0:
            db.commit()
        return expired_count

    @classmethod
    def approve_request(
        cls,
        *,
        db: Session,
        approval_id: str,
        workspace_id: str,
        reviewer: User,
        user_role: str,
        notes: Optional[str] = None,
    ) -> RemediationApproval:
        """
        Approve a pending remediation request.
        Does NOT execute the action (Phase 4.3).
        """
        now_utc = datetime.now(timezone.utc)

        # 1. Atomic query with row lock where supported
        approval = (
            db.query(RemediationApproval)
            .filter(
                RemediationApproval.id == approval_id,
                RemediationApproval.workspace_id == workspace_id,
            )
            .with_for_update()
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Approval request '{approval_id}' not found in this workspace.",
            )

        # 2. State validation
        if approval.approval_status == "approved":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Approval request has already been approved.",
            )
        if approval.approval_status == "rejected":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot approve a request that has already been rejected.",
            )
        if approval.approval_status == "cancelled":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot approve a request that has been cancelled.",
            )
        if approval.approval_status == "expired" or _is_expired(approval.expires_at, now_utc):
            approval.approval_status = "expired"
            if approval.incident_id:
                exp_event = IncidentEvent(
                    incident_id=approval.incident_id,
                    event_type="approval",
                    message=f"Remediation proposal '{approval.action_id}' expired past deadline.",
                    metadata_json=json.dumps({
                        "approval_id": approval.id,
                        "action_id": approval.action_id,
                        "risk_level": approval.risk_level,
                        "expired_at": now_utc.isoformat(),
                    }),
                    timestamp=now_utc,
                )
                db.add(exp_event)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Approval request has expired and can no longer be approved.",
            )
        if approval.approval_status != "pending":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot approve request in '{approval.approval_status}' state.",
            )

        # 3. Two-person integrity rule for high-risk actions
        if approval.risk_level == "high" and approval.requested_by == reviewer.id:
            if not settings.ALLOW_SELF_APPROVAL:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Self-approval is forbidden for high-risk actions. A separate reviewer is required per two-person integrity policy.",
                )

        # 4. Revalidate target service existence, workspace ownership, and active status
        if approval.target_service_id:
            service = (
                db.query(Service)
                .filter(Service.id == approval.target_service_id)
                .first()
            )
            if not service:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Precondition failed: Target service no longer exists in database; cannot finalize approval.",
                )
            if service.workspace_id != workspace_id or service.workspace_id != approval.workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' does not belong to authorized workspace '{workspace_id}'; cannot finalize approval.",
                )
            if not service.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' is inactive; cannot finalize approval.",
                )

            # Revalidate execution policy at approval time
            raw_policy = service.execution_policy
            if raw_policy is None or not str(raw_policy).strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' has null or missing execution policy. Failing closed.",
                )
            svc_policy = str(raw_policy).strip().lower()
            if svc_policy not in ("demo", "approval_required", "observe_only"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' has invalid or unsupported execution policy '{raw_policy}'. Failing closed.",
                )
            if svc_policy == "observe_only":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' execution policy is 'observe_only'; operational remediation cannot be approved.",
                )
            if svc_policy == "demo" and (service.environment or "").strip().lower() != "development":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Precondition failed: Target service '{service.name}' execution policy is 'demo' in non-development environment '{service.environment}'.",
                )

        # 5. Transition state to 'approved'
        approval.approval_status = "approved"
        approval.reviewed_by = reviewer.id
        approval.reviewed_at = now_utc

        # 6. Record incident timeline event if linked to an incident
        if approval.incident_id:
            app_event = IncidentEvent(
                incident_id=approval.incident_id,
                event_type="approval",
                message=f"Remediation proposal '{approval.action_id}' was approved by {reviewer.email or reviewer.id}.",
                metadata_json=json.dumps({
                    "approval_id": approval.id,
                    "action_id": approval.action_id,
                    "risk_level": approval.risk_level,
                    "reviewed_by": reviewer.id,
                    "reviewed_at": now_utc.isoformat(),
                    "notes": notes,
                }),
                timestamp=now_utc,
            )
            db.add(app_event)

        db.commit()
        db.refresh(approval)

        return approval

    @classmethod
    def reject_request(
        cls,
        *,
        db: Session,
        approval_id: str,
        workspace_id: str,
        reviewer: User,
        user_role: str,
        rejection_reason: str,
    ) -> RemediationApproval:
        """
        Reject a pending remediation request with mandatory reason.
        """
        now_utc = datetime.now(timezone.utc)
        clean_reason = (rejection_reason or "").strip()
        if len(clean_reason) < 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A valid rejection reason with at least 3 characters is mandatory.",
            )

        # 1. Atomic query with row lock
        approval = (
            db.query(RemediationApproval)
            .filter(
                RemediationApproval.id == approval_id,
                RemediationApproval.workspace_id == workspace_id,
            )
            .with_for_update()
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Approval request '{approval_id}' not found in this workspace.",
            )

        # 2. State validation
        if approval.approval_status == "approved":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reject a request that has already been approved.",
            )
        if approval.approval_status == "rejected":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Approval request has already been rejected.",
            )
        if approval.approval_status == "cancelled":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reject a request that has been cancelled.",
            )
        if approval.approval_status == "expired" or _is_expired(approval.expires_at, now_utc):
            approval.approval_status = "expired"
            if approval.incident_id:
                exp_event = IncidentEvent(
                    incident_id=approval.incident_id,
                    event_type="approval",
                    message=f"Remediation proposal '{approval.action_id}' expired past deadline.",
                    metadata_json=json.dumps({
                        "approval_id": approval.id,
                        "action_id": approval.action_id,
                        "risk_level": approval.risk_level,
                        "expired_at": now_utc.isoformat(),
                    }),
                    timestamp=now_utc,
                )
                db.add(exp_event)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reject an expired request.",
            )

        # 3. Transition state to 'rejected'
        approval.approval_status = "rejected"
        approval.reviewed_by = reviewer.id
        approval.reviewed_at = now_utc
        approval.rejection_reason = clean_reason

        # 4. Record incident timeline event if linked to an incident
        if approval.incident_id:
            rej_event = IncidentEvent(
                incident_id=approval.incident_id,
                event_type="approval",
                message=f"Remediation proposal '{approval.action_id}' was rejected: {clean_reason}",
                metadata_json=json.dumps({
                    "approval_id": approval.id,
                    "action_id": approval.action_id,
                    "risk_level": approval.risk_level,
                    "reviewed_by": reviewer.id,
                    "reviewed_at": now_utc.isoformat(),
                    "rejection_reason": clean_reason,
                }),
                timestamp=now_utc,
            )
            db.add(rej_event)

        db.commit()
        db.refresh(approval)

        return approval

    @classmethod
    def cancel_request(
        cls,
        *,
        db: Session,
        approval_id: str,
        workspace_id: str,
        user: User,
        user_role: str,
        cancellation_reason: Optional[str] = None,
    ) -> RemediationApproval:
        """
        Cancel a pending approval request. Permitted for original requester or Admin.
        """
        now_utc = datetime.now(timezone.utc)

        approval = (
            db.query(RemediationApproval)
            .filter(
                RemediationApproval.id == approval_id,
                RemediationApproval.workspace_id == workspace_id,
            )
            .with_for_update()
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Approval request '{approval_id}' not found in this workspace.",
            )

        # Only pending requests can be cancelled
        if approval.approval_status != "pending":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel approval request in '{approval.approval_status}' state.",
            )

        # Authorization: Requester or Admin
        if user_role.lower() != "admin" and approval.requested_by != user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied: Only the original requester or a workspace Admin can cancel this request.",
            )

        approval.approval_status = "cancelled"
        approval.reviewed_by = user.id
        approval.reviewed_at = now_utc
        approval.rejection_reason = cancellation_reason or "Cancelled by user"

        # Record incident timeline event if linked to an incident
        if approval.incident_id:
            cancel_event = IncidentEvent(
                incident_id=approval.incident_id,
                event_type="approval",
                message=f"Remediation proposal '{approval.action_id}' was cancelled by {user.email or user.id}.",
                metadata_json=json.dumps({
                    "approval_id": approval.id,
                    "action_id": approval.action_id,
                    "risk_level": approval.risk_level,
                    "cancelled_by": user.id,
                    "cancelled_at": now_utc.isoformat(),
                    "cancellation_reason": approval.rejection_reason,
                }),
                timestamp=now_utc,
            )
            db.add(cancel_event)

        db.commit()
        db.refresh(approval)

        return approval
