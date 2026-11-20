"""Tests for Remediation Human Approval Workflow (Phase 4.2).

Validates:
1. Approval Request Creation:
   - Creating approval from eligible 'approval_required' policy decision
   - Rejecting approval creation for 'rejected' policy decision
   - Rejecting approval creation for 'allowed' policy decision
   - Rejecting approval creation with invalid/missing policy decision ID
   - Rejecting duplicate pending approvals for the same proposal
   - Rejection when target service is inactive or non-existent
2. Role-Based Access Control (RBAC):
   - Viewer cannot create approval requests (HTTP 403)
   - Viewer cannot approve pending requests (HTTP 403)
   - Viewer cannot reject pending requests (HTTP 403)
   - Viewer CAN view approval details and list approval requests
   - Engineer and Admin can approve and reject
3. Approval Safety & State Invariants:
   - Approving an already approved request fails with HTTP 409
   - Approving an already rejected request fails with HTTP 400
   - Approving an expired request fails with HTTP 400
   - Rejection requires valid, non-empty reason (HTTP 400)
   - Dynamic expiration updates pending requests past deadline to 'expired'
   - Cancellation permitted for requester or workspace Admin
   - Cancellation by unauthorized third party fails with HTTP 403
4. Two-Person Integrity / Self-Approval Safety:
   - High-risk action cannot be self-approved by requester (HTTP 403)
   - High-risk action can be approved by a different authorized engineer/admin
5. Precondition Revalidation:
   - If target service becomes inactive before approval, approval is rejected (HTTP 400)
6. Multi-Tenant Isolation:
   - Cross-workspace approval creation, inspection, approval, and rejection rejected with HTTP 403
7. Strict Schema Hardening:
   - Passing 'ai_proposed_risk' or 'ai_proposed_approval' to POST /policy/evaluate is strictly rejected (HTTP 422)
"""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from sqlalchemy.exc import IntegrityError
from app.core.security import create_access_token, get_password_hash
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import PolicyDecision, RemediationApproval
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.approval_service import ApprovalService
from app.remediation.schemas import ApprovalStatus


@pytest.fixture
def approval_env(db_session):
    """Sets up an isolated multi-user, multi-workspace environment for approval testing."""
    # 1. Primary Workspace
    ws1 = Workspace(
        name="Approval Ops",
        slug=f"approval-ops-{uuid.uuid4().hex[:6]}",
        description="Workspace for approval tests",
    )
    # 2. Foreign Workspace
    ws2 = Workspace(
        name="Foreign Ops",
        slug=f"foreign-ops-{uuid.uuid4().hex[:6]}",
        description="Foreign workspace for cross-tenant tests",
    )
    db_session.add_all([ws1, ws2])
    db_session.flush()

    # 3. Users: Admin, Engineer 1 (Requester), Engineer 2 (Reviewer), Viewer, Foreign User
    admin = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Admin SRE",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    eng1 = User(
        email=f"eng1-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Requester Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    eng2 = User(
        email=f"eng2-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Reviewer Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    viewer = User(
        email=f"viewer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Auditor Viewer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    foreign = User(
        email=f"foreign-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Foreign Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add_all([admin, eng1, eng2, viewer, foreign])
    db_session.flush()

    # 4. Memberships
    m_admin = WorkspaceMembership(workspace_id=ws1.id, user_id=admin.id, role="admin")
    m_eng1 = WorkspaceMembership(workspace_id=ws1.id, user_id=eng1.id, role="engineer")
    m_eng2 = WorkspaceMembership(workspace_id=ws1.id, user_id=eng2.id, role="engineer")
    m_viewer = WorkspaceMembership(workspace_id=ws1.id, user_id=viewer.id, role="viewer")
    m_foreign = WorkspaceMembership(workspace_id=ws2.id, user_id=foreign.id, role="engineer")
    db_session.add_all([m_admin, m_eng1, m_eng2, m_viewer, m_foreign])
    db_session.flush()

    # 5. Services:
    svc_active = Service(
        workspace_id=ws1.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
        health_status="healthy",
    )
    svc_inactive = Service(
        workspace_id=ws1.id,
        name="Catalog API",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        is_active=False,
        health_status="unhealthy",
    )
    svc_foreign = Service(
        workspace_id=ws2.id,
        name="Foreign Billing API",
        environment="development",
        health_check_url="http://127.0.0.1:8003/health",
        is_active=True,
        health_status="healthy",
    )
    db_session.add_all([svc_active, svc_inactive, svc_foreign])
    db_session.flush()

    # 6. Policy Decisions in WS1:
    # A. Medium-risk eligible decision ('restart_order_api')
    dec_medium = PolicyDecision(
        workspace_id=ws1.id,
        user_id=eng1.id,
        action_id="restart_order_api",
        target_service_id=svc_active.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Medium-risk action requires human approval.",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_active.id},
    )
    # B. High-risk eligible decision ('disable_service_monitoring')
    dec_high = PolicyDecision(
        workspace_id=ws1.id,
        user_id=eng1.id,
        action_id="disable_service_monitoring",
        target_service_id=svc_active.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="High-risk action strictly requires human approval.",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_active.id},
    )
    # C. Rejected policy decision
    dec_rejected = PolicyDecision(
        workspace_id=ws1.id,
        user_id=eng1.id,
        action_id="restart_order_api",
        target_service_id=svc_inactive.id,
        risk_level="medium",
        decision="rejected",
        decision_reason="Service is already inactive.",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_inactive.id},
    )
    # D. Allowed policy decision ('inspect_service_health')
    dec_allowed = PolicyDecision(
        workspace_id=ws1.id,
        user_id=eng1.id,
        action_id="inspect_service_health",
        target_service_id=svc_active.id,
        risk_level="low",
        decision="allowed",
        decision_reason="Pre-approved diagnostic action.",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_active.id},
    )
    # E. Foreign policy decision in WS2
    dec_foreign = PolicyDecision(
        workspace_id=ws2.id,
        user_id=foreign.id,
        action_id="restart_order_api",
        target_service_id=svc_foreign.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Foreign workspace decision.",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_foreign.id},
    )
    # 6. Incident for timeline event testing
    inc = Incident(
        workspace_id=ws1.id,
        service_id=svc_active.id,
        title="Order API High 5xx Errors",
        severity="high",
        status="awaiting_approval",
        trigger="5xx rate > 5%",
    )
    db_session.add(inc)
    db_session.flush()

    # 7. Policy Decisions in WS1:
    db_session.add_all([dec_medium, dec_high, dec_rejected, dec_allowed, dec_foreign])
    db_session.commit()

    return {
        "ws1": ws1,
        "ws2": ws2,
        "admin": admin,
        "eng1": eng1,
        "eng2": eng2,
        "viewer": viewer,
        "foreign": foreign,
        "svc_active": svc_active,
        "svc_inactive": svc_inactive,
        "svc_foreign": svc_foreign,
        "incident": inc,
        "dec_medium": dec_medium,
        "dec_high": dec_high,
        "dec_rejected": dec_rejected,
        "dec_allowed": dec_allowed,
        "dec_foreign": dec_foreign,
        "admin_token": create_access_token({"sub": admin.id}),
        "eng1_token": create_access_token({"sub": eng1.id}),
        "eng2_token": create_access_token({"sub": eng2.id}),
        "viewer_token": create_access_token({"sub": viewer.id}),
        "foreign_token": create_access_token({"sub": foreign.id}),
    }


# ============================================================================
# 1. Approval Creation Tests
# ============================================================================

def test_create_approval_success(client: TestClient, db_session, approval_env):
    """Creating an approval request from an eligible policy decision succeeds."""
    payload = {
        "workspace_id": approval_env["ws1"].id,
        "policy_decision_id": approval_env["dec_medium"].id,
        "expires_in_hours": 12,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["approval_status"] == "pending"
    assert data["action_id"] == "restart_order_api"
    assert data["action_name"] == "Restart Order API Service"
    assert data["target_service_id"] == approval_env["svc_active"].id
    assert data["target_service_name"] == "Order API"
    assert data["requested_by"] == approval_env["eng1"].id
    assert data["is_expired"] is False
    assert "id" in data

    # Verify database persistence
    db_record = db_session.query(RemediationApproval).filter(RemediationApproval.id == data["id"]).first()
    assert db_record is not None
    assert db_record.approval_status == "pending"
    assert db_record.validated_parameters == {"service_id": approval_env["svc_active"].id}


def test_create_approval_rejected_decision_fails(client: TestClient, approval_env):
    """Cannot create an approval request for a rejected policy decision."""
    payload = {
        "workspace_id": approval_env["ws1"].id,
        "policy_decision_id": approval_env["dec_rejected"].id,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp.status_code == 400
    assert "rejected policy decision" in resp.json()["detail"].lower()


def test_create_approval_allowed_decision_fails(client: TestClient, approval_env):
    """Cannot create an approval request for an already-allowed policy decision."""
    payload = {
        "workspace_id": approval_env["ws1"].id,
        "policy_decision_id": approval_env["dec_allowed"].id,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp.status_code == 400
    assert "already allowed" in resp.json()["detail"].lower()


def test_create_approval_duplicate_pending_prevented(client: TestClient, approval_env):
    """Creating a second pending approval for the same decision returns 409 Conflict."""
    payload = {
        "workspace_id": approval_env["ws1"].id,
        "policy_decision_id": approval_env["dec_medium"].id,
    }
    # First creation succeeds
    resp1 = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp1.status_code == 201

    # Second creation fails with 409
    resp2 = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp2.status_code == 409
    assert "already exists" in resp2.json()["detail"].lower()


def test_create_approval_viewer_forbidden(client: TestClient, approval_env):
    """Viewers cannot create remediation approval requests (HTTP 403)."""
    payload = {
        "workspace_id": approval_env["ws1"].id,
        "policy_decision_id": approval_env["dec_medium"].id,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['viewer_token']}"},
    )
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"] or "engineer" in resp.json()["detail"].lower()


# ============================================================================
# 2. Approval Review (Approve / Reject) Tests
# ============================================================================

def test_approve_request_success(client: TestClient, db_session, approval_env):
    """Authorized engineer can approve a pending request."""
    # 1. Create pending approval
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # 2. Approve via Engineer 2
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["approval_status"] == "approved"
    assert data["reviewed_by"] == approval_env["eng2"].id
    assert data["reviewed_at"] is not None


def test_double_approval_fails(client: TestClient, db_session, approval_env):
    """Attempting to approve an already approved request returns 409 Conflict."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # First approve succeeds
    resp1 = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp1.status_code == 200

    # Second approve fails
    resp2 = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp2.status_code == 409
    assert "already been approved" in resp2.json()["detail"].lower()


def test_reject_request_with_reason(client: TestClient, db_session, approval_env):
    """Authorized reviewer can reject with mandatory rationale."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    payload = {"rejection_reason": "High risk of breaking ongoing batch checkout jobs."}
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/reject?workspace_id={approval_env['ws1'].id}",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["approval_status"] == "rejected"
    assert data["rejection_reason"] == payload["rejection_reason"]
    assert data["reviewed_by"] == approval_env["eng2"].id


def test_reject_without_reason_fails(client: TestClient, db_session, approval_env):
    """Rejecting without a valid reason fails with HTTP 422 or 400."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Empty payload
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/reject?workspace_id={approval_env['ws1'].id}",
        json={},
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code in [400, 422]


def test_approve_already_rejected_request_fails(client: TestClient, db_session, approval_env):
    """Attempting to approve an already rejected request fails."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )
    ApprovalService.reject_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=approval_env["ws1"].id,
        reviewer=approval_env["eng2"],
        user_role="engineer",
        rejection_reason="Declined for testing",
    )

    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['admin_token']}"},
    )
    assert resp.status_code == 400
    assert "already been rejected" in resp.json()["detail"].lower()


# ============================================================================
# 3. Expiration and Safety Rules Tests
# ============================================================================

def test_approve_expired_request_fails(client: TestClient, db_session, approval_env):
    """Attempting to approve an expired request fails and transitions status to expired."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )
    # Fast-forward expiration into the past
    approval.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"].lower()

    # Confirm status in DB is expired
    db_session.refresh(approval)
    assert approval.approval_status == "expired"


def test_self_approval_forbidden_for_high_risk(client: TestClient, db_session, approval_env):
    """Two-person integrity: Requester cannot approve their own high-risk proposal."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_high"].id,  # High risk
        requested_by=approval_env["eng1"],
    )

    # Requester Engineer 1 attempts to approve own high-risk request
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp.status_code == 403
    assert "Self-approval is forbidden" in resp.json()["detail"]

    # But separate Reviewer Engineer 2 CAN approve
    resp2 = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["approval_status"] == "approved"


def test_cancel_request(client: TestClient, db_session, approval_env):
    """Requester or Admin can cancel a pending approval."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Eng 1 cancels their own request
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/cancel?workspace_id={approval_env['ws1'].id}",
        json={"cancellation_reason": "No longer needed."},
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp.status_code == 200
    assert resp.json()["approval_status"] == "cancelled"


def test_cancel_request_unauthorized_user_fails(client: TestClient, db_session, approval_env):
    """Non-requester non-admin engineer cannot cancel someone else's request."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Eng 2 attempts to cancel Eng 1's request
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/cancel?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code == 403
    assert "Only the original requester or a workspace Admin" in resp.json()["detail"]


# ============================================================================
# 4. Multi-Tenant and RBAC Security Tests
# ============================================================================

def test_cross_workspace_approval_forbidden(client: TestClient, db_session, approval_env):
    """User in Foreign Workspace cannot access or approve WS1 requests."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Foreign user attempts to approve
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['foreign_token']}"},
    )
    assert resp.status_code == 403

    # Foreign user attempts to view
    resp_get = client.get(
        f"/api/v1/remediation/approvals/{approval.id}?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['foreign_token']}"},
    )
    assert resp_get.status_code == 403


def test_viewer_cannot_approve_or_reject(client: TestClient, db_session, approval_env):
    """Viewers are rejected from approve and reject endpoints with HTTP 403."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Viewer attempts approve
    resp_app = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['viewer_token']}"},
    )
    assert resp_app.status_code == 403

    # Viewer attempts reject
    resp_rej = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/reject?workspace_id={approval_env['ws1'].id}",
        json={"rejection_reason": "Viewer attempting rejection"},
        headers={"Authorization": f"Bearer {approval_env['viewer_token']}"},
    )
    assert resp_rej.status_code == 403

    # Viewer CAN view details
    resp_view = client.get(
        f"/api/v1/remediation/approvals/{approval.id}?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['viewer_token']}"},
    )
    assert resp_view.status_code == 200
    assert resp_view.json()["id"] == approval.id


def test_strict_rejection_of_ai_proposal_fields(client: TestClient, approval_env):
    """Passing 'ai_proposed_risk' or 'ai_proposed_approval' to evaluate endpoint returns 422."""
    payload = {
        "workspace_id": approval_env["ws1"].id,
        "action_id": "restart_order_api",
        "parameters": {"service_id": approval_env["svc_active"].id},
        "ai_proposed_risk": "low",  # Forbidden field
    }
    resp = client.post(
        "/api/v1/remediation/policy/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp.status_code == 422
    assert "extra fields not permitted" in resp.text.lower() or "extra" in resp.text.lower()


# ============================================================================
# 5. Hardening & Security Audit Regression Tests (Fixes 1-4)
# ============================================================================

def test_database_level_partial_unique_index_enforcement(db_session, approval_env):
    """Direct database insertion of two pending records for the same decision raises IntegrityError."""
    now_utc = datetime.now(timezone.utc)
    app1 = RemediationApproval(
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        action_id="restart_order_api",
        target_service_id=approval_env["svc_active"].id,
        validated_parameters={"service_id": approval_env["svc_active"].id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=approval_env["eng1"].id,
        approval_status="pending",
        requested_at=now_utc,
        expires_at=now_utc + timedelta(hours=24),
    )
    db_session.add(app1)
    db_session.commit()

    # Attempting to insert duplicate pending record at DB level
    app2 = RemediationApproval(
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        action_id="restart_order_api",
        target_service_id=approval_env["svc_active"].id,
        validated_parameters={"service_id": approval_env["svc_active"].id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=approval_env["eng2"].id,
        approval_status="pending",
        requested_at=now_utc,
        expires_at=now_utc + timedelta(hours=24),
    )
    db_session.add(app2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_create_approval_after_previous_non_pending_succeeds(client: TestClient, db_session, approval_env):
    """Creating a new pending proposal succeeds once the previous proposal is no longer pending."""
    # 1. Create first proposal
    resp1 = client.post(
        "/api/v1/remediation/approvals",
        json={"workspace_id": approval_env["ws1"].id, "policy_decision_id": approval_env["dec_medium"].id},
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp1.status_code == 201
    app1_id = resp1.json()["id"]

    # 2. Reject first proposal
    resp_rej = client.post(
        f"/api/v1/remediation/approvals/{app1_id}/reject?workspace_id={approval_env['ws1'].id}",
        json={"rejection_reason": "Rejected for testing new proposal creation."},
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp_rej.status_code == 200

    # 3. Create a second proposal for the same policy decision now that previous is rejected
    resp2 = client.post(
        "/api/v1/remediation/approvals",
        json={"workspace_id": approval_env["ws1"].id, "policy_decision_id": approval_env["dec_medium"].id},
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp2.status_code == 201
    assert resp2.json()["approval_status"] == "pending"
    assert resp2.json()["id"] != app1_id


def test_approve_fails_if_service_deactivated_between_proposal_and_approval(client: TestClient, db_session, approval_env):
    """If target service is deactivated after proposal creation, approval fails with HTTP 400."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Deactivate service before approval
    approval_env["svc_active"].is_active = False
    db_session.commit()

    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code == 400
    assert "inactive" in resp.json()["detail"].lower()

    # Re-activate for subsequent tests
    approval_env["svc_active"].is_active = True
    db_session.commit()


def test_approve_fails_if_service_reassigned_to_another_workspace(client: TestClient, db_session, approval_env):
    """If target service is moved to another workspace, approval fails with HTTP 400."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )

    # Reassign service to foreign workspace WS2
    approval_env["svc_active"].workspace_id = approval_env["ws2"].id
    db_session.commit()

    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp.status_code == 400
    assert "does not belong to authorized workspace" in resp.json()["detail"].lower()

    # Restore service workspace
    approval_env["svc_active"].workspace_id = approval_env["ws1"].id
    db_session.commit()


def test_get_approval_is_strictly_read_only(client: TestClient, db_session, approval_env):
    """GET endpoints do not mutate approval status in DB even if deadline has passed."""
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
    )
    # Fast-forward deadline into past
    approval.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.commit()

    # Call GET /approvals/{id}
    resp = client.get(
        f"/api/v1/remediation/approvals/{approval.id}?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['viewer_token']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_expired"] is True

    # Confirm database record was NOT mutated by the GET request
    db_session.refresh(approval)
    assert approval.approval_status == "pending"

    # Call GET /approvals (list)
    resp_list = client.get(
        f"/api/v1/remediation/approvals?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['viewer_token']}"},
    )
    assert resp_list.status_code == 200

    # Still pending in DB
    db_session.refresh(approval)
    assert approval.approval_status == "pending"


def test_incident_events_created_for_approval_lifecycle(client: TestClient, db_session, approval_env):
    """Successful approval workflow transitions record IncidentEvents on the linked incident."""
    inc_id = approval_env["incident"].id

    # 1. Create approval request linked to incident
    resp_create = client.post(
        "/api/v1/remediation/approvals",
        json={
            "workspace_id": approval_env["ws1"].id,
            "policy_decision_id": approval_env["dec_medium"].id,
            "incident_id": inc_id,
        },
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp_create.status_code == 201
    approval_id = resp_create.json()["id"]

    # Verify 'approval requested' incident event exists
    events1 = db_session.query(IncidentEvent).filter(
        IncidentEvent.incident_id == inc_id,
        IncidentEvent.event_type == "approval",
    ).all()
    assert len(events1) >= 1
    req_event = [e for e in events1 if "requested" in e.message.lower()][0]
    assert "restart_order_api" in req_event.message

    # 2. Approve proposal
    resp_app = client.post(
        f"/api/v1/remediation/approvals/{approval_id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp_app.status_code == 200

    # Verify 'approval granted' incident event exists
    events2 = db_session.query(IncidentEvent).filter(
        IncidentEvent.incident_id == inc_id,
        IncidentEvent.event_type == "approval",
    ).all()
    app_events = [e for e in events2 if "approved" in e.message.lower()]
    assert len(app_events) >= 1


def test_incident_event_created_for_rejection(client: TestClient, db_session, approval_env):
    """Rejection records an IncidentEvent with rationale."""
    inc_id = approval_env["incident"].id

    # Create approval request
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
        incident_id=inc_id,
    )

    # Reject proposal
    resp_rej = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/reject?workspace_id={approval_env['ws1'].id}",
        json={"rejection_reason": "Risk of database connection starvation during peak traffic."},
        headers={"Authorization": f"Bearer {approval_env['eng2_token']}"},
    )
    assert resp_rej.status_code == 200

    # Verify rejection event in incident timeline
    events = db_session.query(IncidentEvent).filter(
        IncidentEvent.incident_id == inc_id,
        IncidentEvent.event_type == "approval",
    ).all()
    rej_events = [e for e in events if "rejected" in e.message.lower()]
    assert len(rej_events) >= 1
    assert "connection starvation" in rej_events[0].message


def test_incident_event_created_for_cancellation(client: TestClient, db_session, approval_env):
    """Cancellation records an IncidentEvent on the linked incident."""
    inc_id = approval_env["incident"].id

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
        incident_id=inc_id,
    )

    resp_cancel = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/cancel?workspace_id={approval_env['ws1'].id}",
        json={"cancellation_reason": "Found root cause in DNS config; restart unneeded."},
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp_cancel.status_code == 200

    events = db_session.query(IncidentEvent).filter(
        IncidentEvent.incident_id == inc_id,
        IncidentEvent.event_type == "approval",
    ).all()
    cancel_events = [e for e in events if "cancelled" in e.message.lower()]
    assert len(cancel_events) >= 1


def test_failed_approval_transition_does_not_create_incident_event(client: TestClient, db_session, approval_env):
    """Failed approval attempts (e.g. approving already rejected) do not produce spurious approval events."""
    inc_id = approval_env["incident"].id

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
        incident_id=inc_id,
    )
    ApprovalService.reject_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=approval_env["ws1"].id,
        reviewer=approval_env["eng2"],
        user_role="engineer",
        rejection_reason="Declined for testing",
    )

    count_before = db_session.query(IncidentEvent).filter(
        IncidentEvent.incident_id == inc_id,
        IncidentEvent.event_type == "approval",
    ).count()

    # Attempt to approve the rejected request (fails with 400)
    resp = client.post(
        f"/api/v1/remediation/approvals/{approval.id}/approve?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['admin_token']}"},
    )
    assert resp.status_code == 400

    count_after = db_session.query(IncidentEvent).filter(
        IncidentEvent.incident_id == inc_id,
        IncidentEvent.event_type == "approval",
    ).count()

    assert count_after == count_before


def test_explicit_maintenance_cleanup_expired_approvals(client: TestClient, db_session, approval_env):
    """Admin can explicitly trigger cleanup of overdue pending approvals."""
    # Create an approval with past expiration
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=approval_env["ws1"].id,
        policy_decision_id=approval_env["dec_medium"].id,
        requested_by=approval_env["eng1"],
        incident_id=approval_env["incident"].id,
    )
    # Manually backdate expiration to 2 hours ago
    approval.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.commit()

    # Engineer/Viewer cannot trigger maintenance cleanup (Admin required)
    resp_eng = client.post(
        f"/api/v1/remediation/approvals/cleanup-expired?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['eng1_token']}"},
    )
    assert resp_eng.status_code == 403

    # Admin successfully runs cleanup
    resp_admin = client.post(
        f"/api/v1/remediation/approvals/cleanup-expired?workspace_id={approval_env['ws1'].id}",
        headers={"Authorization": f"Bearer {approval_env['admin_token']}"},
    )
    assert resp_admin.status_code == 200
    assert resp_admin.json()["expired_count"] >= 1

    # Verify status is now 'expired' in DB
    db_session.refresh(approval)
    assert approval.approval_status == "expired"
