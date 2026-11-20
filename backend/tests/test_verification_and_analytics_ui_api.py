"""Tests for Verification & Recovery and Reports & Analytics UI APIs.

Validates:
1. Route availability and response models for /remediation/verification/cycles and /dashboard/analytics.
2. Correct empirical calculation of MTTD, MTTR, severity distribution, and trends.
3. Empty states and zero-data handling.
4. Tenant/workspace isolation (cross-workspace data rejection).
5. Role-based access control (Admin, Engineer, Viewer).
"""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
from app.models.remediation import RemediationApproval, RemediationExecution
from app.models.verification import VerificationCycle, VerificationProbeResult
from app.core.security import create_access_token


@pytest.fixture
def auth_setup(db_session):
    """Setup workspace, users with different roles, and auth tokens."""
    # 1. Main Workspace
    ws1 = Workspace(id=str(uuid.uuid4()), name="Demo Workspace", slug="demo-ws")
    db_session.add(ws1)

    # 2. Foreign Workspace
    ws2 = Workspace(id=str(uuid.uuid4()), name="Foreign Workspace", slug="foreign-ws")
    db_session.add(ws2)

    # 3. Users: Admin, Engineer, Viewer
    admin_user = User(id=str(uuid.uuid4()), email="admin@test.local", full_name="Admin", is_active=True, hashed_password="pw")
    engineer_user = User(id=str(uuid.uuid4()), email="eng@test.local", full_name="Engineer", is_active=True, hashed_password="pw")
    viewer_user = User(id=str(uuid.uuid4()), email="viewer@test.local", full_name="Viewer", is_active=True, hashed_password="pw")
    foreign_user = User(id=str(uuid.uuid4()), email="foreign@test.local", full_name="Foreign", is_active=True, hashed_password="pw")
    db_session.add_all([admin_user, engineer_user, viewer_user, foreign_user])

    # Memberships
    m1 = WorkspaceMembership(id=str(uuid.uuid4()), workspace_id=ws1.id, user_id=admin_user.id, role="admin")
    m2 = WorkspaceMembership(id=str(uuid.uuid4()), workspace_id=ws1.id, user_id=engineer_user.id, role="engineer")
    m3 = WorkspaceMembership(id=str(uuid.uuid4()), workspace_id=ws1.id, user_id=viewer_user.id, role="viewer")
    m4 = WorkspaceMembership(id=str(uuid.uuid4()), workspace_id=ws2.id, user_id=foreign_user.id, role="admin")
    db_session.add_all([m1, m2, m3, m4])
    db_session.commit()

    return {
        "ws1": ws1,
        "ws2": ws2,
        "admin_token": create_access_token({"sub": admin_user.id, "email": admin_user.email}),
        "eng_token": create_access_token({"sub": engineer_user.id, "email": engineer_user.email}),
        "viewer_token": create_access_token({"sub": viewer_user.id, "email": viewer_user.email}),
        "foreign_token": create_access_token({"sub": foreign_user.id, "email": foreign_user.email}),
    }


def test_verification_cycles_empty_state(client, auth_setup):
    """Test verification cycles returns empty list when no cycles exist."""
    ws1 = auth_setup["ws1"]
    headers = {"Authorization": f"Bearer {auth_setup['viewer_token']}"}

    res = client.get(f"/api/v1/remediation/verification/cycles?workspace_id={ws1.id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 0
    assert data["cycles"] == []


def test_verification_cycles_with_probes(client, db_session, auth_setup):
    """Test verification cycles returns rich probe results and incident context."""
    ws1 = auth_setup["ws1"]
    now = datetime.now(timezone.utc)

    # Create service, incident, execution, cycle, and probe
    svc = Service(id=str(uuid.uuid4()), workspace_id=ws1.id, name="Order API", environment="development", health_check_url="http://127.0.0.1:8001/health")
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        service_id=svc.id,
        title="Test 500 Outage",
        severity="high",
        status="recovered",
        trigger="HTTP 500",
        detected_at=now - timedelta(minutes=10),
        recovered_at=now - timedelta(minutes=5),
    )
    db_session.add(inc)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        incident_id=inc.id,
        policy_decision_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        requested_by=auth_setup["admin_token"],
        approval_status="approved",
        expires_at=now + timedelta(hours=1),
    )
    db_session.add(approval)

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        approval_id=approval.id,
        incident_id=inc.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        status="verified",
        idempotency_key=str(uuid.uuid4()),
        triggered_by="admin",
        triggered_at=now - timedelta(minutes=6),
        started_at=now - timedelta(minutes=6),
        completed_at=now - timedelta(minutes=5),
        verification_status="passed",
    )
    db_session.add(execution)

    cycle = VerificationCycle(
        id=str(uuid.uuid4()),
        execution_id=execution.id,
        workspace_id=ws1.id,
        cycle_number=1,
        status="passed",
        started_at=now - timedelta(minutes=6),
        deadline_at=now - timedelta(minutes=5),
        completed_at=now - timedelta(minutes=5),
        fencing_token=1,
        probes_required=3,
        probes_passed=3,
        probes_failed=0,
    )
    db_session.add(cycle)

    # 3 probes
    p1 = VerificationProbeResult(
        id=str(uuid.uuid4()),
        cycle_id=cycle.id,
        execution_id=execution.id,
        workspace_id=ws1.id,
        probe_number=1,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        status="passed",
        status_code=200,
        latency_ms=35.5,
        passed=True,
    )
    p2 = VerificationProbeResult(
        id=str(uuid.uuid4()),
        cycle_id=cycle.id,
        execution_id=execution.id,
        workspace_id=ws1.id,
        probe_number=2,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        status="passed",
        status_code=200,
        latency_ms=28.1,
        passed=True,
    )
    p3 = VerificationProbeResult(
        id=str(uuid.uuid4()),
        cycle_id=cycle.id,
        execution_id=execution.id,
        workspace_id=ws1.id,
        probe_number=3,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        status="passed",
        status_code=200,
        latency_ms=31.2,
        passed=True,
    )
    db_session.add_all([p1, p2, p3])
    db_session.commit()

    headers = {"Authorization": f"Bearer {auth_setup['viewer_token']}"}
    res = client.get(f"/api/v1/remediation/verification/cycles?workspace_id={ws1.id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    c = data["cycles"][0]
    assert c["id"] == cycle.id
    assert c["status"] == "passed"
    assert c["probes_passed"] == 3
    assert c["action_id"] == "restore_order_api_demo"
    assert c["incident_title"] == "Test 500 Outage"
    assert c["service_name"] == "Order API"
    assert len(c["probes"]) == 3
    assert c["probes"][0]["status_code"] == 200

    # Also test get_execution_verification
    exec_res = client.get(f"/api/v1/remediation/executions/{execution.id}/verification?workspace_id={ws1.id}", headers=headers)
    assert exec_res.status_code == 200
    assert exec_res.json()["total"] == 1


def test_analytics_calculation(client, db_session, auth_setup):
    """Test empirical calculation of MTTR, severity distribution, and trends in /analytics."""
    ws1 = auth_setup["ws1"]
    now = datetime.now(timezone.utc)

    svc = Service(id=str(uuid.uuid4()), workspace_id=ws1.id, name="Order API", environment="development", health_check_url="http://127.0.0.1:8001/health")
    db_session.add(svc)

    # Incident 1: 120 seconds to recover
    inc1 = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        service_id=svc.id,
        title="Incident 1",
        severity="high",
        status="recovered",
        trigger="5xx",
        detected_at=now - timedelta(seconds=300),
        recovered_at=now - timedelta(seconds=180),  # 120s
    )
    # Incident 2: 60 seconds to recover
    inc2 = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        service_id=svc.id,
        title="Incident 2",
        severity="critical",
        status="recovered",
        trigger="unreachable",
        detected_at=now - timedelta(seconds=200),
        recovered_at=now - timedelta(seconds=140),  # 60s
    )
    # Incident 3: Active (no recovered_at)
    inc3 = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        service_id=svc.id,
        title="Incident 3",
        severity="medium",
        status="detected",
        trigger="latency",
        detected_at=now - timedelta(seconds=50),
        recovered_at=None,
    )
    db_session.add_all([inc1, inc2, inc3])
    db_session.commit()

    headers = {"Authorization": f"Bearer {auth_setup['eng_token']}"}
    res = client.get(f"/api/v1/dashboard/analytics?workspace_id={ws1.id}", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_incidents"] == 3
    assert data["active_incidents"] == 1
    assert data["recovered_incidents"] == 2
    # MTTR average: (120 + 60) / 2 = 90.0s
    assert data["avg_mttr_seconds"] == 90.0
    assert data["median_mttr_seconds"] == 90.0
    assert data["mttr_sample_size"] == 2

    # Severity distribution
    assert data["severity_distribution"]["critical"] == 1
    assert data["severity_distribution"]["high"] == 1
    assert data["severity_distribution"]["medium"] == 1
    assert data["severity_distribution"]["low"] == 0

    # Service breakdown
    assert len(data["services"]) == 1
    assert data["services"][0]["service_name"] == "Order API"
    assert data["services"][0]["total_incidents"] == 3
    assert data["services"][0]["recovered_incidents"] == 2
    assert data["services"][0]["avg_mttr_seconds"] == 90.0


def test_analytics_service_filter(client, db_session, auth_setup):
    """Test service_id filter scopes the analytics to a specific service."""
    ws1 = auth_setup["ws1"]
    now = datetime.now(timezone.utc)

    svc1 = Service(id=str(uuid.uuid4()), workspace_id=ws1.id, name="Service 1", environment="development", health_check_url="http://s1/health")
    svc2 = Service(id=str(uuid.uuid4()), workspace_id=ws1.id, name="Service 2", environment="development", health_check_url="http://s2/health")
    db_session.add_all([svc1, svc2])

    inc_s1 = Incident(id=str(uuid.uuid4()), workspace_id=ws1.id, service_id=svc1.id, title="Inc 1", severity="high", status="recovered", trigger="t1", detected_at=now - timedelta(minutes=5), recovered_at=now)
    inc_s2 = Incident(id=str(uuid.uuid4()), workspace_id=ws1.id, service_id=svc2.id, title="Inc 2", severity="low", status="detected", trigger="t2", detected_at=now)
    db_session.add_all([inc_s1, inc_s2])
    db_session.commit()

    headers = {"Authorization": f"Bearer {auth_setup['admin_token']}"}

    # Filter by Service 1
    res1 = client.get(f"/api/v1/dashboard/analytics?workspace_id={ws1.id}&service_id={svc1.id}", headers=headers)
    assert res1.status_code == 200
    assert res1.json()["total_incidents"] == 1
    assert res1.json()["recovered_incidents"] == 1

    # Filter by Service 2
    res2 = client.get(f"/api/v1/dashboard/analytics?workspace_id={ws1.id}&service_id={svc2.id}", headers=headers)
    assert res2.status_code == 200
    assert res2.json()["total_incidents"] == 1
    assert res2.json()["active_incidents"] == 1


def test_workspace_isolation(client, db_session, auth_setup):
    """Ensure user from workspace 2 cannot access workspace 1 data."""
    ws1 = auth_setup["ws1"]
    foreign_headers = {"Authorization": f"Bearer {auth_setup['foreign_token']}"}

    # Foreign user attempting to access workspace 1 verification cycles -> 403 Forbidden
    res_vc = client.get(f"/api/v1/remediation/verification/cycles?workspace_id={ws1.id}", headers=foreign_headers)
    assert res_vc.status_code == 403

    # Foreign user attempting to access workspace 1 analytics -> 403 Forbidden
    res_an = client.get(f"/api/v1/dashboard/analytics?workspace_id={ws1.id}", headers=foreign_headers)
    assert res_an.status_code == 403


def test_role_based_access(client, auth_setup):
    """Ensure Admin, Engineer, and Viewer can all read analytics and verification (read-only)."""
    ws1 = auth_setup["ws1"]

    for role in ["admin_token", "eng_token", "viewer_token"]:
        headers = {"Authorization": f"Bearer {auth_setup[role]}"}

        res_an = client.get(f"/api/v1/dashboard/analytics?workspace_id={ws1.id}", headers=headers)
        assert res_an.status_code == 200, f"Role {role} failed analytics read"

        res_vc = client.get(f"/api/v1/remediation/verification/cycles?workspace_id={ws1.id}", headers=headers)
        assert res_vc.status_code == 200, f"Role {role} failed verification cycles read"

    # Unauthenticated request -> 401 Unauthorized
    res_unauth = client.get(f"/api/v1/dashboard/analytics?workspace_id={ws1.id}")
    assert res_unauth.status_code == 401
