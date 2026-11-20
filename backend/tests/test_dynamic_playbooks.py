"""Tests for Phase 4.1: Persistent Dynamic Remediation Playbooks.

Validates:
1. Playbook creation and validation with allowlist enforcement.
2. Arbitrary code / command injection rejection.
3. Service compatibility check and unsupported service rejection.
4. Versioning and immutable version history preservation.
5. Activation and deactivation lifecycle (fail-closed when inactive).
6. Workspace isolation and cross-workspace access rejection.
7. Role-based permissions (Admin, Engineer, Viewer).
8. Missing playbook behavior (fail-closed in PolicyEngine).
9. Existing Order API compatibility and default playbook seeding.
10. Service-to-playbook association and priority ordering.
11. Reversible Alembic migration 0009 upgrade and downgrade on isolated engine.
"""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.models.playbook import Playbook, PlaybookVersion, ServicePlaybookAssociation
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.policy import PolicyEngine
from app.remediation.playbook_service import PlaybookService
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import PolicyDecisionType
from app.schemas.playbook import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookValidationRequest,
    ServicePlaybookAssociationRequest,
)


@pytest.fixture
def playbook_context(db_session: Session):
    """Sets up workspaces, users with different roles, and registered services."""
    # Workspace A
    ws_a = Workspace(
        id=str(uuid.uuid4()),
        name="Workspace Alpha",
        slug=f"ws-alpha-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws_a)

    # Workspace B
    ws_b = Workspace(
        id=str(uuid.uuid4()),
        name="Workspace Beta",
        slug=f"ws-beta-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws_b)

    # Admin user in Workspace A
    admin_user = User(
        id=str(uuid.uuid4()),
        email=f"admin-{uuid.uuid4().hex[:6]}@example.com",
        full_name="Admin User",
        hashed_password="pw",
        is_active=True,
    )
    db_session.add(admin_user)
    db_session.flush()

    mem_admin = WorkspaceMembership(
        workspace_id=ws_a.id,
        user_id=admin_user.id,
        role="admin",
    )
    db_session.add(mem_admin)

    # Engineer user in Workspace A
    engineer_user = User(
        id=str(uuid.uuid4()),
        email=f"eng-{uuid.uuid4().hex[:6]}@example.com",
        full_name="Engineer User",
        hashed_password="pw",
        is_active=True,
    )
    db_session.add(engineer_user)
    db_session.flush()

    mem_eng = WorkspaceMembership(
        workspace_id=ws_a.id,
        user_id=engineer_user.id,
        role="engineer",
    )
    db_session.add(mem_eng)

    # Viewer user in Workspace A
    viewer_user = User(
        id=str(uuid.uuid4()),
        email=f"view-{uuid.uuid4().hex[:6]}@example.com",
        full_name="Viewer User",
        hashed_password="pw",
        is_active=True,
    )
    db_session.add(viewer_user)
    db_session.flush()

    mem_view = WorkspaceMembership(
        workspace_id=ws_a.id,
        user_id=viewer_user.id,
        role="viewer",
    )
    db_session.add(mem_view)

    # Services in Workspace A
    order_svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_a.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        demo_integration="order_api",
        is_active=True,
    )
    db_session.add(order_svc)

    inventory_svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_a.id,
        name="Inventory API",
        environment="development",
        health_check_url="http://127.0.0.1:7000/api/v1/health",
        monitoring_method="prometheus",
        is_active=True,
    )
    db_session.add(inventory_svc)

    # Service in Workspace B
    service_b = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_b.id,
        name="External Payment API",
        environment="development",
        health_check_url="http://127.0.0.1:9050/health",
        monitoring_method="prometheus",
        is_active=True,
    )
    db_session.add(service_b)

    db_session.commit()

    return {
        "ws_a": ws_a,
        "ws_b": ws_b,
        "admin_user": admin_user,
        "engineer_user": engineer_user,
        "viewer_user": viewer_user,
        "order_svc": order_svc,
        "inventory_svc": inventory_svc,
        "service_b": service_b,
    }


# ============================================================================
# 1. Playbook Creation and Validation
# ============================================================================

def test_playbook_creation_and_validation(db_session: Session, playbook_context: dict):
    """Verifies that an engineer can create a valid playbook with initial version (v1)."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    user = ctx["engineer_user"]

    req = PlaybookCreate(
        workspace_id=ws.id,
        name="Inventory Health Diagnostic",
        description="Periodically inspects inventory health endpoints.",
        category="diagnostics",
        action_template_id="inspect_service_health",
        supported_scenarios=["*"],
        parameter_schema={"service_id": ctx["inventory_svc"].id},
        verification_criteria={"probes_required": 3, "timeout_seconds": 15},
        risk_level="low",
        approval_required=False,
        timeout_seconds=30,
        initial_service_ids=[ctx["inventory_svc"].id],
    )

    playbook = PlaybookService.create_playbook(db=db_session, user=user, data=req)
    assert playbook.id is not None
    assert playbook.name == "Inventory Health Diagnostic"
    assert playbook.current_version == 1
    assert playbook.is_active is True
    assert len(playbook.versions) == 1
    assert playbook.versions[0].version_number == 1
    assert playbook.versions[0].action_template_id == "inspect_service_health"
    assert playbook.versions[0].risk_level == "low"
    assert len(playbook.service_associations) == 1
    assert playbook.service_associations[0].service_id == ctx["inventory_svc"].id

    # Test unique name constraint within workspace
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.create_playbook(db=db_session, user=user, data=req)
    assert exc_info.value.status_code == 409


# ============================================================================
# 2. Safety: Reject Unknown Actions & Arbitrary Scripts
# ============================================================================

def test_playbook_invalid_action_rejection(db_session: Session, playbook_context: dict):
    """Verifies that unknown actions and arbitrary code injections are rejected."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    user = ctx["engineer_user"]

    # 1. Unknown action template
    req_unknown = PlaybookCreate(
        workspace_id=ws.id,
        name="Malicious Unknown Action",
        action_template_id="delete_production_database",
    )
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.create_playbook(db=db_session, user=user, data=req_unknown)
    assert exc_info.value.status_code == 400
    assert "not in the allowlisted remediation actions catalog" in exc_info.value.detail

    # 2. Arbitrary shell command injection attempt
    req_shell = PlaybookCreate(
        workspace_id=ws.id,
        name="Injected Script Action",
        action_template_id="inspect_service_health",
        parameter_schema={"command": "bash -c 'rm -rf /'"},
    )
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.create_playbook(db=db_session, user=user, data=req_shell)
    assert exc_info.value.status_code == 400
    assert "Forbidden executable pattern" in exc_info.value.detail


# ============================================================================
# 3. Safety: Reject Unsupported Service / Action Combinations
# ============================================================================

def test_playbook_unsupported_service_rejection(db_session: Session, playbook_context: dict):
    """Verifies that service-specific actions cannot be associated with incompatible services."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    user = ctx["engineer_user"]

    # restore_order_api_demo is restricted to Order API. Attempting to associate it with Inventory API must be warned/rejected
    val = PlaybookService.validate_playbook_spec(
        db=db_session,
        workspace_id=ws.id,
        action_template_id="restore_order_api_demo",
        service_ids=[ctx["inventory_svc"].id],
    )
    assert len(val.incompatible_services) == 1
    assert val.incompatible_services[0].service_id == ctx["inventory_svc"].id

    # Create playbook with Order API action
    req = PlaybookCreate(
        workspace_id=ws.id,
        name="Order Recovery Only",
        action_template_id="restore_order_api_demo",
        initial_service_ids=[],
    )
    pb = PlaybookService.create_playbook(db=db_session, user=user, data=req)

    # Attempting to explicitly associate with Inventory API must raise 400
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.associate_service(
            db=db_session,
            user=user,
            workspace_id=ws.id,
            playbook_id=pb.id,
            service_id=ctx["inventory_svc"].id,
        )
    assert exc_info.value.status_code == 400
    assert "does not support service" in exc_info.value.detail


# ============================================================================
# 4. Versioning and Immutable History
# ============================================================================

def test_playbook_versioning_and_history(db_session: Session, playbook_context: dict):
    """Verifies that updating specification creates a new immutable version."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    user = ctx["engineer_user"]

    pb = PlaybookService.create_playbook(
        db=db_session,
        user=user,
        data=PlaybookCreate(
            workspace_id=ws.id,
            name="Versioned Playbook",
            action_template_id="inspect_service_health",
            timeout_seconds=30,
            risk_level="low",
        ),
    )
    assert pb.current_version == 1

    # Metadata-only update (does not increment version)
    pb_meta = PlaybookService.update_playbook(
        db=db_session,
        user=user,
        playbook_id=pb.id,
        data=PlaybookUpdate(
            workspace_id=ws.id,
            description="Updated metadata description only",
        ),
    )
    assert pb_meta.current_version == 1
    assert len(pb_meta.versions) == 1
    assert pb_meta.description == "Updated metadata description only"

    # Operational update (increments version)
    pb_v2 = PlaybookService.update_playbook(
        db=db_session,
        user=user,
        playbook_id=pb.id,
        data=PlaybookUpdate(
            workspace_id=ws.id,
            timeout_seconds=45,
            risk_level="medium",
            change_summary="Increased timeout and elevated risk level",
        ),
    )
    assert pb_v2.current_version == 2
    assert len(pb_v2.versions) == 2

    # Verify both versions exist in database
    v1 = db_session.query(PlaybookVersion).filter(PlaybookVersion.playbook_id == pb.id, PlaybookVersion.version_number == 1).first()
    v2 = db_session.query(PlaybookVersion).filter(PlaybookVersion.playbook_id == pb.id, PlaybookVersion.version_number == 2).first()
    assert v1.timeout_seconds == 30
    assert v1.risk_level == "low"
    assert v2.timeout_seconds == 45
    assert v2.risk_level == "medium"
    assert v2.change_summary == "Increased timeout and elevated risk level"


# ============================================================================
# 5. Activation and Deactivation Lifecycle
# ============================================================================

def test_playbook_activation_lifecycle(db_session: Session, playbook_context: dict):
    """Verifies that deactivated playbooks fail closed and are excluded from active lookups."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    user = ctx["engineer_user"]
    svc = ctx["inventory_svc"]

    pb = PlaybookService.create_playbook(
        db=db_session,
        user=user,
        data=PlaybookCreate(
            workspace_id=ws.id,
            name="Toggleable Playbook",
            action_template_id="inspect_service_health",
            initial_service_ids=[svc.id],
        ),
    )
    assert pb.is_active is True

    # Active playbook is found
    active_pbs = PlaybookService.get_playbooks_for_service(db=db_session, service_id=svc.id)
    assert len(active_pbs) == 1
    assert active_pbs[0].id == pb.id

    # Deactivate playbook
    PlaybookService.toggle_playbook_activation(
        db=db_session,
        workspace_id=ws.id,
        playbook_id=pb.id,
        activate=False,
    )
    db_session.refresh(pb)
    assert pb.is_active is False

    # Deactivated playbook is excluded
    active_pbs_after = PlaybookService.get_playbooks_for_service(db=db_session, service_id=svc.id)
    assert len(active_pbs_after) == 0

    # is_action_supported_for_service fails closed when inactive
    assert PlaybookService.is_action_supported_for_service(db_session, "inspect_service_health", svc) is False


# ============================================================================
# 6. Workspace Isolation and Cross-Workspace Rejection
# ============================================================================

def test_playbook_workspace_isolation(db_session: Session, playbook_context: dict):
    """Verifies that playbooks and services cannot cross tenant boundaries."""
    ctx = playbook_context
    ws_a = ctx["ws_a"]
    ws_b = ctx["ws_b"]
    user = ctx["engineer_user"]

    pb_a = PlaybookService.create_playbook(
        db=db_session,
        user=user,
        data=PlaybookCreate(
            workspace_id=ws_a.id,
            name="Workspace A Playbook",
            action_template_id="inspect_service_health",
        ),
    )

    # Attempting to associate Service B (which belongs to Workspace B) with Playbook A (Workspace A) must fail
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.associate_service(
            db=db_session,
            user=user,
            workspace_id=ws_a.id,
            playbook_id=pb_a.id,
            service_id=ctx["service_b"].id,
        )
    assert exc_info.value.status_code == 404

    # Attempting to access Playbook A using Workspace B ID must fail
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.get_playbook(db=db_session, workspace_id=ws_b.id, playbook_id=pb_a.id)
    assert exc_info.value.status_code == 404


# ============================================================================
# 7. Role-Based Permissions (RBAC)
# ============================================================================

def test_role_based_permissions(client, playbook_context: dict):
    """Verifies that Viewers cannot modify playbooks, while Engineers and Admins can."""
    ctx = playbook_context
    ws = ctx["ws_a"]

    viewer_token = create_access_token({"sub": ctx["viewer_user"].id})
    engineer_token = create_access_token({"sub": ctx["engineer_user"].id})

    # 1. Viewer attempts to create playbook -> 403 Forbidden
    resp = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "workspace_id": ws.id,
            "name": "Viewer Unauthorized Playbook",
            "action_template_id": "inspect_service_health",
        },
    )
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.json()["detail"]

    # 2. Engineer creates playbook -> 201 Created
    resp_eng = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {engineer_token}"},
        json={
            "workspace_id": ws.id,
            "name": "Engineer Authorized Playbook",
            "action_template_id": "inspect_service_health",
        },
    )
    assert resp_eng.status_code == 201
    pb_id = resp_eng.json()["id"]

    # 3. Viewer can view playbook list -> 200 OK
    resp_list = client.get(
        f"/api/v1/playbooks?workspace_id={ws.id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp_list.status_code == 200
    assert any(p["id"] == pb_id for p in resp_list.json())

    # 4. Viewer attempts to deactivate playbook -> 403 Forbidden
    resp_deact = client.post(
        f"/api/v1/playbooks/{pb_id}/deactivate?workspace_id={ws.id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp_deact.status_code == 403


# ============================================================================
# 8. Missing Playbook Behavior (Fail Closed)
# ============================================================================

def test_missing_playbook_fails_closed(db_session: Session, playbook_context: dict):
    """Verifies that PolicyEngine fails closed when a service has no active approved playbook."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    svc = ctx["inventory_svc"]

    # Ensure no playbook is associated with inventory_svc
    assocs = db_session.query(ServicePlaybookAssociation).filter(ServicePlaybookAssociation.service_id == svc.id).all()
    for a in assocs:
        db_session.delete(a)
    db_session.commit()

    # Evaluating an operational recovery action for Inventory API must fail closed
    result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": svc.id},
        db=db_session,
        environment="development",
    )
    assert result.decision == PolicyDecisionType.REJECTED
    assert "No approved remediation playbook is configured for this service" in result.decision_reason


# ============================================================================
# 9. Existing Order API Compatibility and Default Playbook Seeding
# ============================================================================

def test_order_api_compatibility_and_seeding(db_session: Session, playbook_context: dict):
    """Verifies that Order API default playbook seeding preserves existing recovery workflow."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    order_svc = ctx["order_svc"]

    # Seed default Order API playbook
    pb = PlaybookService.seed_default_order_api_playbook(
        db=db_session,
        workspace_id=ws.id,
        service_id=order_svc.id,
        user_id=ctx["admin_user"].id,
    )
    assert pb is not None
    assert pb.name == "Order API Failure Recovery"
    assert pb.active_version.action_template_id == "restore_order_api_demo"

    # ActionRegistry reports action is supported
    assert ActionRegistry.is_action_supported_for_service("restore_order_api_demo", order_svc, db=db_session) is True

    # Policy evaluation succeeds and requires approval
    result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": order_svc.id},
        db=db_session,
        environment="development",
    )
    assert result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert result.approval_required is True


# ============================================================================
# 10. Service Playbook Association and Priority Ordering
# ============================================================================

def test_service_playbook_association_priority(db_session: Session, playbook_context: dict):
    """Verifies that multiple playbooks can be bound with priority ordering."""
    ctx = playbook_context
    ws = ctx["ws_a"]
    user = ctx["engineer_user"]
    svc = ctx["inventory_svc"]

    pb1 = PlaybookService.create_playbook(
        db=db_session,
        user=user,
        data=PlaybookCreate(
            workspace_id=ws.id,
            name="Low Priority Diagnostic",
            action_template_id="inspect_service_health",
            initial_service_ids=[svc.id],
        ),
    )
    pb2 = PlaybookService.create_playbook(
        db=db_session,
        user=user,
        data=PlaybookCreate(
            workspace_id=ws.id,
            name="High Priority Diagnostic",
            action_template_id="inspect_service_health",
        ),
    )

    # Associate pb2 with higher priority
    PlaybookService.associate_service(
        db=db_session,
        user=user,
        workspace_id=ws.id,
        playbook_id=pb2.id,
        service_id=svc.id,
        priority=100,
    )

    playbooks = PlaybookService.get_playbooks_for_service(db=db_session, service_id=svc.id)
    assert len(playbooks) == 2
    # High priority playbook must appear first
    assert playbooks[0].id == pb2.id
    assert playbooks[1].id == pb1.id

    # Disassociate pb2
    PlaybookService.disassociate_service(
        db=db_session,
        workspace_id=ws.id,
        playbook_id=pb2.id,
        service_id=svc.id,
    )
    playbooks_after = PlaybookService.get_playbooks_for_service(db=db_session, service_id=svc.id)
    assert len(playbooks_after) == 1
    assert playbooks_after[0].id == pb1.id


# ============================================================================
# 11. Alembic Migration 0009 Reversible Upgrade & Downgrade
# ============================================================================

def test_alembic_migration_0009_upgrade_and_downgrade_on_isolated_engine(tmp_path, monkeypatch):
    """Verify Alembic migration 0009 can be upgraded and downgraded cleanly on an isolated test database."""
    from alembic.config import Config
    from alembic import command
    from app.core.config import settings

    db_path = tmp_path / "isolated_playbook_migration_test.db"
    db_url = f"sqlite:///{db_path}"

    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setattr(settings, "DATABASE_URL", db_url)

    alembic_ini_path = r"d:\Sentinal_AI\backend\alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    alembic_cfg.set_main_option("script_location", r"d:\Sentinal_AI\backend\alembic")

    # 1. Upgrade to head (runs all migrations 0001 through 0009 on isolated SQLite)
    command.upgrade(alembic_cfg, "head")

    test_eng = create_engine(db_url)
    with test_eng.connect() as conn:
        tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "playbooks" in tables
        assert "playbook_versions" in tables
        assert "service_playbook_associations" in tables
        assert "verification_cycles" in tables

    # 2. Downgrade migration 0009 to 0008
    command.downgrade(alembic_cfg, "0008_verification_persistence")

    with test_eng.connect() as conn:
        tables_down = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "playbooks" not in tables_down
        assert "playbook_versions" not in tables_down
        assert "service_playbook_associations" not in tables_down
        # 0008 tables must still exist
        assert "verification_cycles" in tables_down
        assert "verification_probe_results" in tables_down

    # 3. Upgrade back to head
    command.upgrade(alembic_cfg, "head")
    with test_eng.connect() as conn:
        tables_reup = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "playbooks" in tables_reup
        assert "playbook_versions" in tables_reup
        assert "service_playbook_associations" in tables_reup
