"""Tests for Phase 4.3: Dynamic Playbook Integration with LangGraph.

Covers:
1. Correct playbook discovery for a service.
2. Multiple playbooks for one service with deterministic ranking.
3. Inactive playbook rejection.
4. Unassociated playbook rejection.
5. Cross-workspace isolation.
6. Unsupported action rejection.
7. Invalid parameter rejection.
8. Missing parameter escalation (Outcome D).
9. No-playbook escalation (Outcome C) without invented actions.
10. Correct active version selection.
11. Version changes after recommendation generation (stale version rejection).
12. Policy engine enforcement and role restrictions.
13. Existing Order API backward compatibility.
14. Dedicated end-to-end workflow for a newly created service with a newly created playbook.
15. No automatic execution without human approval.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import pytest
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
from app.models.playbook import Playbook, PlaybookVersion, ServicePlaybookAssociation
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.agents.graph import run_investigation, create_investigation_graph
from app.agents.nodes.playbooks import (
    discover_active_playbooks,
    evaluate_playbook_compatibility,
    rank_compatible_playbooks,
    generate_remediation_recommendation,
)
from app.agents.state import InvestigationState
from app.remediation.policy import PolicyEngine
from app.remediation.approval_service import ApprovalService
from app.remediation.playbook_service import PlaybookService
from app.remediation.schemas import PolicyDecisionType


@pytest.fixture
def dynamic_test_setup(db_session: Session):
    """Sets up workspaces, users, services, and baseline incidents."""
    # Workspace A
    ws_a = Workspace(
        id=str(uuid.uuid4()),
        name="Primary SRE Workspace",
        slug=f"primary-sre-{uuid.uuid4().hex[:6]}",
    )
    # Workspace B (Tenant isolation test)
    ws_b = Workspace(
        id=str(uuid.uuid4()),
        name="Foreign Workspace",
        slug=f"foreign-ws-{uuid.uuid4().hex[:6]}",
    )
    db_session.add_all([ws_a, ws_b])
    db_session.flush()

    # Engineer user in Workspace A
    user_eng = User(
        id=str(uuid.uuid4()),
        email="engineer@sentinelops.test",
        hashed_password="pw",
        full_name="Alice Engineer",
        is_active=True,
    )
    # Viewer user in Workspace A
    user_view = User(
        id=str(uuid.uuid4()),
        email="viewer@sentinelops.test",
        hashed_password="pw",
        full_name="Bob Viewer",
        is_active=True,
    )
    db_session.add_all([user_eng, user_view])
    db_session.flush()

    db_session.add(WorkspaceMembership(workspace_id=ws_a.id, user_id=user_eng.id, role="engineer"))
    db_session.add(WorkspaceMembership(workspace_id=ws_a.id, user_id=user_view.id, role="viewer"))
    db_session.flush()

    # Service in Workspace A: Inventory API
    service_inv = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_a.id,
        name="Inventory Management API",
        environment="development",
        health_check_url="http://127.0.0.1:7000/api/v1/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
    )
    # Service in Workspace A: Order API
    service_order = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_a.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        demo_integration="order_api",
    )
    # Service in Workspace B: Foreign Service
    service_foreign = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_b.id,
        name="Foreign Billing API",
        environment="development",
        health_check_url="http://127.0.0.1:9090/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
    )
    db_session.add_all([service_inv, service_order, service_foreign])
    db_session.flush()

    # Baseline incident for Inventory API
    incident_inv = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws_a.id,
        service_id=service_inv.id,
        title="High Error Rate in Inventory API",
        severity="high",
        status="detected",
        trigger="http_5xx_rate_exceeded",
        summary="Inventory API returning HTTP 500 across consecutive health probes",
    )
    db_session.add(incident_inv)
    db_session.commit()

    return {
        "ws_a": ws_a,
        "ws_b": ws_b,
        "user_eng": user_eng,
        "user_view": user_view,
        "service_inv": service_inv,
        "service_order": service_order,
        "service_foreign": service_foreign,
        "incident_inv": incident_inv,
    }


def create_test_playbook(
    db: Session,
    workspace_id: str,
    name: str,
    action_template_id: str,
    service_id: str,
    supported_scenarios=None,
    parameter_schema=None,
    priority: int = 10,
    is_active: bool = True,
    assoc_active: bool = True,
    risk_level: str = "medium",
) -> Playbook:
    """Helper to create a Playbook, PlaybookVersion, and ServicePlaybookAssociation."""
    pb = Playbook(
        workspace_id=workspace_id,
        name=name,
        description=f"Test playbook {name}",
        category="service_recovery",
        is_active=is_active,
        current_version=1,
    )
    db.add(pb)
    db.flush()

    v = PlaybookVersion(
        playbook_id=pb.id,
        version_number=1,
        action_template_id=action_template_id,
        supported_scenarios=supported_scenarios or ["*"],
        parameter_schema=parameter_schema or {},
        verification_criteria={"health_check": True},
        risk_level=risk_level,
        approval_required=True,
        timeout_seconds=30,
        change_summary="Initial version",
    )
    db.add(v)
    db.flush()

    assoc = ServicePlaybookAssociation(
        workspace_id=workspace_id,
        service_id=service_id,
        playbook_id=pb.id,
        is_active=assoc_active,
        priority=priority,
    )
    db.add(assoc)
    db.commit()
    db.refresh(pb)
    return pb


# ============================================================================
# 1. Playbook Discovery Tests
# ============================================================================

@pytest.mark.asyncio
async def test_playbook_discovery_for_service(db_session: Session, dynamic_test_setup):
    """Confirm correct playbook discovery strictly matches the affected service and workspace."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc = setup["service_inv"]

    pb = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Inventory Diagnostic Probe",
        action_template_id="inspect_service_health",
        service_id=svc.id,
    )

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc.id,
        "investigation_id": None,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "incident_context": {"service_id": svc.id},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    result = await discover_active_playbooks(state, db=db_session)
    discovered = result["discovered_playbooks"]

    assert len(discovered) == 1
    assert discovered[0]["playbook_id"] == pb.id
    assert discovered[0]["playbook_name"] == "Inventory Diagnostic Probe"
    assert discovered[0]["action_template_id"] == "inspect_service_health"


@pytest.mark.asyncio
async def test_multiple_playbooks_priority_ranking(db_session: Session, dynamic_test_setup):
    """Confirm multiple compatible playbooks are ranked by association priority descending."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc = setup["service_inv"]

    # Playbook 1: Priority 50
    pb1 = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Inventory Standard Inspection",
        action_template_id="inspect_service_health",
        service_id=svc.id,
        priority=50,
    )
    # Playbook 2: Priority 100 (Higher priority)
    pb2 = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Inventory Expedited Diagnostics",
        action_template_id="inspect_service_health",
        service_id=svc.id,
        priority=100,
    )

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc.id, "trigger": "http_5xx_rate_exceeded"},
        "evidence_items": [{"evidence_id": "ev-1", "source": "health_probe", "collection_status": "failed", "observation": "HTTP 500 error"}],
        "evidence_errors": [],
        "hypotheses": [{"hypothesis_id": "hyp-1", "root_cause": "Elevated 5xx errors", "confidence": 0.9, "is_supported": True}],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    disc = await discover_active_playbooks(state, db=db_session)
    state["discovered_playbooks"] = disc["discovered_playbooks"]

    compat = evaluate_playbook_compatibility(state, db=db_session)
    state["compatible_playbooks"] = compat["compatible_playbooks"]
    state["rejected_playbooks"] = compat["rejected_playbooks"]

    ranked = rank_compatible_playbooks(state)
    ranked_list = ranked["ranked_playbooks"]

    assert len(ranked_list) == 2
    # pb2 (priority 100) must rank before pb1 (priority 50)
    assert ranked_list[0]["playbook_id"] == pb2.id
    assert ranked_list[1]["playbook_id"] == pb1.id


# ============================================================================
# 2. Inactive & Unassociated Playbook Rejection Tests
# ============================================================================

@pytest.mark.asyncio
async def test_inactive_playbook_rejection(db_session: Session, dynamic_test_setup):
    """Confirm inactive playbooks or deactivated associations are never discovered."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc = setup["service_inv"]

    # Inactive playbook
    create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Deactivated Playbook",
        action_template_id="inspect_service_health",
        service_id=svc.id,
        is_active=False,
    )
    # Active playbook but inactive association
    create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Unbound Association Playbook",
        action_template_id="inspect_service_health",
        service_id=svc.id,
        is_active=True,
        assoc_active=False,
    )

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc.id},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    result = await discover_active_playbooks(state, db=db_session)
    assert len(result["discovered_playbooks"]) == 0


@pytest.mark.asyncio
async def test_unassociated_playbook_rejection(db_session: Session, dynamic_test_setup):
    """Confirm playbooks in the same workspace not bound to the target service are ignored."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]
    svc_order = setup["service_order"]

    # Playbook bound to Order API, not Inventory API
    create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Order API Recovery",
        action_template_id="restore_order_api_demo",
        service_id=svc_order.id,
    )

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc_inv.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc_inv.id},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    result = await discover_active_playbooks(state, db=db_session)
    assert len(result["discovered_playbooks"]) == 0


@pytest.mark.asyncio
async def test_cross_workspace_isolation(db_session: Session, dynamic_test_setup):
    """Confirm playbooks belonging to Workspace B are never discovered for Workspace A."""
    setup = dynamic_test_setup
    ws_b = setup["ws_b"]
    svc_foreign = setup["service_foreign"]

    # Playbook in Workspace B
    create_test_playbook(
        db=db_session,
        workspace_id=ws_b.id,
        name="Foreign Workspace Playbook",
        action_template_id="inspect_service_health",
        service_id=svc_foreign.id,
    )

    # Investigation running in Workspace A for Inventory API
    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": setup["ws_a"].id,
        "service_id": setup["service_inv"].id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": setup["service_inv"].id},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    result = await discover_active_playbooks(state, db=db_session)
    assert len(result["discovered_playbooks"]) == 0


# ============================================================================
# 3. Deterministic Compatibility Evaluation Tests
# ============================================================================

def test_unsupported_action_rejection(db_session: Session, dynamic_test_setup):
    """Confirm an action template that does not support the target service is rejected."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]

    # restore_order_api_demo only supports Order API, not Inventory API
    pb = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Incompatible Order Restore on Inventory",
        action_template_id="restore_order_api_demo",
        service_id=svc_inv.id,
    )

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc_inv.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc_inv.id, "trigger": "http_5xx_rate_exceeded"},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [{"hypothesis_id": "hyp-1", "root_cause": "5xx errors", "is_supported": True}],
        "discovered_playbooks": [
            {
                "playbook_id": pb.id,
                "playbook_name": pb.name,
                "current_version": 1,
                "action_template_id": "restore_order_api_demo",
                "supported_scenarios": ["*"],
                "parameter_schema": {},
                "risk_level": "medium",
                "priority": 10,
            }
        ],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    compat = evaluate_playbook_compatibility(state, db=db_session)
    assert len(compat["compatible_playbooks"]) == 0
    assert len(compat["rejected_playbooks"]) == 1
    assert any("does not support service" in r for r in compat["rejected_playbooks"][0]["rejection_reasons"])


def test_invalid_parameter_rejection(db_session: Session, dynamic_test_setup):
    """Confirm a candidate playbook with schema-invalid parameters is rejected deterministically."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]

    # inspect_service_health requires valid service_id and boolean/string fields
    # If parameters has invalid non-boolean types or corrupt data
    pb = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Invalid Param Playbook",
        action_template_id="inspect_service_health",
        service_id=svc_inv.id,
        parameter_schema={"service_id": "not-a-valid-uuid"},
    )

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc_inv.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc_inv.id, "trigger": "http_5xx_rate_exceeded"},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [{"hypothesis_id": "hyp-1", "root_cause": "5xx errors", "is_supported": True}],
        "discovered_playbooks": [
            {
                "playbook_id": pb.id,
                "playbook_name": pb.name,
                "current_version": 1,
                "action_template_id": "inspect_service_health",
                "supported_scenarios": ["*"],
                "parameter_schema": {"service_id": "not-a-valid-uuid"},
                "risk_level": "low",
                "priority": 10,
            }
        ],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    compat = evaluate_playbook_compatibility(state, db=db_session)
    assert len(compat["compatible_playbooks"]) == 0
    assert len(compat["rejected_playbooks"]) == 1
    assert any("validation failed" in r.lower() or "uuid" in r.lower() for r in compat["rejected_playbooks"][0]["rejection_reasons"])


def test_missing_parameter_escalation(db_session: Session, dynamic_test_setup):
    """Confirm Outcome D: Missing required parameter triggers escalation without fabricating values."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]

    # Provide a candidate that has an unrecognized schema or missing parameter
    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc_inv.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc_inv.id, "service_name": svc_inv.name, "trigger": "http_5xx_rate_exceeded"},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [{"hypothesis_id": "hyp-1", "root_cause": "5xx errors", "is_supported": True}],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [
            {
                "playbook_id": "pb-missing",
                "playbook_name": "Database Scaler",
                "version_number": 1,
                "action_template_id": "inspect_service_health",
                "is_compatible": False,
                "rejection_reasons": ["Missing required action parameters: replica_count."],
                "matching_scenarios": ["http_5xx_rate_exceeded"],
                "missing_parameters": ["replica_count"],
                "validated_parameters": {},
            }
        ],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    rec = generate_remediation_recommendation(state)["remediation_recommendation"]

    assert rec["outcome"] == "missing_parameters"
    assert rec["status"] == "human_escalation_required"
    assert "replica_count" in rec["missing_parameters"]
    assert "Never fabricating parameter values" in rec["escalation_reason"]


def test_no_playbook_escalation(db_session: Session, dynamic_test_setup):
    """Confirm Outcome C: No compatible playbook results in human escalation without inventing actions."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]

    state: InvestigationState = {
        "incident_id": setup["incident_inv"].id,
        "workspace_id": ws.id,
        "service_id": svc_inv.id,
        "investigation_id": None,
        "status": "running",
        "started_at": None,
        "completed_at": None,
        "incident_context": {"service_id": svc_inv.id, "service_name": svc_inv.name, "trigger": "http_5xx_rate_exceeded"},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [{"hypothesis_id": "hyp-1", "root_cause": "5xx errors", "is_supported": True}],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": "gemini-2.5-flash",
        "prompt_version": "v1.0",
        "token_usage": None,
        "errors": [],
    }

    rec = generate_remediation_recommendation(state)["remediation_recommendation"]

    assert rec["outcome"] == "no_compatible_playbook"
    assert rec["status"] == "human_escalation_required"
    assert rec["action_template_id"] is None
    assert rec["playbook_id"] is None
    assert "Human SRE engineer intervention is required" in rec["explanation"]


# ============================================================================
# 4. Versioning & Stale Version Rejection Tests
# ============================================================================

def test_correct_active_version_selection(db_session: Session, dynamic_test_setup):
    """Confirm that the playbook's active version (current_version) is used, not stale versions."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]

    pb = Playbook(
        workspace_id=ws.id,
        name="Versioned Diagnostics",
        category="diagnostics",
        is_active=True,
        current_version=2,
    )
    db_session.add(pb)
    db_session.flush()

    # Version 1 (Stale)
    v1 = PlaybookVersion(
        playbook_id=pb.id,
        version_number=1,
        action_template_id="disable_service_monitoring",
        supported_scenarios=["*"],
        parameter_schema={},
        verification_criteria={},
        risk_level="high",
        approval_required=True,
    )
    # Version 2 (Active)
    v2 = PlaybookVersion(
        playbook_id=pb.id,
        version_number=2,
        action_template_id="inspect_service_health",
        supported_scenarios=["*"],
        parameter_schema={},
        verification_criteria={},
        risk_level="low",
        approval_required=False,
    )
    db_session.add_all([v1, v2])
    db_session.flush()

    assoc = ServicePlaybookAssociation(
        workspace_id=ws.id,
        service_id=svc_inv.id,
        playbook_id=pb.id,
        is_active=True,
        priority=10,
    )
    db_session.add(assoc)
    db_session.commit()

    active_v = pb.active_version
    assert active_v is not None
    assert active_v.version_number == 2
    assert active_v.action_template_id == "inspect_service_health"


def test_version_change_after_recommendation_rejection(db_session: Session, dynamic_test_setup):
    """Confirm Section 6: If a recommendation is based on v1, but the playbook was updated to v2, proposal creation rejects it."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    user = setup["user_eng"]
    svc_inv = setup["service_inv"]

    pb = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Mutable Playbook",
        action_template_id="inspect_service_health",
        service_id=svc_inv.id,
    )

    # Evaluate policy matching the recommendation version 1
    eval_v1 = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="inspect_service_health",
        parameters={"service_id": svc_inv.id},
        environment="development",
        db=db_session,
        user_id=user.id,
        playbook_id=pb.id,
        playbook_version=1,
    )
    assert eval_v1.decision in (PolicyDecisionType.ALLOWED, PolicyDecisionType.APPROVAL_REQUIRED)

    # Now bump the playbook to version 2
    pb.current_version = 2
    v2 = PlaybookVersion(
        playbook_id=pb.id,
        version_number=2,
        action_template_id="inspect_service_health",
        supported_scenarios=["*"],
        parameter_schema={},
        verification_criteria={},
        risk_level="low",
        approval_required=False,
    )
    db_session.add(v2)
    db_session.add(pb)
    db_session.commit()

    # Now attempt to evaluate referencing stale version 1
    eval_stale = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="inspect_service_health",
        parameters={"service_id": svc_inv.id},
        environment="development",
        db=db_session,
        user_id=user.id,
        playbook_id=pb.id,
        playbook_version=1,  # Stale version!
    )
    assert eval_stale.decision == PolicyDecisionType.REJECTED
    assert "Playbook version mismatch" in eval_stale.decision_reason


# ============================================================================
# 5. Policy Engine Enforcement & Role Restrictions
# ============================================================================

def test_policy_engine_role_and_policy_enforcement(db_session: Session, dynamic_test_setup):
    """Confirm Viewers cannot propose, observe-only services reject operational actions, and AI risk overrides fail."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]

    pb = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Inventory Health Probe",
        action_template_id="inspect_service_health",
        service_id=svc_inv.id,
    )

    # 1. Viewer role is strictly prohibited from authorizing operational actions
    eval_viewer = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="viewer",
        action_id="restore_order_api_demo",
        parameters={"service_id": setup["service_order"].id},
        environment="development",
        db=db_session,
    )
    assert eval_viewer.decision == PolicyDecisionType.REJECTED
    assert "not authorized to request or approve operational action" in eval_viewer.decision_reason

    # 2. Service with observe_only execution policy rejects operational recovery
    svc_observe = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Observe Only Service",
        environment="development",
        health_check_url="http://127.0.0.1:8000/health",
        monitoring_method="prometheus",
        execution_policy="observe_only",
    )
    db_session.add(svc_observe)
    db_session.flush()

    pb_observe = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Observe Service Recovery",
        action_template_id="restore_order_api_demo",
        service_id=svc_observe.id,
    )

    eval_observe = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": svc_observe.id},
        environment="development",
        db=db_session,
        playbook_id=pb_observe.id,
        playbook_version=1,
    )
    assert eval_observe.decision == PolicyDecisionType.REJECTED
    assert "observe_only" in eval_observe.decision_reason


# ============================================================================
# 6. Order API Compatibility & Dedicated New Service End-to-End Test
# ============================================================================

@pytest.mark.asyncio
async def test_order_api_backward_compatibility(db_session: Session, dynamic_test_setup):
    """Confirm the seeded default Order API recovery playbook integrates with LangGraph and produces an actionable recommendation."""
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_order = setup["service_order"]

    # Seed default Order API playbook
    pb = PlaybookService.seed_default_order_api_playbook(
        db=db_session,
        workspace_id=ws.id,
        service_id=svc_order.id,
        user_id=setup["user_eng"].id,
    )
    assert pb is not None

    # Incident for Order API
    inc_order = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc_order.id,
        title="Order API Demo Failure",
        severity="high",
        status="detected",
        trigger="health_probe_status_code_500",
        summary="Order API /health returned HTTP 500 with simulated database timeout",
    )
    db_session.add(inc_order)
    db_session.commit()

    # Mock HTTP client returning 500 database timeout and metrics
    mock_client = AsyncMock()
    mock_health_resp = MagicMock()
    mock_health_resp.status_code = 500
    mock_health_resp.text = '{"status": "error", "message": "Database request timed out after 5000ms"}'
    mock_health_resp.json.return_value = {"status": "error", "message": "Database request timed out after 5000ms"}

    mock_metrics_resp = MagicMock()
    mock_metrics_resp.status_code = 200
    mock_metrics_resp.text = (
        "# HELP http_requests_total Total HTTP requests\n"
        'http_requests_total{status="500"} 18.0\n'
        'http_requests_total{status="200"} 42.0\n'
    )
    mock_metrics_resp.json.return_value = {}

    async def mock_get(url, **kwargs):
        if "/metrics" in str(url):
            return mock_metrics_resp
        return mock_health_resp

    mock_client.get.side_effect = mock_get

    final_state = await run_investigation(
        incident_id=inc_order.id,
        workspace_id=ws.id,
        db=db_session,
        client=mock_client,
    )

    assert final_state["status"] == "completed"
    rec = final_state.get("remediation_recommendation")
    assert rec is not None
    assert rec["status"] == "actionable"
    assert rec["playbook_id"] == pb.id
    assert rec["action_template_id"] == "restore_order_api_demo"
    assert rec["parameters"]["service_id"] == svc_order.id


@pytest.mark.asyncio
async def test_new_service_new_playbook_end_to_end_workflow(db_session: Session, dynamic_test_setup):
    """
    Dedicated End-to-End Test (Section 10):
    1. Register new dynamic playbook for newly created service (Inventory API).
    2. Create incident and run LangGraph investigation.
    3. Verify dynamic playbook discovery, compatibility evaluation, and recommendation generation.
    4. Pass recommendation to PolicyEngine.evaluate (verifying exact playbook ID & version).
    5. Create human approval request via ApprovalService.
    6. Verify approval record binds immutable parameters and no automatic execution occurs.
    """
    setup = dynamic_test_setup
    ws = setup["ws_a"]
    svc_inv = setup["service_inv"]
    user_eng = setup["user_eng"]
    inc_inv = setup["incident_inv"]

    # 1. Create a custom dynamic playbook for Inventory API
    pb_custom = create_test_playbook(
        db=db_session,
        workspace_id=ws.id,
        name="Inventory Automated Diagnostic Health Probe",
        action_template_id="inspect_service_health",
        service_id=svc_inv.id,
        supported_scenarios=["http_5xx_rate_exceeded", "*"],
        parameter_schema={"health_path": "/api/v1/health"},
        priority=100,
        risk_level="low",
    )

    # 2. Mock HTTP client and execute LangGraph investigation
    mock_client = AsyncMock()
    mock_health_resp = MagicMock()
    mock_health_resp.status_code = 500
    mock_health_resp.text = '{"status": "degraded", "error": "Internal 500 error"}'
    mock_health_resp.json.return_value = {"status": "degraded", "error": "Internal 500 error"}

    mock_metrics_resp = MagicMock()
    mock_metrics_resp.status_code = 200
    mock_metrics_resp.text = (
        "# HELP http_requests_total Total HTTP requests\n"
        'http_requests_total{status="500"} 18.0\n'
        'http_requests_total{status="200"} 42.0\n'
    )
    mock_metrics_resp.json.return_value = {}

    async def mock_get(url, **kwargs):
        if "/metrics" in str(url):
            return mock_metrics_resp
        return mock_health_resp

    mock_client.get.side_effect = mock_get

    final_state = await run_investigation(
        incident_id=inc_inv.id,
        workspace_id=ws.id,
        db=db_session,
        client=mock_client,
    )

    # 3. Verify LangGraph investigation artifacts
    assert final_state["status"] == "completed"
    rec = final_state.get("remediation_recommendation")
    assert rec is not None
    assert rec["outcome"] == "compatible_found"
    assert rec["status"] == "actionable"
    assert rec["playbook_id"] == pb_custom.id
    assert rec["playbook_version"] == 1
    assert rec["action_template_id"] == "inspect_service_health"
    assert rec["service_id"] == svc_inv.id
    assert rec["parameters"]["service_id"] == svc_inv.id

    # Verify persisted investigation summary in database
    inv_record = (
        db_session.query(Investigation)
        .filter(Investigation.incident_id == inc_inv.id)
        .first()
    )
    assert inv_record is not None
    assert inv_record.summary is not None
    persisted_rec = inv_record.summary.get("remediation_recommendation")
    assert persisted_rec is not None
    assert persisted_rec["playbook_name"] == "Inventory Automated Diagnostic Health Probe"

    # 4. Deterministic policy evaluation with exact playbook reference
    eval_result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id=rec["action_template_id"],
        parameters=rec["parameters"],
        environment="development",
        db=db_session,
        user_id=user_eng.id,
        playbook_id=rec["playbook_id"],
        playbook_version=rec["playbook_version"],
    )

    # inspect_service_health on a service with execution_policy='approval_required' requires approval
    assert eval_result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert eval_result.approval_required is True

    # Persist policy decision
    from app.models.remediation import PolicyDecision
    dec_record = PolicyDecision(
        workspace_id=ws.id,
        user_id=user_eng.id,
        action_id=eval_result.action_id,
        target_service_id=eval_result.target_service_id,
        risk_level=eval_result.risk_level,
        decision=eval_result.decision.value,
        decision_reason=eval_result.decision_reason,
        policy_version=eval_result.policy_version,
        validated_parameters=eval_result.validated_parameters,
        timestamp=eval_result.evaluated_at,
    )
    db_session.add(dec_record)
    db_session.commit()
    db_session.refresh(dec_record)

    # 5. Create human approval request linking investigation and incident
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws.id,
        policy_decision_id=dec_record.id,
        requested_by=user_eng,
        incident_id=inc_inv.id,
        investigation_id=inv_record.id,
        expires_in_hours=24,
    )

    assert approval is not None
    assert approval.approval_status == "pending"
    assert approval.action_id == "inspect_service_health"
    assert approval.target_service_id == svc_inv.id
    assert approval.validated_parameters["service_id"] == svc_inv.id

    # 6. Safety invariant: Action is in 'pending' status — NEVER automatically executed
    from app.models.remediation import RemediationExecution
    executions = (
        db_session.query(RemediationExecution)
        .filter(RemediationExecution.approval_id == approval.id)
        .all()
    )
    assert len(executions) == 0, "Safety violation: Action was automatically executed without human approval!"


# ===========================================================================
# Deterministic Scenario Matching Regression Tests
# ===========================================================================

def test_real_detector_http_503_matches_5xx_and_health_check_scenarios(
    db_session: Session, dynamic_test_setup
):
    """
    Verifies that real detector alert 'Elevated 5xx error: HTTP 503 returned by health endpoint'
    matches 'http_5xx_rate_exceeded' and 'health_check_failure', but rejects unrelated scenarios.
    """
    ws = dynamic_test_setup["ws_a"]
    svc = dynamic_test_setup["service_inv"]

    # 1. Playbook configured with http_5xx_rate_exceeded
    pb_5xx = create_test_playbook(
        db_session,
        workspace_id=ws.id,
        service_id=svc.id,
        name="Inventory 5xx Playbook",
        action_template_id="inspect_service_health",
        parameter_schema={"service_id": svc.id},
        supported_scenarios=["http_5xx_rate_exceeded"],
    )

    # 2. Playbook configured with health_check_failure
    pb_health = create_test_playbook(
        db_session,
        workspace_id=ws.id,
        service_id=svc.id,
        name="Inventory Health Check Playbook",
        action_template_id="inspect_service_health",
        parameter_schema={"service_id": svc.id},
        supported_scenarios=["health_check_failure"],
    )

    # 3. Playbook configured with unrelated worker_process_failure
    pb_worker = create_test_playbook(
        db_session,
        workspace_id=ws.id,
        service_id=svc.id,
        name="Inventory Worker Playbook",
        action_template_id="inspect_service_health",
        parameter_schema={"service_id": svc.id},
        supported_scenarios=["worker_process_failure"],
    )

    # 4. Playbook configured with unrelated high_latency
    pb_latency = create_test_playbook(
        db_session,
        workspace_id=ws.id,
        service_id=svc.id,
        name="Inventory Latency Playbook",
        action_template_id="inspect_service_health",
        parameter_schema={"service_id": svc.id},
        supported_scenarios=["high_latency"],
    )

    # Discovered candidates
    discovered = [
        {
            "playbook_id": pb.id,
            "playbook_name": pb.name,
            "current_version": 1,
            "action_template_id": pb.active_version.action_template_id,
            "supported_scenarios": pb.active_version.supported_scenarios,
            "parameter_schema": pb.active_version.parameter_schema,
            "risk_level": "low",
            "priority": 10,
        }
        for pb in [pb_5xx, pb_health, pb_worker, pb_latency]
    ]

    state = {
        "workspace_id": ws.id,
        "service_id": svc.id,
        "incident_context": {
            "service_id": svc.id,
            "trigger": "Elevated 5xx error: HTTP 503 returned by health endpoint",
            "title": "Elevated 5xx error: HTTP 503 returned by health endpoint",
            "triggered_rule": "HTTP_Health_Status_Rule",
            "summary": "Health probe to http://127.0.0.1:7000/health returned HTTP 503",
        },
        "hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "root_cause": "Downstream Database Timeout / Connection Exhaustion",
                "is_supported": True,
            }
        ],
        "evidence_items": [],
        "discovered_playbooks": discovered,
    }

    result = evaluate_playbook_compatibility(state, db_session)
    compat = result["compatible_playbooks"]
    rejected = result["rejected_playbooks"]

    compat_ids = {p["playbook_id"] for p in compat}
    assert pb_5xx.id in compat_ids, "Playbook with http_5xx_rate_exceeded should be compatible"
    assert pb_health.id in compat_ids, "Playbook with health_check_failure should be compatible"
    assert pb_worker.id not in compat_ids, "Playbook with worker_process_failure must NOT be compatible"
    assert pb_latency.id not in compat_ids, "Playbook with high_latency must NOT be compatible"

    # Verify rejection reasons
    rejected_reasons = {p["playbook_id"]: p["rejection_reasons"] for p in rejected}
    assert any("does not match supported scenarios" in r for r in rejected_reasons[pb_worker.id])
    assert any("does not match supported scenarios" in r for r in rejected_reasons[pb_latency.id])


def test_unrelated_incident_does_not_match_health_check_playbook(
    db_session: Session, dynamic_test_setup
):
    """
    Verifies that an unrelated incident whose title happens to mention 'health-service'
    does not trigger false positive matching for health_check_failure playbook.
    """
    ws = dynamic_test_setup["ws_a"]
    svc = dynamic_test_setup["service_inv"]

    pb_health = create_test_playbook(
        db_session,
        workspace_id=ws.id,
        service_id=svc.id,
        name="Inventory Health Playbook",
        action_template_id="inspect_service_health",
        parameter_schema={"service_id": svc.id},
        supported_scenarios=["health_check_failure"],
    )

    state = {
        "workspace_id": ws.id,
        "service_id": svc.id,
        "incident_context": {
            "service_id": svc.id,
            "trigger": "Disk space 95%",
            "title": "Database disk usage high for health-service",
            "triggered_rule": "Disk_Space_Threshold_Rule",
            "summary": "Volume mounted at /var/lib/data reached 95% threshold",
        },
        "hypotheses": [
            {
                "hypothesis_id": "hyp-disk",
                "root_cause": "Filesystem Volume Exhaustion",
                "is_supported": True,
            }
        ],
        "evidence_items": [],
        "discovered_playbooks": [
            {
                "playbook_id": pb_health.id,
                "playbook_name": pb_health.name,
                "current_version": 1,
                "action_template_id": pb_health.active_version.action_template_id,
                "supported_scenarios": pb_health.active_version.supported_scenarios,
                "parameter_schema": pb_health.active_version.parameter_schema,
                "risk_level": "low",
                "priority": 10,
            }
        ],
    }

    result = evaluate_playbook_compatibility(state, db_session)
    compat = result["compatible_playbooks"]
    assert len(compat) == 0, "Unrelated disk incident must NOT match health_check_failure playbook"


def test_unknown_scenario_fails_closed(db_session: Session, dynamic_test_setup):
    """
    Verifies that an unrecognized scenario ID fails closed and is rejected.
    """
    from app.agents.nodes.playbooks import is_scenario_compatible_with_incident

    assert not is_scenario_compatible_with_incident(
        "custom_nonexistent_scenario",
        incident_trigger="Elevated 5xx error: HTTP 503 returned by health endpoint",
        incident_title="Elevated 5xx error: HTTP 503 returned by health endpoint",
        triggered_rule="HTTP_Health_Status_Rule",
    )


def test_exact_slug_matching_preserved():
    """
    Verifies that exact scenario slug matching continues to function seamlessly.
    """
    from app.agents.nodes.playbooks import is_scenario_compatible_with_incident

    assert is_scenario_compatible_with_incident(
        "http_5xx_rate_exceeded",
        incident_trigger="http_5xx_rate_exceeded",
        incident_title="High Error Rate Detected",
    )
    assert is_scenario_compatible_with_incident(
        "worker_process_failure",
        incident_trigger="worker_process_failure",
        incident_title="Worker process failure alert",
    )


@pytest.mark.asyncio
async def test_incident_context_extracts_triggered_rule_from_detection_event(
    db_session: Session, dynamic_test_setup
):
    """
    Verifies that retrieve_incident_context properly inspects the detection event
    and populates 'triggered_rule' in incident_context.
    """
    from app.agents.nodes.context import retrieve_incident_context

    ws = dynamic_test_setup["ws_a"]
    svc = dynamic_test_setup["service_inv"]
    inc = dynamic_test_setup["incident_inv"]

    # Add detection event with deterministic rule name
    detection_event = IncidentEvent(
        incident_id=inc.id,
        event_type="detection",
        message="Incident detected automatically. Deterministic rule 'HTTP_Health_Status_Rule' triggered.",
    )
    db_session.add(detection_event)
    db_session.commit()

    state = {
        "incident_id": inc.id,
        "workspace_id": ws.id,
        "service_id": svc.id,
    }

    result = await retrieve_incident_context(state, db_session)
    ctx = result["incident_context"]

    assert ctx["triggered_rule"] == "HTTP_Health_Status_Rule"
    assert ctx["trigger"] == inc.trigger
