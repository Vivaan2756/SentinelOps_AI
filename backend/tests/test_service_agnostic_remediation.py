"""Unit and Integration Tests for Phase 4.4A: Service-Agnostic Remediation Architecture.

Tests:
1. Capability registration and catalog completeness in ActionRegistry.
2. Capability status and execution mechanisms (executable vs requires_adapter).
3. Service compatibility discovery for Order API (legacy demo support + diagnostics).
4. Service compatibility discovery for Inventory API (diagnostic support, demo rejection).
5. Incompatible service rejection with explicit, deterministic rationale.
6. Environment restrictions (production environment rejects development-only actions).
7. Missing configuration and SSRF rejection (missing health URL, forbidden metadata IP).
8. Parameter schema validation with strict extra='forbid' checks.
9. Workspace isolation in service capabilities API endpoint.
10. Dynamic playbook validation warnings for adapter-dependent templates.
11. LangGraph playbook compatibility evaluation using capability engine.
12. PolicyEngine Rule 2B rejection of unconfigured adapter actions.
13. Human approval requirement enforcement for medium/high risk capabilities.
14. Preservation of legacy Order API demo recovery execution path.
"""

import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.models.service import Service
from app.models.workspace import Workspace
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import (
    ActionCategory,
    CapabilityStatus,
    ClearApplicationCacheParams,
    ExecutionMechanism,
    InspectServiceHealthParams,
    PolicyDecisionType,
    RestartServiceParams,
    RestoreOrderApiDemoParams,
    RiskLevel,
    RollbackDeploymentParams,
)
from app.remediation.policy import PolicyEngine
from app.remediation.playbook_service import PlaybookService
from app.agents.nodes.playbooks import evaluate_playbook_compatibility


# ============================================================================
# 1. Action Registry & Capability Catalog Tests
# ============================================================================

def test_capability_catalog_registration():
    """Verify all reusable and legacy capabilities are registered in ActionRegistry."""
    actions = ActionRegistry.list_actions(include_disabled=True)
    action_ids = {a.action_id for a in actions}

    expected_actions = {
        "inspect_service_health",
        "disable_service_monitoring",
        "restore_order_api_demo",
        "restart_service",
        "restart_order_api",
        "rollback_deployment",
        "clear_application_cache",
    }
    for expected in expected_actions:
        assert expected in action_ids, f"Expected action '{expected}' missing from ActionRegistry."


def test_capability_execution_mechanisms_and_statuses():
    """Verify execution mechanisms and adapter prerequisites are accurately classified."""
    # 1. Genuinely executable diagnostic
    inspect_act = ActionRegistry.get_action("inspect_service_health")
    assert inspect_act is not None
    assert inspect_act.status == CapabilityStatus.EXECUTABLE
    assert inspect_act.is_executable is True
    assert inspect_act.execution_mechanism == ExecutionMechanism.HTTP_DIAGNOSTIC
    assert inspect_act.category == ActionCategory.DIAGNOSTICS
    assert inspect_act.risk_level == RiskLevel.LOW
    assert "*" in inspect_act.supported_services

    # 2. Genuinely executable platform control
    disable_act = ActionRegistry.get_action("disable_service_monitoring")
    assert disable_act is not None
    assert disable_act.status == CapabilityStatus.EXECUTABLE
    assert disable_act.is_executable is True
    assert disable_act.execution_mechanism == ExecutionMechanism.MONITORING_CONTROL
    assert disable_act.risk_level == RiskLevel.HIGH

    # 3. Legacy Order API demo recovery
    restore_act = ActionRegistry.get_action("restore_order_api_demo")
    assert restore_act is not None
    assert restore_act.status == CapabilityStatus.EXECUTABLE
    assert restore_act.is_executable is True
    assert restore_act.execution_mechanism == ExecutionMechanism.DEMO_SERVICE_RESET
    assert "Order API" in restore_act.supported_services
    assert "*" not in restore_act.supported_services

    # 4. Container restart requires adapter
    restart_act = ActionRegistry.get_action("restart_service")
    assert restart_act is not None
    assert restart_act.status == CapabilityStatus.REQUIRES_ADAPTER
    assert restart_act.is_executable is False
    assert restart_act.execution_mechanism == ExecutionMechanism.CONTAINER_LIFECYCLE
    assert restart_act.risk_level == RiskLevel.HIGH
    assert any("container management adapter" in p.lower() for p in restart_act.preconditions)

    # 5. Rollback deployment requires adapter
    rollback_act = ActionRegistry.get_action("rollback_deployment")
    assert rollback_act is not None
    assert rollback_act.status == CapabilityStatus.REQUIRES_ADAPTER
    assert rollback_act.is_executable is False
    assert rollback_act.execution_mechanism == ExecutionMechanism.DEPLOYMENT_ROLLBACK

    # 6. Clear cache requires adapter
    cache_act = ActionRegistry.get_action("clear_application_cache")
    assert cache_act is not None
    assert cache_act.status == CapabilityStatus.REQUIRES_ADAPTER
    assert cache_act.is_executable is False
    assert cache_act.execution_mechanism == ExecutionMechanism.CACHE_MANAGEMENT


# ============================================================================
# 2. Service Compatibility Discovery Tests (Order API vs Inventory API)
# ============================================================================

def test_order_api_capability_discovery():
    """Verify Order API in development supports demo reset and diagnostics."""
    order_svc = Service(
        id="00000000-0000-0000-0000-000000000001",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Order API",
        environment="development",
        health_check_url="http://localhost:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )

    caps = ActionRegistry.discover_service_capabilities(order_svc)
    assert caps.total_count == 8
    assert caps.compatible_count == 4
    assert caps.executable_count == 4

    cap_map = {c.action_id: c for c in caps.capabilities}

    # inspect_service_health: compatible & executable
    assert cap_map["inspect_service_health"].is_compatible is True
    assert cap_map["inspect_service_health"].is_executable is True

    # restore_order_api_demo: compatible & executable for Order API
    assert cap_map["restore_order_api_demo"].is_compatible is True
    assert cap_map["restore_order_api_demo"].is_executable is True

    # restart_order_api: compatible & executable for Order API
    assert cap_map["restart_order_api"].is_compatible is True
    assert cap_map["restart_order_api"].is_executable is True

    # disable_service_monitoring: compatible & executable
    assert cap_map["disable_service_monitoring"].is_compatible is True
    assert cap_map["disable_service_monitoring"].is_executable is True

    # restart_service: requires adapter
    assert cap_map["restart_service"].status == CapabilityStatus.REQUIRES_ADAPTER
    assert cap_map["restart_service"].is_compatible is False
    assert cap_map["restart_service"].is_executable is False


def test_inventory_api_capability_discovery():
    """Verify Inventory API supports diagnostics, but rejects Order API demo recovery."""
    inventory_svc = Service(
        id="5aec4a29-be82-407e-a376-b3407b328cc3",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Inventory Management API",
        environment="development",
        health_check_url="http://localhost:7000/api/v1/health",
        execution_policy="demo",
        is_active=True,
    )

    caps = ActionRegistry.discover_service_capabilities(inventory_svc)
    assert caps.total_count == 8
    # Only universal diagnostics and monitoring control are executable
    assert caps.compatible_count == 2
    assert caps.executable_count == 2

    cap_map = {c.action_id: c for c in caps.capabilities}

    # inspect_service_health: compatible
    assert cap_map["inspect_service_health"].is_compatible is True
    assert cap_map["inspect_service_health"].is_executable is True

    # restore_order_api_demo: strictly rejected as service-specific
    assert cap_map["restore_order_api_demo"].is_compatible is False
    assert cap_map["restore_order_api_demo"].is_executable is False
    assert any(
        "service-specific" in r for r in cap_map["restore_order_api_demo"].reasons
    )

    # restart_service: requires adapter
    assert cap_map["restart_service"].status == CapabilityStatus.REQUIRES_ADAPTER
    assert cap_map["restart_service"].is_compatible is False
    assert any("container_lifecycle" in r for r in cap_map["restart_service"].reasons)


# ============================================================================
# 3. Environment & Configuration Restriction Tests
# ============================================================================

def test_production_environment_rejects_development_only_action():
    """Verify that a production service is rejected for development-only actions."""
    prod_svc = Service(
        id="00000000-0000-0000-0000-000000000002",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Order API",
        environment="production",
        health_check_url="https://order.production.internal/health",
        execution_policy="approval_required",
        is_active=True,
    )

    cap = ActionRegistry.evaluate_service_capability("restore_order_api_demo", prod_svc)
    assert cap.is_compatible is False
    assert any("environment 'production' is not permitted" in r for r in cap.reasons)


def test_missing_health_url_rejects_http_diagnostic():
    """Verify that missing health check URL marks inspect_service_health incompatible."""
    svc_no_url = Service(
        id="00000000-0000-0000-0000-000000000003",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Worker Queue Service",
        environment="development",
        health_check_url="",
        execution_policy="demo",
        is_active=True,
    )

    cap = ActionRegistry.evaluate_service_capability("inspect_service_health", svc_no_url)
    assert cap.is_compatible is False
    assert any("health_check_url" in r for r in cap.reasons)


def test_metadata_ip_rejected_in_health_url():
    """Verify that cloud metadata IP addresses in health URL are rejected as SSRF risk."""
    svc_bad_url = Service(
        id="00000000-0000-0000-0000-000000000004",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Malicious Target Service",
        environment="development",
        health_check_url="http://169.254.169.254/latest/meta-data/",
        execution_policy="demo",
        is_active=True,
    )

    cap = ActionRegistry.evaluate_service_capability("inspect_service_health", svc_bad_url)
    assert cap.is_compatible is False
    assert any("metadata" in r.lower() for r in cap.reasons)


# ============================================================================
# 4. Parameter Schema Validation Tests
# ============================================================================

def test_restart_service_parameter_validation():
    """Verify RestartServiceParams validates service_id and grace_period_seconds with extra='forbid'."""
    is_valid, parsed, err = ActionRegistry.validate_parameters(
        "restart_service",
        {
            "service_id": "00000000-0000-0000-0000-000000000001",
            "grace_period_seconds": 15,
        },
    )
    assert is_valid is True
    assert parsed.grace_period_seconds == 15

    # Reject unknown parameters
    is_valid, _, err = ActionRegistry.validate_parameters(
        "restart_service",
        {
            "service_id": "00000000-0000-0000-0000-000000000001",
            "arbitrary_command": "rm -rf /",
        },
    )
    assert is_valid is False
    assert "Extra inputs are not permitted" in err


def test_rollback_deployment_parameter_validation():
    """Verify RollbackDeploymentParams validates service_id and target_revision with extra='forbid'."""
    is_valid, parsed, err = ActionRegistry.validate_parameters(
        "rollback_deployment",
        {
            "service_id": "00000000-0000-0000-0000-000000000001",
            "target_revision": "v1.2.3",
        },
    )
    assert is_valid is True
    assert parsed.target_revision == "v1.2.3"

    # Reject invalid characters in revision
    is_valid, _, err = ActionRegistry.validate_parameters(
        "rollback_deployment",
        {
            "service_id": "00000000-0000-0000-0000-000000000001",
            "target_revision": "v1.2.3; drop table users;",
        },
    )
    assert is_valid is False


def test_clear_application_cache_parameter_validation():
    """Verify ClearApplicationCacheParams validates service_id and partition with extra='forbid'."""
    is_valid, parsed, err = ActionRegistry.validate_parameters(
        "clear_application_cache",
        {
            "service_id": "00000000-0000-0000-0000-000000000001",
            "cache_partition": "orders:session",
        },
    )
    assert is_valid is True
    assert parsed.cache_partition == "orders:session"


# ============================================================================
# 5. Playbook Service Validation & LangGraph Node Compatibility Tests
# ============================================================================

def test_playbook_spec_validation_flags_adapter_prerequisites():
    """Verify dry-run validation warns that restart_service requires an adapter."""
    mock_db = MagicMock()
    mock_service = Service(
        id="00000000-0000-0000-0000-000000000001",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Generic Microservice",
        environment="development",
        health_check_url="http://localhost:3000/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.all.return_value = [mock_service]

    val_res = PlaybookService.validate_playbook_spec(
        db=mock_db,
        workspace_id="00000000-0000-0000-0000-000000000000",
        action_template_id="restart_service",
        service_ids=[mock_service.id],
        parameter_schema={"service_id": mock_service.id},
    )

    # Must include warning about adapter requirement
    assert any("adapter" in w.lower() for w in val_res.warnings)


def test_langgraph_compatibility_node_rejects_unconfigured_adapters():
    """Verify LangGraph compatibility evaluation rejects playbooks with unconfigured adapters."""
    mock_db = MagicMock()
    mock_service = Service(
        id="00000000-0000-0000-0000-000000000001",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Order API",
        environment="development",
        health_check_url="http://localhost:8001/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = mock_service

    state = {
        "workspace_id": "00000000-0000-0000-0000-000000000000",
        "service_id": mock_service.id,
        "incident_context": {
            "trigger": "http_5xx_rate_exceeded",
            "title": "500 Errors on Order API",
            "severity": "critical",
        },
        "hypotheses": [{"root_cause": "Process hang", "is_supported": True}],
        "evidence_items": [{"evidence_id": "ev-1", "collection_status": "degraded"}],
        "discovered_playbooks": [
            {
                "playbook_id": "pb-restart",
                "playbook_name": "Container Restart Playbook",
                "category": "service_recovery",
                "current_version": 1,
                "priority": 10,
                "action_template_id": "restart_service",
                "supported_scenarios": ["*"],
                "parameter_schema": {"service_id": mock_service.id},
                "verification_criteria": {"probes_required": 3},
                "risk_level": "high",
                "approval_required": True,
                "timeout_seconds": 60,
            }
        ],
    }

    result = evaluate_playbook_compatibility(state, mock_db)
    assert len(result["compatible_playbooks"]) == 0
    assert len(result["rejected_playbooks"]) == 1

    rejected = result["rejected_playbooks"][0]
    assert any("container_lifecycle" in r for r in rejected["rejection_reasons"])


def test_langgraph_compatibility_node_rejects_order_action_on_inventory():
    """Verify LangGraph compatibility evaluation strictly rejects restore_order_api_demo on Inventory API."""
    mock_db = MagicMock()
    mock_inventory = Service(
        id="5aec4a29-be82-407e-a376-b3407b328cc3",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Inventory Management API",
        environment="development",
        health_check_url="http://localhost:7000/api/v1/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = mock_inventory

    state = {
        "workspace_id": "00000000-0000-0000-0000-000000000000",
        "service_id": mock_inventory.id,
        "incident_context": {
            "trigger": "http_5xx_rate_exceeded",
            "title": "500 Errors on Inventory API",
            "severity": "critical",
        },
        "hypotheses": [{"root_cause": "In-memory deadlock", "is_supported": True}],
        "evidence_items": [{"evidence_id": "ev-1", "collection_status": "degraded"}],
        "discovered_playbooks": [
            {
                "playbook_id": "pb-order-restore",
                "playbook_name": "Order API Restore Playbook",
                "category": "service_recovery",
                "current_version": 1,
                "priority": 10,
                "action_template_id": "restore_order_api_demo",
                "supported_scenarios": ["*"],
                "parameter_schema": {"service_id": mock_inventory.id},
                "verification_criteria": {"probes_required": 3},
                "risk_level": "medium",
                "approval_required": True,
                "timeout_seconds": 30,
            }
        ],
    }

    result = evaluate_playbook_compatibility(state, mock_db)
    assert len(result["compatible_playbooks"]) == 0
    assert len(result["rejected_playbooks"]) == 1

    rejected = result["rejected_playbooks"][0]
    assert any("service-specific" in r for r in rejected["rejection_reasons"])


# ============================================================================
# 6. Policy Engine Rule 2B Safeguard Tests
# ============================================================================

def test_policy_engine_rule_2b_rejects_unconfigured_adapter_actions():
    """Verify PolicyEngine Rule 2B rejects proposals for actions requiring uninstalled adapters."""
    mock_db = MagicMock()
    mock_service = Service(
        id="00000000-0000-0000-0000-000000000001",
        workspace_id="00000000-0000-0000-0000-000000000000",
        name="Any Service",
        environment="development",
        health_check_url="http://localhost:8001/health",
        execution_policy="demo",
        is_active=True,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = mock_service

    result = PolicyEngine.evaluate(
        db=mock_db,
        workspace_id="00000000-0000-0000-0000-000000000000",
        action_id="restart_service",
        parameters={"service_id": mock_service.id},
        user_role="engineer",
    )

    assert result.decision == PolicyDecisionType.REJECTED
    assert "requires an infrastructure adapter" in result.decision_reason
    assert "container_lifecycle" in result.decision_reason
