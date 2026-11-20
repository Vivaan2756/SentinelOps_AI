"""Unit and integration tests for service-specific remediation and verification.

Proves:
1. Cab Booking API cannot receive Order API recovery.
2. Services without playbooks cannot generate executable proposals.
3. Order API retains its workflow.
4. Verification uses registered endpoints.
5. Custom paths are preserved.
6. Workspace isolation & SSRF protections hold.
7. Monitoring provider correctness (opentelemetry vs prometheus).
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from app.execution.actions import (
    handle_restore_order_api_demo,
    validate_restore_order_api_demo_preconditions,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    PreconditionFailedError,
)
from app.execution.network import (
    build_container_network_config,
    resolve_safe_target_url,
    validate_safe_target_url,
)
from app.execution.runner import ExecutionResult, MockTestRunner
from app.execution.verification import (
    PostExecutionVerificationEngine,
    ProbeStatus,
    VerificationOutcome,
)
from app.models.incident import Incident
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.approval_service import ApprovalService
from app.remediation.policy import PolicyEngine
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import PolicyDecisionType
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from services.executor.runner import run_inspect_service_health


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def multi_service_context(db_session):
    """Sets up a workspace, admin user, Order API service, and Cab Booking service."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Multi-Service Workspace",
        slug="multi-service-ws",
    )
    db_session.add(ws)

    user = User(
        id=str(uuid.uuid4()),
        email="sre@example.com",
        full_name="SRE Engineer",
        hashed_password="hashed_pw",
    )
    db_session.add(user)

    membership = WorkspaceMembership(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=user.id,
        role="engineer",
    )
    db_session.add(membership)

    # 1. Order API Service (has registered recovery playbook)
    order_api = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )
    db_session.add(order_api)

    # 2. Cab Booking API 2 (no registered recovery playbooks)
    cab_booking = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Cab Booking API 2",
        environment="development",
        health_check_url="http://localhost:9000/api/v1/system/health",
        monitoring_method="opentelemetry",
        execution_policy="demo",
        is_active=True,
    )
    db_session.add(cab_booking)

    db_session.commit()

    return {
        "workspace": ws,
        "user": user,
        "order_api": order_api,
        "cab_booking": cab_booking,
    }


# ============================================================================
# 1. Cab Booking API cannot receive Order API recovery
# ============================================================================

def test_cab_booking_api_policy_evaluation_rejects_order_api_recovery(
    db_session, multi_service_context
):
    """PolicyEngine rejects restore_order_api_demo for Cab Booking API."""
    ctx = multi_service_context
    result = PolicyEngine.evaluate(
        workspace_id=ctx["workspace"].id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": ctx["cab_booking"].id},
        environment="development",
        db=db_session,
    )

    assert result.decision == PolicyDecisionType.REJECTED
    assert result.decision_reason == "No approved remediation playbook is configured for this service."


def test_cab_booking_api_validate_preconditions_fails(multi_service_context):
    """validate_restore_order_api_demo_preconditions fails for Cab Booking API."""
    cab_svc = multi_service_context["cab_booking"]
    with pytest.raises(PreconditionFailedError) as exc_info:
        validate_restore_order_api_demo_preconditions(cab_svc)
    assert "not supported for service 'Cab Booking API 2'" in str(exc_info.value)


def test_cab_booking_api_handle_action_fails(multi_service_context):
    """handle_restore_order_api_demo fails closed for Cab Booking API."""
    cab_svc = multi_service_context["cab_booking"]
    mock_runner = MockTestRunner()
    with pytest.raises(PreconditionFailedError) as exc_info:
        handle_restore_order_api_demo(
            service=cab_svc,
            parameters={"service_id": cab_svc.id},
            runner=mock_runner,
        )
    assert "not supported for service 'Cab Booking API 2'" in str(exc_info.value)


# ============================================================================
# 2. Services without playbooks cannot generate executable proposals
# ============================================================================

def test_service_without_playbooks_cannot_create_approval(
    db_session, multi_service_context
):
    """ApprovalService refuses to create an approval proposal for unconfigured service."""
    from fastapi import HTTPException
    ctx = multi_service_context

    # Simulate an invalid/tampered PolicyDecision that tried to allow restore_order_api_demo
    tampered_decision = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        user_id=ctx["user"].id,
        action_id="restore_order_api_demo",
        target_service_id=ctx["cab_booking"].id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Tampered decision",
        policy_version="v1.0",
        validated_parameters={"service_id": ctx["cab_booking"].id},
    )
    db_session.add(tampered_decision)
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        ApprovalService.create_approval_request(
            db=db_session,
            workspace_id=ctx["workspace"].id,
            policy_decision_id=tampered_decision.id,
            requested_by=ctx["user"],
        )
    assert exc_info.value.status_code == 400
    assert "No approved remediation playbook is configured for this service." in exc_info.value.detail


def test_service_without_playbooks_cannot_create_execution(
    db_session, multi_service_context
):
    """RemediationExecutionManager rejects execution if service has no playbook."""
    from app.execution.manager import RemediationExecutionManager
    ctx = multi_service_context

    # Simulate an approved proposal that bypassed earlier checks
    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        policy_decision_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=ctx["cab_booking"].id,
        validated_parameters={"service_id": ctx["cab_booking"].id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=ctx["user"].id,
        reviewed_by=ctx["user"].id,
        approval_status="approved",
        requested_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(approval)
    db_session.commit()

    with pytest.raises(PreconditionFailedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ctx["workspace"].id,
            approval_id=approval.id,
            idempotency_key="idemp-key-1",
            triggered_by=ctx["user"],
            user_role="engineer",
        )
    assert "No approved remediation playbook is configured for this service." in str(exc_info.value)


# ============================================================================
# 3. Order API retains its workflow
# ============================================================================

def test_order_api_policy_evaluation_allows_proposal(
    db_session, multi_service_context
):
    """Order API successfully passes policy evaluation for restore_order_api_demo."""
    ctx = multi_service_context
    result = PolicyEngine.evaluate(
        workspace_id=ctx["workspace"].id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": ctx["order_api"].id},
        environment="development",
        db=db_session,
    )

    assert result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert result.approval_required is True
    assert result.action_id == "restore_order_api_demo"


def test_playbooks_catalog_query(multi_service_context):
    """ActionRegistry accurately reflects per-service playbooks."""
    ctx = multi_service_context

    order_playbooks = ActionRegistry.get_playbooks_for_service(ctx["order_api"])
    order_action_ids = [p.action_id for p in order_playbooks]
    assert "restore_order_api_demo" in order_action_ids
    assert "restart_order_api" in order_action_ids

    cab_playbooks = ActionRegistry.get_playbooks_for_service(ctx["cab_booking"])
    assert len(cab_playbooks) == 0


def test_dynamic_service_playbook_registration(multi_service_context):
    """Dynamic registration permits safe customization per service ID."""
    ctx = multi_service_context
    cab_id = ctx["cab_booking"].id

    try:
        assert not ActionRegistry.is_action_supported_for_service("restore_order_api_demo", ctx["cab_booking"])

        # Dynamically register custom action for Cab Booking
        ActionRegistry.register_service_playbook(cab_id, ["inspect_service_health"])
        assert ActionRegistry.is_action_supported_for_service("inspect_service_health", ctx["cab_booking"])
        assert not ActionRegistry.is_action_supported_for_service("restore_order_api_demo", ctx["cab_booking"])
    finally:
        ActionRegistry.unregister_service_playbook(cab_id)


# ============================================================================
# 4. Verification uses registered endpoints & preserves custom paths
# ============================================================================

def test_custom_paths_preserved_in_network_config():
    """build_container_network_config preserves custom health check path."""
    config = build_container_network_config(
        environment="development",
        raw_service_url="http://localhost:9000/api/v1/system/health",
        action_id="inspect_service_health",
    )
    container_url, network_kwargs = config
    assert container_url == "http://host.docker.internal:9000/api/v1/system/health"
    assert config.target.path == "/api/v1/system/health"
    assert config.target.port == 9000


def test_verification_engine_uses_registered_custom_path(
    db_session, multi_service_context
):
    """Verification engine dispatches to service's exact health_check_url."""
    ctx = multi_service_context
    cab_svc = ctx["cab_booking"]

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=45,
        output_data={
            "endpoints": {
                "health": {
                    "status_code": 200,
                    "success": True,
                    "output_data": {"status": "healthy"},
                }
            }
        },
    )

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        action_id="inspect_service_health",
        status="verification_pending",
        target_service_id=cab_svc.id,
        fencing_token=1,
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    probe = engine.execute_single_probe(
        service=cab_svc,
        probe_number=1,
        probe_type="baseline",
        runner=mock_runner,
        action_id="inspect_service_health",
    )

    # Dispatched URL must be Cab Booking API's registered custom health URL
    assert probe.target_url == "http://localhost:9000/api/v1/system/health"
    assert probe.passed is True
    assert probe.status == ProbeStatus.PASSED.value

    # Verify runner was called with the exact registered custom health URL
    call_args = mock_runner.execute.call_args[1]
    assert call_args["target_url"] == "http://localhost:9000/api/v1/system/health"
    assert call_args["parameters"]["health_path"] == "/api/v1/system/health"
    assert call_args["parameters"]["is_demo_service"] is False


def test_verification_engine_order_api_requires_demo_status_and_metrics(
    db_session, multi_service_context
):
    """Order API verification requires /demo/status and 5xx metrics."""
    ctx = multi_service_context
    order_svc = ctx["order_api"]

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True

    # Return health 200, but demo failure active
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=45,
        output_data={
            "endpoints": {
                "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}},
                "demo_status": {"status_code": 200, "output_data": {"failure_active": True, "failure_reason": "Injected fault"}},
                "metrics": {"status_code": 200, "raw_text": "order_api_http_5xx_errors_total 5\n"},
            }
        },
    )

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        status="verification_pending",
        target_service_id=order_svc.id,
        fencing_token=1,
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    probe = engine.execute_single_probe(
        service=order_svc,
        probe_number=2,
        probe_type="health_check",
        runner=mock_runner,
        action_id="restore_order_api_demo",
    )

    # Fails because demo failure is active
    assert probe.passed is False
    assert probe.status == ProbeStatus.FAILED.value
    assert "GET /demo/status reports active failure" in probe.error_message


# ============================================================================
# 5. Workspace isolation & SSRF protections hold
# ============================================================================

def test_cross_workspace_policy_evaluation_rejected(
    db_session, multi_service_context
):
    """Cross-workspace service references are rejected by PolicyEngine."""
    ctx = multi_service_context

    # Create second workspace
    other_ws = Workspace(
        id=str(uuid.uuid4()),
        name="Other Workspace",
        slug="other-ws",
    )
    db_session.add(other_ws)
    db_session.commit()

    result = PolicyEngine.evaluate(
        workspace_id=other_ws.id,
        user_role="admin",
        action_id="restore_order_api_demo",
        parameters={"service_id": ctx["order_api"].id},
        environment="development",
        db=db_session,
    )

    assert result.decision == PolicyDecisionType.REJECTED
    assert "Cross-workspace violation" in result.decision_reason


def test_ssrf_protection_on_custom_paths():
    """Metadata IPs and userinfo credentials are blocked even on custom paths."""
    # Cloud metadata IP
    with pytest.raises(BrokerSecurityViolation) as exc:
        validate_safe_target_url(
            "http://169.254.169.254:9000/api/v1/system/health",
            environment="development",
            action_id="inspect_service_health",
        )
    assert "forbidden cloud metadata endpoint" in str(exc.value)

    # Userinfo credentials
    with pytest.raises(BrokerSecurityViolation) as exc:
        validate_safe_target_url(
            "http://admin:secret@localhost:9000/api/v1/system/health",
            environment="development",
            action_id="inspect_service_health",
        )
    assert "Embedded credentials" in str(exc.value)


# ============================================================================
# 6. Monitoring provider correctness (opentelemetry vs prometheus)
# ============================================================================

@pytest.mark.asyncio
async def test_prober_skips_prometheus_scrape_for_opentelemetry():
    """probe_service does not query /metrics when monitoring_method is opentelemetry."""
    from app.detector.prober import probe_service
    import httpx

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "healthy"}'

    async def mock_get(url):
        return mock_resp

    mock_client.get = mock_get

    probe = await probe_service(
        health_url="http://localhost:9000/api/v1/system/health",
        client=mock_client,
        monitoring_method="opentelemetry",
    )

    assert probe.is_reachable is True
    # Metrics map must be empty because prometheus scrape was not attempted
    assert probe.metrics_data == {}
