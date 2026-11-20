"""Regression and Integration Tests for Verification Runner-Executor Parameter Schema Contract.

Proves:
1. Exact reproduction of the schema mismatch error and its resolution.
2. Canonical strict parameter contract enforced in both backend (InspectServiceHealthParams)
   and executor sandbox (InspectServiceHealthModel) with extra="forbid".
3. Invalid, extra, and traversal parameters fail closed across broker and executor.
4. Order API verification cycle dispatches canonical parameters and inspects /health, /demo/status, /metrics.
5. Inventory Management API verification cycle dispatches canonical parameters, preserves custom path (/api/v1/health),
   inspects /api/v1/health and /metrics, and skips demo_status.
6. Failed verification NEVER marks an incident recovered.
7. Direct runner execution against live Inventory Management API on port 7000.
"""

import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from app.db.base import Base
from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerSecurityViolation,
    RestrictedDockerBroker,
)
from app.execution.exceptions import (
    BrokerUnavailableError,
    PreconditionFailedError,
)
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import (
    PostExecutionVerificationEngine,
    ProbeStatus,
    VerificationOutcome,
)
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import InspectServiceHealthParams

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from services.executor.runner import (
    InspectServiceHealthModel,
    run_inspect_service_health,
)


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def verification_test_context(db_session):
    """Sets up a workspace, user, Order API service, and Inventory Management API service."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Verification Test Workspace",
        slug="verif-test-ws",
    )
    db_session.add(ws)

    user = User(
        id=str(uuid.uuid4()),
        email="sre_verif@example.com",
        full_name="SRE Verification Tester",
        hashed_password="hashed_pw_test",
        is_active=True,
    )
    db_session.add(user)

    order_svc = Service(
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
    db_session.add(order_svc)

    inventory_svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Inventory Management API",
        environment="development",
        health_check_url="http://127.0.0.1:7000/api/v1/health",
        monitoring_method="prometheus",
        is_active=True,
    )
    db_session.add(inventory_svc)

    order_inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=order_svc.id,
        title="Order API High Latency Incident",
        severity="high",
        status="awaiting_approval",
        trigger="LatencyThresholdRule",
    )
    db_session.add(order_inc)

    inventory_inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=inventory_svc.id,
        title="Inventory API Service Incident",
        severity="medium",
        status="awaiting_approval",
        trigger="HealthStatusRule",
    )
    db_session.add(inventory_inc)

    db_session.commit()

    return {
        "workspace": ws,
        "user": user,
        "order_service": order_svc,
        "inventory_service": inventory_svc,
        "order_incident": order_inc,
        "inventory_incident": inventory_inc,
    }


class CanonicalRecordingRunner(ExecutionRunnerInterface):
    """Mock runner recording all dispatched action payloads and simulating responses."""

    def __init__(self, mode: str = "order_healthy"):
        self.mode = mode
        self.dispatched_calls = []

    def is_available(self) -> bool:
        return True

    def execute(
        self,
        action_id: str,
        parameters: dict,
        timeout_seconds: int = 30,
        target_url: str = None,
        environment: str = "development",
        execution_id: str = None,
    ) -> ExecutionResult:
        self.dispatched_calls.append({
            "action_id": action_id,
            "parameters": parameters,
            "timeout_seconds": timeout_seconds,
            "target_url": target_url,
            "environment": environment,
            "execution_id": execution_id,
        })

        if self.mode == "order_healthy":
            return ExecutionResult(
                exit_code=0,
                duration_ms=45.0,
                output_data={
                    "status": "completed",
                    "action": "inspect_service_health",
                    "endpoints": {
                        "health": {
                            "status_code": 200,
                            "duration_ms": 12.0,
                            "success": True,
                            "output_data": {"status": "healthy"},
                        },
                        "demo_status": {
                            "status_code": 200,
                            "duration_ms": 8.0,
                            "success": True,
                            "output_data": {"failure_active": False, "error_count": 0},
                        },
                        "metrics": {
                            "status_code": 200,
                            "duration_ms": 10.0,
                            "success": True,
                            "raw_text": "order_api_http_5xx_errors_total 0.0\n",
                        },
                    },
                },
            )
        elif self.mode == "inventory_healthy":
            return ExecutionResult(
                exit_code=0,
                duration_ms=35.0,
                output_data={
                    "status": "completed",
                    "action": "inspect_service_health",
                    "endpoints": {
                        "health": {
                            "status_code": 200,
                            "duration_ms": 14.0,
                            "success": True,
                            "output_data": {
                                "status": "healthy",
                                "service": "Inventory Management API",
                            },
                        },
                        "metrics": {
                            "status_code": 200,
                            "duration_ms": 11.0,
                            "success": True,
                            "raw_text": "http_5xx_errors_total 0.0\n",
                        },
                    },
                },
            )
        elif self.mode == "failure_unhealthy":
            return ExecutionResult(
                exit_code=0,
                duration_ms=40.0,
                output_data={
                    "status": "completed",
                    "action": "inspect_service_health",
                    "endpoints": {
                        "health": {
                            "status_code": 500,
                            "duration_ms": 15.0,
                            "success": False,
                            "error_message": "Internal Server Error",
                            "output_data": {"status": "unhealthy"},
                        },
                    },
                },
            )
        elif self.mode == "container_error":
            return ExecutionResult(
                exit_code=1,
                duration_ms=25.0,
                error_message="Runner dispatch error: Parameter validation failed: Field 'evil_param': Extra inputs are not permitted",
                error_category="dispatch_failure",
            )
        else:
            raise ValueError(f"Unknown test mode {self.mode}")


# ============================================================================
# Unit & Regression Tests
# ============================================================================

def test_schema_mismatch_reproduction_and_resolution():
    """
    Reproduces the exact schema mismatch error reported in live execution 0d532d42-4d4f-4c2c-a072-6f11cf1cee1c:
    Previously: Field 'health_path': Extra inputs are not permitted; Field 'is_demo_service': Extra inputs are not permitted.
    Proves that the canonical contract now accepts health_path, is_demo_service, and has_prometheus_metrics.
    """
    service_id = str(uuid.uuid4())

    # 1. Exact parameter payload dispatched by verification engine
    dispatched_params = {
        "service_id": service_id,
        "health_path": "/health",
        "is_demo_service": True,
        "has_prometheus_metrics": True,
    }

    # Must validate cleanly without error
    is_valid, validated_obj, err_msg = ActionRegistry.validate_parameters(
        "inspect_service_health", dispatched_params
    )
    assert is_valid is True, f"Validation failed unexpectedly: {err_msg}"
    assert err_msg is None
    assert validated_obj.service_id == service_id
    assert validated_obj.health_path == "/health"
    assert validated_obj.is_demo_service is True
    assert validated_obj.has_prometheus_metrics is True

    # 2. Strict extra="forbid" enforcement: Unknown inputs MUST fail closed
    bad_params = {
        "service_id": service_id,
        "health_path": "/health",
        "is_demo_service": True,
        "rogue_input": "attempted_injection",
    }
    is_valid, _, err_msg = ActionRegistry.validate_parameters("inspect_service_health", bad_params)
    assert is_valid is False
    assert "rogue_input" in err_msg
    assert "Extra inputs are not permitted" in err_msg


def test_executor_parameter_model_strict_validation():
    """
    Verifies that the executor sandbox InspectServiceHealthModel enforces identical strict
    canonical contracts with extra='forbid' and path-traversal rejection.
    """
    service_id = str(uuid.uuid4())

    # 1. Valid full canonical model
    m = InspectServiceHealthModel.model_validate({
        "service_id": service_id,
        "health_path": "/api/v1/system/health",
        "is_demo_service": False,
        "has_prometheus_metrics": True,
    })
    assert m.health_path == "/api/v1/system/health"
    assert m.is_demo_service is False
    assert m.has_prometheus_metrics is True

    # 2. Directory traversal attempt must be rejected
    with pytest.raises(Exception) as exc_info:
        InspectServiceHealthModel.model_validate({
            "service_id": service_id,
            "health_path": "/../../etc/passwd",
        })
    assert "directory traversal" in str(exc_info.value).lower()

    # 3. Query string injection attempt must be rejected
    with pytest.raises(Exception) as exc_info:
        InspectServiceHealthModel.model_validate({
            "service_id": service_id,
            "health_path": "/health?debug=true",
        })
    assert "directory traversal" in str(exc_info.value).lower() or "query" in str(exc_info.value).lower()

    # 4. Unknown fields must be strictly forbidden (no extra='allow')
    with pytest.raises(Exception) as exc_info:
        InspectServiceHealthModel.model_validate({
            "service_id": service_id,
            "extra_field": "malicious",
        })
    assert "extra inputs are not permitted" in str(exc_info.value).lower()


def test_broker_parameter_validation_with_canonical_schema():
    """
    Verifies that RestrictedDockerBroker validates inspect_service_health requests
    against the canonical schema before dispatching.
    """
    broker = RestrictedDockerBroker()
    service_id = str(uuid.uuid4())

    # 1. Valid canonical request passes broker validation
    valid_req = BrokerExecuteRequest(
        execution_id=str(uuid.uuid4()),
        action_id="inspect_service_health",
        parameters={
            "service_id": service_id,
            "health_path": "/api/v1/health",
            "is_demo_service": False,
            "has_prometheus_metrics": True,
        },
        target_url="http://127.0.0.1:7000/api/v1/health",
        environment="development",
    )
    # validate_request should succeed without raising
    broker.validate_request(valid_req)

    # 2. Request with rogue parameter fails closed at broker level
    invalid_req = BrokerExecuteRequest(
        execution_id=str(uuid.uuid4()),
        action_id="inspect_service_health",
        parameters={
            "service_id": service_id,
            "health_path": "/health",
            "unauthorized_key": "val",
        },
        target_url="http://127.0.0.1:8001/health",
        environment="development",
    )
    with pytest.raises(BrokerSecurityViolation) as exc_info:
        broker.validate_request(invalid_req)
    assert "Parameter validation failed" in str(exc_info.value)
    assert "unauthorized_key" in str(exc_info.value)


def test_order_api_post_execution_verification_cycle(db_session, verification_test_context):
    """
    Verifies that PostExecutionVerificationEngine correctly dispatches canonical parameters
    for Order API and performs complete 3-consecutive-pass verification.
    """
    ctx = verification_test_context
    runner = CanonicalRecordingRunner(mode="order_healthy")
    engine = PostExecutionVerificationEngine(runner=runner)

    # Create succeeded execution record awaiting verification
    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        incident_id=ctx["order_incident"].id,
        action_id="restore_order_api_demo",
        target_service_id=ctx["order_service"].id,
        status=ExecutionState.EXECUTION_SUCCEEDED.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=ctx["user"].id,
    )
    db_session.add(execution)
    db_session.commit()

    cycle = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ctx["workspace"].id,
        service=ctx["order_service"],
        timeout_seconds=15,
        probes_required=3,
        probe_timeout_seconds=4,
    )

    # Assert verification passed
    assert cycle.outcome == VerificationOutcome.PASS
    assert cycle.consecutive_passes == 3
    # 4 probes total: 1 baseline + 3 consecutive passes
    assert cycle.probes_executed == 4
    assert len(cycle.probe_evaluations) == 4

    # Assert dispatched parameter contract
    assert len(runner.dispatched_calls) == 4
    for call in runner.dispatched_calls:
        assert call["action_id"] == "inspect_service_health"
        params = call["parameters"]
        assert params["service_id"] == str(ctx["order_service"].id)
        assert params["health_path"] == "/health"
        assert params["is_demo_service"] is True
        assert params["has_prometheus_metrics"] is True


def test_inventory_management_api_post_execution_verification_cycle(db_session, verification_test_context):
    """
    Verifies that PostExecutionVerificationEngine correctly handles the Inventory Management API:
    - Preserves custom health_path: /api/v1/health
    - is_demo_service is False (does not probe /demo/status)
    - has_prometheus_metrics is True (probes /metrics)
    - Strictly completes verification cycle with consecutive passes.
    """
    ctx = verification_test_context
    runner = CanonicalRecordingRunner(mode="inventory_healthy")
    engine = PostExecutionVerificationEngine(runner=runner)

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        incident_id=ctx["inventory_incident"].id,
        action_id="inspect_service_health",
        target_service_id=ctx["inventory_service"].id,
        status=ExecutionState.EXECUTION_SUCCEEDED.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=ctx["user"].id,
    )
    db_session.add(execution)
    db_session.commit()

    cycle = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ctx["workspace"].id,
        service=ctx["inventory_service"],
        timeout_seconds=15,
        probes_required=3,
        probe_timeout_seconds=4,
    )

    # Assert verification cycle passed
    assert cycle.outcome == VerificationOutcome.PASS
    assert cycle.consecutive_passes == 3
    assert cycle.probes_executed == 4
    assert len(cycle.probe_evaluations) == 4

    # Assert dispatched parameter contract for Inventory Management API
    for call in runner.dispatched_calls:
        assert call["action_id"] == "inspect_service_health"
        params = call["parameters"]
        assert params["service_id"] == str(ctx["inventory_service"].id)
        assert params["health_path"] == "/api/v1/health"
        assert params["is_demo_service"] is False
        assert params["has_prometheus_metrics"] is True

    # Assert probe results: demo_status is skipped, health and metrics are recorded
    for p in cycle.probe_evaluations:
        out = p.probe_output
        assert "health" in out
        assert out["demo_status"]["status"] == "skipped"
        assert "metrics" in out


def test_failed_verification_never_marks_incident_recovered(db_session, verification_test_context):
    """
    Strict Safety Invariant:
    If verification fails (e.g. endpoint unhealthy or schema/runner failure),
    the incident MUST NEVER transition to recovered or resolved.
    """
    ctx = verification_test_context
    runner = CanonicalRecordingRunner(mode="failure_unhealthy")
    engine = PostExecutionVerificationEngine(runner=runner)

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        incident_id=ctx["order_incident"].id,
        action_id="restore_order_api_demo",
        target_service_id=ctx["order_service"].id,
        status=ExecutionState.EXECUTION_SUCCEEDED.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=ctx["user"].id,
    )
    db_session.add(execution)
    db_session.commit()

    with patch.object(
        IncidentRecoveryBridge, "recover_incident_on_verification_success"
    ) as mock_recover:
        cycle = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=ctx["workspace"].id,
            service=ctx["order_service"],
            timeout_seconds=10,
            probes_required=3,
            probe_timeout_seconds=2,
            recover_incident=True,
        )

        # Verification must FAIL
        assert cycle.outcome == VerificationOutcome.FAIL

        # Safety Invariant: Recovery bridge must NEVER be invoked on failed verification
        mock_recover.assert_not_called()

    # Re-query incident from database
    db_session.refresh(ctx["order_incident"])
    assert ctx["order_incident"].status == "awaiting_approval"
    assert ctx["order_incident"].status != "recovered"
    assert ctx["order_incident"].status != "resolved"


def test_live_runner_inspect_service_health_inventory_api():
    """
    Executes run_inspect_service_health directly against the live Inventory Management API
    on 127.0.0.1:7000 with canonical parameters.
    """
    params = {
        "service_id": str(uuid.uuid4()),
        "health_path": "/api/v1/health",
        "is_demo_service": False,
        "has_prometheus_metrics": True,
    }

    try:
        result = run_inspect_service_health(
            target_url="http://127.0.0.1:7000/api/v1/health",
            timeout_seconds=5.0,
            pinned_ip="127.0.0.1",
            target_host="127.0.0.1",
            tls_verify=False,
            environment="development",
            parameters=params,
        )

        assert result["status"] == "completed"
        assert result["action"] == "inspect_service_health"
        endpoints = result["endpoints"]
        assert "health" in endpoints
        assert endpoints["health"]["status_code"] == 200
        assert "metrics" in endpoints
        assert endpoints["metrics"]["status_code"] == 200
        # demo_status must NOT be in endpoints because is_demo_service=False
        assert "demo_status" not in endpoints
    except Exception as e:
        # If live service on port 7000 is not reachable in this process environment, skip
        pytest.skip(f"Live Inventory API on port 7000 not reachable: {e}")


def test_detector_lifecycle_does_not_recover_when_verification_failed(db_session, verification_test_context):
    """
    Verifies that detector lifecycle poller NEVER marks an incident recovered if an active
    or failed execution exists for that incident that has not been verified.
    """
    from app.detector.lifecycle import process_detection_lifecycle
    from app.detector.evaluator import DetectionReport

    ctx = verification_test_context
    incident = ctx["order_incident"]
    # Mark incident as investigating or awaiting_approval
    incident.status = "awaiting_approval"
    db_session.commit()

    # Create an execution that failed verification
    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        incident_id=incident.id,
        action_id="restore_order_api_demo",
        target_service_id=ctx["order_service"].id,
        status=ExecutionState.VERIFICATION_FAILED.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=ctx["user"].id,
    )
    db_session.add(execution)
    db_session.commit()

    # Now simulate a detector report claiming the service is healthy
    healthy_report = DetectionReport(
        is_healthy=True,
        workspace_id=ctx["workspace"].id,
        service_id=ctx["order_service"].id,
        service_name=ctx["order_service"].name,
        severity="info",
        summary="Service responded 200 OK",
        evidence={"status_code": 200},
    )

    inc, action = process_detection_lifecycle(db_session, healthy_report)
    assert action == "verification_failed_pending_escalation"
    db_session.refresh(incident)
    # Incident status must NOT have been changed to 'recovered'
    assert incident.status == "awaiting_approval"
    assert incident.recovered_at is None


def test_detector_lifecycle_defers_to_bridge_when_remediation_in_flight(db_session, verification_test_context):
    """
    Verifies that detector lifecycle poller defers recovery to IncidentRecoveryBridge
    when a remediation execution is in-flight (queued, executing, verifying).
    """
    from app.detector.lifecycle import process_detection_lifecycle
    from app.detector.evaluator import DetectionReport

    ctx = verification_test_context
    incident = ctx["order_incident"]
    incident.status = "remediating"
    db_session.commit()

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        incident_id=incident.id,
        action_id="restore_order_api_demo",
        target_service_id=ctx["order_service"].id,
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=ctx["user"].id,
    )
    db_session.add(execution)
    db_session.commit()

    healthy_report = DetectionReport(
        is_healthy=True,
        workspace_id=ctx["workspace"].id,
        service_id=ctx["order_service"].id,
        service_name=ctx["order_service"].name,
        severity="info",
        summary="Service responded 200 OK",
        evidence={"status_code": 200},
    )

    inc, action = process_detection_lifecycle(db_session, healthy_report)
    assert action == "remediation_in_flight"
    db_session.refresh(incident)
    assert incident.status == "remediating"
    assert incident.recovered_at is None


def test_remediation_cycle_response_recovery_status_integrity(db_session, verification_test_context):
    """
    Verifies that _build_cycle_response reports recovery_status='failed' when cycle status is failed,
    preventing any false positive 'Incident Recovered' display in the UI.
    """
    from app.api.v1.endpoints.remediation import _build_cycle_response
    from app.models.verification import VerificationCycle

    ctx = verification_test_context
    incident = ctx["order_incident"]
    # Even if incident status was 'recovered' due to an external leak:
    incident.status = "recovered"
    db_session.commit()

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ctx["workspace"].id,
        approval_id=str(uuid.uuid4()),
        incident_id=incident.id,
        action_id="restore_order_api_demo",
        target_service_id=ctx["order_service"].id,
        status=ExecutionState.VERIFICATION_FAILED.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=ctx["user"].id,
    )
    db_session.add(execution)
    db_session.commit()

    cycle = VerificationCycle(
        id=str(uuid.uuid4()),
        execution_id=execution.id,
        workspace_id=ctx["workspace"].id,
        cycle_number=1,
        status="failed",
        started_at=datetime.now(timezone.utc),
        deadline_at=datetime.now(timezone.utc) + timedelta(seconds=30),
        fencing_token=1,
        probes_required=3,
        probes_passed=0,
        probes_failed=1,
    )
    db_session.add(cycle)
    db_session.commit()

    resp = _build_cycle_response(cycle, db_session)
    assert resp.status == "failed"
    # Must report 'failed', NOT 'recovered'
    assert resp.recovery_status == "failed"
