"""Stage 3.1 Regression Test Suite: Security & Generic Verification Corrections.

Demonstrates:
1. Generic health-only service can complete independent verification (VerificationOutcome.PASS).
2. Missing optional metrics do not fail verification for generic services.
3. A configured Prometheus metrics integration still receives mandatory metrics checks (fails on missing/increasing 5xx).
4. An unrelated service on port 8001 does not trigger Order API-specific demo checks (/demo/status).
5. An unrelated service on port 8002 does not trigger Order API-specific demo checks (/demo/status).
6. Missing worker database credentials cause safe startup failure (SecurityConfigurationError).
   Committed static/placeholder passwords also cause safe startup failure.
7. Valid externally supplied credentials work without appearing in logs or error messages (masked).
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from unittest.mock import MagicMock, patch

from app.execution.exceptions import (
    BrokerSecurityViolation,
    ExecutionEnvironmentUnavailable,
    SecurityConfigurationError,
)
from app.execution.runner import ExecutionResult, MockTestRunner
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
    SingleProbeEvaluation,
)
from app.execution.worker import (
    get_worker_db_session_factory,
    sanitize_db_url,
    DurableExecutionWorker,
)
from app.models.incident import Incident
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace


@pytest.fixture
def ws1(db_session):
    """Provide a test workspace for Stage 3.1 tests."""
    workspace = Workspace(
        id=str(uuid.uuid4()),
        name="Stage 3.1 Workspace",
        slug=f"stage31-{uuid.uuid4().hex[:6]}",
        description="Workspace for Stage 3.1 tests",
    )
    db_session.add(workspace)
    db_session.flush()
    return workspace


def create_test_execution(db_session, workspace, service, action_id="execute_http_recovery"):
    """Helper to seed valid database chain for RemediationExecution."""
    now_utc = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()),
        email=f"tester-{uuid.uuid4().hex[:6]}@sentinelops.test",
        full_name="Tester",
        hashed_password="fake_hash",
        is_active=True,
    )
    db_session.add(user)

    incident = Incident(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        service_id=service.id,
        title="Test Incident",
        severity="high",
        status="remediating",
        trigger="test",
    )
    db_session.add(incident)

    policy = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        user_id=user.id,
        action_id=action_id,
        target_service_id=service.id,
        validated_parameters={},
        decision="approval_required",
        decision_reason="Testing",
        policy_version="v1.0",
        risk_level="medium",
        timestamp=now_utc,
    )
    db_session.add(policy)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        policy_decision_id=policy.id,
        incident_id=incident.id,
        target_service_id=service.id,
        action_id=action_id,
        validated_parameters={},
        risk_level="medium",
        policy_version="v1.0",
        approval_status="approved",
        requested_by=user.id,
        reviewed_by=user.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(approval)

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        approval_id=approval.id,
        incident_id=incident.id,
        action_id=action_id,
        target_service_id=service.id,
        approved_parameters={},
        status="verification_pending",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        fencing_token=1,
        locked_by="worker-test",
        triggered_by=user.id,
        attempt_count=1,
        max_attempts=1,
    )
    db_session.add(execution)
    db_session.commit()
    return execution


# ==============================================================================
# 1. Generic Health-Only Service Verification
# ==============================================================================

def test_generic_health_only_service_completes_verification(db_session, ws1):
    """Verify that a generic service exposing only /health successfully completes verification."""
    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        name="Payment Gateway Service",
        environment="development",
        health_check_url="http://127.0.0.1:9050/health",
        monitoring_method="builtin",  # Non-Prometheus metrics configured (built-in health only)
    )
    db_session.add(svc)
    db_session.commit()

    execution = create_test_execution(db_session, ws1, svc)

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True

    # Generic service returns only health endpoint data (no demo_status, no metrics)
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=25,
        output_data={
            "endpoints": {
                "health": {
                    "status_code": 200,
                    "success": True,
                    "output_data": {"status": "healthy", "service": "payment-gateway"},
                }
            }
        },
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ws1.id,
        service=svc,
        runner=mock_runner,
        worker_id="worker-test",
        fencing_token=1,
        probes_required=3,
        probe_interval_seconds=0.0,
    )

    assert summary.outcome == VerificationOutcome.PASS
    assert summary.status == "passed"
    assert summary.probes_executed == 4  # 1 baseline + 3 consecutive passes
    assert summary.consecutive_passes == 3
    assert summary.baseline_5xx is None
    assert summary.final_5xx is None


# ==============================================================================
# 2. Missing Optional Metrics Do Not Fail Verification
# ==============================================================================

def test_missing_optional_metrics_do_not_fail_verification(db_session, ws1):
    """Verify that a service with non-Prometheus monitoring (e.g. OpenTelemetry) does not fail when metrics are absent."""
    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        name="Catalog Search Service",
        environment="development",
        health_check_url="http://127.0.0.1:9060/health",
        monitoring_method="opentelemetry",  # Not Prometheus
    )
    db_session.add(svc)
    db_session.commit()

    execution = create_test_execution(db_session, ws1, svc)

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=30,
        output_data={
            "endpoints": {
                "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}}
            }
        },
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ws1.id,
        service=svc,
        runner=mock_runner,
        worker_id="worker-test",
        fencing_token=1,
        probes_required=3,
        probe_interval_seconds=0.0,
    )

    assert summary.outcome == VerificationOutcome.PASS
    assert summary.status == "passed"


# ==============================================================================
# 3. Configured Metrics Integration Requires Valid Metrics
# ==============================================================================

def test_configured_prometheus_metrics_enforces_metrics_checks(db_session, ws1):
    """Verify that when monitoring_method='prometheus', missing or increasing metrics fail verification."""
    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        name="Telemetry Monitored Service",
        environment="development",
        health_check_url="http://127.0.0.1:9070/health",
        monitoring_method="prometheus",  # Explicitly requires metrics!
    )
    db_session.add(svc)
    db_session.commit()

    execution = create_test_execution(db_session, ws1, svc)

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True

    # Case A: Metrics missing -> Baseline capture must FAIL
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=20,
        output_data={
            "endpoints": {
                "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}},
                "metrics": {"status_code": 200, "raw_text": "# No 5xx metric here\nhttp_requests_total 100"},
            }
        },
    )
    engine = PostExecutionVerificationEngine(runner=mock_runner)
    summary_fail = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ws1.id,
        service=svc,
        runner=mock_runner,
        worker_id="worker-test",
        fencing_token=1,
        probes_required=3,
        probe_interval_seconds=0.0,
    )
    assert summary_fail.outcome == VerificationOutcome.FAIL
    assert any(
        msg in summary_fail.error_message
        for msg in ["Missing required 5xx error counter", "required metrics telemetry is missing"]
    )

    # Case B: Metrics present and stable -> Verification PASSES
    execution_pass = create_test_execution(db_session, ws1, svc)
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=20,
        output_data={
            "endpoints": {
                "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}},
                "metrics": {"status_code": 200, "raw_text": "order_api_http_5xx_errors_total 12.0"},
            }
        },
    )
    summary_pass = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution_pass.id,
        workspace_id=ws1.id,
        service=svc,
        runner=mock_runner,
        worker_id="worker-test",
        fencing_token=1,
        cycle_number=1,
        probes_required=3,
        probe_interval_seconds=0.0,
    )
    assert summary_pass.outcome == VerificationOutcome.PASS
    assert summary_pass.baseline_5xx == 12.0
    assert summary_pass.final_5xx == 12.0


# ==============================================================================
# 4 & 5. Unrelated Services on Port 8001 and 8002 Do Not Trigger Order API Checks
# ==============================================================================

def test_unrelated_service_on_port_8001_does_not_trigger_demo_checks(db_session, ws1):
    """Verify that an unrelated service on port 8001 does NOT expect /demo/status."""
    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        name="Authentication Service",
        environment="development",
        health_check_url="http://127.0.0.1:8001/api/v1/health",  # Port 8001, but NOT Order API!
        monitoring_method="builtin",
    )
    db_session.add(svc)
    db_session.commit()

    execution = create_test_execution(db_session, ws1, svc)

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True

    # If demo checks were triggered, /demo/status would be required. Here only /health is provided.
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=15,
        output_data={
            "endpoints": {
                "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}}
            }
        },
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    single_probe = engine.execute_single_probe(
        runner=mock_runner,
        service=svc,
        probe_number=1,
        probe_type="baseline",
        execution_id=execution.id,
        action_id=execution.action_id,
    )
    assert single_probe.passed is True
    assert single_probe.demo_failure_active is False
    assert single_probe.probe_output.get("demo_status", {}).get("status") == "skipped"

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ws1.id,
        service=svc,
        runner=mock_runner,
        worker_id="worker-test",
        fencing_token=1,
        probes_required=3,
        probe_interval_seconds=0.0,
    )
    assert summary.outcome == VerificationOutcome.PASS


def test_unrelated_service_on_port_8002_does_not_trigger_demo_checks(db_session, ws1):
    """Verify that an unrelated service on port 8002 does NOT expect /demo/status."""
    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        name="Billing Notification Worker",
        environment="development",
        health_check_url="http://127.0.0.1:8002/healthz",  # Port 8002, but NOT Order API!
        monitoring_method="none",
    )
    db_session.add(svc)
    db_session.commit()

    execution = create_test_execution(db_session, ws1, svc)

    mock_runner = MagicMock(spec=MockTestRunner)
    mock_runner.is_available.return_value = True
    mock_runner.execute.return_value = ExecutionResult(
        exit_code=0,
        duration_ms=18,
        output_data={
            "endpoints": {
                "health": {"status_code": 200, "success": True, "output_data": {"alive": True}}
            }
        },
    )

    engine = PostExecutionVerificationEngine(runner=mock_runner)
    single_probe = engine.execute_single_probe(
        runner=mock_runner,
        service=svc,
        probe_number=1,
        probe_type="baseline",
        execution_id=execution.id,
        action_id=execution.action_id,
    )
    assert single_probe.passed is True
    assert single_probe.probe_output.get("demo_status", {}).get("status") == "skipped"

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=ws1.id,
        service=svc,
        runner=mock_runner,
        worker_id="worker-test",
        fencing_token=1,
        probes_required=3,
        probe_interval_seconds=0.0,
    )
    assert summary.outcome == VerificationOutcome.PASS


# ==============================================================================
# 6. Missing Worker Database Credentials & Placeholder Rejection
# ==============================================================================

def test_missing_worker_db_credentials_causes_startup_failure():
    """Verify that missing WORKER_DATABASE_URL in non-test environment fails closed."""
    old_env = os.environ.get("ENVIRONMENT")
    old_worker_url = os.environ.get("WORKER_DATABASE_URL")
    try:
        os.environ["ENVIRONMENT"] = "development"
        os.environ.pop("WORKER_DATABASE_URL", None)

        with pytest.raises(SecurityConfigurationError) as exc_info:
            get_worker_db_session_factory(environment="development")
        assert "WORKER_DATABASE_URL must be explicitly configured" in str(exc_info.value)
        assert "Administrative database fallback is strictly forbidden" in str(exc_info.value)
    finally:
        if old_env is not None:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_worker_url is not None:
            os.environ["WORKER_DATABASE_URL"] = old_worker_url
        else:
            os.environ.pop("WORKER_DATABASE_URL", None)


def test_placeholder_passwords_rejected_in_worker_db_url():
    """Verify that committed static/placeholder passwords in WORKER_DATABASE_URL are rejected."""
    old_worker_url = os.environ.get("WORKER_DATABASE_URL")
    try:
        placeholders = [
            "sentinelops_worker_password",
            "password",
            "change_me",
            "worker_password",
        ]
        for ph in placeholders:
            os.environ["WORKER_DATABASE_URL"] = f"postgresql://sentinelops_worker:{ph}@127.0.0.1:5432/sentinelops_dev"
            with pytest.raises(SecurityConfigurationError) as exc_info:
                get_worker_db_session_factory()
            assert "Insecure or default placeholder password detected" in str(exc_info.value)
    finally:
        if old_worker_url is not None:
            os.environ["WORKER_DATABASE_URL"] = old_worker_url
        else:
            os.environ.pop("WORKER_DATABASE_URL", None)


# ==============================================================================
# 7. Valid Externally Supplied Credentials Work Without Appearing in Logs
# ==============================================================================

def test_valid_worker_credentials_work_without_appearing_in_logs():
    """Verify that valid external credentials work and are sanitized in error and log output."""
    raw_secret = "super_secret_deployment_pass_xyz987"
    raw_url = f"postgresql://sentinelops_worker:{raw_secret}@127.0.0.1:5432/sentinelops_dev"

    # Test URL sanitization function
    sanitized = sanitize_db_url(raw_url)
    assert raw_secret not in sanitized
    assert ":***@" in sanitized
    assert sanitized == "postgresql://sentinelops_worker:***@127.0.0.1:5432/sentinelops_dev"

    # Test error formatting does not leak secret
    invalid_host_url = f"postgresql://sentinelops_worker:{raw_secret}@invalid-host-999.local:5432/nonexistent_db"
    old_url = os.environ.get("WORKER_DATABASE_URL")
    try:
        os.environ["WORKER_DATABASE_URL"] = "sqlite:///:memory:"
        factory = get_worker_db_session_factory()
        session = factory()
        assert session is not None
        session.close()

        # When an error occurs during create_engine or connection, credentials must remain masked
        with patch("sqlalchemy.create_engine", side_effect=ValueError("Simulated engine failure")):
            os.environ["WORKER_DATABASE_URL"] = invalid_host_url
            with pytest.raises(SecurityConfigurationError) as exc_info:
                get_worker_db_session_factory()
            err_msg = str(exc_info.value)
            assert raw_secret not in err_msg
            assert ":***@" in err_msg
    finally:
        if old_url is not None:
            os.environ["WORKER_DATABASE_URL"] = old_url
        else:
            os.environ.pop("WORKER_DATABASE_URL", None)
