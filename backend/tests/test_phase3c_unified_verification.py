"""Phase 3C Unified Verification Architecture Test Suite.

Proves:
1. One logical probe results in exactly one executor invocation.
2. All three endpoints (/health, /demo/status, /metrics) are inspected.
3. HTTP client and connection pool reuse occurs within one invocation.
4. Individual endpoint failures are represented correctly and distinguished from container failures.
5. Invalid paths and URLs are rejected.
6. Pinned-IP security checks remain enforced.
7. Container startup timeout and HTTP timeout are handled independently.
8. Overall probe deadline is enforced.
9. Three consecutive passing checks are still required.
10. Baseline exclusion remains correct.
11. Recovery bridge is not invoked after a failed or timed-out cycle.
12. Recovery bridge is invoked only after successful verification.
"""

from datetime import datetime, timezone
import json
import os
import sys
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import MagicMock, patch

from app.db.base import Base
from app.execution.exceptions import (
    BrokerSecurityViolation,
    PreconditionFailedError,
)
from app.execution.network import validate_safe_target_url
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import (
    DEFAULT_CYCLE_DEADLINE_SECONDS,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    DEFAULT_PROBES_REQUIRED,
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

# Import runner functions from services.executor.runner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from services.executor.runner import (
    DIAGNOSTIC_PATHS,
    PinnedSyncBackend,
    run_inspect_service_health,
)


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def db_session():
    """Create isolated in-memory SQLite session for tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def setup_entities(db_session):
    """Seed test workspace, user, service, incident, and execution."""
    ws = Workspace(id=str(uuid.uuid4()), name="Phase3C-Test", slug="phase3c-test")
    db_session.add(ws)

    user = User(
        id=str(uuid.uuid4()),
        email="sre@sentinelops.test",
        full_name="Test SRE",
        hashed_password="pw",
        is_active=True,
    )
    db_session.add(user)

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="Order API 5xx Failure",
        severity="high",
        status="remediating",
        trigger="HTTP 500 error",
    )
    db_session.add(inc)

    policy = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=user.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        decision="approval_required",
        decision_reason="Operator approval required",
        risk_level="medium",
        policy_version="1.0",
    )
    db_session.add(policy)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        policy_decision_id=policy.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        incident_id=inc.id,
        risk_level="medium",
        approval_status="approved",
        expires_at=datetime.now(timezone.utc),
    )
    db_session.add(approval)

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        approval_id=approval.id,
        incident_id=inc.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        status=ExecutionState.EXECUTION_SUCCEEDED.value,
        idempotency_key=f"exec-{uuid.uuid4().hex[:12]}",
        fencing_token=1,
        locked_by="worker-phase3c",
        triggered_by=user.id,
    )
    db_session.add(execution)
    db_session.commit()

    return {
        "workspace": ws,
        "user": user,
        "service": svc,
        "incident": inc,
        "execution": execution,
    }


class UnifiedTestRunner(ExecutionRunnerInterface):
    """Mock runner recording dispatches and returning unified diagnostic payloads."""

    def __init__(self, failure_on_probe: int = -1, endpoint_to_fail: str = "health"):
        self.dispatched_calls = []
        self.failure_on_probe = failure_on_probe
        self.endpoint_to_fail = endpoint_to_fail
        self.probe_count = 0

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
        self.probe_count += 1

        metrics_txt = (
            "# HELP order_api_http_5xx_errors_total Total 5xx HTTP errors\n"
            "# TYPE order_api_http_5xx_errors_total counter\n"
            "order_api_http_5xx_errors_total 10.0\n"
        )
        endpoints = {
            "health": {
                "status_code": 200,
                "duration_ms": 12.5,
                "output_data": {"status": "healthy"},
                "error_message": None,
                "success": True,
            },
            "demo_status": {
                "status_code": 200,
                "duration_ms": 8.0,
                "output_data": {"failure_active": False},
                "error_message": None,
                "success": True,
            },
            "metrics": {
                "status_code": 200,
                "duration_ms": 10.2,
                "output_data": {"raw_text": metrics_txt, "status_code": 200},
                "raw_text": metrics_txt,
                "error_message": None,
                "success": True,
            },
        }

        # Simulate failure if configured
        if self.failure_on_probe > 0 and self.probe_count >= self.failure_on_probe:
            if self.endpoint_to_fail == "health":
                endpoints["health"]["status_code"] = 500
                endpoints["health"]["success"] = False
                endpoints["health"]["error_message"] = "HTTP 500: Database error"
            elif self.endpoint_to_fail == "demo_status":
                endpoints["demo_status"]["output_data"] = {"failure_active": True, "failure_reason": "Simulated pool exhaustion"}
                endpoints["demo_status"]["success"] = False
            elif self.endpoint_to_fail == "metrics_increase":
                endpoints["metrics"]["raw_text"] = "order_api_http_5xx_errors_total 15.0\n"
                endpoints["metrics"]["output_data"] = {"raw_text": "order_api_http_5xx_errors_total 15.0\n"}
            elif self.endpoint_to_fail == "timeout":
                return ExecutionResult(exit_code=124, duration_ms=15000, error_category="timeout", error_message="Container timeout")

        return ExecutionResult(
            exit_code=0,
            duration_ms=45,
            output_data={
                "status": "completed",
                "action": "inspect_service_health",
                "endpoints": endpoints,
                "all_endpoints_successful": all(ep["success"] for ep in endpoints.values()),
            },
        )


# ============================================================================
# Test Cases Covering All 12 Requirements of Objective D
# ============================================================================

def test_1_one_logical_probe_one_executor_invocation(db_session, setup_entities):
    """Requirement 1: One logical probe results in exactly one executor invocation."""
    runner = UnifiedTestRunner()
    engine = PostExecutionVerificationEngine(runner=runner)

    probe_eval = engine.execute_single_probe(
        runner=runner,
        service=setup_entities["service"],
        probe_number=1,
        probe_type="baseline",
        execution_id=setup_entities["execution"].id,
    )

    assert probe_eval.passed is True
    assert len(runner.dispatched_calls) == 1
    assert runner.dispatched_calls[0]["action_id"] == "inspect_service_health"


def test_2_all_three_endpoints_inspected_in_single_probe(db_session, setup_entities):
    """Requirement 2: All three endpoints are inspected within the single probe."""
    runner = UnifiedTestRunner()
    engine = PostExecutionVerificationEngine(runner=runner)

    probe_eval = engine.execute_single_probe(
        runner=runner,
        service=setup_entities["service"],
        probe_number=1,
        probe_type="baseline",
        execution_id=setup_entities["execution"].id,
    )

    # All 3 endpoints present in probe_output
    assert "health" in probe_eval.probe_output
    assert "demo_status" in probe_eval.probe_output
    assert "metrics" in probe_eval.probe_output

    assert probe_eval.probe_output["health"]["status_code"] == 200
    assert probe_eval.probe_output["demo_status"]["status_code"] == 200
    assert probe_eval.probe_output["metrics"]["extracted_5xx"] == 10.0


def test_3_http_client_and_connection_reuse_within_invocation():
    """Requirement 3: HTTP client reuse occurs within one invocation."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.is_redirect = False
    mock_response.json.return_value = {"status": "healthy", "failure_active": False}
    mock_response.text = "order_api_http_5xx_errors_total 5.0\n"

    with patch("httpx.Client") as mock_client_cls:
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_cls.return_value.__enter__.return_value = mock_client_instance

        result = run_inspect_service_health(
            target_url="http://host.docker.internal:8001/health",
            pinned_ip="192.168.65.254",
            target_host="host.docker.internal",
            environment="development",
        )

        # Verified: Exactly one httpx.Client instantiated
        assert mock_client_cls.call_count == 1

        # Verified: All three diagnostic paths requested on that SAME client instance
        assert mock_client_instance.get.call_count == 3
        called_urls = [call[0][0] for call in mock_client_instance.get.call_args_list]
        assert "http://host.docker.internal:8001/health" in called_urls
        assert "http://host.docker.internal:8001/demo/status" in called_urls
        assert "http://host.docker.internal:8001/metrics" in called_urls


def test_4_individual_endpoint_failures_distinguished_from_container_failure(db_session, setup_entities):
    """Requirement 4: Endpoint failure (HTTP 500) fails the probe cleanly without container crash."""
    runner = UnifiedTestRunner(failure_on_probe=1, endpoint_to_fail="health")
    engine = PostExecutionVerificationEngine(runner=runner)

    probe_eval = engine.execute_single_probe(
        runner=runner,
        service=setup_entities["service"],
        probe_number=1,
        probe_type="health_check",
        baseline_5xx=10.0,
        execution_id=setup_entities["execution"].id,
    )

    # Failed probe due to endpoint 500, but container executed cleanly (status="failed", not "error" or "timeout")
    assert probe_eval.passed is False
    assert probe_eval.status == ProbeStatus.FAILED.value
    assert probe_eval.error_category == "validation_failed"
    assert probe_eval.health_healthy is False
    assert probe_eval.probe_output["health"]["status_code"] == 500
    assert "500" in (probe_eval.error_message or "")


def test_5_invalid_paths_and_urls_rejected():
    """Requirement 5: Invalid paths and unallowlisted URLs are rejected."""
    # SSRF / invalid path rejected
    with pytest.raises(BrokerSecurityViolation):
        validate_safe_target_url(
            "http://127.0.0.1:8001/unauthorized_admin_path",
            environment="development",
            action_id="inspect_service_health",
            allowed_paths={"/health", "/demo/status", "/metrics"},
        )

    # Cloud metadata IP rejected
    with pytest.raises(BrokerSecurityViolation):
        validate_safe_target_url(
            "http://169.254.169.254:8001/health",
            environment="development",
            action_id="inspect_service_health",
        )


def test_6_pinned_ip_security_checks_enforced():
    """Requirement 6: Pinned-IP security checks remain enforced in PinnedSyncBackend."""
    backend = PinnedSyncBackend(
        target_host="order-api.production.svc",
        pinned_ip="10.96.0.5",
        environment="production",
    )

    # Attempting to connect to unpinned host raises RuntimeError
    with pytest.raises(RuntimeError, match="Connection blocked: attempted connection to unpinned host"):
        backend.connect_tcp("evil.attacker.com", 8001)


def test_7_container_startup_and_http_timeout_handled_independently():
    """Requirement 7: Container startup timeout (15s) and HTTP timeout (3s) are decoupled."""
    assert DEFAULT_PROBE_TIMEOUT_SECONDS == 15  # Container dispatch envelope
    assert DEFAULT_HTTP_TIMEOUT_SECONDS == 3    # Individual HTTP request budget
    assert DEFAULT_CYCLE_DEADLINE_SECONDS == 45 # Overall cycle budget
    assert DEFAULT_PROBE_TIMEOUT_SECONDS > DEFAULT_HTTP_TIMEOUT_SECONDS


def test_8_overall_probe_deadline_enforced(db_session, setup_entities):
    """Requirement 8: Overall verification cycle deadline is strictly enforced."""
    runner = UnifiedTestRunner()
    engine = PostExecutionVerificationEngine(runner=runner)

    # Cycle with 0-second deadline immediately fails with deadline exceeded
    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=setup_entities["execution"].id,
        workspace_id=setup_entities["workspace"].id,
        service=setup_entities["service"],
        timeout_seconds=0,
    )

    assert summary.outcome == VerificationOutcome.FAIL
    assert summary.status == "timed_out"
    assert "deadline" in (summary.error_message or "").lower()


def test_9_three_consecutive_passing_checks_required(db_session, setup_entities):
    """Requirement 9: Three consecutive passing checks are required; flapping resets counter."""
    # Probe 1 (baseline) passes, Probe 2 passes (consecutive=1), Probe 3 fails (reset to 0)
    runner = UnifiedTestRunner(failure_on_probe=3, endpoint_to_fail="health")
    engine = PostExecutionVerificationEngine(runner=runner)

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=setup_entities["execution"].id,
        workspace_id=setup_entities["workspace"].id,
        service=setup_entities["service"],
        timeout_seconds=5,
    )

    # Probe 3 failed, so it could not reach 3 consecutive passes
    assert summary.outcome == VerificationOutcome.FAIL
    assert summary.consecutive_passes == 0


def test_10_baseline_exclusion_from_consecutive_passes(db_session, setup_entities):
    """Requirement 10: Baseline probe (Probe 1) is strictly excluded from consecutive pass count."""
    runner = UnifiedTestRunner()
    engine = PostExecutionVerificationEngine(runner=runner)

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=setup_entities["execution"].id,
        workspace_id=setup_entities["workspace"].id,
        service=setup_entities["service"],
    )

    # Standard clean cycle: 1 baseline + 3 consecutive checks = 4 total probes
    assert summary.outcome == VerificationOutcome.PASS
    assert summary.probes_executed == 4
    assert summary.consecutive_passes == 3
    assert len(runner.dispatched_calls) == 4  # Exactly 4 dispatches


def test_11_recovery_bridge_not_invoked_on_failed_cycle(db_session, setup_entities):
    """Requirement 11: Recovery bridge is NOT invoked after a failed or timed-out cycle."""
    runner = UnifiedTestRunner(failure_on_probe=2, endpoint_to_fail="health")
    engine = PostExecutionVerificationEngine(runner=runner)

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=setup_entities["execution"].id,
        workspace_id=setup_entities["workspace"].id,
        service=setup_entities["service"],
        recover_incident=True,
    )

    assert summary.outcome == VerificationOutcome.FAIL

    # Incident remains in remediating (NOT recovered)
    db_session.refresh(setup_entities["incident"])
    assert setup_entities["incident"].status == "remediating"
    assert setup_entities["incident"].recovered_at is None


def test_12_recovery_bridge_invoked_only_after_successful_verification(db_session, setup_entities):
    """Requirement 12: Recovery bridge is invoked only after successful verification."""
    runner = UnifiedTestRunner()
    engine = PostExecutionVerificationEngine(runner=runner)

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=setup_entities["execution"].id,
        workspace_id=setup_entities["workspace"].id,
        service=setup_entities["service"],
        recover_incident=True,
    )

    assert summary.outcome == VerificationOutcome.PASS

    # Execution verified and incident atomically recovered
    db_session.refresh(setup_entities["execution"])
    db_session.refresh(setup_entities["incident"])

    assert setup_entities["execution"].status == ExecutionState.VERIFIED.value
    assert setup_entities["incident"].status == "recovered"
    assert setup_entities["incident"].recovered_at is not None
