"""Post-Execution Verification Engine Test Suite for Phase 4.3.6 Milestone B.

Tests:
1. Baseline capture (Probe 1 - not counted towards consecutive passing count).
2. Three consecutive successful probes (Probes 2-4).
3. Exactly four probe records on standard clean execution.
4. Flapping health responses (consecutive pass counter resets).
5. failure_active=true detection and probe failure.
6. Increased 5xx counter relative to baseline.
7. Missing metrics rejection (never treated as successful zero delta).
8. Reset metrics rejection (current < baseline rejected).
9. HTTP timeout in probe.
10. Overall cycle deadline expiration.
11. Broker IPC unavailable (outcome INCONCLUSIVE, cycle uncertain, execution preserved).
12. Duplicate probe persistence (idempotent duplicate vs conflicting duplicate).
13. Workspace isolation (cross-workspace execution & service rejection).
14. Stale fencing token rejection (fencing protection).
15. No remediation redispatch (strictly inspect_service_health, never restore_order_api_demo).
16. No direct backend network access (runner abstraction only).
17. Worker lease & heartbeat validity during verification_pending.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.base import Base
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ConflictingProbePayloadError,
    CrossWorkspaceViolationError,
    ExecutionEnvironmentUnavailable,
    PreconditionFailedError,
    StaleWorkerFencingError,
)
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
    extract_5xx_metric,
)
from app.execution.verification_persistence import (
    VerificationPersistenceService,
    generate_deterministic_probe_id,
)
from app.models.incident import Incident
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.verification import VerificationCycle, VerificationProbeResult
from app.models.workspace import Workspace


# ============================================================================
# Safe Test Double Runner for Verification Testing
# ============================================================================

class VerificationTestRunner(ExecutionRunnerInterface):
    """
    Safe in-memory test runner for verification testing.
    Records every dispatched action, validates read-only constraints,
    and returns configurable responses per target URL.
    """

    def __init__(self):
        self.dispatched_calls = []
        self._custom_responses = {}
        self._url_call_counts = {}
        self._raise_broker_error = None

    def set_response(self, url_suffix: str, result: ExecutionResult):
        """Set canned response for URLs ending with given suffix (e.g. '/health')."""
        self._custom_responses[url_suffix] = result

    def set_sequenced_responses(self, url_suffix: str, results: list):
        """Set a sequence of canned responses for successive calls to given suffix."""
        self._custom_responses[url_suffix] = list(results)

    def set_broker_unavailable(self, exc: Exception):
        """Configure runner to simulate broker IPC disconnection."""
        self._raise_broker_error = exc

    def is_available(self) -> bool:
        return self._raise_broker_error is None

    def execute(
        self,
        action_id: str,
        parameters: dict,
        timeout_seconds: int = 30,
        target_url: str = None,
        environment: str = "development",
        execution_id: str = None,
    ) -> ExecutionResult:
        # 1. Strictly verify action is read-only diagnostic
        if action_id != "inspect_service_health":
            raise ValueError(
                f"SECURITY VIOLATION: Verification invoked non-diagnostic action '{action_id}'. "
                f"Only read-only 'inspect_service_health' is permitted during verification!"
            )

        # 2. Simulate broker connection drop if configured
        if self._raise_broker_error is not None:
            raise self._raise_broker_error

        # 3. Record dispatched call for audit inspection
        call_record = {
            "action_id": action_id,
            "parameters": parameters,
            "timeout_seconds": timeout_seconds,
            "target_url": target_url,
            "environment": environment,
            "execution_id": execution_id,
        }
        self.dispatched_calls.append(call_record)

        target = target_url or ""
        self._url_call_counts[target] = self._url_call_counts.get(target, 0) + 1

        def _get_ep(suffix: str, default_res: ExecutionResult) -> ExecutionResult:
            self._url_call_counts[suffix] = self._url_call_counts.get(suffix, 0) + 1
            idx = self._url_call_counts[suffix] - 1
            resp_spec = self._custom_responses.get(suffix)
            if resp_spec is not None:
                if isinstance(resp_spec, list):
                    if idx < len(resp_spec):
                        return resp_spec[idx]
                    return resp_spec[-1]
                return resp_spec
            return default_res

        metrics_txt = (
            "# HELP order_api_http_5xx_errors_total Total 5xx HTTP errors\n"
            "# TYPE order_api_http_5xx_errors_total counter\n"
            "order_api_http_5xx_errors_total 10.0\n"
        )
        def_health = ExecutionResult(exit_code=0, duration_ms=25, stdout='{"status": "healthy"}', output_data={"status": "healthy"})
        def_demo = ExecutionResult(exit_code=0, duration_ms=20, stdout='{"failure_active": false, "failure_reason": null, "error_count": 0}', output_data={"failure_active": False, "failure_reason": None, "error_count": 0})
        def_metrics = ExecutionResult(exit_code=0, duration_ms=30, stdout=metrics_txt, output_data={"raw_text": metrics_txt, "status_code": 200})

        res_h = _get_ep("/health", def_health)
        res_d = _get_ep("/demo/status", def_demo)
        res_m = _get_ep("/metrics", def_metrics)

        # If any endpoint simulated timeout (exit_code 124 or error_category timeout)
        for r in (res_h, res_d, res_m):
            if r.exit_code == 124 or r.error_category == "timeout":
                return ExecutionResult(
                    exit_code=124,
                    duration_ms=2000,
                    stderr=r.stderr or "Container execution timed out.",
                    error_category="timeout",
                    error_message=r.error_message or "Timeout",
                )

        endpoints = {
            "health": {
                "status_code": 200 if res_h.exit_code == 0 else 500,
                "duration_ms": res_h.duration_ms,
                "output_data": res_h.output_data or {"status": "healthy"},
                "error_message": res_h.error_message,
                "success": res_h.exit_code == 0,
            },
            "demo_status": {
                "status_code": 200 if res_d.exit_code == 0 else 500,
                "duration_ms": res_d.duration_ms,
                "output_data": res_d.output_data or {"failure_active": False},
                "error_message": res_d.error_message,
                "success": res_d.exit_code == 0 and not bool((res_d.output_data or {}).get("failure_active", False)),
            },
            "metrics": {
                "status_code": 200 if res_m.exit_code == 0 else 500,
                "duration_ms": res_m.duration_ms,
                "output_data": res_m.output_data or {"raw_text": metrics_txt, "status_code": 200},
                "raw_text": getattr(res_m, "stdout", "") or (res_m.output_data or {}).get("raw_text") or metrics_txt,
                "error_message": res_m.error_message,
                "success": res_m.exit_code == 0,
            },
        }

        return ExecutionResult(
            exit_code=0,
            duration_ms=res_h.duration_ms + res_d.duration_ms + res_m.duration_ms,
            output_data={
                "status": "completed",
                "endpoints": endpoints,
                "all_endpoints_successful": all(ep["success"] for ep in endpoints.values()),
            },
        )


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def db_session():
    """Create isolated in-memory SQLite database session for unit tests."""
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
def mock_entities(db_session):
    """Seed test workspace, user, active service, incident, and execution."""
    now_utc = datetime.now(timezone.utc)
    ws_id = str(uuid.uuid4())
    ws = Workspace(id=ws_id, name="Verification Test WS", slug=f"ws-{ws_id[:8]}")
    db_session.add(ws)

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="operator@sentinelops.test",
        full_name="Test Operator",
        hashed_password="fake_hashed_pwd",
        is_active=True,
    )
    db_session.add(user)

    svc_id = str(uuid.uuid4())
    service = Service(
        id=svc_id,
        workspace_id=ws_id,
        name="Order API Dev",
        health_check_url="http://host.docker.internal:8001/health",
        environment="development",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )
    db_session.add(service)

    inc_id = str(uuid.uuid4())
    incident = Incident(
        id=inc_id,
        workspace_id=ws_id,
        service_id=svc_id,
        title="Simulated Outage",
        severity="high",
        status="remediating",
        trigger="http_5xx_threshold",
    )
    db_session.add(incident)

    policy_id = str(uuid.uuid4())
    policy = PolicyDecision(
        id=policy_id,
        workspace_id=ws_id,
        user_id=user_id,
        action_id="restore_order_api_demo",
        target_service_id=svc_id,
        validated_parameters={"service_id": svc_id},
        decision="approval_required",
        decision_reason="Pre-flight test",
        policy_version="v1.0",
        risk_level="medium",
        timestamp=now_utc,
    )
    db_session.add(policy)

    approval_id = str(uuid.uuid4())
    approval = RemediationApproval(
        id=approval_id,
        workspace_id=ws_id,
        policy_decision_id=policy_id,
        incident_id=inc_id,
        target_service_id=svc_id,
        action_id="restore_order_api_demo",
        validated_parameters={"service_id": svc_id},
        risk_level="medium",
        policy_version="v1.0",
        approval_status="approved",
        requested_by=user_id,
        reviewed_by=user_id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(approval)

    exec_id = str(uuid.uuid4())
    execution = RemediationExecution(
        id=exec_id,
        workspace_id=ws_id,
        approval_id=approval_id,
        incident_id=inc_id,
        action_id="restore_order_api_demo",
        target_service_id=svc_id,
        approved_parameters={"service_id": svc_id},
        status=ExecutionState.EXECUTION_SUCCEEDED.value,
        idempotency_key=f"idem-{exec_id[:8]}",
        locked_by="worker-test-01",
        locked_until=now_utc + timedelta(seconds=90),
        heartbeat_at=now_utc,
        fencing_token=1,
        triggered_by=user_id,
        triggered_at=now_utc,
        started_at=now_utc,
        completed_at=now_utc,
        attempt_count=1,
        max_attempts=1,
        execution_output={"exit_code": 0, "status": "demo_restored"},
    )
    db_session.add(execution)
    db_session.commit()

    return {
        "workspace": ws,
        "user": user,
        "service": service,
        "incident": incident,
        "approval": approval,
        "execution": execution,
    }


# ============================================================================
# Unit Tests for Metric Extraction Safety
# ============================================================================

class TestMetricExtractionSafety:
    """Test rigorous extraction of 5xx metrics and rejection of missing/reset telemetry."""

    def test_extract_from_prometheus_text_success(self):
        text = (
            "# HELP order_api_http_5xx_errors_total Counter\n"
            "# TYPE order_api_http_5xx_errors_total counter\n"
            "order_api_http_5xx_errors_total 42.0\n"
        )
        val, is_present = extract_5xx_metric(text)
        assert is_present is True
        assert val == 42.0

    def test_extract_missing_metric_rejected(self):
        """Missing metric returns is_present=False; never treated as zero."""
        text = (
            "# HELP process_cpu_seconds_total Total user and system CPU time\n"
            "# TYPE process_cpu_seconds_total counter\n"
            "process_cpu_seconds_total 12.34\n"
        )
        val, is_present = extract_5xx_metric(text)
        assert is_present is False
        assert val is None

    def test_extract_empty_string_rejected(self):
        val, is_present = extract_5xx_metric("")
        assert is_present is False
        assert val is None

    def test_extract_from_dict_success(self):
        data = {"order_api_http_5xx_errors_total": 5.0}
        val, is_present = extract_5xx_metric(data)
        assert is_present is True
        assert val == 5.0

    def test_extract_from_dict_with_raw_text(self):
        data = {
            "raw_text": "order_api_http_5xx_errors_total 8.0\n",
            "status_code": 200,
        }
        val, is_present = extract_5xx_metric(data)
        assert is_present is True
        assert val == 8.0

    def test_extract_from_empty_dict_rejected(self):
        val, is_present = extract_5xx_metric({})
        assert is_present is False
        assert val is None


# ============================================================================
# Core Post-Execution Verification Engine Tests
# ============================================================================

class TestPostExecutionVerificationEngine:
    """Test end-to-end verification cycle orchestration adhering strictly to Phase 4.3.6."""

    def test_baseline_capture_and_three_consecutive_passing_probes(self, db_session, mock_entities):
        """
        Verify the standard clean path:
        - Probe 1 captures baseline (not counted toward consecutive passes).
        - Probes 2, 3, 4 pass consecutively.
        - Exactly 4 probe records persisted in DB.
        - Outcome is PASS, execution transitions to VERIFIED.
        - Incident is NOT marked recovered.
        """
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]
        incident = mock_entities["incident"]

        runner = VerificationTestRunner()
        engine = PostExecutionVerificationEngine(runner=runner)

        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            cycle_number=1,
        )

        assert summary.outcome == VerificationOutcome.PASS
        assert summary.consecutive_passes == 3
        assert summary.probes_required == 3
        assert summary.probes_executed == 4
        assert summary.baseline_5xx == 10.0
        assert summary.final_5xx == 10.0
        assert summary.error_message is None

        # Verify DB entities
        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFIED.value
        assert execution.verification_status == "verified"
        assert execution.verification_output is not None
        assert execution.verification_output["outcome"] == "PASS"

        # Verify exactly 4 probe records in DB
        probes = VerificationPersistenceService.list_probes_for_cycle(
            db=db_session, cycle_id=summary.cycle_id
        )
        assert len(probes) == 4

        # Probe 1: baseline
        assert probes[0].probe_number == 1
        assert probes[0].probe_type == "baseline"
        assert probes[0].passed is True
        assert probes[0].status == "passed"

        # Probes 2-4: health checks
        for p in probes[1:]:
            assert p.probe_type == "health_check"
            assert p.passed is True
            assert p.status == "passed"

        # CRITICAL ARCHITECTURAL BOUNDARY:
        # Incident is NOT marked recovered in Milestone B
        db_session.refresh(incident)
        assert incident.status == "remediating"
        assert incident.status != "recovered"

    def test_flapping_health_resets_consecutive_counter(self, db_session, mock_entities):
        """
        Verify flapping health response behavior:
        - Probe 1 (baseline): passes.
        - Probe 2: passes (consecutive = 1).
        - Probe 3: fails (/health returns 500). Consecutive counter resets to 0!
        - Probe 4: passes (consecutive = 1).
        - Probe 5: passes (consecutive = 2).
        - Probe 6: passes (consecutive = 3 -> overall PASS).
        """
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        # Configure /health to flap on call 3 (Probe 3)
        runner.set_sequenced_responses(
            "/health",
            [
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"status": "healthy"}),  # Probe 1
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"status": "healthy"}),  # Probe 2
                ExecutionResult(exit_code=1, duration_ms=25, stderr="HTTP 500 Internal Error", error_message="HTTP 500"),  # Probe 3 FAIL
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"status": "healthy"}),  # Probe 4
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"status": "healthy"}),  # Probe 5
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"status": "healthy"}),  # Probe 6
            ],
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            cycle_number=1,
        )

        assert summary.outcome == VerificationOutcome.PASS
        assert summary.consecutive_passes == 3
        # Total probes executed: 1 baseline + 5 health checks = 6 total
        assert summary.probes_executed == 6

        probes = VerificationPersistenceService.list_probes_for_cycle(
            db=db_session, cycle_id=summary.cycle_id
        )
        assert len(probes) == 6
        assert probes[2].probe_number == 3
        assert probes[2].passed is False
        assert probes[2].status == "failed"

    def test_failure_active_true_fails_probe_and_cycle(self, db_session, mock_entities):
        """Verify that failure_active=true on /demo/status causes probe and cycle failure."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        # Baseline succeeds, but Probe 2 reports failure_active=True
        runner.set_sequenced_responses(
            "/demo/status",
            [
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"failure_active": False}),
                ExecutionResult(exit_code=0, duration_ms=20, output_data={"failure_active": True, "failure_reason": "DB deadlock"}),
            ],
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            timeout_seconds=2,
        )

        assert summary.outcome == VerificationOutcome.FAIL
        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFICATION_FAILED.value
        assert execution.verification_status == "failed"

    def test_increased_5xx_counter_fails_verification(self, db_session, mock_entities):
        """Verify that an increase in the 5xx counter relative to baseline causes probe failure."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        runner.set_sequenced_responses(
            "/metrics",
            [
                ExecutionResult(exit_code=0, duration_ms=25, stdout="order_api_http_5xx_errors_total 10.0\n"),  # Baseline: 10
                ExecutionResult(exit_code=0, duration_ms=25, stdout="order_api_http_5xx_errors_total 12.0\n"),  # Probe 2: 12 (increase!)
            ],
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            timeout_seconds=2,
        )

        assert summary.outcome == VerificationOutcome.FAIL
        assert "5xx error counter increased" in (summary.error_message or "")
        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFICATION_FAILED.value

    def test_missing_metrics_rejected_not_treated_as_zero_delta(self, db_session, mock_entities):
        """Verify missing metrics endpoint output is rejected and NEVER treated as zero delta."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        # Returns metrics text without any 5xx error counter
        runner.set_response(
            "/metrics",
            ExecutionResult(exit_code=0, duration_ms=25, stdout="go_goroutines 42\n"),
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            timeout_seconds=2,
        )

        assert summary.outcome == VerificationOutcome.FAIL
        assert "Missing" in (summary.error_message or "")
        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFICATION_FAILED.value

    def test_reset_metric_counter_rejected(self, db_session, mock_entities):
        """Verify metric counter reset (current < baseline) is rejected as invalid telemetry."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        runner.set_sequenced_responses(
            "/metrics",
            [
                ExecutionResult(exit_code=0, duration_ms=25, stdout="order_api_http_5xx_errors_total 100.0\n"),  # Baseline: 100
                ExecutionResult(exit_code=0, duration_ms=25, stdout="order_api_http_5xx_errors_total 2.0\n"),    # Probe 2: 2 (reset!)
            ],
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            timeout_seconds=2,
        )

        assert summary.outcome == VerificationOutcome.FAIL
        assert "reset" in (summary.error_message or "").lower()

    def test_http_timeout_in_probe_fails_cycle(self, db_session, mock_entities):
        """Verify individual HTTP timeout (exit code 124) is recorded as timeout status."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        runner.set_response(
            "/health",
            ExecutionResult(
                exit_code=124,
                duration_ms=2000,
                stderr="Container execution timed out after 2s.",
                error_category="timeout",
            ),
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            timeout_seconds=2,
        )

        assert summary.outcome == VerificationOutcome.FAIL
        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFICATION_FAILED.value

    def test_overall_cycle_deadline_expiration(self, db_session, mock_entities):
        """Verify overall verification cycle deadline enforcement (e.g. 45s)."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        engine = PostExecutionVerificationEngine(runner=runner)

        # Force immediate deadline expiration by setting timeout_seconds to 0
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            timeout_seconds=0,  # 0 second deadline
        )

        assert summary.outcome == VerificationOutcome.FAIL
        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFICATION_FAILED.value

    def test_broker_ipc_unavailable_results_in_inconclusive(self, db_session, mock_entities):
        """
        Verify that broker IPC unavailability results strictly in INCONCLUSIVE,
        cycle status 'uncertain', preserves execution status 'verification_pending',
        and does NOT mark incident recovered.
        """
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]
        incident = mock_entities["incident"]

        runner = VerificationTestRunner()
        runner.set_broker_unavailable(
            BrokerUnavailableError("Broker IPC socket '/var/run/sentinelops/broker.sock' disconnected.")
        )

        engine = PostExecutionVerificationEngine(runner=runner)
        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
        )

        assert summary.outcome == VerificationOutcome.INCONCLUSIVE
        assert summary.status == "uncertain"
        assert "Broker infrastructure unavailable" in (summary.error_message or "")

        db_session.refresh(execution)
        assert execution.status == ExecutionState.VERIFICATION_PENDING.value
        assert execution.verification_status == "inconclusive"
        assert "VERIFICATION_INCONCLUSIVE" in execution.uncertain_reason

        # Incident remains active
        db_session.refresh(incident)
        assert incident.status == "remediating"
        assert incident.status != "recovered"

    def test_duplicate_probe_persistence_rules(self, db_session, mock_entities):
        """
        Verify persistence duplicate handling:
        - Identical duplicate probe: idempotent no-op.
        - Conflicting duplicate probe: raises ConflictingProbePayloadError.
        """
        execution = mock_entities["execution"]
        workspace = mock_entities["workspace"]

        now_utc = datetime.now(timezone.utc)
        cycle = VerificationPersistenceService.create_or_get_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            cycle_number=1,
            deadline_at=now_utc + timedelta(seconds=45),
        )

        # 1. First probe record
        p1 = VerificationPersistenceService.record_probe_result(
            db=db_session,
            cycle_id=cycle.id,
            probe_number=1,
            probe_type="baseline",
            target_url="http://host.docker.internal:8001/health",
            passed=True,
            status="passed",
            status_code=200,
            probe_output={"status": "healthy"},
        )
        assert p1.id == generate_deterministic_probe_id(execution.id, 1, 1)

        # 2. Identical duplicate -> returns existing record idempotently
        p2 = VerificationPersistenceService.record_probe_result(
            db=db_session,
            cycle_id=cycle.id,
            probe_number=1,
            probe_type="baseline",
            target_url="http://host.docker.internal:8001/health",
            passed=True,
            status="passed",
            status_code=200,
            probe_output={"status": "healthy"},
        )
        assert p2.id == p1.id

        # 3. Conflicting duplicate -> raises ConflictingProbePayloadError
        with pytest.raises(ConflictingProbePayloadError):
            VerificationPersistenceService.record_probe_result(
                db=db_session,
                cycle_id=cycle.id,
                probe_number=1,
                probe_type="baseline",
                target_url="http://host.docker.internal:8001/health",
                passed=False,  # Conflict: passed is False!
                status="failed",
                status_code=500,
            )

    def test_workspace_isolation_enforcement(self, db_session, mock_entities):
        """Verify strict workspace isolation: execution or service from wrong workspace rejected."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]

        other_ws = Workspace(id=str(uuid.uuid4()), name="Foreign WS", slug="foreign-ws")
        db_session.add(other_ws)
        db_session.commit()

        runner = VerificationTestRunner()
        engine = PostExecutionVerificationEngine(runner=runner)

        # Cross-workspace execution rejection
        with pytest.raises(CrossWorkspaceViolationError):
            engine.run_verification_cycle(
                db=db_session,
                execution_id=execution.id,
                workspace_id=other_ws.id,  # Mismatch!
                service=service,
            )

    def test_stale_fencing_token_rejection(self, db_session, mock_entities):
        """Verify that stale worker fencing tokens are immediately rejected."""
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        # Execution has fencing_token=1 in DB
        runner = VerificationTestRunner()
        engine = PostExecutionVerificationEngine(runner=runner)

        # Worker attempts verification with stale token=0
        with pytest.raises(StaleWorkerFencingError):
            engine.run_verification_cycle(
                db=db_session,
                execution_id=execution.id,
                workspace_id=workspace.id,
                service=service,
                worker_id="worker-test-01",
                fencing_token=0,  # Stale! (DB has 1)
            )

    def test_no_remediation_redispatch_during_verification(self, db_session, mock_entities):
        """
        Verify safety invariant:
        Zero remediation actions (restore_order_api_demo) are executed during verification.
        Verification traffic uses strictly inspect_service_health.
        """
        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        engine = PostExecutionVerificationEngine(runner=runner)

        engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
        )

        assert len(runner.dispatched_calls) > 0
        for call in runner.dispatched_calls:
            assert call["action_id"] == "inspect_service_health"
            assert call["action_id"] != "restore_order_api_demo"

    def test_transition_to_verification_pending_keeps_lease_valid(self, db_session, mock_entities):
        """Verify transitioning to verification_pending leaves worker lease and token intact."""
        execution = mock_entities["execution"]
        workspace = mock_entities["workspace"]

        original_locked_by = execution.locked_by
        original_token = execution.fencing_token
        original_until = execution.locked_until

        engine = PostExecutionVerificationEngine()
        res = engine.transition_to_verification_pending(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            worker_id=original_locked_by,
            fencing_token=original_token,
        )

        assert res.status == ExecutionState.VERIFICATION_PENDING.value
        assert res.locked_by == original_locked_by
        assert res.fencing_token == original_token
        assert res.locked_until == original_until

    def test_no_direct_backend_network_access_from_verification_engine(self, db_session, mock_entities, monkeypatch):
        """
        Verify that PostExecutionVerificationEngine NEVER opens direct network sockets
        or HTTP client connections to target services. All traffic delegates to runner.execute.
        """
        import socket
        import urllib.request
        import httpx

        # Poison direct network calls
        def forbidden_direct_call(*args, **kwargs):
            raise AssertionError("SECURITY VIOLATION: Verification engine made direct network call without runner!")

        monkeypatch.setattr(httpx.Client, "send", forbidden_direct_call)
        monkeypatch.setattr(urllib.request, "urlopen", forbidden_direct_call)

        execution = mock_entities["execution"]
        service = mock_entities["service"]
        workspace = mock_entities["workspace"]

        runner = VerificationTestRunner()
        engine = PostExecutionVerificationEngine(runner=runner)

        summary = engine.run_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            service=service,
            worker_id="worker-test-01",
            fencing_token=1,
            cycle_number=1,
        )

        assert summary.outcome == VerificationOutcome.PASS
        # Assert traffic went strictly through runner: exactly 1 dispatch per probe
        assert len(runner.dispatched_calls) == 4  # Phase 3C: 4 probes (1 baseline + 3 checks) = 4 dispatches
        for c in runner.dispatched_calls:
            assert c["action_id"] == "inspect_service_health"
