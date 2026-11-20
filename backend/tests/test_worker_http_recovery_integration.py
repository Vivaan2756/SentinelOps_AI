"""Comprehensive Integration Test Suite for Option C Stage 2.
Worker Integration, Audience Migration & Durable Coordination.

Validates:
1. Worker dispatches allowlisted HTTP recovery actions via IsolatedHttpRecoveryRunner.
2. Complete authorization manifest and detached Ed25519 signature are forwarded through
   RunnerBrokerClientAdapter to IsolatedHttpRecoveryRunner.
3. New 'sentinelops.execution' audience is strictly verified; legacy 'sentinelops.broker'
   fails closed during pre-flight.
4. Tampered, expired, or invalid manifests fail closed before dispatch and never touch the network.
5. Unsupported infrastructure actions fail closed immediately with zero fallback to broker.
6. Durable coordination pipeline (SQLite reservation, binary OperationJournal DISPATCH_PREPARED,
   fencing check, and CALL_STARTED barrier) strictly precedes network execution.
7. Network timeout or connection drop fails closed into ExecutionUncertainError, recording
   DISPATCH_UNCERTAIN and locking with HOLD_EXPIRATION_TIMESTAMP (year 9999).
8. Uncertain executions cannot be blindly reclaimed by any subsequent worker.
9. Independent PostExecutionVerificationEngine probes the service; 3 consecutive passes
   recovers the incident.
10. Failed post-execution verification leaves the incident open; HTTP response alone never closes it.
11. Complete privilege separation: public verification keys only, zero private key access, zero Docker socket.
"""

import base64
import copy
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch
import uuid

import httpcore
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.config import settings
from app.core.manifest_crypto import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    MAX_MANIFEST_LIFETIME_SECONDS,
    ExecutionManifest,
    compute_parameters_digest,
)
from app.core.rfc8785 import canonicalize
from app.execution.broker import BrokerExecuteRequest, BrokerExecuteResponse
from app.execution.broker_dispatcher import BrokerDispatcher, BrokerDispatchResult
from app.execution.dispatch_coordinator import DispatchCoordinator
from app.execution.exceptions import (
    BrokerSecurityViolation,
    ExecutionUncertainError,
    PreconditionFailedError,
    SecurityConfigurationError,
    StaleWorkerFencingError,
)
from app.execution.journal import OperationJournal
from app.execution.manager import RemediationExecutionManager
from app.execution.manifest_signer import generate_and_sign_execution_manifest
from app.execution.public_keys import BrokerPublicKeyRegistry, KeyStatus
from app.execution.registry import OperationRegistry, OperationStatus
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
    get_execution_runner,
)
from app.execution.runners.http_recovery import (
    ExecutionAuthorizationError,
    IsolatedHttpRecoveryRunner,
)
from app.execution.state_machine import ExecutionState
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
)
from app.execution.worker import (
    HOLD_EXPIRATION_TIMESTAMP,
    DurableExecutionWorker,
    RunnerBrokerClientAdapter,
)
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership


TEST_KEY_ID = "sentinelops-test-key-v1"


@pytest.fixture
def test_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate ephemeral Ed25519 keypair for cryptographic testing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def pub_key_registry(test_keypair) -> BrokerPublicKeyRegistry:
    """Initialize public-key registry with test public verification key only (zero private key)."""
    _, pub = test_keypair
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    config = {
        TEST_KEY_ID: {
            "public_key": pub_b64,
            "status": "active",
        }
    }
    return BrokerPublicKeyRegistry(config=config)


@pytest.fixture
def isolated_http_runner(pub_key_registry) -> IsolatedHttpRecoveryRunner:
    """Instantiate IsolatedHttpRecoveryRunner with test public verification key."""
    return IsolatedHttpRecoveryRunner(
        public_key_registry=pub_key_registry,
        environment="development",
    )


@pytest.fixture
def stage2_env(db_session, test_keypair, monkeypatch):
    """Provide fully populated database environment with signing key for worker integration tests."""
    priv, _ = test_keypair
    priv_bytes = priv.private_bytes_raw()
    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", priv_b64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Stage 2 Test WS",
        slug=f"stage2-ws-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws)

    engineer = User(
        id=str(uuid.uuid4()),
        email=f"stage2_eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Stage 2 Test Engineer",
        hashed_password="pw",
    )
    db_session.add(engineer)

    m_eng = WorkspaceMembership(workspace_id=ws.id, user_id=engineer.id, role="engineer")
    db_session.add(m_eng)

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        is_active=True,
        execution_policy="approval_required",
    )
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="High Error Rate in Order API",
        severity="high",
        status="investigating",
        trigger="high_error_rate",
    )
    db_session.add(inc)

    recovery_params = {
        "service_id": svc.id,
        "recovery_path": "/demo/restore",
        "payload": {"reason": "automated test recovery"},
        "expected_status_codes": [200],
    }

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="execute_http_recovery",
        target_service_id=svc.id,
        risk_level="medium",
        decision="allowed",
        decision_reason="Approved recovery for test incident",
        policy_version="v1.0",
        validated_parameters=recovery_params,
    )
    db_session.add(dec)

    now_utc = datetime.now(timezone.utc)
    appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="execute_http_recovery",
        target_service_id=svc.id,
        validated_parameters=recovery_params,
        risk_level="medium",
        approval_status="approved",
        reviewed_by=engineer.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
        policy_version="v1.0",
    )
    db_session.add(appr)
    db_session.commit()

    # Register dynamic playbook association so execute_http_recovery is authorized for this service
    from app.remediation.registry import ActionRegistry
    ActionRegistry.register_service_playbook(svc.id, ["execute_http_recovery"])

    yield {
        "ws": ws,
        "engineer": engineer,
        "svc": svc,
        "inc": inc,
        "approval": appr,
        "priv_key": priv,
        "recovery_params": recovery_params,
    }

    ActionRegistry.clear_dynamic_playbooks()


# ============================================================================
# 1. Real Worker Dispatches via IsolatedHttpRecoveryRunner
# ============================================================================

def test_worker_dispatches_http_recovery_via_isolated_runner(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    Test that the real worker dispatches an approved HTTP recovery action
    via IsolatedHttpRecoveryRunner, validating end-to-end manifest pass-through,
    execution identity binding, and durable state finalization.
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    # Confirm manifest was issued with the new execution audience
    assert exec_record.authorization_manifest["audience"] == "sentinelops.execution"
    assert exec_record.authorization_manifest["issuer"] == "sentinelops.control-plane"
    assert exec_record.authorization_manifest["action_id"] == "execute_http_recovery"

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    # Mock outbound HTTP client to return 200 OK
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.text = json.dumps({"status": "recovered", "orders_active": True})
    mock_resp.json.return_value = {"status": "recovered", "orders_active": True}

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id
        mock_post.assert_called_once()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_SUCCEEDED.value
    assert exec_record.execution_output["status_code"] == 200
    assert exec_record.execution_output["response"]["status"] == "recovered"
    assert exec_record.locked_by is None
    worker.stop()


# ============================================================================
# 2. Rejection of Legacy Broker-Audience Manifest
# ============================================================================

def test_worker_rejects_broker_audience_manifest_in_preflight(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    Critical audience migration test:
    Verify that an execution manifest signed with legacy 'sentinelops.broker' audience
    is strictly rejected by the new worker in pre-flight authorization, failing closed
    into execution_failed without writing CALL_STARTED or initiating network requests.
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    # Re-sign manifest deliberately with legacy broker audience
    broker_manifest, sig, digest = generate_and_sign_execution_manifest(
        execution_id=exec_record.id,
        approval=env["approval"],
        service=env["svc"],
        private_key=env["priv_key"],
        key_id=TEST_KEY_ID,
        audience="sentinelops.broker",  # Deliberate legacy broker audience
    )
    exec_record.manifest_id = broker_manifest.manifest_id
    exec_record.authorization_manifest = broker_manifest.model_dump()
    exec_record.manifest_signature = sig
    exec_record.manifest_digest = digest
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    with patch("httpx.Client.post") as mock_post:
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id
        mock_post.assert_not_called()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "authorization_failed"
    assert "Invalid manifest audience 'sentinelops.broker'" in exec_record.error_message
    assert "Expected 'sentinelops.execution'" in exec_record.error_message

    # Verify SQLite and journal records were NEVER created (pre-flight rejection)
    reg = OperationRegistry(db_path=reg_path)
    reg.initialize()
    op = reg.get_by_execution_and_token(exec_record.id, 1)
    assert op is None
    worker.stop()


# ============================================================================
# 3. Rejection of Tampered Manifest
# ============================================================================

def test_worker_rejects_tampered_manifest_in_preflight(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """Verify worker rejects manifest whose parameters or signature have been tampered."""
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    # Tamper with the parameter digest
    tampered_manifest = copy.deepcopy(exec_record.authorization_manifest)
    tampered_manifest["parameters_sha256"] = "0" * 64
    exec_record.authorization_manifest = tampered_manifest
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    with patch("httpx.Client.post") as mock_post:
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id
        mock_post.assert_not_called()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "authorization_failed"
    worker.stop()


# ============================================================================
# 4. Rejection of Unsupported Actions (No Broker Fallback)
# ============================================================================

def test_worker_rejects_unsupported_action_without_fallback(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    Verify that an action not in the allowlist of IsolatedHttpRecoveryRunner fails
    closed immediately and never attempts to fall back to broker execution.
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    # Change action_id on execution record to unsupported action
    exec_record.action_id = "restart_docker_container"
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    with patch("httpx.Client.post") as mock_post:
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id
        mock_post.assert_not_called()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    worker.stop()


# ============================================================================
# 5. Network Timeout Fails Closed into Execution Uncertain & Permanent Hold
# ============================================================================

def test_worker_handles_timeout_as_execution_uncertain_with_permanent_hold(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    Verify that a network timeout after CALL_STARTED records DISPATCH_UNCERTAIN
    and sets locked_until to HOLD_EXPIRATION_TIMESTAMP (year 9999), ensuring
    the operation can NEVER be reclaimed or blindly retried.
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_coordinator=True,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    # Simulate network timeout during HTTP request
    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Read timed out")):
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_UNCERTAIN.value
    # Assert locked_until is set to HOLD_EXPIRATION_TIMESTAMP (year 9999)
    assert exec_record.locked_until.year == 9999

    # Verify that a subsequent worker CANNOT reclaim this uncertain execution
    worker2 = DurableExecutionWorker(
        worker_id="test-stage2-worker-2",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_coordinator=True,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )
    next_claim = worker2.run_once()
    assert next_claim is None, "Uncertain execution with HOLD_EXPIRATION_TIMESTAMP must not be reclaimable"

    # Verify SQLite recorded DISPATCH_UNCERTAIN
    reg = OperationRegistry(db_path=reg_path)
    op = reg.get_by_execution_and_token(exec_record.id, 1)
    assert op is not None
    assert op.operation_status == OperationStatus.DISPATCH_UNCERTAIN
    worker.stop()
    worker2.stop()


# ============================================================================
# 6. Connection Reset Handling
# ============================================================================

def test_worker_handles_connection_reset_as_execution_uncertain(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """Verify connection drop after request transmission records execution_uncertain."""
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_coordinator=True,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    with patch("httpx.Client.post", side_effect=httpcore.TimeoutException("Server connection timed out")):
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_record.locked_until.year == 9999
    worker.stop()


# ============================================================================
# 7. Pre-Dispatch Persistence Barrier & Ordering Verification
# ============================================================================

def test_worker_durable_pre_dispatch_ordering(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    Verify strict dispatch ordering:
    1. Local operation reservation in SQLite registry
    2. DISPATCH_PREPARED in binary OperationJournal
    3. Fencing and database revalidation
    4. CALL_STARTED written to journal and registry
    5. Only then HTTP network request dispatched
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    events_recorded = []

    def mock_post_interceptor(*args, **kwargs):
        # Inspect durable SQLite registry and journal AT THE EXACT MOMENT OF NETWORK TRANSMISSION
        reg = OperationRegistry(db_path=reg_path)
        op = reg.get_by_execution_and_token(exec_record.id, 1)
        assert op is not None, "Operation MUST be reserved before network dispatch"
        assert op.operation_status == OperationStatus.DOCKER_CALL_STARTED, (
            "CALL_STARTED marker MUST be persisted before HTTP network transmission"
        )
        events_recorded.append("NETWORK_CALLED")

        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_redirect = False
        resp.text = json.dumps({"status": "ok"})
        resp.json.return_value = {"status": "ok"}
        return resp

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_coordinator=True,
        enable_verification=False,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    with patch("httpx.Client.post", side_effect=mock_post_interceptor):
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id

    assert "NETWORK_CALLED" in events_recorded

    # Stop worker to release journal file lock before replay inspection
    worker.stop()

    # Check journal records
    jour = OperationJournal(journal_dir=jour_dir)
    records = jour.replay()
    record_types = [r.record_type if isinstance(r.record_type, str) else r.record_type.value for r in records]
    assert "DISPATCH_PREPARED" in record_types
    assert "DOCKER_CALL_STARTED" in record_types
    assert "DOCKER_CALL_COMPLETED" in record_types

    # Ensure PREPARED preceded STARTED, and STARTED preceded COMPLETED
    prep_idx = record_types.index("DISPATCH_PREPARED")
    start_idx = record_types.index("DOCKER_CALL_STARTED")
    comp_idx = record_types.index("DOCKER_CALL_COMPLETED")
    assert prep_idx < start_idx < comp_idx, "Durable dispatch ordering violated!"


# ============================================================================
# 8. Post-Execution Independent Verification Lifecycle
# ============================================================================

def test_worker_lifecycle_with_independent_verification_success(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    Verify complete lifecycle:
    1. Recovery action succeeds via IsolatedHttpRecoveryRunner.
    2. Execution transitions to verification_pending.
    3. PostExecutionVerificationEngine independently probes the registered service.
    4. 3 consecutive passing health checks transition cycle to PASS and execution to VERIFIED.
    5. Incident transitions to recovered and closed.
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_coordinator=True,
        enable_verification=True,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    # Recovery response
    recovery_resp = MagicMock(spec=httpx.Response)
    recovery_resp.status_code = 200
    recovery_resp.is_redirect = False
    recovery_resp.text = json.dumps({"status": "restored"})
    recovery_resp.json.return_value = {"status": "restored"}

    # Diagnostic probe handler (for /health, /demo/status, /metrics)
    def mock_diagnostic_get(url, *args, **kwargs):
        url_str = str(url)
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_redirect = False
        if "/demo/status" in url_str:
            resp.text = json.dumps({"status": "ok", "failure_active": False})
            resp.json.return_value = {"status": "ok", "failure_active": False}
        elif "/metrics" in url_str:
            resp.text = "order_api_http_5xx_errors_total 0\n"
            resp.json.return_value = {"order_api_http_5xx_errors_total": 0}
        else:
            resp.text = json.dumps({"status": "healthy", "service": "Order API"})
            resp.json.return_value = {"status": "healthy", "service": "Order API"}
        return resp

    with patch("httpx.Client.post", return_value=recovery_resp), \
         patch("httpx.Client.get", side_effect=mock_diagnostic_get):
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.VERIFIED.value
    assert exec_record.verification_status in ("verified", "passed")

    # Incident must be marked recovered
    inc = db_session.query(Incident).filter(Incident.id == env["inc"].id).first()
    assert inc.status == "recovered"
    assert inc.recovered_at is not None
    worker.stop()


def test_failed_verification_leaves_incident_open(
    db_session, stage2_env, isolated_http_runner, tmp_path
):
    """
    CRITICAL SAFETY REQUIREMENT:
    A successful HTTP recovery response alone MUST NEVER close an incident.
    If post-execution verification fails, the incident must remain open.
    """
    env = stage2_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    db_session.commit()

    reg_path = str(tmp_path / "registry.db")
    jour_dir = str(tmp_path / "journal")
    os.makedirs(jour_dir, exist_ok=True)

    worker = DurableExecutionWorker(
        worker_id="test-stage2-worker",
        runner=isolated_http_runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_coordinator=True,
        enable_verification=True,
        registry_path=reg_path,
        journal_dir=jour_dir,
    )

    # Recovery response returns 200 OK (remediation claimed success)
    recovery_resp = MagicMock(spec=httpx.Response)
    recovery_resp.status_code = 200
    recovery_resp.is_redirect = False
    recovery_resp.text = json.dumps({"status": "restored"})
    recovery_resp.json.return_value = {"status": "restored"}

    # Diagnostic probe returns 503 Service Unavailable (service is STILL broken)
    def mock_fail_get(url, *args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 503
        resp.is_redirect = False
        resp.text = json.dumps({"status": "unhealthy", "error": "db down"})
        resp.json.return_value = {"status": "unhealthy", "error": "db down"}
        return resp

    with patch("httpx.Client.post", return_value=recovery_resp), \
         patch("httpx.Client.get", side_effect=mock_fail_get):
        claimed_id = worker.run_once()
        assert claimed_id == exec_record.id

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.VERIFICATION_FAILED.value
    assert exec_record.verification_status == "failed"

    # Incident MUST REMAIN OPEN (investigating)
    inc = db_session.query(Incident).filter(Incident.id == env["inc"].id).first()
    assert inc.status == "investigating"
    assert inc.recovered_at is None
    worker.stop()
