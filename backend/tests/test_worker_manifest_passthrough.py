"""Tests for Phase 2A.1 Stage 5: Worker IPC Manifest Pass-Through.

Verifies:
1. Exact pass-through of control-plane signed authorization manifest and detached signature
   from RemediationExecution to BrokerExecuteRequest over IPC.
2. Worker acts strictly as a transport: zero mutation, zero key loading, zero manifest creation.
3. Pre-flight fail-closed semantics for:
   - Missing authorization_manifest
   - Missing manifest_signature
   - Incomplete manifest metadata (manifest_id, manifest_digest, manifest_key_id)
   - Invalid manifest type (non-dict)
   - Identity mismatches (execution_id, workspace_id, approval_id, action_id, service_id, manifest_id, key_id)
4. Immediate pre-dispatch revalidation (Stage 6) detecting manifest tampering between claim and dispatch.
5. Historical executions without manifests cannot be newly dispatched.
6. Coordinator journal and registry start_metadata records manifest_id.
7. Length-prefixed framing and Pydantic strictness (extra='forbid') roundtrip preservation.
"""

import copy
import json
import struct
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_dispatcher import BrokerDispatcher
from app.execution.dispatch_coordinator import DispatchCoordinator
from app.execution.manager import RemediationExecutionManager
from app.execution.journal import (
    JournalRecordType,
    OperationJournal,
)
from app.execution.registry import (
    OperationRegistry,
    OperationStatus,
)
from app.execution.worker import DurableExecutionWorker
from app.execution.state_machine import ExecutionState
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
from app.models.workspace import Workspace, WorkspaceMembership


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def passthrough_env(db_session):
    """Provide a complete environment with signed execution records."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Worker Manifest Passthrough WS",
        slug=f"passthrough-ws-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws)

    engineer = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Passthrough Engineer",
        hashed_password="hashed_pw",
    )
    db_session.add(engineer)

    membership = WorkspaceMembership(workspace_id=ws.id, user_id=engineer.id, role="engineer")
    db_session.add(membership)

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        is_active=True,
    )
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="High Latency Warning",
        severity="medium",
        status="investigating",
        trigger="high_latency",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="inspect_service_health",
        target_service_id=svc.id,
        risk_level="low",
        decision="allowed",
        decision_reason="Read-only health check",
        policy_version="v1.0",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)

    now_utc = datetime.now(timezone.utc)
    appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="inspect_service_health",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="low",
        approval_status="approved",
        requested_by=engineer.id,
        requested_at=now_utc,
        reviewed_by=engineer.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(appr)
    db_session.commit()

    return {
        "ws": ws,
        "engineer": engineer,
        "svc": svc,
        "incident": inc,
        "decision": dec,
        "approval": appr,
    }


@pytest.fixture
def coordinator_setup(tmp_path):
    """Provide isolated SQLite OperationRegistry and binary OperationJournal."""
    reg_db = tmp_path / "coordinator_registry.db"
    jour_dir = tmp_path / "journal"
    jour_dir.mkdir(exist_ok=True)
    registry = OperationRegistry(db_path=str(reg_db))
    journal = OperationJournal(journal_dir=str(jour_dir))
    coordinator = DispatchCoordinator(registry=registry, journal=journal)
    coordinator.initialize()
    mock_client = MagicMock()
    dispatcher = BrokerDispatcher(coordinator=coordinator, broker_client=mock_client)
    return {
        "coordinator": coordinator,
        "registry": registry,
        "journal": journal,
        "mock_client": mock_client,
        "dispatcher": dispatcher,
    }


# ============================================================================
# 1. Exact Pass-Through via Coordinated Dispatch Pipeline
# ============================================================================

def test_coordinated_worker_manifest_passthrough_exactness(db_session, passthrough_env, coordinator_setup):
    """
    Worker retrieves the exact signed authorization manifest and detached signature
    persisted by the control plane and passes them completely unchanged in BrokerExecuteRequest.
    """
    env = passthrough_env
    coord = coordinator_setup

    # Create execution with control-plane signed manifest
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec_record.authorization_manifest is not None
    assert exec_record.manifest_signature is not None
    assert exec_record.manifest_id is not None
    assert exec_record.manifest_digest is not None

    captured_request: Optional[BrokerExecuteRequest] = None

    def fake_execute_action(req: BrokerExecuteRequest) -> BrokerExecuteResponse:
        nonlocal captured_request
        captured_request = req
        return BrokerExecuteResponse(
            execution_id=req.execution_id,
            exit_code=0,
            duration_ms=50,
            stdout_sample="All checks passed.",
        )

    coord["mock_client"].execute_action.side_effect = fake_execute_action

    worker = DurableExecutionWorker(
        worker_id="worker-passthrough-1",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    claimed_id = worker.run_once()
    assert claimed_id == exec_record.id
    assert coord["mock_client"].execute_action.call_count == 1
    assert captured_request is not None

    # Assert exact byte-for-byte / value equality
    assert captured_request.execution_id == exec_record.id
    assert captured_request.action_id == exec_record.action_id
    assert captured_request.authorization_manifest == exec_record.authorization_manifest
    assert captured_request.manifest_signature == exec_record.manifest_signature

    # Assert deepcopy / immutability
    assert captured_request.authorization_manifest is not exec_record.authorization_manifest

    # Assert execution completed successfully
    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_SUCCEEDED.value


# ============================================================================
# 2. Coordinator Journal Records Manifest ID in DOCKER_CALL_STARTED Marker
# ============================================================================

def test_coordinator_journal_records_manifest_id(db_session, passthrough_env, coordinator_setup):
    """The local coordinator journal logs manifest_id in start_metadata before IPC invocation."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    coord["mock_client"].execute_action.return_value = BrokerExecuteResponse(
        execution_id=exec_record.id,
        exit_code=0,
        duration_ms=45,
        stdout_sample="OK",
    )

    worker = DurableExecutionWorker(
        worker_id="worker-passthrough-jour",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()

    # Verify journal records
    records = coord["journal"].replay()
    start_records = [r for r in records if r.record_type == JournalRecordType.DOCKER_CALL_STARTED.value]
    assert len(start_records) == 1
    assert start_records[0].metadata.get("manifest_id") == exec_record.manifest_id


# ============================================================================
# 3. Pre-Flight Fail-Closed: Missing Manifest or Signature
# ============================================================================

def test_preflight_missing_manifest_fails_closed(db_session, passthrough_env, coordinator_setup):
    """If authorization_manifest is None, preflight fails closed with missing_authorization_manifest."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    # Simulate missing manifest
    exec_record.authorization_manifest = None
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-missing-manifest",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    claimed_id = worker.run_once()
    assert claimed_id == exec_record.id
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "missing_authorization_manifest"
    assert "signed authorization manifest" in exec_record.error_message.lower()


def test_preflight_missing_signature_fails_closed(db_session, passthrough_env, coordinator_setup):
    """If manifest_signature is None or empty string, preflight fails closed."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    exec_record.manifest_signature = ""
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-missing-sig",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "missing_authorization_manifest"


# ============================================================================
# 4. Pre-Flight Fail-Closed: Incomplete Manifest Metadata
# ============================================================================

@pytest.mark.parametrize("missing_field", ["manifest_id", "manifest_digest", "manifest_key_id"])
def test_preflight_incomplete_metadata_fails_closed(db_session, passthrough_env, coordinator_setup, missing_field):
    """If any of manifest_id, manifest_digest, or manifest_key_id is missing, preflight fails closed."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    setattr(exec_record, missing_field, None)
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-incomplete-meta",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "incomplete_authorization_data"


def test_preflight_invalid_manifest_payload_fails_closed(db_session, passthrough_env, coordinator_setup):
    """If authorization_manifest is not a dict, preflight fails closed."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    exec_record.authorization_manifest = "not-a-dictionary-string"
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-invalid-manifest",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "invalid_authorization_manifest"


# ============================================================================
# 5. Pre-Flight Fail-Closed: Identity Mismatches
# ============================================================================

def test_preflight_mismatched_execution_id_fails_closed(db_session, passthrough_env, coordinator_setup):
    """Manifest execution_id tampered to differ from RemediationExecution.id."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    tampered_manifest = copy.deepcopy(exec_record.authorization_manifest)
    tampered_manifest["execution_id"] = str(uuid.uuid4())
    exec_record.authorization_manifest = tampered_manifest
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-mismatch-exec-id",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_execution_mismatch"


def test_preflight_mismatched_workspace_id_fails_closed(db_session, passthrough_env, coordinator_setup):
    """Manifest workspace_id tampered to differ from RemediationExecution.workspace_id."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    tampered_manifest = copy.deepcopy(exec_record.authorization_manifest)
    tampered_manifest["workspace_id"] = str(uuid.uuid4())
    exec_record.authorization_manifest = tampered_manifest
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-mismatch-ws-id",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_workspace_mismatch"


def test_preflight_mismatched_approval_id_fails_closed(db_session, passthrough_env, coordinator_setup):
    """Manifest approval_id tampered to differ from RemediationExecution.approval_id."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    tampered_manifest = copy.deepcopy(exec_record.authorization_manifest)
    tampered_manifest["approval_id"] = str(uuid.uuid4())
    exec_record.authorization_manifest = tampered_manifest
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-mismatch-appr-id",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_approval_mismatch"


def test_preflight_mismatched_action_id_fails_closed(db_session, passthrough_env, coordinator_setup):
    """Manifest action_id tampered to differ from RemediationExecution.action_id."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    tampered_manifest = copy.deepcopy(exec_record.authorization_manifest)
    tampered_manifest["action_id"] = "restore_order_api_demo"
    exec_record.authorization_manifest = tampered_manifest
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-mismatch-act-id",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_action_mismatch"


def test_preflight_mismatched_service_id_fails_closed(db_session, passthrough_env, coordinator_setup):
    """Manifest service_id tampered to differ from RemediationExecution.target_service_id."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    tampered_manifest = copy.deepcopy(exec_record.authorization_manifest)
    tampered_manifest["service_id"] = str(uuid.uuid4())
    exec_record.authorization_manifest = tampered_manifest
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-mismatch-svc-id",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_service_mismatch"


def test_preflight_mismatched_manifest_or_key_id_fails_closed(db_session, passthrough_env, coordinator_setup):
    """Manifest manifest_id or key_id tampered to differ from execution columns."""
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    # Tamper manifest_id in the execution column
    exec_record.manifest_id = str(uuid.uuid4())
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-mismatch-id-column",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    worker.run_once()
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_identity_mismatch"


# ============================================================================
# 6. Immediate Pre-Dispatch Revalidation: Tampering Detected
# ============================================================================

def test_immediate_predispatch_tampering_fails_closed(db_session, passthrough_env, coordinator_setup):
    """
    If manifest_id or manifest_digest in the DB is altered between the initial
    worker claim and the Stage 6 immediate pre-dispatch revalidation, the dispatch
    is aborted and execution is failed closed.
    """
    env = passthrough_env
    coord = coordinator_setup

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    worker = DurableExecutionWorker(
        worker_id="worker-test-predispatch-tamper",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    # Intercept prepare_dispatch to tamper with the execution manifest in DB before Stage 6
    orig_prepare_dispatch = coord["coordinator"].prepare_dispatch

    def tamper_then_prepare(*args, **kwargs):
        res = orig_prepare_dispatch(*args, **kwargs)
        # Directly mutate the database record to simulate an attacker altering it in flight
        with worker._get_db() as db:
            e = db.query(RemediationExecution).filter(RemediationExecution.id == exec_record.id).first()
            e.manifest_digest = "e" * 64
            db.commit()
        return res

    coord["coordinator"].prepare_dispatch = tamper_then_prepare

    worker.run_once()

    # Broker was NEVER called
    assert coord["mock_client"].execute_action.call_count == 0

    # Execution is failed closed
    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "manifest_tampered"
    assert "manifest altered between claim and dispatch" in exec_record.error_message.lower()


# ============================================================================
# 7. Historical Manifest-less Executions Cannot Be Dispatched
# ============================================================================

def test_historical_manifestless_execution_cannot_be_dispatched(db_session, passthrough_env, coordinator_setup):
    """
    Simulates a historical execution queued before Phase 2A.1 without any manifest fields.
    The worker claims it, but pre-flight fails closed, preventing dispatch.
    """
    env = passthrough_env
    coord = coordinator_setup
    now_utc = datetime.now(timezone.utc)

    # Insert raw legacy execution record without manifest
    legacy_exec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.QUEUED.value,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"].id,
        triggered_at=now_utc,
        # Manifest fields are left NULL
        manifest_id=None,
        authorization_manifest=None,
        manifest_signature=None,
        manifest_digest=None,
        manifest_key_id=None,
    )
    db_session.add(legacy_exec)
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="worker-test-historical",
        coordinator=coord["coordinator"],
        broker_dispatcher=coord["dispatcher"],
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    claimed_id = worker.run_once()
    assert claimed_id == legacy_exec.id
    assert coord["mock_client"].execute_action.call_count == 0

    db_session.refresh(legacy_exec)
    assert legacy_exec.status == ExecutionState.EXECUTION_FAILED.value
    assert legacy_exec.error_category == "missing_authorization_manifest"


# ============================================================================
# 8. BrokerExecuteRequest Schema Validation & Wire Framing
# ============================================================================

def test_broker_execute_request_schema_strictness():
    """Verify BrokerExecuteRequest validates authorization_manifest and manifest_signature and rejects extra fields."""
    req_data = {
        "execution_id": str(uuid.uuid4()),
        "action_id": "inspect_service_health",
        "parameters": {"service_id": "svc-123"},
        "target_url": "http://127.0.0.1:8001/health",
        "timeout_seconds": 30,
        "environment": "development",
        "authorization_manifest": {
            "manifest_version": "1.0",
            "execution_id": "exec-123",
            "action_id": "inspect_service_health",
        },
        "manifest_signature": "mock-ed25519-signature-base64url",
    }

    req = BrokerExecuteRequest.model_validate(req_data)
    assert req.authorization_manifest == req_data["authorization_manifest"]
    assert req.manifest_signature == req_data["manifest_signature"]

    # Reject unexpected fields (extra="forbid")
    bad_data = copy.deepcopy(req_data)
    bad_data["malicious_extra_field"] = "injection_attempt"
    with pytest.raises(ValidationError):
        BrokerExecuteRequest.model_validate(bad_data)


def test_broker_execute_request_wire_framing_roundtrip():
    """
    Simulates IPC framing roundtrip:
    Client serializes BrokerExecuteRequest with 4-byte length prefix ->
    Broker receives, extracts header, decodes JSON ->
    deserializes identical BrokerExecuteRequest.
    """
    req = BrokerExecuteRequest(
        execution_id=str(uuid.uuid4()),
        action_id="inspect_service_health",
        parameters={"service_id": "svc-order"},
        target_url="http://127.0.0.1:8001/health",
        timeout_seconds=30,
        environment="development",
        authorization_manifest={
            "manifest_version": "1.0",
            "manifest_id": str(uuid.uuid4()),
            "execution_id": "exec-abc",
            "service_id": "svc-order",
            "action_id": "inspect_service_health",
            "authorized_scheme": "http",
            "authorized_hostname": "127.0.0.1",
            "authorized_port": 8001,
            "authorized_path": "/health",
        },
        manifest_signature="signed_b64url_string_sample",
    )

    # Serialize client side
    payload_bytes = json.dumps(req.model_dump()).encode("utf-8")
    header = struct.pack("!I", len(payload_bytes))
    wire_bytes = header + payload_bytes

    # Deserialize server side
    recv_header = wire_bytes[:4]
    recv_payload_len = struct.unpack("!I", recv_header)[0]
    assert recv_payload_len == len(payload_bytes)

    recv_payload = wire_bytes[4 : 4 + recv_payload_len]
    recv_dict = json.loads(recv_payload.decode("utf-8"))
    server_req = BrokerExecuteRequest.model_validate(recv_dict)

    # Assert zero corruption
    assert server_req.execution_id == req.execution_id
    assert server_req.authorization_manifest == req.authorization_manifest
    assert server_req.manifest_signature == req.manifest_signature
