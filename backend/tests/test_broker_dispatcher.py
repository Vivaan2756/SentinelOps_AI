"""Comprehensive Test Suite for Broker IPC Dispatch Integration (Phase 4.3.6 Milestone E.3.3).

Covers:
1. Successful coordinator-to-broker request ordering.
2. Nonzero container exit code recording.
3. Journal failure before start marker prevents broker invocation.
4. Registry failure before dispatch prevents broker invocation.
5. Broker timeout after start marker creates an uncertain outcome.
6. Broker connection loss creates an uncertain outcome.
7. Malformed broker responses fail closed into uncertainty.
8. Duplicate operation requests do not redispatch.
9. Existing start markers prevent redispatch.
10. Fencing-token mismatch prevents dispatch.
11. Workspace/operation identity mismatch prevents dispatch.
12. Action not in allowlist is rejected immediately.
13. Broker success does not mark execution verified or incident recovered.
14. No Docker daemon, real container, PostgreSQL database, or /demo/* endpoint is contacted.
"""

import json
import os
import socket
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_client import UnixSocketBrokerClient
from app.execution.broker_dispatcher import (
    BrokerDispatcher,
    BrokerDispatchResult,
)
from app.execution.dispatch_coordinator import (
    CoordinatorConflictError,
    CoordinatorError,
    CoordinatorInvalidStateError,
    CoordinatorUncertaintyError,
    CoordinatorValidationError,
    DispatchCoordinator,
)
from app.execution.exceptions import (
    BrokerUnavailableError,
    ExecutionUncertainError,
)
from app.execution.journal import (
    JournalError,
    JournalRecordType,
    JournalWriteError,
    OperationJournal,
)
from app.execution.registry import (
    OperationRegistry,
    OperationStatus,
    RegistryIOError,
)


@pytest.fixture
def dispatcher_env():
    """Provides an isolated coordinator and mock broker client environment."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "dispatcher_test.db")
        journal_dir = os.path.join(tmp_dir, "journal")
        os.makedirs(journal_dir, exist_ok=True)

        reg = OperationRegistry(db_path=db_path)
        jour = OperationJournal(journal_dir=journal_dir)
        coord = DispatchCoordinator(registry=reg, journal=jour)
        coord.initialize()

        # Mock broker client
        mock_client = MagicMock(spec=UnixSocketBrokerClient)
        # Default canned response: successful exit 0
        mock_client.execute_action.return_value = BrokerExecuteResponse(
            execution_id="exec-1",
            exit_code=0,
            duration_ms=85,
            stdout_sample="Target service demo state restored.",
            stderr_sample="",
            output_data={"restored": True},
        )

        dispatcher = BrokerDispatcher(coordinator=coord, broker_client=mock_client)

        yield dispatcher, coord, reg, jour, mock_client, tmp_dir

        coord.close()


# ============================================================================
# 1. Successful Coordinator-to-Broker Request Ordering
# ============================================================================

def test_successful_coordinator_to_broker_ordering(dispatcher_env):
    """
    CRITICAL ORDERING REQUIREMENT:
    1. Validate operation identity and fencing token.
    2. Durably reserve operation in SQLite.
    3. DISPATCH_PREPARED journaled and fsynced.
    4. DOCKER_CALL_STARTED journaled and fsynced.
    5. ONLY THEN send broker IPC request.
    6. Persist broker completion in journal and SQLite.
    """
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    # Intercept broker execute_action to inspect state AT THE MOMENT OF INVOCATION
    observed_state_at_invocation = {}

    def inspect_at_call(req: BrokerExecuteRequest):
        # When broker is called, DOCKER_CALL_STARTED must already be durable
        j_records = jour.replay()
        observed_state_at_invocation["records_count"] = len(j_records)
        observed_state_at_invocation["latest_record_type"] = j_records[-1].record_type
        op = reg.get_by_execution_and_token(req.execution_id, 100)
        # SQLite must reflect DOCKER_CALL_STARTED
        observed_state_at_invocation["registry_status"] = op.operation_status if op else None
        return BrokerExecuteResponse(
            execution_id=req.execution_id,
            exit_code=0,
            duration_ms=120,
            stdout_sample="Order API demo restored successfully.",
        )

    mock_client.execute_action.side_effect = inspect_at_call

    result = dispatcher.dispatch_action(
        execution_id="exec-order-1",
        workspace_id="ws-prod",
        approval_id="appr-order-1",
        attempt_number=1,
        fencing_token=100,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
        parameters={"scope": "full_reset"},
        timeout_seconds=30,
    )

    # 1. Verify broker was called exactly once
    assert mock_client.execute_action.call_count == 1
    call_arg: BrokerExecuteRequest = mock_client.execute_action.call_args[0][0]
    assert call_arg.execution_id == "exec-order-1"
    assert call_arg.action_id == "restore_order_api_demo"
    assert call_arg.target_url == "http://order-api:8000/demo/restore"
    assert call_arg.parameters == {"scope": "full_reset"}

    # 2. Verify state AT MOMENT OF BROKER INVOCATION:
    # DISPATCH_PREPARED (seq 1) and DOCKER_CALL_STARTED (seq 2) were already fsynced!
    assert observed_state_at_invocation["records_count"] == 2
    assert observed_state_at_invocation["latest_record_type"] == JournalRecordType.DOCKER_CALL_STARTED.value

    # 3. Verify final state after broker return:
    # Journal now has seq 3 (DOCKER_CALL_COMPLETED)
    assert jour.current_sequence == 3
    final_records = jour.replay()
    assert [r.record_type for r in final_records] == [
        JournalRecordType.DISPATCH_PREPARED.value,
        JournalRecordType.DOCKER_CALL_STARTED.value,
        JournalRecordType.DOCKER_CALL_COMPLETED.value,
    ]

    # 4. Verify SQLite registry matches terminal completion
    reg_op = reg.get_operation(result.operation_id)
    assert reg_op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED

    # 5. Verify result payload
    assert result.is_success is True
    assert result.broker_completed is True
    assert result.exit_code == 0
    assert result.duration_ms == 120
    assert result.is_uncertain is False
    assert result.status == OperationStatus.DOCKER_CALL_COMPLETED


# ============================================================================
# 2. Nonzero Container Exit Code Recording
# ============================================================================

def test_nonzero_container_exit_recorded_as_failed(dispatcher_env):
    """If broker reports nonzero exit code, coordinator records DISPATCH_FAILED."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    mock_client.execute_action.return_value = BrokerExecuteResponse(
        execution_id="exec-err-1",
        exit_code=2,
        duration_ms=45,
        stdout_sample="",
        stderr_sample="Connection refused by service endpoint",
        error_message="Container command returned exit status 2",
        error_category="service_unreachable",
    )

    result = dispatcher.dispatch_action(
        execution_id="exec-err-1",
        workspace_id="ws-prod",
        approval_id="appr-err-1",
        attempt_number=1,
        fencing_token=101,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
    )

    assert result.is_success is False
    assert result.broker_completed is True
    assert result.exit_code == 2
    assert result.is_uncertain is False
    assert result.status == OperationStatus.DISPATCH_FAILED
    assert "exit status 2" in result.error_message

    # Verify SQLite and journal record DISPATCH_FAILED
    reg_op = reg.get_operation(result.operation_id)
    assert reg_op.operation_status == OperationStatus.DISPATCH_FAILED
    assert jour.current_sequence == 3
    assert jour.replay()[-1].record_type == JournalRecordType.DISPATCH_FAILED.value


# ============================================================================
# 3. Journal Failure Before Start Marker Prevents Broker Invocation
# ============================================================================

def test_journal_failure_before_start_marker_prevents_broker_call(dispatcher_env):
    """
    PRE-DISPATCH PERSISTENCE BARRIER:
    If journal append fails when attempting to write DOCKER_CALL_STARTED,
    the broker MUST NOT be contacted under any circumstance.
    """
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    # Mock journal append to fail on DOCKER_CALL_STARTED
    orig_append = jour.append

    def failing_append(record_type, **kwargs):
        if record_type == JournalRecordType.DOCKER_CALL_STARTED:
            raise JournalWriteError("Disk I/O error during start marker append")
        return orig_append(record_type, **kwargs)

    with patch.object(jour, "append", side_effect=failing_append):
        with pytest.raises(CoordinatorError, match="Journal append failed"):
            dispatcher.dispatch_action(
                execution_id="exec-jfail-1",
                workspace_id="ws-prod",
                approval_id="appr-jfail-1",
                attempt_number=1,
                fencing_token=102,
                action_id="restore_order_api_demo",
                target_url="http://order-api:8000/demo/restore",
            )

    # Broker must NEVER have been called
    assert mock_client.execute_action.call_count == 0

    # SQLite must remain in DISPATCH_PREPARED, never advancing to DOCKER_CALL_STARTED
    op = reg.get_by_execution_and_token("exec-jfail-1", 102)
    assert op is not None
    assert op.operation_status == OperationStatus.DISPATCH_PREPARED


# ============================================================================
# 4. Registry Failure Before Dispatch Prevents Broker Invocation
# ============================================================================

def test_registry_failure_before_dispatch_prevents_broker_call(dispatcher_env):
    """If SQLite registry fails before dispatch, broker is NEVER called."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    with patch.object(reg, "transition_operation", side_effect=RegistryIOError("SQLite lock timeout")):
        with pytest.raises(RegistryIOError, match="SQLite lock timeout"):
            dispatcher.dispatch_action(
                execution_id="exec-regfail-1",
                workspace_id="ws-prod",
                approval_id="appr-regfail-1",
                attempt_number=1,
                fencing_token=103,
                action_id="restore_order_api_demo",
                target_url="http://order-api:8000/demo/restore",
            )

    # Broker was never invoked
    assert mock_client.execute_action.call_count == 0


# ============================================================================
# 5. Broker Timeout After Start Marker Creates an Uncertain Outcome
# ============================================================================

def test_broker_timeout_after_start_marker_creates_uncertain_outcome(dispatcher_env):
    """
    FAIL-CLOSED UNCERTAINTY RULE:
    When broker times out after DOCKER_CALL_STARTED has been written,
    it is ambiguous whether socket bytes were delivered to Docker.
    The outcome MUST be classified as DISPATCH_UNCERTAIN.
    """
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    # Broker raises timeout
    mock_client.execute_action.side_effect = BrokerUnavailableError("Broker timed out during execution: 30s")

    result = dispatcher.dispatch_action(
        execution_id="exec-timeout-1",
        workspace_id="ws-prod",
        approval_id="appr-timeout-1",
        attempt_number=1,
        fencing_token=104,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
    )

    # 1. Result must be marked uncertain
    assert result.is_uncertain is True
    assert result.is_success is False
    assert result.broker_completed is False
    assert result.status == OperationStatus.DISPATCH_UNCERTAIN
    assert "Broker timed out" in result.error_message

    # 2. SQLite registry must be in DISPATCH_UNCERTAIN
    reg_op = reg.get_operation(result.operation_id)
    assert reg_op.operation_status == OperationStatus.DISPATCH_UNCERTAIN

    # 3. Journal must contain DISPATCH_UNCERTAIN
    assert jour.current_sequence == 3
    assert jour.replay()[-1].record_type == JournalRecordType.DISPATCH_UNCERTAIN.value


def test_broker_timeout_with_raise_on_error(dispatcher_env):
    """When raise_on_error=True, broker timeout raises ExecutionUncertainError."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    mock_client.execute_action.side_effect = socket.timeout("Timed out waiting for socket")

    with pytest.raises(ExecutionUncertainError, match="Broker IPC failed after start marker"):
        dispatcher.dispatch_action(
            execution_id="exec-timeout-raise",
            workspace_id="ws-prod",
            approval_id="appr-timeout-raise",
            attempt_number=1,
            fencing_token=105,
            action_id="restore_order_api_demo",
            target_url="http://order-api:8000/demo/restore",
            raise_on_error=True,
        )


# ============================================================================
# 6. Broker Connection Loss Creates an Uncertain Outcome
# ============================================================================

def test_broker_connection_loss_creates_uncertain_outcome(dispatcher_env):
    """Connection drop after start marker fsync fails closed into DISPATCH_UNCERTAIN."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    mock_client.execute_action.side_effect = ConnectionError("Connection closed prematurely. Received 0/4 bytes.")

    result = dispatcher.dispatch_action(
        execution_id="exec-connloss-1",
        workspace_id="ws-prod",
        approval_id="appr-connloss-1",
        attempt_number=1,
        fencing_token=106,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
    )

    assert result.is_uncertain is True
    assert result.status == OperationStatus.DISPATCH_UNCERTAIN
    assert "Connection closed prematurely" in result.error_message

    reg_op = reg.get_operation(result.operation_id)
    assert reg_op.operation_status == OperationStatus.DISPATCH_UNCERTAIN


# ============================================================================
# 7. Malformed Broker Responses Fail Closed
# ============================================================================

def test_malformed_broker_response_fails_closed(dispatcher_env):
    """Malformed or invalid JSON payload from broker fails closed into DISPATCH_UNCERTAIN."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    mock_client.execute_action.side_effect = json.JSONDecodeError("Expecting value", "invalid_json", 0)

    result = dispatcher.dispatch_action(
        execution_id="exec-malform-1",
        workspace_id="ws-prod",
        approval_id="appr-malform-1",
        attempt_number=1,
        fencing_token=107,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
    )

    assert result.is_uncertain is True
    assert result.status == OperationStatus.DISPATCH_UNCERTAIN
    assert reg.get_operation(result.operation_id).operation_status == OperationStatus.DISPATCH_UNCERTAIN


# ============================================================================
# 8. Duplicate Operation Requests Do Not Redispatch
# ============================================================================

def test_duplicate_operation_request_does_not_redispatch(dispatcher_env):
    """
    NON-REDISPATCH INVARIANT:
    Attempting to dispatch an operation that has already completed
    raises CoordinatorInvalidStateError and never calls broker again.
    """
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    # First dispatch succeeds
    res1 = dispatcher.dispatch_action(
        execution_id="exec-dup-1",
        workspace_id="ws-prod",
        approval_id="appr-dup-1",
        attempt_number=1,
        fencing_token=108,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
    )
    assert res1.is_success is True
    assert mock_client.execute_action.call_count == 1

    # Second dispatch with identical operation_id MUST fail closed
    with pytest.raises(CoordinatorInvalidStateError, match="Automatic redispatch is strictly forbidden"):
        dispatcher.dispatch_action(
            operation_id=res1.operation_id,
            execution_id="exec-dup-1",
            workspace_id="ws-prod",
            approval_id="appr-dup-1",
            attempt_number=1,
            fencing_token=108,
            action_id="restore_order_api_demo",
            target_url="http://order-api:8000/demo/restore",
        )

    # Broker call count is still 1! Never redispatched.
    assert mock_client.execute_action.call_count == 1


# ============================================================================
# 9. Existing Start Markers Prevent Redispatch
# ============================================================================

def test_existing_start_marker_prevents_redispatch(dispatcher_env):
    """If an operation already has DOCKER_CALL_STARTED, dispatch_action rejects it."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    # Manually reserve, prepare, and write start marker (simulating crash before completion)
    rec = coord.reserve_operation("exec-start-exist", "ws-prod", "appr-start-exist", 1, 109)
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)

    # Calling dispatcher on this operation must be blocked
    with pytest.raises(CoordinatorInvalidStateError, match="already started"):
        dispatcher.dispatch_action(
            operation_id=rec.operation_id,
            execution_id="exec-start-exist",
            workspace_id="ws-prod",
            approval_id="appr-start-exist",
            attempt_number=1,
            fencing_token=109,
            action_id="restore_order_api_demo",
            target_url="http://order-api:8000/demo/restore",
        )

    assert mock_client.execute_action.call_count == 0


# ============================================================================
# 10. Fencing-Token Mismatch Prevents Dispatch
# ============================================================================

def test_fencing_token_mismatch_prevents_dispatch(dispatcher_env):
    """Mismatched fencing token is rejected before broker invocation."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    rec = coord.reserve_operation("exec-fence-mis", "ws-prod", "appr-fence-mis", 1, fencing_token=50)

    with pytest.raises(CoordinatorConflictError, match="Conflicting fencing_token"):
        dispatcher.dispatch_action(
            operation_id=rec.operation_id,
            execution_id="exec-fence-mis",
            workspace_id="ws-prod",
            approval_id="appr-fence-mis",
            attempt_number=1,
            fencing_token=99,  # Mismatch!
            action_id="restore_order_api_demo",
            target_url="http://order-api:8000/demo/restore",
        )

    assert mock_client.execute_action.call_count == 0


# ============================================================================
# 11. Workspace / Operation Identity Mismatch Prevents Dispatch
# ============================================================================

def test_workspace_or_execution_mismatch_prevents_dispatch(dispatcher_env):
    """Mismatched workspace_id or execution_id fails closed before broker call."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    rec = coord.reserve_operation("exec-id-orig", "ws-prod", "appr-orig", 1, 60)

    # Workspace mismatch
    with pytest.raises(CoordinatorConflictError, match="Conflicting workspace_id"):
        dispatcher.dispatch_action(
            operation_id=rec.operation_id,
            execution_id="exec-id-orig",
            workspace_id="ws-ATTACKER",
            approval_id="appr-orig",
            attempt_number=1,
            fencing_token=60,
            action_id="restore_order_api_demo",
            target_url="http://order-api:8000/demo/restore",
        )

    # Execution mismatch
    with pytest.raises(CoordinatorConflictError, match="Conflicting execution_id"):
        dispatcher.dispatch_action(
            operation_id=rec.operation_id,
            execution_id="exec-DIFFERENT",
            workspace_id="ws-prod",
            approval_id="appr-orig",
            attempt_number=1,
            fencing_token=60,
            action_id="restore_order_api_demo",
            target_url="http://order-api:8000/demo/restore",
        )

    assert mock_client.execute_action.call_count == 0


# ============================================================================
# 12. Action Not in Allowlist is Rejected Immediately
# ============================================================================

def test_disallowed_action_rejected_immediately(dispatcher_env):
    """Non-allowlisted actions are rejected before any durable state or broker call."""
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    with pytest.raises(CoordinatorValidationError, match="not in allowed broker actions"):
        dispatcher.dispatch_action(
            execution_id="exec-disallow",
            workspace_id="ws-prod",
            approval_id="appr-disallow",
            attempt_number=1,
            fencing_token=1,
            action_id="malicious_unrestricted_bash",
            target_url="http://order-api:8000/demo/restore",
        )

    assert mock_client.execute_action.call_count == 0
    assert jour.current_sequence == 0


# ============================================================================
# 13. Broker Success Does Not Mark Execution Verified or Incident Recovered
# ============================================================================

def test_broker_success_does_not_mark_verified_or_recovered(dispatcher_env):
    """
    CRITICAL ARCHITECTURAL SEPARATION:
    Broker dispatch success (exit_code=0) records local container output ONLY.
    It does NOT touch PostgreSQL incident tables, does NOT mark incident RECOVERED,
    and does NOT claim verification. PostExecutionVerificationEngine and
    IncidentRecoveryBridge remain strictly responsible.
    """
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    result = dispatcher.dispatch_action(
        execution_id="exec-boundary-check",
        workspace_id="ws-prod",
        approval_id="appr-boundary-check",
        attempt_number=1,
        fencing_token=70,
        action_id="restore_order_api_demo",
        target_url="http://order-api:8000/demo/restore",
    )

    # 1. Dispatch indicates container process exit 0
    assert result.is_success is True
    assert result.exit_code == 0
    assert result.broker_completed is True

    # 2. Result MUST NOT have verification or incident recovery properties
    assert not hasattr(result, "is_verified")
    assert not hasattr(result, "incident_recovered")
    assert not hasattr(result, "recovered_at")

    # 3. Verify no PostgreSQL engine, verification engine, or recovery bridge was called
    assert not hasattr(dispatcher, "db_session")
    assert not hasattr(dispatcher, "verification_engine")
    assert not hasattr(dispatcher, "recovery_bridge")


# ============================================================================
# 14. Absolute Isolation: Zero Docker SDK, PostgreSQL, or /demo/* Calls
# ============================================================================

def test_absolute_isolation_from_docker_daemon_postgres_demo(dispatcher_env):
    """
    Verify complete isolation:
    - Zero Docker daemon socket calls
    - Zero production database operations
    - Zero direct HTTP calls to demo endpoints
    """
    dispatcher, coord, reg, jour, mock_client, _ = dispatcher_env

    # Run dispatch
    res = dispatcher.dispatch_action(
        execution_id="exec-iso-check",
        workspace_id="ws-prod",
        approval_id="appr-iso-check",
        attempt_number=1,
        fencing_token=80,
        action_id="inspect_service_health",
        target_url="http://order-api:8000/health",
    )

    assert res.is_success is True
    # The dispatcher only interacts with coordinator (SQLite + journal) and UnixSocketBrokerClient
    assert isinstance(dispatcher.coordinator, DispatchCoordinator)
    assert dispatcher.broker_client == mock_client
    assert not hasattr(dispatcher, "docker_client")
    assert not hasattr(dispatcher, "requests")
    assert not hasattr(dispatcher, "httpx")
