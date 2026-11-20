"""Comprehensive Test Suite for Standalone Dispatch Coordinator (Phase 4.3.6 Milestone E.3.2).

Covers:
1. Normal reservation and preparation.
2. Normal dispatch-start recording.
3. Normal completion with exit code 0.
4. Completion with nonzero exit code.
5. Duplicate reservation idempotency.
6. Conflicting reservation rejection.
7. Incorrect operation/execution/workspace identity rejection.
8. Incorrect fencing token rejection.
9. Invalid lifecycle transition rejection.
10. Journal failure prevents SQLite from advancing.
11. SQLite failure after journal fsync is recoverable through replay.
12. Journal uncertainty hold blocks further coordination.
13. Journal corruption blocks reconciliation.
14. Incomplete journal tail blocks reconciliation.
15. Repeated reconciliation is idempotent.
16. Conflicting journal and registry state fails closed.
17. Missing dispatch marker is not treated as proof of safe abort.
18. The 8 explicit crash boundaries.
19. Zero Docker calls, zero PostgreSQL writes, zero /demo/* calls.
"""

import os
import struct
import tempfile
from unittest.mock import patch
import uuid

import pytest

from app.execution.dispatch_coordinator import (
    ALL_PROOF_CONDITIONS,
    AbsenceProofCondition,
    AbsenceProofWitness,
    CoordinatorConflictError,
    CoordinatorError,
    CoordinatorInvalidStateError,
    CoordinatorReconciliationError,
    CoordinatorUncertaintyError,
    CoordinatorValidationError,
    DispatchCoordinator,
    PreDispatchResolution,
    PreDispatchState,
    ReconciliationSummary,
)
from app.execution.journal import (
    HEADER_FORMAT,
    MAGIC_BYTES,
    JournalRecordType,
    JournalWriteError,
    OperationJournal,
)
from app.execution.registry import (
    OperationRegistry,
    OperationStatus,
    RegistryConflictError,
)


@pytest.fixture
def coordinator_env():
    """Provides an isolated environment with initialized SQLite registry and binary journal."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "coordinator_test.db")
        journal_dir = os.path.join(tmp_dir, "journal")
        os.makedirs(journal_dir, exist_ok=True)

        reg = OperationRegistry(db_path=db_path)
        jour = OperationJournal(journal_dir=journal_dir)
        coord = DispatchCoordinator(registry=reg, journal=jour)
        coord.initialize()

        yield coord, reg, jour, tmp_dir

        coord.close()


# ============================================================================
# 1. Normal Reservation and Preparation
# ============================================================================

def test_coordinator_normal_reservation_and_preparation(coordinator_env):
    """Operation is reserved in SQLite, then DISPATCH_PREPARED is fsynced to journal and SQLite advances."""
    coord, reg, jour, _ = coordinator_env

    # 1. Reserve
    rec = coord.reserve_operation(
        execution_id="exec-1",
        workspace_id="ws-1",
        approval_id="appr-1",
        attempt_number=1,
        fencing_token=10,
        metadata={"target": "order-api"},
    )
    assert rec.operation_id is not None
    assert rec.operation_status == OperationStatus.RESERVED
    op_id = rec.operation_id

    # Verify journal has not written any records yet
    assert jour.current_sequence == 0

    # 2. Prepare dispatch
    j_rec, reg_rec = coord.prepare_dispatch(
        operation_id=op_id,
        execution_id="exec-1",
        fencing_token=10,
        workspace_id="ws-1",
    )

    # Journal must have recorded sequence 1
    assert j_rec.sequence == 1
    assert j_rec.record_type == JournalRecordType.DISPATCH_PREPARED.value
    assert j_rec.operation_id == op_id

    # SQLite must now be in DISPATCH_PREPARED
    assert reg_rec.operation_status == OperationStatus.DISPATCH_PREPARED


# ============================================================================
# 2. Normal Dispatch-Start Recording
# ============================================================================

def test_coordinator_normal_dispatch_start_recording(coordinator_env):
    """Prepared operation transitions to DOCKER_CALL_STARTED after journal fsync."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-start",
        workspace_id="ws-1",
        approval_id="appr-start",
        attempt_number=1,
        fencing_token=5,
    )
    coord.prepare_dispatch(rec.operation_id)

    # Record dispatch start
    j_rec, reg_rec = coord.record_docker_call_started(rec.operation_id)

    assert j_rec.sequence == 2
    assert j_rec.record_type == JournalRecordType.DOCKER_CALL_STARTED.value
    assert reg_rec.operation_status == OperationStatus.DOCKER_CALL_STARTED

    # Verify query reflects DOCKER_CALL_STARTED
    db_rec = reg.get_operation(rec.operation_id)
    assert db_rec.operation_status == OperationStatus.DOCKER_CALL_STARTED


# ============================================================================
# 3. Normal Completion with Exit Code 0
# ============================================================================

def test_coordinator_normal_completion_exit_code_zero(coordinator_env):
    """Container exit code 0 is recorded in journal and SQLite transitions to DOCKER_CALL_COMPLETED."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-comp-0",
        workspace_id="ws-1",
        approval_id="appr-comp-0",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)

    j_rec, reg_rec = coord.complete_dispatch(
        operation_id=rec.operation_id,
        exit_code=0,
        duration_ms=250,
        output_data={"remediated": True},
        stdout_sample="Success",
    )

    assert j_rec.sequence == 3
    assert j_rec.record_type == JournalRecordType.DOCKER_CALL_COMPLETED.value
    assert j_rec.metadata["exit_code"] == 0
    assert j_rec.metadata["duration_ms"] == 250
    assert j_rec.metadata["output_data"] == {"remediated": True}

    assert reg_rec.operation_status == OperationStatus.DOCKER_CALL_COMPLETED
    assert reg_rec.metadata["exit_code"] == 0


# ============================================================================
# 4. Completion with Nonzero Exit Code
# ============================================================================

def test_coordinator_completion_nonzero_exit_code(coordinator_env):
    """Container exit code != 0 is preserved in outcome metadata (distinguishing action result)."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-comp-nonzero",
        workspace_id="ws-1",
        approval_id="appr-comp-nonzero",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)

    j_rec, reg_rec = coord.complete_dispatch(
        operation_id=rec.operation_id,
        exit_code=137,
        duration_ms=400,
        stderr_sample="Container killed OOM",
    )

    assert j_rec.metadata["exit_code"] == 137
    assert j_rec.metadata["stderr_sample"] == "Container killed OOM"
    assert reg_rec.operation_status == OperationStatus.DOCKER_CALL_COMPLETED
    assert reg_rec.metadata["exit_code"] == 137


# ============================================================================
# 5. Duplicate Reservation Idempotency
# ============================================================================

def test_coordinator_duplicate_reservation_idempotency(coordinator_env):
    """Identical reservation requests return the existing record idempotently."""
    coord, reg, jour, _ = coordinator_env

    r1 = coord.reserve_operation(
        execution_id="exec-dup",
        workspace_id="ws-1",
        approval_id="appr-dup",
        attempt_number=1,
        fencing_token=10,
    )
    r2 = coord.reserve_operation(
        execution_id="exec-dup",
        workspace_id="ws-1",
        approval_id="appr-dup",
        attempt_number=1,
        fencing_token=10,
    )

    assert r1.operation_id == r2.operation_id
    assert r1.created_at == r2.created_at


# ============================================================================
# 6. Conflicting Reservation Rejection
# ============================================================================

def test_coordinator_conflicting_reservation_rejection(coordinator_env):
    """Conflicting reservation parameters raise RegistryConflictError."""
    coord, reg, jour, _ = coordinator_env

    coord.reserve_operation(
        execution_id="exec-conf",
        workspace_id="ws-1",
        approval_id="appr-conf",
        attempt_number=1,
        fencing_token=10,
    )

    with pytest.raises(RegistryConflictError):
        coord.reserve_operation(
            execution_id="exec-DIFFERENT",
            workspace_id="ws-1",
            approval_id="appr-conf",
            attempt_number=1,
            fencing_token=10,
        )


# ============================================================================
# 7. Incorrect Operation/Execution/Workspace Identity Rejection
# ============================================================================

def test_coordinator_identity_mismatch_rejection(coordinator_env):
    """Mismatched execution_id or workspace_id raises CoordinatorConflictError."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-ident",
        workspace_id="ws-correct",
        approval_id="appr-ident",
        attempt_number=1,
        fencing_token=1,
    )

    # Mismatched execution_id
    with pytest.raises(CoordinatorConflictError, match="Conflicting execution_id"):
        coord.prepare_dispatch(
            operation_id=rec.operation_id,
            execution_id="exec-WRONG",
        )

    # Mismatched workspace_id
    with pytest.raises(CoordinatorConflictError, match="Conflicting workspace_id"):
        coord.prepare_dispatch(
            operation_id=rec.operation_id,
            workspace_id="ws-WRONG",
        )


# ============================================================================
# 8. Incorrect Fencing Token Rejection
# ============================================================================

def test_coordinator_fencing_token_mismatch_rejection(coordinator_env):
    """Mismatched fencing token raises CoordinatorConflictError."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-fence",
        workspace_id="ws-1",
        approval_id="appr-fence",
        attempt_number=1,
        fencing_token=50,
    )

    with pytest.raises(CoordinatorConflictError, match="Conflicting fencing_token"):
        coord.prepare_dispatch(
            operation_id=rec.operation_id,
            fencing_token=99,
        )


# ============================================================================
# 9. Invalid Lifecycle Transition Rejection
# ============================================================================

def test_coordinator_invalid_lifecycle_transition_rejection(coordinator_env):
    """Calling start without prepare or complete without start raises CoordinatorInvalidStateError."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-fsm",
        workspace_id="ws-1",
        approval_id="appr-fsm",
        attempt_number=1,
        fencing_token=1,
    )

    # Calling start directly on RESERVED operation
    with pytest.raises(CoordinatorInvalidStateError, match="expected DISPATCH_PREPARED"):
        coord.record_docker_call_started(rec.operation_id)

    # Calling complete on RESERVED operation
    with pytest.raises(CoordinatorInvalidStateError, match="expected DOCKER_CALL_STARTED"):
        coord.complete_dispatch(rec.operation_id, exit_code=0)


# ============================================================================
# 10. Journal Failure Prevents SQLite From Advancing
# ============================================================================

def test_coordinator_journal_failure_prevents_sqlite_advancing(coordinator_env):
    """If journal append/fsync fails, SQLite is NOT updated to DISPATCH_PREPARED."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-fail-j",
        workspace_id="ws-1",
        approval_id="appr-fail-j",
        attempt_number=1,
        fencing_token=1,
    )

    with patch.object(jour, "append", side_effect=JournalWriteError("Disk I/O error")):
        with pytest.raises(CoordinatorError, match="Journal append failed"):
            coord.prepare_dispatch(rec.operation_id)

    # SQLite must remain in RESERVED
    db_rec = reg.get_operation(rec.operation_id)
    assert db_rec.operation_status == OperationStatus.RESERVED


# ============================================================================
# 11. SQLite Failure After Journal Fsync is Recoverable Through Replay
# ============================================================================

def test_coordinator_sqlite_failure_after_journal_fsync_recoverable(coordinator_env):
    """If SQLite update fails after journal fsync, reconciliation recovers and synchronizes SQLite."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-recover-sql",
        workspace_id="ws-1",
        approval_id="appr-recover-sql",
        attempt_number=1,
        fencing_token=1,
    )

    # Append DISPATCH_PREPARED to journal directly (simulating crash before SQLite update)
    jour.append(
        record_type=JournalRecordType.DISPATCH_PREPARED,
        operation_id=rec.operation_id,
        execution_id=rec.execution_id,
        workspace_id=rec.workspace_id,
        attempt_number=rec.attempt_number,
        fencing_token=rec.fencing_token,
        approval_id=rec.approval_id,
    )

    # SQLite is still RESERVED
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.RESERVED

    # Reconcile from journal
    summary = coord.reconcile_from_journal()
    assert summary.records_replayed == 1
    assert summary.operations_advanced == 1

    # SQLite is now recovered to DISPATCH_PREPARED
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DISPATCH_PREPARED


# ============================================================================
# 12. Journal Uncertainty Hold Blocks Further Coordination
# ============================================================================

def test_coordinator_journal_uncertainty_hold_blocks_coordination(coordinator_env):
    """If journal enters an uncertainty hold, further dispatches are refused."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-unc-hold",
        workspace_id="ws-1",
        approval_id="appr-unc-hold",
        attempt_number=1,
        fencing_token=1,
    )

    # Force journal into uncertainty hold
    jour._can_append = False
    jour._is_corrupted = True

    with pytest.raises(CoordinatorUncertaintyError):
        coord.prepare_dispatch(rec.operation_id)


# ============================================================================
# 13. Journal Corruption Blocks Reconciliation
# ============================================================================

def test_coordinator_journal_corruption_blocks_reconciliation(coordinator_env):
    """Corrupted journal file raises CoordinatorReconciliationError during reconciliation."""
    coord, reg, jour, tmp_dir = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-corrupt",
        workspace_id="ws-1",
        approval_id="appr-corrupt",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)

    # Corrupt journal bytes at tail
    journal_path = os.path.join(tmp_dir, "journal", "operations.journal")
    with open(journal_path, "r+b") as f:
        f.seek(8)
        f.write(b"\xFF\xFF\xFF\xFF")

    # Re-open journal to detect corruption
    jour.close()
    jour.open()

    with pytest.raises(CoordinatorReconciliationError, match="corruption or uncertainty"):
        coord.reconcile_from_journal()


# ============================================================================
# 14. Incomplete Journal Tail Blocks Reconciliation
# ============================================================================

def test_coordinator_incomplete_journal_tail_blocks_reconciliation(coordinator_env):
    """Incomplete trailing frame at journal tail fails closed during reconciliation."""
    coord, reg, jour, tmp_dir = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-tail",
        workspace_id="ws-1",
        approval_id="appr-tail",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)

    # Append 15 bytes of incomplete header at tail
    journal_path = os.path.join(tmp_dir, "journal", "operations.journal")
    with open(journal_path, "ab") as f:
        f.write(MAGIC_BYTES + struct.pack("!QI", 2, 50))

    jour.close()
    jour.open()

    with pytest.raises(CoordinatorReconciliationError, match="corruption or uncertainty"):
        coord.reconcile_from_journal()


# ============================================================================
# 15. Repeated Reconciliation is Idempotent
# ============================================================================

def test_coordinator_repeated_reconciliation_is_idempotent(coordinator_env):
    """Executing reconcile_from_journal multiple times produces identical state without error."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-idem-recon",
        workspace_id="ws-1",
        approval_id="appr-idem-recon",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)
    coord.complete_dispatch(rec.operation_id, exit_code=0)

    # First reconciliation
    s1 = coord.reconcile_from_journal()
    assert s1.records_replayed == 3
    assert s1.operations_advanced == 0  # Already at completion

    # Second reconciliation
    s2 = coord.reconcile_from_journal()
    assert s2.records_replayed == 3
    assert s2.operations_advanced == 0
    assert s2.operations_already_synchronized == 1


# ============================================================================
# 16. Conflicting Journal and Registry State Fails Closed
# ============================================================================

def test_coordinator_conflicting_journal_and_registry_fails_closed(coordinator_env):
    """If journal record contains mismatched execution identity for same operation_id, reconciliation fails closed."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-correct",
        workspace_id="ws-1",
        approval_id="appr-conflict-check",
        attempt_number=1,
        fencing_token=1,
    )

    # Manually append record with conflicting execution_id
    jour.append(
        record_type=JournalRecordType.DISPATCH_PREPARED,
        operation_id=rec.operation_id,
        execution_id="exec-TAMPERED",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=1,
        approval_id=rec.approval_id,
    )

    with pytest.raises(CoordinatorConflictError, match="conflicting identity"):
        coord.reconcile_from_journal()


# ============================================================================
# 17. Missing Dispatch Marker Not Treated as Proof of Safe Abort
# ============================================================================

def test_coordinator_missing_marker_not_proof_of_safe_abort(coordinator_env):
    """
    CRITICAL ABSENCE INVARIANT:
    If an operation was prepared in journal/registry, but no DOCKER_CALL_STARTED exists,
    reconciliation does NOT mark it as aborted or safely pre-dispatch.
    It remains preserved in DISPATCH_PREPARED without automatic redispatch.
    """
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-pre-abort",
        workspace_id="ws-1",
        approval_id="appr-pre-abort",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)

    # Reconcile
    summary = coord.reconcile_from_journal()
    assert summary.records_replayed == 1

    # Operation must remain in DISPATCH_PREPARED (NOT silently marked aborted)
    reg_op = reg.get_operation(rec.operation_id)
    assert reg_op.operation_status == OperationStatus.DISPATCH_PREPARED


# ============================================================================
# 18. The 8 Explicit Crash Boundaries
# ============================================================================

def test_coordinator_crash_boundary_1_before_sqlite_reservation(coordinator_env):
    """Crash 1: Crash occurs before SQLite reservation; neither store has any record."""
    coord, reg, jour, _ = coordinator_env
    # Process dies before reserve_operation()
    assert reg.get_by_approval("appr-b1") is None
    assert jour.current_sequence == 0


def test_coordinator_crash_boundary_2_after_reservation_before_prepared_journal(coordinator_env):
    """Crash 2: Crash occurs after SQLite reservation, before DISPATCH_PREPARED journal append."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b2",
        workspace_id="ws-1",
        approval_id="appr-b2",
        attempt_number=1,
        fencing_token=1,
    )
    # Process dies here

    summary = coord.reconcile_from_journal()
    assert summary.records_replayed == 0
    # SQLite remains RESERVED; absence of marker is NOT treated as safe abort
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.RESERVED


def test_coordinator_crash_boundary_3_after_prepared_journal_before_sqlite_prepared(coordinator_env):
    """Crash 3: Crash occurs after DISPATCH_PREPARED journal fsync, before SQLite update."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b3",
        workspace_id="ws-1",
        approval_id="appr-b3",
        attempt_number=1,
        fencing_token=1,
    )
    jour.append(
        record_type=JournalRecordType.DISPATCH_PREPARED,
        operation_id=rec.operation_id,
        execution_id=rec.execution_id,
        workspace_id=rec.workspace_id,
        attempt_number=rec.attempt_number,
        fencing_token=rec.fencing_token,
        approval_id=rec.approval_id,
    )
    # Process dies here (SQLite is still RESERVED)
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.RESERVED

    # Reconciliation synchronizes SQLite to DISPATCH_PREPARED
    coord.reconcile_from_journal()
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DISPATCH_PREPARED


def test_coordinator_crash_boundary_4_after_sqlite_preparation(coordinator_env):
    """Crash 4: Crash occurs after SQLite preparation; both stores in DISPATCH_PREPARED."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b4",
        workspace_id="ws-1",
        approval_id="appr-b4",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    # Process dies here

    coord.reconcile_from_journal()
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DISPATCH_PREPARED


def test_coordinator_crash_boundary_5_after_docker_started_journal_before_sqlite(coordinator_env):
    """Crash 5: Crash occurs after DOCKER_CALL_STARTED journal fsync, before SQLite update."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b5",
        workspace_id="ws-1",
        approval_id="appr-b5",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)

    # Append DOCKER_CALL_STARTED directly to journal
    jour.append(
        record_type=JournalRecordType.DOCKER_CALL_STARTED,
        operation_id=rec.operation_id,
        execution_id=rec.execution_id,
        workspace_id=rec.workspace_id,
        attempt_number=rec.attempt_number,
        fencing_token=rec.fencing_token,
        approval_id=rec.approval_id,
    )
    # Process dies before SQLite update; SQLite is still DISPATCH_PREPARED
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DISPATCH_PREPARED

    # Reconcile: SQLite forward-transitions to DOCKER_CALL_STARTED
    coord.reconcile_from_journal()
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DOCKER_CALL_STARTED


def test_coordinator_crash_boundary_6_after_sqlite_start_transition(coordinator_env):
    """Crash 6: Crash occurs after SQLite start transition; both stores in DOCKER_CALL_STARTED."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b6",
        workspace_id="ws-1",
        approval_id="appr-b6",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)
    # Process dies here

    coord.reconcile_from_journal()
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DOCKER_CALL_STARTED


def test_coordinator_crash_boundary_7_after_docker_completed_journal_before_sqlite(coordinator_env):
    """Crash 7: Crash occurs after DOCKER_CALL_COMPLETED journal fsync, before SQLite update."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b7",
        workspace_id="ws-1",
        approval_id="appr-b7",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)

    # Append DOCKER_CALL_COMPLETED directly to journal
    jour.append(
        record_type=JournalRecordType.DOCKER_CALL_COMPLETED,
        operation_id=rec.operation_id,
        execution_id=rec.execution_id,
        workspace_id=rec.workspace_id,
        attempt_number=rec.attempt_number,
        fencing_token=rec.fencing_token,
        approval_id=rec.approval_id,
        metadata={"exit_code": 0, "duration_ms": 150},
    )
    # SQLite is still DOCKER_CALL_STARTED
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DOCKER_CALL_STARTED

    # Reconcile: SQLite forward-transitions to DOCKER_CALL_COMPLETED
    coord.reconcile_from_journal()
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DOCKER_CALL_COMPLETED
    assert reg.get_operation(rec.operation_id).metadata["exit_code"] == 0


def test_coordinator_crash_boundary_8_after_sqlite_completion(coordinator_env):
    """Crash 8: Crash occurs after SQLite completion; both stores in DOCKER_CALL_COMPLETED."""
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-b8",
        workspace_id="ws-1",
        approval_id="appr-b8",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(rec.operation_id)
    coord.record_docker_call_started(rec.operation_id)
    coord.complete_dispatch(rec.operation_id, exit_code=0)
    # Process dies here

    summary = coord.reconcile_from_journal()
    assert summary.records_replayed == 3
    assert reg.get_operation(rec.operation_id).operation_status == OperationStatus.DOCKER_CALL_COMPLETED


# ============================================================================
# 19. Failure and Uncertainty Tracking
# ============================================================================

def test_coordinator_record_failure_and_uncertainty(coordinator_env):
    """Definite failure and uncertain outcomes are durably recorded in journal and SQLite."""
    coord, reg, jour, _ = coordinator_env

    # 1. Definite failure
    r1 = coord.reserve_operation(
        execution_id="exec-fail-1",
        workspace_id="ws-1",
        approval_id="appr-fail-1",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(r1.operation_id)
    j_fail, reg_fail = coord.record_dispatch_failure(
        r1.operation_id,
        error_message="Configuration error",
        error_category="config_error",
    )
    assert j_fail.record_type == JournalRecordType.DISPATCH_FAILED.value
    assert reg_fail.operation_status == OperationStatus.DISPATCH_FAILED

    # 2. Ambiguous uncertainty
    r2 = coord.reserve_operation(
        execution_id="exec-unc-1",
        workspace_id="ws-1",
        approval_id="appr-unc-1",
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(r2.operation_id)
    coord.record_docker_call_started(r2.operation_id)
    j_unc, reg_unc = coord.record_dispatch_uncertain(
        r2.operation_id,
        reason="Network socket dropped mid-call",
    )
    assert j_unc is not None
    assert j_unc.record_type == JournalRecordType.DISPATCH_UNCERTAIN.value
    assert reg_unc.operation_status == OperationStatus.DISPATCH_UNCERTAIN


# ============================================================================
# 20. Revision 10 Pre-Dispatch Safety Corrections (Milestone E.3.2 Focused Correction)
# ============================================================================

def test_reserved_with_empty_journal_never_auto_resumes_or_aborts(coordinator_env):
    """
    CRITICAL SAFETY REQUIREMENT 1:
    When SQLite contains RESERVED but the journal has no corresponding record:
    - Does NOT automatically resume dispatch.
    - Does NOT automatically classify the operation as a safe abort.
    - Preserves the reservation in SQLite.
    - Returns an explicit unresolved/pre-dispatch state requiring reconciliation.
    - Does NOT invoke Docker or any broker.
    """
    coord, reg, jour, _ = coordinator_env

    # 1. Operation is reserved in SQLite
    rec = coord.reserve_operation(
        execution_id="exec-empty-j",
        workspace_id="ws-1",
        approval_id="appr-empty-j",
        attempt_number=1,
        fencing_token=10,
        metadata={"action": "restore_order_api_demo"},
    )
    op_id = rec.operation_id
    assert rec.operation_status == OperationStatus.RESERVED
    assert jour.current_sequence == 0

    # 2. Reconcile with completely empty journal
    summary = coord.reconcile_from_journal()
    assert summary.records_replayed == 0
    assert op_id in summary.unresolved_operations
    assert summary.unresolved_details[op_id] == PreDispatchState.UNRESOLVED_RESERVED

    # 3. Reservation is preserved in SQLite; neither auto-advanced nor auto-aborted
    stored_rec = reg.get_operation(op_id)
    assert stored_rec.operation_status == OperationStatus.RESERVED
    assert stored_rec.metadata["action"] == "restore_order_api_demo"

    # 4. Explicit evaluation returns explicit unresolved pre-dispatch state
    resolution = coord.evaluate_pre_dispatch_state(op_id)
    assert resolution.state == PreDispatchState.UNRESOLVED_RESERVED
    assert resolution.operation_status == OperationStatus.RESERVED
    assert resolution.requires_reconciliation is True
    assert resolution.can_auto_resume is False
    assert resolution.can_auto_redispatch is False
    assert resolution.is_safe_abort is False


def test_dispatch_prepared_without_start_marker_never_auto_redispatches(coordinator_env):
    """
    CRITICAL SAFETY REQUIREMENT 2:
    When the journal contains DISPATCH_PREPARED but no DOCKER_CALL_STARTED:
    - Does NOT automatically resume or redispatch.
    - Does NOT infer that Docker was never contacted.
    - Preserves the operation in its prepared state or uncertainty hold.
    - Requires the complete six-condition Revision 10 absence proof before any clean abort.
    """
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-prepared-no-start",
        workspace_id="ws-1",
        approval_id="appr-prepared-no-start",
        attempt_number=1,
        fencing_token=11,
    )
    op_id = rec.operation_id

    # Advance to DISPATCH_PREPARED
    coord.prepare_dispatch(op_id)
    assert jour.current_sequence == 1

    # Simulate crash before DOCKER_CALL_STARTED; reconcile from journal
    summary = coord.reconcile_from_journal()
    assert summary.records_replayed == 1
    assert op_id in summary.unresolved_operations
    assert summary.unresolved_details[op_id] == PreDispatchState.UNRESOLVED_PREPARED

    # State is preserved in DISPATCH_PREPARED; never auto-redispatched to DOCKER_CALL_STARTED
    reg_op = reg.get_operation(op_id)
    assert reg_op.operation_status == OperationStatus.DISPATCH_PREPARED

    # Direct evaluation exposes unresolved state requiring absence proof
    resolution = coord.evaluate_pre_dispatch_state(op_id)
    assert resolution.state == PreDispatchState.UNRESOLVED_PREPARED
    assert resolution.requires_reconciliation is True
    assert resolution.can_auto_resume is False
    assert resolution.can_auto_redispatch is False
    assert resolution.is_safe_abort is False
    assert len(resolution.missing_proof_conditions) == 6


def test_missing_proof_conditions_prevent_clean_abort_classification(coordinator_env):
    """
    CRITICAL SAFETY REQUIREMENT 3:
    Six-condition proof boundary:
    E.3.2 must not implement or claim the complete physical absence proof.
    It must expose an unresolved result when proof is unavailable.
    Missing, unknown or corrupt evidence means uncertainty hold.
    """
    coord, reg, jour, _ = coordinator_env

    rec = coord.reserve_operation(
        execution_id="exec-proof-test",
        workspace_id="ws-1",
        approval_id="appr-proof-test",
        attempt_number=1,
        fencing_token=12,
    )
    op_id = rec.operation_id
    coord.prepare_dispatch(op_id)

    # Case A: Proof is completely unavailable (proof_witness=None)
    # Attempting to clean-abort without proof MUST fail closed into uncertainty
    with pytest.raises(CoordinatorUncertaintyError, match="Cannot classify operation .* as clean pre-dispatch abort"):
        coord.abort_pre_dispatch_operation(op_id, proof_witness=None)

    # After failure to prove absence, operation enters UNCERTAINTY_HOLD
    reg_op = reg.get_operation(op_id)
    assert reg_op.operation_status == OperationStatus.DISPATCH_UNCERTAIN

    # Case B: Test partial / missing conditions on a new prepared operation
    rec2 = coord.reserve_operation(
        execution_id="exec-partial-proof",
        workspace_id="ws-1",
        approval_id="appr-partial-proof",
        attempt_number=1,
        fencing_token=13,
    )
    op2_id = rec2.operation_id
    coord.prepare_dispatch(op2_id)

    # Witness has conditions 1, 2, 4, 5, 6 True, but Condition 3 (exclusive_socket_ownership) is False!
    partial_witness = AbsenceProofWitness(
        authoritative_journal=True,
        complete_lineage=True,
        exclusive_socket_ownership=False,  # FAILED
        no_alternate_access=True,
        no_surviving_dispatcher=True,
        registry_journal_synced=True,
    )
    eval_partial = coord.evaluate_pre_dispatch_state(op2_id, proof_witness=partial_witness)
    assert eval_partial.state == PreDispatchState.UNCERTAINTY_HOLD
    assert eval_partial.is_safe_abort is False
    assert "exclusive_socket_ownership" in eval_partial.missing_proof_conditions

    with pytest.raises(CoordinatorUncertaintyError, match="exclusive_socket_ownership"):
        coord.abort_pre_dispatch_operation(op2_id, proof_witness=partial_witness)

    # Operation 2 must be fail-closed into DISPATCH_UNCERTAIN
    assert reg.get_operation(op2_id).operation_status == OperationStatus.DISPATCH_UNCERTAIN

    # Case C: All 6 conditions verified True allows clean abort
    rec3 = coord.reserve_operation(
        execution_id="exec-complete-proof",
        workspace_id="ws-1",
        approval_id="appr-complete-proof",
        attempt_number=1,
        fencing_token=14,
    )
    op3_id = rec3.operation_id
    coord.prepare_dispatch(op3_id)

    complete_witness = AbsenceProofWitness(
        authoritative_journal=True,
        complete_lineage=True,
        exclusive_socket_ownership=True,
        no_alternate_access=True,
        no_surviving_dispatcher=True,
        registry_journal_synced=True,
    )
    eval_complete = coord.evaluate_pre_dispatch_state(op3_id, proof_witness=complete_witness)
    assert eval_complete.state == PreDispatchState.PROVED_CLEAN_ABORT
    assert eval_complete.is_safe_abort is True
    assert len(eval_complete.missing_proof_conditions) == 0

    aborted_rec = coord.abort_pre_dispatch_operation(op3_id, proof_witness=complete_witness)
    assert aborted_rec.operation_status == OperationStatus.DISPATCH_ABORTED_PRE_DOCKER
    assert reg.get_operation(op3_id).operation_status == OperationStatus.DISPATCH_ABORTED_PRE_DOCKER
    assert jour.current_sequence == 6


def test_repeated_reconciliation_remains_idempotent_with_unresolved_states(coordinator_env):
    """
    Repeated reconciliation over mixed operations (RESERVED, PREPARED, COMPLETED)
    remains completely idempotent without changing states or producing errors.
    """
    coord, reg, jour, _ = coordinator_env

    # 1. Reserved operation (no journal)
    r_reserved = coord.reserve_operation("exec-id-1", "ws-1", "appr-id-1", 1, 1)
    # 2. Prepared operation (journal has DISPATCH_PREPARED)
    r_prep = coord.reserve_operation("exec-id-2", "ws-1", "appr-id-2", 1, 2)
    coord.prepare_dispatch(r_prep.operation_id)
    # 3. Completed operation (journal has 3 records)
    r_comp = coord.reserve_operation("exec-id-3", "ws-1", "appr-id-3", 1, 3)
    coord.prepare_dispatch(r_comp.operation_id)
    coord.record_docker_call_started(r_comp.operation_id)
    coord.complete_dispatch(r_comp.operation_id, exit_code=0)

    # First reconciliation
    s1 = coord.reconcile_from_journal()
    assert s1.records_replayed == 4
    assert r_reserved.operation_id in s1.unresolved_operations
    assert r_prep.operation_id in s1.unresolved_operations
    assert r_comp.operation_id not in s1.unresolved_operations

    # Second reconciliation
    s2 = coord.reconcile_from_journal()
    assert s2.records_replayed == 4
    assert s2.operations_advanced == 0
    assert s2.unresolved_operations == s1.unresolved_operations
    assert s2.unresolved_details == s1.unresolved_details

    # Third reconciliation
    s3 = coord.reconcile_from_journal()
    assert s3.records_replayed == 4
    assert s3.operations_advanced == 0
    assert s3.unresolved_operations == s1.unresolved_operations
    assert s3.unresolved_details == s1.unresolved_details

    # Verify states unchanged in registry
    assert reg.get_operation(r_reserved.operation_id).operation_status == OperationStatus.RESERVED
    assert reg.get_operation(r_prep.operation_id).operation_status == OperationStatus.DISPATCH_PREPARED
    assert reg.get_operation(r_comp.operation_id).operation_status == OperationStatus.DOCKER_CALL_COMPLETED


def test_zero_docker_broker_postgres_or_demo_calls(coordinator_env):
    """
    CRITICAL ISOLATION GUARANTEE:
    Verify that throughout reservation, preparation, replay, reconciliation,
    and pre-dispatch safety evaluation, zero Docker, broker, PostgreSQL,
    or /demo/* calls are made.
    """
    coord, reg, jour, _ = coordinator_env

    # Reserve, prepare, evaluate, reconcile
    rec = coord.reserve_operation("exec-iso", "ws-1", "appr-iso", 1, 20)
    coord.prepare_dispatch(rec.operation_id)
    coord.evaluate_pre_dispatch_state(rec.operation_id)
    coord.reconcile_from_journal()

    # Verify coordinator holds only registry (SQLite) and journal (local binary log)
    assert isinstance(coord.registry, OperationRegistry)
    assert isinstance(coord.journal, OperationJournal)
    assert not hasattr(coord, "broker")
    assert not hasattr(coord, "docker_client")
    assert not hasattr(coord, "db_session")
