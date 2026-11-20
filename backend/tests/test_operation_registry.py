"""Comprehensive Test Suite for Standalone SQLite Operation Registry (Phase 4.3.6 Milestone E.2).

Covers all 18 required scenarios:
1. Schema initialization and version tracking.
2. Reopening a database preserves committed reservations.
3. Reservation creates a stable operation ID.
4. Idempotent duplicate reservation returns the original record.
5. Conflicting approval reservation is rejected.
6. Conflicting execution/fencing-token reservation is rejected.
7. Negative identifiers/tokens and signed 64-bit overflow are rejected.
8. Valid lifecycle transitions succeed.
9. Invalid lifecycle transitions fail.
10. Uncertain and terminal states cannot be reset improperly.
11. Concurrent threads cannot create duplicate reservations.
12. Concurrent processes cannot create duplicate reservations.
13. Busy timeout produces a typed availability error.
14. Database corruption fails closed.
15. Sensitive metadata is sanitized.
16. SQL values are parameterized.
17. No INSERT OR REPLACE behavior exists.
18. Database path and permissions checks work on supported platforms.
"""

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import os
import sqlite3
import tempfile
import time
import uuid

import pytest

from app.execution.registry import (
    ALLOWED_TRANSITIONS,
    MAX_SQLITE_INT,
    TERMINAL_STATUSES,
    OperationRecord,
    OperationRegistry,
    OperationStatus,
    RegistryBusyError,
    RegistryConflictError,
    RegistryCorruptedError,
    RegistryError,
    RegistryIOError,
    RegistryInvalidTransitionError,
    RegistryNotFoundError,
    RegistryPermissionError,
    RegistryUnavailableError,
    RegistryValidationError,
    sanitize_registry_metadata,
)


@pytest.fixture
def temp_registry_dir():
    """Provides a fresh isolated temporary directory for registry tests."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        yield tmp_dir


@pytest.fixture
def registry(temp_registry_dir):
    """Provides an initialized OperationRegistry instance in a temp directory."""
    db_path = os.path.join(temp_registry_dir, "test_operation_registry.db")
    reg = OperationRegistry(db_path=db_path)
    reg.initialize()
    yield reg
    reg.close()


# Module-level worker function for multiprocessing tests (Windows spawn safe)
def _multiprocess_reserve_worker(
    db_path: str,
    execution_id: str,
    workspace_id: str,
    approval_id: str,
    attempt_number: int,
    fencing_token: int,
    out_queue: multiprocessing.Queue,
) -> None:
    try:
        reg = OperationRegistry(db_path=db_path)
        rec = reg.reserve_operation(
            execution_id=execution_id,
            workspace_id=workspace_id,
            approval_id=approval_id,
            attempt_number=attempt_number,
            fencing_token=fencing_token,
        )
        reg.close()
        out_queue.put(("SUCCESS", rec.operation_id))
    except Exception as e:
        out_queue.put(("ERROR", type(e).__name__, str(e)))


# ============================================================================
# 1. Schema Initialization and Version Tracking
# ============================================================================

def test_registry_schema_initialization_and_version(temp_registry_dir):
    """Schema initializes with version 1, proper tables, and indexes."""
    db_path = os.path.join(temp_registry_dir, "init_test.db")
    reg = OperationRegistry(db_path=db_path)
    try:
        reg.initialize()
        assert reg.get_schema_version() == 1

        # Verify tables and indexes exist directly via raw sqlite
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert "registry_schema_version" in tables
        assert "operation_reservations" in tables

        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_operations_approval" in indexes
        assert "idx_operations_execution_fencing" in indexes
        assert "idx_operations_status" in indexes
        assert "idx_operations_workspace" in indexes
        conn.close()
    finally:
        reg.close()


# ============================================================================
# 2. Reopening a Database Preserves Committed Reservations
# ============================================================================

def test_registry_reopening_preserves_committed_reservations(temp_registry_dir):
    """Committed reservations persist across process/connection restarts."""
    db_path = os.path.join(temp_registry_dir, "persist_test.db")

    # Instance 1: write and transition
    reg1 = OperationRegistry(db_path=db_path)
    try:
        reg1.initialize()
        rec1 = reg1.reserve_operation(
            execution_id="exec-100",
            workspace_id="ws-100",
            approval_id="appr-100",
            attempt_number=1,
            fencing_token=42,
            metadata={"source": "test_persist"},
        )
        op_id = rec1.operation_id

        # Transition to DISPATCH_PREPARED
        reg1.transition_operation(
            operation_id=op_id,
            target_status=OperationStatus.DISPATCH_PREPARED,
            metadata={"step": "prepared"},
        )
    finally:
        reg1.close()

    # Instance 2: reopen and verify persistence
    reg2 = OperationRegistry(db_path=db_path)
    try:
        reg2.initialize()
        rec2 = reg2.get_operation(op_id)
        assert rec2 is not None
        assert rec2.operation_id == op_id
        assert rec2.execution_id == "exec-100"
        assert rec2.workspace_id == "ws-100"
        assert rec2.approval_id == "appr-100"
        assert rec2.attempt_number == 1
        assert rec2.fencing_token == 42
        assert rec2.operation_status == OperationStatus.DISPATCH_PREPARED
        assert rec2.metadata["source"] == "test_persist"
        assert rec2.metadata["step"] == "prepared"

        # Also verify get_by_approval works across restart
        rec_appr = reg2.get_by_approval("appr-100")
        assert rec_appr is not None
        assert rec_appr.operation_id == op_id
    finally:
        reg2.close()


# ============================================================================
# 3. Reservation Creates a Stable Operation ID
# ============================================================================

def test_registry_reservation_stable_operation_id(registry):
    """Reservation assigns a stable UUID or preserves an explicitly supplied ID."""
    # Auto-generated UUID
    rec1 = registry.reserve_operation(
        execution_id="exec-stable",
        workspace_id="ws-1",
        approval_id="appr-stable-1",
        attempt_number=1,
        fencing_token=1,
    )
    assert rec1.operation_id is not None
    assert len(rec1.operation_id) >= 32
    # Verify retrieval
    found1 = registry.get_operation(rec1.operation_id)
    assert found1 is not None
    assert found1.operation_id == rec1.operation_id

    # Explicit operation_id
    custom_id = str(uuid.uuid4())
    rec2 = registry.reserve_operation(
        operation_id=custom_id,
        execution_id="exec-stable-2",
        workspace_id="ws-1",
        approval_id="appr-stable-2",
        attempt_number=1,
        fencing_token=2,
    )
    assert rec2.operation_id == custom_id
    found2 = registry.get_operation(custom_id)
    assert found2 is not None
    assert found2.operation_id == custom_id


# ============================================================================
# 4. Idempotent Duplicate Reservation Returns Original Record
# ============================================================================

def test_registry_idempotent_duplicate_reservation(registry):
    """Calling reserve_operation with identical data returns the existing record."""
    rec1 = registry.reserve_operation(
        execution_id="exec-idem",
        workspace_id="ws-1",
        approval_id="appr-idem",
        attempt_number=1,
        fencing_token=10,
        metadata={"key": "val"},
    )

    rec2 = registry.reserve_operation(
        execution_id="exec-idem",
        workspace_id="ws-1",
        approval_id="appr-idem",
        attempt_number=1,
        fencing_token=10,
        metadata={"key": "val"},
    )

    assert rec1.operation_id == rec2.operation_id
    assert rec1.created_at == rec2.created_at
    assert rec1.operation_status == rec2.operation_status
    assert rec1.fencing_token == rec2.fencing_token


# ============================================================================
# 5. Conflicting Approval Reservation is Rejected
# ============================================================================

def test_registry_conflicting_approval_reservation_rejected(registry):
    """Reserving an existing approval with conflicting parameters raises RegistryConflictError."""
    registry.reserve_operation(
        execution_id="exec-1",
        workspace_id="ws-1",
        approval_id="appr-conflict",
        attempt_number=1,
        fencing_token=10,
    )

    # Conflict 1: different execution_id
    with pytest.raises(RegistryConflictError, match="Conflicting reservation for approval_id"):
        registry.reserve_operation(
            execution_id="exec-2",
            workspace_id="ws-1",
            approval_id="appr-conflict",
            attempt_number=1,
            fencing_token=10,
        )

    # Conflict 2: different fencing_token
    with pytest.raises(RegistryConflictError, match="Conflicting reservation for approval_id"):
        registry.reserve_operation(
            execution_id="exec-1",
            workspace_id="ws-1",
            approval_id="appr-conflict",
            attempt_number=1,
            fencing_token=20,
        )

    # Conflict 3: different attempt_number
    with pytest.raises(RegistryConflictError, match="Conflicting reservation for approval_id"):
        registry.reserve_operation(
            execution_id="exec-1",
            workspace_id="ws-1",
            approval_id="appr-conflict",
            attempt_number=2,
            fencing_token=10,
        )


# ============================================================================
# 6. Conflicting Execution/Fencing-Token Reservation is Rejected
# ============================================================================

def test_registry_conflicting_execution_and_fencing_token_rejected(registry):
    """Reserving an existing (execution_id, fencing_token) under a different approval raises RegistryConflictError."""
    registry.reserve_operation(
        execution_id="exec-dup-token",
        workspace_id="ws-1",
        approval_id="appr-first",
        attempt_number=1,
        fencing_token=55,
    )

    # Same execution and fencing token, but different approval_id
    with pytest.raises(RegistryConflictError, match="Conflicting reservation for execution_id"):
        registry.reserve_operation(
            execution_id="exec-dup-token",
            workspace_id="ws-1",
            approval_id="appr-second",
            attempt_number=1,
            fencing_token=55,
        )


# ============================================================================
# 7. Negative Identifiers/Tokens and Signed 64-Bit Overflow Rejected
# ============================================================================

def test_registry_negative_and_overflow_values_rejected(registry):
    """Negative values and integers exceeding 2^63 - 1 raise RegistryValidationError."""
    # Negative attempt_number
    with pytest.raises(RegistryValidationError, match="attempt_number"):
        registry.reserve_operation(
            execution_id="exec-1",
            workspace_id="ws-1",
            approval_id="appr-neg-1",
            attempt_number=-1,
            fencing_token=1,
        )

    # Negative fencing_token
    with pytest.raises(RegistryValidationError, match="fencing_token"):
        registry.reserve_operation(
            execution_id="exec-1",
            workspace_id="ws-1",
            approval_id="appr-neg-2",
            attempt_number=1,
            fencing_token=-5,
        )

    # Overflow attempt_number (> 2^63 - 1)
    with pytest.raises(RegistryValidationError, match="attempt_number"):
        registry.reserve_operation(
            execution_id="exec-1",
            workspace_id="ws-1",
            approval_id="appr-over-1",
            attempt_number=MAX_SQLITE_INT + 1,
            fencing_token=1,
        )

    # Overflow fencing_token (> 2^63 - 1)
    with pytest.raises(RegistryValidationError, match="fencing_token"):
        registry.reserve_operation(
            execution_id="exec-1",
            workspace_id="ws-1",
            approval_id="appr-over-2",
            attempt_number=1,
            fencing_token=MAX_SQLITE_INT + 1,
        )

    # Maximum signed 64-bit bounds succeed cleanly
    rec_max = registry.reserve_operation(
        execution_id="exec-1",
        workspace_id="ws-1",
        approval_id="appr-max-bounds",
        attempt_number=MAX_SQLITE_INT,
        fencing_token=MAX_SQLITE_INT,
    )
    assert rec_max.attempt_number == MAX_SQLITE_INT
    assert rec_max.fencing_token == MAX_SQLITE_INT

    # Empty identifiers rejected
    with pytest.raises(RegistryValidationError, match="execution_id"):
        registry.reserve_operation("   ", "ws-1", "appr-1", 1, 1)

    with pytest.raises(RegistryValidationError, match="workspace_id"):
        registry.reserve_operation("exec-1", "", "appr-1", 1, 1)

    with pytest.raises(RegistryValidationError, match="approval_id"):
        registry.reserve_operation("exec-1", "ws-1", None, 1, 1)


# ============================================================================
# 8. Valid Lifecycle Transitions Succeed
# ============================================================================

def test_registry_valid_lifecycle_transitions(registry):
    """Step through the canonical dispatch lifecycle from RESERVED to DOCKER_CALL_COMPLETED."""
    rec = registry.reserve_operation(
        execution_id="exec-fsm",
        workspace_id="ws-1",
        approval_id="appr-fsm-1",
        attempt_number=1,
        fencing_token=1,
    )
    op_id = rec.operation_id
    assert rec.operation_status == OperationStatus.RESERVED

    # RESERVED -> DISPATCH_PREPARED
    r1 = registry.transition_operation(op_id, OperationStatus.DISPATCH_PREPARED)
    assert r1.operation_status == OperationStatus.DISPATCH_PREPARED

    # DISPATCH_PREPARED -> DISPATCH_ACCEPTED
    r2 = registry.transition_operation(op_id, OperationStatus.DISPATCH_ACCEPTED)
    assert r2.operation_status == OperationStatus.DISPATCH_ACCEPTED

    # DISPATCH_ACCEPTED -> DOCKER_CALL_STARTED
    r3 = registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_STARTED)
    assert r3.operation_status == OperationStatus.DOCKER_CALL_STARTED

    # DOCKER_CALL_STARTED -> DOCKER_CALL_CONFIRMED
    r4 = registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_CONFIRMED)
    assert r4.operation_status == OperationStatus.DOCKER_CALL_CONFIRMED

    # DOCKER_CALL_CONFIRMED -> DOCKER_CALL_COMPLETED
    r5 = registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_COMPLETED)
    assert r5.operation_status == OperationStatus.DOCKER_CALL_COMPLETED

    # Verify query reflects final state
    final_rec = registry.get_operation(op_id)
    assert final_rec.operation_status == OperationStatus.DOCKER_CALL_COMPLETED


# ============================================================================
# 9. Invalid Lifecycle Transitions Fail
# ============================================================================

def test_registry_invalid_lifecycle_transitions(registry):
    """Illegal jumps or preconditions trigger typed errors."""
    rec = registry.reserve_operation(
        execution_id="exec-jump",
        workspace_id="ws-1",
        approval_id="appr-jump",
        attempt_number=1,
        fencing_token=1,
    )
    op_id = rec.operation_id

    # Illegal jump: RESERVED -> DOCKER_CALL_COMPLETED
    with pytest.raises(RegistryInvalidTransitionError, match="Illegal state transition"):
        registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_COMPLETED)

    # Illegal jump: RESERVED -> DOCKER_CALL_CONFIRMED
    with pytest.raises(RegistryInvalidTransitionError, match="Illegal state transition"):
        registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_CONFIRMED)

    # Precondition mismatch
    with pytest.raises(RegistryConflictError, match="Precondition failed"):
        registry.transition_operation(
            op_id,
            OperationStatus.DISPATCH_PREPARED,
            expected_status=OperationStatus.DISPATCH_ACCEPTED,
        )

    # Non-existent operation
    with pytest.raises(RegistryNotFoundError):
        registry.transition_operation("non-existent-op-id", OperationStatus.DISPATCH_PREPARED)


# ============================================================================
# 10. Uncertain and Terminal States Cannot Be Reset Improperly
# ============================================================================

def test_registry_terminal_and_uncertain_states_cannot_be_reset(registry):
    """Terminal (COMPLETED, FAILED, ABORTED) and UNCERTAIN states cannot be transitioned out of."""
    # 1. DISPATCH_UNCERTAIN
    rec1 = registry.reserve_operation(
        execution_id="exec-unc",
        workspace_id="ws-1",
        approval_id="appr-unc",
        attempt_number=1,
        fencing_token=1,
    )
    registry.transition_operation(rec1.operation_id, OperationStatus.DISPATCH_UNCERTAIN)

    with pytest.raises(RegistryInvalidTransitionError, match="terminal/uncertain"):
        registry.transition_operation(rec1.operation_id, OperationStatus.RESERVED)

    with pytest.raises(RegistryInvalidTransitionError, match="terminal/uncertain"):
        registry.transition_operation(rec1.operation_id, OperationStatus.DISPATCH_PREPARED)

    with pytest.raises(RegistryInvalidTransitionError, match="terminal/uncertain"):
        registry.transition_operation(rec1.operation_id, OperationStatus.DOCKER_CALL_COMPLETED)

    # Verify listed in uncertain operations
    uncertain_list = registry.list_uncertain_operations()
    assert any(u.operation_id == rec1.operation_id for u in uncertain_list)

    # 2. DOCKER_CALL_COMPLETED
    rec2 = registry.reserve_operation(
        execution_id="exec-comp",
        workspace_id="ws-1",
        approval_id="appr-comp",
        attempt_number=1,
        fencing_token=2,
    )
    registry.transition_operation(rec2.operation_id, OperationStatus.DISPATCH_PREPARED)
    registry.transition_operation(rec2.operation_id, OperationStatus.DISPATCH_ACCEPTED)
    registry.transition_operation(rec2.operation_id, OperationStatus.DOCKER_CALL_STARTED)
    registry.transition_operation(rec2.operation_id, OperationStatus.DOCKER_CALL_COMPLETED)

    with pytest.raises(RegistryInvalidTransitionError, match="terminal/uncertain"):
        registry.transition_operation(rec2.operation_id, OperationStatus.DOCKER_CALL_STARTED)

    # 3. DISPATCH_FAILED
    rec3 = registry.reserve_operation(
        execution_id="exec-fail",
        workspace_id="ws-1",
        approval_id="appr-fail",
        attempt_number=1,
        fencing_token=3,
    )
    registry.transition_operation(rec3.operation_id, OperationStatus.DISPATCH_FAILED)

    with pytest.raises(RegistryInvalidTransitionError, match="terminal/uncertain"):
        registry.transition_operation(rec3.operation_id, OperationStatus.RESERVED)

    # 4. DISPATCH_ABORTED_PRE_DOCKER
    rec4 = registry.reserve_operation(
        execution_id="exec-abort",
        workspace_id="ws-1",
        approval_id="appr-abort",
        attempt_number=1,
        fencing_token=4,
    )
    registry.transition_operation(rec4.operation_id, OperationStatus.DISPATCH_ABORTED_PRE_DOCKER)

    with pytest.raises(RegistryInvalidTransitionError, match="terminal/uncertain"):
        registry.transition_operation(rec4.operation_id, OperationStatus.RESERVED)


# ============================================================================
# 11. Concurrent Threads Cannot Create Duplicate Reservations
# ============================================================================

def test_registry_concurrent_threads_no_duplicate_reservations(registry):
    """10 concurrent threads attempting identical reservation produce exactly 1 record without error."""
    approval_id = "appr-thread-test"
    execution_id = "exec-thread-test"

    def worker():
        return registry.reserve_operation(
            execution_id=execution_id,
            workspace_id="ws-1",
            approval_id=approval_id,
            attempt_number=1,
            fencing_token=100,
        )

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker) for _ in range(10)]
        results = [f.result() for f in futures]

    # All returned operation_ids must be identical
    op_ids = {r.operation_id for r in results}
    assert len(op_ids) == 1

    # Verify only 1 row exists in database
    conn = sqlite3.connect(registry.db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM operation_reservations WHERE approval_id = ?",
        (approval_id,),
    )
    count = cursor.fetchone()[0]
    conn.close()
    assert count == 1


# ============================================================================
# 12. Concurrent Processes Cannot Create Duplicate Reservations
# ============================================================================

def test_registry_concurrent_processes_no_duplicate_reservations(temp_registry_dir):
    """Multiple spawned OS processes attempting identical reservation produce exactly 1 row."""
    db_path = os.path.join(temp_registry_dir, "process_concurrency.db")
    init_reg = OperationRegistry(db_path=db_path)
    init_reg.initialize()
    init_reg.close()

    approval_id = "appr-proc-test"
    execution_id = "exec-proc-test"
    queue = multiprocessing.Queue()
    processes = []

    for _ in range(4):
        p = multiprocessing.Process(
            target=_multiprocess_reserve_worker,
            args=(db_path, execution_id, "ws-1", approval_id, 1, 999, queue),
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=10)

    # Collect outcomes
    outcomes = []
    while not queue.empty():
        outcomes.append(queue.get())

    assert len(outcomes) == 4
    # All succeeded and returned identical operation_id
    success_ids = [item[1] for item in outcomes if item[0] == "SUCCESS"]
    assert len(success_ids) == 4
    assert len(set(success_ids)) == 1

    # Verify exact single row count in database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM operation_reservations WHERE approval_id = ?",
        (approval_id,),
    )
    count = cursor.fetchone()[0]
    conn.close()
    assert count == 1


# ============================================================================
# 13. Busy Timeout Produces Typed Availability Error
# ============================================================================

def test_registry_busy_timeout_produces_typed_availability_error(temp_registry_dir):
    """When a transaction holds exclusive write lock, competing short-timeout connection raises RegistryBusyError."""
    db_path = os.path.join(temp_registry_dir, "busy_test.db")
    init_reg = OperationRegistry(db_path=db_path)
    init_reg.initialize()
    init_reg.close()

    # Connection 1: hold exclusive transaction
    conn1 = sqlite3.connect(db_path, isolation_level=None)
    conn1.execute("BEGIN EXCLUSIVE")

    try:
        # Connection 2: short busy timeout (50ms)
        reg_short = OperationRegistry(db_path=db_path, busy_timeout_ms=50)
        with pytest.raises(RegistryBusyError, match="Database busy"):
            reg_short.reserve_operation(
                execution_id="exec-busy",
                workspace_id="ws-1",
                approval_id="appr-busy",
                attempt_number=1,
                fencing_token=1,
            )
        reg_short.close()
    finally:
        conn1.execute("ROLLBACK")
        conn1.close()


# ============================================================================
# 14. Database Corruption Fails Closed
# ============================================================================

def test_registry_database_corruption_fails_closed(temp_registry_dir):
    """Corrupted database file triggers RegistryCorruptedError and fails closed."""
    db_path = os.path.join(temp_registry_dir, "corrupted.db")
    # Write garbage into file
    with open(db_path, "wb") as f:
        f.write(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_CORRUPTED_BYTES" * 10)

    reg = OperationRegistry(db_path=db_path)
    try:
        with pytest.raises(RegistryCorruptedError):
            reg.initialize()
    finally:
        reg.close()


# ============================================================================
# 15. Sensitive Metadata is Sanitized
# ============================================================================

def test_registry_sensitive_metadata_sanitized(registry):
    """Credentials, tokens, authorization headers, and secrets are scrubbed before storage."""
    dirty_meta = {
        "password": "MySuperSecretPassword123!",
        "authorization": "Bearer eyJhbGciOi...",
        "api_key": "sk-1234567890",
        "set-cookie": "session=abc",
        "nested": {
            "token": "secret-token",
            "raw_request_body": "sensitive request payload",
            "safe_counter": 100,
        },
        "safe_flag": True,
    }

    rec = registry.reserve_operation(
        execution_id="exec-clean",
        workspace_id="ws-1",
        approval_id="appr-clean",
        attempt_number=1,
        fencing_token=1,
        metadata=dirty_meta,
    )

    # Verify in-memory returned record is redacted
    assert rec.metadata["password"] == "[REDACTED]"
    assert rec.metadata["authorization"] == "[REDACTED]"
    assert rec.metadata["api_key"] == "[REDACTED]"
    assert rec.metadata["set-cookie"] == "[REDACTED]"
    assert rec.metadata["nested"]["token"] == "[REDACTED]"
    assert rec.metadata["nested"]["raw_request_body"] == "[REDACTED]"
    assert rec.metadata["nested"]["safe_counter"] == 100
    assert rec.metadata["safe_flag"] is True

    # Verify directly in SQLite storage on disk
    conn = sqlite3.connect(registry.db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT metadata_json FROM operation_reservations WHERE approval_id = ?",
        ("appr-clean",),
    )
    raw_json = cursor.fetchone()[0]
    conn.close()

    assert "MySuperSecretPassword123!" not in raw_json
    assert "eyJhbGciOi" not in raw_json
    assert "sk-1234567890" not in raw_json


# ============================================================================
# 16. SQL Values Are Parameterized
# ============================================================================

def test_registry_sql_values_are_parameterized(registry):
    """SQL injection payloads are treated as literal text values and cause no damage."""
    injection_payload = "'; DROP TABLE operation_reservations; --"

    rec = registry.reserve_operation(
        execution_id=injection_payload,
        workspace_id="ws-1",
        approval_id=injection_payload,
        attempt_number=1,
        fencing_token=1,
    )

    assert rec.approval_id == injection_payload
    assert rec.execution_id == injection_payload

    # Verify table was NOT dropped and record is queryable
    found = registry.get_by_approval(injection_payload)
    assert found is not None
    assert found.operation_id == rec.operation_id

    # Verify table still exists and is healthy
    conn = sqlite3.connect(registry.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM operation_reservations")
    count = cursor.fetchone()[0]
    conn.close()
    assert count >= 1


# ============================================================================
# 17. No INSERT OR REPLACE Behavior Exists
# ============================================================================

def test_registry_no_insert_or_replace_behavior(registry):
    """An existing reservation cannot be overwritten by a replacement attempt."""
    rec1 = registry.reserve_operation(
        execution_id="exec-no-replace",
        workspace_id="ws-1",
        approval_id="appr-no-replace",
        attempt_number=1,
        fencing_token=10,
        metadata={"version": 1},
    )

    # Attempt replacement with different payload
    with pytest.raises(RegistryConflictError):
        registry.reserve_operation(
            execution_id="exec-DIFFERENT",
            workspace_id="ws-1",
            approval_id="appr-no-replace",
            attempt_number=2,
            fencing_token=20,
            metadata={"version": 2},
        )

    # Verify original row is completely intact and unaltered
    rec_check = registry.get_by_approval("appr-no-replace")
    assert rec_check.operation_id == rec1.operation_id
    assert rec_check.execution_id == "exec-no-replace"
    assert rec_check.attempt_number == 1
    assert rec_check.fencing_token == 10
    assert rec_check.metadata["version"] == 1


# ============================================================================
# 18. Database Path and Permissions Checks Work on Supported Platforms
# ============================================================================

def test_registry_database_path_symlink_rejection(temp_registry_dir):
    """Opening database through a symbolic link is rejected with RegistryPermissionError."""
    real_db_path = os.path.join(temp_registry_dir, "real_registry.db")
    symlink_path = os.path.join(temp_registry_dir, "symlink_registry.db")

    # Initialize real db first
    reg = OperationRegistry(db_path=real_db_path)
    reg.initialize()
    reg.close()

    try:
        os.symlink(real_db_path, symlink_path)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this OS/privilege context.")

    sym_reg = OperationRegistry(db_path=symlink_path)
    try:
        with pytest.raises(RegistryPermissionError, match="Symlinked database path rejected"):
            sym_reg.initialize()
    finally:
        sym_reg.close()
