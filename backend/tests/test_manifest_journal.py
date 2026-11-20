"""Unit and Integration Tests for Broker Persistent Replay Journal (Phase 2A.1 Stage 3).

Tests cover all required scenarios:
1. First-time execution claim with complete metadata binding.
2. Duplicate execution rejection.
3. Duplicate manifest ID rejection.
4. Conflicting execution/manifest identifiers.
5. Concurrent duplicate claims (multi-threaded race conditions).
6. Persistence across journal reopen/restart.
7. Valid state transitions.
8. Invalid state transitions.
9. OUTCOME_UNKNOWN behavior (crash recovery reconciliation & terminality).
10. Journal unavailable/corrupt behavior (fail-closed, no silent resets).
11. No automatic retry after uncertain outcomes.
12. Exact authorized_path, key_id, and manifest_digest persistence.
13. Strict validation and rejection of malformed metadata.
14. Database symlink rejection and path safety.
15. Incompatible schema fails closed without silently discarding data.
"""

import os
import sqlite3
import stat
import tempfile
import threading
import time
from unittest.mock import patch
import uuid
import pytest

from app.execution.manifest_journal import (
    BrokerManifestJournal,
    ExecutionState,
    JournalClaimError,
    JournalConflictError,
    JournalError,
    JournalRecordNotFoundError,
    JournalStateTransitionError,
    JournalUnavailableError,
    ManifestRecord,
)

SAMPLE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SAMPLE_MANIFEST_DIGEST = "c744f6f17e082c5f1c911bc93efb8e21a415a77be60c9ea4ca4187f5d96ca446"
SAMPLE_KEY_ID = "key-ed25519-v1"
SAMPLE_PATH = "/api/v1/orders/recovery"


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a path to a temporary SQLite database file."""
    return str(tmp_path / "test_manifest_journal.db")


@pytest.fixture
def journal(temp_db_path):
    """Initialize a fresh BrokerManifestJournal instance."""
    j = BrokerManifestJournal(db_path=temp_db_path)
    yield j
    j.close()


class TestBrokerManifestJournal:
    """Test suite verifying all Stage 3 requirements and corrections."""

    # 1. First-time execution claim
    def test_01_first_time_execution_claim(self, journal):
        manifest_id = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())
        now = int(time.time())
        expires_at = now + 60

        record = journal.claim_manifest(
            manifest_id=manifest_id,
            execution_id=execution_id,
            action_id="execute_http_recovery",
            authorized_origin="https://order-api.internal:8001",
            authorized_path=SAMPLE_PATH,
            parameters_sha256=SAMPLE_SHA256,
            key_id=SAMPLE_KEY_ID,
            manifest_digest=SAMPLE_MANIFEST_DIGEST,
            expires_at=expires_at,
        )

        assert record.manifest_id == manifest_id
        assert record.execution_id == execution_id
        assert record.action_id == "execute_http_recovery"
        assert record.authorized_origin == "https://order-api.internal:8001"
        assert record.authorized_path == SAMPLE_PATH
        assert record.parameters_sha256 == SAMPLE_SHA256
        assert record.key_id == SAMPLE_KEY_ID
        assert record.manifest_digest == SAMPLE_MANIFEST_DIGEST
        assert record.state == ExecutionState.CLAIMED
        assert record.expires_at == expires_at
        assert record.error_message is None

        # Verify lookup
        by_m = journal.get_record(manifest_id)
        assert by_m == record
        by_e = journal.get_record_by_execution_id(execution_id)
        assert by_e == record

    # 2. Duplicate execution rejection
    def test_02_duplicate_execution_rejection(self, journal):
        manifest_id = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())
        now = int(time.time())

        journal.claim_manifest(
            manifest_id=manifest_id,
            execution_id=execution_id,
            action_id="execute_http_recovery",
            authorized_origin="https://order-api.internal:8001",
            authorized_path=SAMPLE_PATH,
            parameters_sha256=SAMPLE_SHA256,
            key_id=SAMPLE_KEY_ID,
            manifest_digest=SAMPLE_MANIFEST_DIGEST,
            expires_at=now + 60,
        )

        # Attempt duplicate claim with exact same identifiers
        with pytest.raises(JournalConflictError) as exc_info:
            journal.claim_manifest(
                manifest_id=manifest_id,
                execution_id=execution_id,
                action_id="execute_http_recovery",
                authorized_origin="https://order-api.internal:8001",
                authorized_path=SAMPLE_PATH,
                parameters_sha256=SAMPLE_SHA256,
                key_id=SAMPLE_KEY_ID,
                manifest_digest=SAMPLE_MANIFEST_DIGEST,
                expires_at=now + 60,
            )

        assert "already been claimed" in str(exc_info.value)

    # 3. Duplicate manifest ID rejection
    def test_03_duplicate_manifest_id_rejection(self, journal):
        manifest_id = str(uuid.uuid4())
        exec_id_1 = str(uuid.uuid4())
        exec_id_2 = str(uuid.uuid4())
        now = int(time.time())

        journal.claim_manifest(
            manifest_id=manifest_id,
            execution_id=exec_id_1,
            action_id="restore_order_api_demo",
            authorized_origin="http://localhost:8001",
            authorized_path="/demo/restore",
            parameters_sha256=SAMPLE_SHA256,
            key_id=SAMPLE_KEY_ID,
            manifest_digest=SAMPLE_MANIFEST_DIGEST,
            expires_at=now + 60,
        )

        # Re-use manifest_id with different execution_id
        with pytest.raises(JournalConflictError) as exc_info:
            journal.claim_manifest(
                manifest_id=manifest_id,
                execution_id=exec_id_2,
                action_id="restore_order_api_demo",
                authorized_origin="http://localhost:8001",
                authorized_path="/demo/restore",
                parameters_sha256=SAMPLE_SHA256,
                key_id=SAMPLE_KEY_ID,
                manifest_digest=SAMPLE_MANIFEST_DIGEST,
                expires_at=now + 60,
            )

        assert "different execution ID" in str(exc_info.value)

    # 4. Conflicting execution/manifest identifiers
    def test_04_conflicting_execution_manifest_identifiers(self, journal):
        manifest_1 = str(uuid.uuid4())
        manifest_2 = str(uuid.uuid4())
        exec_id_1 = str(uuid.uuid4())
        now = int(time.time())

        # Claim manifest 1 with exec 1
        journal.claim_manifest(
            manifest_id=manifest_1,
            execution_id=exec_id_1,
            action_id="inspect_service_health",
            authorized_origin="https://health.internal:8000",
            authorized_path="/health",
            parameters_sha256=SAMPLE_SHA256,
            key_id=SAMPLE_KEY_ID,
            manifest_digest=SAMPLE_MANIFEST_DIGEST,
            expires_at=now + 60,
        )

        # Claim manifest 2 with same exec 1
        with pytest.raises(JournalConflictError) as exc_info:
            journal.claim_manifest(
                manifest_id=manifest_2,
                execution_id=exec_id_1,
                action_id="inspect_service_health",
                authorized_origin="https://health.internal:8000",
                authorized_path="/health",
                parameters_sha256=SAMPLE_SHA256,
                key_id=SAMPLE_KEY_ID,
                manifest_digest=SAMPLE_MANIFEST_DIGEST,
                expires_at=now + 60,
            )

        assert "already been claimed with different manifest ID" in str(exc_info.value)

    # 5. Concurrent duplicate claims
    def test_05_concurrent_duplicate_claims(self, temp_db_path):
        manifest_id = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())
        now = int(time.time())
        expires_at = now + 60

        # Pre-initialize journal database before concurrent claims race
        init_j = BrokerManifestJournal(db_path=temp_db_path, timeout=10.0)
        init_j.close()

        successes = []
        conflicts = []
        errors = []
        barrier = threading.Barrier(10)

        def worker(worker_id):
            try:
                j = BrokerManifestJournal(db_path=temp_db_path, timeout=10.0)
                try:
                    barrier.wait(timeout=5.0)
                    rec = j.claim_manifest(
                        manifest_id=manifest_id,
                        execution_id=execution_id,
                        action_id="execute_http_recovery",
                        authorized_origin="https://order-api.internal:8001",
                        authorized_path=SAMPLE_PATH,
                        parameters_sha256=SAMPLE_SHA256,
                        key_id=SAMPLE_KEY_ID,
                        manifest_digest=SAMPLE_MANIFEST_DIGEST,
                        expires_at=expires_at,
                    )
                    successes.append((worker_id, rec))
                except JournalConflictError as e:
                    conflicts.append((worker_id, str(e)))
                except Exception as e:
                    errors.append((worker_id, f"{type(e).__name__}: {e}"))
                finally:
                    j.close()
            except Exception as e:
                errors.append((worker_id, f"Worker init error: {type(e).__name__}: {e}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Unexpected errors: {errors}"
        assert len(successes) == 1, f"Expected exactly 1 claim to succeed, got: {len(successes)}"
        assert len(conflicts) == 9, f"Expected 9 conflicts, got: {len(conflicts)}"

    # 6. Persistence across journal reopen/restart
    def test_06_persistence_across_journal_restart(self, temp_db_path):
        manifest_id = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())
        now = int(time.time())

        # Session 1: Claim and transition to EXECUTING
        j1 = BrokerManifestJournal(db_path=temp_db_path)
        j1.claim_manifest(
            manifest_id=manifest_id,
            execution_id=execution_id,
            action_id="execute_http_recovery",
            authorized_origin="https://order-api.internal:8001",
            authorized_path=SAMPLE_PATH,
            parameters_sha256=SAMPLE_SHA256,
            key_id=SAMPLE_KEY_ID,
            manifest_digest=SAMPLE_MANIFEST_DIGEST,
            expires_at=now + 60,
        )
        rec1 = j1.mark_executing(manifest_id)
        assert rec1.state == ExecutionState.EXECUTING
        j1.close()

        # Session 2: Reopen journal and inspect record
        j2 = BrokerManifestJournal(db_path=temp_db_path)
        rec2 = j2.get_record(manifest_id)
        assert rec2 is not None
        assert rec2.manifest_id == manifest_id
        assert rec2.execution_id == execution_id
        assert rec2.authorized_path == SAMPLE_PATH
        assert rec2.key_id == SAMPLE_KEY_ID
        assert rec2.manifest_digest == SAMPLE_MANIFEST_DIGEST
        assert rec2.state == ExecutionState.EXECUTING

        # Mark COMPLETED in session 2
        rec3 = j2.mark_completed(manifest_id)
        assert rec3.state == ExecutionState.COMPLETED
        j2.close()

        # Session 3: Reopen journal and verify COMPLETED state persisted
        j3 = BrokerManifestJournal(db_path=temp_db_path)
        rec4 = j3.get_record(manifest_id)
        assert rec4 is not None
        assert rec4.state == ExecutionState.COMPLETED
        j3.close()

    # 7. Valid state transitions
    def test_07_valid_state_transitions(self, journal):
        now = int(time.time())

        # Path A: CLAIMED -> EXECUTING -> COMPLETED
        m_a = str(uuid.uuid4())
        journal.claim_manifest(m_a, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        rec = journal.mark_executing(m_a)
        assert rec.state == ExecutionState.EXECUTING
        rec = journal.mark_completed(m_a)
        assert rec.state == ExecutionState.COMPLETED

        # Path B: CLAIMED -> EXECUTING -> FAILED
        m_b = str(uuid.uuid4())
        journal.claim_manifest(m_b, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        journal.mark_executing(m_b)
        rec = journal.mark_failed(m_b, error_message="Action process returned exit code 1")
        assert rec.state == ExecutionState.FAILED
        assert "exit code 1" in rec.error_message

        # Path C: CLAIMED -> FAILED (e.g. firewall/container setup error before executing)
        m_c = str(uuid.uuid4())
        journal.claim_manifest(m_c, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        rec = journal.mark_failed(m_c, error_message="Container creation failed")
        assert rec.state == ExecutionState.FAILED
        assert "Container creation failed" in rec.error_message

        # Path D: CLAIMED -> OUTCOME_UNKNOWN (e.g. uncertain failure during pre-launch)
        m_d = str(uuid.uuid4())
        journal.claim_manifest(m_d, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        rec = journal.mark_outcome_unknown(m_d, reason="Preflight indeterminate")
        assert rec.state == ExecutionState.OUTCOME_UNKNOWN

        # Path E: EXECUTING -> OUTCOME_UNKNOWN (e.g. timeout with uncertain container state)
        m_e = str(uuid.uuid4())
        journal.claim_manifest(m_e, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        journal.mark_executing(m_e)
        rec = journal.mark_outcome_unknown(m_e, reason="Execution timeout; status unconfirmed")
        assert rec.state == ExecutionState.OUTCOME_UNKNOWN

    # 8. Invalid state transitions
    def test_08_invalid_state_transitions(self, journal):
        now = int(time.time())

        # Test A: Cannot skip EXECUTING to COMPLETED from CLAIMED
        m1 = str(uuid.uuid4())
        journal.claim_manifest(m1, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        with pytest.raises(JournalStateTransitionError) as exc_info:
            journal.mark_completed(m1)
        assert "Illegal state transition from CLAIMED to COMPLETED" in str(exc_info.value)

        # Test B: Cannot transition from COMPLETED to anything
        journal.mark_executing(m1)
        journal.mark_completed(m1)
        with pytest.raises(JournalStateTransitionError):
            journal.mark_executing(m1)
        with pytest.raises(JournalStateTransitionError):
            journal.mark_failed(m1)
        with pytest.raises(JournalStateTransitionError):
            journal.mark_outcome_unknown(m1)

        # Test C: Cannot transition from FAILED to anything
        m2 = str(uuid.uuid4())
        journal.claim_manifest(m2, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        journal.mark_failed(m2, "failed")
        with pytest.raises(JournalStateTransitionError):
            journal.mark_executing(m2)
        with pytest.raises(JournalStateTransitionError):
            journal.mark_completed(m2)

        # Test D: Non-existent manifest record
        with pytest.raises(JournalRecordNotFoundError):
            journal.mark_executing(str(uuid.uuid4()))

    # 9. OUTCOME_UNKNOWN behavior and crash recovery reconciliation
    def test_09_outcome_unknown_behavior_and_crash_recovery(self, temp_db_path):
        now = int(time.time())

        # Create session and claim two manifests; one left in CLAIMED, one in EXECUTING
        j1 = BrokerManifestJournal(db_path=temp_db_path)
        m_claimed = str(uuid.uuid4())
        m_executing = str(uuid.uuid4())
        m_completed = str(uuid.uuid4())

        j1.claim_manifest(m_claimed, str(uuid.uuid4()), "act", "https://api:80", "/p1", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        j1.claim_manifest(m_executing, str(uuid.uuid4()), "act", "https://api:80", "/p2", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        j1.mark_executing(m_executing)
        j1.claim_manifest(m_completed, str(uuid.uuid4()), "act", "https://api:80", "/p3", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        j1.mark_executing(m_completed)
        j1.mark_completed(m_completed)

        # Simulate sudden broker crash (close connections without clean termination of in-flight executions)
        j1.close()

        # Broker restart: Daemon initializes new journal and triggers reconciliation
        j2 = BrokerManifestJournal(db_path=temp_db_path)
        reconciled = j2.reconcile_unresolved_claims()

        assert len(reconciled) == 2
        reconciled_ids = {r.manifest_id for r in reconciled}
        assert m_claimed in reconciled_ids
        assert m_executing in reconciled_ids
        assert m_completed not in reconciled_ids

        # Verify database state after recovery
        rec_claimed = j2.get_record(m_claimed)
        assert rec_claimed.state == ExecutionState.OUTCOME_UNKNOWN
        assert rec_claimed.authorized_path == "/p1"
        assert rec_claimed.key_id == "k1"
        assert rec_claimed.manifest_digest == SAMPLE_MANIFEST_DIGEST
        assert "Broker recovery reconciliation" in rec_claimed.error_message

        rec_executing = j2.get_record(m_executing)
        assert rec_executing.state == ExecutionState.OUTCOME_UNKNOWN

        rec_completed = j2.get_record(m_completed)
        assert rec_completed.state == ExecutionState.COMPLETED

        # Verify OUTCOME_UNKNOWN terminality: cannot transition to any state
        with pytest.raises(JournalStateTransitionError):
            j2.mark_executing(m_claimed)
        with pytest.raises(JournalStateTransitionError):
            j2.mark_completed(m_claimed)
        with pytest.raises(JournalStateTransitionError):
            j2.mark_failed(m_claimed)

        j2.close()

    # 10. Journal unavailable/corrupt behavior
    def test_10_journal_unavailable_and_corrupt_behavior(self, tmp_path):
        # Case A: Corrupted SQLite database file (refuses to reset, fails closed)
        corrupt_db_path = str(tmp_path / "corrupt_manifest_journal.db")
        with open(corrupt_db_path, "wb") as f:
            f.write(b"NOT_A_VALID_SQLITE3_DATABASE_HEADER_CORRUPTED_DATA_BYTES")

        with pytest.raises(JournalUnavailableError) as exc_info:
            BrokerManifestJournal(db_path=corrupt_db_path)

        assert "corrupted" in str(exc_info.value).lower()
        # Verify file was NOT deleted or reset
        assert os.path.exists(corrupt_db_path)
        with open(corrupt_db_path, "rb") as f:
            header = f.read(20)
            assert header.startswith(b"NOT_A_VALID_SQLITE3")

        # Case B: Directory cannot be created / accessed (file blocking directory)
        invalid_path = str(tmp_path / "file_blocking_dir" / "sub" / "journal.db")
        with open(str(tmp_path / "file_blocking_dir"), "w") as f:
            f.write("blocking")

        with pytest.raises(JournalUnavailableError):
            BrokerManifestJournal(db_path=invalid_path)

    # 11. No automatic retry after uncertain outcomes
    def test_11_no_automatic_retry_after_uncertain_outcomes(self, journal):
        now = int(time.time())
        manifest_id = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())

        # Claim and transition to OUTCOME_UNKNOWN
        journal.claim_manifest(
            manifest_id=manifest_id,
            execution_id=execution_id,
            action_id="execute_http_recovery",
            authorized_origin="https://order-api.internal:8001",
            authorized_path=SAMPLE_PATH,
            parameters_sha256=SAMPLE_SHA256,
            key_id=SAMPLE_KEY_ID,
            manifest_digest=SAMPLE_MANIFEST_DIGEST,
            expires_at=now + 60,
        )
        journal.mark_outcome_unknown(manifest_id, reason="Broker disconnected during execution")

        # Verify state is OUTCOME_UNKNOWN
        record = journal.get_record(manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Attempt to re-claim the exact same manifest or execution ID
        with pytest.raises(JournalConflictError) as exc_info:
            journal.claim_manifest(
                manifest_id=manifest_id,
                execution_id=execution_id,
                action_id="execute_http_recovery",
                authorized_origin="https://order-api.internal:8001",
                authorized_path=SAMPLE_PATH,
                parameters_sha256=SAMPLE_SHA256,
                key_id=SAMPLE_KEY_ID,
                manifest_digest=SAMPLE_MANIFEST_DIGEST,
                expires_at=now + 60,
            )
        assert "already been claimed" in str(exc_info.value)
        assert "OUTCOME_UNKNOWN" in str(exc_info.value)

        # Attempt to transition OUTCOME_UNKNOWN back to CLAIMED or EXECUTING
        with pytest.raises(JournalStateTransitionError):
            journal.mark_executing(manifest_id)

    # 12. Exact authorized_path, key_id, and manifest_digest persistence
    def test_12_exact_authorization_fields_persistence(self, temp_db_path):
        now = int(time.time())
        m_id = str(uuid.uuid4())
        e_id = str(uuid.uuid4())
        specific_path = "/api/v2/tenants/custom/endpoints/recover"
        specific_key = "key-control-plane-staging-2026-v2"
        specific_digest = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

        j = BrokerManifestJournal(db_path=temp_db_path)
        rec = j.claim_manifest(
            manifest_id=m_id,
            execution_id=e_id,
            action_id="execute_http_recovery",
            authorized_origin="https://service.internal:8443",
            authorized_path=specific_path,
            parameters_sha256=SAMPLE_SHA256,
            key_id=specific_key,
            manifest_digest=specific_digest,
            expires_at=now + 60,
        )
        assert rec.authorized_path == specific_path
        assert rec.key_id == specific_key
        assert rec.manifest_digest == specific_digest
        j.close()

        # Reopen and verify database preserved exact strings
        j2 = BrokerManifestJournal(db_path=temp_db_path)
        stored = j2.get_record(m_id)
        assert stored is not None
        assert stored.authorized_path == specific_path
        assert stored.key_id == specific_key
        assert stored.manifest_digest == specific_digest
        j2.close()

    # 13. Rejection of missing or malformed metadata
    def test_13_metadata_validation_and_rejections(self, journal):
        now = int(time.time())

        # Path validation: must start with /
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "no-slash", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        assert "must start with '/'" in str(exc.value)

        # Path validation: traversal prohibited
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path/../admin", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        assert "forbidden traversal or delimiters" in str(exc.value)

        # Path validation: backslash prohibited
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path\\escape", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        assert "forbidden traversal or delimiters" in str(exc.value)

        # Path validation: query strings prohibited
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path?query=1", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        assert "forbidden traversal or delimiters" in str(exc.value)

        # key_id validation: non-empty
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "", SAMPLE_MANIFEST_DIGEST, now + 60)
        assert "key_id must be a non-empty string" in str(exc.value)

        # key_id validation: max length 64
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k" * 65, SAMPLE_MANIFEST_DIGEST, now + 60)
        assert "at most 64 characters" in str(exc.value)

        # manifest_digest validation: must be 64-char lowercase hex
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", "not-a-valid-sha256", now + 60)
        assert "manifest_digest must be a 64-character lowercase hex SHA-256 digest" in str(exc.value)

        # manifest_digest validation: uppercase rejected
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST.upper(), now + 60)
        assert "manifest_digest must be a 64-character lowercase hex SHA-256 digest" in str(exc.value)

        # Expired manifest claim rejected
        with pytest.raises(JournalClaimError) as exc:
            journal.claim_manifest(str(uuid.uuid4()), str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now - 10)
        assert "expired" in str(exc.value).lower()

        # Sensitive error message redaction
        m = str(uuid.uuid4())
        journal.claim_manifest(m, str(uuid.uuid4()), "act", "https://api:80", "/path", SAMPLE_SHA256, "k1", SAMPLE_MANIFEST_DIGEST, now + 60)
        sensitive_err = "Failed with Bearer my_secret_token_12345 and password: secret_password"
        rec = journal.mark_failed(m, error_message=sensitive_err)
        assert "my_secret_token_12345" not in rec.error_message
        assert "[REDACTED]" in rec.error_message
        assert "secret_password" not in rec.error_message

    # 14. Database symlink rejection and path safety
    def test_14_symlink_rejection_and_path_safety(self, tmp_path):
        target_db = tmp_path / "actual.db"
        symlink_db = tmp_path / "symlink_journal.db"

        # Attempt to create real symlink if OS supports it
        symlink_created = False
        try:
            target_db.write_text("dummy")
            os.symlink(str(target_db), str(symlink_db))
            symlink_created = True
        except (OSError, NotImplementedError):
            pass

        if symlink_created:
            with pytest.raises(JournalUnavailableError) as exc_info:
                BrokerManifestJournal(db_path=str(symlink_db))
            assert "symbolic link" in str(exc_info.value).lower()
        else:
            # On platforms where unprivileged symlink creation is prohibited (e.g. standard Windows),
            # verify path safety check using monkeypatch / mock on os.path.islink
            with patch("os.path.islink", return_value=True):
                with pytest.raises(JournalUnavailableError) as exc_info:
                    BrokerManifestJournal(db_path=str(tmp_path / "mocked_symlink.db"))
                assert "symbolic link" in str(exc_info.value).lower()

    # 15. Incompatible existing database schema fails closed without silently recreating
    def test_15_incompatible_schema_fails_closed(self, tmp_path):
        legacy_db_path = str(tmp_path / "legacy_manifest_journal.db")

        # Manually create a legacy table missing authorized_path, key_id, manifest_digest
        conn = sqlite3.connect(legacy_db_path)
        conn.execute(
            """
            CREATE TABLE manifest_claims (
                manifest_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL UNIQUE,
                action_id TEXT NOT NULL,
                authorized_origin TEXT NOT NULL,
                parameters_sha256 TEXT NOT NULL,
                claimed_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                error_message TEXT,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

        # Opening with new journal must fail closed with JournalUnavailableError
        # and NOT silently drop or recreate the existing table
        with pytest.raises(JournalUnavailableError) as exc_info:
            BrokerManifestJournal(db_path=legacy_db_path)

        assert "incompatible schema" in str(exc_info.value).lower()
        assert "authorized_path" in str(exc_info.value)

        # Verify existing table was preserved and not overwritten
        conn2 = sqlite3.connect(legacy_db_path)
        cur = conn2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manifest_claims'")
        assert cur.fetchone() is not None
        cur_cols = conn2.execute("PRAGMA table_info(manifest_claims)")
        cols = {row[1] for row in cur_cols.fetchall()}
        assert "authorized_path" not in cols  # Still legacy, not silently modified
        conn2.close()
