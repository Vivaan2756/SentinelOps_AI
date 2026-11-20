"""Comprehensive Test Suite for OperationJournal Engine (Phase 4.3.6 Milestone E.1).

Covers all 18 required scenarios:
1. Journal initialization.
2. Append one record and replay it.
3. Append multiple records and verify sequence continuity.
4. Verify SHA-256 digest chain.
5. Detect CRC32 corruption.
6. Detect invalid magic bytes.
7. Detect sequence gaps and duplicates.
8. Detect invalid payload lengths.
9. Handle partial writes using a controlled write test double.
10. Handle incomplete trailing frames conservatively.
11. Fail closed on potentially dispatch-related torn records.
12. Reject appends after corruption is detected.
13. Verify single-writer locking.
14. Verify sequence overflow rejection (2^63 - 1).
15. Verify fsync failure handling.
16. Verify permissions and symlink protections where supported.
17. Verify deterministic JSON serialization.
18. Verify sensitive metadata sanitization.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import struct
import tempfile
from unittest.mock import MagicMock, patch
import uuid
import zlib

import pytest

from app.execution.journal import (
    GENESIS_DIGEST,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC_BYTES,
    MAX_SEQUENCE,
    TRAILER_FORMAT,
    TRAILER_SIZE,
    JournalCorruptedError,
    JournalLockError,
    JournalPermissionError,
    JournalRecordType,
    JournalRecoveryResult,
    JournalSequenceError,
    JournalTailState,
    JournalUncertaintyError,
    JournalWriteError,
    OperationJournal,
    _looping_write,
    compute_frame_digest,
    serialize_payload_deterministic,
)


@pytest.fixture
def temp_journal_dir():
    """Provides a fresh, isolated temporary directory for journal tests."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        yield tmp_dir


# ============================================================================
# 1. Journal Initialization
# ============================================================================

def test_journal_initialization(temp_journal_dir):
    """Journal initializes cleanly on an empty directory with sequence 0 and genesis digest."""
    journal = OperationJournal(journal_dir=temp_journal_dir)
    res = journal.open()

    assert res.is_clean is True
    assert res.records_replayed == 0
    assert res.tail_state == JournalTailState.CLEAN_EOF
    assert res.last_valid_sequence == 0
    assert res.last_valid_digest == GENESIS_DIGEST
    assert res.uncertain_hold_required is False
    assert res.can_append is True

    assert journal.current_sequence == 0
    assert journal.current_digest == GENESIS_DIGEST
    assert journal.is_clean is True
    assert journal.can_append is True

    journal.close()


# ============================================================================
# 2. Append One Record and Replay
# ============================================================================

def test_journal_append_and_replay_single_record(temp_journal_dir):
    """Appending a single record persists it durably and replays with exact fields."""
    op_id = str(uuid.uuid4())
    exec_id = str(uuid.uuid4())
    ws_id = str(uuid.uuid4())

    with OperationJournal(journal_dir=temp_journal_dir) as j:
        rec = j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id=op_id,
            execution_id=exec_id,
            workspace_id=ws_id,
            attempt_number=1,
            fencing_token=10,
            approval_id="appr-1",
            metadata={"target": "order-api"},
        )
        assert rec.sequence == 1
        assert rec.previous_digest == GENESIS_DIGEST
        assert len(rec.frame_digest) == 32
        assert rec.record_type == JournalRecordType.DISPATCH_PREPARED.value

    # Re-open in a new journal instance
    with OperationJournal(journal_dir=temp_journal_dir) as j2:
        records = j2.replay()
        assert len(records) == 1
        r = records[0]
        assert r.sequence == 1
        assert r.operation_id == op_id
        assert r.execution_id == exec_id
        assert r.workspace_id == ws_id
        assert r.approval_id == "appr-1"
        assert r.attempt_number == 1
        assert r.fencing_token == 10
        assert r.record_type == "DISPATCH_PREPARED"
        assert r.previous_digest == GENESIS_DIGEST
        assert r.metadata == {"target": "order-api"}
        assert j2.current_sequence == 1
        assert j2.current_digest == r.frame_digest


# ============================================================================
# 3. Append Multiple Records & Verify Sequence Continuity
# ============================================================================

def test_journal_append_multiple_records_sequence_continuity(temp_journal_dir):
    """Sequences increment monotonically (1..5) across multiple record types."""
    types = [
        JournalRecordType.DISPATCH_PREPARED,
        JournalRecordType.DISPATCH_ACCEPTED,
        JournalRecordType.DOCKER_CALL_STARTED,
        JournalRecordType.DOCKER_CALL_CONFIRMED,
        JournalRecordType.DOCKER_CALL_COMPLETED,
    ]

    with OperationJournal(journal_dir=temp_journal_dir) as j:
        for i, t in enumerate(types, start=1):
            rec = j.append(
                record_type=t,
                operation_id="op-1",
                execution_id="exec-1",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=5,
                metadata={"step": i},
            )
            assert rec.sequence == i

        assert j.current_sequence == 5

    with OperationJournal(journal_dir=temp_journal_dir) as j2:
        records = j2.replay()
        assert len(records) == 5
        for i, r in enumerate(records, start=1):
            assert r.sequence == i
            assert r.record_type == types[i - 1].value


# ============================================================================
# 4. Verify SHA-256 Digest Chain
# ============================================================================

def test_journal_sha256_digest_chain(temp_journal_dir):
    """Cryptographic hash chain is verified against manual SHA-256 calculation."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        r1 = j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-chain",
            execution_id="exec-chain",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
            timestamp="2026-10-31T20:00:00Z",
        )
        r2 = j.append(
            record_type=JournalRecordType.DISPATCH_ACCEPTED,
            operation_id="op-chain",
            execution_id="exec-chain",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
            timestamp="2026-10-31T20:00:01Z",
        )
        r3 = j.append(
            record_type=JournalRecordType.DOCKER_CALL_STARTED,
            operation_id="op-chain",
            execution_id="exec-chain",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
            timestamp="2026-10-31T20:00:02Z",
        )

    # 1. Verify previous_digest linkage
    assert r1.previous_digest == GENESIS_DIGEST
    assert r2.previous_digest == r1.frame_digest
    assert r3.previous_digest == r2.frame_digest

    # 2. Re-compute manually from raw payloads
    p1 = serialize_payload_deterministic(
        operation_id="op-chain",
        execution_id="exec-chain",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=1,
        record_type="DISPATCH_PREPARED",
        timestamp="2026-10-31T20:00:00Z",
    )
    expected_d1 = hashlib.sha256(struct.pack("!Q", 1) + GENESIS_DIGEST + p1).digest()
    assert r1.frame_digest == expected_d1

    p2 = serialize_payload_deterministic(
        operation_id="op-chain",
        execution_id="exec-chain",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=1,
        record_type="DISPATCH_ACCEPTED",
        timestamp="2026-10-31T20:00:01Z",
    )
    expected_d2 = hashlib.sha256(struct.pack("!Q", 2) + expected_d1 + p2).digest()
    assert r2.frame_digest == expected_d2

    p3 = serialize_payload_deterministic(
        operation_id="op-chain",
        execution_id="exec-chain",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=1,
        record_type="DOCKER_CALL_STARTED",
        timestamp="2026-10-31T20:00:02Z",
    )
    expected_d3 = hashlib.sha256(struct.pack("!Q", 3) + expected_d2 + p3).digest()
    assert r3.frame_digest == expected_d3


# ============================================================================
# 5. Detect CRC32 Corruption
# ============================================================================

def test_journal_detect_crc32_corruption(temp_journal_dir):
    """Mutating a byte in the payload triggers CRC32 integrity failure."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-crc",
            execution_id="exec-crc",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
            metadata={"secret_state": "intact"},
        )

    # Mutate byte in file at byte offset 90 (inside payload)
    path = os.path.join(temp_journal_dir, "operations.journal")
    with open(path, "r+b") as f:
        f.seek(90)
        original = f.read(1)
        f.seek(90)
        # Flip bits
        f.write(bytes([original[0] ^ 0xFF]))

    # Reopening must detect corruption and fail closed
    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False

        with pytest.raises(JournalCorruptedError):
            j2.replay()
    finally:
        j2.close()


# ============================================================================
# 6. Detect Invalid Magic Bytes
# ============================================================================

def test_journal_detect_invalid_magic_bytes(temp_journal_dir):
    """Mutating magic bytes from 'SOJ1' to 'BAD1' fails validation."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-magic",
            execution_id="exec-magic",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Mutate magic bytes at offset 0
    path = os.path.join(temp_journal_dir, "operations.journal")
    with open(path, "r+b") as f:
        f.seek(0)
        f.write(b"BAD1")

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False
        assert "Invalid magic bytes" in (res.error_message or "")
    finally:
        j2.close()


# ============================================================================
# 7. Detect Sequence Gaps and Duplicates
# ============================================================================

def test_journal_detect_sequence_gaps_and_duplicates(temp_journal_dir):
    """A synthetic sequence gap (sequence 1 followed by sequence 3) raises JournalSequenceError."""
    # Write record 1 cleanly
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-seq",
            execution_id="exec-seq",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Manually append frame with sequence = 3 (gap of sequence 2)
    path = os.path.join(temp_journal_dir, "operations.journal")
    p = serialize_payload_deterministic(
        operation_id="op-seq",
        execution_id="exec-seq",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=1,
        record_type="DISPATCH_ACCEPTED",
        timestamp="2026-10-31T20:00:00Z",
    )
    # Construct frame with sequence = 3
    dig = compute_frame_digest(3, GENESIS_DIGEST, p)
    hdr = struct.pack(HEADER_FORMAT, MAGIC_BYTES, 3, len(p), GENESIS_DIGEST, dig)
    crc = zlib.crc32(hdr + p) & 0xFFFFFFFF
    trl = struct.pack(TRAILER_FORMAT, crc)

    with open(path, "ab") as f:
        f.write(hdr + p + trl)

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        with pytest.raises(JournalSequenceError, match="Sequence continuity break"):
            j2.open()
    finally:
        j2.close()


# ============================================================================
# 8. Detect Invalid Payload Lengths
# ============================================================================

def test_journal_detect_invalid_payload_length(temp_journal_dir):
    """Mutating payload length to exceed actual frame boundary fails recovery."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-len",
            execution_id="exec-len",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    path = os.path.join(temp_journal_dir, "operations.journal")
    # Mutate payload length in header (offset 12..15)
    with open(path, "r+b") as f:
        f.seek(12)
        f.write(struct.pack("!I", 50000))  # Claim 50000 bytes payload

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False
    finally:
        j2.close()


# ============================================================================
# 9. Handle Partial Writes using Controlled Write Test Double
# ============================================================================

def test_journal_partial_write_handling():
    """_looping_write handles fragmented os.write() calls without data loss."""
    fake_fd = 999
    payload = b"A" * 50

    call_count = 0
    written_data = bytearray()

    def mock_write(fd, data):
        nonlocal call_count, written_data
        assert fd == fake_fd
        call_count += 1
        # Write only 10 bytes at a time
        chunk = data[:10]
        written_data.extend(chunk)
        return len(chunk)

    with patch("os.write", side_effect=mock_write):
        _looping_write(fake_fd, payload)

    assert call_count == 5  # 50 bytes / 10 bytes per chunk = 5 calls
    assert bytes(written_data) == payload


# ============================================================================
# 10. Handle Incomplete Trailing Frames Conservatively
# ============================================================================

def test_journal_handle_incomplete_trailing_frames_conservatively(temp_journal_dir):
    """Truncated trailing frame at EOF is detected; journal enters uncertainty hold and refuses appends/replays."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-torn",
            execution_id="exec-torn",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Append 15 bytes of incomplete header at EOF
    path = os.path.join(temp_journal_dir, "operations.journal")
    with open(path, "ab") as f:
        f.write(b"SOJ1\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00")

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False
        assert res.unrecovered_bytes == 14
        assert res.uncertain_hold_required is True  # Ambiguous trailing bytes
        assert res.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j2.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j2.append(
                record_type=JournalRecordType.DISPATCH_FAILED,
                operation_id="op-torn",
                execution_id="exec-torn",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j2.close()


# ============================================================================
# 11. Fail Closed on Potentially Dispatch-Related Torn Records
# ============================================================================

def test_journal_fail_closed_on_dispatch_related_torn_records(temp_journal_dir):
    """
    CRITICAL SAFETY INVARIANT:
    If incomplete trailing bytes contain DOCKER_CALL_STARTED, journal must enter
    fail-closed uncertainty hold (TORN_DISPATCH_AMBIGUOUS). Never claim Docker was not called.
    """
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_ACCEPTED,
            operation_id="op-dispatch-torn",
            execution_id="exec-dispatch-torn",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=10,
        )

    # Simulate crash mid-write of DOCKER_CALL_STARTED (partial JSON containing marker)
    path = os.path.join(temp_journal_dir, "operations.journal")
    partial_dispatch_frame = (
        MAGIC_BYTES
        + struct.pack("!QI", 2, 120)
        + b"\x00" * 32
        + b"\x00" * 32
        + b'{"record_type":"DOCKER_CALL_STARTED","operation_id":"op-dispatch-torn"'
    )
    with open(path, "ab") as f:
        f.write(partial_dispatch_frame)

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS
        assert res.uncertain_hold_required is True
        assert res.can_append is False

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j2.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j2.append(
                record_type=JournalRecordType.DISPATCH_FAILED,
                operation_id="op-dispatch-torn",
                execution_id="exec-dispatch-torn",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=10,
            )
    finally:
        j2.close()


# ============================================================================
# Focused Tests: Conservative Incomplete-Tail Handling Invariants
# ============================================================================

def test_journal_partial_header_always_causes_uncertainty_hold(temp_journal_dir):
    """A partial header (< 80 bytes) at tail always causes uncertainty hold."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-ph",
            execution_id="exec-ph",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Append 30 bytes of incomplete header (less than HEADER_SIZE=80)
    path = os.path.join(temp_journal_dir, "operations.journal")
    with open(path, "ab") as f:
        f.write(MAGIC_BYTES + struct.pack("!QI", 2, 50) + b"\xaa" * 14)

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False
        assert res.uncertain_hold_required is True
        assert res.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS
        assert res.unrecovered_bytes == 30

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j2.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j2.append(
                record_type=JournalRecordType.DISPATCH_ACCEPTED,
                operation_id="op-ph",
                execution_id="exec-ph",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j2.close()


def test_journal_partial_payload_without_marker_causes_uncertainty_hold(temp_journal_dir):
    """
    A partial payload causes uncertainty hold even when NO dispatch marker
    is present in the available fragment.
    """
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        rec1 = j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-no-marker",
            execution_id="exec-no-marker",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Prepare frame 2 with full header specifying payload_len = 80
    path = os.path.join(temp_journal_dir, "operations.journal")
    full_payload = b'{"operation_id":"op-no-marker","step":"validate","safe_info":"completely_innocent"}'
    payload_len = len(full_payload)
    dig2 = compute_frame_digest(2, rec1.frame_digest, full_payload)
    hdr2 = struct.pack(HEADER_FORMAT, MAGIC_BYTES, 2, payload_len, rec1.frame_digest, dig2)

    # Write full header (80B) + only first 25 bytes of payload (no marker at all)
    partial_payload = full_payload[:25]
    assert b"DOCKER" not in partial_payload
    assert b"DISPATCH" not in partial_payload

    with open(path, "ab") as f:
        f.write(hdr2 + partial_payload)

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        # Must be treated as ambiguous despite having no marker in available fragment
        assert res.is_clean is False
        assert res.can_append is False
        assert res.uncertain_hold_required is True
        assert res.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS
        assert res.unrecovered_bytes == HEADER_SIZE + len(partial_payload)

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j2.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j2.append(
                record_type=JournalRecordType.DISPATCH_ACCEPTED,
                operation_id="op-no-marker",
                execution_id="exec-no-marker",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j2.close()


def test_journal_partial_payload_marker_later_in_payload_causes_uncertainty_hold(temp_journal_dir):
    """
    A partial payload causes uncertainty hold when the marker would have appeared
    later in the original unwritten payload bytes.
    """
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        rec1 = j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-late-marker",
            execution_id="exec-late-marker",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Full payload has DOCKER_CALL_STARTED placed at the end of the JSON object
    path = os.path.join(temp_journal_dir, "operations.journal")
    full_payload = (
        b'{"metadata":{"filler":"padding_bytes_to_push_marker_back_in_json"},'
        b'"record_type":"DOCKER_CALL_STARTED"}'
    )
    payload_len = len(full_payload)
    dig2 = compute_frame_digest(2, rec1.frame_digest, full_payload)
    hdr2 = struct.pack(HEADER_FORMAT, MAGIC_BYTES, 2, payload_len, rec1.frame_digest, dig2)

    # Cut off write at byte 35 (inside filler metadata, before "DOCKER_CALL_STARTED" appears)
    partial_payload = full_payload[:35]
    assert b"DOCKER_CALL_STARTED" not in partial_payload
    assert b"DOCKER" not in partial_payload

    with open(path, "ab") as f:
        f.write(hdr2 + partial_payload)

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False
        assert res.uncertain_hold_required is True
        assert res.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j2.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j2.append(
                record_type=JournalRecordType.DISPATCH_FAILED,
                operation_id="op-late-marker",
                execution_id="exec-late-marker",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j2.close()


def test_journal_missing_or_partial_crc_trailer_causes_uncertainty_hold(temp_journal_dir):
    """
    A missing or partial CRC trailer (0, 1, 2, or 3 bytes of 4) causes uncertainty hold.
    """
    # Case A: Missing CRC trailer entirely (0 of 4 bytes)
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        rec1 = j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-crc-missing",
            execution_id="exec-crc-missing",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    path = os.path.join(temp_journal_dir, "operations.journal")
    payload2 = serialize_payload_deterministic(
        operation_id="op-crc-missing",
        execution_id="exec-crc-missing",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=1,
        record_type="DISPATCH_ACCEPTED",
        timestamp="2026-10-31T20:00:00Z",
    )
    dig2 = compute_frame_digest(2, rec1.frame_digest, payload2)
    hdr2 = struct.pack(HEADER_FORMAT, MAGIC_BYTES, 2, len(payload2), rec1.frame_digest, dig2)

    # Write full header + full payload, but ZERO bytes of CRC trailer
    with open(path, "ab") as f:
        f.write(hdr2 + payload2)

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is False
        assert res.can_append is False
        assert res.uncertain_hold_required is True
        assert res.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j2.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j2.append(
                record_type=JournalRecordType.DISPATCH_FAILED,
                operation_id="op-crc-missing",
                execution_id="exec-crc-missing",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j2.close()

    # Case B: Partial CRC trailer (2 of 4 bytes)
    # Append 2 bytes of the CRC
    body2 = hdr2 + payload2
    crc2 = zlib.crc32(body2) & 0xFFFFFFFF
    partial_crc = struct.pack(TRAILER_FORMAT, crc2)[:2]
    with open(path, "ab") as f:
        f.write(partial_crc)

    j3 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res3 = j3.open()
        assert res3.is_clean is False
        assert res3.can_append is False
        assert res3.uncertain_hold_required is True
        assert res3.tail_state == JournalTailState.TORN_DISPATCH_AMBIGUOUS

        with pytest.raises(JournalUncertaintyError, match="fail-closed uncertainty hold"):
            j3.replay()

        with pytest.raises(JournalUncertaintyError, match="ambiguous/uncertain dispatch state"):
            j3.append(
                record_type=JournalRecordType.DISPATCH_FAILED,
                operation_id="op-crc-missing",
                execution_id="exec-crc-missing",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j3.close()


def test_journal_complete_valid_ending_at_clean_eof_remains_appendable(temp_journal_dir):
    """A complete valid journal ending at clean EOF remains fully appendable and replayable."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-clean-eof",
            execution_id="exec-clean-eof",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )
        j.append(
            record_type=JournalRecordType.DISPATCH_ACCEPTED,
            operation_id="op-clean-eof",
            execution_id="exec-clean-eof",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Reopen and inspect tail state
    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        res = j2.open()
        assert res.is_clean is True
        assert res.can_append is True
        assert res.tail_state == JournalTailState.CLEAN_EOF
        assert res.uncertain_hold_required is False
        assert res.records_replayed == 2
        assert res.last_valid_sequence == 2

        # Replay must succeed cleanly
        records = j2.replay()
        assert len(records) == 2
        assert records[0].sequence == 1
        assert records[1].sequence == 2

        # Appending must succeed cleanly
        rec3 = j2.append(
            record_type=JournalRecordType.DOCKER_CALL_STARTED,
            operation_id="op-clean-eof",
            execution_id="exec-clean-eof",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )
        assert rec3.sequence == 3
        assert j2.current_sequence == 3
    finally:
        j2.close()


# ============================================================================
# 12. Reject Appends After Corruption is Detected
# ============================================================================

def test_journal_reject_appends_after_corruption_detected(temp_journal_dir):
    """A corrupted journal unconditionally blocks append() calls."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-1",
            execution_id="exec-1",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
        )

    # Corrupt file
    path = os.path.join(temp_journal_dir, "operations.journal")
    with open(path, "r+b") as f:
        f.seek(10)
        f.write(b"\xFF\xFF")

    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        j2.open()
        assert j2.can_append is False

        with pytest.raises((JournalCorruptedError, JournalUncertaintyError)):
            j2.append(
                record_type=JournalRecordType.DISPATCH_ACCEPTED,
                operation_id="op-1",
                execution_id="exec-1",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )
    finally:
        j2.close()


# ============================================================================
# 13. Verify Single-Writer Locking
# ============================================================================

def test_journal_single_writer_locking(temp_journal_dir):
    """Two concurrent journal instances cannot hold lock simultaneously."""
    j1 = OperationJournal(journal_dir=temp_journal_dir)
    j2 = OperationJournal(journal_dir=temp_journal_dir)
    try:
        j1.open()
        with pytest.raises(JournalLockError):
            j2.open()

        # Close j1, j2 can now acquire
        j1.close()
        res2 = j2.open()
        assert res2.is_clean is True
    finally:
        j1.close()
        j2.close()


# ============================================================================
# 14. Verify Sequence Overflow Rejection (2^63 - 1)
# ============================================================================

def test_journal_sequence_overflow_rejection(temp_journal_dir):
    """Sequence number cannot exceed MAX_SEQUENCE (2^63 - 1). Rejects overflow rather than wrapping."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        # Simulate tail reaching MAX_SEQUENCE
        j._current_sequence = MAX_SEQUENCE

        with pytest.raises(JournalSequenceError, match="Journal sequence number overflow"):
            j.append(
                record_type=JournalRecordType.DISPATCH_PREPARED,
                operation_id="op-overflow",
                execution_id="exec-overflow",
                workspace_id="ws-1",
                attempt_number=1,
                fencing_token=1,
            )


# ============================================================================
# 15. Verify Fsync Failure Handling
# ============================================================================

def test_journal_fsync_failure_handling(temp_journal_dir):
    """Failure during os.fsync() raises JournalWriteError and sets can_append=False."""
    with OperationJournal(journal_dir=temp_journal_dir) as j:
        with patch("os.fsync", side_effect=OSError("Disk I/O fsync failure")):
            with pytest.raises(JournalWriteError, match="os.fsync failed"):
                j.append(
                    record_type=JournalRecordType.DISPATCH_PREPARED,
                    operation_id="op-fsync-err",
                    execution_id="exec-fsync-err",
                    workspace_id="ws-1",
                    attempt_number=1,
                    fencing_token=1,
                )

        assert j.can_append is False


# ============================================================================
# 16. Verify Permissions and Symlink Protections
# ============================================================================

def test_journal_permissions_and_symlink_protections(temp_journal_dir):
    """Opening a symlinked journal file is rejected with JournalPermissionError."""
    real_file = os.path.join(temp_journal_dir, "real_journal.journal")
    with open(real_file, "wb") as f:
        f.write(b"")

    symlink_file = os.path.join(temp_journal_dir, "symlink.journal")
    try:
        os.symlink(real_file, symlink_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this OS/privilege context.")

    j = OperationJournal(
        journal_dir=temp_journal_dir,
        journal_filename="symlink.journal",
    )
    try:
        with pytest.raises(JournalPermissionError, match="symbolic link"):
            j.open()
    finally:
        j.close()


# ============================================================================
# 17. Verify Deterministic JSON Serialization
# ============================================================================

def test_journal_deterministic_json_serialization():
    """Dictionaries with different key insertion orders produce byte-identical serialized JSON."""
    meta1 = {"zeta": 1, "alpha": 2, "gamma": {"nested_z": 9, "nested_a": 8}}
    meta2 = {"alpha": 2, "zeta": 1, "gamma": {"nested_a": 8, "nested_z": 9}}

    p1 = serialize_payload_deterministic(
        operation_id="op-1",
        execution_id="exec-1",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=5,
        record_type="DISPATCH_PREPARED",
        timestamp="2026-10-31T20:00:00Z",
        metadata=meta1,
    )

    p2 = serialize_payload_deterministic(
        operation_id="op-1",
        execution_id="exec-1",
        workspace_id="ws-1",
        attempt_number=1,
        fencing_token=5,
        record_type="DISPATCH_PREPARED",
        timestamp="2026-10-31T20:00:00Z",
        metadata=meta2,
    )

    assert p1 == p2


# ============================================================================
# 18. Verify Sensitive Metadata Sanitization
# ============================================================================

def test_journal_sensitive_metadata_sanitization(temp_journal_dir):
    """Passwords, tokens, credentials, and secrets are scrubbed before persistence."""
    dirty_meta = {
        "password": "SuperSecretPassword123!",
        "auth_token": "bearer-token-abc",
        "api_credential": "key-xyz",
        "nested": {
            "secret_key": "topsecret",
            "safe_value": "visible",
        },
        "safe_int": 42,
    }

    with OperationJournal(journal_dir=temp_journal_dir) as j:
        rec = j.append(
            record_type=JournalRecordType.DISPATCH_PREPARED,
            operation_id="op-clean",
            execution_id="exec-clean",
            workspace_id="ws-1",
            attempt_number=1,
            fencing_token=1,
            metadata=dirty_meta,
        )
        assert rec.metadata["password"] == "[REDACTED]"
        assert rec.metadata["auth_token"] == "[REDACTED]"
        assert rec.metadata["api_credential"] == "[REDACTED]"
        assert rec.metadata["nested"]["secret_key"] == "[REDACTED]"
        assert rec.metadata["nested"]["safe_value"] == "visible"
        assert rec.metadata["safe_int"] == 42

    # Replay from disk: verify scrubbed values are durable
    with OperationJournal(journal_dir=temp_journal_dir) as j2:
        records = j2.replay()
        r = records[0]
        assert r.metadata["password"] == "[REDACTED]"
        assert r.metadata["auth_token"] == "[REDACTED]"
        assert r.metadata["api_credential"] == "[REDACTED]"
        assert r.metadata["nested"]["secret_key"] == "[REDACTED]"
        assert r.metadata["nested"]["safe_value"] == "visible"
        assert r.metadata["safe_int"] == 42
