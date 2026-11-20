"""Durable Operation Journal Engine for Phase 4.3.6 Milestone E.1.

Authoritative append-only operation journal providing:
1. Append-only binary-framed records with deterministic JSON payloads.
2. Monotonic 64-bit sequence numbers capped at 2^63 - 1 (SQLite signed INTEGER compatible).
3. Cryptographic SHA-256 hash chaining:
       digest_i = SHA256(sequence_i || previous_digest_i || payload_bytes_i)
   NOTE: This is an append-only cryptographic hash chain (linear blockchain structure),
   not a Merkle tree.
4. CRC32 frame checksumming over headers and payloads.
5. Single-writer mutual exclusion via OS-level non-blocking file locking.
6. Looping os.write() partial write handling and synchronous os.fsync() durability.
7. Conservative torn-write recovery:
   - Differentiates clean EOF from incomplete trailing frames.
   - If an incomplete or corrupted tail frame could represent a dispatch-related record
     (e.g., DOCKER_CALL_STARTED), fails closed into an uncertainty state.
   - Refuses further appends when safety cannot be established.
8. Recursive metadata sanitization (zero credentials, passwords, or tokens persisted).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import os
import struct
import sys
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union
import zlib

from app.execution.manager import sanitize_metadata

logger = logging.getLogger(__name__)

# ============================================================================
# Binary Framing & Cryptographic Constants
# ============================================================================

# Frame magic bytes (4 bytes ASCII 'SOJ1' - SentinelOps Journal v1)
MAGIC_BYTES = b"SOJ1"

# Maximum sequence number: 2^63 - 1 (maximum signed 64-bit integer)
# Strictly compatible with SQLite signed INTEGER columns in Milestone E.2.
MAX_SEQUENCE = (1 << 63) - 1

# Fixed genesis digest (32 bytes SHA-256) used as previous_digest for sequence 1
GENESIS_DIGEST = hashlib.sha256(b"SENTINELOPS_OPERATION_JOURNAL_GENESIS_V1").digest()

# Binary Frame Layout:
# - Magic: 4 bytes (b"SOJ1")
# - Sequence: 8 bytes uint64, big-endian
# - Payload Length: 4 bytes uint32, big-endian
# - Previous Digest: 32 bytes binary SHA-256
# - Frame Digest: 32 bytes binary SHA-256
# Total Header Size: 4 + 8 + 4 + 32 + 32 = 80 bytes
HEADER_FORMAT = "!4sQI32s32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Trailer Layout:
# - CRC32: 4 bytes uint32, big-endian (IEEE 802.3 over Header + Payload)
TRAILER_FORMAT = "!I"
TRAILER_SIZE = struct.calcsize(TRAILER_FORMAT)

# Minimum valid frame size (Header + Trailer with 0 payload)
MIN_FRAME_SIZE = HEADER_SIZE + TRAILER_SIZE  # 84 bytes

# Maximum sanity size for a single payload (16 MB)
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024


# ============================================================================
# Enums and Structured Models
# ============================================================================

class JournalRecordType(str, Enum):
    """Canonical operation record types for dispatch lifecycle tracking."""
    DISPATCH_PREPARED = "DISPATCH_PREPARED"
    DISPATCH_ACCEPTED = "DISPATCH_ACCEPTED"
    DOCKER_CALL_STARTED = "DOCKER_CALL_STARTED"
    DOCKER_CALL_CONFIRMED = "DOCKER_CALL_CONFIRMED"
    DOCKER_CALL_COMPLETED = "DOCKER_CALL_COMPLETED"
    DISPATCH_ABORTED_PRE_DOCKER = "DISPATCH_ABORTED_PRE_DOCKER"
    DISPATCH_FAILED = "DISPATCH_FAILED"
    DISPATCH_UNCERTAIN = "DISPATCH_UNCERTAIN"


# Record types that mark entry into the physical dispatch boundary
DISPATCH_CRITICAL_MARKERS = {
    JournalRecordType.DOCKER_CALL_STARTED.value,
    JournalRecordType.DOCKER_CALL_CONFIRMED.value,
}


class JournalTailState(str, Enum):
    """Classification of the journal tail after replay and recovery scanning."""
    CLEAN_EOF = "CLEAN_EOF"
    TORN_INCOMPLETE_CLEAN = "TORN_INCOMPLETE_CLEAN"
    TORN_DISPATCH_AMBIGUOUS = "TORN_DISPATCH_AMBIGUOUS"
    CORRUPTED_FRAME = "CORRUPTED_FRAME"


@dataclass
class JournalRecord:
    """In-memory representation of a validated journal record."""
    sequence: int
    record_type: str
    operation_id: str
    execution_id: str
    workspace_id: str
    attempt_number: int
    fencing_token: int
    timestamp: str
    approval_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    previous_digest: bytes = field(default_factory=bytes)
    frame_digest: bytes = field(default_factory=bytes)


@dataclass
class JournalRecoveryResult:
    """Outcome of recovery scan across the journal file."""
    is_clean: bool
    records_replayed: int
    tail_state: JournalTailState
    last_valid_sequence: int
    last_valid_digest: bytes
    uncertain_hold_required: bool
    can_append: bool
    unrecovered_bytes: int = 0
    error_message: Optional[str] = None


# ============================================================================
# Custom Exceptions
# ============================================================================

class JournalError(Exception):
    """Base exception for all operation journal errors."""
    pass


class JournalLockError(JournalError):
    """Raised when the exclusive journal process lock cannot be acquired."""
    pass


class JournalCorruptedError(JournalError):
    """Raised when journal record corruption, checksum mismatch, or tamper is detected."""
    pass


class JournalUncertaintyError(JournalError):
    """Raised when an ambiguous tail could contain an in-flight dispatch marker."""
    pass


class JournalSequenceError(JournalError):
    """Raised on sequence number gaps, duplicates, or overflow beyond 2^63 - 1."""
    pass


class JournalPermissionError(JournalError):
    """Raised when journal directory, file permissions, or symlink policies are breached."""
    pass


class JournalWriteError(JournalError):
    """Raised when looping write or fsync operations fail."""
    pass


# ============================================================================
# Platform-Specific Locking & Filesystem Primitives
# ============================================================================

def _lock_file_exclusive(fd: int) -> None:
    """Acquire non-blocking exclusive process lock on file descriptor."""
    if sys.platform == "win32":
        import msvcrt
        try:
            # Ensure file pointer is at byte 0
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except (IOError, OSError) as e:
            raise JournalLockError(f"Failed to acquire exclusive lock on journal lockfile: {e}") from e
    else:
        import fcntl
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as e:
            raise JournalLockError(f"Failed to acquire exclusive lock on journal lockfile: {e}") from e


def _unlock_file(fd: int) -> None:
    """Release exclusive process lock on file descriptor."""
    if sys.platform == "win32":
        import msvcrt
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except (IOError, OSError):
            pass
    else:
        import fcntl
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except (IOError, OSError):
            pass


def _fsync_dir(dir_path: str) -> None:
    """Fsync parent directory inode entry on POSIX systems (no-op on Windows)."""
    if sys.platform == "win32":
        return
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        dir_fd = os.open(dir_path, flags)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as e:
        logger.warning("Parent directory fsync warning for '%s': %s", dir_path, str(e))


def _looping_write(fd: int, data: bytes) -> None:
    """Looping os.write() to guarantee all bytes are written to file descriptor."""
    written = 0
    total = len(data)
    while written < total:
        try:
            n = os.write(fd, data[written:])
            if n == 0:
                raise JournalWriteError("os.write returned 0 bytes written (disk full or pipe closed).")
            written += n
        except OSError as e:
            raise JournalWriteError(f"Failed writing {total - written} bytes to journal: {e}") from e


def _fsync_file(fd: int) -> None:
    """Synchronously flush in-core file state to physical storage media."""
    try:
        os.fsync(fd)
    except OSError as e:
        raise JournalWriteError(f"os.fsync failed: {e}") from e


# ============================================================================
# Cryptographic Hash Chain Computation
# ============================================================================

def compute_frame_digest(sequence: int, previous_digest: bytes, payload_bytes: bytes) -> bytes:
    """
    Compute cryptographic SHA-256 frame digest:
        digest_i = SHA256(sequence_i || previous_digest_i || payload_bytes_i)

    NOTE: This is an append-only cryptographic hash chain (linear sequence verification),
    not a Merkle tree.
    """
    hasher = hashlib.sha256()
    hasher.update(struct.pack("!Q", sequence))
    hasher.update(previous_digest)
    hasher.update(payload_bytes)
    return hasher.digest()


def serialize_payload_deterministic(
    operation_id: str,
    execution_id: str,
    workspace_id: str,
    attempt_number: int,
    fencing_token: int,
    record_type: str,
    timestamp: str,
    approval_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Serialize record payload to deterministic UTF-8 JSON.
    Applies metadata sanitization to scrub sensitive credentials or tokens.
    """
    clean_meta = sanitize_metadata(metadata or {})
    payload_dict = {
        "operation_id": operation_id,
        "execution_id": execution_id,
        "workspace_id": workspace_id,
        "approval_id": approval_id,
        "attempt_number": attempt_number,
        "fencing_token": fencing_token,
        "record_type": record_type,
        "timestamp": timestamp,
        "metadata": clean_meta,
    }
    # Deterministic JSON: sorted keys, compact separators, UTF-8 encoded
    return json.dumps(payload_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ============================================================================
# OperationJournal Class
# ============================================================================

class OperationJournal:
    """
    Durable, append-only operation journal engine.
    Guarantees monotonic sequence allocation, SHA-256 digest chaining,
    CRC32 frame integrity, single-writer process locking, and conservative
    torn-write recovery.
    """

    def __init__(
        self,
        journal_dir: str,
        journal_filename: str = "operations.journal",
        lock_filename: str = "operations.journal.lock",
        enforce_permissions: bool = True,
    ):
        self.journal_dir = os.path.abspath(journal_dir)
        self.journal_path = os.path.join(self.journal_dir, journal_filename)
        self.lock_path = os.path.join(self.journal_dir, lock_filename)
        self.enforce_permissions = enforce_permissions

        self._lock_fd: Optional[int] = None
        self._journal_fd: Optional[int] = None
        self._is_open = False
        self._is_corrupted = False
        self._can_append = False

        self._current_sequence = 0
        self._current_digest = GENESIS_DIGEST
        self._records: List[JournalRecord] = []
        self._recovery_result: Optional[JournalRecoveryResult] = None

    @property
    def current_sequence(self) -> int:
        """Return the highest valid sequence number committed to the journal."""
        return self._current_sequence

    @property
    def current_digest(self) -> bytes:
        """Return the cryptographic SHA-256 digest of the active tail."""
        return self._current_digest

    @property
    def is_clean(self) -> bool:
        """Return True only if journal is recovered and verified free of corruption."""
        return self._recovery_result is not None and self._recovery_result.is_clean and not self._is_corrupted

    @property
    def can_append(self) -> bool:
        """Return True if the journal is safely open and ready to append records."""
        return self._is_open and self._can_append and not self._is_corrupted

    # ------------------------------------------------------------------------
    # Lifecycle: Open, Lock, Recover, Close
    # ------------------------------------------------------------------------

    def open(self) -> JournalRecoveryResult:
        """
        Open the journal directory and files:
        1. Validates directory permissions and symlink policies.
        2. Acquires exclusive process lock on operations.journal.lock.
        3. Opens journal file with safe flags.
        4. Runs authoritative replay and recovery scan.
        """
        if self._is_open:
            return self._recovery_result  # type: ignore[return-value]

        # 1. Directory creation and permission validation
        if not os.path.exists(self.journal_dir):
            os.makedirs(self.journal_dir, mode=0o700, exist_ok=True)
            _fsync_dir(os.path.dirname(self.journal_dir))

        self._validate_path_security(self.journal_dir, is_dir=True)

        # 2. Acquire single-writer lock
        self._acquire_lock()

        # 3. Open journal file with safe flags
        self._validate_path_security(self.journal_path, is_dir=False)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            self._journal_fd = os.open(self.journal_path, flags, 0o600)
            _fsync_dir(self.journal_dir)
        except OSError as e:
            self._release_lock()
            raise JournalPermissionError(f"Failed opening journal file '{self.journal_path}': {e}") from e

        self._is_open = True

        # 4. Perform startup recovery scan
        recovery_result = self.recover()
        return recovery_result

    def close(self) -> None:
        """Flush, close file descriptors, and release exclusive process lock."""
        if self._journal_fd is not None:
            try:
                _fsync_file(self._journal_fd)
            except Exception:
                pass
            try:
                os.close(self._journal_fd)
            except Exception:
                pass
            self._journal_fd = None

        self._release_lock()
        self._is_open = False
        self._can_append = False

    def __enter__(self) -> "OperationJournal":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ------------------------------------------------------------------------
    # Locking & Security Helpers
    # ------------------------------------------------------------------------

    def _acquire_lock(self) -> None:
        """Acquire exclusive non-blocking OS lockfile."""
        if self._lock_fd is not None:
            return

        self._validate_path_security(self.lock_path, is_dir=False)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            self._lock_fd = os.open(self.lock_path, flags, 0o600)
            # Write at least 1 byte on Windows for msvcrt byte-range locking
            if sys.platform == "win32":
                if os.fstat(self._lock_fd).st_size == 0:
                    os.write(self._lock_fd, b"L")
            _lock_file_exclusive(self._lock_fd)
        except JournalLockError:
            if self._lock_fd is not None:
                try:
                    os.close(self._lock_fd)
                except Exception:
                    pass
                self._lock_fd = None
            raise
        except OSError as e:
            if self._lock_fd is not None:
                try:
                    os.close(self._lock_fd)
                except Exception:
                    pass
                self._lock_fd = None
            raise JournalLockError(f"Could not open/lock file '{self.lock_path}': {e}") from e

    def _release_lock(self) -> None:
        """Release lockfile and close file descriptor."""
        if self._lock_fd is not None:
            try:
                _unlock_file(self._lock_fd)
            finally:
                try:
                    os.close(self._lock_fd)
                except Exception:
                    pass
                self._lock_fd = None

    def _validate_path_security(self, target_path: str, is_dir: bool = False) -> None:
        """Validate symlink rejection and strict permission boundaries."""
        if os.path.islink(target_path):
            raise JournalPermissionError(
                f"Path '{target_path}' is a symbolic link. Symlinks are strictly prohibited."
            )

        if not self.enforce_permissions or not os.path.exists(target_path):
            return

        # On POSIX systems, check permissions
        if sys.platform != "win32":
            st = os.stat(target_path)
            mode = st.st_mode
            # Disallow world-writable files/directories
            if mode & 0o002:
                raise JournalPermissionError(
                    f"Path '{target_path}' is world-writable (mode {oct(mode)}). Permissions must be restricted."
                )

    # ------------------------------------------------------------------------
    # Recovery and Replay
    # ------------------------------------------------------------------------

    def recover(self) -> JournalRecoveryResult:
        """
        Replay journal from sequence 1 to EOF.
        Verifies:
        - Header magic bytes and payload lengths
        - CRC32 checksums
        - Sequence continuity (S_i == S_{i-1} + 1)
        - Previous digest continuity and frame SHA-256 chain
        - Conservative tail inspection for incomplete or torn writes
        """
        if not self._is_open or self._journal_fd is None:
            raise JournalError("Journal is not open.")

        self._records.clear()
        self._current_sequence = 0
        self._current_digest = GENESIS_DIGEST
        self._is_corrupted = False
        self._can_append = False

        total_size = os.fstat(self._journal_fd).st_size
        if total_size == 0:
            result = JournalRecoveryResult(
                is_clean=True,
                records_replayed=0,
                tail_state=JournalTailState.CLEAN_EOF,
                last_valid_sequence=0,
                last_valid_digest=GENESIS_DIGEST,
                uncertain_hold_required=False,
                can_append=True,
                unrecovered_bytes=0,
            )
            self._recovery_result = result
            self._can_append = True
            return result

        os.lseek(self._journal_fd, 0, os.SEEK_SET)
        offset = 0
        expected_seq = 1
        expected_prev_digest = GENESIS_DIGEST

        while offset < total_size:
            bytes_remaining = total_size - offset

            # 1. Inspect incomplete header at tail
            if bytes_remaining < HEADER_SIZE:
                trailing_bytes = os.read(self._journal_fd, bytes_remaining)
                return self._handle_trailing_torn_bytes(
                    offset=offset,
                    trailing_bytes=trailing_bytes,
                    expected_seq=expected_seq,
                    expected_prev_digest=expected_prev_digest,
                    reason="Incomplete frame header at physical tail",
                )

            # Read full header
            header_bytes = os.read(self._journal_fd, HEADER_SIZE)
            magic, seq, payload_len, prev_dig, frame_dig = struct.unpack(HEADER_FORMAT, header_bytes)

            # Validate magic
            if magic != MAGIC_BYTES:
                trailing_bytes = header_bytes + os.read(self._journal_fd, bytes_remaining - HEADER_SIZE)
                self._is_corrupted = True
                self._can_append = False
                err = f"Invalid magic bytes '{magic!r}' at sequence offset {offset}"
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=len(trailing_bytes),
                    error_message=err,
                )
                self._recovery_result = result
                return result

            # Validate payload length sanity
            if payload_len > MAX_PAYLOAD_BYTES or payload_len < 2:
                trailing_bytes = header_bytes + os.read(self._journal_fd, bytes_remaining - HEADER_SIZE)
                self._is_corrupted = True
                self._can_append = False
                err = f"Corrupted payload length {payload_len} at sequence {seq}"
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=len(trailing_bytes),
                    error_message=err,
                )
                self._recovery_result = result
                return result

            full_frame_len = HEADER_SIZE + payload_len + TRAILER_SIZE
            if bytes_remaining < full_frame_len:
                # Incomplete payload or trailer at physical tail
                partial_body = os.read(self._journal_fd, bytes_remaining - HEADER_SIZE)
                trailing_bytes = header_bytes + partial_body
                return self._handle_trailing_torn_bytes(
                    offset=offset,
                    trailing_bytes=trailing_bytes,
                    expected_seq=expected_seq,
                    expected_prev_digest=expected_prev_digest,
                    reason=f"Incomplete frame body at tail: expected {full_frame_len} bytes, found {bytes_remaining}",
                )

            # Read payload and trailer
            payload_bytes = os.read(self._journal_fd, payload_len)
            trailer_bytes = os.read(self._journal_fd, TRAILER_SIZE)
            expected_crc = struct.unpack(TRAILER_FORMAT, trailer_bytes)[0]

            # 2. Check CRC32 integrity
            body_for_crc = header_bytes + payload_bytes
            computed_crc = zlib.crc32(body_for_crc) & 0xFFFFFFFF
            if computed_crc != expected_crc:
                self._is_corrupted = True
                self._can_append = False
                err = f"CRC32 mismatch for sequence {seq}: computed {computed_crc}, expected {expected_crc}"
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=total_size - offset,
                    error_message=err,
                )
                self._recovery_result = result
                return result

            # 3. Check sequence continuity
            if seq != expected_seq:
                self._is_corrupted = True
                self._can_append = False
                err = f"Sequence continuity break at offset {offset}: expected {expected_seq}, found {seq}."
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=total_size - offset,
                    error_message=err,
                )
                self._recovery_result = result
                raise JournalSequenceError(err)

            # 4. Check previous digest continuity
            if prev_dig != expected_prev_digest:
                self._is_corrupted = True
                self._can_append = False
                err = f"Digest chain break at sequence {seq}: prev_digest does not match predecessor frame digest."
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=total_size - offset,
                    error_message=err,
                )
                self._recovery_result = result
                raise JournalCorruptedError(err)

            # 5. Check frame SHA-256 digest correctness
            computed_digest = compute_frame_digest(seq, prev_dig, payload_bytes)
            if computed_digest != frame_dig:
                self._is_corrupted = True
                self._can_append = False
                err = f"Cryptographic frame digest mismatch at sequence {seq}."
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=total_size - offset,
                    error_message=err,
                )
                self._recovery_result = result
                raise JournalCorruptedError(err)

            # 6. Parse structured JSON payload
            try:
                payload_dict = json.loads(payload_bytes.decode("utf-8"))
            except Exception as e:
                self._is_corrupted = True
                self._can_append = False
                err = f"Invalid JSON payload at sequence {seq}: {e}"
                result = JournalRecoveryResult(
                    is_clean=False,
                    records_replayed=len(self._records),
                    tail_state=JournalTailState.CORRUPTED_FRAME,
                    last_valid_sequence=self._current_sequence,
                    last_valid_digest=self._current_digest,
                    uncertain_hold_required=False,
                    can_append=False,
                    unrecovered_bytes=total_size - offset,
                    error_message=err,
                )
                self._recovery_result = result
                raise JournalCorruptedError(err) from e

            record = JournalRecord(
                sequence=seq,
                record_type=str(payload_dict.get("record_type", "")),
                operation_id=str(payload_dict.get("operation_id", "")),
                execution_id=str(payload_dict.get("execution_id", "")),
                workspace_id=str(payload_dict.get("workspace_id", "")),
                attempt_number=int(payload_dict.get("attempt_number", 0)),
                fencing_token=int(payload_dict.get("fencing_token", 0)),
                timestamp=str(payload_dict.get("timestamp", "")),
                approval_id=payload_dict.get("approval_id"),
                metadata=payload_dict.get("metadata", {}),
                previous_digest=prev_dig,
                frame_digest=frame_dig,
            )
            self._records.append(record)

            # Advance state
            self._current_sequence = seq
            self._current_digest = frame_dig
            expected_seq = seq + 1
            expected_prev_digest = frame_dig
            offset += full_frame_len

        # Clean EOF reached
        result = JournalRecoveryResult(
            is_clean=True,
            records_replayed=len(self._records),
            tail_state=JournalTailState.CLEAN_EOF,
            last_valid_sequence=self._current_sequence,
            last_valid_digest=self._current_digest,
            uncertain_hold_required=False,
            can_append=True,
            unrecovered_bytes=0,
        )
        self._recovery_result = result
        self._can_append = True
        return result

    def _handle_trailing_torn_bytes(
        self,
        offset: int,
        trailing_bytes: bytes,
        expected_seq: int,
        expected_prev_digest: bytes,
        reason: str,
    ) -> JournalRecoveryResult:
        """
        Conservative incomplete-tail handler at journal tail.
        CRITICAL SAFETY RULE:
        Treat EVERY incomplete trailing frame as ambiguous (TORN_DISPATCH_AMBIGUOUS),
        regardless of whether the currently available bytes contain a recognizable
        dispatch marker. This includes:
        - Partial header (< 80 bytes)
        - Complete header but incomplete payload
        - Complete header and payload but incomplete CRC trailer
        Sets can_append = False and uncertain_hold_required = True.
        Never silently truncates, repairs, skips, or appends after an incomplete frame.
        Never classifies an incomplete frame as a clean pre-dispatch abort.
        """
        self._is_corrupted = True
        self._can_append = False

        tail_state = JournalTailState.TORN_DISPATCH_AMBIGUOUS
        msg = (
            f"Incomplete trailing frame detected at journal tail (offset {offset}, "
            f"{len(trailing_bytes)} bytes unrecovered): {reason}. "
            f"Ambiguous tail state; fail-closed uncertainty hold required."
        )
        logger.error(msg)

        result = JournalRecoveryResult(
            is_clean=False,
            records_replayed=len(self._records),
            tail_state=tail_state,
            last_valid_sequence=self._current_sequence,
            last_valid_digest=self._current_digest,
            uncertain_hold_required=True,
            can_append=False,
            unrecovered_bytes=len(trailing_bytes),
            error_message=msg,
        )
        self._recovery_result = result
        return result

    def replay(self) -> List[JournalRecord]:
        """
        Return the complete sequential list of validated journal records.
        Raises JournalCorruptedError or JournalUncertaintyError if journal is not clean.
        """
        if not self._is_open:
            self.open()

        if self._recovery_result and not self._recovery_result.is_clean:
            if self._recovery_result.uncertain_hold_required:
                raise JournalUncertaintyError(
                    f"Replay aborted: Journal tail requires fail-closed uncertainty hold: "
                    f"{self._recovery_result.error_message}"
                )
            raise JournalCorruptedError(
                f"Replay aborted: Journal corruption detected: {self._recovery_result.error_message}"
            )

        return list(self._records)

    # ------------------------------------------------------------------------
    # Append Protocol
    # ------------------------------------------------------------------------

    def append(
        self,
        record_type: Union[JournalRecordType, str],
        operation_id: str,
        execution_id: str,
        workspace_id: str,
        attempt_number: int,
        fencing_token: int,
        approval_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> JournalRecord:
        """
        Append a new binary-framed record to the journal:
        1. Checks journal is open and in clean, appendable state.
        2. Validates monotonic sequence bounds (rejects overflow > 2^63 - 1).
        3. Deterministically serializes sanitized JSON payload.
        4. Calculates SHA-256 hash chain digest.
        5. Computes CRC32 frame checksum.
        6. Writes frame using looping os.write() and synchronous os.fsync().
        7. Advances in-memory tail state.
        """
        if not self._is_open or self._journal_fd is None:
            self.open()

        if not self._can_append or self._is_corrupted:
            if self._recovery_result and self._recovery_result.uncertain_hold_required:
                raise JournalUncertaintyError(
                    f"Cannot append to journal: Tail is in an ambiguous/uncertain dispatch state "
                    f"({self._recovery_result.tail_state.value}). Further writes forbidden."
                )
            raise JournalCorruptedError(
                f"Cannot append to journal: Journal is corrupted or unrecovered "
                f"({self._recovery_result.tail_state.value if self._recovery_result else 'NOT_RECOVERED'})."
            )

        # 1. Monotonic sequence calculation and overflow check
        next_seq = self._current_sequence + 1
        if next_seq > MAX_SEQUENCE:
            raise JournalSequenceError(
                f"Journal sequence number overflow: sequence {next_seq} exceeds "
                f"maximum 64-bit signed integer limit (2^63 - 1)."
            )

        rec_type_str = record_type.value if isinstance(record_type, JournalRecordType) else str(record_type)
        ts_str = timestamp or datetime.now(timezone.utc).isoformat()

        # 2. Deterministic JSON payload serialization
        payload_bytes = serialize_payload_deterministic(
            operation_id=operation_id,
            execution_id=execution_id,
            workspace_id=workspace_id,
            attempt_number=attempt_number,
            fencing_token=fencing_token,
            record_type=rec_type_str,
            timestamp=ts_str,
            approval_id=approval_id,
            metadata=metadata,
        )

        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise JournalWriteError(
                f"Payload size {len(payload_bytes)} exceeds maximum limit {MAX_PAYLOAD_BYTES} bytes."
            )

        # 3. Compute cryptographic SHA-256 frame digest
        prev_digest = self._current_digest
        frame_digest = compute_frame_digest(next_seq, prev_digest, payload_bytes)

        # 4. Binary framing
        header_bytes = struct.pack(
            HEADER_FORMAT,
            MAGIC_BYTES,
            next_seq,
            len(payload_bytes),
            prev_digest,
            frame_digest,
        )
        body_bytes = header_bytes + payload_bytes
        crc32_val = zlib.crc32(body_bytes) & 0xFFFFFFFF
        trailer_bytes = struct.pack(TRAILER_FORMAT, crc32_val)
        full_frame = body_bytes + trailer_bytes

        # 5. Durable looping write and fsync
        try:
            # Seek to EOF to ensure strict append positioning
            os.lseek(self._journal_fd, 0, os.SEEK_END)
            _looping_write(self._journal_fd, full_frame)
            _fsync_file(self._journal_fd)
        except JournalError:
            self._is_corrupted = True
            self._can_append = False
            raise
        except Exception as e:
            # On write or fsync failure, journal state becomes unverified
            self._is_corrupted = True
            self._can_append = False
            logger.critical("Journal write/fsync failure at sequence %d: %s", next_seq, str(e), exc_info=True)
            raise JournalWriteError(f"Journal append write/fsync failed: {e}") from e

        # 6. Update in-memory tail state
        record = JournalRecord(
            sequence=next_seq,
            record_type=rec_type_str,
            operation_id=operation_id,
            execution_id=execution_id,
            workspace_id=workspace_id,
            attempt_number=attempt_number,
            fencing_token=fencing_token,
            timestamp=ts_str,
            approval_id=approval_id,
            metadata=sanitize_metadata(metadata or {}),
            previous_digest=prev_digest,
            frame_digest=frame_digest,
        )

        self._records.append(record)
        self._current_sequence = next_seq
        self._current_digest = frame_digest

        return record
