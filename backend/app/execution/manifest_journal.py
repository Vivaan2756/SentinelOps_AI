"""Broker Persistent Replay Journal (Phase 2A.1 Stage 3).

Provides:
- BrokerManifestJournal: SQLite-backed authoritative execution replay journal.
- Persistent execution authorization tracking across broker restarts.
- Atomic claims using SQLite BEGIN IMMEDIATE transactions.
- Strict state machine: CLAIMED, EXECUTING, COMPLETED, FAILED, OUTCOME_UNKNOWN.
- Terminality enforcement for OUTCOME_UNKNOWN, COMPLETED, and FAILED.
- Strict rejection of duplicate claims, replays, or conflicting identifiers.
- Exact authorization identity binding: manifest_id, execution_id, action_id,
  authorized_origin, authorized_path, parameters_sha256, key_id, manifest_digest.
- Symlink rejection and path safety enforcement (fails closed, O_NOFOLLOW where supported).
- Fail-closed behavior on corrupted or incompatible journal storage.
- Sanitized metadata storage (zero private keys, credentials, or sensitive action parameters).
"""

from dataclasses import dataclass
from enum import Enum
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinelops.execution.manifest_journal")

DEFAULT_JOURNAL_PATH = os.environ.get(
    "SENTINELOPS_MANIFEST_JOURNAL_PATH",
    "/var/lib/sentinelops/broker/manifest_journal.db",
)

HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# Patterns to strip sensitive data from error messages
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)(bearer\s+)[^\s]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(private_key\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(cookie:\s*)[^\r\n]+"),
]


def _sanitize_message(msg: Optional[str], max_len: int = 1024) -> Optional[str]:
    """Sanitize sensitive patterns and truncate error message."""
    if msg is None:
        return None
    sanitized = msg
    for pat in SENSITIVE_PATTERNS:
        sanitized = pat.sub(r"\1[REDACTED]", sanitized)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + " ... [TRUNCATED]"
    return sanitized


# ============================================================================
# Exceptions
# ============================================================================


class JournalError(Exception):
    """Base exception for all manifest journal errors."""


class JournalUnavailableError(JournalError):
    """Raised when the journal storage is unavailable, unwritable, or corrupted."""


class JournalClaimError(JournalError):
    """Raised when a claim request is malformed or invalid."""


class JournalConflictError(JournalError):
    """Raised when a claim conflicts with an existing claim (replay or ID mismatch)."""


class JournalStateTransitionError(JournalError):
    """Raised when an invalid state transition is attempted."""


class JournalRecordNotFoundError(JournalError):
    """Raised when an operation references a non-existent manifest record."""


# ============================================================================
# State Machine & Data Models
# ============================================================================


class ExecutionState(str, Enum):
    """Authoritative execution lifecycle states in the broker replay journal."""

    CLAIMED = "CLAIMED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


# Permitted state transitions. All unlisted transitions are strictly forbidden.
PERMITTED_TRANSITIONS: Dict[ExecutionState, Set[ExecutionState]] = {
    ExecutionState.CLAIMED: {
        ExecutionState.EXECUTING,
        ExecutionState.FAILED,
        ExecutionState.OUTCOME_UNKNOWN,
    },
    ExecutionState.EXECUTING: {
        ExecutionState.COMPLETED,
        ExecutionState.FAILED,
        ExecutionState.OUTCOME_UNKNOWN,
    },
    ExecutionState.COMPLETED: set(),  # Terminal
    ExecutionState.FAILED: set(),  # Terminal
    ExecutionState.OUTCOME_UNKNOWN: set(),  # Terminal: never retried or re-transitioned
}


@dataclass(frozen=True)
class ManifestRecord:
    """Immutable snapshot of an execution claim record in the journal."""

    manifest_id: str
    execution_id: str
    action_id: str
    authorized_origin: str
    authorized_path: str
    parameters_sha256: str
    key_id: str
    manifest_digest: str
    claimed_at: int
    expires_at: int
    state: ExecutionState
    error_message: Optional[str] = None
    updated_at: int = 0


# ============================================================================
# Database Schema
# ============================================================================

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS manifest_claims (
    manifest_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE,
    action_id TEXT NOT NULL,
    authorized_origin TEXT NOT NULL,
    authorized_path TEXT NOT NULL,
    parameters_sha256 TEXT NOT NULL,
    key_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    claimed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('CLAIMED', 'EXECUTING', 'COMPLETED', 'FAILED', 'OUTCOME_UNKNOWN')),
    error_message TEXT,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_manifest_claims_execution_id ON manifest_claims(execution_id);
CREATE INDEX IF NOT EXISTS idx_manifest_claims_expires_at ON manifest_claims(expires_at);
CREATE INDEX IF NOT EXISTS idx_manifest_claims_state ON manifest_claims(state);
CREATE INDEX IF NOT EXISTS idx_manifest_claims_manifest_digest ON manifest_claims(manifest_digest);
"""

REQUIRED_COLUMNS: Set[str] = {
    "manifest_id",
    "execution_id",
    "action_id",
    "authorized_origin",
    "authorized_path",
    "parameters_sha256",
    "key_id",
    "manifest_digest",
    "claimed_at",
    "expires_at",
    "state",
    "error_message",
    "updated_at",
}


# ============================================================================
# BrokerManifestJournal Implementation
# ============================================================================


class BrokerManifestJournal:
    """
    SQLite-backed authoritative execution replay journal for the broker daemon.

    Guarantees:
    - Atomicity & Concurrency: Uses BEGIN IMMEDIATE transactions and WAL mode.
    - Replay Prevention: Manifest ID and Execution ID are globally unique.
    - Terminality: COMPLETED, FAILED, and OUTCOME_UNKNOWN states cannot be altered.
    - Crash Safety: reconcile_unresolved_claims() transitions in-flight claims to OUTCOME_UNKNOWN.
    - Fail-Closed: Refuses to reset or delete corrupted or incompatible journal files.
    - Exact Authorization Binding: manifest_id, execution_id, action_id, origin, path,
      parameters hash, key_id, manifest_digest.
    - Symlink Safety: Verifies database path and parent directory are not symbolic links.
    """

    _storage_init_lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None, timeout: float = 5.0):
        self.db_path = db_path or DEFAULT_JOURNAL_PATH
        self.timeout = timeout
        self._local = threading.local()
        self._all_conns: List[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        self._is_closed = False

        self._initialize_storage()

    def _verify_path_safety(self, path: str) -> None:
        """
        Verify that database path and parent directory are not symbolic links.
        Uses O_NOFOLLOW where supported to prevent TOCTOU symlink races.
        Fails closed if safety cannot be established.
        """
        try:
            abs_path = os.path.abspath(path)
            parent_dir = os.path.dirname(abs_path)

            # 1. Check parent directory for symlink
            if parent_dir and os.path.lexists(parent_dir) and os.path.islink(parent_dir):
                raise JournalUnavailableError(
                    f"Journal parent directory '{parent_dir}' is a symbolic link. Symlinks are prohibited."
                )

            # 2. Check target database path for symlink (including broken symlinks)
            if os.path.lexists(abs_path) and os.path.islink(abs_path):
                raise JournalUnavailableError(
                    f"Journal database path '{abs_path}' is a symbolic link. Symlinks are prohibited."
                )

            # 3. Guard against TOCTOU race condition using O_NOFOLLOW where supported (POSIX)
            if hasattr(os, "O_NOFOLLOW") and os.path.exists(abs_path):
                try:
                    fd = os.open(abs_path, os.O_RDONLY | os.O_NOFOLLOW)
                    os.close(fd)
                except OSError as e:
                    raise JournalUnavailableError(
                        f"Symlink race check failed for journal database '{abs_path}': {e}"
                    ) from e

        except JournalUnavailableError:
            raise
        except OSError as e:
            raise JournalUnavailableError(
                f"Filesystem safety check failed for '{path}': {e}"
            ) from e

    def _initialize_storage(self) -> None:
        """Validate storage path, set directory/file permissions, verify safety, and create schema."""
        with self._storage_init_lock:
            # Verify symlink safety before any filesystem access
            self._verify_path_safety(self.db_path)

            # Ensure parent directory exists
            parent_dir = os.path.dirname(os.path.abspath(self.db_path))
            if parent_dir and not os.path.exists(parent_dir):
                try:
                    os.makedirs(parent_dir, mode=0o700, exist_ok=True)
                except OSError as e:
                    raise JournalUnavailableError(
                        f"Failed to create journal directory '{parent_dir}': {e}"
                    ) from e

            # Ensure parent directory permissions (POSIX 0700) where supported
            if hasattr(os, "chmod") and os.name != "nt":
                try:
                    os.chmod(parent_dir, 0o700)
                except OSError as e:
                    logger.warning(f"Could not set mode 0700 on journal directory '{parent_dir}': {e}")

            # Check if DB file exists prior to connection
            file_existed = os.path.exists(self.db_path)

            # Connect and verify database integrity
            try:
                conn = self._get_connection()

                if file_existed:
                    # 1. Integrity check
                    try:
                        cursor = conn.execute("PRAGMA integrity_check")
                        rows = cursor.fetchall()
                        if not rows or rows[0][0] != "ok":
                            raise JournalUnavailableError(
                                f"SQLite journal database '{self.db_path}' is corrupted: {rows}"
                            )
                    except sqlite3.DatabaseError as e:
                        raise JournalUnavailableError(
                            f"SQLite journal database '{self.db_path}' is corrupted: {e}"
                        ) from e

                    # 2. Existing schema compatibility check
                    # Do not silently discard or recreate incompatible existing journal data
                    try:
                        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manifest_claims'")
                        table_exists = cursor.fetchone() is not None
                        if table_exists:
                            cursor = conn.execute("PRAGMA table_info(manifest_claims)")
                            cols = {row["name"] for row in cursor.fetchall()}
                            missing_cols = REQUIRED_COLUMNS - cols
                            if missing_cols:
                                raise JournalUnavailableError(
                                    f"Existing journal database at '{self.db_path}' has incompatible schema "
                                    f"missing required columns: {sorted(missing_cols)}. "
                                    f"Refusing to silently discard or recreate existing journal data."
                                )
                    except sqlite3.DatabaseError as e:
                        if not isinstance(e, JournalUnavailableError):
                            raise JournalUnavailableError(
                                f"Failed to inspect existing table schema at '{self.db_path}': {e}"
                            ) from e
                        raise

                # Check and enable WAL mode once during initialization if not already active
                cur = conn.execute("PRAGMA journal_mode")
                mode_row = cur.fetchone()
                if mode_row and str(mode_row[0]).lower() != "wal":
                    conn.execute("PRAGMA journal_mode = WAL")

                # Initialize schema (executescript manages its own transaction)
                conn.executescript(SCHEMA_SQL)

            except (sqlite3.DatabaseError, JournalUnavailableError) as e:
                if isinstance(e, JournalUnavailableError):
                    raise
                raise JournalUnavailableError(
                    f"Failed to initialize SQLite journal database at '{self.db_path}': {e}"
                ) from e
            except OSError as e:
                raise JournalUnavailableError(
                    f"I/O error accessing journal storage at '{self.db_path}': {e}"
                ) from e

            # Restrict permissions on journal database file (POSIX 0600) where supported
            if hasattr(os, "chmod") and os.name != "nt":
                try:
                    if os.path.exists(self.db_path):
                        os.chmod(self.db_path, 0o600)
                except OSError as e:
                    logger.warning(f"Could not set mode 0600 on journal file '{self.db_path}': {e}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create thread-local SQLite connection with WAL mode and autocommit disabled."""
        if self._is_closed:
            raise JournalUnavailableError("Journal has been closed.")

        conn = getattr(self._local, "conn", None)
        if conn is None:
            # Re-verify path safety before connecting
            self._verify_path_safety(self.db_path)

            try:
                # isolation_level=None enables explicit transaction control with BEGIN IMMEDIATE
                conn = sqlite3.connect(
                    self.db_path,
                    timeout=self.timeout,
                    isolation_level=None,
                    check_same_thread=False,
                )
                conn.row_factory = sqlite3.Row
                conn.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)}")
                conn.execute("PRAGMA synchronous = FULL")
                self._local.conn = conn

                with self._conns_lock:
                    self._all_conns.append(conn)
            except sqlite3.DatabaseError as e:
                raise JournalUnavailableError(
                    f"SQLite journal database '{self.db_path}' is corrupted or unreadable: {e}"
                ) from e
            except OSError as e:
                raise JournalUnavailableError(
                    f"Storage error connecting to journal '{self.db_path}': {e}"
                ) from e

        return conn

    def _row_to_record(self, row: sqlite3.Row) -> ManifestRecord:
        """Convert a database row to an immutable ManifestRecord."""
        return ManifestRecord(
            manifest_id=row["manifest_id"],
            execution_id=row["execution_id"],
            action_id=row["action_id"],
            authorized_origin=row["authorized_origin"],
            authorized_path=row["authorized_path"],
            parameters_sha256=row["parameters_sha256"],
            key_id=row["key_id"],
            manifest_digest=row["manifest_digest"],
            claimed_at=row["claimed_at"],
            expires_at=row["expires_at"],
            state=ExecutionState(row["state"]),
            error_message=row["error_message"],
            updated_at=row["updated_at"],
        )

    # ========================================================================
    # Core API
    # ========================================================================

    def claim_manifest(
        self,
        manifest_id: str,
        execution_id: str,
        action_id: str,
        authorized_origin: str,
        authorized_path: str,
        parameters_sha256: str,
        key_id: str,
        manifest_digest: str,
        expires_at: int,
        claimed_at: Optional[int] = None,
    ) -> ManifestRecord:
        """
        Atomically claim a verified execution manifest in the replay journal.

        Enforces:
        - Strict parameter validation (origin, path, digest, key_id, hashes).
        - Expiry check against current time.
        - Immediate exclusive locking via BEGIN IMMEDIATE.
        - Rejection of duplicate manifest IDs (replays).
        - Rejection of duplicate execution IDs (replays).
        - Rejection of mismatched ID pairs (manifest reused with different execution ID, or vice versa).
        - New claims always start in CLAIMED state; caller cannot supply initial state.
        """
        # 1. Parameter validation
        if not manifest_id or not isinstance(manifest_id, str) or not manifest_id.strip():
            raise JournalClaimError("manifest_id must be a non-empty string.")
        if not execution_id or not isinstance(execution_id, str) or not execution_id.strip():
            raise JournalClaimError("execution_id must be a non-empty string.")
        if not action_id or not isinstance(action_id, str) or not action_id.strip():
            raise JournalClaimError("action_id must be a non-empty string.")
        if not authorized_origin or not isinstance(authorized_origin, str) or not authorized_origin.strip():
            raise JournalClaimError("authorized_origin must be a non-empty string.")

        # Validate authorized_path strictly
        if not authorized_path or not isinstance(authorized_path, str) or not authorized_path.strip():
            raise JournalClaimError("authorized_path must be a non-empty string.")
        if not authorized_path.startswith("/"):
            raise JournalClaimError(f"authorized_path must start with '/': '{authorized_path}'.")
        if any(bad in authorized_path for bad in ("..", "\\", "%", "//", "?", "#")):
            raise JournalClaimError(
                f"authorized_path contains forbidden traversal or delimiters: '{authorized_path}'."
            )

        # Validate hashes
        if not parameters_sha256 or not isinstance(parameters_sha256, str) or not HEX_64_PATTERN.match(parameters_sha256):
            raise JournalClaimError("parameters_sha256 must be a 64-character lowercase hex SHA-256 digest.")

        # Validate key_id
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise JournalClaimError("key_id must be a non-empty string.")
        if len(key_id) > 64:
            raise JournalClaimError(f"key_id must be at most 64 characters, got {len(key_id)}.")

        # Validate manifest_digest
        if not manifest_digest or not isinstance(manifest_digest, str) or not HEX_64_PATTERN.match(manifest_digest):
            raise JournalClaimError("manifest_digest must be a 64-character lowercase hex SHA-256 digest.")

        # Validate timestamps
        if not isinstance(expires_at, int) or expires_at <= 0:
            raise JournalClaimError(f"expires_at must be a positive integer Unix timestamp, got {expires_at}.")

        now = int(time.time())
        claim_time = claimed_at if claimed_at is not None else now
        if not isinstance(claim_time, int) or claim_time <= 0:
            raise JournalClaimError(f"claimed_at must be a positive integer Unix timestamp, got {claim_time}.")

        if expires_at <= claim_time:
            raise JournalClaimError(
                f"Cannot claim expired manifest: expires_at ({expires_at}) <= claimed_at ({claim_time})."
            )

        conn = self._get_connection()
        try:
            # Begin immediate write transaction
            conn.execute("BEGIN IMMEDIATE")

            # 2. Check for existing claim by manifest_id
            cursor = conn.execute(
                "SELECT * FROM manifest_claims WHERE manifest_id = ?",
                (manifest_id,),
            )
            row_by_manifest = cursor.fetchone()

            # 3. Check for existing claim by execution_id
            cursor = conn.execute(
                "SELECT * FROM manifest_claims WHERE execution_id = ?",
                (execution_id,),
            )
            row_by_execution = cursor.fetchone()

            # Enforce replay and conflict rules
            if row_by_manifest is not None:
                conn.execute("ROLLBACK")
                existing = self._row_to_record(row_by_manifest)
                if existing.execution_id != execution_id:
                    raise JournalConflictError(
                        f"Manifest ID '{manifest_id}' has already been claimed for different execution ID "
                        f"'{existing.execution_id}' (attempted execution ID: '{execution_id}')."
                    )
                raise JournalConflictError(
                    f"Manifest ID '{manifest_id}' has already been claimed for execution ID "
                    f"'{execution_id}' (current state: {existing.state.value})."
                )

            if row_by_execution is not None:
                conn.execute("ROLLBACK")
                existing = self._row_to_record(row_by_execution)
                raise JournalConflictError(
                    f"Execution ID '{execution_id}' has already been claimed with different manifest ID "
                    f"'{existing.manifest_id}' (attempted manifest ID: '{manifest_id}')."
                )

            # 4. Insert new claim with hardcoded CLAIMED state
            conn.execute(
                """
                INSERT INTO manifest_claims (
                    manifest_id, execution_id, action_id, authorized_origin,
                    authorized_path, parameters_sha256, key_id, manifest_digest,
                    claimed_at, expires_at, state, error_message, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest_id,
                    execution_id,
                    action_id,
                    authorized_origin,
                    authorized_path,
                    parameters_sha256,
                    key_id,
                    manifest_digest,
                    claim_time,
                    expires_at,
                    ExecutionState.CLAIMED.value,
                    None,
                    now,
                ),
            )
            conn.execute("COMMIT")

            logger.info(
                f"Manifest claimed successfully: manifest_id={manifest_id}, execution_id={execution_id}, "
                f"action_id={action_id}, origin={authorized_origin}, path={authorized_path}"
            )

            return ManifestRecord(
                manifest_id=manifest_id,
                execution_id=execution_id,
                action_id=action_id,
                authorized_origin=authorized_origin,
                authorized_path=authorized_path,
                parameters_sha256=parameters_sha256,
                key_id=key_id,
                manifest_digest=manifest_digest,
                claimed_at=claim_time,
                expires_at=expires_at,
                state=ExecutionState.CLAIMED,
                error_message=None,
                updated_at=now,
            )

        except (JournalConflictError, JournalClaimError):
            raise
        except sqlite3.IntegrityError as e:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise JournalConflictError(
                f"Claim conflict on manifest_id '{manifest_id}' or execution_id '{execution_id}': {e}"
            ) from e
        except sqlite3.DatabaseError as e:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise JournalUnavailableError(f"Database error during claim: {e}") from e
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def _transition_state(
        self,
        manifest_id: str,
        target_state: ExecutionState,
        error_message: Optional[str] = None,
    ) -> ManifestRecord:
        """Execute atomic state transition with validation against PERMITTED_TRANSITIONS."""
        if not manifest_id or not isinstance(manifest_id, str):
            raise JournalRecordNotFoundError("manifest_id must be a non-empty string.")

        sanitized_error = _sanitize_message(error_message)
        now = int(time.time())
        conn = self._get_connection()

        try:
            conn.execute("BEGIN IMMEDIATE")

            cursor = conn.execute(
                "SELECT * FROM manifest_claims WHERE manifest_id = ?",
                (manifest_id,),
            )
            row = cursor.fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise JournalRecordNotFoundError(
                    f"No journal record found for manifest_id '{manifest_id}'."
                )

            current_state = ExecutionState(row["state"])

            # Verify permitted transition
            allowed_next = PERMITTED_TRANSITIONS.get(current_state, set())
            if target_state not in allowed_next:
                conn.execute("ROLLBACK")
                raise JournalStateTransitionError(
                    f"Illegal state transition from {current_state.value} to {target_state.value} "
                    f"for manifest_id '{manifest_id}'."
                )

            # Preserve previous error_message if new one is not specified
            new_error = sanitized_error if sanitized_error is not None else row["error_message"]

            conn.execute(
                """
                UPDATE manifest_claims
                SET state = ?, error_message = ?, updated_at = ?
                WHERE manifest_id = ?
                """,
                (target_state.value, new_error, now, manifest_id),
            )
            conn.execute("COMMIT")

            logger.info(
                f"Manifest state transitioned: manifest_id={manifest_id}, "
                f"{current_state.value} -> {target_state.value}"
            )

            return ManifestRecord(
                manifest_id=row["manifest_id"],
                execution_id=row["execution_id"],
                action_id=row["action_id"],
                authorized_origin=row["authorized_origin"],
                authorized_path=row["authorized_path"],
                parameters_sha256=row["parameters_sha256"],
                key_id=row["key_id"],
                manifest_digest=row["manifest_digest"],
                claimed_at=row["claimed_at"],
                expires_at=row["expires_at"],
                state=target_state,
                error_message=new_error,
                updated_at=now,
            )

        except (JournalRecordNotFoundError, JournalStateTransitionError):
            raise
        except sqlite3.DatabaseError as e:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise JournalUnavailableError(f"Database error during state transition: {e}") from e
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def mark_executing(self, manifest_id: str) -> ManifestRecord:
        """Transition state from CLAIMED to EXECUTING."""
        return self._transition_state(manifest_id, ExecutionState.EXECUTING)

    def mark_completed(self, manifest_id: str) -> ManifestRecord:
        """Transition state from EXECUTING to COMPLETED."""
        return self._transition_state(manifest_id, ExecutionState.COMPLETED)

    def mark_failed(self, manifest_id: str, error_message: Optional[str] = None) -> ManifestRecord:
        """Transition state from CLAIMED or EXECUTING to FAILED."""
        return self._transition_state(manifest_id, ExecutionState.FAILED, error_message=error_message)

    def mark_outcome_unknown(self, manifest_id: str, reason: Optional[str] = None) -> ManifestRecord:
        """Transition state from CLAIMED or EXECUTING to OUTCOME_UNKNOWN."""
        return self._transition_state(manifest_id, ExecutionState.OUTCOME_UNKNOWN, error_message=reason)

    def get_record(self, manifest_id: str) -> Optional[ManifestRecord]:
        """Fetch immutable record by manifest_id."""
        if not manifest_id or not isinstance(manifest_id, str):
            return None

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM manifest_claims WHERE manifest_id = ?",
                (manifest_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_record(row)
        except sqlite3.DatabaseError as e:
            raise JournalUnavailableError(f"Database error reading record: {e}") from e

    def get_record_by_execution_id(self, execution_id: str) -> Optional[ManifestRecord]:
        """Fetch immutable record by execution_id."""
        if not execution_id or not isinstance(execution_id, str):
            return None

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM manifest_claims WHERE execution_id = ?",
                (execution_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_record(row)
        except sqlite3.DatabaseError as e:
            raise JournalUnavailableError(f"Database error reading record: {e}") from e

    def reconcile_unresolved_claims(self) -> List[ManifestRecord]:
        """
        Crash recovery reconciliation.

        At broker startup or daemon initialization, finds all claims left in
        non-terminal CLAIMED or EXECUTING states (caused by an unhandled crash, power
        loss, or unexpected kill) and atomically transitions them to OUTCOME_UNKNOWN.

        Returns the list of reconciled ManifestRecord snapshots.
        """
        now = int(time.time())
        conn = self._get_connection()
        reconciled: List[ManifestRecord] = []

        try:
            conn.execute("BEGIN IMMEDIATE")

            cursor = conn.execute(
                """
                SELECT * FROM manifest_claims
                WHERE state IN ('CLAIMED', 'EXECUTING')
                """
            )
            rows = cursor.fetchall()

            for row in rows:
                manifest_id = row["manifest_id"]
                orig_state = row["state"]
                reconcile_msg = (
                    f"Broker recovery reconciliation: execution left in non-terminal state "
                    f"'{orig_state}'; marked OUTCOME_UNKNOWN"
                )

                conn.execute(
                    """
                    UPDATE manifest_claims
                    SET state = ?, error_message = ?, updated_at = ?
                    WHERE manifest_id = ?
                    """,
                    (ExecutionState.OUTCOME_UNKNOWN.value, reconcile_msg, now, manifest_id),
                )

                reconciled.append(
                    ManifestRecord(
                        manifest_id=row["manifest_id"],
                        execution_id=row["execution_id"],
                        action_id=row["action_id"],
                        authorized_origin=row["authorized_origin"],
                        authorized_path=row["authorized_path"],
                        parameters_sha256=row["parameters_sha256"],
                        key_id=row["key_id"],
                        manifest_digest=row["manifest_digest"],
                        claimed_at=row["claimed_at"],
                        expires_at=row["expires_at"],
                        state=ExecutionState.OUTCOME_UNKNOWN,
                        error_message=reconcile_msg,
                        updated_at=now,
                    )
                )

            conn.execute("COMMIT")

            if reconciled:
                logger.warning(
                    f"Reconciled {len(reconciled)} unresolved manifest claims to OUTCOME_UNKNOWN on broker startup."
                )

            return reconciled

        except sqlite3.DatabaseError as e:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise JournalUnavailableError(f"Database error during crash reconciliation: {e}") from e
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def close(self) -> None:
        """Close all open SQLite connections for this journal."""
        self._is_closed = True
        with self._conns_lock:
            for conn in self._all_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
        if hasattr(self._local, "conn"):
            self._local.conn = None
