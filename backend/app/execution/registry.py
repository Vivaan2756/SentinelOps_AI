"""Standalone SQLite Operation Registry Engine for Phase 4.3.6 Milestone E.2.

Provides a durable local registry that records operation reservations and their
dispatch states independently of PostgreSQL.

Key Architectural Guarantees:
1. SQLite WAL mode with synchronous=FULL and busy_timeout=5000ms.
2. Versioned schema with explicit migration tracking.
3. Atomic reservation via BEGIN IMMEDIATE with deterministic duplicate handling:
   - Same approval & identical data: returns existing reservation idempotently.
   - Same approval with conflicting data: raises RegistryConflictError.
   - Same (execution_id, fencing_token) with different approval: raises RegistryConflictError.
4. Strict 64-bit integer bounds [0, 2^63 - 1] matching SQLite signed INTEGER.
5. Finite-state machine enforcing valid dispatch transitions.
   - Terminal and uncertain states cannot be reset to earlier states.
6. Recursive metadata sanitization (zero passwords, tokens, or credentials persisted).
7. Standalone operation: separate durable system from the binary OperationJournal.
   (No cross-store transactions claimed or implemented).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
import sqlite3
import sys
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

logger = logging.getLogger(__name__)

# Default production-container filesystem path
DEFAULT_REGISTRY_PATH = "/var/lib/sentinelops/registry/operation_registry.db"

# Maximum signed 64-bit integer limit (2^63 - 1)
MAX_SQLITE_INT = (1 << 63) - 1

# Sensitive keys scrubbed from metadata
FORBIDDEN_METADATA_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "secret",
    "token",
    "credential",
    "api_key",
    "bearer",
    "raw_request_body",
    "target_secret",
    "auth",
}


# ============================================================================
# Operation Status & Lifecycle FSM
# ============================================================================

class OperationStatus(str, Enum):
    """Explicit lifecycle states for an operation reservation."""
    RESERVED = "RESERVED"
    DISPATCH_PREPARED = "DISPATCH_PREPARED"
    DISPATCH_ACCEPTED = "DISPATCH_ACCEPTED"
    DOCKER_CALL_STARTED = "DOCKER_CALL_STARTED"
    DOCKER_CALL_CONFIRMED = "DOCKER_CALL_CONFIRMED"
    DOCKER_CALL_COMPLETED = "DOCKER_CALL_COMPLETED"
    DISPATCH_ABORTED_PRE_DOCKER = "DISPATCH_ABORTED_PRE_DOCKER"
    DISPATCH_FAILED = "DISPATCH_FAILED"
    DISPATCH_UNCERTAIN = "DISPATCH_UNCERTAIN"


# Allowed state transitions for operation execution
ALLOWED_TRANSITIONS: Dict[OperationStatus, Set[OperationStatus]] = {
    OperationStatus.RESERVED: {
        OperationStatus.DISPATCH_PREPARED,
        OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
        OperationStatus.DISPATCH_FAILED,
        OperationStatus.DISPATCH_UNCERTAIN,
    },
    OperationStatus.DISPATCH_PREPARED: {
        OperationStatus.DISPATCH_ACCEPTED,
        OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
        OperationStatus.DISPATCH_FAILED,
        OperationStatus.DISPATCH_UNCERTAIN,
    },
    OperationStatus.DISPATCH_ACCEPTED: {
        OperationStatus.DOCKER_CALL_STARTED,
        OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
        OperationStatus.DISPATCH_FAILED,
        OperationStatus.DISPATCH_UNCERTAIN,
    },
    OperationStatus.DOCKER_CALL_STARTED: {
        OperationStatus.DOCKER_CALL_CONFIRMED,
        OperationStatus.DOCKER_CALL_COMPLETED,
        OperationStatus.DISPATCH_FAILED,
        OperationStatus.DISPATCH_UNCERTAIN,
    },
    OperationStatus.DOCKER_CALL_CONFIRMED: {
        OperationStatus.DOCKER_CALL_COMPLETED,
        OperationStatus.DISPATCH_FAILED,
        OperationStatus.DISPATCH_UNCERTAIN,
    },
    # Terminal and uncertain states cannot be transitioned out of
    OperationStatus.DOCKER_CALL_COMPLETED: set(),
    OperationStatus.DISPATCH_ABORTED_PRE_DOCKER: set(),
    OperationStatus.DISPATCH_FAILED: set(),
    OperationStatus.DISPATCH_UNCERTAIN: set(),
}

# Set of terminal and uncertain statuses that strictly block further modification
TERMINAL_STATUSES: Set[OperationStatus] = {
    OperationStatus.DOCKER_CALL_COMPLETED,
    OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
    OperationStatus.DISPATCH_FAILED,
    OperationStatus.DISPATCH_UNCERTAIN,
}


# ============================================================================
# Domain Models & Records
# ============================================================================

@dataclass(frozen=True)
class OperationRecord:
    """Immutable in-memory representation of an operation reservation."""
    operation_id: str
    execution_id: str
    workspace_id: str
    approval_id: str
    attempt_number: int
    fencing_token: int
    operation_status: OperationStatus
    created_at: str
    updated_at: str
    metadata: Dict[str, Any]


# ============================================================================
# Custom Registry Exceptions
# ============================================================================

class RegistryError(Exception):
    """Base exception for all operation registry operations."""
    pass


class RegistryValidationError(RegistryError):
    """Raised when an identifier, parameter, or numeric bound is invalid."""
    pass


class RegistryConflictError(RegistryError):
    """Raised on conflicting reservation parameters or unexpected state precondition."""
    pass


class RegistryInvalidTransitionError(RegistryError):
    """Raised when an illegal state transition or reset of terminal/uncertain state is attempted."""
    pass


class RegistryNotFoundError(RegistryError):
    """Raised when an operation_id or approval_id is not found in the registry."""
    pass


class RegistryBusyError(RegistryError):
    """Raised when SQLite database busy or locked timeout is reached."""
    pass


class RegistryUnavailableError(RegistryError):
    """Raised when the SQLite database is unavailable."""
    pass


class RegistryCorruptedError(RegistryError):
    """Raised when database corruption or malformed pages are detected."""
    pass


class RegistryPermissionError(RegistryError):
    """Raised when directory, database file permissions, or symlink policies are breached."""
    pass


class RegistryIOError(RegistryError):
    """Raised on underlying filesystem or disk I/O failure."""
    pass


# ============================================================================
# Helpers
# ============================================================================

def sanitize_registry_metadata(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively scrub credentials, authorization headers, and secrets from metadata."""
    if not data:
        return {}

    cleaned: Dict[str, Any] = {}
    for key, val in data.items():
        lower_key = str(key).lower()
        if any(forbidden in lower_key for forbidden in FORBIDDEN_METADATA_KEYS):
            cleaned[key] = "[REDACTED]"
        elif isinstance(val, dict):
            cleaned[key] = sanitize_registry_metadata(val)
        elif isinstance(val, list):
            cleaned[key] = [
                sanitize_registry_metadata(item) if isinstance(item, dict) else item
                for item in val
            ]
        else:
            cleaned[key] = val
    return cleaned


def _validate_safe_path(path: str) -> None:
    """Validate database path rejecting symbolic links and verifying safe directory paths."""
    abs_path = os.path.abspath(path)

    if os.path.islink(abs_path):
        raise RegistryPermissionError(f"Symlinked database path rejected for security: '{abs_path}'")

    # Traverse all parent directories to detect any symlinked parent components
    curr = os.path.dirname(abs_path)
    while curr and curr != os.path.dirname(curr):
        if os.path.islink(curr):
            raise RegistryPermissionError(f"Symlinked directory in database path rejected: '{curr}'")
        curr = os.path.dirname(curr)


# ============================================================================
# OperationRegistry Class
# ============================================================================

class OperationRegistry:
    """
    Durable local SQLite Operation Registry.
    Coordinates operation reservations, fencing tokens, and dispatch states
    independently of PostgreSQL and the OperationJournal.
    """

    CURRENT_SCHEMA_VERSION = 1

    def __init__(
        self,
        db_path: Optional[str] = None,
        busy_timeout_ms: int = 5000,
        enforce_path_security: bool = True,
    ):
        self.db_path = os.path.abspath(db_path or DEFAULT_REGISTRY_PATH)
        self.busy_timeout_ms = busy_timeout_ms
        self.enforce_path_security = enforce_path_security

        self._local = threading.local()
        self._is_initialized = False
        self._init_lock = threading.Lock()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Return a thread-local SQLite connection configured with mandatory durability pragmas:
        - WAL mode
        - synchronous=FULL
        - busy_timeout=5000ms
        - foreign_keys=ON
        - temp_store=MEMORY
        - autocommit mode (isolation_level=None) for explicit BEGIN IMMEDIATE control
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn

        if self.enforce_path_security:
            _validate_safe_path(self.db_path)

        parent_dir = os.path.dirname(self.db_path)
        if parent_dir:
            try:
                os.makedirs(parent_dir, exist_ok=True, mode=0o700)
            except OSError as e:
                raise RegistryIOError(f"Failed creating registry directory '{parent_dir}': {e}") from e

        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=float(self.busy_timeout_ms) / 1000.0,
                isolation_level=None,  # Autocommit mode; transactions managed via explicit SQL
                check_same_thread=True,
            )
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "busy" in err_str or "locked" in err_str:
                raise RegistryBusyError(f"SQLite connection busy: {e}") from e
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"SQLite database file is corrupted: {e}") from e
            raise RegistryIOError(f"Failed opening SQLite database at '{self.db_path}': {e}") from e
        except Exception as e:
            raise RegistryUnavailableError(f"Could not connect to SQLite database: {e}") from e

        # Configure mandatory pragmas on every new connection
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA temp_store=MEMORY")
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            conn.close()
            err_str = str(e).lower()
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption encountered while applying pragmas: {e}") from e
            if "busy" in err_str or "locked" in err_str:
                raise RegistryBusyError(f"Database busy applying pragmas: {e}") from e
            raise RegistryIOError(f"Failed applying PRAGMA configuration: {e}") from e

        self._local.conn = conn
        return conn

    # ------------------------------------------------------------------------
    # Initialization and Versioned Schema
    # ------------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Initialize database schema with version tracking.
        Applies version 1 schema and verifies integrity.
        """
        with self._init_lock:
            conn = self._get_connection()
            try:
                # 1. Quick integrity check
                cursor = conn.execute("PRAGMA quick_check")
                res = cursor.fetchone()
                if not res or res[0].lower() != "ok":
                    raise RegistryCorruptedError(f"SQLite quick_check failed: {res[0] if res else 'Unknown'}")

                # 2. Schema migrations table
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS registry_schema_version (
                        version INTEGER PRIMARY KEY,
                        applied_at TEXT NOT NULL,
                        description TEXT NOT NULL
                    )
                    """
                )

                cursor = conn.execute("SELECT MAX(version) FROM registry_schema_version")
                row = cursor.fetchone()
                current_v = row[0] if row and row[0] is not None else 0

                if current_v < 1:
                    # Apply migration 1
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS operation_reservations (
                                operation_id TEXT PRIMARY KEY,
                                execution_id TEXT NOT NULL,
                                workspace_id TEXT NOT NULL,
                                approval_id TEXT NOT NULL,
                                attempt_number INTEGER NOT NULL,
                                fencing_token INTEGER NOT NULL,
                                operation_status TEXT NOT NULL,
                                created_at TEXT NOT NULL,
                                updated_at TEXT NOT NULL,
                                metadata_json TEXT NOT NULL,
                                CONSTRAINT uq_operations_approval UNIQUE (approval_id),
                                CONSTRAINT uq_operations_execution_fencing UNIQUE (execution_id, fencing_token)
                            )
                            """
                        )
                        conn.execute(
                            "CREATE INDEX IF NOT EXISTS idx_operations_approval ON operation_reservations(approval_id)"
                        )
                        conn.execute(
                            "CREATE INDEX IF NOT EXISTS idx_operations_execution_fencing ON operation_reservations(execution_id, fencing_token)"
                        )
                        conn.execute(
                            "CREATE INDEX IF NOT EXISTS idx_operations_status ON operation_reservations(operation_status)"
                        )
                        conn.execute(
                            "CREATE INDEX IF NOT EXISTS idx_operations_workspace ON operation_reservations(workspace_id)"
                        )

                        now_iso = datetime.now(timezone.utc).isoformat()
                        conn.execute(
                            "INSERT INTO registry_schema_version (version, applied_at, description) VALUES (?, ?, ?)",
                            (1, now_iso, "Initial operation reservations schema with uniqueness constraints"),
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise

                self._is_initialized = True
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                err_str = str(e).lower()
                if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                    raise RegistryCorruptedError(f"Database corruption during initialization: {e}") from e
                if "busy" in err_str or "locked" in err_str:
                    raise RegistryBusyError(f"Database busy during initialization: {e}") from e
                raise RegistryIOError(f"Database error during initialization: {e}") from e

    def get_schema_version(self) -> int:
        """Return the current schema version applied to the database."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT MAX(version) FROM registry_schema_version")
            row = cursor.fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption: {e}") from e
            raise RegistryIOError(f"Error querying schema version: {e}") from e

    # ------------------------------------------------------------------------
    # Reservation Protocol
    # ------------------------------------------------------------------------

    def reserve_operation(
        self,
        execution_id: str,
        workspace_id: str,
        approval_id: str,
        attempt_number: int,
        fencing_token: int,
        operation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OperationRecord:
        """
        Atomically reserve an operation using BEGIN IMMEDIATE.

        Validation & Uniqueness:
        1. Validates identifiers and ensures integer bounds [0, 2^63 - 1].
        2. Recursively sanitizes metadata.
        3. Checks whether approval_id already has a reservation.
        4. Checks whether (execution_id, fencing_token) already has a reservation.
        5. Handles duplicates:
           - Same approval and identical reservation data: returns existing record idempotently.
           - Same approval with conflicting data: raises RegistryConflictError.
           - Same execution_id/fencing_token with different approval: raises RegistryConflictError.
        6. Inserts the reservation via parameterized SQL and commits before reporting success.
        """
        # 1. Validation of identifiers
        if not execution_id or not isinstance(execution_id, str) or not execution_id.strip():
            raise RegistryValidationError("execution_id must be a non-empty string.")
        if not workspace_id or not isinstance(workspace_id, str) or not workspace_id.strip():
            raise RegistryValidationError("workspace_id must be a non-empty string.")
        if not approval_id or not isinstance(approval_id, str) or not approval_id.strip():
            raise RegistryValidationError("approval_id must be a non-empty string.")

        # 2. Validation of numeric bounds (SQLite signed 64-bit integer compatibility)
        if not isinstance(attempt_number, int) or attempt_number < 0 or attempt_number > MAX_SQLITE_INT:
            raise RegistryValidationError(
                f"attempt_number must be an integer between 0 and {MAX_SQLITE_INT}. Got {attempt_number!r}."
            )
        if not isinstance(fencing_token, int) or fencing_token < 0 or fencing_token > MAX_SQLITE_INT:
            raise RegistryValidationError(
                f"fencing_token must be an integer between 0 and {MAX_SQLITE_INT}. Got {fencing_token!r}."
            )

        # 3. Operation ID generation / validation
        if operation_id is not None:
            if not isinstance(operation_id, str) or not operation_id.strip():
                raise RegistryValidationError("operation_id, if provided, must be a non-empty string.")
            op_id = operation_id.strip()
        else:
            op_id = str(uuid.uuid4())

        clean_meta = sanitize_registry_metadata(metadata)
        meta_json = json.dumps(clean_meta, sort_keys=True, separators=(",", ":"))

        conn = self._get_connection()

        # 4. Atomic transaction with BEGIN IMMEDIATE
        try:
            conn.execute("BEGIN IMMEDIATE")
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "busy" in err_str or "locked" in err_str:
                raise RegistryBusyError(f"Database busy acquiring write lock for reservation: {e}") from e
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption encountered: {e}") from e
            raise RegistryIOError(f"Failed starting immediate transaction: {e}") from e

        try:
            # Query existing reservation by approval_id
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            row_approval = cursor.fetchone()

            # Query existing reservation by (execution_id, fencing_token)
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE execution_id = ? AND fencing_token = ?
                """,
                (execution_id, fencing_token),
            )
            row_token = cursor.fetchone()

            # Deterministic conflict / duplicate evaluation
            if row_approval:
                existing = self._row_to_record(row_approval)
                # Check whether the reservation request is identical
                is_identical = (
                    existing.execution_id == execution_id
                    and existing.workspace_id == workspace_id
                    and existing.approval_id == approval_id
                    and existing.attempt_number == attempt_number
                    and existing.fencing_token == fencing_token
                )
                if is_identical:
                    # Idempotent return
                    conn.execute("COMMIT")
                    return existing

                # Conflicting approval reservation data
                raise RegistryConflictError(
                    f"Conflicting reservation for approval_id '{approval_id}': "
                    f"existing [execution_id={existing.execution_id}, token={existing.fencing_token}, attempt={existing.attempt_number}]; "
                    f"requested [execution_id={execution_id}, token={fencing_token}, attempt={attempt_number}]."
                )

            if row_token:
                existing = self._row_to_record(row_token)
                raise RegistryConflictError(
                    f"Conflicting reservation for execution_id '{execution_id}' and fencing_token {fencing_token}: "
                    f"already reserved under approval_id '{existing.approval_id}' (operation_id '{existing.operation_id}')."
                )

            # Insert new reservation (parameterized, plain INSERT - no INSERT OR REPLACE)
            now_iso = datetime.now(timezone.utc).isoformat()
            initial_status = OperationStatus.RESERVED.value

            conn.execute(
                """
                INSERT INTO operation_reservations (
                    operation_id, execution_id, workspace_id, approval_id, attempt_number,
                    fencing_token, operation_status, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    op_id,
                    execution_id,
                    workspace_id,
                    approval_id,
                    attempt_number,
                    fencing_token,
                    initial_status,
                    now_iso,
                    now_iso,
                    meta_json,
                ),
            )
            conn.execute("COMMIT")

            return OperationRecord(
                operation_id=op_id,
                execution_id=execution_id,
                workspace_id=workspace_id,
                approval_id=approval_id,
                attempt_number=attempt_number,
                fencing_token=fencing_token,
                operation_status=OperationStatus.RESERVED,
                created_at=now_iso,
                updated_at=now_iso,
                metadata=clean_meta,
            )

        except RegistryError:
            conn.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as e:
            conn.execute("ROLLBACK")
            raise RegistryConflictError(f"Database uniqueness constraint violation: {e}") from e
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            conn.execute("ROLLBACK")
            err_str = str(e).lower()
            if "busy" in err_str or "locked" in err_str:
                raise RegistryBusyError(f"Database locked during reservation: {e}") from e
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption during reservation: {e}") from e
            raise RegistryIOError(f"Operational error during reservation: {e}") from e
        except Exception as e:
            conn.execute("ROLLBACK")
            raise RegistryIOError(f"Unexpected error during operation reservation: {e}") from e

    # ------------------------------------------------------------------------
    # State Transition Protocol
    # ------------------------------------------------------------------------

    def transition_operation(
        self,
        operation_id: str,
        target_status: Union[OperationStatus, str],
        metadata: Optional[Dict[str, Any]] = None,
        expected_status: Optional[Union[OperationStatus, str]] = None,
    ) -> OperationRecord:
        """
        Transition an operation to a target lifecycle state using BEGIN IMMEDIATE.

        Rules:
        1. Operation must exist (or raises RegistryNotFoundError).
        2. If expected_status is specified, current status must match (or raises RegistryConflictError).
        3. Terminal and uncertain states cannot be transitioned out of (raises RegistryInvalidTransitionError).
        4. Target status must be in ALLOWED_TRANSITIONS[current_status] (raises RegistryInvalidTransitionError).
        5. Updates updated_at and merges sanitized metadata.
        """
        if not operation_id or not isinstance(operation_id, str):
            raise RegistryValidationError("operation_id must be a non-empty string.")

        try:
            target_enum = (
                target_status
                if isinstance(target_status, OperationStatus)
                else OperationStatus(str(target_status))
            )
        except ValueError:
            raise RegistryValidationError(f"Invalid target operation status '{target_status}'.")

        expected_enum: Optional[OperationStatus] = None
        if expected_status is not None:
            try:
                expected_enum = (
                    expected_status
                    if isinstance(expected_status, OperationStatus)
                    else OperationStatus(str(expected_status))
                )
            except ValueError:
                raise RegistryValidationError(f"Invalid expected operation status '{expected_status}'.")

        conn = self._get_connection()

        try:
            conn.execute("BEGIN IMMEDIATE")
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "busy" in err_str or "locked" in err_str:
                raise RegistryBusyError(f"Database busy acquiring write lock for transition: {e}") from e
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption encountered: {e}") from e
            raise RegistryIOError(f"Failed starting transition transaction: {e}") from e

        try:
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE operation_id = ?
                """,
                (operation_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise RegistryNotFoundError(f"Operation with ID '{operation_id}' not found.")

            current_record = self._row_to_record(row)
            current_status = current_record.operation_status

            # Precondition validation
            if expected_enum is not None and current_status != expected_enum:
                raise RegistryConflictError(
                    f"Precondition failed for operation '{operation_id}': "
                    f"expected status '{expected_enum.value}', but found '{current_status.value}'."
                )

            # Terminal / Uncertain protection rule: cannot transition out
            if current_status in TERMINAL_STATUSES:
                raise RegistryInvalidTransitionError(
                    f"Cannot transition operation '{operation_id}' out of terminal/uncertain state "
                    f"'{current_status.value}' to '{target_enum.value}'."
                )

            # Valid transition rule
            allowed = ALLOWED_TRANSITIONS.get(current_status, set())
            if target_enum not in allowed:
                raise RegistryInvalidTransitionError(
                    f"Illegal state transition for operation '{operation_id}' from "
                    f"'{current_status.value}' to '{target_enum.value}'."
                )

            # Merge and sanitize metadata
            merged_metadata = dict(current_record.metadata)
            if metadata:
                merged_metadata.update(sanitize_registry_metadata(metadata))

            now_iso = datetime.now(timezone.utc).isoformat()
            meta_json = json.dumps(merged_metadata, sort_keys=True, separators=(",", ":"))

            conn.execute(
                """
                UPDATE operation_reservations
                SET operation_status = ?, updated_at = ?, metadata_json = ?
                WHERE operation_id = ?
                """,
                (target_enum.value, now_iso, meta_json, operation_id),
            )
            conn.execute("COMMIT")

            return OperationRecord(
                operation_id=current_record.operation_id,
                execution_id=current_record.execution_id,
                workspace_id=current_record.workspace_id,
                approval_id=current_record.approval_id,
                attempt_number=current_record.attempt_number,
                fencing_token=current_record.fencing_token,
                operation_status=target_enum,
                created_at=current_record.created_at,
                updated_at=now_iso,
                metadata=merged_metadata,
            )

        except RegistryError:
            conn.execute("ROLLBACK")
            raise
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            conn.execute("ROLLBACK")
            err_str = str(e).lower()
            if "busy" in err_str or "locked" in err_str:
                raise RegistryBusyError(f"Database locked during transition: {e}") from e
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption during transition: {e}") from e
            raise RegistryIOError(f"Operational error during transition: {e}") from e
        except Exception as e:
            conn.execute("ROLLBACK")
            raise RegistryIOError(f"Unexpected error during state transition: {e}") from e

    # ------------------------------------------------------------------------
    # Query APIs
    # ------------------------------------------------------------------------

    def get_operation(self, operation_id: str) -> Optional[OperationRecord]:
        """Fetch an operation by stable UUID operation_id."""
        if not operation_id or not isinstance(operation_id, str):
            return None

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE operation_id = ?
                """,
                (operation_id,),
            )
            row = cursor.fetchone()
            return self._row_to_record(row) if row else None
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption reading operation: {e}") from e
            raise RegistryIOError(f"Error querying operation '{operation_id}': {e}") from e

    def get_by_approval(self, approval_id: str) -> Optional[OperationRecord]:
        """Fetch an operation reservation by approval_id."""
        if not approval_id or not isinstance(approval_id, str):
            return None

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            row = cursor.fetchone()
            return self._row_to_record(row) if row else None
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption reading approval: {e}") from e
            raise RegistryIOError(f"Error querying approval '{approval_id}': {e}") from e

    def get_by_execution_and_token(
        self, execution_id: str, fencing_token: int
    ) -> Optional[OperationRecord]:
        """Fetch an operation reservation by (execution_id, fencing_token)."""
        if not execution_id or not isinstance(execution_id, str) or not isinstance(fencing_token, int):
            return None

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE execution_id = ? AND fencing_token = ?
                """,
                (execution_id, fencing_token),
            )
            row = cursor.fetchone()
            return self._row_to_record(row) if row else None
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption: {e}") from e
            raise RegistryIOError(f"Error querying by execution and fencing token: {e}") from e

    def list_uncertain_operations(self) -> List[OperationRecord]:
        """List all operations currently in DISPATCH_UNCERTAIN state."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT operation_id, execution_id, workspace_id, approval_id, attempt_number,
                       fencing_token, operation_status, created_at, updated_at, metadata_json
                FROM operation_reservations
                WHERE operation_status = ?
                ORDER BY created_at ASC
                """,
                (OperationStatus.DISPATCH_UNCERTAIN.value,),
            )
            rows = cursor.fetchall()
            return [self._row_to_record(r) for r in rows]
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            err_str = str(e).lower()
            if "corrupt" in err_str or "not a database" in err_str or "malformed" in err_str:
                raise RegistryCorruptedError(f"Database corruption listing uncertain operations: {e}") from e
            raise RegistryIOError(f"Error listing uncertain operations: {e}") from e

    # ------------------------------------------------------------------------
    # Lifecycle and Cleanup
    # ------------------------------------------------------------------------

    def close(self) -> None:
        """Close thread-local connection for the calling thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def __enter__(self) -> "OperationRegistry":
        self.initialize()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------

    @staticmethod
    def _row_to_record(row: Tuple[Any, ...]) -> OperationRecord:
        """Convert a database row tuple to an immutable OperationRecord."""
        raw_meta = row[9]
        meta: Dict[str, Any] = {}
        if raw_meta:
            try:
                meta = json.loads(raw_meta)
            except Exception:
                meta = {}

        return OperationRecord(
            operation_id=str(row[0]),
            execution_id=str(row[1]),
            workspace_id=str(row[2]),
            approval_id=str(row[3]),
            attempt_number=int(row[4]),
            fencing_token=int(row[5]),
            operation_status=OperationStatus(str(row[6])),
            created_at=str(row[7]),
            updated_at=str(row[8]),
            metadata=meta,
        )
