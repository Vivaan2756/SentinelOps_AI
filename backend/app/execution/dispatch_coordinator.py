"""Standalone Dispatch Coordinator for Phase 4.3.6 Milestone E.3.2.

Coordinates local durable state transitions between:
1. OperationRegistry (Milestone E.2): SQLite local fast-coordination store.
2. OperationJournal (Milestone E.1): Append-only, tamper-evident cryptographic evidence log.

Key Architectural Guarantees:
1. Strict Write Ordering:
   - Reservation: SQLite reserved first.
   - Preparation: Journal DISPATCH_PREPARED fsynced BEFORE SQLite transitions to DISPATCH_PREPARED.
   - Dispatch Marker: Journal DOCKER_CALL_STARTED fsynced BEFORE SQLite transitions to DOCKER_CALL_STARTED.
   - Completion: Journal DOCKER_CALL_COMPLETED fsynced BEFORE SQLite transitions to DOCKER_CALL_COMPLETED.
   - Failure/Uncertainty: Journal updated before SQLite where writable.
2. Conservative Forward Reconciliation:
   - Replays journal in strict monotonic sequence order.
   - Synchronizes SQLite registry forward only; never downgrades state.
   - Fails closed if journal is corrupted or in an uncertainty hold.
   - Never infers clean pre-dispatch abort from the mere absence of DOCKER_CALL_STARTED.
3. Separation of Concerns:
   - Purely local host coordination. Zero Docker calls, zero PostgreSQL writes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.execution.journal import (
    JournalCorruptedError,
    JournalError,
    JournalLockError,
    JournalRecord,
    JournalRecordType,
    JournalTailState,
    JournalUncertaintyError,
    OperationJournal,
)
from app.execution.registry import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATUSES,
    OperationRecord,
    OperationRegistry,
    OperationStatus,
    RegistryBusyError,
    RegistryConflictError,
    RegistryCorruptedError,
    RegistryError,
    RegistryInvalidTransitionError,
    RegistryNotFoundError,
    RegistryValidationError,
    sanitize_registry_metadata,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Coordinator Custom Exceptions
# ============================================================================

class CoordinatorError(Exception):
    """Base exception for all dispatch coordinator errors."""
    pass


class CoordinatorValidationError(CoordinatorError):
    """Raised when request parameters, IDs, or tokens are invalid."""
    pass


class CoordinatorConflictError(CoordinatorError):
    """Raised when request identity or fencing token conflicts with registry state."""
    pass


class CoordinatorInvalidStateError(CoordinatorError):
    """Raised when an operation is not in the required state for a transition."""
    pass


class CoordinatorUncertaintyError(CoordinatorError):
    """Raised when the journal tail is in an ambiguous or uncertain dispatch state."""
    pass


class CoordinatorReconciliationError(CoordinatorError):
    """Raised when journal-to-registry reconciliation fails or encounters corruption."""
    pass


# ============================================================================
# Pre-Dispatch Recovery & Absence Proof Models (Revision 10)
# ============================================================================

class PreDispatchState(str, Enum):
    """Explicit pre-dispatch recovery state for an operation."""
    SYNCHRONIZED = "SYNCHRONIZED"
    UNRESOLVED_RESERVED = "UNRESOLVED_RESERVED"
    UNRESOLVED_PREPARED = "UNRESOLVED_PREPARED"
    UNCERTAINTY_HOLD = "UNCERTAINTY_HOLD"
    PROVED_CLEAN_ABORT = "PROVED_CLEAN_ABORT"


class AbsenceProofCondition(str, Enum):
    """The six mandatory conditions of the Revision 10 Absence Proof."""
    AUTHORITATIVE_JOURNAL = "authoritative_journal"
    COMPLETE_LINEAGE = "complete_lineage"
    EXCLUSIVE_SOCKET_OWNERSHIP = "exclusive_socket_ownership"
    NO_ALTERNATE_ACCESS = "no_alternate_access"
    NO_SURVIVING_DISPATCHER = "no_surviving_dispatcher"
    REGISTRY_JOURNAL_SYNCED = "registry_journal_synced"


ALL_PROOF_CONDITIONS: Tuple[AbsenceProofCondition, ...] = (
    AbsenceProofCondition.AUTHORITATIVE_JOURNAL,
    AbsenceProofCondition.COMPLETE_LINEAGE,
    AbsenceProofCondition.EXCLUSIVE_SOCKET_OWNERSHIP,
    AbsenceProofCondition.NO_ALTERNATE_ACCESS,
    AbsenceProofCondition.NO_SURVIVING_DISPATCHER,
    AbsenceProofCondition.REGISTRY_JOURNAL_SYNCED,
)


@dataclass(frozen=True)
class AbsenceProofWitness:
    """Witness inputs for the six-condition Revision 10 absence proof.

    The absence of DOCKER_CALL_STARTED proves that Docker was never invoked
    if and only if ALL SIX conditions are simultaneously verified True:
    1. authoritative_journal: Exactly one single-writer authoritative journal.
    2. complete_lineage: Sequence 1 to tail verified, no gaps, no torn frames.
    3. exclusive_socket_ownership: Only authorized dispatcher holds Docker socket FDs.
    4. no_alternate_access: No alternate TCP/TLS, SSH, CLI, or root container access.
    5. no_surviving_dispatcher: No surviving old dispatcher process from prior epochs.
    6. registry_journal_synced: SQLite registry and journal are synchronized.

    If ANY condition is None (unknown/unavailable), False, or corrupt:
    the proof fails closed into an uncertainty hold.
    """
    authoritative_journal: Optional[bool] = None
    complete_lineage: Optional[bool] = None
    exclusive_socket_ownership: Optional[bool] = None
    no_alternate_access: Optional[bool] = None
    no_surviving_dispatcher: Optional[bool] = None
    registry_journal_synced: Optional[bool] = None

    def evaluate(self) -> Tuple[bool, List[str]]:
        """Return (is_proven, list_of_missing_or_failed_conditions)."""
        missing_or_failed: List[str] = []
        checks = {
            AbsenceProofCondition.AUTHORITATIVE_JOURNAL.value: self.authoritative_journal,
            AbsenceProofCondition.COMPLETE_LINEAGE.value: self.complete_lineage,
            AbsenceProofCondition.EXCLUSIVE_SOCKET_OWNERSHIP.value: self.exclusive_socket_ownership,
            AbsenceProofCondition.NO_ALTERNATE_ACCESS.value: self.no_alternate_access,
            AbsenceProofCondition.NO_SURVIVING_DISPATCHER.value: self.no_surviving_dispatcher,
            AbsenceProofCondition.REGISTRY_JOURNAL_SYNCED.value: self.registry_journal_synced,
        }
        for cond, val in checks.items():
            if val is not True:
                missing_or_failed.append(cond)
        return (len(missing_or_failed) == 0, missing_or_failed)


@dataclass(frozen=True)
class PreDispatchResolution:
    """Explicit resolution of an operation during pre-dispatch recovery."""
    operation_id: str
    state: PreDispatchState
    operation_status: OperationStatus
    requires_reconciliation: bool
    can_auto_resume: bool = False
    can_auto_redispatch: bool = False
    is_safe_abort: bool = False
    missing_proof_conditions: Tuple[str, ...] = ()
    details: str = ""


# ============================================================================
# Reconciliation Data Models
# ============================================================================

@dataclass(frozen=True)
class ReconciliationSummary:
    """Summary outcome of journal-to-registry forward synchronization."""
    records_replayed: int
    operations_scanned: int
    operations_advanced: int
    operations_already_synchronized: int
    is_clean: bool
    unresolved_operations: Tuple[str, ...] = ()
    unresolved_details: Dict[str, PreDispatchState] = field(default_factory=dict)


# ============================================================================
# DispatchCoordinator Implementation
# ============================================================================

class DispatchCoordinator:
    """
    Standalone coordinator enforcing durable write ordering and reconciliation
    across the SQLite OperationRegistry and the append-only OperationJournal.
    """

    def __init__(
        self,
        registry: OperationRegistry,
        journal: OperationJournal,
    ):
        self.registry = registry
        self.journal = journal

    def initialize(self) -> None:
        """Initialize both underlying registry and journal engines."""
        self.registry.initialize()
        self.journal.open()

    # ------------------------------------------------------------------------
    # 1. Reservation Protocol
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
        Step 1 in dispatch workflow:
        Reserve operation in SQLite registry using BEGIN IMMEDIATE.
        - Identical reservations are returned idempotently.
        - Conflicting reservations raise RegistryConflictError.
        """
        return self.registry.reserve_operation(
            execution_id=execution_id,
            workspace_id=workspace_id,
            approval_id=approval_id,
            attempt_number=attempt_number,
            fencing_token=fencing_token,
            operation_id=operation_id,
            metadata=metadata,
        )

    # ------------------------------------------------------------------------
    # 2. Preparation Protocol
    # ------------------------------------------------------------------------

    def prepare_dispatch(
        self,
        operation_id: str,
        execution_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[JournalRecord, OperationRecord]:
        """
        Step 2 in dispatch workflow:
        1. Validate operation exists in registry and is currently in RESERVED state.
        2. Validate identity fields if supplied.
        3. Append DISPATCH_PREPARED to the journal and await fsync completion.
        4. ONLY THEN transition SQLite registry to DISPATCH_PREPARED.
        """
        op = self._get_and_validate_operation(
            operation_id=operation_id,
            execution_id=execution_id,
            fencing_token=fencing_token,
            workspace_id=workspace_id,
        )

        if op.operation_status != OperationStatus.RESERVED:
            raise CoordinatorInvalidStateError(
                f"Cannot prepare dispatch: operation '{operation_id}' is in status "
                f"'{op.operation_status.value}', expected '{OperationStatus.RESERVED.value}'."
            )

        merged_meta = dict(op.metadata)
        if metadata:
            merged_meta.update(metadata)

        # 1. Append to journal first (with looping write and os.fsync)
        try:
            j_rec = self.journal.append(
                record_type=JournalRecordType.DISPATCH_PREPARED,
                operation_id=op.operation_id,
                execution_id=op.execution_id,
                workspace_id=op.workspace_id,
                attempt_number=op.attempt_number,
                fencing_token=op.fencing_token,
                approval_id=op.approval_id,
                metadata=merged_meta,
            )
        except (JournalUncertaintyError, JournalCorruptedError) as e:
            raise CoordinatorUncertaintyError(f"Journal append rejected: {e}") from e
        except JournalError as e:
            raise CoordinatorError(f"Journal append failed: {e}") from e

        # 2. Only after journal fsync succeeds, advance SQLite
        reg_rec = self.registry.transition_operation(
            operation_id=op.operation_id,
            target_status=OperationStatus.DISPATCH_PREPARED,
            expected_status=OperationStatus.RESERVED,
            metadata=merged_meta,
        )

        return j_rec, reg_rec

    # ------------------------------------------------------------------------
    # 3. Dispatch-Start Marker Protocol
    # ------------------------------------------------------------------------

    def record_docker_call_started(
        self,
        operation_id: str,
        execution_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[JournalRecord, OperationRecord]:
        """
        Step 3 in dispatch workflow (Immediately prior to invoking Docker API):
        1. Require operation to be in the prepared state (DISPATCH_PREPARED or DISPATCH_ACCEPTED).
        2. Append DOCKER_CALL_STARTED to the journal and await fsync completion.
        3. ONLY THEN transition SQLite registry to DOCKER_CALL_STARTED.

        IMPORTANT: This records the physical boundary. It does not invoke Docker.
        """
        op = self._get_and_validate_operation(
            operation_id=operation_id,
            execution_id=execution_id,
            fencing_token=fencing_token,
            workspace_id=workspace_id,
        )

        if op.operation_status not in (
            OperationStatus.DISPATCH_PREPARED,
            OperationStatus.DISPATCH_ACCEPTED,
        ):
            raise CoordinatorInvalidStateError(
                f"Cannot record dispatch start: operation '{operation_id}' is in status "
                f"'{op.operation_status.value}', expected DISPATCH_PREPARED or DISPATCH_ACCEPTED."
            )

        merged_meta = dict(op.metadata)
        if metadata:
            merged_meta.update(metadata)

        # 1. Append DOCKER_CALL_STARTED to journal first (with looping write and os.fsync)
        try:
            j_rec = self.journal.append(
                record_type=JournalRecordType.DOCKER_CALL_STARTED,
                operation_id=op.operation_id,
                execution_id=op.execution_id,
                workspace_id=op.workspace_id,
                attempt_number=op.attempt_number,
                fencing_token=op.fencing_token,
                approval_id=op.approval_id,
                metadata=merged_meta,
            )
        except (JournalUncertaintyError, JournalCorruptedError) as e:
            raise CoordinatorUncertaintyError(f"Journal append rejected: {e}") from e
        except JournalError as e:
            raise CoordinatorError(f"Journal append failed: {e}") from e

        # 2. Only after journal fsync succeeds, advance SQLite to DOCKER_CALL_STARTED
        # If in DISPATCH_PREPARED, step through DISPATCH_ACCEPTED to satisfy registry FSM
        if op.operation_status == OperationStatus.DISPATCH_PREPARED:
            self.registry.transition_operation(
                operation_id=op.operation_id,
                target_status=OperationStatus.DISPATCH_ACCEPTED,
                expected_status=OperationStatus.DISPATCH_PREPARED,
            )

        reg_rec = self.registry.transition_operation(
            operation_id=op.operation_id,
            target_status=OperationStatus.DOCKER_CALL_STARTED,
            expected_status=OperationStatus.DISPATCH_ACCEPTED,
            metadata=merged_meta,
        )

        return j_rec, reg_rec

    # ------------------------------------------------------------------------
    # 4. Completion Protocol
    # ------------------------------------------------------------------------

    def complete_dispatch(
        self,
        operation_id: str,
        exit_code: int,
        duration_ms: Optional[int] = None,
        output_data: Optional[Dict[str, Any]] = None,
        stdout_sample: Optional[str] = None,
        stderr_sample: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[JournalRecord, OperationRecord]:
        """
        Step 4 in dispatch workflow (Upon container exit):
        1. Require operation to be in DOCKER_CALL_STARTED or DOCKER_CALL_CONFIRMED.
        2. Append DOCKER_CALL_COMPLETED to the journal with actual outcome & metadata.
        3. Await fsync completion.
        4. Transition SQLite registry to DOCKER_CALL_COMPLETED.

        NOTE: DOCKER_CALL_COMPLETED indicates the Docker call finished.
        It preserves the exit code and does NOT imply remediation succeeded.
        """
        op = self.registry.get_operation(operation_id)
        if not op:
            raise CoordinatorValidationError(f"Operation '{operation_id}' not found in registry.")

        if op.operation_status not in (
            OperationStatus.DOCKER_CALL_STARTED,
            OperationStatus.DOCKER_CALL_CONFIRMED,
        ):
            raise CoordinatorInvalidStateError(
                f"Cannot complete dispatch: operation '{operation_id}' is in status "
                f"'{op.operation_status.value}', expected DOCKER_CALL_STARTED or DOCKER_CALL_CONFIRMED."
            )

        outcome_meta: Dict[str, Any] = {
            "exit_code": exit_code,
            "duration_ms": duration_ms if duration_ms is not None else 0,
            "stdout_sample": stdout_sample or "",
            "stderr_sample": stderr_sample or "",
        }
        if output_data is not None:
            outcome_meta["output_data"] = output_data
        if metadata:
            outcome_meta.update(metadata)

        # 1. Append DOCKER_CALL_COMPLETED to journal first
        try:
            j_rec = self.journal.append(
                record_type=JournalRecordType.DOCKER_CALL_COMPLETED,
                operation_id=op.operation_id,
                execution_id=op.execution_id,
                workspace_id=op.workspace_id,
                attempt_number=op.attempt_number,
                fencing_token=op.fencing_token,
                approval_id=op.approval_id,
                metadata=outcome_meta,
            )
        except (JournalUncertaintyError, JournalCorruptedError) as e:
            raise CoordinatorUncertaintyError(f"Journal append rejected: {e}") from e
        except JournalError as e:
            raise CoordinatorError(f"Journal append failed: {e}") from e

        # 2. Transition SQLite to DOCKER_CALL_COMPLETED
        reg_rec = self.registry.transition_operation(
            operation_id=op.operation_id,
            target_status=OperationStatus.DOCKER_CALL_COMPLETED,
            metadata=outcome_meta,
        )

        return j_rec, reg_rec

    # ------------------------------------------------------------------------
    # 5. Failure and Uncertainty Protocols
    # ------------------------------------------------------------------------

    def record_dispatch_failure(
        self,
        operation_id: str,
        error_message: str,
        error_category: Optional[str] = None,
        exit_code: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[JournalRecord, OperationRecord]:
        """
        Record a definite dispatch failure:
        1. Operation must not be in a terminal/uncertain state.
        2. Append DISPATCH_FAILED to journal.
        3. Transition SQLite registry to DISPATCH_FAILED.
        """
        op = self.registry.get_operation(operation_id)
        if not op:
            raise CoordinatorValidationError(f"Operation '{operation_id}' not found in registry.")

        if op.operation_status in TERMINAL_STATUSES:
            raise CoordinatorInvalidStateError(
                f"Cannot fail dispatch: operation '{operation_id}' is already in terminal/uncertain status "
                f"'{op.operation_status.value}'."
            )

        fail_meta: Dict[str, Any] = {
            "error_message": error_message,
            "error_category": error_category or "dispatch_failure",
            "exit_code": exit_code if exit_code is not None else 1,
        }
        if metadata:
            fail_meta.update(metadata)

        try:
            j_rec = self.journal.append(
                record_type=JournalRecordType.DISPATCH_FAILED,
                operation_id=op.operation_id,
                execution_id=op.execution_id,
                workspace_id=op.workspace_id,
                attempt_number=op.attempt_number,
                fencing_token=op.fencing_token,
                approval_id=op.approval_id,
                metadata=fail_meta,
            )
        except (JournalUncertaintyError, JournalCorruptedError) as e:
            raise CoordinatorUncertaintyError(f"Journal append rejected: {e}") from e
        except JournalError as e:
            raise CoordinatorError(f"Journal append failed: {e}") from e

        reg_rec = self.registry.transition_operation(
            operation_id=op.operation_id,
            target_status=OperationStatus.DISPATCH_FAILED,
            metadata=fail_meta,
        )

        return j_rec, reg_rec

    def record_dispatch_uncertain(
        self,
        operation_id: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[JournalRecord], OperationRecord]:
        """
        Record an ambiguous or uncertain dispatch outcome:
        1. Operation must not be in a terminal/uncertain state.
        2. If journal remains clean and writable, append DISPATCH_UNCERTAIN.
        3. Transition SQLite registry to DISPATCH_UNCERTAIN.
        """
        op = self.registry.get_operation(operation_id)
        if not op:
            raise CoordinatorValidationError(f"Operation '{operation_id}' not found in registry.")

        if op.operation_status in TERMINAL_STATUSES:
            raise CoordinatorInvalidStateError(
                f"Cannot set uncertain: operation '{operation_id}' is already in terminal/uncertain status "
                f"'{op.operation_status.value}'."
            )

        unc_meta: Dict[str, Any] = {
            "uncertain_reason": reason,
        }
        if metadata:
            unc_meta.update(metadata)

        j_rec: Optional[JournalRecord] = None
        if self.journal.can_append:
            try:
                j_rec = self.journal.append(
                    record_type=JournalRecordType.DISPATCH_UNCERTAIN,
                    operation_id=op.operation_id,
                    execution_id=op.execution_id,
                    workspace_id=op.workspace_id,
                    attempt_number=op.attempt_number,
                    fencing_token=op.fencing_token,
                    approval_id=op.approval_id,
                    metadata=unc_meta,
                )
            except Exception as e:
                logger.warning("Could not append DISPATCH_UNCERTAIN to journal: %s", e)

        reg_rec = self.registry.transition_operation(
            operation_id=op.operation_id,
            target_status=OperationStatus.DISPATCH_UNCERTAIN,
            metadata=unc_meta,
        )

        return j_rec, reg_rec

    # ------------------------------------------------------------------------
    # 6. Journal-to-Registry Reconciliation Protocol
    # ------------------------------------------------------------------------

    def reconcile_from_journal(self) -> ReconciliationSummary:
        """
        Conservative forward synchronization from OperationJournal into OperationRegistry.

        Rules:
        1. Validates the journal completely via replay(). If the journal tail is incomplete,
           torn, or corrupted, fails closed immediately with CoordinatorReconciliationError.
        2. Validates identity fields (approval_id, execution_id, workspace_id, attempt, token).
        3. Replays records in strictly ascending monotonic sequence order.
        4. Applies valid forward state transitions to SQLite; never downgrades state.
        5. Never invents missing events.
        6. Critical Absence Rule: Does not classify an operation as safely pre-dispatch
           merely because no DOCKER_CALL_STARTED record exists. Incomplete operations
           remain in their durable state without automatic assumption of non-dispatch.
        """
        try:
            journal_records = self.journal.replay()
        except (JournalUncertaintyError, JournalCorruptedError) as e:
            logger.error("Reconciliation blocked by journal uncertainty or corruption: %s", e)
            raise CoordinatorReconciliationError(
                f"Journal replay failed due to corruption or uncertainty hold: {e}"
            ) from e
        except Exception as e:
            raise CoordinatorReconciliationError(f"Unexpected journal replay failure: {e}") from e

        records_processed = 0
        advanced_op_ids: Set[str] = set()
        scanned_op_ids: Set[str] = set()

        for record in journal_records:
            records_processed += 1
            op_id = record.operation_id
            scanned_op_ids.add(op_id)

            reg_op = self.registry.get_operation(op_id)
            if reg_op is None:
                # Reconstruct initial reservation in SQLite matching exact journal parameters
                reg_op = self.registry.reserve_operation(
                    execution_id=record.execution_id,
                    workspace_id=record.workspace_id,
                    approval_id=record.approval_id,
                    attempt_number=record.attempt_number,
                    fencing_token=record.fencing_token,
                    operation_id=op_id,
                    metadata=record.metadata,
                )
                advanced_op_ids.add(op_id)

            # Identity consistency check
            if (
                reg_op.execution_id != record.execution_id
                or reg_op.workspace_id != record.workspace_id
                or reg_op.approval_id != record.approval_id
                or reg_op.attempt_number != record.attempt_number
                or reg_op.fencing_token != record.fencing_token
            ):
                raise CoordinatorConflictError(
                    f"Journal record sequence {record.sequence} has conflicting identity for "
                    f"operation '{op_id}': registry=[exec={reg_op.execution_id}, token={reg_op.fencing_token}], "
                    f"journal=[exec={record.execution_id}, token={record.fencing_token}]."
                )

            # Map journal record_type to target OperationStatus
            target_status = self._map_record_type_to_status(record.record_type)
            if target_status is None:
                continue

            current_status = reg_op.operation_status
            if current_status == target_status:
                continue

            # Forward transition check
            if self._is_forward_transition(current_status, target_status):
                self._apply_forward_transition(op_id, current_status, target_status, record.metadata)
                advanced_op_ids.add(op_id)
            else:
                # Never downgrade registry state
                pass

        operations_advanced = len(advanced_op_ids)
        operations_already_sync = len(scanned_op_ids - advanced_op_ids)

        # Collect operations present in SQLite to detect pre-dispatch / SQLite-only reservations
        conn = self.registry._get_connection()
        cursor = conn.execute(
            "SELECT operation_id, operation_status, fencing_token, execution_id FROM operation_reservations"
        )
        registry_rows = cursor.fetchall()

        unresolved_ops: List[str] = []
        unresolved_details: Dict[str, PreDispatchState] = {}

        # Track latest journal record per operation
        op_latest_journal_rec: Dict[str, JournalRecord] = {}
        for rec in journal_records:
            op_latest_journal_rec[rec.operation_id] = rec

        for row in registry_rows:
            r_op_id = row[0]
            r_status = OperationStatus(row[1])

            # Case 1: SQLite contains RESERVED but journal has no record for this operation
            if r_status == OperationStatus.RESERVED and r_op_id not in scanned_op_ids:
                # Do not automatically resume dispatch.
                # Do not automatically classify as safe abort.
                # Preserve the reservation in RESERVED.
                # Return explicit unresolved/pre-dispatch state requiring reconciliation.
                unresolved_ops.append(r_op_id)
                unresolved_details[r_op_id] = PreDispatchState.UNRESOLVED_RESERVED

            # Case 2: DISPATCH_PREPARED without DOCKER_CALL_STARTED
            elif r_op_id in scanned_op_ids:
                latest_rec = op_latest_journal_rec.get(r_op_id)
                if latest_rec and latest_rec.record_type in (
                    JournalRecordType.DISPATCH_PREPARED.value,
                    JournalRecordType.DISPATCH_ACCEPTED.value,
                ):
                    # Incomplete operation: prepared in journal/SQLite, but no start marker.
                    # Do not automatically resume or redispatch.
                    # Do not infer that Docker was never contacted.
                    # Preserve operation in prepared state; absence proof required.
                    unresolved_ops.append(r_op_id)
                    unresolved_details[r_op_id] = PreDispatchState.UNRESOLVED_PREPARED
                elif r_status == OperationStatus.DISPATCH_UNCERTAIN:
                    unresolved_ops.append(r_op_id)
                    unresolved_details[r_op_id] = PreDispatchState.UNCERTAINTY_HOLD
            elif r_status == OperationStatus.DISPATCH_UNCERTAIN:
                unresolved_ops.append(r_op_id)
                unresolved_details[r_op_id] = PreDispatchState.UNCERTAINTY_HOLD

        return ReconciliationSummary(
            records_replayed=records_processed,
            operations_scanned=len(scanned_op_ids),
            operations_advanced=operations_advanced,
            operations_already_synchronized=operations_already_sync,
            is_clean=True,
            unresolved_operations=tuple(unresolved_ops),
            unresolved_details=unresolved_details,
        )

    # ------------------------------------------------------------------------
    # 7. Pre-Dispatch Recovery & Absence Proof Evaluation (Revision 10)
    # ------------------------------------------------------------------------

    def evaluate_pre_dispatch_state(
        self,
        operation_id: str,
        proof_witness: Optional[AbsenceProofWitness] = None,
    ) -> PreDispatchResolution:
        """
        Evaluate the pre-dispatch recovery state of an operation under Revision 10 rules.

        Enforces:
        1. RESERVED operation with empty journal is explicit UNRESOLVED_RESERVED:
           - Never auto-resumes dispatch.
           - Never auto-aborts.
           - Preserves reservation.
           - Requires explicit reconciliation.
        2. DISPATCH_PREPARED without DOCKER_CALL_STARTED is UNRESOLVED_PREPARED:
           - Never auto-resumes or redispatches.
           - Does not infer non-invocation without the complete 6-condition proof.
           - Exposes unresolved state if physical proof is unavailable.
        3. Six-Condition Proof Boundary:
           - E.3.2 does not implement or claim complete physical absence proof (conditions 3, 4, 5).
           - Missing, unknown, or corrupt conditions fail closed into UNCERTAINTY_HOLD.
        """
        op = self.registry.get_operation(operation_id)
        if not op:
            raise CoordinatorValidationError(f"Operation '{operation_id}' not found in registry.")

        # Replay journal to inspect records for this operation
        try:
            journal_records = self.journal.replay()
        except (JournalUncertaintyError, JournalCorruptedError) as e:
            return PreDispatchResolution(
                operation_id=operation_id,
                state=PreDispatchState.UNCERTAINTY_HOLD,
                operation_status=op.operation_status,
                requires_reconciliation=True,
                can_auto_resume=False,
                can_auto_redispatch=False,
                is_safe_abort=False,
                missing_proof_conditions=tuple(c.value for c in ALL_PROOF_CONDITIONS),
                details=f"Journal replay failed due to corruption or uncertainty hold: {e}",
            )

        op_records = [r for r in journal_records if r.operation_id == operation_id]

        # 1. Operation is RESERVED in SQLite and absent in journal
        if op.operation_status == OperationStatus.RESERVED and not op_records:
            return PreDispatchResolution(
                operation_id=operation_id,
                state=PreDispatchState.UNRESOLVED_RESERVED,
                operation_status=OperationStatus.RESERVED,
                requires_reconciliation=True,
                can_auto_resume=False,
                can_auto_redispatch=False,
                is_safe_abort=False,
                missing_proof_conditions=(),
                details=(
                    "Operation is RESERVED in SQLite but absent from journal. "
                    "Cannot automatically resume dispatch or classify as safe abort. "
                    "Reservation is preserved; requires explicit reconciliation."
                ),
            )

        # 2. Operation has DISPATCH_PREPARED / DISPATCH_ACCEPTED without DOCKER_CALL_STARTED
        latest_record_type = op_records[-1].record_type if op_records else None
        has_started_marker = any(
            r.record_type == JournalRecordType.DOCKER_CALL_STARTED.value for r in op_records
        )

        if (
            op.operation_status in (OperationStatus.DISPATCH_PREPARED, OperationStatus.DISPATCH_ACCEPTED)
            or latest_record_type in (JournalRecordType.DISPATCH_PREPARED.value, JournalRecordType.DISPATCH_ACCEPTED.value)
        ) and not has_started_marker:
            # Check 6-condition absence proof
            if proof_witness is None:
                # E.3.2 physical absence proof is unavailable
                return PreDispatchResolution(
                    operation_id=operation_id,
                    state=PreDispatchState.UNRESOLVED_PREPARED,
                    operation_status=op.operation_status,
                    requires_reconciliation=True,
                    can_auto_resume=False,
                    can_auto_redispatch=False,
                    is_safe_abort=False,
                    missing_proof_conditions=tuple(c.value for c in ALL_PROOF_CONDITIONS),
                    details=(
                        "Operation is DISPATCH_PREPARED without DOCKER_CALL_STARTED. "
                        "Absence of start marker does not prove non-invocation. "
                        "Complete six-condition Revision 10 proof is unavailable in E.3.2."
                    ),
                )

            # Evaluate witness conditions
            # Check local coordinator conditions if not explicitly overridden
            c1_val = proof_witness.authoritative_journal
            if c1_val is None:
                c1_val = self.journal.is_open and self.journal.is_locked and not self.journal.is_corrupted

            c2_val = proof_witness.complete_lineage
            if c2_val is None:
                c2_val = self.journal.can_append and not self.journal.is_corrupted

            c6_val = proof_witness.registry_journal_synced
            if c6_val is None:
                c6_val = (
                    op.operation_status in (OperationStatus.DISPATCH_PREPARED, OperationStatus.DISPATCH_ACCEPTED)
                    and latest_record_type in (JournalRecordType.DISPATCH_PREPARED.value, JournalRecordType.DISPATCH_ACCEPTED.value)
                )

            # Conditions 3, 4, 5 are physical and cannot be inferred by E.3.2
            c3_val = proof_witness.exclusive_socket_ownership
            c4_val = proof_witness.no_alternate_access
            c5_val = proof_witness.no_surviving_dispatcher

            evaluated_witness = AbsenceProofWitness(
                authoritative_journal=c1_val,
                complete_lineage=c2_val,
                exclusive_socket_ownership=c3_val,
                no_alternate_access=c4_val,
                no_surviving_dispatcher=c5_val,
                registry_journal_synced=c6_val,
            )

            is_proven, missing_conditions = evaluated_witness.evaluate()
            if is_proven:
                return PreDispatchResolution(
                    operation_id=operation_id,
                    state=PreDispatchState.PROVED_CLEAN_ABORT,
                    operation_status=op.operation_status,
                    requires_reconciliation=False,
                    can_auto_resume=False,
                    can_auto_redispatch=False,
                    is_safe_abort=True,
                    missing_proof_conditions=(),
                    details=(
                        "All six Revision 10 absence proof conditions verified True. "
                        "Docker was definitively not invoked; clean pre-dispatch abort is proven."
                    ),
                )
            else:
                # Any missing, unknown, or corrupt condition mandates uncertainty hold
                return PreDispatchResolution(
                    operation_id=operation_id,
                    state=PreDispatchState.UNCERTAINTY_HOLD,
                    operation_status=op.operation_status,
                    requires_reconciliation=True,
                    can_auto_resume=False,
                    can_auto_redispatch=False,
                    is_safe_abort=False,
                    missing_proof_conditions=tuple(missing_conditions),
                    details=(
                        f"Revision 10 absence proof failed for conditions: {missing_conditions}. "
                        "Fail-closed into uncertainty hold. Redispatch is prohibited."
                    ),
                )

        # 3. Uncertainty hold
        if op.operation_status == OperationStatus.DISPATCH_UNCERTAIN:
            return PreDispatchResolution(
                operation_id=operation_id,
                state=PreDispatchState.UNCERTAINTY_HOLD,
                operation_status=OperationStatus.DISPATCH_UNCERTAIN,
                requires_reconciliation=True,
                can_auto_resume=False,
                can_auto_redispatch=False,
                is_safe_abort=False,
                details="Operation is in uncertainty hold.",
            )

        # 4. Synchronized terminal states
        return PreDispatchResolution(
            operation_id=operation_id,
            state=PreDispatchState.SYNCHRONIZED,
            operation_status=op.operation_status,
            requires_reconciliation=False,
            can_auto_resume=False,
            can_auto_redispatch=False,
            is_safe_abort=(op.operation_status == OperationStatus.DISPATCH_ABORTED_PRE_DOCKER),
            details=f"Operation is in status '{op.operation_status.value}'.",
        )

    def abort_pre_dispatch_operation(
        self,
        operation_id: str,
        proof_witness: Optional[AbsenceProofWitness] = None,
        reason: Optional[str] = None,
    ) -> OperationRecord:
        """
        Cleanly abort an operation pre-dispatch if and only if:
        1. For RESERVED operations: journal has no records for this operation.
        2. For DISPATCH_PREPARED operations: all six Revision 10 conditions are verified True.

        If proof is unavailable or any condition fails:
        Fails closed into uncertainty hold (or raises CoordinatorUncertaintyError).
        NEVER marks safe abort without verified proof.
        """
        op = self.registry.get_operation(operation_id)
        if not op:
            raise CoordinatorValidationError(f"Operation '{operation_id}' not found in registry.")

        if op.operation_status in TERMINAL_STATUSES:
            raise CoordinatorInvalidStateError(
                f"Cannot abort operation '{operation_id}': already in terminal/uncertain status "
                f"'{op.operation_status.value}'."
            )

        if op.operation_status == OperationStatus.RESERVED:
            # Explicit abort of reservation before preparation
            abort_meta = {"abort_reason": reason or "Explicit pre-preparation abort"}
            return self.registry.transition_operation(
                operation_id=operation_id,
                target_status=OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
                metadata=abort_meta,
            )

        if op.operation_status in (OperationStatus.DISPATCH_PREPARED, OperationStatus.DISPATCH_ACCEPTED):
            resolution = self.evaluate_pre_dispatch_state(operation_id, proof_witness=proof_witness)
            if resolution.state != PreDispatchState.PROVED_CLEAN_ABORT:
                # Place in uncertainty hold in SQLite and fail closed
                fail_reason = (
                    f"Pre-dispatch abort rejected: proof unsatisfied ({resolution.details})"
                )
                try:
                    self.record_dispatch_uncertain(
                        operation_id=operation_id,
                        reason=fail_reason,
                    )
                except Exception:
                    pass

                raise CoordinatorUncertaintyError(
                    f"Cannot classify operation '{operation_id}' as clean pre-dispatch abort. "
                    f"{resolution.details}"
                )

            # Six-condition proof verified! Append DISPATCH_ABORTED_PRE_DOCKER to journal, then update SQLite
            abort_meta = {"abort_reason": reason or "Revision 10 absence proof verified; cleanly aborted pre-Docker."}
            try:
                self.journal.append(
                    record_type=JournalRecordType.DISPATCH_ABORTED_PRE_DOCKER,
                    operation_id=op.operation_id,
                    execution_id=op.execution_id,
                    workspace_id=op.workspace_id,
                    attempt_number=op.attempt_number,
                    fencing_token=op.fencing_token,
                    approval_id=op.approval_id,
                    metadata=abort_meta,
                )
            except (JournalUncertaintyError, JournalCorruptedError) as e:
                raise CoordinatorUncertaintyError(f"Journal append rejected: {e}") from e
            except JournalError as e:
                raise CoordinatorError(f"Journal append failed: {e}") from e

            return self.registry.transition_operation(
                operation_id=operation_id,
                target_status=OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
                metadata=abort_meta,
            )

        raise CoordinatorInvalidStateError(
            f"Cannot abort pre-dispatch: operation '{operation_id}' has already initiated Docker call "
            f"(status '{op.operation_status.value}')."
        )

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------

    def _get_and_validate_operation(
        self,
        operation_id: str,
        execution_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        workspace_id: Optional[str] = None,
    ) -> OperationRecord:
        """Fetch operation from registry and assert identity fields match if supplied."""
        if not operation_id or not isinstance(operation_id, str):
            raise CoordinatorValidationError("operation_id must be a non-empty string.")

        op = self.registry.get_operation(operation_id)
        if not op:
            raise CoordinatorValidationError(f"Operation '{operation_id}' not found in registry.")

        if execution_id is not None and execution_id != op.execution_id:
            raise CoordinatorConflictError(
                f"Conflicting execution_id for operation '{operation_id}': "
                f"registry has '{op.execution_id}', caller provided '{execution_id}'."
            )

        if fencing_token is not None and fencing_token != op.fencing_token:
            raise CoordinatorConflictError(
                f"Conflicting fencing_token for operation '{operation_id}': "
                f"registry has {op.fencing_token}, caller provided {fencing_token}."
            )

        if workspace_id is not None and workspace_id != op.workspace_id:
            raise CoordinatorConflictError(
                f"Conflicting workspace_id for operation '{operation_id}': "
                f"registry has '{op.workspace_id}', caller provided '{workspace_id}'."
            )

        return op

    @staticmethod
    def _map_record_type_to_status(record_type: str) -> Optional[OperationStatus]:
        """Map journal record_type string to OperationStatus enum."""
        mapping = {
            JournalRecordType.DISPATCH_PREPARED.value: OperationStatus.DISPATCH_PREPARED,
            JournalRecordType.DISPATCH_ACCEPTED.value: OperationStatus.DISPATCH_ACCEPTED,
            JournalRecordType.DOCKER_CALL_STARTED.value: OperationStatus.DOCKER_CALL_STARTED,
            JournalRecordType.DOCKER_CALL_CONFIRMED.value: OperationStatus.DOCKER_CALL_CONFIRMED,
            JournalRecordType.DOCKER_CALL_COMPLETED.value: OperationStatus.DOCKER_CALL_COMPLETED,
            JournalRecordType.DISPATCH_ABORTED_PRE_DOCKER.value: OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
            JournalRecordType.DISPATCH_FAILED.value: OperationStatus.DISPATCH_FAILED,
            JournalRecordType.DISPATCH_UNCERTAIN.value: OperationStatus.DISPATCH_UNCERTAIN,
        }
        return mapping.get(record_type)

    @staticmethod
    def _is_forward_transition(current: OperationStatus, target: OperationStatus) -> bool:
        """Return True if target represents a valid forward progression from current."""
        if current in TERMINAL_STATUSES:
            return False

        # Status rank order in the linear progression
        rank = {
            OperationStatus.RESERVED: 0,
            OperationStatus.DISPATCH_PREPARED: 1,
            OperationStatus.DISPATCH_ACCEPTED: 2,
            OperationStatus.DOCKER_CALL_STARTED: 3,
            OperationStatus.DOCKER_CALL_CONFIRMED: 4,
            OperationStatus.DOCKER_CALL_COMPLETED: 5,
        }

        # Terminal targets are always forward from non-terminal states
        if target in TERMINAL_STATUSES:
            return True

        curr_rank = rank.get(current, -1)
        tgt_rank = rank.get(target, -1)
        return tgt_rank > curr_rank

    def _apply_forward_transition(
        self,
        op_id: str,
        current: OperationStatus,
        target: OperationStatus,
        metadata: Optional[Dict[str, Any]],
    ) -> None:
        """Step through valid intermediate transitions to reach target status without violating FSM."""
        # Handle terminal / abort / failure jumps directly allowed by current
        if target in (
            OperationStatus.DISPATCH_FAILED,
            OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
            OperationStatus.DISPATCH_UNCERTAIN,
        ):
            self.registry.transition_operation(op_id, target, metadata=metadata)
            return

        # Canonical progression steps
        curr = current
        if curr == OperationStatus.RESERVED and target != OperationStatus.RESERVED:
            self.registry.transition_operation(op_id, OperationStatus.DISPATCH_PREPARED)
            curr = OperationStatus.DISPATCH_PREPARED

        if curr == OperationStatus.DISPATCH_PREPARED and target in (
            OperationStatus.DISPATCH_ACCEPTED,
            OperationStatus.DOCKER_CALL_STARTED,
            OperationStatus.DOCKER_CALL_CONFIRMED,
            OperationStatus.DOCKER_CALL_COMPLETED,
        ):
            self.registry.transition_operation(op_id, OperationStatus.DISPATCH_ACCEPTED)
            curr = OperationStatus.DISPATCH_ACCEPTED

        if curr == OperationStatus.DISPATCH_ACCEPTED and target in (
            OperationStatus.DOCKER_CALL_STARTED,
            OperationStatus.DOCKER_CALL_CONFIRMED,
            OperationStatus.DOCKER_CALL_COMPLETED,
        ):
            self.registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_STARTED)
            curr = OperationStatus.DOCKER_CALL_STARTED

        if curr == OperationStatus.DOCKER_CALL_STARTED and target in (
            OperationStatus.DOCKER_CALL_CONFIRMED,
            OperationStatus.DOCKER_CALL_COMPLETED,
        ):
            if target == OperationStatus.DOCKER_CALL_CONFIRMED:
                self.registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_CONFIRMED)
                curr = OperationStatus.DOCKER_CALL_CONFIRMED
            else:
                self.registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_COMPLETED, metadata=metadata)
                curr = OperationStatus.DOCKER_CALL_COMPLETED

        if curr == OperationStatus.DOCKER_CALL_CONFIRMED and target == OperationStatus.DOCKER_CALL_COMPLETED:
            self.registry.transition_operation(op_id, OperationStatus.DOCKER_CALL_COMPLETED, metadata=metadata)

    def close(self) -> None:
        """Close registry and journal handles cleanly."""
        self.registry.close()
        self.journal.close()

    def __enter__(self) -> "DispatchCoordinator":
        self.initialize()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
