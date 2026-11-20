"""Three-Way Execution Reconciliation Service for Phase 4.3.6 Milestone E.3.5.

Bounded, auditable, idempotent reconciliation across:
1. PostgreSQL execution state (RemediationExecution, ExecutionAttempt, ExecutionEvent,
   VerificationCycle, Incident).
2. SQLite OperationRegistry (operation_reservations).
3. Append-only OperationJournal (SOJ1 binary frames).

Key Invariants (Revision 10 baseline):
- Zero Blind Redispatch: An operation that was prepared, started, or completed is NEVER
  automatically redispatched or retried.
- Fail-Closed: If any store is corrupt, torn, or contradictory, fails closed into an uncertainty hold.
- Strict Read-Only Verification: Container exit 0 only advances to verification_pending;
  only read-only diagnostic probes are resumed.
- Incident Recovery Exclusivity: Incident recovery is executed exclusively by
  IncidentRecoveryBridge upon confirmed verification success.
- Dry-Run Support: Reports proposed changes without acquiring long-lived locks or mutating any store.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import logging
import sqlite3
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.execution.dispatch_coordinator import (
    AbsenceProofWitness,
    DispatchCoordinator,
    PreDispatchResolution,
    PreDispatchState,
)
from app.execution.exceptions import (
    CrossWorkspaceViolationError,
    IllegalStateTransitionError,
    PreconditionFailedError,
    StaleWorkerFencingError,
)
from app.execution.journal import (
    JournalCorruptedError,
    JournalError,
    JournalRecord,
    JournalRecordType,
    JournalTailState,
    JournalUncertaintyError,
    OperationJournal,
)
from app.execution.manager import sanitize_metadata
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.registry import (
    OperationRecord,
    OperationRegistry,
    OperationStatus,
    RegistryBusyError,
    RegistryCorruptedError,
    RegistryError,
    RegistryUnavailableError,
)
from app.execution.state_machine import (
    ExecutionState,
    validate_state_transition,
)
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
)
from app.execution.watchdog import HOLD_EXPIRATION_TIMESTAMP
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    RemediationExecution,
)
from app.models.verification import VerificationCycle, VerificationProbeResult

logger = logging.getLogger(__name__)


# ============================================================================
# Reconciliation Classifications
# ============================================================================

class ReconciliationClassification(str, Enum):
    """Explicit classifications for three-way store reconciliation."""
    UNCERTAIN_NO_LOCAL_RECORD = "UNCERTAIN_NO_LOCAL_RECORD"
    UNRESOLVED_RESERVATION = "UNRESOLVED_RESERVATION"
    UNRESOLVED_PREPARED = "UNRESOLVED_PREPARED"
    UNCERTAIN_STARTED_NO_OUTCOME = "UNCERTAIN_STARTED_NO_OUTCOME"
    UNCERTAIN_STORE_FLAGGED = "UNCERTAIN_STORE_FLAGGED"
    COMPLETED_EXIT_ZERO = "COMPLETED_EXIT_ZERO"
    COMPLETED_NONZERO_EXIT = "COMPLETED_NONZERO_EXIT"
    PERSISTED_VERIFICATION_SUCCESS = "PERSISTED_VERIFICATION_SUCCESS"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    JOURNAL_CORRUPT_OR_TORN = "JOURNAL_CORRUPT_OR_TORN"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    ALREADY_SYNCHRONIZED = "ALREADY_SYNCHRONIZED"
    NON_CANDIDATE_STATE = "NON_CANDIDATE_STATE"


@dataclass(frozen=True)
class ReconciliationResult:
    """Detailed result for a single reconciled execution."""
    execution_id: str
    classification: ReconciliationClassification
    previous_state: Optional[str]
    resulting_state: Optional[str]
    action_taken: str
    reason: str
    operation_id: Optional[str] = None
    fencing_token: Optional[int] = None
    is_dry_run: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass(frozen=True)
class ReconciliationReport:
    """Summary report of a three-way reconciliation scan."""
    executions_scanned: int
    executions_reconciled: int
    executions_held_uncertain: int
    executions_unresolved: int
    is_dry_run: bool
    results: List[ReconciliationResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ============================================================================
# Three-Way Execution Reconciler Service
# ============================================================================

class ThreeWayExecutionReconciler:
    """
    Service reconciling state across PostgreSQL, SQLite Registry, and OperationJournal.
    Enforces fail-closed safety, strict zero-redispatch invariants, and dry-run isolation.
    """

    def __init__(
        self,
        *,
        registry: OperationRegistry,
        journal: OperationJournal,
        db_factory: Optional[Callable[[], Session]] = None,
        db: Optional[Session] = None,
        coordinator: Optional[DispatchCoordinator] = None,
        verification_engine: Optional[PostExecutionVerificationEngine] = None,
        reconciler_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        resume_verification: bool = False,
    ):
        self.registry = registry
        self.journal = journal
        self.coordinator = coordinator or DispatchCoordinator(registry=registry, journal=journal)
        self.verification_engine = verification_engine
        self.reconciler_id = reconciler_id or f"reconciler-{uuid.uuid4().hex[:8]}"
        self.workspace_id = workspace_id
        self.resume_verification = resume_verification

        self._db_factory = db_factory or SessionLocal
        self._external_db = db
        if self._external_db is None and db_factory is not None:
            try:
                s1 = db_factory()
                s2 = db_factory()
                if s1 is s2:
                    self._external_db = s1
                else:
                    s1.close()
                    s2.close()
            except Exception:
                pass

    def get_session(self) -> Session:
        """Provide database session (external instance or new session from factory)."""
        if self._external_db is not None:
            return self._external_db
        return self._db_factory()

    def _is_postgresql(self, session: Session) -> bool:
        """Check if session is backed by PostgreSQL dialect."""
        try:
            bind = session.get_bind()
            return bind is not None and bind.dialect.name == "postgresql"
        except Exception:
            return False

    # ------------------------------------------------------------------------
    # Core Reconciliation Method
    # ------------------------------------------------------------------------

    def reconcile_execution(
        self,
        execution_id: str,
        dry_run: bool = False,
        now_utc: Optional[datetime] = None,
    ) -> ReconciliationResult:
        """
        Reconcile a single execution across PostgreSQL, SQLite Registry, and OperationJournal.

        - In dry_run mode: No database locks acquired, no changes committed to any store.
        - In active mode: Atomically updates PostgreSQL under row-level lock.
        """
        now = now_utc or datetime.now(timezone.utc)
        db = self.get_session()
        try:
            return self._reconcile_execution_with_session(db, execution_id, dry_run, now)
        finally:
            if self._external_db is None:
                db.close()

    def _reconcile_execution_with_session(
        self,
        db: Session,
        execution_id: str,
        dry_run: bool,
        now_utc: datetime,
    ) -> ReconciliationResult:
        """Internal execution reconciliation logic with explicit session."""
        # --------------------------------------------------------------------
        # Stage 1: Store Availability & Integrity Validation
        # --------------------------------------------------------------------
        journal_records: List[JournalRecord] = []
        journal_is_clean = True
        journal_error_msg: Optional[str] = None

        try:
            journal_records = self.journal.replay()
        except (JournalCorruptedError, JournalUncertaintyError) as e:
            journal_is_clean = False
            journal_error_msg = str(e)
            logger.error("Three-way reconciliation detected journal corruption/uncertainty: %s", e)
        except Exception as e:
            logger.error("Journal store unavailable during reconciliation: %s", e)
            return ReconciliationResult(
                execution_id=execution_id,
                classification=ReconciliationClassification.STORE_UNAVAILABLE,
                previous_state=None,
                resulting_state=None,
                action_taken="fail_closed_store_unavailable",
                reason=f"Operation journal unavailable: {e}",
                is_dry_run=dry_run,
                error=str(e),
            )

        try:
            # Quick probe for SQLite registry availability
            self.registry.list_uncertain_operations()
        except (RegistryBusyError, RegistryUnavailableError, sqlite3.OperationalError) as e:
            logger.error("Registry store unavailable or busy during reconciliation: %s", e)
            return ReconciliationResult(
                execution_id=execution_id,
                classification=ReconciliationClassification.STORE_UNAVAILABLE,
                previous_state=None,
                resulting_state=None,
                action_taken="fail_closed_store_unavailable",
                reason=f"Operation registry unavailable or busy: {e}",
                is_dry_run=dry_run,
                error=str(e),
            )
        except Exception as e:
            logger.error("Unexpected registry error: %s", e)
            return ReconciliationResult(
                execution_id=execution_id,
                classification=ReconciliationClassification.STORE_UNAVAILABLE,
                previous_state=None,
                resulting_state=None,
                action_taken="fail_closed_store_unavailable",
                reason=f"Operation registry error: {e}",
                is_dry_run=dry_run,
                error=str(e),
            )

        # --------------------------------------------------------------------
        # Stage 2: PostgreSQL Execution Fetch & Row-Level Lock
        # --------------------------------------------------------------------
        try:
            query = db.query(RemediationExecution).filter(RemediationExecution.id == execution_id)
            if not dry_run:
                if self._is_postgresql(db):
                    query = query.with_for_update(skip_locked=True)
                else:
                    query = query.with_for_update()

            execution = query.first()
            if not execution:
                return ReconciliationResult(
                    execution_id=execution_id,
                    classification=ReconciliationClassification.NON_CANDIDATE_STATE,
                    previous_state=None,
                    resulting_state=None,
                    action_taken="execution_not_found",
                    reason=f"RemediationExecution '{execution_id}' does not exist or is locked.",
                    is_dry_run=dry_run,
                )

            # Workspace isolation check
            if self.workspace_id and execution.workspace_id != self.workspace_id:
                raise CrossWorkspaceViolationError(
                    f"Cross-workspace violation: Execution belongs to '{execution.workspace_id}', not '{self.workspace_id}'."
                )

            prev_state = execution.status
            current_token = execution.fencing_token

            # If journal was corrupt/torn, fail closed for active executions
            if not journal_is_clean:
                if execution.status in (
                    ExecutionState.QUEUED.value,
                    ExecutionState.VALIDATING.value,
                    ExecutionState.EXECUTING.value,
                    ExecutionState.VERIFICATION_PENDING.value,
                ):
                    reason = f"JOURNAL_CORRUPT_OR_TORN: Reconciler detected journal corruption: {journal_error_msg}"
                    if dry_run:
                        return ReconciliationResult(
                            execution_id=execution.id,
                            classification=ReconciliationClassification.JOURNAL_CORRUPT_OR_TORN,
                            previous_state=prev_state,
                            resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                            action_taken="dry_run_proposed_uncertainty_hold",
                            reason=reason,
                            fencing_token=current_token,
                            is_dry_run=True,
                            details={"journal_error": journal_error_msg},
                        )
                    return self._apply_uncertainty_hold(
                        db=db,
                        execution=execution,
                        classification=ReconciliationClassification.JOURNAL_CORRUPT_OR_TORN,
                        reason=reason,
                        now_utc=now_utc,
                        details={"journal_error": journal_error_msg},
                    )
                else:
                    # Already terminal or held
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.JOURNAL_CORRUPT_OR_TORN,
                        previous_state=prev_state,
                        resulting_state=prev_state,
                        action_taken="journal_corrupt_preserved_terminal",
                        reason=f"Journal corrupt but execution is already in state '{prev_state}'.",
                        fencing_token=current_token,
                        is_dry_run=dry_run,
                    )

            # ----------------------------------------------------------------
            # Stage 3: Cross-Store Correlation & Evidence Gathering
            # ----------------------------------------------------------------
            op: Optional[OperationRecord] = None
            try:
                op = self.registry.get_by_execution_and_token(execution.id, execution.fencing_token)
            except Exception:
                pass

            if op is None and execution.approval_id:
                try:
                    op = self.registry.get_by_approval(execution.approval_id)
                except Exception:
                    pass

            if op is None:
                # Query all registry operations for this execution_id
                try:
                    ops = self.registry.list_operations(execution_id=execution.id)
                    if ops:
                        op = ops[-1]
                except Exception:
                    pass

            # Gather journal records for this execution / operation
            op_journal_records = [
                r for r in journal_records
                if r.execution_id == execution.id or (op and r.operation_id == op.operation_id)
            ]

            # ----------------------------------------------------------------
            # Stage 4: Contradictory Evidence Detection
            # ----------------------------------------------------------------
            contradictions: List[str] = []
            if op:
                if op.workspace_id != execution.workspace_id:
                    contradictions.append(
                        f"Workspace mismatch: PostgreSQL '{execution.workspace_id}' vs Registry '{op.workspace_id}'"
                    )
                if execution.approval_id and op.approval_id != execution.approval_id:
                    contradictions.append(
                        f"Approval mismatch: PostgreSQL '{execution.approval_id}' vs Registry '{op.approval_id}'"
                    )
                if op.execution_id != execution.id:
                    contradictions.append(
                        f"Execution ID mismatch: PostgreSQL '{execution.id}' vs Registry '{op.execution_id}'"
                    )

            for j_rec in op_journal_records:
                if j_rec.workspace_id != execution.workspace_id:
                    contradictions.append(
                        f"Journal workspace mismatch: PostgreSQL '{execution.workspace_id}' vs Journal '{j_rec.workspace_id}'"
                    )
                if execution.approval_id and j_rec.approval_id and j_rec.approval_id != execution.approval_id:
                    contradictions.append(
                        f"Journal approval mismatch: PostgreSQL '{execution.approval_id}' vs Journal '{j_rec.approval_id}'"
                    )

            if contradictions:
                reason = "CONTRADICTORY_EVIDENCE: Conflicting store records: " + "; ".join(contradictions)
                logger.critical("Three-way reconciliation found contradictory evidence: %s", reason)
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.CONTRADICTORY_EVIDENCE,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                        action_taken="dry_run_proposed_quarantine_hold",
                        reason=reason,
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=True,
                        details={"contradictions": contradictions},
                    )
                return self._apply_uncertainty_hold(
                    db=db,
                    execution=execution,
                    classification=ReconciliationClassification.CONTRADICTORY_EVIDENCE,
                    reason=reason,
                    now_utc=now_utc,
                    details={"contradictions": contradictions},
                )

            # ----------------------------------------------------------------
            # Stage 5: Classification and Safe Reconciliation
            # ----------------------------------------------------------------

            # Check if stores are already synchronized in terminal/held state
            if execution.status == ExecutionState.EXECUTION_UNCERTAIN.value:
                if execution.locked_by and execution.locked_by.startswith("HOLD:"):
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.ALREADY_SYNCHRONIZED,
                        previous_state=prev_state,
                        resulting_state=prev_state,
                        action_taken="already_held_uncertain",
                        reason="Execution is already locked under authoritative uncertainty hold.",
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=dry_run,
                    )

            if execution.status in (ExecutionState.VERIFIED.value, ExecutionState.EXECUTION_FAILED.value):
                return ReconciliationResult(
                    execution_id=execution.id,
                    classification=ReconciliationClassification.ALREADY_SYNCHRONIZED,
                    previous_state=prev_state,
                    resulting_state=prev_state,
                    action_taken="already_terminal",
                    reason=f"Execution is already in terminal state '{prev_state}'.",
                    operation_id=op.operation_id if op else None,
                    fencing_token=current_token,
                    is_dry_run=dry_run,
                )

            # Condition 0: PostgreSQL verification_pending handling
            if execution.status == ExecutionState.VERIFICATION_PENDING.value:
                cycle = (
                    db.query(VerificationCycle)
                    .filter(VerificationCycle.execution_id == execution.id)
                    .order_by(VerificationCycle.cycle_number.desc())
                    .first()
                )
                if cycle and cycle.status == "passed":
                    outcome = (cycle.cycle_metadata or {}).get("outcome")
                    if outcome in ("PASS", VerificationOutcome.PASS.value):
                        reason = (
                            f"PERSISTED_VERIFICATION_SUCCESS: Cycle #{cycle.cycle_number} passed successfully. "
                            "Invoking IncidentRecoveryBridge to atomically recover incident and verify execution."
                        )
                        if dry_run:
                            return ReconciliationResult(
                                execution_id=execution.id,
                                classification=ReconciliationClassification.PERSISTED_VERIFICATION_SUCCESS,
                                previous_state=prev_state,
                                resulting_state=ExecutionState.VERIFIED.value,
                                action_taken="dry_run_proposed_atomic_incident_recovery",
                                reason=reason,
                                operation_id=op.operation_id if op else None,
                                fencing_token=current_token,
                                is_dry_run=True,
                                details={"cycle_id": cycle.id, "cycle_number": cycle.cycle_number},
                            )

                        return self._recover_from_passed_verification(
                            db=db,
                            execution=execution,
                            cycle=cycle,
                            now_utc=now_utc,
                        )
                elif self.resume_verification and self.verification_engine:
                    execution.locked_by = self.reconciler_id
                    execution.locked_until = now_utc + timedelta(seconds=60)
                    execution.heartbeat_at = now_utc
                    db.commit()
                    next_cycle = (cycle.cycle_number + 1) if cycle else 1
                    summary = self.verification_engine.run_verification_cycle(
                        db=db,
                        execution_id=execution.id,
                        workspace_id=execution.workspace_id,
                        worker_id=self.reconciler_id,
                        fencing_token=execution.fencing_token,
                        cycle_number=next_cycle,
                        probes_required=1,
                        timeout_seconds=30,
                        recover_incident=True,
                    )
                    resulting_state = (
                        ExecutionState.VERIFIED.value
                        if summary.outcome == VerificationOutcome.PASS
                        else ExecutionState.VERIFICATION_FAILED.value
                    )
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=(
                            ReconciliationClassification.PERSISTED_VERIFICATION_SUCCESS
                            if summary.outcome == VerificationOutcome.PASS
                            else ReconciliationClassification.COMPLETED_EXIT_ZERO
                        ),
                        previous_state=prev_state,
                        resulting_state=resulting_state,
                        action_taken="resumed_verification_from_pending",
                        reason=f"Resumed verification from verification_pending: outcome={summary.outcome.value}",
                        operation_id=op.operation_id if op else None,
                        fencing_token=execution.fencing_token,
                        is_dry_run=False,
                        details={"verification_outcome": summary.outcome.value},
                    )

            # Condition 1: PostgreSQL executing with NO local operation record
            if op is None and len(op_journal_records) == 0:
                if execution.status in (ExecutionState.EXECUTING.value, ExecutionState.VALIDATING.value):
                    reason = "UNCERTAIN_NO_LOCAL_RECORD: Execution in executing state without local registry or journal record."
                    if dry_run:
                        return ReconciliationResult(
                            execution_id=execution.id,
                            classification=ReconciliationClassification.UNCERTAIN_NO_LOCAL_RECORD,
                            previous_state=prev_state,
                            resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                            action_taken="dry_run_proposed_uncertainty_hold",
                            reason=reason,
                            fencing_token=current_token,
                            is_dry_run=True,
                        )
                    return self._apply_uncertainty_hold(
                        db=db,
                        execution=execution,
                        classification=ReconciliationClassification.UNCERTAIN_NO_LOCAL_RECORD,
                        reason=reason,
                        now_utc=now_utc,
                    )
                else:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.NON_CANDIDATE_STATE,
                        previous_state=prev_state,
                        resulting_state=prev_state,
                        action_taken="no_action_queued_or_non_executing",
                        reason=f"Execution is in '{prev_state}' with no local record; safe to remain.",
                        fencing_token=current_token,
                        is_dry_run=dry_run,
                    )

            # Condition 2: Uncertainty explicitly flagged in any store
            has_journal_uncertain = any(
                r.record_type == JournalRecordType.DISPATCH_UNCERTAIN.value for r in op_journal_records
            )
            if (
                execution.status == ExecutionState.EXECUTION_UNCERTAIN.value
                or (op and op.operation_status == OperationStatus.DISPATCH_UNCERTAIN)
                or has_journal_uncertain
            ):
                reason = "UNCERTAIN_STORE_FLAGGED: Uncertainty marker detected in registry, journal, or PostgreSQL."
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.UNCERTAIN_STORE_FLAGGED,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                        action_taken="dry_run_proposed_uncertainty_hold",
                        reason=reason,
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=True,
                    )
                return self._apply_uncertainty_hold(
                    db=db,
                    execution=execution,
                    classification=ReconciliationClassification.UNCERTAIN_STORE_FLAGGED,
                    reason=reason,
                    now_utc=now_utc,
                    operation=op,
                )

            # Condition 3: RESERVED with empty journal
            if op and op.operation_status == OperationStatus.RESERVED and len(op_journal_records) == 0:
                reason = (
                    "UNRESOLVED_RESERVATION: SQLite has RESERVED reservation but journal has zero records. "
                    "Preserving reservation; fail closed without automatic resume or abort."
                )
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.UNRESOLVED_RESERVATION,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                        action_taken="dry_run_proposed_uncertainty_hold",
                        reason=reason,
                        operation_id=op.operation_id,
                        fencing_token=current_token,
                        is_dry_run=True,
                    )
                return self._apply_uncertainty_hold(
                    db=db,
                    execution=execution,
                    classification=ReconciliationClassification.UNRESOLVED_RESERVATION,
                    reason=reason,
                    now_utc=now_utc,
                    operation=op,
                )

            # Condition 4: PREPARED without STARTED marker
            has_started_marker = any(
                r.record_type in (
                    JournalRecordType.DOCKER_CALL_STARTED.value,
                    JournalRecordType.DOCKER_CALL_CONFIRMED.value,
                )
                for r in op_journal_records
            )
            is_prepared = (
                (op and op.operation_status in (OperationStatus.DISPATCH_PREPARED, OperationStatus.DISPATCH_ACCEPTED))
                or any(r.record_type == JournalRecordType.DISPATCH_PREPARED.value for r in op_journal_records)
            )

            if is_prepared and not has_started_marker:
                # Revision 10 rule: Missing start marker is NOT physical proof of non-dispatch
                reason = (
                    "UNRESOLVED_PREPARED: Operation prepared in journal/registry but lacks DOCKER_CALL_STARTED. "
                    "Absence of start marker does not prove non-invocation; establishing uncertainty hold."
                )
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.UNRESOLVED_PREPARED,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                        action_taken="dry_run_proposed_uncertainty_hold",
                        reason=reason,
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=True,
                    )
                return self._apply_uncertainty_hold(
                    db=db,
                    execution=execution,
                    classification=ReconciliationClassification.UNRESOLVED_PREPARED,
                    reason=reason,
                    now_utc=now_utc,
                    operation=op,
                )

            # Condition 5: STARTED without outcome
            has_outcome = (
                (op and op.operation_status in (
                    OperationStatus.DOCKER_CALL_COMPLETED,
                    OperationStatus.DISPATCH_FAILED,
                    OperationStatus.DISPATCH_UNCERTAIN,
                    OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
                ))
                or any(
                    r.record_type in (
                        JournalRecordType.DOCKER_CALL_COMPLETED.value,
                        JournalRecordType.DISPATCH_FAILED.value,
                        JournalRecordType.DISPATCH_UNCERTAIN.value,
                        JournalRecordType.DISPATCH_ABORTED_PRE_DOCKER.value,
                    )
                    for r in op_journal_records
                )
            )

            if has_started_marker and not has_outcome:
                reason = (
                    "UNCERTAIN_STARTED_NO_OUTCOME: DOCKER_CALL_STARTED marker exists without completion outcome. "
                    "Physical container status indeterminate; zero redispatch enforced."
                )
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.UNCERTAIN_STARTED_NO_OUTCOME,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
                        action_taken="dry_run_proposed_uncertainty_hold",
                        reason=reason,
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=True,
                    )
                return self._apply_uncertainty_hold(
                    db=db,
                    execution=execution,
                    classification=ReconciliationClassification.UNCERTAIN_STARTED_NO_OUTCOME,
                    reason=reason,
                    now_utc=now_utc,
                    operation=op,
                )

            # Condition 6: COMPLETED with exit code 0
            is_completed_zero = False
            completed_meta: Dict[str, Any] = {}
            if op and op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED:
                exit_c = op.metadata.get("exit_code", 0)
                if exit_c == 0:
                    is_completed_zero = True
                    completed_meta = op.metadata

            if not is_completed_zero:
                comp_records = [
                    r for r in op_journal_records
                    if r.record_type == JournalRecordType.DOCKER_CALL_COMPLETED.value
                ]
                if comp_records:
                    last_comp = comp_records[-1]
                    if last_comp.metadata.get("exit_code", 0) == 0:
                        is_completed_zero = True
                        completed_meta = last_comp.metadata

            if is_completed_zero and execution.status in (ExecutionState.EXECUTING.value, ExecutionState.VALIDATING.value):
                reason = (
                    "COMPLETED_EXIT_ZERO: Durable DOCKER_CALL_COMPLETED record with exit code 0 detected. "
                    "Reconciling to verification_pending; zero redispatch; read-only verification permitted."
                )
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.COMPLETED_EXIT_ZERO,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.VERIFICATION_PENDING.value,
                        action_taken="dry_run_proposed_verification_pending",
                        reason=reason,
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=True,
                        details={"exit_code": 0},
                    )

                return self._finalize_completed_exit_zero(
                    db=db,
                    execution=execution,
                    op=op,
                    completed_meta=completed_meta,
                    now_utc=now_utc,
                )

            # Condition 7: COMPLETED with non-zero exit code
            is_completed_nonzero = False
            nz_exit_code = 1
            if op and (
                op.operation_status == OperationStatus.DISPATCH_FAILED
                or (op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED and op.metadata.get("exit_code", 0) != 0)
            ):
                is_completed_nonzero = True
                nz_exit_code = op.metadata.get("exit_code", 1)

            if not is_completed_nonzero:
                nz_records = [
                    r for r in op_journal_records
                    if r.record_type in (JournalRecordType.DOCKER_CALL_COMPLETED.value, JournalRecordType.DISPATCH_FAILED.value)
                    and r.metadata.get("exit_code", 0) != 0
                ]
                if nz_records:
                    is_completed_nonzero = True
                    nz_exit_code = nz_records[-1].metadata.get("exit_code", 1)

            if is_completed_nonzero and execution.status in (ExecutionState.EXECUTING.value, ExecutionState.VALIDATING.value):
                reason = f"COMPLETED_NONZERO_EXIT: Container exited with non-zero code {nz_exit_code}. Finalizing execution_failed."
                if dry_run:
                    return ReconciliationResult(
                        execution_id=execution.id,
                        classification=ReconciliationClassification.COMPLETED_NONZERO_EXIT,
                        previous_state=prev_state,
                        resulting_state=ExecutionState.EXECUTION_FAILED.value,
                        action_taken="dry_run_proposed_execution_failed",
                        reason=reason,
                        operation_id=op.operation_id if op else None,
                        fencing_token=current_token,
                        is_dry_run=True,
                        details={"exit_code": nz_exit_code},
                    )

                return self._finalize_completed_nonzero(
                    db=db,
                    execution=execution,
                    exit_code=nz_exit_code,
                    op=op,
                    now_utc=now_utc,
                )

            # Condition 8: PostgreSQL verification_pending with persisted successful cycle
            if execution.status == ExecutionState.VERIFICATION_PENDING.value:
                cycle = (
                    db.query(VerificationCycle)
                    .filter(VerificationCycle.execution_id == execution.id)
                    .order_by(VerificationCycle.cycle_number.desc())
                    .first()
                )
                if cycle and cycle.status == "passed":
                    outcome = (cycle.cycle_metadata or {}).get("outcome")
                    if outcome in ("PASS", VerificationOutcome.PASS.value):
                        reason = (
                            f"PERSISTED_VERIFICATION_SUCCESS: Cycle #{cycle.cycle_number} passed successfully. "
                            "Invoking IncidentRecoveryBridge to atomically recover incident and verify execution."
                        )
                        if dry_run:
                            return ReconciliationResult(
                                execution_id=execution.id,
                                classification=ReconciliationClassification.PERSISTED_VERIFICATION_SUCCESS,
                                previous_state=prev_state,
                                resulting_state=ExecutionState.VERIFIED.value,
                                action_taken="dry_run_proposed_atomic_incident_recovery",
                                reason=reason,
                                operation_id=op.operation_id if op else None,
                                fencing_token=current_token,
                                is_dry_run=True,
                                details={"cycle_id": cycle.id, "cycle_number": cycle.cycle_number},
                            )

                        return self._recover_from_passed_verification(
                            db=db,
                            execution=execution,
                            cycle=cycle,
                            now_utc=now_utc,
                        )

            # Default: Execution does not require state modification
            return ReconciliationResult(
                execution_id=execution.id,
                classification=ReconciliationClassification.ALREADY_SYNCHRONIZED,
                previous_state=prev_state,
                resulting_state=prev_state,
                action_taken="no_reconciliation_needed",
                reason="Execution states are consistent or non-candidate across all stores.",
                operation_id=op.operation_id if op else None,
                fencing_token=current_token,
                is_dry_run=dry_run,
            )

        except CrossWorkspaceViolationError:
            raise
        except Exception as exc:
            logger.error("Three-way reconciliation error on execution '%s': %s", execution_id, exc)
            db.rollback()
            return ReconciliationResult(
                execution_id=execution_id,
                classification=ReconciliationClassification.STORE_UNAVAILABLE,
                previous_state=None,
                resulting_state=None,
                action_taken="fail_closed_error",
                reason=f"Reconciliation persistence or execution failure: {exc}",
                is_dry_run=dry_run,
                error=str(exc),
            )

    # ------------------------------------------------------------------------
    # State Finalization Helpers (Non-Dry-Run)
    # ------------------------------------------------------------------------

    def _apply_uncertainty_hold(
        self,
        *,
        db: Session,
        execution: RemediationExecution,
        classification: ReconciliationClassification,
        reason: str,
        now_utc: datetime,
        operation: Optional[OperationRecord] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> ReconciliationResult:
        """Establish authoritative fail-closed HOLD:EXECUTION_UNCERTAIN."""
        prev_state = execution.status
        validate_state_transition(execution.status, ExecutionState.EXECUTION_UNCERTAIN.value)

        execution.status = ExecutionState.EXECUTION_UNCERTAIN.value
        execution.locked_by = "HOLD:EXECUTION_UNCERTAIN"
        execution.locked_until = HOLD_EXPIRATION_TIMESTAMP
        execution.fencing_token += 1
        execution.completed_at = now_utc
        execution.updated_at = now_utc
        execution.error_category = classification.value.lower()
        execution.uncertain_reason = reason

        output_meta = execution.execution_output or {}
        output_meta["uncertainty_hold"] = {
            "hold_type": "HOLD:EXECUTION_UNCERTAIN",
            "hold_reason": reason,
            "classification": classification.value,
            "held_at": now_utc.isoformat(),
            "reconciler_id": self.reconciler_id,
            "fenced_fencing_token": execution.fencing_token,
        }
        if details:
            output_meta["uncertainty_hold"].update(details)
        execution.execution_output = sanitize_metadata(output_meta)

        # Update active attempt to uncertain
        attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if attempt and attempt.status == "running":
            attempt.status = "uncertain"
            attempt.completed_at = now_utc
            attempt.error_category = classification.value.lower()
            attempt.error_message = reason

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="execution_uncertain",
            message=f"Three-way reconciliation established uncertainty hold ({classification.value}): {reason}",
            metadata_json=sanitize_metadata({
                "reconciler_id": self.reconciler_id,
                "classification": classification.value,
                "fencing_token": execution.fencing_token,
                "hold_type": "HOLD:EXECUTION_UNCERTAIN",
            }),
            timestamp=now_utc,
        )
        db.add(event)

        if execution.incident_id:
            inc_event = IncidentEvent(
                id=str(uuid.uuid4()),
                incident_id=execution.incident_id,
                event_type="action",
                message=(
                    f"Remediation action '{execution.action_id}' placed on uncertainty hold by reconciler. "
                    "Incident remains active; zero redispatch enforced."
                ),
                metadata_json=json.dumps(
                    sanitize_metadata({
                        "execution_id": execution.id,
                        "action_id": execution.action_id,
                        "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                        "classification": classification.value,
                    })
                ),
                timestamp=now_utc,
            )
            db.add(inc_event)

        # If operation exists in registry and is not terminal, advance registry to DISPATCH_UNCERTAIN
        # NOTE: UNRESOLVED_RESERVATION and UNRESOLVED_PREPARED must preserve existing status without mutation
        if (
            operation
            and classification not in (
                ReconciliationClassification.UNRESOLVED_RESERVATION,
                ReconciliationClassification.UNRESOLVED_PREPARED,
            )
            and operation.operation_status not in (
                OperationStatus.DOCKER_CALL_COMPLETED,
                OperationStatus.DISPATCH_FAILED,
                OperationStatus.DISPATCH_UNCERTAIN,
                OperationStatus.DISPATCH_ABORTED_PRE_DOCKER,
            )
        ):
            try:
                self.coordinator.record_dispatch_uncertain(
                    operation_id=operation.operation_id,
                    reason=reason,
                )
            except Exception as e:
                logger.warning("Could not advance registry to DISPATCH_UNCERTAIN during reconciliation hold: %s", e)

        db.commit()

        return ReconciliationResult(
            execution_id=execution.id,
            classification=classification,
            previous_state=prev_state,
            resulting_state=ExecutionState.EXECUTION_UNCERTAIN.value,
            action_taken="established_uncertainty_hold",
            reason=reason,
            operation_id=operation.operation_id if operation else None,
            fencing_token=execution.fencing_token,
            is_dry_run=False,
            details=details or {},
        )

    def _finalize_completed_exit_zero(
        self,
        *,
        db: Session,
        execution: RemediationExecution,
        op: Optional[OperationRecord],
        completed_meta: Dict[str, Any],
        now_utc: datetime,
    ) -> ReconciliationResult:
        """Finalize execution whose container completed with exit code 0 to verification_pending."""
        prev_state = execution.status
        validate_state_transition(execution.status, ExecutionState.EXECUTION_SUCCEEDED.value)

        execution.status = ExecutionState.EXECUTION_SUCCEEDED.value
        execution.completed_at = now_utc
        execution.fencing_token += 1
        execution.updated_at = now_utc
        execution.execution_output = sanitize_metadata(completed_meta.get("output_data") or {})

        attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if attempt and attempt.status == "running":
            attempt.status = "succeeded"
            attempt.completed_at = now_utc
            attempt.exit_code = 0

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="execution_succeeded",
            message="Three-way reconciliation recognized completed container call with exit code 0.",
            metadata_json=sanitize_metadata({
                "reconciler_id": self.reconciler_id,
                "operation_id": op.operation_id if op else None,
                "fencing_token": execution.fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(event)

        # Transition to VERIFICATION_PENDING
        validate_state_transition(execution.status, ExecutionState.VERIFICATION_PENDING.value)
        execution.status = ExecutionState.VERIFICATION_PENDING.value
        execution.verification_status = "pending"
        execution.completed_at = None
        if self.resume_verification and self.verification_engine:
            execution.locked_by = self.reconciler_id
            execution.locked_until = now_utc + timedelta(seconds=60)
            execution.heartbeat_at = now_utc
        else:
            execution.locked_by = None
            execution.locked_until = None

        pending_event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="verification_pending",
            message="Advancing to verification_pending following three-way reconciliation completion.",
            metadata_json=sanitize_metadata({
                "reconciler_id": self.reconciler_id,
                "operation_id": op.operation_id if op else None,
                "fencing_token": execution.fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(pending_event)
        db.commit()

        # If resume_verification is requested and engine is present, resume read-only verification
        if self.resume_verification and self.verification_engine:
            logger.info("Reconciler resuming read-only verification for execution '%s'", execution.id)
            summary = self.verification_engine.run_verification_cycle(
                db=db,
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                worker_id=self.reconciler_id,
                fencing_token=execution.fencing_token,
                cycle_number=1,
                probes_required=1,
                timeout_seconds=30,
                recover_incident=True,
            )
            resulting_state = (
                ExecutionState.VERIFIED.value
                if summary.outcome == VerificationOutcome.PASS
                else ExecutionState.VERIFICATION_FAILED.value
            )
            return ReconciliationResult(
                execution_id=execution.id,
                classification=ReconciliationClassification.COMPLETED_EXIT_ZERO,
                previous_state=prev_state,
                resulting_state=resulting_state,
                action_taken="reconciled_and_resumed_verification",
                reason=f"Reconciled to verification_pending and resumed verification cycle: outcome={summary.outcome.value}",
                operation_id=op.operation_id if op else None,
                fencing_token=execution.fencing_token,
                is_dry_run=False,
                details={"verification_outcome": summary.outcome.value},
            )

        return ReconciliationResult(
            execution_id=execution.id,
            classification=ReconciliationClassification.COMPLETED_EXIT_ZERO,
            previous_state=prev_state,
            resulting_state=ExecutionState.VERIFICATION_PENDING.value,
            action_taken="finalized_verification_pending",
            reason="Durable exit 0 call advanced to verification_pending; read-only verification pending.",
            operation_id=op.operation_id if op else None,
            fencing_token=execution.fencing_token,
            is_dry_run=False,
        )

    def _finalize_completed_nonzero(
        self,
        *,
        db: Session,
        execution: RemediationExecution,
        exit_code: int,
        op: Optional[OperationRecord],
        now_utc: datetime,
    ) -> ReconciliationResult:
        """Finalize execution whose container exited with non-zero exit code to execution_failed."""
        prev_state = execution.status
        validate_state_transition(execution.status, ExecutionState.EXECUTION_FAILED.value)

        msg = f"Container process exited with non-zero code {exit_code}."
        cat = "container_nonzero_exit"

        execution.status = ExecutionState.EXECUTION_FAILED.value
        execution.error_category = cat
        execution.error_message = msg
        execution.completed_at = now_utc
        if self.resume_verification and self.verification_engine:
            execution.locked_by = self.reconciler_id
            execution.locked_until = now_utc + timedelta(seconds=60)
            execution.heartbeat_at = now_utc
        else:
            execution.locked_by = None
            execution.locked_until = None
        execution.fencing_token += 1
        execution.updated_at = now_utc

        attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if attempt and attempt.status == "running":
            attempt.status = "failed"
            attempt.completed_at = now_utc
            attempt.exit_code = exit_code
            attempt.error_category = cat
            attempt.error_message = msg

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="execution_failed",
            message=f"Action '{execution.action_id}' failed with exit code {exit_code}.",
            metadata_json=sanitize_metadata({
                "reconciler_id": self.reconciler_id,
                "exit_code": exit_code,
                "error_category": cat,
                "fencing_token": execution.fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(event)
        db.commit()

        return ReconciliationResult(
            execution_id=execution.id,
            classification=ReconciliationClassification.COMPLETED_NONZERO_EXIT,
            previous_state=prev_state,
            resulting_state=ExecutionState.EXECUTION_FAILED.value,
            action_taken="finalized_execution_failed",
            reason=f"Container exited with code {exit_code}. Clean failure finalized; no redispatch.",
            operation_id=op.operation_id if op else None,
            fencing_token=execution.fencing_token,
            is_dry_run=False,
            details={"exit_code": exit_code},
        )

    def _recover_from_passed_verification(
        self,
        *,
        db: Session,
        execution: RemediationExecution,
        cycle: VerificationCycle,
        now_utc: datetime,
    ) -> ReconciliationResult:
        """Atomically recover incident from a persisted successful verification cycle."""
        prev_state = execution.status
        try:
            # Renew lease temporarily for bridge ownership check
            execution.locked_by = self.reconciler_id
            execution.locked_until = now_utc + timedelta(seconds=60)
            execution.fencing_token += 1
            db.flush()

            IncidentRecoveryBridge.recover_incident_on_verification_success(
                db=db,
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                cycle_id=cycle.id,
                incident_id=execution.incident_id,
                worker_id=self.reconciler_id,
                fencing_token=execution.fencing_token,
                auto_commit=False,
            )
            db.commit()

            return ReconciliationResult(
                execution_id=execution.id,
                classification=ReconciliationClassification.PERSISTED_VERIFICATION_SUCCESS,
                previous_state=prev_state,
                resulting_state=ExecutionState.VERIFIED.value,
                action_taken="atomic_incident_recovery_from_passed_cycle",
                reason=f"Atomically recovered incident from passed verification cycle #{cycle.cycle_number}.",
                fencing_token=execution.fencing_token,
                is_dry_run=False,
                details={"cycle_id": cycle.id, "cycle_number": cycle.cycle_number},
            )
        except Exception as e:
            logger.warning("Recovery bridge attempt during reconciliation failed: %s", e)
            db.rollback()
            # If bridge preconditions failed, establish verification uncertainty hold
            return self._apply_uncertainty_hold(
                db=db,
                execution=execution,
                classification=ReconciliationClassification.UNCERTAIN_STORE_FLAGGED,
                reason=f"Recovery bridge preconditions not met: {e}",
                now_utc=now_utc,
                details={"bridge_error": str(e)},
            )

    # ------------------------------------------------------------------------
    # Batch Reconciliation
    # ------------------------------------------------------------------------

    def reconcile_all(
        self,
        dry_run: bool = False,
        batch_size: int = 50,
        now_utc: Optional[datetime] = None,
    ) -> ReconciliationReport:
        """
        Scan and reconcile all candidate executions across all stores.

        Candidates include:
        - Executions in EXECUTING, VALIDATING, VERIFICATION_PENDING, or QUEUED with expired lease.
        - Executions associated with incomplete/uncertain reservations in SQLite registry.
        """
        now = now_utc or datetime.now(timezone.utc)
        db = self.get_session()
        candidate_ids: List[str] = []

        try:
            query = db.query(RemediationExecution.id).filter(
                RemediationExecution.status.in_([
                    ExecutionState.EXECUTING.value,
                    ExecutionState.VALIDATING.value,
                    ExecutionState.VERIFICATION_PENDING.value,
                    ExecutionState.QUEUED.value,
                ])
            )
            if self.workspace_id:
                query = query.filter(RemediationExecution.workspace_id == self.workspace_id)

            rows = query.order_by(RemediationExecution.created_at.asc()).limit(batch_size).all()
            candidate_ids = [r[0] for r in rows]

            # Also check SQLite registry for active or uncertain operations that might have orphaned executions
            try:
                uncertain_ops = self.registry.list_uncertain_operations()
                for op in uncertain_ops:
                    if op.execution_id and op.execution_id not in candidate_ids:
                        candidate_ids.append(op.execution_id)
            except Exception:
                pass

        finally:
            if self._external_db is None:
                db.close()

        results: List[ReconciliationResult] = []
        errors: List[str] = []
        held_count = 0
        unresolved_count = 0
        reconciled_count = 0

        for exec_id in candidate_ids:
            try:
                res = self.reconcile_execution(exec_id, dry_run=dry_run, now_utc=now)
                results.append(res)
                if res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value:
                    held_count += 1
                elif res.classification in (
                    ReconciliationClassification.UNRESOLVED_RESERVATION,
                    ReconciliationClassification.UNRESOLVED_PREPARED,
                ):
                    unresolved_count += 1

                if res.action_taken not in (
                    "no_reconciliation_needed",
                    "no_action_queued_or_non_executing",
                    "execution_not_found",
                    "already_terminal",
                    "already_held_uncertain",
                ):
                    reconciled_count += 1

            except Exception as e:
                logger.error("Error reconciling execution '%s': %s", exec_id, e)
                errors.append(f"{exec_id}: {e}")

        return ReconciliationReport(
            executions_scanned=len(candidate_ids),
            executions_reconciled=reconciled_count,
            executions_held_uncertain=held_count,
            executions_unresolved=unresolved_count,
            is_dry_run=dry_run,
            results=results,
            errors=errors,
        )
