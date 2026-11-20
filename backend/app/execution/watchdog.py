"""Durable Fail-Closed Watchdog & Recovery Daemon for Phase 4.3.6 Milestone D.

Periodically scans for remediation executions and verification cycles requiring reconciliation:
1. Expired worker leases (queued, validating, executing, verification_pending).
2. Stuck executions whose workers have crashed or stopped heartbeating.
3. Expired verification cycle deadlines.
4. Preserves and establishes fail-closed uncertainty holds:
   - HOLD:EXECUTION_UNCERTAIN (mutating remediation dispatch stalled)
   - HOLD:VERIFICATION_UNCERTAIN (non-mutating verification stalled)
5. Zero-Redispatch Invariant: Never automatically redispatches remediation actions.
6. Row-level locking with FOR UPDATE SKIP LOCKED for multi-instance concurrency safety.
7. Monotonic fencing token increments on every state change to lock out zombie workers.
8. Single-transaction ACID mutations with audit event persistence.
9. Optional read-only verification resumption via PostExecutionVerificationEngine.
"""

from datetime import datetime, timedelta, timezone
import json
import logging
import signal
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from sqlalchemy import or_, and_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.execution.dispatch_coordinator import DispatchCoordinator, PreDispatchState
from app.execution.exceptions import (
    CrossWorkspaceViolationError,
    IllegalStateTransitionError,
    PreconditionFailedError,
    StaleWorkerFencingError,
    VerificationCycleNotFoundError,
    VerificationDeadlineExpiredError,
    VerificationPreconditionError,
)
from app.execution.manager import sanitize_metadata
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.registry import OperationRecord, OperationStatus
from app.execution.runner import ExecutionRunnerInterface, get_execution_runner
from app.execution.state_machine import ExecutionState, validate_state_transition
from app.execution.verification import PostExecutionVerificationEngine, VerificationOutcome
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.verification import VerificationCycle, VerificationProbeResult

logger = get_logger(__name__)

# Canonical infinite hold timestamp to block worker claims
# Year 9999 Jan 1 is chosen to prevent year 10000 overflow in positive UTC offset timezones
HOLD_EXPIRATION_TIMESTAMP = datetime(9999, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)


class ExecutionWatchdog:
    """
    Durable watchdog and reconciliation engine.
    Scans for expired leases, heartbeat loss, stuck executions, and expired deadlines,
    transitioning them safely and fail-closed into deterministic states or uncertainty holds.
    """

    def __init__(
        self,
        *,
        db_factory: Optional[Callable[[], Session]] = None,
        db: Optional[Session] = None,
        watchdog_id: Optional[str] = None,
        poll_interval: float = 5.0,
        batch_size: int = 50,
        heartbeat_timeout_seconds: float = 60.0,
        lease_grace_period_seconds: float = 0.0,
        shutdown_grace_period: float = 30.0,
        resume_verification: bool = False,
        runner: Optional[ExecutionRunnerInterface] = None,
        workspace_id: Optional[str] = None,
        coordinator: Optional[DispatchCoordinator] = None,
        verification_engine: Optional[PostExecutionVerificationEngine] = None,
    ):
        self.watchdog_id = watchdog_id or f"watchdog-{uuid.uuid4().hex[:8]}"
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
        self.poll_interval = max(0.1, poll_interval)
        self.batch_size = max(1, batch_size)
        self.heartbeat_timeout_seconds = max(1.0, heartbeat_timeout_seconds)
        self.lease_grace_period_seconds = max(0.0, lease_grace_period_seconds)
        self.shutdown_grace_period = max(1.0, shutdown_grace_period)
        self.resume_verification = resume_verification
        self.runner = runner
        self.workspace_id = workspace_id
        self.coordinator = coordinator
        self.verification_engine = verification_engine

        self._shutdown_event = threading.Event()
        self._is_running = False
        self._worker_thread: Optional[threading.Thread] = None

    def get_session(self) -> Session:
        """Provide database session (external instance or new session from factory)."""
        if self._external_db is not None:
            return self._external_db
        return self._db_factory()

    def _is_postgresql(self, session: Session) -> bool:
        """Check if session is backed by a PostgreSQL database."""
        try:
            bind = session.get_bind()
            return bind is not None and bind.dialect.name == "postgresql"
        except Exception:
            return False

    def scan_candidate_executions(
        self,
        db: Session,
        now_utc: datetime,
    ) -> List[str]:
        """
        Scan and lock candidates requiring watchdog reconciliation.
        Uses FOR UPDATE SKIP LOCKED on PostgreSQL to prevent contention across instances.
        Returns a list of candidate execution IDs.
        """
        lease_cutoff = now_utc - timedelta(seconds=self.lease_grace_period_seconds)
        heartbeat_cutoff = now_utc - timedelta(seconds=self.heartbeat_timeout_seconds)

        # Base query for remediation executions
        query = db.query(RemediationExecution.id)

        # Workspace isolation scoping if configured
        if self.workspace_id:
            query = query.filter(RemediationExecution.workspace_id == self.workspace_id)

        # Candidate criteria:
        # 1. In-flight with expired lease
        c1_expired_lease = and_(
            RemediationExecution.status.in_([
                ExecutionState.QUEUED.value,
                ExecutionState.VALIDATING.value,
                ExecutionState.EXECUTING.value,
                ExecutionState.VERIFICATION_PENDING.value,
            ]),
            RemediationExecution.locked_by.isnot(None),
            ~RemediationExecution.locked_by.like("HOLD:%"),
            ~RemediationExecution.locked_by.like("RESERVED:%"),
            RemediationExecution.locked_until < lease_cutoff,
        )

        # 2. In-flight with lost heartbeat (heartbeat_at older than cutoff)
        c2_lost_heartbeat = and_(
            RemediationExecution.status.in_([
                ExecutionState.VALIDATING.value,
                ExecutionState.EXECUTING.value,
                ExecutionState.VERIFICATION_PENDING.value,
            ]),
            RemediationExecution.locked_by.isnot(None),
            ~RemediationExecution.locked_by.like("HOLD:%"),
            RemediationExecution.heartbeat_at.isnot(None),
            RemediationExecution.heartbeat_at < heartbeat_cutoff,
        )

        # 3. Queued execution with expired approval
        c3_expired_approval = and_(
            RemediationExecution.status == ExecutionState.QUEUED.value,
            RemediationExecution.approval_id.isnot(None),
            RemediationExecution.approval.has(RemediationApproval.expires_at < now_utc),
        )

        # 4. Verification pending with expired verification cycle deadline
        c4_expired_cycle = and_(
            RemediationExecution.status == ExecutionState.VERIFICATION_PENDING.value,
            RemediationExecution.verification_cycles.any(
                and_(
                    VerificationCycle.status.in_(["pending", "running"]),
                    VerificationCycle.deadline_at < now_utc,
                )
            ),
        )

        query = query.filter(
            or_(
                c1_expired_lease,
                c2_lost_heartbeat,
                c3_expired_approval,
                c4_expired_cycle,
            )
        )

        # Row-level locking
        if self._is_postgresql(db):
            query = query.with_for_update(skip_locked=True)
        else:
            query = query.with_for_update()

        query = query.order_by(RemediationExecution.created_at.asc()).limit(self.batch_size)
        rows = query.all()
        return [r[0] for r in rows]

    def reconcile_execution(
        self,
        db: Any,
        execution_id: Optional[str] = None,
        now_utc: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Reconcile a single candidate execution atomically under row lock.
        Validates state, workspace, lease, and fencing token. Rolls back on error.
        Supports both signatures:
        - reconcile_execution(db, execution_id, now_utc=...)
        - reconcile_execution(execution_id, now_utc=...)
        """
        if isinstance(db, str) and execution_id is None:
            actual_exec_id = db
            session = self.get_session()
            try:
                return self.reconcile_execution(session, actual_exec_id, now_utc)
            finally:
                if self._external_db is None:
                    session.close()

        actual_db: Session = db
        actual_exec_id: str = execution_id
        now = now_utc or datetime.now(timezone.utc)

        try:
            # 1. Fetch and row-lock the execution
            query = actual_db.query(RemediationExecution).filter(RemediationExecution.id == actual_exec_id)
            if self._is_postgresql(actual_db):
                query = query.with_for_update(skip_locked=True)
            else:
                query = query.with_for_update()

            execution = query.first()
            if not execution:
                # Row already processed, locked by another watchdog, or deleted
                return None

            # Workspace isolation validation
            if self.workspace_id and execution.workspace_id != self.workspace_id:
                raise CrossWorkspaceViolationError(
                    f"Cross-workspace violation: Execution belongs to '{execution.workspace_id}', not '{self.workspace_id}'."
                )

            # If already in an uncertainty hold, no further reconciliation needed
            if execution.locked_by and execution.locked_by.startswith("HOLD:"):
                logger.info(
                    "Watchdog skipping already-held uncertainty execution",
                    extra={
                        "execution_id": execution.id,
                        "workspace_id": execution.workspace_id,
                        "hold_type": execution.locked_by,
                        "uncertain_reason": execution.uncertain_reason,
                    },
                )
                return None

            prev_state = execution.status
            prev_worker = execution.locked_by

            result_info: Optional[Dict[str, Any]] = None

            # Dispatch reconciliation based on execution state
            if execution.status == ExecutionState.QUEUED.value:
                result_info = self._reconcile_queued(actual_db, execution, now)

            elif execution.status == ExecutionState.VALIDATING.value:
                result_info = self._reconcile_validating(actual_db, execution, now)

            elif execution.status == ExecutionState.EXECUTING.value:
                result_info = self._reconcile_executing(actual_db, execution, now)

            elif execution.status == ExecutionState.VERIFICATION_PENDING.value:
                result_info = self._reconcile_verification_pending(actual_db, execution, now)

            elif execution.status == ExecutionState.EXECUTION_UNCERTAIN.value:
                result_info = self._reconcile_already_uncertain(actual_db, execution, now)

            else:
                # Terminal or non-candidate state
                return None

            if result_info is not None:
                actual_db.commit()
                logger.info(
                    "Watchdog successfully reconciled execution",
                    extra={
                        "execution_id": execution.id,
                        "workspace_id": execution.workspace_id,
                        "previous_state": prev_state,
                        "resulting_state": result_info.get("resulting_state"),
                        "previous_worker": prev_worker,
                        "reconciliation_reason": result_info.get("reason"),
                        "fencing_token": execution.fencing_token,
                    },
                )

            return result_info

        except Exception as e:
            actual_db.rollback()
            logger.error(
                "Watchdog reconciliation failed for execution '%s': %s",
                actual_exec_id,
                str(e),
                exc_info=True,
            )
            raise e

    # ------------------------------------------------------------------------
    # State-Specific Reconciliation Handlers
    # ------------------------------------------------------------------------

    def _reconcile_queued(
        self,
        db: Session,
        execution: RemediationExecution,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """
        Reconcile execution stuck in QUEUED:
        - If approval expired: transition to CANCELLED.
        - If lease expired on queued job: clear worker lock, increment fencing token.
        """
        # Check approval expiration
        if execution.approval and execution.approval.expires_at:
            exp = execution.approval.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now_utc:
                validate_state_transition(execution.status, ExecutionState.CANCELLED.value)
                execution.status = ExecutionState.CANCELLED.value
                execution.locked_by = None
                execution.locked_until = None
                execution.fencing_token += 1
                execution.completed_at = now_utc
                execution.updated_at = now_utc
                execution.error_category = "approval_expired_in_queue"
                execution.error_message = (
                    f"Remediation approval '{execution.approval_id}' expired at {exp.isoformat()} "
                    "while execution was waiting in queue."
                )

                event = ExecutionEvent(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    workspace_id=execution.workspace_id,
                    event_type="approval_expired_cancelled",
                    message=execution.error_message,
                    metadata_json=sanitize_metadata({
                        "watchdog_id": self.watchdog_id,
                        "approval_id": execution.approval_id,
                        "fencing_token": execution.fencing_token,
                        "status": ExecutionState.CANCELLED.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(event)

                return {
                    "execution_id": execution.id,
                    "previous_state": ExecutionState.QUEUED.value,
                    "resulting_state": ExecutionState.CANCELLED.value,
                    "action": "cancelled_due_to_expired_approval",
                    "reason": execution.error_message,
                }

        # Expired worker claim on queued execution
        prev_worker = execution.locked_by
        execution.locked_by = None
        execution.locked_until = None
        execution.fencing_token += 1
        execution.updated_at = now_utc

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="lease_cleared_queued",
            message=f"Watchdog cleared expired worker lease from '{prev_worker}' in queued state.",
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "cleared_worker": prev_worker,
                "fencing_token": execution.fencing_token,
                "status": ExecutionState.QUEUED.value,
            }),
            timestamp=now_utc,
        )
        db.add(event)

        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.QUEUED.value,
            "resulting_state": ExecutionState.QUEUED.value,
            "action": "cleared_expired_queue_lease",
            "reason": f"Worker '{prev_worker}' lease expired in queued state.",
        }

    def _reconcile_validating(
        self,
        db: Session,
        execution: RemediationExecution,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """
        Reconcile execution stuck in VALIDATING:
        Worker crashed or stopped heartbeating before container dispatch.
        Fail-closed: transition to EXECUTION_FAILED (never automatically redispatched).
        If coordinator is active:
        - Check if durable start marker or uncertainty exists -> HOLD:EXECUTION_UNCERTAIN
        - Check if unresolved pre-dispatch reservation exists -> HOLD:EXECUTION_UNCERTAIN
        """
        if self.coordinator:
            op = self.coordinator.registry.get_by_execution_and_token(
                execution.id, execution.fencing_token
            )
            if not op and execution.approval_id:
                op = self.coordinator.registry.get_by_approval(execution.approval_id)

            if op:
                if op.operation_status in (
                    OperationStatus.DOCKER_CALL_STARTED,
                    OperationStatus.DOCKER_CALL_CONFIRMED,
                    OperationStatus.DISPATCH_UNCERTAIN,
                ):
                    reason = (
                        f"WATCHDOG_LEASE_EXPIRED_DURING_VALIDATION: Operation has durable start marker or uncertain status "
                        f"('{op.operation_status.value}'). Redispatch is strictly forbidden."
                    )
                    return self._establish_execution_uncertain_hold(db, execution, now_utc, reason)

                eval_res = self.coordinator.evaluate_pre_dispatch_state(op.operation_id)
                if eval_res.state in (
                    PreDispatchState.UNRESOLVED_RESERVED,
                    PreDispatchState.UNRESOLVED_PREPARED,
                    PreDispatchState.UNCERTAINTY_HOLD,
                ):
                    reason = (
                        f"WATCHDOG_UNRESOLVED_PRE_DISPATCH: Operation '{op.operation_id}' is in unresolved pre-dispatch "
                        f"state '{eval_res.state.value}'. Absence of start marker does not prove non-invocation without "
                        f"Revision 10 physical proof (missing: {eval_res.missing_proof_conditions}). Redispatch forbidden."
                    )
                    return self._establish_execution_uncertain_hold(db, execution, now_utc, reason)

        prev_worker = execution.locked_by
        validate_state_transition(execution.status, ExecutionState.EXECUTION_FAILED.value)

        execution.status = ExecutionState.EXECUTION_FAILED.value
        execution.locked_by = None
        execution.locked_until = None
        execution.fencing_token += 1
        execution.completed_at = now_utc
        execution.updated_at = now_utc
        execution.error_category = "worker_crash_during_validation"
        execution.error_message = (
            f"Worker '{prev_worker}' lease expired during pre-flight validation before container dispatch."
        )

        # Update active attempt to failed if present
        active_attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if active_attempt and active_attempt.status == "running":
            active_attempt.status = "failed"
            active_attempt.completed_at = now_utc
            active_attempt.error_category = "worker_crash_during_validation"
            active_attempt.error_message = execution.error_message

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="validation_timeout_failed",
            message=execution.error_message,
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "recovered_from_worker": prev_worker,
                "fencing_token": execution.fencing_token,
                "status": ExecutionState.EXECUTION_FAILED.value,
            }),
            timestamp=now_utc,
        )
        db.add(event)

        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.VALIDATING.value,
            "resulting_state": ExecutionState.EXECUTION_FAILED.value,
            "action": "failed_due_to_validation_timeout",
            "reason": execution.error_message,
        }

    def _reconcile_executing(
        self,
        db: Session,
        execution: RemediationExecution,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """
        Reconcile execution stuck in EXECUTING:
        Worker lease expired while in-flight after container dispatch was authorized.
        Physical dispatch outcome is indeterminate unless completed in coordinator.
        Mandatory safety rule: establish HOLD:EXECUTION_UNCERTAIN.
        Never automatically redispatch.
        """
        if self.coordinator:
            op = self.coordinator.registry.get_by_execution_and_token(
                execution.id, execution.fencing_token
            )
            if not op and execution.approval_id:
                op = self.coordinator.registry.get_by_approval(execution.approval_id)

            if op and op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED:
                return self._reconcile_completed_broker_call(db, execution, op, now_utc)
            elif op and op.operation_status == OperationStatus.DISPATCH_FAILED:
                return self._reconcile_failed_broker_call(db, execution, op, now_utc)

        prev_worker = execution.locked_by
        reason = (
            f"WATCHDOG_LEASE_EXPIRED_AFTER_DISPATCH: Worker '{prev_worker}' lease expired while in-flight "
            "in 'executing' state. Container dispatch outcome is uncertain; blind duplicate execution prevented."
        )
        return self._establish_execution_uncertain_hold(db, execution, now_utc, reason)

    def _establish_execution_uncertain_hold(
        self,
        db: Session,
        execution: RemediationExecution,
        now_utc: datetime,
        reason: str,
        category: str = "worker_crash_after_dispatch",
    ) -> Dict[str, Any]:
        """Establish fail-closed HOLD:EXECUTION_UNCERTAIN locking out any automatic re-runs."""
        prev_worker = execution.locked_by
        validate_state_transition(execution.status, ExecutionState.EXECUTION_UNCERTAIN.value)

        execution.status = ExecutionState.EXECUTION_UNCERTAIN.value
        execution.locked_by = "HOLD:EXECUTION_UNCERTAIN"
        execution.locked_until = HOLD_EXPIRATION_TIMESTAMP
        execution.fencing_token += 1
        execution.completed_at = now_utc
        execution.updated_at = now_utc
        execution.error_category = category
        execution.uncertain_reason = reason

        # Store hold metadata
        output_meta = execution.execution_output or {}
        output_meta["uncertainty_hold"] = {
            "hold_type": "HOLD:EXECUTION_UNCERTAIN",
            "hold_reason": reason,
            "held_at": now_utc.isoformat(),
            "original_worker_id": prev_worker,
            "fenced_fencing_token": execution.fencing_token,
            "watchdog_id": self.watchdog_id,
        }
        execution.execution_output = sanitize_metadata(output_meta)

        # Update active attempt to uncertain
        active_attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if active_attempt and active_attempt.status == "running":
            active_attempt.status = "uncertain"
            active_attempt.completed_at = now_utc
            active_attempt.error_category = category
            active_attempt.error_message = reason

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="lease_recovery_post_dispatch_uncertain",
            message=reason,
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "recovered_from_worker": prev_worker,
                "fencing_token": execution.fencing_token,
                "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                "hold_type": "HOLD:EXECUTION_UNCERTAIN",
            }),
            timestamp=now_utc,
        )
        db.add(event)

        # Record IncidentEvent (incident is NOT recovered; remains active)
        if execution.incident_id:
            inc_event = IncidentEvent(
                id=str(uuid.uuid4()),
                incident_id=execution.incident_id,
                event_type="action",
                message=(
                    f"Remediation execution '{execution.id}' marked uncertain after worker '{prev_worker}' "
                    "lease expired. Duplicate execution prevented; incident remains active."
                ),
                metadata_json=json.dumps(
                    sanitize_metadata({
                        "execution_id": execution.id,
                        "action_id": execution.action_id,
                        "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                        "watchdog_id": self.watchdog_id,
                    })
                ),
                timestamp=now_utc,
            )
            db.add(inc_event)

        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.EXECUTING.value,
            "resulting_state": ExecutionState.EXECUTION_UNCERTAIN.value,
            "action": "established_execution_uncertain_hold",
            "reason": reason,
        }

    def _reconcile_completed_broker_call(
        self,
        db: Session,
        execution: RemediationExecution,
        op: OperationRecord,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """
        Reconcile an execution whose broker container already completed with exit code 0 before crash.

        Strict Safety Contract:
        1. A durable DOCKER_CALL_COMPLETED record must never trigger another BrokerDispatcher or Docker request.
        2. Reconciles existing completion result into PostgreSQL (EXECUTION_SUCCEEDED -> VERIFICATION_PENDING).
        3. Preserves original operation identity; does not create any new dispatch operations or start markers.
        4. If resume_verification=True, resumes read-only verification workflow (diagnostic probes only).
        5. Incident recovery remains exclusively controlled by IncidentRecoveryBridge after successful verification.
        """
        prev_worker = execution.locked_by
        validate_state_transition(execution.status, ExecutionState.EXECUTION_SUCCEEDED.value)

        execution.status = ExecutionState.EXECUTION_SUCCEEDED.value
        execution.completed_at = now_utc
        execution.fencing_token += 1
        execution.updated_at = now_utc
        execution.execution_output = sanitize_metadata(op.metadata.get("output_data") or {})

        active_attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if active_attempt and active_attempt.status == "running":
            active_attempt.status = "succeeded"
            active_attempt.completed_at = now_utc
            active_attempt.exit_code = 0

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="execution_succeeded",
            message=(
                f"Watchdog recognized completed broker call from coordinator for operation '{op.operation_id}'. "
                "Advancing execution state."
            ),
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "operation_id": op.operation_id,
                "fencing_token": execution.fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(event)

        # Transition immediately to VERIFICATION_PENDING
        validate_state_transition(execution.status, ExecutionState.VERIFICATION_PENDING.value)
        execution.status = ExecutionState.VERIFICATION_PENDING.value
        execution.verification_status = "pending"
        execution.completed_at = None
        execution.locked_by = None
        execution.locked_until = None

        pending_event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="verification_pending",
            message="Advancing to verification_pending following coordinator completion recovery.",
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "operation_id": op.operation_id,
                "fencing_token": execution.fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(pending_event)

        if self.resume_verification:
            return self._reconcile_verification_pending(db, execution, now_utc)

        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.EXECUTING.value,
            "resulting_state": ExecutionState.VERIFICATION_PENDING.value,
            "action": "reconciled_completed_broker_call",
            "reason": f"Durable completed call for '{op.operation_id}' advanced to verification_pending.",
        }

    def _reconcile_failed_broker_call(
        self,
        db: Session,
        execution: RemediationExecution,
        op: OperationRecord,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """Reconcile an execution whose broker container exited with non-zero exit code before crash."""
        prev_worker = execution.locked_by
        validate_state_transition(execution.status, ExecutionState.EXECUTION_FAILED.value)

        msg = op.metadata.get("error_message") or "Process exited with non-zero exit code."
        cat = op.metadata.get("error_category") or "container_exit_nonzero"
        exit_code = op.metadata.get("exit_code", 1)

        execution.status = ExecutionState.EXECUTION_FAILED.value
        execution.error_category = cat
        execution.error_message = msg
        execution.completed_at = now_utc
        execution.locked_by = None
        execution.locked_until = None
        execution.fencing_token += 1
        execution.updated_at = now_utc

        active_attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution.id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )
        if active_attempt and active_attempt.status == "running":
            active_attempt.status = "failed"
            active_attempt.completed_at = now_utc
            active_attempt.error_category = cat
            active_attempt.error_message = msg
            active_attempt.exit_code = exit_code

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="execution_failed",
            message=f"Watchdog recognized non-zero broker exit for operation '{op.operation_id}': {msg}",
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "operation_id": op.operation_id,
                "exit_code": exit_code,
                "fencing_token": execution.fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(event)

        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.EXECUTING.value,
            "resulting_state": ExecutionState.EXECUTION_FAILED.value,
            "action": "reconciled_failed_broker_call",
            "reason": msg,
        }

    def _reconcile_verification_pending(
        self,
        db: Session,
        execution: RemediationExecution,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """
        Reconcile execution stuck in VERIFICATION_PENDING:
        1. If verification cycle already passed before crash: atomically recover incident via recovery bridge.
        2. If verification cycle deadline expired: mark cycle timed_out, execution verification_failed.
        3. If deadline not expired, but worker lease expired:
           - If resume_verification=True: claim and run read-only verification cycle.
           - Else: establish HOLD:VERIFICATION_UNCERTAIN (fail-closed, no auto-recovery).
        """
        prev_worker = execution.locked_by

        # Fetch latest verification cycle
        cycle = (
            db.query(VerificationCycle)
            .filter(VerificationCycle.execution_id == execution.id)
            .order_by(VerificationCycle.cycle_number.desc())
            .first()
        )

        # --------------------------------------------------------------------
        # Branch 1: Cycle already completed successfully before worker died
        # --------------------------------------------------------------------
        if cycle and cycle.status == "passed":
            cycle_meta = cycle.cycle_metadata or {}
            outcome = cycle_meta.get("outcome")
            if outcome in (VerificationOutcome.PASS.value, "PASS"):
                try:
                    # Renew lease for watchdog coordinator to satisfy recovery bridge lease check
                    execution.locked_by = self.watchdog_id
                    execution.locked_until = now_utc + timedelta(seconds=60)
                    execution.fencing_token += 1
                    db.flush()

                    res_exec, res_inc = IncidentRecoveryBridge.recover_incident_on_verification_success(
                        db=db,
                        execution_id=execution.id,
                        workspace_id=execution.workspace_id,
                        cycle_id=cycle.id,
                        incident_id=execution.incident_id,
                        worker_id=self.watchdog_id,
                        fencing_token=execution.fencing_token,
                        auto_commit=False,
                    )
                    return {
                        "execution_id": execution.id,
                        "previous_state": ExecutionState.VERIFICATION_PENDING.value,
                        "resulting_state": ExecutionState.VERIFIED.value,
                        "action": "atomic_incident_recovery_from_passed_cycle",
                        "reason": f"Watchdog completed pending recovery for passed cycle #{cycle.cycle_number}.",
                    }
                except Exception as rec_err:
                    logger.warning("Recovery bridge attempt during watchdog failed: %s", str(rec_err))

        # --------------------------------------------------------------------
        # Branch 2: Cycle deadline expired
        # --------------------------------------------------------------------
        cycle_deadline_expired = False
        if cycle:
            deadline = cycle.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            if now_utc > deadline:
                cycle_deadline_expired = True

        if cycle_deadline_expired and cycle is not None:
            cycle.status = "timed_out"
            cycle.completed_at = now_utc
            cycle.updated_at = now_utc

            validate_state_transition(execution.status, ExecutionState.VERIFICATION_FAILED.value)
            reason = (
                f"WATCHDOG_VERIFICATION_DEADLINE_EXPIRED: Verification cycle #{cycle.cycle_number} "
                f"deadline ({cycle.deadline_at.isoformat()}) expired without confirming required consecutive passes."
            )

            execution.status = ExecutionState.VERIFICATION_FAILED.value
            execution.verification_status = "failed"
            execution.locked_by = None
            execution.locked_until = None
            execution.fencing_token += 1
            execution.completed_at = now_utc
            execution.updated_at = now_utc
            execution.error_category = "verification_deadline_expired"
            execution.error_message = reason
            execution.uncertain_reason = reason

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                event_type="verification_failed",
                message=reason,
                metadata_json=sanitize_metadata({
                    "watchdog_id": self.watchdog_id,
                    "cycle_id": cycle.id,
                    "cycle_number": cycle.cycle_number,
                    "fencing_token": execution.fencing_token,
                    "status": ExecutionState.VERIFICATION_FAILED.value,
                }),
                timestamp=now_utc,
            )
            db.add(event)

            # Incident remains active (remediating / verifying) - NEVER recovered
            return {
                "execution_id": execution.id,
                "previous_state": ExecutionState.VERIFICATION_PENDING.value,
                "resulting_state": ExecutionState.VERIFICATION_FAILED.value,
                "action": "failed_due_to_verification_deadline_expired",
                "reason": reason,
            }

        # --------------------------------------------------------------------
        # Branch 3: Read-only verification resumption (if enabled & unexpired)
        # --------------------------------------------------------------------
        if self.resume_verification and not cycle_deadline_expired:
            # Resume read-only verification checks using PostExecutionVerificationEngine
            logger.info("Watchdog attempting read-only verification resumption for execution '%s'", execution.id)
            effective_runner = self.runner or get_execution_runner()
            engine = self.verification_engine or PostExecutionVerificationEngine(runner=effective_runner)

            # Claim lease for watchdog
            execution.locked_by = self.watchdog_id
            execution.locked_until = now_utc + timedelta(seconds=60)
            execution.heartbeat_at = now_utc
            execution.fencing_token += 1
            db.flush()

            next_cycle_num = (cycle.cycle_number + 1) if cycle is not None else 1
            probes_req = cycle.probes_required if cycle is not None else 1

            summary = engine.run_verification_cycle(
                db=db,
                execution_id=execution.id,
                workspace_id=execution.workspace_id,
                cycle_number=next_cycle_num,
                probes_required=probes_req,
                timeout_seconds=30,
                worker_id=self.watchdog_id,
                fencing_token=execution.fencing_token,
                runner=effective_runner,
                recover_incident=True,
            )

            res_state = (
                ExecutionState.VERIFIED.value
                if summary.outcome == VerificationOutcome.PASS
                else ExecutionState.VERIFICATION_FAILED.value
            )
            return {
                "execution_id": execution.id,
                "previous_state": ExecutionState.VERIFICATION_PENDING.value,
                "resulting_state": res_state,
                "action": "resumed_read_only_verification",
                "outcome": summary.outcome.value,
                "reason": f"Watchdog executed verification cycle #{next_cycle_num} with outcome '{summary.outcome.value}'.",
            }

        # --------------------------------------------------------------------
        # Branch 4: Establish HOLD:VERIFICATION_UNCERTAIN (fail-closed default)
        # --------------------------------------------------------------------
        reason = (
            f"WATCHDOG_LEASE_EXPIRED_DURING_VERIFICATION_PROBES: Worker '{prev_worker}' lease expired "
            "while post-execution verification was pending."
        )

        execution.locked_by = "HOLD:VERIFICATION_UNCERTAIN"
        execution.locked_until = HOLD_EXPIRATION_TIMESTAMP
        execution.fencing_token += 1
        execution.uncertain_reason = reason
        execution.verification_status = "uncertain"
        execution.updated_at = now_utc

        if cycle and cycle.status in ("pending", "running"):
            cycle.status = "uncertain"
            cycle.completed_at = now_utc
            cycle.updated_at = now_utc

        # Record uncertainty hold metadata in verification_output
        out_meta = execution.verification_output or {}
        out_meta["uncertainty_hold"] = {
            "hold_type": "HOLD:VERIFICATION_UNCERTAIN",
            "hold_reason": "WATCHDOG_LEASE_EXPIRED_DURING_VERIFICATION_PROBES",
            "held_at": now_utc.isoformat(),
            "original_worker_id": prev_worker,
            "fenced_fencing_token": execution.fencing_token,
            "watchdog_id": self.watchdog_id,
        }
        execution.verification_output = sanitize_metadata(out_meta)

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="verification_uncertain",
            message=reason,
            metadata_json=sanitize_metadata({
                "watchdog_id": self.watchdog_id,
                "recovered_from_worker": prev_worker,
                "fencing_token": execution.fencing_token,
                "status": execution.status,
                "hold_type": "HOLD:VERIFICATION_UNCERTAIN",
            }),
            timestamp=now_utc,
        )
        db.add(event)

        # Incident is NOT recovered; remains active
        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.VERIFICATION_PENDING.value,
            "resulting_state": ExecutionState.VERIFICATION_PENDING.value,
            "action": "established_verification_uncertain_hold",
            "reason": reason,
        }

    def _reconcile_already_uncertain(
        self,
        db: Session,
        execution: RemediationExecution,
        now_utc: datetime,
    ) -> Dict[str, Any]:
        """
        Preserve existing EXECUTION_UNCERTAIN state:
        Never converts execution_uncertain into a retry or success.
        Ensures locked_by remains HOLD:EXECUTION_UNCERTAIN.
        """
        if execution.locked_by != "HOLD:EXECUTION_UNCERTAIN":
            execution.locked_by = "HOLD:EXECUTION_UNCERTAIN"
            execution.locked_until = HOLD_EXPIRATION_TIMESTAMP
            execution.updated_at = now_utc

        return {
            "execution_id": execution.id,
            "previous_state": ExecutionState.EXECUTION_UNCERTAIN.value,
            "resulting_state": ExecutionState.EXECUTION_UNCERTAIN.value,
            "action": "preserved_execution_uncertainty",
            "reason": "Execution remains held in uncertainty; awaiting operator attestation or manual resolution.",
        }

    # ------------------------------------------------------------------------
    # Polling Loop & Daemon Lifecycle
    # ------------------------------------------------------------------------

    def run_once(self) -> int:
        """
        Execute a single reconciliation sweep.
        Returns the number of executions reconciled.
        """
        now_utc = datetime.now(timezone.utc)
        reconciled_count = 0

        session = self.get_session()
        try:
            candidate_ids = self.scan_candidate_executions(session, now_utc)
            if not candidate_ids:
                return 0

            logger.info("Watchdog candidate scan found %d executions", len(candidate_ids))

            for eid in candidate_ids:
                try:
                    res = self.reconcile_execution(session, eid, now_utc)
                    if res is not None:
                        reconciled_count += 1
                except Exception as rec_err:
                    logger.error("Error reconciling candidate '%s': %s", eid, str(rec_err))
                    # Continue reconciling remaining candidates

            return reconciled_count

        finally:
            if self._external_db is None:
                session.close()

    def run_forever(self) -> None:
        """
        Run continuous reconciliation loop until shutdown signal.
        """
        self._is_running = True
        logger.info(
            "ExecutionWatchdog started daemon loop (ID: %s, poll_interval: %.1fs, batch_size: %d)",
            self.watchdog_id,
            self.poll_interval,
            self.batch_size,
        )

        while not self._shutdown_event.is_set():
            try:
                self.run_once()
            except Exception as loop_err:
                logger.error("Watchdog sweep error: %s", str(loop_err), exc_info=True)

            self._shutdown_event.wait(timeout=self.poll_interval)

        self._is_running = False
        logger.info("ExecutionWatchdog daemon loop terminated gracefully (ID: %s).", self.watchdog_id)

    def start(self) -> None:
        """Start watchdog daemon in background thread."""
        if self._worker_thread is not None and self._worker_thread.is_alive():
            logger.warning("ExecutionWatchdog thread is already running.")
            return

        self._shutdown_event.clear()
        self._worker_thread = threading.Thread(
            target=self.run_forever,
            name=f"WatchdogThread-{self.watchdog_id}",
            daemon=True,
        )
        self._worker_thread.start()

    def stop(self) -> None:
        """Signal shutdown and wait up to shutdown_grace_period."""
        self._shutdown_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=self.shutdown_grace_period)
        self._is_running = False
