"""Atomic Incident Recovery Bridge for Phase 4.3.6 Milestone C.

Orchestrates the atomic integration between remediation verification and incident recovery:
1. Atomically updates RemediationExecution to VERIFIED and associated Incident to RECOVERED.
2. Populates incident.recovered_at timestamp.
3. Persists audit events (ExecutionEvent type 'verified', IncidentEvent type 'verification')
   inside the exact same database transaction.
4. Enforces row-level locking (with_for_update) on both execution and incident rows.
5. Strict validation:
   - Workspace isolation
   - Exact incident association (execution.incident_id == incident.id)
   - Service association (execution.target_service_id == incident.service_id)
   - Monotonic fencing token validation
   - Worker lease and identity check
   - Verification cycle status == 'passed', outcome == 'PASS'
   - Probe sequence validation (Probe 1 baseline, required consecutive passing probes)
   - Cycle deadline bound (must not be expired)
   - Incident lifecycle (already closed incidents cannot be overwritten)
6. Full ACID rollback guarantee: any validation or database failure rolls back all changes.
7. Idempotent finalization: repeated finalization with the same verified result is safe and idempotent.
"""

from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.execution.exceptions import (
    CrossWorkspaceViolationError,
    IncidentAssociationMismatchError,
    IncidentRecoveryError,
    PreconditionFailedError,
    StaleWorkerFencingError,
    VerificationCycleNotFoundError,
    VerificationDeadlineExpiredError,
    VerificationPreconditionError,
)
from app.execution.manager import sanitize_metadata
from app.execution.state_machine import ExecutionState
from app.execution.verification import VerificationOutcome
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import ExecutionEvent, RemediationExecution
from app.models.verification import VerificationCycle, VerificationProbeResult

logger = logging.getLogger(__name__)

# Active incident states eligible for recovery
RECOVERABLE_INCIDENT_STATUSES = {
    "detected",
    "investigating",
    "awaiting_approval",
    "investigation_failed",
    "remediating",
    "verifying",
}


class IncidentRecoveryBridge:
    """Atomic bridge between verified remediation execution and incident recovery."""

    @classmethod
    def recover_incident_on_verification_success(
        cls,
        *,
        db: Session,
        execution_id: str,
        workspace_id: str,
        cycle_id: str,
        incident_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        auto_commit: bool = True,
    ) -> Tuple[RemediationExecution, Optional[Incident]]:
        """
        Atomically transition execution to VERIFIED and incident to RECOVERED in one ACID transaction.
        Enforces strict row-level locking, fencing validation, cycle probe rechecking,
        and workspace isolation. Rolls back on any error.
        """
        now_utc = datetime.now(timezone.utc)

        try:
            # 1. Fetch and row-lock the RemediationExecution
            execution = (
                db.query(RemediationExecution)
                .filter(RemediationExecution.id == execution_id)
                .with_for_update()
                .first()
            )
            if not execution:
                raise PreconditionFailedError(f"Remediation execution '{execution_id}' does not exist.")

            # Workspace isolation
            if execution.workspace_id != workspace_id:
                raise CrossWorkspaceViolationError(
                    f"Cross-workspace violation: Execution belongs to workspace '{execution.workspace_id}', not '{workspace_id}'."
                )

            # Monotonic fencing token validation
            expected_token = fencing_token if fencing_token is not None else execution.fencing_token
            if execution.fencing_token != expected_token:
                raise StaleWorkerFencingError(
                    f"Stale worker fencing token: execution has {execution.fencing_token}, expected {expected_token}."
                )

            # Worker identity validation
            if worker_id is not None and execution.locked_by and execution.locked_by != worker_id:
                raise StaleWorkerFencingError(
                    f"Execution is locked by worker '{execution.locked_by}', not '{worker_id}'."
                )

            # Worker lease expiration validation
            if execution.locked_until:
                locked_until = execution.locked_until
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)
                if locked_until < now_utc:
                    raise StaleWorkerFencingError(
                        f"Worker lease expired at {locked_until.isoformat()} (current time {now_utc.isoformat()}). "
                        "Cannot finalize recovery with an expired lease."
                    )

            # Execution state check: execution must be in verification_pending (or verified for idempotent replay)
            if execution.status not in (ExecutionState.VERIFICATION_PENDING.value, ExecutionState.VERIFIED.value):
                raise VerificationPreconditionError(
                    f"Cannot recover incident: execution '{execution_id}' is in status '{execution.status}', "
                    f"expected '{ExecutionState.VERIFICATION_PENDING.value}'. Execution success alone must never recover an incident."
                )

            # 2. Fetch and row-lock the VerificationCycle
            cycle = (
                db.query(VerificationCycle)
                .filter(VerificationCycle.id == cycle_id)
                .with_for_update()
                .first()
            )
            if not cycle:
                raise VerificationCycleNotFoundError(f"Verification cycle '{cycle_id}' does not exist.")

            if cycle.execution_id != execution.id:
                raise VerificationPreconditionError(
                    f"Verification cycle '{cycle_id}' belongs to execution '{cycle.execution_id}', not '{execution.id}'."
                )
            if cycle.workspace_id != workspace_id:
                raise CrossWorkspaceViolationError(
                    f"Cross-workspace violation: Verification cycle belongs to workspace '{cycle.workspace_id}', not '{workspace_id}'."
                )

            # Verification cycle status and outcome validation
            if cycle.status != "passed":
                raise VerificationPreconditionError(
                    f"Cannot recover incident: verification cycle '{cycle_id}' status is '{cycle.status}', not 'passed'. "
                    "Failed or inconclusive verification must never recover an incident."
                )

            cycle_meta = cycle.cycle_metadata or {}
            cycle_outcome = cycle_meta.get("outcome")
            if cycle_outcome != VerificationOutcome.PASS.value and cycle_outcome != "PASS":
                raise VerificationPreconditionError(
                    f"Cannot recover incident: verification cycle outcome is '{cycle_outcome}', not 'PASS'."
                )

            # Cycle deadline validation
            deadline = cycle.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            completion_time = cycle.completed_at or now_utc
            if completion_time.tzinfo is None:
                completion_time = completion_time.replace(tzinfo=timezone.utc)

            if completion_time > deadline:
                raise VerificationDeadlineExpiredError(
                    f"Cannot recover incident: verification cycle deadline ({deadline.isoformat()}) "
                    f"expired before completion ({completion_time.isoformat()})."
                )

            # Recheck probe sequence integrity
            probes = (
                db.query(VerificationProbeResult)
                .filter(VerificationProbeResult.cycle_id == cycle.id)
                .order_by(VerificationProbeResult.probe_number.asc())
                .all()
            )
            if not probes:
                raise VerificationPreconditionError(f"Verification cycle '{cycle_id}' contains zero probe records.")

            # Probe 1 must be passed baseline
            probe1 = probes[0]
            if probe1.probe_number != 1 or probe1.probe_type != "baseline" or not probe1.passed:
                raise VerificationPreconditionError(
                    f"Verification cycle '{cycle_id}' invalid: Probe 1 is not a passed baseline probe."
                )

            # Probes 2..N must satisfy required consecutive passes
            consecutive = 0
            max_consecutive = 0
            for p in probes[1:]:
                if p.passed and p.status == "passed":
                    consecutive += 1
                    if consecutive > max_consecutive:
                        max_consecutive = consecutive
                else:
                    consecutive = 0

            if max_consecutive < cycle.probes_required:
                raise VerificationPreconditionError(
                    f"Verification cycle '{cycle_id}' probe sequence validation failed: "
                    f"required {cycle.probes_required} consecutive passes, but max consecutive was {max_consecutive}."
                )

            # 3. Handle associated Incident
            effective_incident_id = incident_id or execution.incident_id
            if not effective_incident_id:
                # Execution has no associated incident; finalize execution only
                execution.status = ExecutionState.VERIFIED.value
                execution.verification_status = "verified"
                execution.completed_at = now_utc
                execution.updated_at = now_utc
                execution.locked_by = None
                execution.locked_until = None
                if auto_commit:
                    db.commit()
                    db.refresh(execution)
                return execution, None

            # Verify incident ID matches execution association
            if execution.incident_id and execution.incident_id != effective_incident_id:
                raise IncidentAssociationMismatchError(
                    f"Incident association mismatch: Execution '{execution.id}' is associated with incident "
                    f"'{execution.incident_id}', not '{effective_incident_id}'."
                )

            # Fetch and row-lock the Incident
            incident = (
                db.query(Incident)
                .filter(Incident.id == effective_incident_id)
                .with_for_update()
                .first()
            )
            if not incident:
                raise PreconditionFailedError(
                    f"Associated incident '{effective_incident_id}' not found in database."
                )

            # Incident workspace isolation
            if incident.workspace_id != workspace_id:
                raise CrossWorkspaceViolationError(
                    f"Cross-workspace violation: Incident belongs to workspace '{incident.workspace_id}', not '{workspace_id}'."
                )

            # Service association validation: exact service match
            if incident.service_id != execution.target_service_id:
                raise IncidentAssociationMismatchError(
                    f"Incident service mismatch: Incident '{incident.id}' is associated with service "
                    f"'{incident.service_id}', not execution target service '{execution.target_service_id}'."
                )

            # Terminal lifecycle check: closed incident cannot be recovered
            if incident.status == "closed":
                raise PreconditionFailedError(
                    f"Cannot recover incident '{incident.id}': incident is already closed and terminal."
                )

            # Active/recoverable incident state check
            if incident.status not in RECOVERABLE_INCIDENT_STATUSES and incident.status != "recovered":
                raise PreconditionFailedError(
                    f"Cannot recover incident '{incident.id}': incident status '{incident.status}' is not recoverable."
                )

            # Idempotency check: if execution is already verified
            if execution.status == ExecutionState.VERIFIED.value:
                if incident.status == "recovered":
                    # Idempotent no-op: return existing verified state without duplicating events
                    return execution, incident
                raise PreconditionFailedError(
                    f"Execution '{execution.id}' is already verified, but incident '{incident.id}' is in status '{incident.status}'."
                )

            # 4. Atomic Mutation
            # Update execution
            execution.status = ExecutionState.VERIFIED.value
            execution.verification_status = "verified"
            execution.completed_at = now_utc
            execution.updated_at = now_utc
            execution.locked_by = None
            execution.locked_until = None

            # Update incident
            incident.status = "recovered"
            incident.recovered_at = now_utc
            incident.updated_at = now_utc

            # 5. Persist Audit Events Atomically
            svc_name = incident.service.name if incident.service else execution.target_service_id

            exec_event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="verified",
                message=(
                    f"Remediation execution '{execution.id}' verified successfully (Cycle #{cycle.cycle_number}). "
                    f"Associated incident '{incident.id}' marked recovered."
                ),
                metadata_json=sanitize_metadata({
                    "execution_id": execution.id,
                    "incident_id": incident.id,
                    "service_id": incident.service_id,
                    "cycle_id": cycle.id,
                    "cycle_number": cycle.cycle_number,
                    "fencing_token": execution.fencing_token,
                    "worker_id": worker_id or cycle.verifying_worker_id,
                    "recovered_at": now_utc.isoformat(),
                }),
                timestamp=now_utc,
            )
            db.add(exec_event)

            inc_event = IncidentEvent(
                id=str(uuid.uuid4()),
                incident_id=incident.id,
                event_type="verification",
                message=(
                    f"Remediation verified: Service '{svc_name}' passed all {cycle.probes_required} "
                    f"post-execution verification probes. Incident marked recovered."
                ),
                metadata_json=json.dumps(
                    sanitize_metadata({
                        "execution_id": execution.id,
                        "cycle_id": cycle.id,
                        "cycle_number": cycle.cycle_number,
                        "action_id": execution.action_id,
                        "fencing_token": execution.fencing_token,
                        "probes_passed": cycle.probes_passed,
                        "recovered_at": now_utc.isoformat(),
                        "status": "recovered",
                    })
                ),
                timestamp=now_utc,
            )
            db.add(inc_event)

            if auto_commit:
                db.commit()
                db.refresh(execution)
                db.refresh(incident)
            else:
                db.flush()

            return execution, incident

        except Exception as e:
            db.rollback()
            raise e
