"""Verification Persistence Service for Phase 4.3.6 Milestone A.

Handles durable persistence for verification cycles and individual synthetic probe results.
Enforces:
1. Deterministic probe identity generation.
2. Duplicate consistency:
   - Identical duplicate payload: idempotent no-op (returns existing record).
   - Conflicting duplicate payload: raises ConflictingProbePayloadError (409 Conflict).
3. Workspace isolation: rejects cross-workspace entities.
4. Execution relationships: binds strictly to existing RemediationExecution.
5. Sanitization of probe outputs and cycle metadata.
"""

import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.execution.exceptions import (
    ConflictingCyclePayloadError,
    ConflictingProbePayloadError,
    CrossWorkspaceViolationError,
    VerificationCycleNotFoundError,
)
from app.execution.manager import sanitize_metadata
from app.models.remediation import RemediationExecution
from app.models.verification import VerificationCycle, VerificationProbeResult

VALID_PROBE_STATUSES = {"passed", "failed", "error", "timeout"}
VALID_CYCLE_STATUSES = {"pending", "running", "passed", "failed", "timed_out", "uncertain"}


def generate_deterministic_probe_id(execution_id: str, cycle_number: int, probe_number: int) -> str:
    """
    Generate a deterministic, globally unique probe ID based on execution, cycle, and probe sequence.
    Example: 'probe:f47ac10b-58cc-4372-a567-0e02b2c3d479:1:1'
    """
    clean_exec = str(execution_id).strip()
    return f"probe:{clean_exec}:{int(cycle_number)}:{int(probe_number)}"


def _normalize_dict_for_comparison(d: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize dictionary recursively for deterministic value comparison."""
    if not d:
        return {}
    try:
        return json.loads(json.dumps(d, sort_keys=True, default=str))
    except Exception:
        return copy.deepcopy(d)


class VerificationPersistenceService:
    """Service for managing persistence of verification cycles and probe results."""

    @classmethod
    def create_or_get_verification_cycle(
        cls,
        *,
        db: Session,
        execution_id: str,
        workspace_id: str,
        cycle_number: int = 1,
        started_at: Optional[datetime] = None,
        deadline_at: Optional[datetime] = None,
        timeout_seconds: int = 30,
        fencing_token: int = 0,
        verifying_worker_id: Optional[str] = None,
        probes_required: int = 3,
        cycle_metadata: Optional[Dict[str, Any]] = None,
    ) -> VerificationCycle:
        """
        Create a new verification cycle or retrieve existing if identical (idempotent).
        Rejects cross-workspace violations and conflicting re-creations.
        """
        # 1. Enforce execution existence and workspace isolation
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .first()
        )
        if not execution:
            raise ValueError(f"Remediation execution '{execution_id}' does not exist.")

        if execution.workspace_id != workspace_id:
            raise CrossWorkspaceViolationError(
                f"Cross-workspace violation: Execution '{execution_id}' belongs to workspace "
                f"'{execution.workspace_id}', not '{workspace_id}'."
            )

        now_utc = datetime.now(timezone.utc)
        start_time = started_at or now_utc
        deadline_time = deadline_at or (start_time + timedelta(seconds=timeout_seconds))

        sanitized_meta = sanitize_metadata(cycle_metadata) if cycle_metadata else {}

        # 2. Check for existing cycle by (execution_id, cycle_number)
        existing_cycle = (
            db.query(VerificationCycle)
            .filter(
                VerificationCycle.execution_id == execution_id,
                VerificationCycle.cycle_number == cycle_number,
            )
            .first()
        )

        if existing_cycle:
            # Check for conflicting payload
            if existing_cycle.workspace_id != workspace_id:
                raise ConflictingCyclePayloadError(
                    f"Conflicting workspace for cycle {cycle_number} of execution '{execution_id}'."
                )
            if existing_cycle.fencing_token != fencing_token:
                raise ConflictingCyclePayloadError(
                    f"Conflicting fencing token for cycle {cycle_number} of execution '{execution_id}': "
                    f"existing has {existing_cycle.fencing_token}, request has {fencing_token}."
                )
            # Idempotent no-op
            return existing_cycle

        # 3. Create new VerificationCycle
        cycle = VerificationCycle(
            id=str(uuid.uuid4()),
            execution_id=execution_id,
            workspace_id=workspace_id,
            cycle_number=cycle_number,
            status="pending",
            started_at=start_time,
            deadline_at=deadline_time,
            fencing_token=fencing_token,
            verifying_worker_id=verifying_worker_id,
            probes_required=probes_required,
            probes_passed=0,
            probes_failed=0,
            cycle_metadata=sanitized_meta,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(cycle)
        db.flush()
        return cycle

    @classmethod
    def record_probe_result(
        cls,
        *,
        db: Session,
        cycle_id: str,
        probe_number: int,
        probe_type: str,
        target_url: str,
        passed: bool,
        status: str,
        status_code: Optional[int] = None,
        latency_ms: Optional[float] = None,
        probe_output: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        executed_at: Optional[datetime] = None,
        probe_id: Optional[str] = None,
    ) -> VerificationProbeResult:
        """
        Record the result of an individual verification probe.
        Enforces deterministic identity and duplicate consistency:
        - Identical duplicate payload: idempotent no-op (returns existing record).
        - Conflicting duplicate payload: raises ConflictingProbePayloadError (409 Conflict).
        """
        norm_status = (status or "").strip().lower()
        if norm_status not in VALID_PROBE_STATUSES:
            raise ValueError(
                f"Invalid probe status '{status}'. Must be one of: {sorted(VALID_PROBE_STATUSES)}."
            )

        # 1. Fetch parent cycle
        cycle = (
            db.query(VerificationCycle)
            .filter(VerificationCycle.id == cycle_id)
            .first()
        )
        if not cycle:
            raise VerificationCycleNotFoundError(f"Verification cycle '{cycle_id}' not found.")

        # 2. Determine deterministic probe_id
        det_probe_id = probe_id or generate_deterministic_probe_id(
            execution_id=cycle.execution_id,
            cycle_number=cycle.cycle_number,
            probe_number=probe_number,
        )

        sanitized_output = sanitize_metadata(probe_output) if probe_output else {}
        norm_input_output = _normalize_dict_for_comparison(sanitized_output)

        # 3. Check for existing probe record by primary key (id) OR by (cycle_id, probe_number)
        existing_probe = (
            db.query(VerificationProbeResult)
            .filter(
                (VerificationProbeResult.id == det_probe_id)
                | (
                    (VerificationProbeResult.cycle_id == cycle_id)
                    & (VerificationProbeResult.probe_number == probe_number)
                )
            )
            .first()
        )

        if existing_probe:
            # Check duplicate consistency: compare all essential payload fields
            norm_existing_output = _normalize_dict_for_comparison(existing_probe.probe_output)

            is_identical = (
                existing_probe.id == det_probe_id
                and existing_probe.cycle_id == cycle_id
                and existing_probe.probe_number == probe_number
                and existing_probe.probe_type == probe_type
                and existing_probe.target_url == target_url
                and existing_probe.passed == passed
                and existing_probe.status == norm_status
                and existing_probe.status_code == status_code
                and (
                    existing_probe.error_message == error_message
                    or (not existing_probe.error_message and not error_message)
                )
                and norm_existing_output == norm_input_output
            )

            if is_identical:
                # Idempotent no-op
                return existing_probe
            else:
                # Conflicting duplicate payload
                diffs = []
                if existing_probe.passed != passed:
                    diffs.append(f"passed: {existing_probe.passed} vs {passed}")
                if existing_probe.status != norm_status:
                    diffs.append(f"status: {existing_probe.status} vs {norm_status}")
                if existing_probe.status_code != status_code:
                    diffs.append(f"status_code: {existing_probe.status_code} vs {status_code}")
                if existing_probe.target_url != target_url:
                    diffs.append(f"target_url: {existing_probe.target_url} vs {target_url}")
                if norm_existing_output != norm_input_output:
                    diffs.append("probe_output mismatch")
                if existing_probe.error_message != error_message:
                    diffs.append(f"error_message: {existing_probe.error_message} vs {error_message}")

                raise ConflictingProbePayloadError(
                    f"Conflicting payload for probe '{det_probe_id}' in cycle '{cycle_id}' "
                    f"(Probe #{probe_number}): {'; '.join(diffs)}."
                )

        # 4. Insert new VerificationProbeResult
        now_utc = datetime.now(timezone.utc)
        probe_record = VerificationProbeResult(
            id=det_probe_id,
            cycle_id=cycle_id,
            execution_id=cycle.execution_id,
            workspace_id=cycle.workspace_id,
            probe_number=probe_number,
            probe_type=probe_type,
            target_url=target_url,
            status=norm_status,
            status_code=status_code,
            latency_ms=round(latency_ms, 2) if latency_ms is not None else None,
            passed=passed,
            probe_output=sanitized_output,
            error_message=error_message,
            executed_at=executed_at or now_utc,
            created_at=now_utc,
        )
        db.add(probe_record)

        # 5. Update cycle stats atomically
        if passed:
            cycle.probes_passed += 1
        else:
            cycle.probes_failed += 1
        cycle.updated_at = now_utc

        db.flush()
        return probe_record

    @classmethod
    def get_verification_cycle(
        cls,
        *,
        db: Session,
        cycle_id: str,
        workspace_id: Optional[str] = None,
    ) -> VerificationCycle:
        """Fetch verification cycle with optional workspace scoping."""
        cycle = db.query(VerificationCycle).filter(VerificationCycle.id == cycle_id).first()
        if not cycle:
            raise VerificationCycleNotFoundError(f"Verification cycle '{cycle_id}' not found.")
        if workspace_id and cycle.workspace_id != workspace_id:
            raise CrossWorkspaceViolationError(
                f"Cross-workspace violation: Cycle belongs to workspace '{cycle.workspace_id}', not '{workspace_id}'."
            )
        return cycle

    @classmethod
    def list_probes_for_cycle(
        cls,
        *,
        db: Session,
        cycle_id: str,
        workspace_id: Optional[str] = None,
    ) -> List[VerificationProbeResult]:
        """List all probe results for a cycle ordered by probe_number."""
        cls.get_verification_cycle(db=db, cycle_id=cycle_id, workspace_id=workspace_id)
        return (
            db.query(VerificationProbeResult)
            .filter(VerificationProbeResult.cycle_id == cycle_id)
            .order_by(VerificationProbeResult.probe_number.asc())
            .all()
        )
