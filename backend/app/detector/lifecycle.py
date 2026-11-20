"""Incident lifecycle state manager for detection, deduplication, and recovery.

Blueprint Sections 2, 4, 5, 6, 9:
- Scoped to workspace and registered service.
- Deduplication: Prevents duplicate active incidents during repeated polling.
- Persistence: Persists detection evidence, trigger condition, severity, and timeline events in PostgreSQL.
- Recovery: Detects recovery and records transition to 'recovered' with verification event.
"""

import json
from datetime import datetime, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.models.incident import Incident, IncidentEvent
from app.models.service import Service
from app.detector.evaluator import DetectionReport
from app.core.logging import get_logger

logger = get_logger("sentinelops.lifecycle")

ACTIVE_INCIDENT_STATUSES = [
    "detected",
    "investigating",
    "awaiting_approval",
    "investigation_failed",
    "remediating",
    "verifying",
]


def process_detection_lifecycle(
    db: Session,
    report: DetectionReport,
) -> Tuple[Optional[Incident], str]:
    """
    Process evaluation results against the database lifecycle:
    - If failing & no active incident: create new incident + detection event (status: 'created')
    - If failing & active incident exists: deduplicate, do not create redundant incident (status: 'deduplicated')
    - If healthy & active incident exists: mark incident recovered + verification event (status: 'recovered')
    - If healthy & no active incident: normal state (status: 'healthy')

    Returns:
    - (incident_instance, lifecycle_action_string)
    """
    # 1. Search for existing active incident for this service within the workspace
    active_incident = (
        db.query(Incident)
        .filter(
            Incident.workspace_id == report.workspace_id,
            Incident.service_id == report.service_id,
            Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
        )
        .order_by(Incident.detected_at.desc())
        .first()
    )

    now_utc = datetime.now(timezone.utc)

    # 2. Case: Service is failing
    if not report.is_healthy:
        if active_incident:
            # Deduplication: an active incident already tracks this failure
            logger.info(
                "Deduplicating failure for service '%s' (Workspace: %s). Active Incident ID: %s",
                report.service_name,
                report.workspace_id,
                active_incident.id,
            )
            return active_incident, "deduplicated"

        # No active incident: Create a new persisted incident in PostgreSQL
        title = f"Incident on {report.service_name}: {report.trigger}"
        new_incident = Incident(
            workspace_id=report.workspace_id,
            service_id=report.service_id,
            title=title[:255],
            severity=report.severity,
            status="detected",
            trigger=report.trigger or "Unknown trigger condition",
            summary=report.summary,
            detected_at=now_utc,
        )
        db.add(new_incident)
        db.flush()  # Obtain new_incident.id

        # Record initial detection event with evidence reference
        detection_event = IncidentEvent(
            incident_id=new_incident.id,
            event_type="detection",
            message=f"Deterministic rule '{report.triggered_rule}' triggered incident detection.",
            metadata_json=json.dumps(report.evidence),
            timestamp=now_utc,
        )
        db.add(detection_event)
        db.commit()
        db.refresh(new_incident)

        logger.warning(
            "Created new Incident %s for service '%s' (Trigger: %s)",
            new_incident.id,
            report.service_name,
            new_incident.trigger,
        )
        return new_incident, "created"

    # 3. Case: Service is healthy
    if active_incident:
        # Check if active incident has remediation executions that control recovery
        from app.models.remediation import RemediationExecution

        executions = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.incident_id == active_incident.id)
            .order_by(RemediationExecution.triggered_at.desc())
            .all()
        )
        if executions:
            # If any execution is actively running/verifying, defer to IncidentRecoveryBridge
            in_flight = [
                e
                for e in executions
                if e.status
                in (
                    "queued",
                    "validating",
                    "executing",
                    "execution_succeeded",
                    "verification_pending",
                )
            ]
            if in_flight:
                logger.info(
                    "Service '%s' is healthy but Incident %s has in-flight remediation execution(s). "
                    "Deferring recovery to IncidentRecoveryBridge.",
                    report.service_name,
                    active_incident.id,
                )
                return active_incident, "remediation_in_flight"

            # If the latest execution failed verification/execution and has not been verified
            has_verified = any(e.status == "verified" for e in executions)
            if not has_verified:
                latest_exec = executions[0]
                if latest_exec.status in (
                    "verification_failed",
                    "execution_failed",
                    "execution_uncertain",
                    "timed_out",
                ):
                    logger.warning(
                        "Service '%s' responded healthy but Incident %s has failed execution %s (status=%s). "
                        "Preserving incident state for audit/escalation; not auto-recovering.",
                        report.service_name,
                        active_incident.id,
                        latest_exec.id,
                        latest_exec.status,
                    )
                    return active_incident, "verification_failed_pending_escalation"

        # Service has recovered: transition active incident to 'recovered'
        active_incident.status = "recovered"
        active_incident.recovered_at = now_utc
        active_incident.updated_at = now_utc

        # Record recovery verification event
        recovery_event = IncidentEvent(
            incident_id=active_incident.id,
            event_type="verification",
            message=f"Service '{report.service_name}' health check and telemetry confirmed recovered.",
            metadata_json=json.dumps(report.evidence),
            timestamp=now_utc,
        )
        db.add(recovery_event)
        db.commit()
        db.refresh(active_incident)

        logger.info(
            "Incident %s on service '%s' marked RECOVERED at %s",
            active_incident.id,
            report.service_name,
            now_utc.isoformat(),
        )
        return active_incident, "recovered"

    # Healthy and no active incident
    return None, "healthy"
