"""Evaluation runner orchestrating target evaluation and lifecycle updates."""

from typing import Tuple, Optional, Dict, Any, List
import httpx
from sqlalchemy.orm import Session
from app.models.service import Service
from app.models.incident import Incident
from app.detector.evaluator import evaluate_service_health, DetectionReport
from app.detector.lifecycle import process_detection_lifecycle


class EvaluationResult:
    """Consolidated outcome of evaluating a service and updating its lifecycle."""
    def __init__(
        self,
        service_id: str,
        service_name: str,
        workspace_id: str,
        is_healthy: bool,
        lifecycle_action: str,  # "created", "deduplicated", "recovered", "healthy"
        incident: Optional[Incident],
        report: DetectionReport,
    ):
        self.service_id = service_id
        self.service_name = service_name
        self.workspace_id = workspace_id
        self.is_healthy = is_healthy
        self.lifecycle_action = lifecycle_action
        self.incident = incident
        self.report = report

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_id": self.service_id,
            "service_name": self.service_name,
            "workspace_id": self.workspace_id,
            "is_healthy": self.is_healthy,
            "lifecycle_action": self.lifecycle_action,
            "incident_id": self.incident.id if self.incident else None,
            "incident_status": self.incident.status if self.incident else None,
            "trigger": self.report.trigger,
            "evidence": self.report.evidence,
        }


async def run_evaluation_for_service(
    service_id: str,
    db: Session,
    client: Optional[httpx.AsyncClient] = None,
    timeout_seconds: Optional[float] = None,
) -> EvaluationResult:
    """
    Execute full detection and lifecycle cycle for a single service:
    1. Fetch registered service from DB.
    2. Run deterministic health probe and rules evaluation.
    3. Update incident lifecycle in DB (creation, deduplication, or recovery).
    """
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise ValueError(f"Service '{service_id}' not found in database.")

    # Run evaluation
    report = await evaluate_service_health(
        service=service,
        client=client,
        timeout_seconds=timeout_seconds,
    )

    # Process lifecycle in DB
    incident, action = process_detection_lifecycle(db, report)

    # Update service health status cache
    service.last_checked_at = report.evaluated_at
    if report.is_healthy:
        service.health_status = "healthy"
    elif report.severity == "medium":
        service.health_status = "degraded"
    else:
        service.health_status = "unhealthy"
    db.commit()
    db.refresh(service)

    return EvaluationResult(
        service_id=service.id,
        service_name=service.name,
        workspace_id=service.workspace_id,
        is_healthy=report.is_healthy,
        lifecycle_action=action,
        incident=incident,
        report=report,
    )


async def run_evaluation_for_workspace(
    workspace_id: str,
    db: Session,
    client: Optional[httpx.AsyncClient] = None,
    timeout_seconds: Optional[float] = None,
) -> List[EvaluationResult]:
    """Execute detection for all active services registered in a workspace."""
    services = (
        db.query(Service)
        .filter(Service.workspace_id == workspace_id, Service.is_active == True)
        .all()
    )
    results = []
    for s in services:
        res = await run_evaluation_for_service(
            service_id=s.id,
            db=db,
            client=client,
            timeout_seconds=timeout_seconds,
        )
        results.append(res)
    return results
