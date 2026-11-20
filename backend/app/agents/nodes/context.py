"""Node 1: Incident Context Retrieval for Agentic AI Investigation."""

import re
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.agents.state import InvestigationState
from app.models.incident import Incident, IncidentEvent
from app.models.service import Service


async def retrieve_incident_context(
    state: InvestigationState,
    db: Session,
) -> Dict[str, Any]:
    """
    Retrieves incident record, affected service details, and timeline history.
    Enforces workspace boundary authorization and records investigation startup event.
    """
    incident_id = state.get("incident_id")
    workspace_id = state.get("workspace_id")
    now_iso = datetime.now(timezone.utc).isoformat()

    if not incident_id or not workspace_id:
        return {
            "status": "failed",
            "errors": state.get("errors", []) + ["Missing incident_id or workspace_id in graph state."],
        }

    try:
        # Query incident scoped to workspace
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id, Incident.workspace_id == workspace_id)
            .first()
        )

        if not incident:
            return {
                "status": "failed",
                "errors": state.get("errors", []) + [
                    f"Incident '{incident_id}' not found in workspace '{workspace_id}'."
                ],
            }

        # Query service
        service = db.query(Service).filter(Service.id == incident.service_id).first()

        # Update incident status to 'investigating' only if not recovered or closed
        if incident.status in ("detected", "investigation_failed", "awaiting_approval"):
            incident.status = "investigating"
            db.add(incident)

        # Append timeline audit event
        startup_event = IncidentEvent(
            incident_id=incident.id,
            event_type="investigation",
            message="AI investigation workflow initiated via LangGraph orchestration.",
            metadata_json='{"status": "running", "orchestrator": "LangGraph"}',
        )
        db.add(startup_event)
        db.commit()

        # Resolve initial triggered rule identifier from detection event
        detection_event = (
            db.query(IncidentEvent)
            .filter(
                IncidentEvent.incident_id == incident.id,
                IncidentEvent.event_type == "detection",
            )
            .order_by(IncidentEvent.timestamp.asc())
            .first()
        )
        triggered_rule = None
        if detection_event and detection_event.message:
            rule_match = re.search(r"Deterministic rule '([^']+)'", detection_event.message)
            if rule_match:
                triggered_rule = rule_match.group(1)

        context_dict = {
            "incident_id": incident.id,
            "workspace_id": incident.workspace_id,
            "service_id": incident.service_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "trigger": incident.trigger,
            "triggered_rule": triggered_rule,
            "summary": incident.summary,
            "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
            "service_name": service.name if service else "Unknown Service",
            "service_environment": service.environment if service else "unknown",
            "health_check_url": service.health_check_url if service else None,
            "monitoring_method": service.monitoring_method if service else "prometheus",
            "execution_policy": service.execution_policy if service else "demo",
        }

        return {
            "service_id": incident.service_id,
            "incident_context": context_dict,
            "status": "running",
            "started_at": state.get("started_at") or now_iso,
        }

    except Exception as e:
        db.rollback()
        return {
            "status": "failed",
            "errors": state.get("errors", []) + [f"Failed to retrieve incident context: {str(e)}"],
        }
