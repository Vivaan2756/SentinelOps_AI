"""Read-only incident history & initial detection evidence tool for Agentic SRE."""

from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.incident import Incident, IncidentEvent


def collect_incident_history_evidence(
    service_id: str,
    workspace_id: str,
    current_incident_id: str,
    db: Session,
    evidence_id: str = "ev-history",
) -> Dict[str, Any]:
    """
    Collects historical incident and stability patterns for the service within the workspace.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        past_incidents = (
            db.query(Incident)
            .filter(
                Incident.service_id == service_id,
                Incident.workspace_id == workspace_id,
                Incident.id != current_incident_id,
            )
            .order_by(Incident.detected_at.desc())
            .limit(5)
            .all()
        )

        total_past = len(past_incidents)
        recovered_count = sum(1 for i in past_incidents if i.status == "recovered")
        active_past = sum(1 for i in past_incidents if i.status not in ("recovered", "closed"))

        if total_past == 0:
            obs = "No prior incidents recorded for this service in the workspace (first observed anomaly)."
        else:
            obs = (
                f"Service has {total_past} prior incidents recorded in this workspace "
                f"({recovered_count} recovered, {active_past} active). "
            )
            recent_triggers = [i.trigger for i in past_incidents[:3]]
            obs += f"Recent triggers: {', '.join(recent_triggers)}."

        return {
            "evidence_id": evidence_id,
            "source": "incident_history",
            "observation": obs,
            "timestamp": now_iso,
            "collection_status": "success",
            "data": {
                "prior_incidents_count": total_past,
                "recovered_count": recovered_count,
                "recent_triggers": [i.trigger for i in past_incidents[:3]],
            },
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "source": "incident_history",
            "observation": f"Could not retrieve historical incident patterns: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"error": str(e)},
        }


def collect_initial_detection_evidence(
    incident: Incident,
    db: Session,
    evidence_id: str = "ev-trigger",
) -> Dict[str, Any]:
    """
    Extracts initial detection alert snapshot and timeline events for the active incident.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        events = (
            db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == incident.id)
            .order_by(IncidentEvent.timestamp.asc())
            .all()
        )

        event_summaries: List[Dict[str, Any]] = []
        detection_metadata = None

        for ev in events:
            summary = {
                "event_type": ev.event_type,
                "message": ev.message,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            }
            if ev.event_type == "detection" and ev.metadata_json:
                summary["metadata"] = ev.metadata_json
                detection_metadata = ev.metadata_json
            event_summaries.append(summary)

        obs = (
            f"Incident was triggered at {incident.detected_at.isoformat()} with severity '{incident.severity}'. "
            f"Rule trigger: '{incident.trigger}'. Total timeline events recorded: {len(events)}."
        )
        if incident.summary:
            obs += f" Initial detector summary: '{incident.summary}'."

        return {
            "evidence_id": evidence_id,
            "source": "initial_detection",
            "observation": obs,
            "timestamp": now_iso,
            "collection_status": "success",
            "data": {
                "trigger": incident.trigger,
                "severity": incident.severity,
                "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
                "summary": incident.summary,
                "timeline_events": event_summaries[:10],
                "detection_metadata": detection_metadata,
            },
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "source": "initial_detection",
            "observation": f"Could not extract initial detection evidence: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"error": str(e)},
        }
