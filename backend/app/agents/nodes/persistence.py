"""Node 6: Investigation Persistence and Audit Event Logging for Agentic SRE."""

from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.agents.state import InvestigationState
from app.models.investigation import Investigation
from app.models.incident import Incident, IncidentEvent


async def persist_investigation_results(
    state: InvestigationState,
    db: Session,
) -> Dict[str, Any]:
    """
    Persists the completed investigation into the PostgreSQL 'investigations' table
    and appends a chronological audit event to 'incident_events'.
    """
    incident_id = state.get("incident_id")
    workspace_id = state.get("workspace_id")
    status = state.get("status", "completed")
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    started_at_dt = None
    if state.get("started_at"):
        try:
            started_at_dt = datetime.fromisoformat(state["started_at"])
        except Exception:
            started_at_dt = now_dt

    summary = state.get("investigation_summary")
    evidence_items = state.get("evidence_items", [])
    hypotheses = state.get("hypotheses", [])
    errors = state.get("errors", [])
    err_msg = "; ".join(errors) if errors else None

    # Check for existing pending/running investigation for this incident
    inv_id = state.get("investigation_id")
    investigation = None
    if inv_id:
        investigation = db.query(Investigation).filter(Investigation.id == inv_id).first()

    if not investigation:
        investigation = Investigation(
            incident_id=incident_id,
            workspace_id=workspace_id,
            status=status,
            model_name=state.get("model_name", "gemini-2.5-flash"),
            prompt_version=state.get("prompt_version", "v1.0"),
            evidence=evidence_items,
            hypotheses=hypotheses,
            summary=summary,
            error_message=err_msg,
            token_usage=state.get("token_usage"),
            started_at=started_at_dt or now_dt,
            completed_at=now_dt,
        )
        db.add(investigation)
    else:
        investigation.status = status
        investigation.model_name = state.get("model_name", investigation.model_name)
        investigation.prompt_version = state.get("prompt_version", investigation.prompt_version)
        investigation.evidence = evidence_items
        investigation.hypotheses = hypotheses
        investigation.summary = summary
        investigation.error_message = err_msg
        investigation.token_usage = state.get("token_usage")
        investigation.completed_at = now_dt
        db.add(investigation)

    # Update incident lifecycle state (do not overwrite recovered or closed incidents)
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident and incident.status not in ("recovered", "closed"):
        if status == "completed":
            incident.status = "awaiting_approval"
        elif status == "failed":
            incident.status = "investigation_failed"
        db.add(incident)

    db.flush()

    import json

    # Append chronological audit event to incident_events
    likely_cause = summary.get("likely_root_cause", "Unspecified") if summary else "Diagnosis Incomplete"
    top_hyp = hypotheses[0] if hypotheses else None
    conf_str = f" (Confidence: {top_hyp.get('confidence', 0.0)})" if top_hyp else ""

    audit_msg = (
        f"AI investigation {status}: Primary diagnosis identified '{likely_cause}'{conf_str}. "
        f"Evaluated {len(hypotheses)} candidate hypotheses against {len(evidence_items)} diagnostic evidence items."
    )

    rec = (summary or {}).get("remediation_recommendation") or state.get("remediation_recommendation")
    meta_dict: Dict[str, Any] = {
        "investigation_id": investigation.id,
        "status": status,
        "likely_root_cause": likely_cause[:100],
    }

    if rec:
        rec_outcome = rec.get("outcome")
        meta_dict["recommendation_outcome"] = rec_outcome
        if rec.get("playbook_id"):
            meta_dict["playbook_id"] = rec.get("playbook_id")
            meta_dict["playbook_version"] = rec.get("playbook_version")
            meta_dict["action_template_id"] = rec.get("action_template_id")
        if rec.get("status") == "actionable":
            audit_msg += (
                f" Recommended dynamic playbook '{rec.get('playbook_name')}' "
                f"(v{rec.get('playbook_version')}) executing action '{rec.get('action_template_id')}'."
            )
        elif rec_outcome == "no_compatible_playbook":
            audit_msg += " No compatible remediation playbook available for service; escalated for human intervention."
        elif rec_outcome == "missing_parameters":
            audit_msg += f" Remediation playbook '{rec.get('playbook_name')}' requires human input for missing parameters."

    if err_msg:
        audit_msg += f" Notice: {err_msg[:120]}"

    audit_event = IncidentEvent(
        incident_id=incident_id,
        event_type="investigation",
        message=audit_msg,
        metadata_json=json.dumps(meta_dict),
    )
    db.add(audit_event)
    db.commit()
    db.refresh(investigation)

    return {
        "investigation_id": investigation.id,
        "completed_at": now_iso,
        "status": status,
    }
