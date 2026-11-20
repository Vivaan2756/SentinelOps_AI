"""Node 2: Evidence Collection for Agentic AI Investigation."""

from typing import Dict, Any, List, Optional
import httpx
from sqlalchemy.orm import Session
from app.agents.state import InvestigationState
from app.agents.tools.health import collect_health_evidence
from app.agents.tools.metrics import collect_metrics_evidence
from app.agents.tools.incidents import (
    collect_incident_history_evidence,
    collect_initial_detection_evidence,
)
from app.models.incident import Incident


async def collect_diagnostic_evidence(
    state: InvestigationState,
    db: Session,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """
    Executes bounded, read-only diagnostic tools across approved evidence sources:
    - Initial detection alert & timeline events
    - Health check endpoint probe (SSRF safeguarded)
    - Prometheus metrics scrape (SSRF safeguarded)
    - Service incident history in workspace
    """
    incident_context = state.get("incident_context", {})
    incident_id = state.get("incident_id")
    workspace_id = state.get("workspace_id")
    service_id = state.get("service_id")
    health_url = incident_context.get("health_check_url")

    evidence_items: List[Dict[str, Any]] = []
    evidence_errors: List[str] = []

    # 1. Initial Detection Evidence
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            init_ev = collect_initial_detection_evidence(incident, db, evidence_id="ev-1")
            evidence_items.append(init_ev)
        else:
            evidence_errors.append("Incident record not found for initial detection extraction.")
    except Exception as e:
        evidence_errors.append(f"Failed to extract initial detection evidence: {str(e)}")

    # 2. Live Health Check Probe
    if health_url:
        try:
            health_ev = await collect_health_evidence(
                url=health_url,
                evidence_id="ev-2",
                client=client,
            )
            evidence_items.append(health_ev)
            if health_ev.get("collection_status") == "failed":
                evidence_errors.append(health_ev.get("observation", "Health probe failed"))
        except Exception as e:
            evidence_errors.append(f"Health probe execution error: {str(e)}")
            evidence_items.append({
                "evidence_id": "ev-2",
                "source": "health_probe",
                "observation": f"Health probe failed: {str(e)}",
                "timestamp": incident_context.get("detected_at") or "",
                "collection_status": "failed",
                "data": {"error": str(e)},
            })
    else:
        evidence_errors.append("No health_check_url configured for registered service.")

    # 3. Prometheus Metrics Scrape (only for Prometheus monitoring method)
    if health_url:
        monitoring_method = incident_context.get("monitoring_method", "prometheus")
        if (monitoring_method or "").lower() == "prometheus":
            try:
                metrics_ev = await collect_metrics_evidence(
                    health_url=health_url,
                    evidence_id="ev-3",
                    client=client,
                )
                evidence_items.append(metrics_ev)
                if metrics_ev.get("collection_status") == "failed":
                    evidence_errors.append(metrics_ev.get("observation", "Metrics scrape failed"))
            except Exception as e:
                evidence_errors.append(f"Metrics scrape execution error: {str(e)}")
                evidence_items.append({
                    "evidence_id": "ev-3",
                    "source": "prometheus_metrics",
                    "observation": f"Metrics scrape failed: {str(e)}",
                    "timestamp": incident_context.get("detected_at") or "",
                    "collection_status": "failed",
                    "data": {"error": str(e)},
                })
        else:
            evidence_items.append({
                "evidence_id": "ev-3",
                "source": "monitoring_provider",
                "observation": f"Service monitoring method is '{monitoring_method}'. Prometheus metrics scraping skipped.",
                "timestamp": incident_context.get("detected_at") or "",
                "collection_status": "skipped",
                "data": {"monitoring_method": monitoring_method},
            })

    # 4. Incident History & Pattern Analysis
    if service_id and workspace_id:
        try:
            hist_ev = collect_incident_history_evidence(
                service_id=service_id,
                workspace_id=workspace_id,
                current_incident_id=incident_id,
                db=db,
                evidence_id="ev-4",
            )
            evidence_items.append(hist_ev)
        except Exception as e:
            evidence_errors.append(f"Failed to collect historical incident evidence: {str(e)}")

    return {
        "evidence_items": evidence_items,
        "evidence_errors": evidence_errors,
    }
