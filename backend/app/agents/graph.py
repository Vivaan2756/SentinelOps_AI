"""Coordinated Investigation Workflow Orchestrator using LangGraph."""

from typing import Optional, Any, Dict
import asyncio
from datetime import datetime, timezone
import httpx
from sqlalchemy.orm import Session
from langgraph.graph import StateGraph, START, END
from app.core.config import settings
from app.core.logging import get_logger
from app.agents.state import InvestigationState
from app.models.investigation import Investigation
from app.models.incident import Incident, IncidentEvent
from app.agents.nodes.context import retrieve_incident_context
from app.agents.nodes.evidence import collect_diagnostic_evidence
from app.agents.nodes.hypotheses import generate_hypotheses
from app.agents.nodes.evaluation import evaluate_and_rank_hypotheses
from app.agents.nodes.summary import generate_investigation_summary
from app.agents.nodes.persistence import persist_investigation_results
from app.agents.nodes.playbooks import (
    discover_active_playbooks,
    evaluate_playbook_compatibility,
    rank_compatible_playbooks,
    generate_remediation_recommendation,
)

logger = get_logger("sentinelops.agents.graph")


def create_investigation_graph(
    db: Session,
    client: Optional[httpx.AsyncClient] = None,
    llm: Optional[Any] = None,
):
    """
    Constructs the compiled LangGraph StateGraph for Incident Investigation.
    Logical flow:
    START -> context -> [check failure] -> evidence -> hypotheses -> evaluation
          -> discover_active_playbooks -> evaluate_playbook_compatibility
          -> rank_compatible_playbooks -> generate_remediation_recommendation
          -> summary -> persistence -> END
    """
    workflow = StateGraph(InvestigationState)

    # Node wrappers injecting dependencies
    async def node_context(state: InvestigationState) -> Dict[str, Any]:
        return await retrieve_incident_context(state, db=db)

    async def node_evidence(state: InvestigationState) -> Dict[str, Any]:
        return await collect_diagnostic_evidence(state, db=db, client=client)

    async def node_hypotheses(state: InvestigationState) -> Dict[str, Any]:
        return await generate_hypotheses(state, llm=llm)

    def node_evaluation(state: InvestigationState) -> Dict[str, Any]:
        return evaluate_and_rank_hypotheses(state)

    async def node_discover_playbooks(state: InvestigationState) -> Dict[str, Any]:
        return await discover_active_playbooks(state, db=db)

    def node_evaluate_playbooks(state: InvestigationState) -> Dict[str, Any]:
        return evaluate_playbook_compatibility(state, db=db)

    def node_rank_playbooks(state: InvestigationState) -> Dict[str, Any]:
        return rank_compatible_playbooks(state, llm=llm)

    def node_generate_recommendation(state: InvestigationState) -> Dict[str, Any]:
        return generate_remediation_recommendation(state)

    async def node_summary(state: InvestigationState) -> Dict[str, Any]:
        return generate_investigation_summary(state)

    async def node_persistence(state: InvestigationState) -> Dict[str, Any]:
        return await persist_investigation_results(state, db=db)

    # Add Nodes
    workflow.add_node("context", node_context)
    workflow.add_node("evidence", node_evidence)
    workflow.add_node("hypotheses", node_hypotheses)
    workflow.add_node("evaluation", node_evaluation)
    workflow.add_node("discover_active_playbooks", node_discover_playbooks)
    workflow.add_node("evaluate_playbook_compatibility", node_evaluate_playbooks)
    workflow.add_node("rank_compatible_playbooks", node_rank_playbooks)
    workflow.add_node("generate_remediation_recommendation", node_generate_recommendation)
    workflow.add_node("summary", node_summary)
    workflow.add_node("persistence", node_persistence)

    # Conditional Routing from Context
    def route_after_context(state: InvestigationState) -> str:
        if state.get("status") == "failed":
            logger.warning("Context retrieval failed; routing to persistence. Errors: %s", state.get("errors"))
            return "persistence"
        return "evidence"

    # Add Edges
    workflow.add_edge(START, "context")
    workflow.add_conditional_edges("context", route_after_context, ["evidence", "persistence"])
    workflow.add_edge("evidence", "hypotheses")
    workflow.add_edge("hypotheses", "evaluation")
    workflow.add_edge("evaluation", "discover_active_playbooks")
    workflow.add_edge("discover_active_playbooks", "evaluate_playbook_compatibility")
    workflow.add_edge("evaluate_playbook_compatibility", "rank_compatible_playbooks")
    workflow.add_edge("rank_compatible_playbooks", "generate_remediation_recommendation")
    workflow.add_edge("generate_remediation_recommendation", "summary")
    workflow.add_edge("summary", "persistence")
    workflow.add_edge("persistence", END)

    return workflow.compile()


async def run_investigation(
    incident_id: str,
    workspace_id: str,
    db: Session,
    investigation_id: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    llm: Optional[Any] = None,
) -> InvestigationState:
    """
    Entrypoint function executing the end-to-end LangGraph incident investigation workflow.
    Guarantees that exceptions, timeouts, or graph failures persist failure state and audit events.
    """
    app = create_investigation_graph(db=db, client=client, llm=llm)

    now_iso = datetime.now(timezone.utc).isoformat()
    initial_state: InvestigationState = {
        "incident_id": incident_id,
        "workspace_id": workspace_id,
        "service_id": None,
        "investigation_id": investigation_id,
        "status": "pending",
        "started_at": now_iso,
        "completed_at": None,
        "incident_context": {},
        "evidence_items": [],
        "evidence_errors": [],
        "hypotheses": [],
        "discovered_playbooks": [],
        "playbook_compatibility_results": [],
        "compatible_playbooks": [],
        "rejected_playbooks": [],
        "ranked_playbooks": [],
        "remediation_recommendation": None,
        "investigation_summary": None,
        "model_name": settings.GEMINI_MODEL,
        "prompt_version": settings.INVESTIGATION_PROMPT_VERSION,
        "token_usage": None,
        "errors": [],
    }

    try:
        timeout = settings.INVESTIGATION_TIMEOUT_SECONDS
        final_state = await asyncio.wait_for(app.ainvoke(initial_state), timeout=timeout)
        return final_state
    except Exception as exc:
        logger.error("Investigation execution failed for incident %s: %s", incident_id, exc, exc_info=True)
        now_dt = datetime.now(timezone.utc)
        err_msg = str(exc) or "Investigation execution encountered an unhandled exception or timeout."

        # Persist failed investigation record
        inv = None
        if investigation_id:
            inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            inv = Investigation(
                incident_id=incident_id,
                workspace_id=workspace_id,
                status="failed",
                model_name=settings.GEMINI_MODEL,
                prompt_version=settings.INVESTIGATION_PROMPT_VERSION,
                error_message=err_msg,
                evidence=[],
                hypotheses=[],
                started_at=now_dt,
                completed_at=now_dt,
            )
            db.add(inv)
        else:
            inv.status = "failed"
            inv.error_message = err_msg
            inv.completed_at = now_dt
            db.add(inv)

        # Update incident lifecycle state to investigation_failed (preserving recovered/closed)
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident and incident.status not in ("recovered", "closed"):
            incident.status = "investigation_failed"
            db.add(incident)

        # Record timeline audit event
        failure_event = IncidentEvent(
            incident_id=incident_id,
            event_type="investigation",
            message=f"AI investigation failed: {err_msg[:200]}",
            metadata_json=f'{{"status": "failed", "error": "{err_msg[:120]}"}}',
            timestamp=now_dt,
        )
        db.add(failure_event)

        try:
            db.commit()
            if inv:
                db.refresh(inv)
        except Exception as db_err:
            db.rollback()
            logger.error("Failed to commit failure state for incident %s: %s", incident_id, db_err)

        return {
            **initial_state,
            "status": "failed",
            "investigation_id": inv.id if inv else investigation_id,
            "completed_at": now_dt.isoformat(),
            "errors": [err_msg],
        }
