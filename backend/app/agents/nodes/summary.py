"""Node 5: Investigation Summary & SRE Recommendations for Agentic SRE."""

from typing import Dict, Any, List
from app.agents.state import InvestigationState
from app.schemas.investigation import InvestigationSummary, Hypothesis


def generate_investigation_summary(
    state: InvestigationState,
) -> Dict[str, Any]:
    """
    Synthesizes the finalized, structured investigation report.
    Produces clear explainability linking the primary diagnosis to actual evidence,
    unresolved questions, and informational SRE next steps.
    """
    incident_context = state.get("incident_context", {})
    evidence_items = state.get("evidence_items", [])
    hypotheses_raw = state.get("hypotheses", [])
    hypotheses = [Hypothesis(**h) for h in hypotheses_raw]

    top_hyp = hypotheses[0] if hypotheses else None
    title = incident_context.get("title", "Incident")
    trigger = incident_context.get("trigger", "Unknown trigger")
    service_name = incident_context.get("service_name", "Monitored service")

    # 1. Executive Incident Summary
    if top_hyp and top_hyp.is_supported:
        inc_summary = (
            f"Automated SRE diagnostic investigation of incident '{title}' on {service_name}. "
            f"The incident was triggered by rule '{trigger}'. Telemetry evidence indicates "
            f"'{top_hyp.root_cause}' as the primary contributing factor with evidential score {top_hyp.confidence}."
        )
        likely_cause = top_hyp.root_cause
    elif top_hyp and not top_hyp.is_supported:
        inc_summary = (
            f"Investigation of '{title}' on {service_name} concluded with indeterminate root cause. "
            f"Available evidence did not conclusively verify candidate hypotheses."
        )
        likely_cause = f"Unverified: {top_hyp.root_cause} (Insufficient Evidence)"
    else:
        inc_summary = (
            f"Investigation of '{title}' on {service_name} was unable to establish a root cause "
            f"due to insufficient telemetry data."
        )
        likely_cause = "Indeterminate / Insufficient Telemetry"


    # 2. Extract Supporting & Contradicting Evidence descriptions
    ev_map = {e.get("evidence_id"): e.get("observation", "") for e in evidence_items}
    supporting_obs: List[str] = []
    contradicting_obs: List[str] = []

    if top_hyp:
        for eid in top_hyp.supporting_evidence_ids:
            if eid in ev_map:
                supporting_obs.append(f"[{eid}] {ev_map[eid]}")
        for eid in top_hyp.contradicting_evidence_ids:
            if eid in ev_map:
                contradicting_obs.append(f"[{eid}] {ev_map[eid]}")

    if not supporting_obs and evidence_items:
        supporting_obs = [f"[{e.get('evidence_id')}] {e.get('observation')}" for e in evidence_items[:2]]

    # 3. Informational Recommended Next Diagnostic Steps
    # Tailored to diagnosed root cause; strictly READ-ONLY actions for human engineers
    recommended_steps: List[str] = []
    cause_lower = likely_cause.lower()

    if "database" in cause_lower or "timeout" in cause_lower:
        recommended_steps = [
            "Inspect downstream database active sessions and lock contention via pg_stat_activity.",
            f"Verify connection pool configuration limits (max_connections, pool_timeout) on {service_name}.",
            "Check database host CPU, memory, and disk I/O metrics during the failure window.",
            "Review slow query logs for queries exceeding the 5.0-second execution threshold.",
        ]
    elif "unreachable" in cause_lower or "connection" in cause_lower:
        recommended_steps = [
            "Verify process daemon status and port binding on the target service host.",
            "Inspect container exit codes or systemd journal logs for unexpected termination.",
            "Check ingress reverse proxy and network security group routing rules.",
        ]
    elif "5xx" in cause_lower or "server error" in cause_lower:
        recommended_steps = [
            "Inspect microservice standard error logs for unhandled exception tracebacks.",
            "Check upstream dependencies and external API response codes.",
            "Verify recent deployment history or configuration changes prior to alert onset.",
        ]
    else:
        recommended_steps = [
            "Verify monitoring target URL connectivity and telemetry endpoint accessibility.",
            "Ensure Prometheus exporter / metrics scraper is operational.",
            "Confirm service health endpoint returns valid JSON payload.",
        ]

    # Incorporate dynamic playbook remediation recommendation (Phase 4.3)
    rec = state.get("remediation_recommendation")
    if rec and rec.get("status") == "actionable":
        recommended_steps.insert(
            0,
            f"Dynamic Remediation Playbook: Propose recovery via '{rec.get('playbook_name')}' "
            f"(v{rec.get('playbook_version')}) executing action '{rec.get('action_template_id')}'. "
            "Requires human approval."
        )
    elif rec and rec.get("outcome") == "no_compatible_playbook":
        recommended_steps.insert(
            0,
            "No compatible remediation playbook is configured for this service. "
            "Manual diagnostic and recovery intervention required."
        )
    elif rec and rec.get("outcome") == "missing_parameters":
        missing = ", ".join(rec.get("missing_parameters", []))
        recommended_steps.insert(
            0,
            f"Remediation playbook requires human input: Missing parameter(s) '{missing}' "
            "before remediation can proceed."
        )

    # 4. Unresolved Questions
    unresolved_questions: List[str] = [
        "Did an external dependency or database network partition precede the error onset?",
        "Are error rates isolated to specific endpoints or affecting all service traffic?",
        "Was the anomaly accompanied by elevated client request concurrency?",
    ]

    # 5. Confidence & Limitations
    conf_score = top_hyp.confidence if top_hyp else 0.0
    conf_statement = (
        f"Evidential confidence score: {conf_score:.2f}. "
        "NOTE: This metric is a heuristic score based on observed HTTP status codes, Prometheus error counters, "
        "and alert triggers. It is NOT a calibrated statistical probability."
    )
    limitations_statement = (
        "Investigation operated under strict read-only constraints. Diagnostic probes were bounded "
        "to registered endpoints and public telemetry metrics without internal container shell or database inspection."
    )

    summary_obj = InvestigationSummary(
        incident_summary=inc_summary,
        likely_root_cause=likely_cause,
        ranked_hypotheses=hypotheses,
        supporting_evidence=supporting_obs,
        contradicting_evidence=contradicting_obs,
        confidence_and_limitations=conf_statement,
        unresolved_questions=unresolved_questions,
        recommended_next_steps=recommended_steps,
        limitations=limitations_statement,
        remediation_recommendation=rec,
    )

    return {
        "investigation_summary": summary_obj.model_dump(),
        "status": "completed",
    }
