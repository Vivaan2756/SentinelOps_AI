"""LangGraph state definition for Agentic AI Incident Investigation."""

from typing import TypedDict, List, Dict, Any, Optional


class InvestigationState(TypedDict):
    """
    Explicit, strongly-typed state dictionary passed across LangGraph nodes.
    Maintains incident context, collected evidence items, evaluated hypotheses,
    model metadata, and execution error logs.
    """
    # Identifiers
    incident_id: str
    workspace_id: str
    service_id: Optional[str]
    investigation_id: Optional[str]

    # Lifecycle & status
    status: str  # "pending", "running", "completed", "partially_completed", "failed"
    started_at: Optional[str]
    completed_at: Optional[str]

    # Context & inputs
    incident_context: Dict[str, Any]

    # Evidence artifacts
    evidence_items: List[Dict[str, Any]]
    evidence_errors: List[str]

    # Hypothesis artifacts
    hypotheses: List[Dict[str, Any]]

    # Final summary & recommendations
    investigation_summary: Optional[Dict[str, Any]]

    # Dynamic playbook integration (Phase 4.3)
    discovered_playbooks: List[Dict[str, Any]]
    playbook_compatibility_results: List[Dict[str, Any]]
    compatible_playbooks: List[Dict[str, Any]]
    rejected_playbooks: List[Dict[str, Any]]
    ranked_playbooks: List[Dict[str, Any]]
    remediation_recommendation: Optional[Dict[str, Any]]

    # Telemetry, models & guardrail audit
    model_name: str
    prompt_version: str
    token_usage: Optional[Dict[str, Any]]
    errors: List[str]
