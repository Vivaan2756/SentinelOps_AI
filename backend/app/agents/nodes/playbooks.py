"""Playbook Discovery, Compatibility Evaluation & Remediation Recommendation Nodes (Phase 4.3).

Implements deterministic discovery, validation, ranking, and recommendation of dynamic
remediation playbooks within the LangGraph incident investigation workflow.

Blueprint & Guardrail Guarantees:
- Deterministic evaluation: The LLM CANNOT authorize actions or override deterministic rejections.
- Tenant isolation: Playbooks, services, and incident records are strictly workspace-isolated.
- Fail-closed security: Inactive, unassociated, or unallowlisted actions are strictly rejected.
- Specification immutability: Recommendations bind the exact playbook ID, version, action template, and parameters.
- Never fabricate: Parameters are strictly validated; missing parameters trigger escalation without fabrication.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.core.logging import get_logger
from app.agents.state import InvestigationState
from app.models.playbook import Playbook, PlaybookVersion, ServicePlaybookAssociation
from app.models.service import Service
from app.remediation.registry import ActionRegistry, ACTION_PARAMETER_MODELS
from app.remediation.schemas import ActionCategory
from app.schemas.investigation import (
    PlaybookCompatibilityResult,
    RemediationRecommendation,
)

logger = get_logger("sentinelops.agents.nodes.playbooks")


async def discover_active_playbooks(
    state: InvestigationState,
    db: Session,
) -> Dict[str, Any]:
    """
    Node: discover_active_playbooks
    Retrieves active dynamic playbooks associated with the affected service in the current workspace.
    Fails closed if service or workspace cannot be resolved.
    """
    workspace_id = state.get("workspace_id")
    service_id = state.get("service_id")
    incident_context = state.get("incident_context", {})

    if not service_id and incident_context:
        service_id = incident_context.get("service_id")

    if not workspace_id or not service_id:
        logger.warning(
            "discover_active_playbooks: Missing workspace_id (%s) or service_id (%s); skipping discovery.",
            workspace_id,
            service_id,
        )
        return {
            "discovered_playbooks": [],
        }

    # Query active service-playbook associations joined with active playbooks
    # Strictly scoped by workspace_id to enforce multi-tenant isolation
    associations = (
        db.query(ServicePlaybookAssociation)
        .join(Playbook, Playbook.id == ServicePlaybookAssociation.playbook_id)
        .filter(
            ServicePlaybookAssociation.workspace_id == workspace_id,
            ServicePlaybookAssociation.service_id == service_id,
            ServicePlaybookAssociation.is_active == True,
            Playbook.workspace_id == workspace_id,
            Playbook.is_active == True,
        )
        .order_by(
            ServicePlaybookAssociation.priority.desc(),
            Playbook.name.asc(),
        )
        .all()
    )

    if not associations:
        service = db.query(Service).filter(Service.id == service_id, Service.workspace_id == workspace_id).first()
        if service and getattr(service, "recovery_enabled", False) and getattr(service, "recovery_endpoint", None):
            try:
                from app.remediation.playbook_service import PlaybookService
                PlaybookService.ensure_generic_http_recovery_playbook(db, workspace_id, service_id)
                associations = (
                    db.query(ServicePlaybookAssociation)
                    .join(Playbook, Playbook.id == ServicePlaybookAssociation.playbook_id)
                    .filter(
                        ServicePlaybookAssociation.workspace_id == workspace_id,
                        ServicePlaybookAssociation.service_id == service_id,
                        ServicePlaybookAssociation.is_active == True,
                        Playbook.workspace_id == workspace_id,
                        Playbook.is_active == True,
                    )
                    .order_by(
                        ServicePlaybookAssociation.priority.desc(),
                        Playbook.name.asc(),
                    )
                    .all()
                )
            except Exception as e:
                logger.warning("Failed to dynamically ensure generic playbook for service %s: %s", service_id, e)

    discovered: List[Dict[str, Any]] = []
    for assoc in associations:
        pb: Playbook = assoc.playbook
        if not pb or not pb.is_active:
            continue

        active_version = pb.active_version
        if not active_version:
            logger.warning("Playbook %s has no active version matching current_version %s", pb.id, pb.current_version)
            continue

        discovered.append({
            "playbook_id": pb.id,
            "playbook_name": pb.name,
            "category": pb.category,
            "current_version": pb.current_version,
            "priority": assoc.priority,
            "association_id": assoc.id,
            "version_id": active_version.id,
            "action_template_id": active_version.action_template_id,
            "supported_scenarios": active_version.supported_scenarios or [],
            "parameter_schema": active_version.parameter_schema or {},
            "verification_criteria": active_version.verification_criteria or {},
            "risk_level": active_version.risk_level,
            "approval_required": active_version.approval_required,
            "timeout_seconds": active_version.timeout_seconds,
        })

    logger.info(
        "discover_active_playbooks: Discovered %d active playbooks for service %s in workspace %s",
        len(discovered),
        service_id,
        workspace_id,
    )

    return {
        "discovered_playbooks": discovered,
    }


# ---------------------------------------------------------------------------
# Centralized Scenario Specification Registry (Deterministic Scenario Matching)
# ---------------------------------------------------------------------------

SCENARIO_SPEC_REGISTRY: Dict[str, Dict[str, Any]] = {
    "http_5xx_rate_exceeded": {
        "rule_ids": {"Prometheus_5xx_Error_Rule"},
        "trigger_indicators": {
            "http_5xx_rate_exceeded",
            "elevated 5xx",
            "5xx error",
            "5xx errors",
            "http 500",
            "http 502",
            "http 503",
            "http 504",
            "total_5xx_errors",
            "5xx server error",
            "5xx",
        },
        "root_cause_indicators": {
            "5xx",
            "http 5",
            "elevated application error rate",
            "server error",
            "downstream database timeout",
            "connection exhaustion",
        },
    },
    "health_check_failure": {
        "rule_ids": {"HTTP_Health_Status_Rule"},
        "trigger_indicators": {
            "health_check_failure",
            "health endpoint",
            "health probe",
            "service unreachable",
            "client error on health endpoint",
            "probe to http",
        },
        "root_cause_indicators": {
            "health check",
            "health endpoint",
            "probe failure",
            "service unreachable",
        },
    },
    "high_latency": {
        "rule_ids": {"High_Latency_Rule"},
        "trigger_indicators": {
            "high_latency",
            "high latency",
            "latency threshold",
            "max_latency_ms",
            "slow response",
        },
        "root_cause_indicators": {
            "high latency",
            "response latency",
            "latency degradation",
        },
    },
    "latency_spike": {
        "rule_ids": {"High_Latency_Rule"},
        "trigger_indicators": {
            "latency_spike",
            "latency spike",
            "high_latency",
            "high latency",
            "latency threshold",
            "max_latency_ms",
            "slow response",
        },
        "root_cause_indicators": {
            "high latency",
            "latency spike",
            "response latency",
            "latency degradation",
        },
    },
    "demo_failure": {
        "rule_ids": set(),
        "trigger_indicators": {
            "demo_failure",
            "demo failure",
            "simulated",
            "simulated failure",
            "injected failure",
        },
        "root_cause_indicators": {
            "demo failure",
            "simulated",
            "injected failure",
        },
    },
    "worker_process_failure": {
        "rule_ids": set(),
        "trigger_indicators": {
            "worker_process_failure",
            "worker process",
            "worker down",
            "queue consumer",
            "celery worker",
        },
        "root_cause_indicators": {
            "worker process",
            "queue consumer",
            "worker failure",
        },
    },
}


def is_scenario_compatible_with_incident(
    scenario: str,
    *,
    incident_trigger: str,
    incident_title: str,
    incident_summary: Optional[str] = None,
    triggered_rule: Optional[str] = None,
    supported_root_causes: Optional[List[str]] = None,
) -> bool:
    """
    Evaluates whether a candidate playbook scenario is compatible with an incident.
    Preserves exact/slug matching, applies structured detector rule signals,
    and checks trigger/title/root-cause indicators. Unknown scenarios fail closed.
    """
    normalized_sc = scenario.strip().lower().replace("-", "_")
    if normalized_sc in ("*", "all"):
        return True

    # Unknown scenario IDs must fail closed
    if normalized_sc not in SCENARIO_SPEC_REGISTRY:
        return False

    spec = SCENARIO_SPEC_REGISTRY[normalized_sc]

    norm_trigger = (incident_trigger or "").strip().lower().replace("-", "_")
    norm_title = (incident_title or "").strip().lower().replace("-", "_")
    norm_summary = (incident_summary or "").strip().lower().replace("-", "_")
    rc_list = [rc.lower().strip() for rc in (supported_root_causes or [])]

    # 1. Exact or substring match of scenario slug against trigger or title
    if normalized_sc in norm_trigger or normalized_sc in norm_title:
        return True

    # 2. Rule ID match
    rule_ids = spec.get("rule_ids", set())
    if triggered_rule and triggered_rule in rule_ids:
        return True

    # Special case: HealthStatusRule returning 5xx is also compatible with http_5xx_rate_exceeded
    if normalized_sc == "http_5xx_rate_exceeded" and triggered_rule == "HTTP_Health_Status_Rule":
        if any(term in norm_trigger or term in norm_title for term in ("5xx", "500", "502", "503", "504")):
            return True

    # 3. Trigger / title indicators
    trigger_indicators = spec.get("trigger_indicators", set())
    for indicator in trigger_indicators:
        if indicator in norm_trigger or indicator in norm_title:
            return True

    # 4. Summary indicators (require length > 3 to prevent accidental single-word collisions)
    if norm_summary:
        for indicator in trigger_indicators:
            if len(indicator) > 3 and indicator in norm_summary:
                return True

    # 5. Root cause indicators and scenario token splits (len >= 3 to include "5xx")
    root_cause_indicators = spec.get("root_cause_indicators", set())
    for rc in rc_list:
        for ind in root_cause_indicators:
            if ind in rc:
                return True
        for term in normalized_sc.split("_"):
            if len(term) >= 3 and term in rc:
                return True

    return False


def evaluate_playbook_compatibility(
    state: InvestigationState,
    db: Session,
) -> Dict[str, Any]:
    """
    Node: evaluate_playbook_compatibility
    Deterministically evaluates all discovered playbooks against 8 explicit criteria:
    1. Service applicability
    2. Incident scenario matching
    3. Root cause compatibility
    4. Action template support for service
    5. Parameter availability and validity
    6. Environment compatibility
    7. Active status verification
    8. Safety and execution policy constraints
    """
    discovered = state.get("discovered_playbooks", [])
    workspace_id = state.get("workspace_id")
    service_id = state.get("service_id")
    incident_context = state.get("incident_context", {})
    evidence_items = state.get("evidence_items", [])
    hypotheses = state.get("hypotheses", [])

    if not service_id and incident_context:
        service_id = incident_context.get("service_id")

    # Fetch authoritative service model
    service = None
    if service_id and workspace_id:
        service = (
            db.query(Service)
            .filter(Service.id == service_id, Service.workspace_id == workspace_id)
            .first()
        )

    # Incident attributes for scenario matching
    incident_trigger = (incident_context.get("trigger") or "").strip().lower()
    incident_title = (incident_context.get("title") or "").strip().lower()
    incident_severity = (incident_context.get("severity") or "").strip().lower()
    incident_summary = (incident_context.get("summary") or "").strip().lower()
    triggered_rule = incident_context.get("triggered_rule")

    # Top supported hypothesis and root cause collection
    top_hyp = hypotheses[0] if hypotheses and hypotheses[0].get("is_supported") else None
    root_cause = (top_hyp.get("root_cause") or "").lower() if top_hyp else ""
    is_indeterminate = not top_hyp or "insufficient" in root_cause or not top_hyp.get("is_supported", False)
    supported_root_causes = [
        (h.get("root_cause") or "").strip().lower()
        for h in hypotheses
        if h.get("is_supported") and h.get("root_cause")
    ]
    if root_cause and root_cause not in supported_root_causes:
        supported_root_causes.append(root_cause)

    # Telemetry evidence mapping
    evidence_ids = [e.get("evidence_id") for e in evidence_items if e.get("evidence_id")]
    err_evidence_ids = [
        e.get("evidence_id")
        for e in evidence_items
        if e.get("collection_status") in ("failed", "degraded")
        or any(k in e.get("observation", "").lower() for k in ["500", "503", "error", "timeout", "refused"])
    ]

    compatibility_results: List[Dict[str, Any]] = []
    compatible_list: List[Dict[str, Any]] = []
    rejected_list: List[Dict[str, Any]] = []

    for candidate in discovered:
        playbook_id = candidate["playbook_id"]
        playbook_name = candidate["playbook_name"]
        version_num = candidate["current_version"]
        action_template_id = candidate["action_template_id"]
        supported_scenarios = [s.lower().strip() for s in candidate.get("supported_scenarios", [])]
        candidate_params = dict(candidate.get("parameter_schema") or {})
        risk_level = candidate.get("risk_level", "medium")
        priority = candidate.get("priority", 0)

        rejection_reasons: List[str] = []
        matching_scenarios: List[str] = []
        matching_evidence: List[str] = []
        missing_parameters: List[str] = []
        validated_parameters: Dict[str, Any] = {}

        # --------------------------------------------------------------------
        # 1. Service Applicability Check
        # --------------------------------------------------------------------
        if not service:
            rejection_reasons.append("Target service could not be resolved in current workspace.")
        elif not service.is_active:
            rejection_reasons.append(f"Target service '{service.name}' is currently inactive.")

        # --------------------------------------------------------------------
        # 2. Scenario Trigger Matching
        # --------------------------------------------------------------------
        scenario_matched = False
        if "*" in supported_scenarios or not supported_scenarios:
            scenario_matched = True
            matching_scenarios.append("* (Universal)")
        else:
            for sc in supported_scenarios:
                if is_scenario_compatible_with_incident(
                    sc,
                    incident_trigger=incident_trigger,
                    incident_title=incident_title,
                    incident_summary=incident_summary,
                    triggered_rule=triggered_rule,
                    supported_root_causes=supported_root_causes,
                ):
                    scenario_matched = True
                    matching_scenarios.append(sc)

        if not scenario_matched:
            rejection_reasons.append(
                f"Incident trigger '{incident_trigger}' does not match supported scenarios: {candidate.get('supported_scenarios')}."
            )

        # --------------------------------------------------------------------
        # 3. Root Cause Compatibility Check
        # --------------------------------------------------------------------
        action_def = ActionRegistry.get_action(action_template_id)
        is_operational = action_def and action_def.category == ActionCategory.SERVICE_RECOVERY

        if is_indeterminate and is_operational:
            rejection_reasons.append(
                "Root-cause diagnosis is indeterminate or unsupported by telemetry evidence. "
                "Automated operational recovery cannot be safely recommended."
            )

        # --------------------------------------------------------------------
        # 4. Action Capability & Service Compatibility Check
        # --------------------------------------------------------------------
        if not action_def:
            rejection_reasons.append(
                f"Action template '{action_template_id}' is not in the allowlisted remediation registry."
            )
        elif not action_def.enabled:
            rejection_reasons.append(
                f"Action template '{action_template_id}' is currently disabled in the action registry."
            )
        elif service:
            cap = ActionRegistry.evaluate_service_capability(action_template_id, service, db=db)
            if not cap.is_compatible or not cap.is_executable:
                for r in cap.reasons:
                    if r not in rejection_reasons:
                        rejection_reasons.append(r)

        # --------------------------------------------------------------------
        # 5. Parameter Validation & Completeness Check
        # --------------------------------------------------------------------
        if service and action_def:
            # Inject service_id automatically if expected
            if "service_id" not in candidate_params and service_id:
                candidate_params["service_id"] = service_id

            # Model parameter validation
            is_valid, parsed_model, err_or_model = ActionRegistry.validate_parameters(
                action_template_id, candidate_params
            )
            if is_valid:
                validated_parameters = (
                    parsed_model.model_dump()
                    if hasattr(parsed_model, "model_dump")
                    else (parsed_model or {})
                )
            else:
                # Check if failure is due to missing required fields
                param_model = ACTION_PARAMETER_MODELS.get(action_template_id)
                if param_model:
                    for field_name, field_info in param_model.model_fields.items():
                        if field_info.is_required() and field_name not in candidate_params:
                            missing_parameters.append(field_name)

                if missing_parameters:
                    rejection_reasons.append(
                        f"Missing required action parameters: {', '.join(missing_parameters)}."
                    )
                else:
                    rejection_reasons.append(f"Parameter schema validation failed: {err_or_model}")

        # --------------------------------------------------------------------
        # 6. Target Environment Restrictions
        # --------------------------------------------------------------------
        if service and action_def:
            svc_env = (service.environment or "").strip().lower()
            supported_envs = [e.lower() for e in (action_def.supported_environments or ["development"])]
            if svc_env not in supported_envs:
                rejection_reasons.append(
                    f"Service environment '{service.environment}' is not supported by action template '{action_template_id}' (requires {supported_envs})."
                )

        # --------------------------------------------------------------------
        # 7. Safety & Execution Policy Enforcement
        # --------------------------------------------------------------------
        if service and is_operational:
            svc_policy = (service.execution_policy or "").strip().lower()
            if not svc_policy:
                rejection_reasons.append("Service execution policy is null or missing. Failing closed.")
            elif svc_policy == "observe_only":
                rejection_reasons.append("Service execution policy is 'observe_only'; operational recovery actions are forbidden.")
            elif svc_policy not in ("demo", "approval_required"):
                rejection_reasons.append(f"Service execution policy '{service.execution_policy}' is unsupported.")

        # Match evidence items
        if top_hyp:
            matching_evidence = [
                eid for eid in top_hyp.get("supporting_evidence_ids", [])
                if eid in evidence_ids
            ]
        if not matching_evidence and err_evidence_ids:
            matching_evidence = err_evidence_ids[:2]

        is_compatible = len(rejection_reasons) == 0

        explanation = ""
        if is_compatible:
            explanation = (
                f"Playbook '{playbook_name}' (v{version_num}) is compatible: Action template "
                f"'{action_template_id}' is allowlisted and supported for service '{service.name if service else 'unknown'}', "
                f"matched scenario(s) {matching_scenarios}, parameters verified, and environment policy satisfied."
            )
        else:
            explanation = f"Playbook '{playbook_name}' rejected: {'; '.join(rejection_reasons)}"

        compat_result = {
            "playbook_id": playbook_id,
            "playbook_name": playbook_name,
            "version_number": version_num,
            "action_template_id": action_template_id,
            "is_compatible": is_compatible,
            "rejection_reasons": rejection_reasons,
            "matching_scenarios": matching_scenarios,
            "matching_evidence_ids": matching_evidence,
            "missing_parameters": missing_parameters,
            "validated_parameters": validated_parameters,
            "risk_level": risk_level,
            "priority": priority,
            "compatibility_explanation": explanation,
        }

        compatibility_results.append(compat_result)
        if is_compatible:
            compatible_list.append(compat_result)
        else:
            rejected_list.append(compat_result)

    logger.info(
        "evaluate_playbook_compatibility: Evaluated %d playbooks (%d compatible, %d rejected)",
        len(compatibility_results),
        len(compatible_list),
        len(rejected_list),
    )

    return {
        "playbook_compatibility_results": compatibility_results,
        "compatible_playbooks": compatible_list,
        "rejected_playbooks": rejected_list,
    }


def rank_compatible_playbooks(
    state: InvestigationState,
    llm: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Node: rank_compatible_playbooks
    Ranks compatible playbooks deterministically based on:
    1. Association priority descending
    2. Specific scenario match over wildcard '*'
    3. Evidential score and risk level (lowest operational risk preferred)
    """
    compatible = state.get("compatible_playbooks", [])
    if not compatible:
        return {"ranked_playbooks": []}

    if len(compatible) == 1:
        return {"ranked_playbooks": compatible}

    def sort_key(candidate: Dict[str, Any]) -> tuple:
        priority = candidate.get("priority", 0)
        # Prefer exact scenario match over wildcard
        has_wildcard = "*" in candidate.get("matching_scenarios", [])
        scenario_specificity = 0 if has_wildcard else 1
        # Risk ordering: low > medium > high
        risk = candidate.get("risk_level", "medium").lower()
        risk_score = {"low": 3, "medium": 2, "high": 1}.get(risk, 0)
        return (priority, scenario_specificity, risk_score)

    ranked = sorted(compatible, key=sort_key, reverse=True)
    return {"ranked_playbooks": ranked}


def generate_remediation_recommendation(
    state: InvestigationState,
) -> Dict[str, Any]:
    """
    Node: generate_remediation_recommendation
    Produces the structured RemediationRecommendation representing one of four canonical outcomes:
    - Outcome A: Single compatible playbook found -> Actionable recommendation.
    - Outcome B: Multiple compatible playbooks found -> Ranked recommendation.
    - Outcome C: No compatible playbook found -> Human escalation required.
    - Outcome D: Missing required parameters -> Parameter collection escalation required.
    """
    ranked_playbooks = state.get("ranked_playbooks", [])
    compatible_playbooks = state.get("compatible_playbooks", [])
    rejected_playbooks = state.get("rejected_playbooks", [])
    incident_context = state.get("incident_context", {})
    workspace_id = state.get("workspace_id")
    incident_id = state.get("incident_id")
    investigation_id = state.get("investigation_id")
    service_id = state.get("service_id") or incident_context.get("service_id")
    service_name = incident_context.get("service_name", "Monitored service")
    hypotheses = state.get("hypotheses", [])
    top_hyp = hypotheses[0] if hypotheses and hypotheses[0].get("is_supported") else None
    root_cause = top_hyp.get("root_cause") if top_hyp else "Indeterminate cause"

    # Outcome D: Check if any candidate was rejected solely due to missing parameters
    missing_param_candidates = [
        r for r in rejected_playbooks if r.get("missing_parameters") and len(r.get("rejection_reasons", [])) == 1
    ]

    recommendation: Dict[str, Any]

    if ranked_playbooks:
        primary = ranked_playbooks[0]
        has_multiple = len(ranked_playbooks) > 1

        outcome = "multiple_compatible" if has_multiple else "compatible_found"
        explanation = (
            f"Diagnosed primary root cause '{root_cause}' on {service_name}. "
            f"Recommended active playbook '{primary['playbook_name']}' (v{primary['version_number']}) "
            f"targeting allowlisted action '{primary['action_template_id']}' with verified parameters. "
            f"Playbook priority: {primary['priority']}."
        )
        if has_multiple:
            alt_names = [f"'{p['playbook_name']}' (priority {p['priority']})" for p in ranked_playbooks[1:]]
            explanation += f" Evaluated and ranked {len(ranked_playbooks)} compatible candidates. Alternatives: {', '.join(alt_names)}."

        recommendation = {
            "outcome": outcome,
            "status": "actionable",
            "playbook_id": primary["playbook_id"],
            "playbook_name": primary["playbook_name"],
            "playbook_version": primary["version_number"],
            "action_template_id": primary["action_template_id"],
            "service_id": service_id,
            "workspace_id": workspace_id,
            "incident_id": incident_id,
            "investigation_id": investigation_id,
            "risk_level": primary.get("risk_level", "medium"),
            "parameters": primary.get("validated_parameters", {}),
            "explanation": explanation,
            "supporting_evidence_ids": primary.get("matching_evidence_ids", []),
            "missing_parameters": [],
            "compatible_playbooks": compatible_playbooks,
            "rejected_playbooks": rejected_playbooks,
            "ranked_candidates": ranked_playbooks,
            "escalation_reason": None,
        }

    elif missing_param_candidates:
        # Outcome D: Missing parameters escalation
        candidate = missing_param_candidates[0]
        missing = candidate["missing_parameters"]
        recommendation = {
            "outcome": "missing_parameters",
            "status": "human_escalation_required",
            "playbook_id": candidate["playbook_id"],
            "playbook_name": candidate["playbook_name"],
            "playbook_version": candidate["version_number"],
            "action_template_id": candidate["action_template_id"],
            "service_id": service_id,
            "workspace_id": workspace_id,
            "incident_id": incident_id,
            "investigation_id": investigation_id,
            "risk_level": candidate.get("risk_level", "medium"),
            "parameters": {},
            "explanation": (
                f"Candidate playbook '{candidate['playbook_name']}' (v{candidate['version_number']}) "
                f"matches incident symptoms, but required parameters ({', '.join(missing)}) could not be resolved from telemetry or defaults. "
                "Parameters must be provided by a human engineer before remediation can proceed."
            ),
            "supporting_evidence_ids": candidate.get("matching_evidence_ids", []),
            "missing_parameters": missing,
            "compatible_playbooks": [],
            "rejected_playbooks": rejected_playbooks,
            "ranked_candidates": [],
            "escalation_reason": (
                f"Missing required parameter(s): {', '.join(missing)}. "
                "Never fabricating parameter values under SentinelOps safety policies."
            ),
        }

    else:
        # Outcome C: No compatible playbook -> Human escalation required
        rejection_summaries = []
        for r in rejected_playbooks:
            reasons = "; ".join(r.get("rejection_reasons", []))
            rejection_summaries.append(f"Playbook '{r['playbook_name']}': {reasons}")

        escalation_explanation = (
            f"No approved, active remediation playbook is currently configured or compatible for service '{service_name}' "
            f"matching the diagnosed incident condition ('{root_cause}'). "
            "Autonomous recovery cannot be initiated. Human SRE engineer intervention is required."
        )

        escalation_reason = (
            f"Evaluated {len(rejected_playbooks)} candidate playbook(s); all were rejected by deterministic policy: "
            + ("; ".join(rejection_summaries) if rejection_summaries else "Zero playbooks bound to service.")
        )

        recommendation = {
            "outcome": "no_compatible_playbook",
            "status": "human_escalation_required",
            "playbook_id": None,
            "playbook_name": None,
            "playbook_version": None,
            "action_template_id": None,
            "service_id": service_id,
            "workspace_id": workspace_id,
            "incident_id": incident_id,
            "investigation_id": investigation_id,
            "risk_level": None,
            "parameters": {},
            "explanation": escalation_explanation,
            "supporting_evidence_ids": [],
            "missing_parameters": [],
            "compatible_playbooks": [],
            "rejected_playbooks": rejected_playbooks,
            "ranked_candidates": [],
            "escalation_reason": escalation_reason,
        }

    return {
        "remediation_recommendation": recommendation,
    }
