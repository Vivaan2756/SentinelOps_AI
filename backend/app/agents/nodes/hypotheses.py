"""Node 3: Hypothesis Generation using Gemini 2.5 Flash for Agentic SRE."""

from typing import Dict, Any, List, Optional
from langchain_core.messages import SystemMessage, HumanMessage
from app.core.config import settings
from app.core.logging import get_logger
from app.agents.state import InvestigationState
from app.agents.prompts.investigation import (
    SYSTEM_INVESTIGATION_PROMPT,
    format_investigation_prompt,
)
from app.schemas.investigation import (
    Hypothesis,
    HypothesisGenerationOutput,
)

logger = get_logger("sentinelops.agents.hypotheses")


def deterministic_fallback_hypotheses(
    incident_context: dict,
    evidence_items: list,
) -> HypothesisGenerationOutput:
    """
    Deterministic hypothesis synthesizer used when GEMINI_API_KEY is not configured
    or when the LLM provider experiences network/quota interruptions.
    Ensures zero unhandled exceptions and full operational continuity.
    """
    hypotheses: List[Hypothesis] = []

    # Map observations and identify signals
    has_healthy_probe = False
    healthy_ids: List[str] = []
    has_timeout = False
    has_connect_error = False
    has_http_500 = False
    has_elevated_5xx = False
    has_high_latency = False
    err_supporting_ids: List[str] = []

    for ev in evidence_items:
        obs = ev.get("observation", "").lower()
        ev_id = ev.get("evidence_id", "ev-1")

        if "200 ok" in obs or "returned http 200" in obs or "status: 'healthy'" in obs:
            has_healthy_probe = True
            healthy_ids.append(ev_id)

        if any(k in obs for k in ["database timeout", "database request timed out", "connection pool", "pool exhausted"]):
            has_timeout = True
            err_supporting_ids.append(ev_id)
        elif any(k in obs for k in ["connection refused", "host unreachable"]):
            has_connect_error = True
            err_supporting_ids.append(ev_id)
        elif any(k in obs for k in ["http 500", "returned http 500", "status_code 500", "status: 500", "status 500", "http 503", "returned http 503", "status_code 503", "status: 503", "status 503"]):
            has_http_500 = True
            err_supporting_ids.append(ev_id)
        elif "elevated 5xx error count" in obs or "elevated 5xx" in obs:

            has_elevated_5xx = True
            err_supporting_ids.append(ev_id)
        elif "latency" in obs and any(k in obs for k in ["high", "exceeded", "threshold", "3200", "delay"]):
            has_high_latency = True
            err_supporting_ids.append(ev_id)

    unique_err_ids = list(dict.fromkeys(err_supporting_ids))
    unique_healthy_ids = list(dict.fromkeys(healthy_ids))

    # Check if telemetry is insufficient / completely missing or failed without connection refused
    telemetry_items = [e for e in evidence_items if e.get("source") in ("health_probe", "prometheus_metrics")]
    all_telemetry_failed = (
        len(telemetry_items) == 0
        or (all(e.get("collection_status") == "failed" for e in telemetry_items) and not has_connect_error)
    )

    if all_telemetry_failed:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Insufficient Diagnostic Evidence for Definitive Root Cause",
                supporting_evidence_ids=[e.get("evidence_id") for e in evidence_items if e.get("evidence_id")],
                contradicting_evidence_ids=[],
                explanation="No active telemetry could be gathered from service endpoints. Telemetry targets unreachable or unconfigured.",
                confidence=0.20,
                is_supported=False,
                evaluation_notes="Evidence is insufficient to diagnose underlying cause.",
            )
        )

    elif has_timeout:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Downstream Database Timeout / Connection Exhaustion",
                supporting_evidence_ids=unique_err_ids or ["ev-1"],
                contradicting_evidence_ids=[],
                explanation="Health probe and detector evidence captured HTTP 500 error reporting database request timeout. Telemetry indicates downstream connection pool exhaustion.",
                confidence=0.88,
            )
        )
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-2",
                root_cause="Elevated Application Error Rate",
                supporting_evidence_ids=unique_err_ids or ["ev-1"],
                contradicting_evidence_ids=[],
                explanation="Order API service returning 5xx status codes causing alert trigger activation.",
                confidence=0.75,
            )
        )
    elif has_connect_error and has_healthy_probe:
        # Conflicting signals: prior alert was unreachable, but live probe is 200 OK
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Normal Operational Variance / Transient Anomaly",
                supporting_evidence_ids=unique_healthy_ids or ["ev-2"],
                contradicting_evidence_ids=unique_err_ids,
                explanation="Live diagnostic health probe returned HTTP 200 OK. The previous unreachable alert was likely a transient anomaly or false alarm.",
                confidence=0.80,
            )
        )
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-2",
                root_cause="Service Process Unreachable / Network Interruption",
                supporting_evidence_ids=unique_err_ids or ["ev-1"],
                contradicting_evidence_ids=unique_healthy_ids,
                explanation="Prior alert recorded connection failure, but live check is currently responding.",
                confidence=0.40,
            )
        )
    elif has_connect_error:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Service Process Unreachable / Network Interruption",
                supporting_evidence_ids=unique_err_ids or ["ev-1"],
                contradicting_evidence_ids=[],
                explanation="Probe could not establish TCP connection to registered target URL.",
                confidence=0.90,
            )
        )
    elif has_http_500 or has_elevated_5xx:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Internal Server Error (HTTP 500) Degradation",
                supporting_evidence_ids=unique_err_ids or ["ev-1"],
                contradicting_evidence_ids=[],
                explanation="Target service returning 500 response codes as evidenced by health probe and metric counters.",
                confidence=0.85,
            )
        )
    elif has_high_latency:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Elevated Response Latency / Degraded Downstream Performance",
                supporting_evidence_ids=unique_err_ids or unique_healthy_ids or ["ev-1"],
                contradicting_evidence_ids=[],
                explanation="Telemetry captures latency exceeding baseline thresholds during operational checks.",
                confidence=0.82,
            )
        )
    elif has_healthy_probe:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Normal Operational Variance / Transient Anomaly",
                supporting_evidence_ids=unique_healthy_ids or [e.get("evidence_id") for e in evidence_items if e.get("evidence_id")],
                contradicting_evidence_ids=[],
                explanation="Diagnostic health checks returned 200 OK and metrics show zero active 5xx errors.",
                confidence=0.80,
            )
        )
    else:
        hypotheses.append(
            Hypothesis(
                hypothesis_id="hyp-1",
                root_cause="Insufficient Diagnostic Evidence for Definitive Root Cause",
                supporting_evidence_ids=[e.get("evidence_id") for e in evidence_items if e.get("evidence_id")],
                contradicting_evidence_ids=[],
                explanation="No active telemetry could be gathered from service endpoints. Telemetry targets unreachable or unconfigured.",
                confidence=0.20,
                is_supported=False,
                evaluation_notes="Evidence is insufficient to diagnose underlying cause.",
            )
        )


    return HypothesisGenerationOutput(
        hypotheses=hypotheses,
        evidence_sufficient=len(hypotheses) > 0 and hypotheses[0].confidence > 0.3,
        reasoning_notes="Generated via deterministic telemetry rule synthesis.",
    )



async def generate_hypotheses(
    state: InvestigationState,
    llm: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Executes structured hypothesis generation:
    1. Uses Gemini 2.5 Flash if GEMINI_API_KEY is available (or passed mock LLM).
    2. Falls back to deterministic rule synthesis if API key is not configured.
    """
    incident_context = state.get("incident_context", {})
    evidence_items = state.get("evidence_items", [])
    model_name = settings.GEMINI_MODEL
    prompt_version = settings.INVESTIGATION_PROMPT_VERSION

    # Check if custom LLM injected (e.g. in test fixtures)
    active_llm = llm

    if active_llm is None and settings.GEMINI_API_KEY:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            active_llm = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=settings.GEMINI_API_KEY,
                temperature=0.1,
                timeout=settings.INVESTIGATION_TIMEOUT_SECONDS,
            )
        except Exception as e:
            logger.warning("Could not initialize ChatGoogleGenerativeAI: %s", str(e))
            active_llm = None

    token_usage = None

    if active_llm is not None:
        try:
            formatted_prompt = format_investigation_prompt(incident_context, evidence_items)
            messages = [
                SystemMessage(content=SYSTEM_INVESTIGATION_PROMPT),
                HumanMessage(content=formatted_prompt),
            ]

            # Try structured output
            structured_llm = active_llm.with_structured_output(HypothesisGenerationOutput)
            result: HypothesisGenerationOutput = await structured_llm.ainvoke(messages)

            hypotheses_dict = [h.model_dump() for h in result.hypotheses]
            return {
                "hypotheses": hypotheses_dict,
                "model_name": model_name,
                "prompt_version": prompt_version,
                "token_usage": token_usage,
            }
        except Exception as e:
            logger.error("Gemini 2.5 Flash invocation error: %s. Using deterministic fallback.", str(e))
            errors = state.get("errors", []) + [f"Gemini API invocation error: {str(e)}"]
            fallback = deterministic_fallback_hypotheses(incident_context, evidence_items)
            return {
                "hypotheses": [h.model_dump() for h in fallback.hypotheses],
                "model_name": f"{model_name}-fallback",
                "prompt_version": prompt_version,
                "errors": errors,
            }
    else:
        # Deterministic fallback when no API key configured
        fallback = deterministic_fallback_hypotheses(incident_context, evidence_items)
        return {
            "hypotheses": [h.model_dump() for h in fallback.hypotheses],
            "model_name": f"{model_name}-deterministic",
            "prompt_version": prompt_version,
        }
