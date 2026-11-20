"""Evaluation engine that combines target probes and deterministic rules."""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import httpx
from app.detector.prober import probe_service, ProbeResult
from app.detector.rules import (
    HealthStatusRule,
    Elevated5xxRule,
    LatencyThresholdRule,
    RuleEvaluation,
)
from app.models.service import Service


class DetectionReport:
    """Consolidated findings of an evaluation pass for a service."""
    def __init__(
        self,
        service_id: str,
        workspace_id: str,
        service_name: str,
        is_healthy: bool,
        triggered_rule: Optional[str] = None,
        severity: str = "low",
        trigger: Optional[str] = None,
        summary: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        probe_result: Optional[ProbeResult] = None,
    ):
        self.service_id = service_id
        self.workspace_id = workspace_id
        self.service_name = service_name
        self.is_healthy = is_healthy
        self.triggered_rule = triggered_rule
        self.severity = severity
        self.trigger = trigger
        self.summary = summary
        self.evidence = evidence or {}
        self.probe_result = probe_result
        self.evaluated_at = datetime.now(timezone.utc)


async def evaluate_service_health(
    service: Service,
    client: Optional[httpx.AsyncClient] = None,
    timeout_seconds: Optional[float] = None,
) -> DetectionReport:
    """
    Execute a deterministic evaluation pass against a registered service:
    1. Probe service health and metrics.
    2. Run rules pipeline.
    3. Construct structured DetectionReport.
    """
    probe = await probe_service(
        health_url=service.health_check_url,
        timeout_seconds=timeout_seconds,
        client=client,
        monitoring_method=service.monitoring_method or "prometheus",
    )

    # Registered deterministic rule set
    rules = [
        HealthStatusRule(),
        Elevated5xxRule(),
        LatencyThresholdRule(),
    ]

    failed_evaluation: Optional[RuleEvaluation] = None
    for rule in rules:
        eval_result = rule.evaluate(probe)
        if not eval_result.passed:
            failed_evaluation = eval_result
            break  # Prioritize primary health / 5xx rule failure

    evidence = {
        "target_url": probe.target_url,
        "is_reachable": probe.is_reachable,
        "status_code": probe.status_code,
        "latency_ms": round(probe.latency_ms, 2),
        "error_message": probe.error_message,
        "response_sample": probe.response_body[:300] if probe.response_body else None,
        "metrics_summary": probe.metrics_data,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    if failed_evaluation:
        return DetectionReport(
            service_id=service.id,
            workspace_id=service.workspace_id,
            service_name=service.name,
            is_healthy=False,
            triggered_rule=failed_evaluation.rule_name,
            severity=failed_evaluation.severity,
            trigger=failed_evaluation.trigger_message,
            summary=failed_evaluation.rationale,
            evidence=evidence,
            probe_result=probe,
        )

    return DetectionReport(
        service_id=service.id,
        workspace_id=service.workspace_id,
        service_name=service.name,
        is_healthy=True,
        severity="low",
        trigger=None,
        summary=f"All health and telemetry checks passed for service '{service.name}'",
        evidence=evidence,
        probe_result=probe,
    )
