"""Deterministic detection rules for evaluating service telemetry and health.

No LLM is used for incident detection or rule evaluation. All rules are deterministic,
measurable, and auditable per Blueprint Section 2, 5, and 8.
"""

from typing import Optional, Tuple
from app.detector.prober import ProbeResult


class RuleEvaluation:
    """Outcome of a single deterministic rule evaluation."""
    def __init__(
        self,
        passed: bool,
        rule_name: str,
        severity: str = "high",
        trigger_message: Optional[str] = None,
        rationale: Optional[str] = None,
    ):
        self.passed = passed
        self.rule_name = rule_name
        self.severity = severity
        self.trigger_message = trigger_message
        self.rationale = rationale


class HealthStatusRule:
    """
    Evaluates whether the service is reachable and returning healthy HTTP status codes (< 500).
    Fails on connection timeout, refusal, or HTTP 5xx responses.
    """
    def __init__(self, name: str = "HTTP_Health_Status_Rule"):
        self.name = name

    def evaluate(self, probe: ProbeResult) -> RuleEvaluation:
        # Check target reachability
        if not probe.is_reachable:
            return RuleEvaluation(
                passed=False,
                rule_name=self.name,
                severity="critical" if "timed out" in (probe.error_message or "") else "high",
                trigger_message=f"Service unreachable: {probe.error_message}",
                rationale=f"Health probe to {probe.target_url} failed with error: {probe.error_message}",
            )

        # Check HTTP status code
        if probe.status_code is not None and probe.status_code >= 500:
            return RuleEvaluation(
                passed=False,
                rule_name=self.name,
                severity="high",
                trigger_message=f"Elevated 5xx error: HTTP {probe.status_code} returned by health endpoint",
                rationale=f"Health probe to {probe.target_url} returned HTTP {probe.status_code}. Response snippet: {probe.response_body[:200]}",
            )

        if probe.status_code is not None and probe.status_code >= 400:
            return RuleEvaluation(
                passed=False,
                rule_name=self.name,
                severity="medium",
                trigger_message=f"Client error on health endpoint: HTTP {probe.status_code}",
                rationale=f"Health probe returned client error {probe.status_code}.",
            )

        return RuleEvaluation(passed=True, rule_name=self.name)


class Elevated5xxRule:
    """
    Evaluates Prometheus metrics for accumulated HTTP 5xx server errors.
    """
    def __init__(self, name: str = "Prometheus_5xx_Error_Rule", threshold_errors: float = 1.0):
        self.name = name
        self.threshold_errors = threshold_errors

    def evaluate(self, probe: ProbeResult) -> RuleEvaluation:
        # If health endpoint returns 200 OK and target is reachable, the service has recovered
        if probe.is_reachable and probe.status_code == 200:
            return RuleEvaluation(passed=True, rule_name=self.name)

        total_5xx = probe.metrics_data.get("total_5xx_errors", 0.0)
        if total_5xx >= self.threshold_errors:
            return RuleEvaluation(
                passed=False,
                rule_name=self.name,
                severity="high",
                trigger_message=f"Prometheus telemetry indicates {int(total_5xx)} total 5xx errors recorded",
                rationale=f"Metric total_5xx_errors reached {total_5xx}, exceeding threshold of {self.threshold_errors}.",
            )
        return RuleEvaluation(passed=True, rule_name=self.name)


class LatencyThresholdRule:
    """
    Evaluates response latency against configured maximum latency threshold.
    """
    def __init__(self, name: str = "High_Latency_Rule", max_latency_ms: float = 4000.0):
        self.name = name
        self.max_latency_ms = max_latency_ms

    def evaluate(self, probe: ProbeResult) -> RuleEvaluation:
        if probe.latency_ms > self.max_latency_ms:
            return RuleEvaluation(
                passed=False,
                rule_name=self.name,
                severity="medium",
                trigger_message=f"Elevated response latency: {probe.latency_ms:.1f}ms exceeds threshold of {self.max_latency_ms}ms",
                rationale=f"Latency observed was {probe.latency_ms:.1f}ms on {probe.target_url}.",
            )
        return RuleEvaluation(passed=True, rule_name=self.name)
