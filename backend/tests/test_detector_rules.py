"""Test suite for deterministic detection rules."""

from app.detector.prober import ProbeResult
from app.detector.rules import HealthStatusRule, Elevated5xxRule, LatencyThresholdRule


def test_health_status_rule_healthy():
    """Verify rule passes on HTTP 200."""
    rule = HealthStatusRule()
    probe = ProbeResult(target_url="http://127.0.0.1:8001/health", is_reachable=True, status_code=200, latency_ms=15.0)
    res = rule.evaluate(probe)
    assert res.passed is True


def test_health_status_rule_500_failure():
    """Verify rule triggers high severity failure on HTTP 500."""
    rule = HealthStatusRule()
    probe = ProbeResult(
        target_url="http://127.0.0.1:8001/health",
        is_reachable=True,
        status_code=500,
        response_body='{"error": "Database timeout"}',
    )
    res = rule.evaluate(probe)
    assert res.passed is False
    assert res.severity == "high"
    assert "500" in res.trigger_message


def test_health_status_rule_unreachable():
    """Verify rule triggers critical/high failure on timeout or connection refusal."""
    rule = HealthStatusRule()
    probe = ProbeResult(
        target_url="http://127.0.0.1:8001/health",
        is_reachable=False,
        error_message="Connection timed out after 3.0s",
    )
    res = rule.evaluate(probe)
    assert res.passed is False
    assert res.severity == "critical"
    assert "timed out" in res.trigger_message


def test_elevated_5xx_rule():
    """Verify Prometheus metrics 5xx rule evaluation."""
    rule = Elevated5xxRule(threshold_errors=1.0)

    # 0 errors -> passes
    probe_clean = ProbeResult(target_url="http://test", is_reachable=True, status_code=200, metrics_data={"total_5xx_errors": 0.0})
    assert rule.evaluate(probe_clean).passed is True

    # 3 errors on unhealthy service -> fails
    probe_errors = ProbeResult(target_url="http://test", is_reachable=True, status_code=500, metrics_data={"total_5xx_errors": 3.0})
    eval_fail = rule.evaluate(probe_errors)
    assert eval_fail.passed is False
    assert eval_fail.severity == "high"
    assert "3 total 5xx errors" in eval_fail.trigger_message


def test_latency_threshold_rule():
    """Verify latency evaluation."""
    rule = LatencyThresholdRule(max_latency_ms=2000.0)

    # Fast -> passes
    probe_fast = ProbeResult(target_url="http://test", is_reachable=True, status_code=200, latency_ms=120.0)
    assert rule.evaluate(probe_fast).passed is True

    # Slow -> fails
    probe_slow = ProbeResult(target_url="http://test", is_reachable=True, status_code=200, latency_ms=4500.0)
    eval_slow = rule.evaluate(probe_slow)
    assert eval_slow.passed is False
    assert "threshold" in eval_slow.trigger_message
