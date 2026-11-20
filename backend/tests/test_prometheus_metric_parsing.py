"""Regression test suite for Prometheus metric parsing and OpenMetrics timestamp handling.

Validates:
1. `_created` metrics are strictly ignored and never interpreted as counter values.
2. Identical prefix pairs (e.g. `order_api_http_5xx_errors_total` vs `order_api_http_5xx_errors_created`) are handled correctly.
3. Exact `order_api_http_5xx_errors_total` extraction and aggregation across label sets.
4. Total requests calculation without timestamp contamination.
5. AI evidence observations, alert explanations, and data payloads use the corrected metric values.
6. Unrelated metrics, duration histograms, gauges, and arbitrary labels continue to work.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from app.detector.prober import parse_prometheus_text, ProbeResult
from app.detector.rules import Elevated5xxRule
from app.agents.tools.metrics import parse_metrics_payload, collect_metrics_evidence


SAMPLE_PROMETHEUS_OUTPUT = """# HELP order_api_http_5xx_errors_total Total count of HTTP 5xx server errors emitted by Order API
# TYPE order_api_http_5xx_errors_total counter
order_api_http_5xx_errors_total{endpoint="/health",method="GET"} 5.0
order_api_http_5xx_errors_created{endpoint="/health",method="GET"} 1793344593.570527
# HELP order_api_http_requests_total Total count of HTTP requests processed by Order API
# TYPE order_api_http_requests_total counter
order_api_http_requests_total{endpoint="/health",method="GET",status_code="200"} 42.0
order_api_http_requests_total{endpoint="/health",method="GET",status_code="500"} 5.0
order_api_http_requests_created{endpoint="/health",method="GET",status_code="200"} 1793344593.570123
order_api_http_requests_created{endpoint="/health",method="GET",status_code="500"} 1793344593.570123
# HELP order_api_http_request_duration_seconds HTTP request latency in seconds
# TYPE order_api_http_request_duration_seconds histogram
order_api_http_request_duration_seconds_bucket{endpoint="/health",le="0.05",method="GET"} 40.0
order_api_http_request_duration_seconds_bucket{endpoint="/health",le="+Inf",method="GET"} 47.0
order_api_http_request_duration_seconds_sum{endpoint="/health",method="GET"} 1.25
order_api_http_request_duration_seconds_count{endpoint="/health",method="GET"} 47.0
order_api_http_request_duration_seconds_created{endpoint="/health",method="GET"} 1793344593.570527
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 12.34
# HELP jvm_memory_used_bytes Memory usage
# TYPE jvm_memory_used_bytes gauge
jvm_memory_used_bytes{area="heap",id="G1_Old_Gen"} 104857600.0
"""


def test_created_timestamps_never_interpreted_as_counter_values():
    """Verify that *_created epoch timestamps are never added to counter values."""
    parsed_metrics, error_5xx, req_total = parse_metrics_payload(SAMPLE_PROMETHEUS_OUTPUT)

    # 1. Exact 5xx error counter total must be 5.0, NOT 1793344598+
    assert error_5xx == 5.0
    assert error_5xx < 1000.0  # Safeguard against timestamp contamination

    # 2. Total requests must be 42 + 5 = 47.0, NOT adding *_created timestamps
    assert req_total == 47.0

    # 3. *_created keys must not pollute parsed_metrics
    for key in parsed_metrics.keys():
        assert not key.startswith("order_api_http_5xx_errors_created")
        assert not key.startswith("order_api_http_requests_created")
        assert not key.startswith("order_api_http_request_duration_seconds_created")


def test_prober_parse_prometheus_text_ignores_created_metrics():
    """Verify that prober.parse_prometheus_text extracts total_5xx_errors without _created."""
    metrics_map = parse_prometheus_text(SAMPLE_PROMETHEUS_OUTPUT)

    # total_5xx_errors must equal 5.0
    assert "total_5xx_errors" in metrics_map
    assert metrics_map["total_5xx_errors"] == 5.0

    # Ensure _created keys are excluded
    for key in metrics_map.keys():
        assert not key.startswith("order_api_http_5xx_errors_created")


def test_elevated_5xx_alert_explanation_accuracy():
    """Verify that alert explanations cite the exact error count, not timestamps."""
    metrics_map = parse_prometheus_text(SAMPLE_PROMETHEUS_OUTPUT)

    probe = ProbeResult(
        target_url="http://127.0.0.1:8001/health",
        is_reachable=True,
        status_code=500,
        metrics_data=metrics_map,
    )

    rule = Elevated5xxRule(threshold_errors=1.0)
    result = rule.evaluate(probe)

    assert result.passed is False
    assert result.severity == "high"
    # Expected: "Prometheus telemetry indicates 5 total 5xx errors recorded"
    assert "5 total 5xx errors" in result.trigger_message
    assert "1793344" not in result.trigger_message
    assert "5.0" in result.rationale
    assert "1793344" not in result.rationale


@pytest.mark.asyncio
async def test_ai_metrics_evidence_collection_and_observation():
    """Verify that collect_metrics_evidence builds accurate observations for AI investigation."""
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = SAMPLE_PROMETHEUS_OUTPUT
    mock_client.get.return_value = mock_resp

    evidence = await collect_metrics_evidence(
        health_url="http://127.0.0.1:8001/health",
        evidence_id="ev-metrics-test",
        client=mock_client,
    )

    assert evidence["collection_status"] == "success"
    assert evidence["data"]["error_5xx_total"] == 5.0
    assert evidence["data"]["requests_total"] == 47.0

    obs = evidence["observation"]
    assert "Observed 5xx error counter total: 5;" in obs
    assert "total requests recorded: 47." in obs
    assert "elevated 5xx error count (5)" in obs

    # Critical check: timestamp ~1.79 billion must NOT appear in the observation
    assert "1793344" not in obs


def test_multiple_endpoints_5xx_errors_aggregation():
    """Verify that 5xx errors across multiple endpoints are summed, ignoring created timestamps."""
    multi_endpoint_text = """
order_api_http_5xx_errors_total{endpoint="/health",method="GET"} 3.0
order_api_http_5xx_errors_created{endpoint="/health",method="GET"} 1793344593.0
order_api_http_5xx_errors_total{endpoint="/orders",method="POST"} 7.0
order_api_http_5xx_errors_created{endpoint="/orders",method="POST"} 1793344593.0
order_api_http_requests_total{endpoint="/health",method="GET"} 10.0
order_api_http_requests_total{endpoint="/orders",method="POST"} 20.0
"""
    parsed, error_5xx, req_total = parse_metrics_payload(multi_endpoint_text)
    assert error_5xx == 10.0  # 3 + 7
    assert req_total == 30.0  # 10 + 20


def test_dedicated_counter_precedence_over_generic_requests():
    """Verify dedicated 5xx counter prevents double counting with http_requests_total."""
    overlap_text = """
order_api_http_5xx_errors_total{endpoint="/health",method="GET"} 4.0
order_api_http_requests_total{endpoint="/health",method="GET",status_code="500"} 4.0
order_api_http_requests_total{endpoint="/health",method="GET",status_code="200"} 16.0
"""
    parsed, error_5xx, req_total = parse_metrics_payload(overlap_text)
    # Must use dedicated counter (4.0), not 4.0 + 4.0 = 8.0
    assert error_5xx == 4.0
    assert req_total == 20.0


def test_label_based_5xx_status_fallback():
    """Verify fallback for generic Prometheus exporters with status code labels."""
    generic_text = """
http_requests_total{method="GET",status="500"} 6.0
http_requests_total{method="POST",status="503"} 2.0
http_requests_total{method="GET",status="200"} 50.0
http_requests_created{method="GET",status="500"} 1793344593.0
"""
    parsed, error_5xx, req_total = parse_metrics_payload(generic_text)
    assert error_5xx == 8.0  # 6 + 2
    assert req_total == 58.0  # 6 + 2 + 50


def test_unrelated_metrics_and_labels_preserved():
    """Verify that non-error metrics (histograms, gauges, cpu) and arbitrary labels work normally."""
    parsed, error_5xx, req_total = parse_metrics_payload(SAMPLE_PROMETHEUS_OUTPUT)

    assert parsed.get("process_cpu_seconds_total") == 12.34
    assert parsed.get('order_api_http_request_duration_seconds_sum{endpoint="/health",method="GET"}') == 1.25
    assert parsed.get('order_api_http_request_duration_seconds_count{endpoint="/health",method="GET"}') == 47.0
    assert parsed.get('jvm_memory_used_bytes{area="heap",id="G1_Old_Gen"}') == 104857600.0
