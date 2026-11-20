"""Bounded asynchronous target prober for health and metrics."""

import re
import time
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import httpx
from app.core.config import settings
from app.core.logging import get_logger
from app.detector.validator import validate_target_url, SSRFValidationError

logger = get_logger("sentinelops.prober")


class ProbeResult:
    """Encapsulates the raw results of a target service probe."""
    def __init__(
        self,
        target_url: str,
        is_reachable: bool,
        status_code: Optional[int] = None,
        latency_ms: float = 0.0,
        response_body: Optional[str] = None,
        error_message: Optional[str] = None,
        metrics_data: Optional[Dict[str, float]] = None,
    ):
        self.target_url = target_url
        self.is_reachable = is_reachable
        self.status_code = status_code
        self.latency_ms = latency_ms
        self.response_body = response_body
        self.error_message = error_message
        self.metrics_data = metrics_data or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "is_reachable": self.is_reachable,
            "status_code": self.status_code,
            "latency_ms": round(self.latency_ms, 2),
            "error_message": self.error_message,
            "metrics": self.metrics_data,
        }


def parse_prometheus_text(text: str) -> Dict[str, float]:
    """Parse key counter and gauge values from Prometheus text format.

    Safely extracts metrics while strictly ignoring OpenMetrics epoch creation
    timestamps (*_created) from counter and error aggregations.
    """
    metrics: Dict[str, float] = {}
    dedicated_5xx_total: float = 0.0
    has_dedicated_5xx: bool = False
    status_5xx_total: float = 0.0

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(
            r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([0-9eE\.\+\-]+|NaN|\+Inf|-Inf)(?:\s+[0-9]+)?$",
            line,
        )
        if not match:
            parts = line.split()
            if len(parts) >= 2:
                metric_name_with_labels = parts[0]
                try:
                    val = float(parts[1])
                    if not (metric_name_with_labels.endswith("_created") or "_created" in metric_name_with_labels):
                        metrics[metric_name_with_labels] = val
                except ValueError:
                    pass
            continue

        m_name, labels_str, val_str = match.groups()
        try:
            val = float(val_str)
        except ValueError:
            continue

        key = f"{m_name}{{{labels_str}}}" if labels_str else m_name
        m_lower = m_name.lower()

        # STRICT SAFETY: *_created metrics are OpenMetrics timestamps, NEVER counters or gauges!
        if m_name.endswith("_created") or "_created" in m_name:
            continue

        metrics[key] = val

        # Check for dedicated 5xx error counters (e.g. order_api_http_5xx_errors_total, http_5xx_errors_total)
        if (
            m_lower == "order_api_http_5xx_errors_total"
            or m_lower.endswith("_5xx_errors_total")
            or m_lower == "http_5xx_errors_total"
            or "http_5xx_errors_total" in m_lower
            or m_lower.endswith("_5xx_total")
        ):
            dedicated_5xx_total += val
            has_dedicated_5xx = True
        elif labels_str and any(pat in labels_str for pat in ['status="5', "status='5", 'status_code="5', "status_code='5"]):
            status_5xx_total += val
        elif "5xx" in m_lower and not has_dedicated_5xx:
            status_5xx_total += val

    # Use dedicated 5xx counter if present, otherwise fallback to label-based 5xx status sum
    total_5xx = dedicated_5xx_total if has_dedicated_5xx else status_5xx_total
    metrics["total_5xx_errors"] = total_5xx
    return metrics


async def probe_service(
    health_url: str,
    timeout_seconds: Optional[float] = None,
    client: Optional[httpx.AsyncClient] = None,
    allow_local: Optional[bool] = None,
    monitoring_method: str = "prometheus",
) -> ProbeResult:
    """
    Safely probe a service's health endpoint and metrics endpoint.
    Guaranteed bounded timeout and SSRF protection.
    Disentangles monitoring method (prometheus vs opentelemetry/builtin).
    """
    timeout = timeout_seconds or settings.DETECTOR_TIMEOUT_SECONDS
    allow_loc = allow_local if allow_local is not None else settings.ALLOW_LOCAL_PROBES

    # 1. Validate target URL against SSRF
    try:
        validate_target_url(health_url, allow_local=allow_loc)
    except SSRFValidationError as err:
        logger.warning("SSRF validation failed for target %s: %s", health_url, str(err))
        return ProbeResult(
            target_url=health_url,
            is_reachable=False,
            error_message=f"SSRF validation blocked: {str(err)}",
        )

    # 2. Derive metrics URL from health URL (e.g. http://host:port/metrics)
    parsed = urlparse(health_url)
    metrics_url = f"{parsed.scheme}://{parsed.netloc}/metrics"

    manage_client = client is None
    http_client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    start_time = time.perf_counter()
    try:
        # Probe health endpoint
        response = await http_client.get(health_url)
        latency = (time.perf_counter() - start_time) * 1000.0

        metrics_map: Dict[str, float] = {}
        # Only probe metrics endpoint if service monitoring method is Prometheus pull scraping
        if (monitoring_method or "").lower() == "prometheus":
            try:
                m_resp = await http_client.get(metrics_url)
                if m_resp.status_code == 200:
                    metrics_map = parse_prometheus_text(m_resp.text)
            except Exception as m_exc:
                logger.debug("Metrics endpoint probe skipped or failed: %s", str(m_exc))

        return ProbeResult(
            target_url=health_url,
            is_reachable=True,
            status_code=response.status_code,
            latency_ms=latency,
            response_body=response.text[:1000],  # Bounded sample
            metrics_data=metrics_map,
        )

    except httpx.TimeoutException:
        latency = (time.perf_counter() - start_time) * 1000.0
        return ProbeResult(
            target_url=health_url,
            is_reachable=False,
            latency_ms=latency,
            error_message=f"Connection timed out after {timeout}s",
        )
    except httpx.ConnectError as exc:
        latency = (time.perf_counter() - start_time) * 1000.0
        return ProbeResult(
            target_url=health_url,
            is_reachable=False,
            latency_ms=latency,
            error_message=f"Connection refused or target host unreachable: {str(exc)}",
        )
    except Exception as exc:
        latency = (time.perf_counter() - start_time) * 1000.0
        return ProbeResult(
            target_url=health_url,
            is_reachable=False,
            latency_ms=latency,
            error_message=f"Probe failed: {str(exc)}",
        )
    finally:
        if manage_client:
            await http_client.aclose()
