"""Read-only Prometheus metrics diagnostic tool for Agentic SRE."""

import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, Optional, Tuple
import httpx
from app.core.config import settings
from app.detector.validator import validate_target_url, SSRFValidationError


def derive_metrics_url(health_url: str) -> str:
    """Derive standard /metrics endpoint from registered health URL."""
    parsed = urlparse(health_url)
    # If path already ends in /metrics, keep it; otherwise replace or append /metrics
    new_path = "/metrics"
    return urlunparse((parsed.scheme, parsed.netloc, new_path, "", "", ""))


def parse_metrics_payload(text: str) -> Tuple[Dict[str, float], float, float]:
    """
    Parse Prometheus text exposition payload into operational metrics.

    Safely calculates exact 5xx error counter total and requests total while
    strictly ignoring OpenMetrics epoch creation timestamps (*_created).

    Returns:
        (parsed_metrics, error_5xx_total, requests_total)
    """
    parsed_metrics: Dict[str, float] = {}
    dedicated_5xx_total: float = 0.0
    has_dedicated_5xx: bool = False
    status_5xx_total: float = 0.0
    requests_total: float = 0.0

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(
            r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([0-9eE\.\+\-]+|NaN|\+Inf|-Inf)(?:\s+[0-9]+)?$",
            line,
        )
        if not match:
            continue

        m_name, labels_str, val_str = match.groups()
        try:
            val = float(val_str)
        except ValueError:
            continue

        key = f"{m_name}{{{labels_str}}}" if labels_str else m_name
        m_lower = m_name.lower()

        # STRICT REQUIREMENT: OpenMetrics *_created timestamp metrics MUST NEVER be counted as counter totals!
        if m_name.endswith("_created") or "_created" in m_name:
            continue

        # Keep operational metrics in scraped_metrics dictionary
        if any(k in m_lower for k in ["5xx", "error", "requests_total", "requests", "latency", "duration", "cpu", "memory"]):
            parsed_metrics[key] = val

        # 1. 5xx Error Calculation: Prioritize dedicated 5xx counter (e.g. order_api_http_5xx_errors_total)
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

        # 2. Total Requests Calculation
        if m_lower.endswith("_requests_total") or m_lower == "http_requests_total" or "requests_total" in m_lower:
            requests_total += val

    error_5xx_total = dedicated_5xx_total if has_dedicated_5xx else status_5xx_total
    return parsed_metrics, error_5xx_total, requests_total


async def collect_metrics_evidence(
    health_url: str,
    evidence_id: str = "ev-metrics",
    client: Optional[httpx.AsyncClient] = None,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Safely probes Prometheus metrics endpoint, extracts 5xx error counters and
    request latency vectors. Returns an EvidenceItem dictionary.
    """
    metrics_url = derive_metrics_url(health_url)
    timeout = timeout_seconds or settings.DETECTOR_TIMEOUT_SECONDS
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. SSRF Safety Check
    try:
        validate_target_url(metrics_url, allow_local=settings.ALLOW_LOCAL_PROBES)
    except SSRFValidationError as e:
        return {
            "evidence_id": evidence_id,
            "source": "prometheus_metrics",
            "observation": f"Metrics probe blocked by SSRF safeguard: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": metrics_url, "error": str(e), "error_type": "ssrf_violation"},
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "source": "prometheus_metrics",
            "observation": f"Metrics URL validation failed: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": metrics_url, "error": str(e)},
        }

    # 2. Execute Bounded Metrics Probe
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout)
        close_client = True

    start_time = time.perf_counter()
    try:
        response = await client.get(metrics_url)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if response.status_code != 200:
            return {
                "evidence_id": evidence_id,
                "source": "prometheus_metrics",
                "observation": (
                    f"Metrics endpoint {metrics_url} returned HTTP {response.status_code} "
                    f"(metrics unavailable or unconfigured)."
                ),
                "timestamp": now_iso,
                "collection_status": "not_available",
                "data": {"url": metrics_url, "status_code": response.status_code},
            }

        # Parse text metrics
        text = response.text[:settings.MAX_EVIDENCE_PAYLOAD_BYTES]
        parsed_metrics, error_5xx_total, requests_total = parse_metrics_payload(text)

        # Synthesize clean observation summary without created timestamps
        fmt_5xx = int(error_5xx_total) if error_5xx_total.is_integer() else round(error_5xx_total, 2)
        fmt_req = int(requests_total) if requests_total.is_integer() else round(requests_total, 2)

        obs_summary = (
            f"Scraped Prometheus metrics from {metrics_url} in {duration_ms}ms. "
            f"Observed 5xx error counter total: {fmt_5xx}; total requests recorded: {fmt_req}."
        )
        if error_5xx_total > 0:
            obs_summary += f" Alert rule trigger consistent with elevated 5xx error count ({fmt_5xx})."
        else:
            obs_summary += " No active 5xx errors recorded in current telemetry counter window."

        return {
            "evidence_id": evidence_id,
            "source": "prometheus_metrics",
            "observation": obs_summary,
            "timestamp": now_iso,
            "collection_status": "success",
            "data": {
                "url": metrics_url,
                "error_5xx_total": error_5xx_total,
                "requests_total": requests_total,
                "scraped_metrics": dict(list(parsed_metrics.items())[:20]),
                "latency_ms": duration_ms,
            },
        }

    except httpx.TimeoutException:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "evidence_id": evidence_id,
            "source": "prometheus_metrics",
            "observation": f"Metrics probe to {metrics_url} timed out after {duration_ms}ms.",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": metrics_url, "error": "timeout"},
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "source": "prometheus_metrics",
            "observation": f"Metrics endpoint probe to {metrics_url} failed: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": metrics_url, "error": str(e)},
        }
    finally:
        if close_client:
            await client.aclose()
