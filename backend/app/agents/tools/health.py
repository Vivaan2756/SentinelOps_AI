"""Read-only health check diagnostic tool for Agentic SRE."""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings
from app.detector.validator import validate_target_url, SSRFValidationError


async def collect_health_evidence(
    url: str,
    evidence_id: str = "ev-health",
    client: Optional[httpx.AsyncClient] = None,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Safely probes registered service health endpoint with SSRF safeguards and bounded limits.
    Returns an EvidenceItem dictionary.
    """
    timeout = timeout_seconds or settings.DETECTOR_TIMEOUT_SECONDS
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. SSRF Safety Check
    try:
        validate_target_url(url, allow_local=settings.ALLOW_LOCAL_PROBES)
    except SSRFValidationError as e:
        return {
            "evidence_id": evidence_id,
            "source": "health_probe",
            "observation": f"Health check blocked by SSRF safeguard: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": url, "error": str(e), "error_type": "ssrf_violation"},
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "source": "health_probe",
            "observation": f"Health check URL validation error: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": url, "error": str(e), "error_type": "invalid_url"},
        }

    # 2. Execute Bounded Probe
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout)
        close_client = True

    start_time = time.perf_counter()
    try:
        response = await client.get(url)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Truncate response content to prevent payload flooding
        max_bytes = settings.MAX_EVIDENCE_PAYLOAD_BYTES
        raw_text = response.text[:max_bytes]

        try:
            json_body = response.json()
        except Exception:
            json_body = None

        is_2xx = 200 <= response.status_code < 300
        obs_detail = (
            f"Health check probe to {url} returned HTTP {response.status_code} in {duration_ms}ms."
        )
        if not is_2xx:
            obs_detail += f" Response snippet: {raw_text[:200]}"
        elif json_body and isinstance(json_body, dict):
            status_val = json_body.get("status") or json_body.get("state")
            if status_val:
                obs_detail += f" Reported payload status: '{status_val}'."

        return {
            "evidence_id": evidence_id,
            "source": "health_probe",
            "observation": obs_detail,
            "timestamp": now_iso,
            "collection_status": "success" if is_2xx else "degraded",
            "data": {
                "url": url,
                "status_code": response.status_code,
                "latency_ms": duration_ms,
                "body_preview": raw_text[:500],
                "json_payload": json_body if isinstance(json_body, (dict, list)) else None,
            },
        }

    except httpx.TimeoutException:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "evidence_id": evidence_id,
            "source": "health_probe",
            "observation": f"Health probe to {url} timed out after {duration_ms}ms (threshold: {timeout}s).",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": url, "error": "timeout", "latency_ms": duration_ms},
        }
    except httpx.ConnectError as e:
        return {
            "evidence_id": evidence_id,
            "source": "health_probe",
            "observation": f"Health probe to {url} failed: Connection refused or host unreachable.",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": url, "error": str(e), "error_type": "connect_error"},
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "source": "health_probe",
            "observation": f"Health probe to {url} encountered unexpected error: {str(e)}",
            "timestamp": now_iso,
            "collection_status": "failed",
            "data": {"url": url, "error": str(e), "error_type": "unknown_exception"},
        }
    finally:
        if close_client:
            await client.aclose()
