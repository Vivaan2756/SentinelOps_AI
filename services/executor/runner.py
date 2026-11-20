"""Static Action Executor Runner with Connection-Time DNS/IP Pinning.

Executed inside the ephemeral container sandbox:
- Reads action parameters and validated network parameters from environment variables.
- Strictly validates pinned IP, target host, port, scheme, and path consistency.
- Routes TCP connections directly to the validated pinned IP via PinnedSyncBackend.
- Preserves the original hostname for HTTP Host header, TLS SNI, and certificate validation.
- Strictly disables automatic HTTP redirect following (follow_redirects=False).
- Dispatches strictly to static handlers (restore_order_api_demo, inspect_service_health).
- Outputs structured JSON to stdout.
- Zero shell or dynamic script execution.
"""

import ipaddress
import json
import os
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpcore
from httpcore._backends.sync import SyncBackend
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator


DEV_HOST_GATEWAY_HOSTNAME: str = "host.docker.internal"
DEV_LOCALHOST_ORIGINS: Set[str] = {
    "127.0.0.1",
    "localhost",
    DEV_HOST_GATEWAY_HOSTNAME,
}

# Blocked cloud metadata & link-local IP addresses (IPv4 & IPv6)
FORBIDDEN_METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS / Azure / GCP IMDSv1/v2 IPv4
    "169.254.170.2",    # AWS ECS task metadata
    "100.100.100.200",  # Alibaba metadata
    "fd00:ec2::254",    # AWS EC2 IMDS IPv6
}

# Trusted Docker host-gateway networks for development environment:
# - RFC 1918 private IPv4 subnets (standard Docker bridge & host-gateway subnets)
# - RFC 4193 IPv6 Unique Local Address (ULA) prefix fc00::/7 (Docker Desktop WSL2/Hyper-V gateway)
TRUSTED_DOCKER_GATEWAY_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def resolve_and_validate_host_gateway(
    hostname: str,
    port: int,
    trusted_gateway: Optional[str] = None,
) -> str:
    """
    Safely resolves the Docker host-gateway IP for 'host.docker.internal' and validates:
    1. Only 'host.docker.internal' is permitted for host-gateway resolution.
    2. Queries system resolver (/etc/hosts populated by Docker's --add-host host.docker.internal:host-gateway).
    3. Rejects unexpected multiple conflicting addresses within the same address family.
    4. Strictly NOT loopback (127.0.0.0/8, ::1) since container loopback cannot reach host.
    5. Strictly NOT cloud metadata or link-local metadata endpoints.
    6. Rejects multicast, unspecified, and reserved special addresses.
    7. Matches configured trusted gateway IP (if provided) or belongs to trusted Docker gateway networks.
    """
    clean_host = hostname.lower().strip()
    if clean_host != DEV_HOST_GATEWAY_HOSTNAME:
        raise RuntimeError(
            f"Host-gateway resolution is strictly restricted to '{DEV_HOST_GATEWAY_HOSTNAME}', got '{hostname}'."
        )

    try:
        addr_info = socket.getaddrinfo(
            DEV_HOST_GATEWAY_HOSTNAME,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        raise RuntimeError(f"Failed to resolve host-gateway '{DEV_HOST_GATEWAY_HOSTNAME}': {e}")

    if not addr_info:
        raise RuntimeError(f"Host-gateway '{DEV_HOST_GATEWAY_HOSTNAME}' resolved to zero IP addresses.")

    # Deduplicate resolved IP addresses while preserving discovery order
    unique_raw_ips: List[str] = list(dict.fromkeys(entry[4][0] for entry in addr_info))

    validated_ips: List[Tuple[str, Any]] = []
    ipv4_candidates: List[str] = []
    ipv6_candidates: List[str] = []

    for raw_ip in unique_raw_ips:
        # Validate IP address syntax
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError as e:
            raise RuntimeError(f"Invalid resolved IP '{raw_ip}' for '{DEV_HOST_GATEWAY_HOSTNAME}': {e}")

        # Handle IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
            raw_ip = str(ip)

        # 1. Reject loopback addresses
        if ip.is_loopback:
            raise RuntimeError(
                f"Resolved host-gateway IP '{raw_ip}' is a loopback address. "
                "Ephemeral container loopback cannot connect to host services."
            )

        # 2. Reject metadata IPs
        if str(ip).lower() in FORBIDDEN_METADATA_IPS:
            raise RuntimeError(
                f"Resolved host-gateway IP '{raw_ip}' is a forbidden cloud metadata endpoint."
            )

        # 3. Reject multicast, unspecified, reserved
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise RuntimeError(
                f"Resolved host-gateway IP '{raw_ip}' is an invalid special address."
            )

        # 4. Validate that IP belongs to trusted Docker gateway networks
        in_trusted_network = any(ip in net for net in TRUSTED_DOCKER_GATEWAY_NETWORKS)
        if not in_trusted_network:
            raise RuntimeError(
                f"Resolved host-gateway IP '{raw_ip}' is not in trusted Docker gateway networks "
                f"({[str(n) for n in TRUSTED_DOCKER_GATEWAY_NETWORKS]})."
            )

        validated_ips.append((raw_ip, ip))
        if ip.version == 4:
            ipv4_candidates.append(raw_ip)
        else:
            ipv6_candidates.append(raw_ip)

    # Reject multiple conflicting addresses within the same address family
    if len(ipv4_candidates) > 1:
        raise RuntimeError(
            f"Host-gateway '{DEV_HOST_GATEWAY_HOSTNAME}' resolved to multiple conflicting IPv4 addresses: {ipv4_candidates}."
        )
    if len(ipv6_candidates) > 1:
        raise RuntimeError(
            f"Host-gateway '{DEV_HOST_GATEWAY_HOSTNAME}' resolved to multiple conflicting IPv6 addresses: {ipv6_candidates}."
        )

    # 5. Check against configured trusted gateway (if provided via parameter or environment variable)
    config_gateway = (trusted_gateway or os.environ.get("SENTINELOPS_TRUSTED_GATEWAY_IP", "")).strip()
    if config_gateway:
        allowed_gateways = [g.strip() for g in config_gateway.split(",") if g.strip()]
        matched_ips: List[str] = []
        for raw_ip, ip in validated_ips:
            for allowed in allowed_gateways:
                try:
                    allowed_net = ipaddress.ip_network(allowed, strict=False)
                    if ip in allowed_net:
                        matched_ips.append(raw_ip)
                        break
                except ValueError:
                    if str(ip) == allowed:
                        matched_ips.append(raw_ip)
                        break
        if not matched_ips:
            raise RuntimeError(
                f"Resolved host-gateway IP does not match configured trusted gateway '{config_gateway}': {unique_raw_ips}."
            )
        return matched_ips[0]

    # 6. Default selection: IPv4 is preferred for Docker bridge network connectivity
    if ipv4_candidates:
        return ipv4_candidates[0]
    return ipv6_candidates[0]


class PinnedSyncBackend(SyncBackend):
    """
    Custom NetworkBackend that connects TCP sockets directly to the validated pinned IP.
    Prevents DNS resolution and DNS rebinding attacks at connection time.
    Preserves server_hostname for TLS SNI and certificate verification.

    Development Exception:
    For 'host.docker.internal' in development/test environments only, securely resolves
    the Docker host-gateway IP provided via --add-host host.docker.internal:host-gateway
    and validates it against trusted gateway IP networks/configuration before routing TCP.
    """

    def __init__(
        self,
        target_host: str,
        pinned_ip: str,
        environment: str = "development",
        trusted_gateway: Optional[str] = None,
    ):
        super().__init__()
        self.target_host = target_host.lower().strip()
        self.pinned_ip = pinned_ip.strip()
        self.environment = environment.lower().strip()
        self.trusted_gateway = trusted_gateway

    @property
    def is_dev_env(self) -> bool:
        return self.environment in ("development", "dev", "test")

    def connect_tcp(
        self,
        host: str,
        port: int,
        *args,
        **kwargs,
    ) -> httpcore.NetworkStream:
        """
        Intercept TCP connection: if host matches expected target_host,
        route directly to pinned_ip (or validated host-gateway IP for host.docker.internal in dev),
        bypassing arbitrary DNS lookup entirely.
        """
        clean_host = host.lower().strip()
        if clean_host != self.target_host:
            raise RuntimeError(
                f"Connection blocked: attempted connection to unpinned host '{host}' (expected '{self.target_host}')."
            )

        # Narrowly scoped development-only mapping for localhost origins to Docker host-gateway
        if clean_host in DEV_LOCALHOST_ORIGINS:
            if not self.is_dev_env:
                raise RuntimeError(
                    f"Connection blocked: localhost / host-gateway origin '{clean_host}' is strictly prohibited in "
                    f"non-development environment '{self.environment}'."
                )
            connect_ip = resolve_and_validate_host_gateway(
                DEV_HOST_GATEWAY_HOSTNAME,
                port,
                trusted_gateway=self.trusted_gateway,
            )
            return super().connect_tcp(connect_ip, port, *args, **kwargs)

        # Security validation for non-localhost pinned IP connections
        try:
            ip_obj = ipaddress.ip_address(self.pinned_ip)
        except ValueError as e:
            raise RuntimeError(f"Connection blocked: invalid pinned IP '{self.pinned_ip}': {e}")

        # Reject cloud metadata endpoints
        if str(ip_obj).lower() in FORBIDDEN_METADATA_IPS:
            raise RuntimeError(
                f"Connection blocked: pinned IP '{self.pinned_ip}' is a forbidden cloud metadata endpoint."
            )

        # Reject loopback IPs in non-development environments
        if ip_obj.is_loopback and not self.is_dev_env:
            raise RuntimeError(
                f"Connection blocked: loopback IP '{self.pinned_ip}' is prohibited in "
                f"non-development environment '{self.environment}'."
            )

        # Reject unrelated loopback addresses outside standard 127.0.0.1 / ::1
        if ip_obj.is_loopback and str(ip_obj) not in ("127.0.0.1", "::1"):
            raise RuntimeError(
                f"Connection blocked: loopback IP '{self.pinned_ip}' is prohibited outside standard 127.0.0.1 loopback."
            )

        # For all other targets, strictly route to pinned_ip without DNS lookup
        return super().connect_tcp(self.pinned_ip, port, *args, **kwargs)


class PinnedIPTransport(httpx.HTTPTransport):
    """
    HTTPX transport configuring a ConnectionPool with PinnedSyncBackend.
    Ensures that connections to target_host use the pinned IP while preserving Host header and TLS SNI.
    """

    def __init__(
        self,
        target_host: str,
        pinned_ip: str,
        verify: bool = True,
        environment: str = "development",
        trusted_gateway: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(verify=verify, **kwargs)
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._pool._ssl_context,
            network_backend=PinnedSyncBackend(
                target_host,
                pinned_ip,
                environment=environment,
                trusted_gateway=trusted_gateway,
            ),
        )


def validate_connection_parameters(
    target_url: str,
    pinned_ip: str,
    target_host: str,
    target_port: int,
    target_scheme: str,
    target_path: str,
) -> None:
    """
    Strict fail-closed validation of all network parameters before connection.
    Guarantees no mismatch between URL and pinned connection parameters.
    """
    if not target_url:
        raise ValueError("Missing TARGET_URL environment variable.")
    if not pinned_ip:
        raise ValueError("Missing PINNED_IP environment variable.")
    if not target_host:
        raise ValueError("Missing TARGET_HOST environment variable.")

    # Validate IP address format (IPv4 or IPv6)
    try:
        ip_obj = ipaddress.ip_address(pinned_ip)
    except ValueError as e:
        raise ValueError(f"Invalid PINNED_IP '{pinned_ip}': {e}")

    if str(ip_obj).lower() in FORBIDDEN_METADATA_IPS:
        raise ValueError(f"PINNED_IP '{pinned_ip}' is a forbidden cloud metadata endpoint.")

    # Parse and validate target_url consistency
    parsed = urlparse(target_url)
    if parsed.scheme.lower() != target_scheme.lower():
        raise ValueError(f"Scheme mismatch: URL scheme '{parsed.scheme}' != TARGET_SCHEME '{target_scheme}'.")

    url_host = (parsed.hostname or "").lower().strip()
    if url_host != target_host.lower().strip():
        raise ValueError(f"Hostname mismatch: URL host '{url_host}' != TARGET_HOST '{target_host}'.")

    url_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if url_port != int(target_port):
        raise ValueError(f"Port mismatch: URL port {url_port} != TARGET_PORT {target_port}.")

    url_path = parsed.path.rstrip("/") or "/"
    expected_path = target_path.rstrip("/") or "/"
    if url_path != expected_path:
        raise ValueError(f"Path mismatch: URL path '{url_path}' != TARGET_PATH '{expected_path}'.")


def run_restore_order_api_demo(
    target_url: str,
    timeout_seconds: float = 30.0,
    pinned_ip: Optional[str] = None,
    target_host: Optional[str] = None,
    tls_verify: bool = True,
    environment: str = "development",
    trusted_gateway: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute restore_order_api_demo against target endpoint using pinned IP connection."""
    parsed = urlparse(target_url)
    target_host = target_host or parsed.hostname or "localhost"
    pinned_ip = pinned_ip or "127.0.0.1"

    transport = PinnedIPTransport(
        target_host=target_host,
        pinned_ip=pinned_ip,
        verify=tls_verify,
        environment=environment,
        trusted_gateway=trusted_gateway,
    )
    with httpx.Client(transport=transport, timeout=timeout_seconds, follow_redirects=False) as client:
        resp = client.post(target_url)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            raise RuntimeError(f"HTTP Redirect to '{resp.headers.get('location')}' rejected: redirects are forbidden.")
        if resp.status_code != 200:
            raise RuntimeError(f"Target service returned HTTP {resp.status_code}: {resp.text}")
        try:
            return resp.json()
        except Exception:
            return {"raw_text": resp.text, "status_code": resp.status_code}


class HttpRecoveryModel(BaseModel):
    """Strict parameter model for execute_http_recovery in executor sandbox (Phase 5A)."""
    service_id: Optional[str] = None
    recovery_path: str = Field(..., description="Relative recovery endpoint path")
    payload: Optional[Dict[str, Any]] = None
    expected_status_codes: Optional[List[int]] = Field(default_factory=lambda: [200])
    timeout_seconds: Optional[int] = Field(default=30)

    model_config = ConfigDict(extra="forbid")

    @field_validator("recovery_path")
    @classmethod
    def validate_recovery_path(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("recovery_path must be a non-empty string")
        v = v.strip()
        if not v.startswith("/"):
            raise ValueError("recovery_path must start with '/'")
        if ".." in v or "?" in v or "#" in v or "@" in v or "://" in v or "//" in v or "\\" in v or "%" in v:
            raise ValueError("recovery_path contains forbidden traversal, characters, or URL delimiters")
        if not re.match(r"^/[a-zA-Z0-9_./-]*$", v):
            raise ValueError(f"recovery_path contains invalid characters: {v}")
        return v

    @field_validator("expected_status_codes")
    @classmethod
    def validate_status_codes(cls, v: Optional[List[int]]) -> List[int]:
        if not v:
            return [200]
        for c in v:
            if not isinstance(c, int) or c < 200 or c > 299:
                raise ValueError(f"Invalid status code '{c}': only 2xx HTTP success codes permitted")
        return sorted(list(set(v)))


def run_http_recovery(
    target_url: str,
    payload: Optional[Dict[str, Any]] = None,
    expected_status_codes: Optional[List[int]] = None,
    timeout_seconds: float = 30.0,
    pinned_ip: Optional[str] = None,
    target_host: Optional[str] = None,
    tls_verify: bool = True,
    environment: str = "development",
    trusted_gateway: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute HTTP POST recovery operation against target endpoint using pinned IP connection.
    Strictly rejects redirects and accepts only configured 2xx response codes.
    """
    parsed = urlparse(target_url)
    target_host = target_host or parsed.hostname or "localhost"
    pinned_ip = pinned_ip or "127.0.0.1"
    expected_codes = expected_status_codes or [200]

    transport = PinnedIPTransport(
        target_host=target_host,
        pinned_ip=pinned_ip,
        verify=tls_verify,
        environment=environment,
        trusted_gateway=trusted_gateway,
    )

    start_time = time.time()
    with httpx.Client(transport=transport, timeout=timeout_seconds, follow_redirects=False) as client:
        resp = client.post(target_url, json=payload if payload is not None else None)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Strictly reject redirects (SSRF defense)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location", "")
            raise RuntimeError(f"HTTP Redirect to '{loc}' rejected: redirects are forbidden.")

        if resp.status_code not in expected_codes:
            raise RuntimeError(f"Target service returned unexpected HTTP {resp.status_code}: {resp.text[:200]}")

        try:
            body = resp.json()
        except Exception:
            body = {"raw_text": resp.text[:1000], "status_code": resp.status_code}

        return {
            "status": "completed",
            "action": "execute_http_recovery",
            "target_url": target_url,
            "status_code": resp.status_code,
            "duration_ms": duration_ms,
            "response": body,
        }


DIAGNOSTIC_PATHS: Tuple[Tuple[str, str], ...] = (
    ("/health", "health"),
    ("/demo/status", "demo_status"),
    ("/metrics", "metrics"),
)


class InspectServiceHealthModel(BaseModel):
    """Strict canonical parameter contract for inspect_service_health in executor sandbox."""
    service_id: Optional[str] = None
    health_path: Optional[str] = Field(default="/health")
    is_demo_service: bool = Field(default=False)
    has_prometheus_metrics: bool = Field(default=False)

    model_config = ConfigDict(extra="forbid")

    @field_validator("health_path")
    @classmethod
    def validate_health_path(cls, v: Optional[str]) -> str:
        if v is None:
            return "/health"
        v = v.strip()
        if not v.startswith("/"):
            v = f"/{v}"
        if ".." in v or "?" in v or "#" in v:
            raise ValueError(
                "health_path must be a clean relative path without query strings or directory traversal"
            )
        if not re.match(r"^/[a-zA-Z0-9_./-]*$", v):
            raise ValueError(f"health_path contains invalid path characters: {v}")
        return v


def run_inspect_service_health(
    target_url: str,
    timeout_seconds: float = 30.0,
    pinned_ip: Optional[str] = None,
    target_host: Optional[str] = None,
    tls_verify: bool = True,
    environment: str = "development",
    trusted_gateway: Optional[str] = None,
    http_timeout_seconds: Optional[float] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute unified inspect_service_health against target endpoint using pinned IP connection.
    Collects health endpoint, and conditionally /demo/status and /metrics for demo services
    within a single process and HTTP client session.
    Reuses the HTTP connection pool across all diagnostic requests.
    """
    parsed = urlparse(target_url)
    target_host = target_host or parsed.hostname or "localhost"
    pinned_ip = pinned_ip or "127.0.0.1"
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or f"{target_host}:{parsed.port or (443 if scheme == 'https' else 80)}"
    base_url = f"{scheme}://{netloc}"

    # Individual HTTP request timeout (separate from overall container/dispatch timeout)
    request_timeout = http_timeout_seconds or float(os.environ.get("HTTP_TIMEOUT_SECONDS", "3.0"))

    # Resolve and strictly validate parameters
    raw_params = parameters or {}
    if not raw_params and os.environ.get("PARAMETERS_JSON"):
        try:
            raw_params = json.loads(os.environ["PARAMETERS_JSON"])
        except Exception as e:
            raise ValueError(f"Invalid JSON in PARAMETERS_JSON: {e}")

    # Strict canonical model validation (extra='forbid')
    validated_params = InspectServiceHealthModel.model_validate(raw_params)

    # Service-specific health path: preserve custom paths (e.g. /api/v1/system/health)
    if raw_params.get("health_path"):
        health_path = validated_params.health_path
    else:
        health_path = parsed.path or "/health"
    if not health_path.startswith("/"):
        health_path = f"/{health_path}"

    is_demo_service = validated_params.is_demo_service
    if "is_demo_service" not in raw_params:
        # Default heuristic: Order API host/port or standard /health path without custom prefix
        is_order_api = "8001" in netloc or "order" in target_host.lower() or "order" in target_url.lower()
        is_demo_service = is_order_api or (health_path == "/health")

    has_prometheus_metrics = validated_params.has_prometheus_metrics

    # Build dynamic diagnostic paths to probe
    diagnostic_paths: List[Tuple[str, str]] = [(health_path, "health")]
    if is_demo_service:
        diagnostic_paths.append(("/demo/status", "demo_status"))
        diagnostic_paths.append(("/metrics", "metrics"))
    elif has_prometheus_metrics:
        diagnostic_paths.append(("/metrics", "metrics"))

    transport = PinnedIPTransport(
        target_host=target_host,
        pinned_ip=pinned_ip,
        verify=tls_verify,
        environment=environment,
        trusted_gateway=trusted_gateway,
    )

    results: Dict[str, Any] = {
        "status": "completed",
        "action": "inspect_service_health",
        "base_url": base_url,
        "endpoints": {},
        "all_endpoints_successful": True,
    }

    start_all = time.time()
    with httpx.Client(transport=transport, timeout=request_timeout, follow_redirects=False) as client:
        for path, ep_key in diagnostic_paths:
            ep_url = f"{base_url}{path}"
            ep_start = time.time()
            ep_res: Dict[str, Any] = {
                "endpoint": path,
                "status_code": None,
                "duration_ms": 0.0,
                "output_data": None,
                "error_message": None,
                "success": False,
            }

            try:
                resp = client.get(ep_url)
                ep_res["duration_ms"] = round((time.time() - ep_start) * 1000, 2)
                ep_res["status_code"] = resp.status_code

                # Strict redirect rejection (SSRF protection)
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location", "")
                    raise RuntimeError(f"HTTP Redirect to '{loc}' rejected: redirects are forbidden.")

                if resp.status_code == 200:
                    ep_res["success"] = True
                    try:
                        ep_res["output_data"] = resp.json()
                    except Exception:
                        ep_res["output_data"] = {"raw_text": resp.text, "status_code": resp.status_code}
                        ep_res["raw_text"] = resp.text
                else:
                    ep_res["success"] = False
                    ep_res["error_message"] = f"Endpoint '{path}' returned HTTP {resp.status_code}: {resp.text[:200]}"
                    try:
                        ep_res["output_data"] = resp.json()
                    except Exception:
                        ep_res["output_data"] = {"raw_text": resp.text, "status_code": resp.status_code}
                    results["all_endpoints_successful"] = False

            except RuntimeError as re:
                # Fatal security exception (e.g. redirect or unpinned host) fails process immediately
                raise re
            except httpx.TimeoutException:
                ep_res["duration_ms"] = round((time.time() - ep_start) * 1000, 2)
                ep_res["error_message"] = f"Endpoint '{path}' timed out after {request_timeout}s."
                ep_res["success"] = False
                results["all_endpoints_successful"] = False
            except Exception as exc:
                ep_res["duration_ms"] = round((time.time() - ep_start) * 1000, 2)
                ep_res["error_message"] = f"Endpoint '{path}' error: {str(exc)}"
                ep_res["success"] = False
                results["all_endpoints_successful"] = False

            results["endpoints"][ep_key] = ep_res

    results["total_duration_ms"] = round((time.time() - start_all) * 1000, 2)
    return results


def main() -> None:
    action_id = os.environ.get("ACTION_ID", "").strip()
    target_url = os.environ.get("TARGET_URL", "").strip()
    pinned_ip = os.environ.get("PINNED_IP", "").strip()
    target_host = os.environ.get("TARGET_HOST", "").strip()
    target_port_str = os.environ.get("TARGET_PORT", "").strip()
    target_scheme = os.environ.get("TARGET_SCHEME", "http").strip()
    target_path = os.environ.get("TARGET_PATH", "").strip()
    timeout_seconds = float(os.environ.get("TIMEOUT_SECONDS", "30"))
    tls_verify = os.environ.get("TLS_VERIFY", "true").lower() == "true"
    environment = os.environ.get("ENVIRONMENT", "development").strip().lower()
    trusted_gateway = os.environ.get("SENTINELOPS_TRUSTED_GATEWAY_IP", "").strip() or None

    if not action_id or not target_url:
        print(json.dumps({"error": "Missing ACTION_ID or TARGET_URL environment variable."}))
        sys.exit(1)

    try:
        # Enforce connection parameter presence and consistency
        if not pinned_ip or not target_host or not target_port_str:
            parsed = urlparse(target_url)
            target_host = target_host or parsed.hostname or ""
            target_port_str = target_port_str or str(parsed.port or (443 if parsed.scheme == "https" else 80))
            target_scheme = target_scheme or parsed.scheme
            target_path = target_path or parsed.path

        target_port = int(target_port_str)
        validate_connection_parameters(
            target_url=target_url,
            pinned_ip=pinned_ip,
            target_host=target_host,
            target_port=target_port,
            target_scheme=target_scheme,
            target_path=target_path,
        )

        if action_id == "restore_order_api_demo":
            result = run_restore_order_api_demo(
                target_url=target_url,
                timeout_seconds=timeout_seconds,
                pinned_ip=pinned_ip,
                target_host=target_host,
                tls_verify=tls_verify,
                environment=environment,
                trusted_gateway=trusted_gateway,
            )
        elif action_id == "inspect_service_health":
            raw_params = os.environ.get("PARAMETERS_JSON", "{}").strip()
            parsed_params = {}
            if raw_params:
                try:
                    parsed_params = json.loads(raw_params)
                except Exception:
                    pass
            result = run_inspect_service_health(
                target_url=target_url,
                timeout_seconds=timeout_seconds,
                pinned_ip=pinned_ip,
                target_host=target_host,
                tls_verify=tls_verify,
                environment=environment,
                trusted_gateway=trusted_gateway,
                parameters=parsed_params,
            )
        elif action_id == "execute_http_recovery":
            raw_params = os.environ.get("PARAMETERS_JSON", "{}").strip()
            parsed_params = {}
            if raw_params:
                try:
                    parsed_params = json.loads(raw_params)
                except Exception as e:
                    raise ValueError(f"Invalid JSON in PARAMETERS_JSON: {e}")
            validated_rec = HttpRecoveryModel.model_validate(parsed_params)
            result = run_http_recovery(
                target_url=target_url,
                payload=validated_rec.payload,
                expected_status_codes=validated_rec.expected_status_codes,
                timeout_seconds=timeout_seconds,
                pinned_ip=pinned_ip,
                target_host=target_host,
                tls_verify=tls_verify,
                environment=environment,
                trusted_gateway=trusted_gateway,
            )
        else:
            print(json.dumps({"error": f"Unknown action '{action_id}'"}))
            sys.exit(1)

        print(json.dumps(result))
        sys.exit(0)

    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
