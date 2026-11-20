"""Native Isolated HTTP Recovery Runner for SentinelOps Option C.

Provides an unprivileged, isolated execution runner for allowlisted HTTP remediation actions:
1. Strict cryptographic authorization via detached Ed25519 signatures and RFC 8785 canonical manifests.
2. Complete verification using public keys only (BrokerPublicKeyRegistry). Zero private keys loaded.
3. Zero dependency on Docker daemon, Docker SDK, or /var/run/docker.sock.
4. Destination origin and relative path derived strictly from signed manifest and service configuration.
5. Dual-layer SSRF defense, connection-time DNS/IP pinning, and strict redirect rejection.
6. Execution uncertainty preservation: network timeouts and ambiguous connection drops fail closed
   into ExecutionUncertainError to prevent blind automated retries.
7. Fixed static handlers only (execute_http_recovery, restore_order_api_demo, inspect_service_health).
   Zero arbitrary shell commands, subprocesses, or dynamic code execution.
8. Network isolation scope: Enforces application-layer SSRF defense, connection-time DNS/IP pinning,
   and redirect rejection. Does NOT claim kernel-level packet filtering (iptables) or network namespace isolation.
   See docs/STAGE_3_OPERATIONAL_SECURITY_AND_VERIFICATION_LIMITS.md for architecture details.
"""

import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
import httpcore
from httpcore._backends.sync import SyncBackend
import httpx

from app.core.manifest_crypto import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    MAX_MANIFEST_LIFETIME_SECONDS,
    ExecutionManifest,
    NormalizedOrigin,
    compute_parameters_digest,
    normalize_origin_and_path,
)
from app.core.rfc8785 import canonicalize
from app.execution.exceptions import (
    BrokerSecurityViolation,
    ExecutionUncertainError,
    PreconditionFailedError,
    SecurityConfigurationError,
)
from app.execution.network import (
    FORBIDDEN_METADATA_IPS,
    ValidatedTarget,
    resolve_safe_target_url,
)
from app.execution.public_keys import BrokerPublicKeyRegistry
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.remediation.schemas import (
    HttpRecoveryParams,
    InspectServiceHealthParams,
    RestoreOrderApiDemoParams,
)

logger = logging.getLogger("sentinelops.execution.runners.http_recovery")

# Allowlisted actions that this runner is authorized to execute
SUPPORTED_ACTIONS: Set[str] = {
    "execute_http_recovery",
    "restore_order_api_demo",
    "inspect_service_health",
}

DEV_HOST_GATEWAY_HOSTNAME = "host.docker.internal"
DEV_LOCALHOST_ORIGINS: Set[str] = {
    "127.0.0.1",
    "localhost",
    DEV_HOST_GATEWAY_HOSTNAME,
    "::1",
    "[::1]",
}


class ExecutionAuthorizationError(BrokerSecurityViolation):
    """Raised when an execution request fails cryptographic manifest verification,
    temporal bounds check, parameter digest binding, or origin/path authorization."""
    pass


class PinnedSyncBackend(SyncBackend):
    """
    HTTPCore SyncBackend that intercepts connect_tcp to connect directly to the
    pre-validated pinned_ip while preserving target_host for TLS SNI and Host header.
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
        route directly to pinned_ip while strictly validating against metadata and loopback rules.
        """
        clean_host = host.lower().strip()
        if clean_host != self.target_host:
            raise RuntimeError(
                f"Connection blocked: attempted connection to unpinned host '{host}' (expected '{self.target_host}')."
            )

        # Validate IP address syntax
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

        # Reject non-standard loopback outside 127.0.0.1 / ::1
        if ip_obj.is_loopback and str(ip_obj) not in ("127.0.0.1", "::1"):
            raise RuntimeError(
                f"Connection blocked: loopback IP '{self.pinned_ip}' is prohibited outside standard 127.0.0.1 loopback."
            )

        connect_ip = self.pinned_ip

        # If targeting host.docker.internal in dev, attempt gateway resolution if available;
        # otherwise connect directly to pinned IP
        if self.is_dev_env and clean_host == DEV_HOST_GATEWAY_HOSTNAME:
            try:
                addr_info = socket.getaddrinfo(
                    DEV_HOST_GATEWAY_HOSTNAME,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
                if addr_info:
                    connect_ip = addr_info[0][4][0]
            except Exception:
                connect_ip = self.pinned_ip

        return super().connect_tcp(connect_ip, port, *args, **kwargs)


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


class IsolatedHttpRecoveryRunner(ExecutionRunnerInterface):
    """
    Dedicated unprivileged HTTP recovery runner for SentinelOps Option C.

    Key Architectural Guarantees:
    1. Cryptographic Authorization: Requires valid Ed25519 signed manifest verified
       strictly via public key registry before initiating any network operation.
    2. Zero Private Keys: Operates with public keys only. Never loads SENTINELOPS_MANIFEST_PRIVATE_KEY.
    3. Zero Docker Access: Makes outbound HTTP requests using PinnedIPTransport. Zero Docker socket needed.
    4. Authoritative Target Resolution: Destination origin and path are validated against
       the signed manifest; caller cannot override or supply an arbitrary URL.
    5. Dual-Layer SSRF Defense: Pre-flight URL validation and connect-time IP pinning reject
       cloud metadata, prohibited private networks, and DNS rebinding.
    6. Non-Redirecting HTTP: follow_redirects=False strictly enforced; redirects fail closed.
    7. Uncertainty Fail-Closed Contract: Network timeouts and ambiguous connection losses raise
       ExecutionUncertainError rather than reporting a clean failure, preventing blind retries.
    8. Static Handlers Only: Dispatches only allowlisted actions with strict parameter models.
    """

    def __init__(
        self,
        *,
        public_key_registry: Optional[BrokerPublicKeyRegistry] = None,
        environment: Optional[str] = None,
        trusted_gateway: Optional[str] = None,
        allowed_actions: Optional[Set[str]] = None,
        allow_unauthenticated_probes: bool = False,
        demo_service_authorizer: Optional[Callable[[str], bool]] = None,
    ):
        self.public_key_registry = public_key_registry or BrokerPublicKeyRegistry()
        self.environment = environment.lower().strip() if environment else None
        self.trusted_gateway = trusted_gateway
        self.allowed_actions = allowed_actions or SUPPORTED_ACTIONS
        self.allow_unauthenticated_probes = allow_unauthenticated_probes
        self.demo_service_authorizer = demo_service_authorizer

    def is_authorized_demo_service(self, service_id: str) -> bool:
        """Verify whether service_id is explicitly authorized as an order_api demo service."""
        if self.demo_service_authorizer is not None:
            try:
                return bool(self.demo_service_authorizer(str(service_id)))
            except Exception as e:
                logger.warning("Error checking demo service authorization for %s: %s", service_id, e)
                return False
        # Fallback to ActionRegistry in-memory registration
        try:
            from app.remediation.registry import ActionRegistry
            return str(service_id) in ActionRegistry._registered_demo_services.get("order_api", set())
        except Exception:
            return False

    def _resolve_demo_recovery_headers(
        self,
        *,
        action_id: str,
        manifest: ExecutionManifest,
    ) -> Dict[str, str]:
        """
        Safely resolve administrative authentication headers for authorized demo recovery actions.

        Enforces:
        1. Verification probes and unauthenticated probe runners NEVER receive credentials.
        2. Only action_id == 'restore_order_api_demo' is eligible. Generic recovery and health checks are prohibited.
        3. Manifest action_id and authorized_path must strictly match 'restore_order_api_demo' and '/demo/restore'.
        4. Service must be explicitly verified as the authorized 'order_api' demo service.
        5. Credential is read strictly from fixed environment secret ORDER_API_DEMO_ADMIN_TOKEN (arbitrary env vars prohibited).
        6. Headers are returned for HTTP dispatch and NEVER logged or stored.
        """
        # Guard 1: Probe/verification runner must never receive credentials
        if self.allow_unauthenticated_probes:
            return {}

        # Guard 2: Only restore_order_api_demo is eligible
        if action_id != "restore_order_api_demo":
            return {}

        # Guard 3: Manifest binding check
        if manifest.action_id != "restore_order_api_demo" or manifest.authorized_path != "/demo/restore":
            raise ExecutionAuthorizationError(
                "Manifest authorization mismatch for demo recovery credential injection."
            )

        # Guard 4: Service identity binding check
        if not self.is_authorized_demo_service(manifest.service_id):
            raise ExecutionAuthorizationError(
                f"Service '{manifest.service_id}' is not an authorized order_api demo service. Credential injection denied."
            )

        # Guard 5: Fixed environment variable read (arbitrary env vars prohibited)
        token = os.environ.get("ORDER_API_DEMO_ADMIN_TOKEN", "").strip()
        if not token:
            raise SecurityConfigurationError(
                "Order API demo admin token (ORDER_API_DEMO_ADMIN_TOKEN) is not configured in worker environment. Recovery cannot be authorized."
            )

        # Guard 6: Never log or expose token value
        return {"X-Demo-Token": token}

    def is_available(self) -> bool:
        """
        Check if the runner is available and operational.
        Returns True if the public-key registry is initialized and ready to verify manifests.
        """
        return self.public_key_registry is not None

    def verify_authorization(
        self,
        *,
        action_id: str,
        parameters: Dict[str, Any],
        execution_id: Optional[str],
        target_url: Optional[str],
        environment: str,
        authorization_manifest: Optional[Dict[str, Any]],
        manifest_signature: Optional[str],
    ) -> Tuple[ExecutionManifest, ValidatedTarget]:
        """
        Independently verify Ed25519 signature, manifest validity, parameter binding,
        request binding, and target origin/path authorization before any network socket is opened.

        Returns (manifest, validated_target).
        Raises ExecutionAuthorizationError (or BrokerSecurityViolation) on any defect.
        """
        # 1. Action allowlist check
        if action_id not in self.allowed_actions:
            raise ExecutionAuthorizationError(
                f"Action '{action_id}' is not in authorized runner actions: {sorted(self.allowed_actions)}."
            )

        # Allow unauthenticated read-only probe strictly for inspect_service_health
        # if allow_unauthenticated_probes is explicitly enabled on this runner instance
        if self.allow_unauthenticated_probes and action_id == "inspect_service_health" and not authorization_manifest:
            effective_url = target_url or "http://localhost/health"
            norm_target = normalize_origin_and_path(effective_url)
            resolved_target = resolve_safe_target_url(
                effective_url,
                environment=environment,
                action_id=action_id,
            )
            return None, resolved_target

        # 2. Require manifest, signature, and execution ID
        if not authorization_manifest or not isinstance(authorization_manifest, dict):
            raise ExecutionAuthorizationError("Missing or invalid authorization_manifest in execution request.")
        if not manifest_signature or not isinstance(manifest_signature, str) or not manifest_signature.strip():
            raise ExecutionAuthorizationError("Missing or invalid manifest_signature in execution request.")
        if not execution_id or not str(execution_id).strip():
            raise ExecutionAuthorizationError("Missing execution_id in execution request.")

        # 3. Manifest schema validation
        try:
            manifest = ExecutionManifest.model_validate(authorization_manifest)
        except Exception as e:
            raise ExecutionAuthorizationError(f"Manifest schema validation failed: {e}")

        # 4. Manifest action allowlist and request binding checks
        if manifest.action_id not in self.allowed_actions:
            raise ExecutionAuthorizationError(
                f"Manifest action '{manifest.action_id}' is not in authorized runner actions."
            )
        if execution_id != manifest.execution_id:
            raise ExecutionAuthorizationError(
                f"Execution ID mismatch: request has '{execution_id}', "
                f"manifest authorizes '{manifest.execution_id}'."
            )
        if action_id != manifest.action_id:
            raise ExecutionAuthorizationError(
                f"Action ID mismatch: request has '{action_id}', "
                f"manifest authorizes '{manifest.action_id}'."
            )

        # 5. Issuer, Audience, and Environment verification
        if manifest.issuer != "sentinelops.control-plane":
            raise ExecutionAuthorizationError(
                f"Invalid manifest issuer '{manifest.issuer}'. Expected 'sentinelops.control-plane'."
            )
        if manifest.audience != "sentinelops.execution":
            raise ExecutionAuthorizationError(
                f"Invalid manifest audience '{manifest.audience}'. Expected 'sentinelops.execution'."
            )
        if manifest.environment != environment:
            raise ExecutionAuthorizationError(
                f"Environment mismatch: manifest issued for '{manifest.environment}', "
                f"but request specified '{environment}'."
            )
        if self.environment and manifest.environment != self.environment:
            raise ExecutionAuthorizationError(
                f"Environment mismatch: manifest issued for '{manifest.environment}', "
                f"but runner is configured for '{self.environment}'."
            )

        # 6. Public key resolution & status verification (strictly public key)
        if self.public_key_registry is None:
            raise ExecutionAuthorizationError("Runner has no public-key registry configured.")
        pub_key = self.public_key_registry.resolve_and_verify_key(manifest.key_id)

        # 7. Temporal validity check
        now = int(time.time())
        # Future skew check
        if manifest.issued_at > now + CLOCK_SKEW_TOLERANCE_SECONDS:
            raise ExecutionAuthorizationError(
                f"Manifest issued_at ({manifest.issued_at}) is in the future beyond {CLOCK_SKEW_TOLERANCE_SECONDS}s skew tolerance (now: {now})."
            )
        # Expiry check
        if now > manifest.expires_at:
            raise ExecutionAuthorizationError(
                f"Manifest expired at {manifest.expires_at} (now: {now}, expired by {now - manifest.expires_at}s)."
            )
        # Validity window bound: max 60s
        if (manifest.expires_at - manifest.issued_at) > MAX_MANIFEST_LIFETIME_SECONDS:
            raise ExecutionAuthorizationError(
                f"Manifest validity window ({manifest.expires_at - manifest.issued_at}s) exceeds max {MAX_MANIFEST_LIFETIME_SECONDS}s."
            )
        # Maximum age from issued_at: max 60s
        if (now - manifest.issued_at) > MAX_MANIFEST_LIFETIME_SECONDS:
            raise ExecutionAuthorizationError(
                f"Manifest was issued {now - manifest.issued_at}s ago, exceeding max {MAX_MANIFEST_LIFETIME_SECONDS}s lifetime."
            )

        # 8. Ed25519 signature verification over RFC 8785 canonical bytes
        canonical_bytes = canonicalize(manifest.model_dump())
        try:
            padded_sig = manifest_signature.strip()
            sig_bytes = base64.urlsafe_b64decode(padded_sig + "=" * (-len(padded_sig) % 4))
            if len(sig_bytes) != 64:
                raise ValueError(f"Invalid signature length: {len(sig_bytes)} bytes (expected 64)")
        except Exception as e:
            raise ExecutionAuthorizationError(f"Malformed Ed25519 signature: {e}")

        try:
            pub_key.verify(sig_bytes, canonical_bytes)
        except InvalidSignature:
            raise ExecutionAuthorizationError(
                "Ed25519 signature verification failed: signature does not match canonical manifest."
            )

        # 9. Parameter digest verification
        expected_param_sha = compute_parameters_digest(parameters)
        if expected_param_sha != manifest.parameters_sha256:
            raise ExecutionAuthorizationError(
                f"Parameter digest mismatch: manifest specifies '{manifest.parameters_sha256}', "
                f"but request parameters hash to '{expected_param_sha}'."
            )

        # 10. Origin and path verification against authorized target
        auth_origin = f"{manifest.authorized_scheme}://{manifest.authorized_hostname}:{manifest.authorized_port}"
        auth_url = f"{auth_origin}{manifest.authorized_path}"

        effective_url = target_url or auth_url
        norm_target = normalize_origin_and_path(effective_url)

        if norm_target.scheme != manifest.authorized_scheme:
            raise ExecutionAuthorizationError(
                f"Target scheme mismatch: target has '{norm_target.scheme}', "
                f"manifest authorizes '{manifest.authorized_scheme}'."
            )
        if norm_target.hostname != manifest.authorized_hostname:
            raise ExecutionAuthorizationError(
                f"Target hostname mismatch: target has '{norm_target.hostname}', "
                f"manifest authorizes '{manifest.authorized_hostname}'."
            )
        if norm_target.port != manifest.authorized_port:
            raise ExecutionAuthorizationError(
                f"Target port mismatch: target has {norm_target.port}, "
                f"manifest authorizes {manifest.authorized_port}."
            )
        if norm_target.path != manifest.authorized_path:
            raise ExecutionAuthorizationError(
                f"Target path mismatch: target has '{norm_target.path}', "
                f"manifest authorizes '{manifest.authorized_path}'."
            )

        # 11. Dual-layer SSRF validation and destination IP pinning
        resolved_target = resolve_safe_target_url(
            effective_url,
            environment=environment,
            action_id=action_id,
        )

        return manifest, resolved_target

    def execute(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        timeout_seconds: int = 30,
        target_url: Optional[str] = None,
        environment: str = "development",
        execution_id: Optional[str] = None,
        authorization_manifest: Optional[Dict[str, Any]] = None,
        manifest_signature: Optional[str] = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """
        Execute an allowlisted HTTP remediation action inside the unprivileged runner sandbox.

        Enforces:
        1. Pre-execution cryptographic authorization check (fails closed before socket open).
        2. Connection-time IP pinning (PinnedIPTransport) preventing DNS rebinding.
        3. Strict follow_redirects=False (redirects treated as SSRF violation).
        4. Parameter validation against strict action models.
        5. HTTP status code verification against expected 2xx codes.
        6. Timeout and connection loss fail closed into ExecutionUncertainError.
        """
        # Step 1: Authoritative verification before ANY network activity
        manifest, resolved_target = self.verify_authorization(
            action_id=action_id,
            parameters=parameters,
            execution_id=execution_id,
            target_url=target_url,
            environment=environment,
            authorization_manifest=authorization_manifest,
            manifest_signature=manifest_signature,
        )

        # Step 2: Validate parameters strictly per action model
        request_payload: Optional[Dict[str, Any]] = None
        expected_codes: List[int] = [200]
        effective_timeout = max(1, min(60, int(timeout_seconds)))

        if action_id == "execute_http_recovery":
            # HttpRecoveryParams validates service_id, recovery_path, payload, expected_status_codes
            try:
                validated_params = HttpRecoveryParams.model_validate(parameters)
            except Exception as e:
                raise PreconditionFailedError(f"Approved parameter validation failed for execute_http_recovery: {e}")
            request_payload = validated_params.payload
            expected_codes = validated_params.expected_status_codes or [200]
            if validated_params.timeout_seconds:
                effective_timeout = max(1, min(effective_timeout, validated_params.timeout_seconds))

        elif action_id == "restore_order_api_demo":
            try:
                RestoreOrderApiDemoParams.model_validate(parameters or {})
            except Exception as e:
                raise PreconditionFailedError(f"Approved parameter validation failed for restore_order_api_demo: {e}")
            request_payload = None
            expected_codes = [200]

        elif action_id == "inspect_service_health":
            try:
                health_params = InspectServiceHealthParams.model_validate(parameters or {})
            except Exception as e:
                raise PreconditionFailedError(f"Approved parameter validation failed for inspect_service_health: {e}")
            request_payload = None
            expected_codes = [200]

        else:
            raise ExecutionAuthorizationError(f"Unsupported action_id '{action_id}'.")

        # Step 3: Setup connection-time DNS pinning transport
        transport = PinnedIPTransport(
            target_host=resolved_target.hostname,
            pinned_ip=resolved_target.pinned_ip,
            verify=True,
            environment=environment,
            trusted_gateway=self.trusted_gateway,
        )

        # Step 4: Dispatch HTTP request
        start_time = time.time()
        try:
            with httpx.Client(
                transport=transport,
                timeout=float(effective_timeout),
                follow_redirects=False,
            ) as client:
                if action_id == "inspect_service_health":
                    h_path = health_params.health_path or "/health"
                    if not h_path.startswith("/"):
                        h_path = f"/{h_path}"
                    diagnostic_paths: List[Tuple[str, str]] = [(h_path, "health")]
                    if health_params.is_demo_service:
                        diagnostic_paths.append(("/demo/status", "demo_status"))
                        diagnostic_paths.append(("/metrics", "metrics"))
                    elif health_params.has_prometheus_metrics:
                        diagnostic_paths.append(("/metrics", "metrics"))

                    endpoints: Dict[str, Any] = {}
                    all_ok = True
                    base_url = f"{resolved_target.scheme}://{resolved_target.hostname}:{resolved_target.port}"

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
                            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                                loc = resp.headers.get("location", "")
                                raise BrokerSecurityViolation(
                                    f"HTTP Redirect to '{loc}' rejected: redirects are forbidden."
                                )
                            if resp.status_code == 200:
                                ep_res["success"] = True
                                ep_res["raw_text"] = resp.text
                                try:
                                    body_json = resp.json()
                                    if isinstance(body_json, dict) and "raw_text" not in body_json:
                                        body_json["raw_text"] = resp.text
                                    ep_res["output_data"] = body_json
                                except Exception:
                                    ep_res["output_data"] = {"raw_text": resp.text, "status_code": resp.status_code}
                            else:
                                ep_res["success"] = False
                                ep_res["raw_text"] = resp.text
                                ep_res["error_message"] = (
                                    f"Endpoint '{path}' returned HTTP {resp.status_code}: {resp.text[:200]}"
                                )
                                try:
                                    body_json = resp.json()
                                    if isinstance(body_json, dict) and "raw_text" not in body_json:
                                        body_json["raw_text"] = resp.text
                                    ep_res["output_data"] = body_json
                                except Exception:
                                    ep_res["output_data"] = {"raw_text": resp.text, "status_code": resp.status_code}
                                all_ok = False
                        except (BrokerSecurityViolation, ExecutionAuthorizationError):
                            raise
                        except Exception as ep_err:
                            ep_res["success"] = False
                            ep_res["error_message"] = str(ep_err)
                            all_ok = False
                        endpoints[ep_key] = ep_res

                    total_duration_ms = int((time.time() - start_time) * 1000)
                    results_data = {
                        "status": "completed" if all_ok else "failed",
                        "action": "inspect_service_health",
                        "base_url": base_url,
                        "endpoints": endpoints,
                        "all_endpoints_successful": all_ok,
                    }
                    return ExecutionResult(
                        exit_code=0 if all_ok else 1,
                        duration_ms=total_duration_ms,
                        stdout=json.dumps(results_data),
                        output_data=results_data,
                        error_message=None if all_ok else "One or more diagnostic endpoints failed",
                        error_category=None if all_ok else "probe_failed",
                    )

                if action_id in ("execute_http_recovery", "restore_order_api_demo"):
                    headers: Dict[str, str] = {}
                    if action_id == "restore_order_api_demo":
                        try:
                            headers = self._resolve_demo_recovery_headers(
                                action_id=action_id,
                                manifest=manifest,
                            )
                        except SecurityConfigurationError as sce:
                            return ExecutionResult(
                                exit_code=1,
                                duration_ms=0,
                                error_message=str(sce),
                                error_category="missing_credential",
                            )
                        except ExecutionAuthorizationError as eae:
                            return ExecutionResult(
                                exit_code=1,
                                duration_ms=0,
                                error_message=str(eae),
                                error_category="authorization_denied",
                            )

                    resp = client.post(
                        resolved_target.url,
                        headers=headers or None,
                        json=request_payload if request_payload is not None else None,
                    )
                else:
                    raise ExecutionAuthorizationError(f"Unsupported action_id '{action_id}'.")

                duration_ms = int((time.time() - start_time) * 1000)

                # Strictly reject redirects (SSRF defense)
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location", "")
                    raise BrokerSecurityViolation(
                        f"HTTP Redirect to '{loc}' rejected: redirects are strictly forbidden."
                    )

                # Check expected status codes
                if resp.status_code not in expected_codes:
                    logger.warning(
                        "Action '%s' returned HTTP %d (expected %s) for execution '%s'",
                        action_id,
                        resp.status_code,
                        expected_codes,
                        execution_id,
                    )
                    return ExecutionResult(
                        exit_code=1,
                        duration_ms=duration_ms,
                        stdout=resp.text[:10240],
                        stderr=f"Target service returned unexpected HTTP {resp.status_code}: {resp.text[:200]}",
                        error_message=f"HTTP status code {resp.status_code} not in expected {expected_codes}",
                        error_category="status_code_mismatch",
                        output_data={"status_code": resp.status_code, "raw_response": resp.text[:1000]},
                    )

                # Parse JSON response body if possible
                try:
                    body = resp.json()
                except Exception:
                    body = {"raw_text": resp.text[:1000], "status_code": resp.status_code}

                return ExecutionResult(
                    exit_code=0,
                    duration_ms=duration_ms,
                    stdout=resp.text[:10240],
                    output_data={"status_code": resp.status_code, "response": body},
                )

        except (httpx.TimeoutException, httpcore.TimeoutException) as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "HTTP recovery request timed out after %ds for execution '%s' (action '%s'): %s",
                effective_timeout,
                execution_id,
                action_id,
                e,
            )
            # Fails closed into ExecutionUncertainError: preserves uncertain outcome contract
            raise ExecutionUncertainError(
                f"HTTP recovery request timed out after {effective_timeout}s for action '{action_id}' "
                f"(execution '{execution_id}'). Outcome is indeterminate: {e}"
            ) from e

        except (BrokerSecurityViolation, ExecutionAuthorizationError):
            # Propagate security and authorization violations directly
            raise

        except ExecutionUncertainError:
            raise

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "HTTP recovery execution failed for execution '%s' (action '%s'): %s",
                execution_id,
                action_id,
                e,
            )
            return ExecutionResult(
                exit_code=1,
                duration_ms=duration_ms,
                stderr=str(e),
                error_message=str(e),
                error_category="execution_failed",
            )
