"""Control-Plane Manifest Signer (Phase 2A.1 Stage 4).

Provides:
- Manifest generation, Ed25519 signing, and digest calculation for remediation executions.
- Strict isolation of private signing key to the control-plane runtime.
- Fail-closed behavior on missing, malformed, or unavailable private keys.
- Accurate origin and path resolution from registered service and playbook definitions.
- Parameter canonicalization via RFC 8785 (JCS) and SHA-256 hashing.
"""

import base64
from datetime import datetime, timezone
import hashlib
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.manifest_crypto import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    MAX_MANIFEST_LIFETIME_SECONDS,
    ExecutionManifest,
    ManifestSecurityError,
    NormalizedOrigin,
    compute_parameters_digest,
    normalize_origin_and_path,
    sign_manifest,
    verify_manifest,
)
from app.core.rfc8785 import canonicalize
from app.execution.exceptions import PreconditionFailedError
from app.models.remediation import RemediationApproval
from app.models.service import Service
from app.remediation.schemas import validate_relative_recovery_path

logger = logging.getLogger("sentinelops.execution.manifest_signer")


class ManifestSigningError(Exception):
    """Raised when control-plane manifest generation or signing fails."""


# Cached control-plane signing key tuple (key_id, priv_key, raw_key_str) to allow safe in-process worker operation
_CACHED_SIGNING_KEY: Optional[Tuple[str, ed25519.Ed25519PrivateKey, Optional[str]]] = None


def load_control_plane_signing_key(
    key_id: Optional[str] = None,
    private_key_b64: Optional[str] = None,
) -> Tuple[str, ed25519.Ed25519PrivateKey]:
    """
    Load the authoritative control-plane Ed25519 private signing key and key_id.
    Fails closed if the key is missing, empty, or malformed.
    Never generates ephemeral keys.
    """
    global _CACHED_SIGNING_KEY

    # If an explicit private key is passed, parse and return without caching
    if private_key_b64 is not None:
        resolved_key_id = (key_id or os.environ.get("SENTINELOPS_MANIFEST_KEY_ID", "sentinelops-control-plane-v1")).strip()
        try:
            key_bytes = base64.b64decode(str(private_key_b64).strip())
            return resolved_key_id, ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
        except Exception as e:
            raise ManifestSigningError(f"Supplied private key is malformed: {e}. Failing closed.")

    resolved_key_id = (key_id or os.environ.get("SENTINELOPS_MANIFEST_KEY_ID", "sentinelops-control-plane-v1")).strip()
    if not resolved_key_id:
        raise ManifestSigningError("Control-plane signing key_id is empty or not configured. Failing closed.")

    raw_key = os.environ.get("SENTINELOPS_MANIFEST_PRIVATE_KEY")

    # Return cached key if available and neither key_id nor env key changed
    if _CACHED_SIGNING_KEY is not None:
        cached_id, cached_key, cached_raw = _CACHED_SIGNING_KEY
        if resolved_key_id == cached_id and (not raw_key or raw_key == cached_raw):
            return cached_id, cached_key

    if not raw_key or not str(raw_key).strip():
        raise ManifestSigningError(
            "Control-plane private signing key is not configured (SENTINELOPS_MANIFEST_PRIVATE_KEY is missing or empty). "
            "Remediation executions require a valid Ed25519 signing key. Failing closed."
        )

    try:
        key_bytes = base64.b64decode(str(raw_key).strip())
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    except Exception as e:
        raise ManifestSigningError(
            f"Control-plane private signing key (SENTINELOPS_MANIFEST_PRIVATE_KEY) is malformed: {e}. Failing closed."
        )

    _CACHED_SIGNING_KEY = (resolved_key_id, priv_key, raw_key)
    return resolved_key_id, priv_key


def resolve_action_recovery_path(
    action_id: str,
    service: Service,
    validated_parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Deterministically resolve and validate the authorized relative recovery path.
    - restore_order_api_demo -> /demo/restore
    - inspect_service_health -> path from health_check_url or /health
    - execute_http_recovery -> validated recovery_path parameter
    """
    params = validated_parameters or {}

    if action_id == "restore_order_api_demo":
        return "/demo/restore"

    if action_id == "inspect_service_health":
        parsed = urlparse(service.health_check_url or "")
        return parsed.path if parsed.path and parsed.path.startswith("/") else "/health"

    if action_id == "execute_http_recovery":
        param_service_id = params.get("service_id")
        if param_service_id and str(param_service_id) != str(service.id):
            raise ManifestSigningError(
                f"Cross-service parameter mismatch: parameter service_id '{param_service_id}' "
                f"does not match execution target service '{service.id}'."
            )

        service_rec_path = getattr(service, "recovery_endpoint", None)
        if service_rec_path:
            if not getattr(service, "recovery_enabled", False):
                raise ManifestSigningError(
                    f"Recovery is disabled on service '{service.name}'. Failing closed."
                )
            param_path = params.get("recovery_path")
            if param_path and param_path.strip() != service_rec_path.strip():
                raise ManifestSigningError(
                    f"Execution parameter recovery_path ('{param_path}') cannot override "
                    f"service authorized recovery endpoint ('{service_rec_path}')."
                )
            return validate_relative_recovery_path(service_rec_path)

        rec_path = params.get("recovery_path")
        if not rec_path or not isinstance(rec_path, str) or not rec_path.strip():
            raise ManifestSigningError(
                "Action 'execute_http_recovery' requires an authorized recovery endpoint configured on the service or in approved parameters."
            )
        try:
            return validate_relative_recovery_path(rec_path)
        except ValueError as e:
            raise ManifestSigningError(f"Invalid recovery path for 'execute_http_recovery': {e}")

    # Fallback for any other action
    if "recovery_path" in params and isinstance(params["recovery_path"], str):
        try:
            return validate_relative_recovery_path(params["recovery_path"])
        except ValueError as e:
            raise ManifestSigningError(f"Invalid recovery path in parameters: {e}")

    return "/"


def generate_and_sign_execution_manifest(
    *,
    execution_id: str,
    approval: RemediationApproval,
    service: Service,
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    key_id: Optional[str] = None,
    now_utc_ts: Optional[int] = None,
    audience: str = "sentinelops.execution",
) -> Tuple[ExecutionManifest, str, str]:
    """
    Construct, validate, and sign an immutable ExecutionManifest for a new execution.

    Enforces:
    1. Key isolation & fail-closed key loading.
    2. Normalized origin and relative path resolution.
    3. Deterministic RFC 8785 parameter digest calculation.
    4. Strict 60-second lifetime boundary.
    5. Ed25519 signature generation over canonical bytes.
    6. SHA-256 manifest digest calculation over canonical manifest payload.
    7. Immediate self-verification to guarantee validity before returning.

    Returns:
    (ExecutionManifest, signature_b64, manifest_digest)
    """
    # 1. Load private signing key
    if private_key is not None and key_id is not None:
        signing_key_id = key_id.strip()
        signing_priv_key = private_key
    else:
        signing_key_id, signing_priv_key = load_control_plane_signing_key(key_id=key_id)

    # 2. Service origin resolution & canonicalization
    if not service.health_check_url:
        raise ManifestSigningError(f"Target service '{service.name}' has no configured health_check_url.")

    try:
        norm_origin = normalize_origin_and_path(service.health_check_url)
    except Exception as e:
        raise ManifestSigningError(f"Failed to normalize target service origin '{service.health_check_url}': {e}")

    # 3. Authorized relative path resolution
    recovery_path = resolve_action_recovery_path(
        action_id=approval.action_id,
        service=service,
        validated_parameters=approval.validated_parameters,
    )

    # 4. Deterministic parameter digest calculation (RFC 8785 JCS + SHA-256)
    try:
        parameters_digest = compute_parameters_digest(approval.validated_parameters or {})
    except Exception as e:
        raise ManifestSigningError(f"Failed to compute parameter digest: {e}")

    # 5. Timing & lifetime (strict 60s max lifetime)
    issued_at = now_utc_ts if now_utc_ts is not None else int(time.time())
    expires_at = issued_at + MAX_MANIFEST_LIFETIME_SECONDS

    # 6. Service environment
    service_env = (service.environment or "development").strip().lower()
    if service_env not in ("development", "staging", "production"):
        raise ManifestSigningError(f"Invalid service environment '{service.environment}'.")

    # 7. Construct ExecutionManifest
    approval_ref = f"{approval.id}:{approval.policy_version or 'v1.0'}"
    manifest_id = str(uuid.uuid4())

    try:
        manifest = ExecutionManifest(
            manifest_version="1.0",
            key_id=signing_key_id,
            issuer="sentinelops.control-plane",
            audience=audience,
            environment=service_env,
            manifest_id=manifest_id,
            execution_id=execution_id,
            approval_id=approval.id,
            approval_reference=approval_ref,
            workspace_id=approval.workspace_id,
            service_id=service.id,
            action_id=approval.action_id,
            authorized_scheme=norm_origin.scheme,
            authorized_hostname=norm_origin.hostname,
            authorized_port=norm_origin.port,
            authorized_path=recovery_path,
            parameters_sha256=parameters_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except Exception as e:
        raise ManifestSigningError(f"ExecutionManifest validation failed: {e}")

    # 8. Sign canonical manifest
    try:
        signature_b64 = sign_manifest(manifest, signing_priv_key)
    except Exception as e:
        raise ManifestSigningError(f"Failed to sign manifest with Ed25519: {e}")

    # 9. Compute manifest_digest over canonical bytes (excluding detached signature)
    canonical_manifest_bytes = canonicalize(manifest.model_dump())
    manifest_digest = hashlib.sha256(canonical_manifest_bytes).hexdigest()

    # 10. Self-verify immediately to ensure validity before returning
    try:
        pub_key = signing_priv_key.public_key()
        verify_manifest(
            manifest_data=manifest,
            signature_b64=signature_b64,
            public_keys={signing_key_id: pub_key},
            expected_environment=service_env,
            now_utc_ts=issued_at,
            expected_audience=audience,
        )
    except Exception as e:
        raise ManifestSigningError(f"Manifest self-verification failed after signing: {e}")

    logger.info(
        f"Execution manifest generated and signed: manifest_id={manifest_id}, execution_id={execution_id}, "
        f"action={approval.action_id}, origin={norm_origin.canonical_origin}, path={recovery_path}, "
        f"digest={manifest_digest[:16]}..."
    )

    return manifest, signature_b64, manifest_digest
