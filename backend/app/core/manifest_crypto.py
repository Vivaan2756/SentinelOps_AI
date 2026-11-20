"""Execution Authorization Manifest Cryptography & Origin Normalization.

Phase 2A.1 Specification:
1. Strict ExecutionManifest schema with extra='forbid' and strict type validation.
2. RFC 8785-based canonical serialization for manifest signatures and parameter digests.
3. Ed25519 asymmetric signing and verification (private key held exclusively by control plane).
4. Origin normalization for IPv4, IPv6 (RFC 5952), IDNA hostnames (RFC 5890/Punycode),
   and default port normalization.
5. Binding verification: key_id, issuer, audience, environment, expiry, execution,
   approval, and parameter hash.
"""

import base64
import hashlib
import ipaddress
import re
import time
from typing import Any, Dict, Literal, NamedTuple, Optional, Set, Union
from urllib.parse import urlsplit
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import idna
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.rfc8785 import canonicalize


# Allowlisted actions that can be authorized via signed manifest
ALLOWED_MANIFEST_ACTIONS: Set[str] = {
    "execute_http_recovery",
    "restore_order_api_demo",
    "inspect_service_health",
}

MAX_MANIFEST_LIFETIME_SECONDS = 60   # 60 seconds maximum validity window
CLOCK_SKEW_TOLERANCE_SECONDS = 5     # 5 seconds clock skew allowance


class ManifestSecurityError(Exception):
    """Raised when an authorization manifest fails cryptographic, scoping, or expiry validation."""
    pass


class NormalizedOrigin(NamedTuple):
    """Normalized result of an authoritative service origin and endpoint path."""
    scheme: str
    hostname: str
    port: int
    path: str
    canonical_origin: str
    canonical_url: str


def normalize_origin_and_path(url: str) -> NormalizedOrigin:
    """
    Deterministically normalize a service origin and endpoint path.

    Rules:
    1. Scheme strictly 'http' or 'https' (lowercased).
    2. Userinfo (credentials) strictly rejected.
    3. Hostname normalization:
       - Lowercased ASCII.
       - Trailing dot removed.
       - IPv6 literals normalized to RFC 5952 canonical compressed representation in brackets.
       - IPv4 literals normalized to standard 4-octet dotted decimal (no octal/hex).
       - Domain names normalized to Punycode using IDNA 2008.
    4. Port normalization:
       - Explicit standard port matching scheme default is normalized to standard integer (443/80).
       - Explicit non-standard port preserved if 1 <= port <= 65535.
    5. Path normalization:
       - Must start with '/'.
       - Traversal ('..'), backslashes, percent-encoding, query strings, and fragments rejected.
    """
    if not url or not isinstance(url, str):
        raise ManifestSecurityError("Target URL must be a non-empty string.")

    cleaned_url = url.strip()
    parsed = urlsplit(cleaned_url)

    # 1. Scheme
    scheme = (parsed.scheme or "").lower().strip()
    if scheme not in ("http", "https"):
        raise ManifestSecurityError(f"Invalid URL scheme '{scheme}'. Only 'http' and 'https' are permitted.")

    # 2. Reject userinfo
    if parsed.username or parsed.password:
        raise ManifestSecurityError("Embedded credentials in target URL are strictly prohibited.")

    raw_hostname = (parsed.hostname or "").strip()
    if not raw_hostname:
        raise ManifestSecurityError("Target URL hostname is missing.")

    # Strip trailing dot if present
    if raw_hostname.endswith("."):
        raw_hostname = raw_hostname[:-1]
    if not raw_hostname:
        raise ManifestSecurityError("Target URL hostname cannot be a single dot.")

    # 3. Hostname Normalization (IPv6, IPv4, or IDNA domain)
    canonical_hostname = ""
    # Check if raw_hostname is an IPv6 address (urlsplit strips enclosing brackets)
    try:
        ip6 = ipaddress.IPv6Address(raw_hostname)
        canonical_hostname = f"[{ip6.compressed}]"
    except ValueError:
        pass

    if not canonical_hostname:
        # Check if raw_hostname is an IPv4 address
        try:
            ip4 = ipaddress.IPv4Address(raw_hostname)
            canonical_hostname = str(ip4)
        except ValueError:
            pass

    if not canonical_hostname:
        # IDNA domain name conversion to Punycode / ASCII lowercase with strict UTS #46 and STD3 rules
        try:
            punycode_bytes = idna.encode(raw_hostname.lower(), uts46=True, std3_rules=True, transitional=False)
            canonical_hostname = punycode_bytes.decode("ascii")
        except Exception as e:
            raise ManifestSecurityError(f"Malformed or invalid domain name '{raw_hostname}': {e}")

    # 4. Port Normalization
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    else:
        if not (1 <= port <= 65535):
            raise ManifestSecurityError(f"Invalid port number {port}. Must be between 1 and 65535.")

    # 5. Path Normalization
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise ManifestSecurityError(f"Path must start with '/': '{path}'.")
    if ".." in path:
        raise ManifestSecurityError(f"Path traversal ('..') is prohibited: '{path}'.")
    if "\\" in path:
        raise ManifestSecurityError(f"Backslashes are prohibited in path: '{path}'.")
    if "%" in path:
        raise ManifestSecurityError(f"Percent-encoded sequences are prohibited in path: '{path}'.")
    if "//" in path:
        raise ManifestSecurityError(f"Double slashes ('//') are prohibited in path: '{path}'.")
    if parsed.query:
        raise ManifestSecurityError(f"Query strings are prohibited in recovery path: '{parsed.query}'.")
    if parsed.fragment:
        raise ManifestSecurityError(f"URL fragments are prohibited in recovery path: '{parsed.fragment}'.")

    canonical_origin = f"{scheme}://{canonical_hostname}:{port}"
    canonical_url = f"{canonical_origin}{path}"

    return NormalizedOrigin(
        scheme=scheme,
        hostname=canonical_hostname,
        port=port,
        path=path,
        canonical_origin=canonical_origin,
        canonical_url=canonical_url,
    )


def compute_parameters_digest(parameters: Optional[Dict[str, Any]]) -> str:
    """
    Compute a deterministic SHA-256 hex digest of approved parameters
    using RFC 8785 JSON Canonicalization Scheme (JCS).
    """
    safe_params = parameters if parameters is not None else {}
    canonical_bytes = canonicalize(safe_params)
    return hashlib.sha256(canonical_bytes).hexdigest()


class ExecutionManifest(BaseModel):
    """
    Immutable authorization manifest defining approved execution boundaries.
    Signed by the Control Plane using Ed25519 and verified by the Broker.
    """
    manifest_version: Literal["1.0"] = Field("1.0", description="Manifest schema version")
    key_id: str = Field(..., min_length=1, max_length=64, description="Signing key identifier")
    issuer: Literal["sentinelops.control-plane"] = Field("sentinelops.control-plane")
    audience: Literal["sentinelops.broker", "sentinelops.execution"] = Field("sentinelops.execution")
    environment: Literal["development", "staging", "production"] = Field(...)
    manifest_id: str = Field(..., description="Unique one-time manifest UUID")
    execution_id: str = Field(..., description="Target execution UUID")
    approval_id: str = Field(..., description="Approved proposal UUID")
    approval_reference: str = Field(..., description="Immutable approval reference e.g. <approval_id>:<version>")
    workspace_id: str = Field(..., description="Tenant workspace UUID")
    service_id: str = Field(..., description="Registered service UUID")
    action_id: str = Field(..., description="Allowlisted remediation action ID")
    authorized_scheme: Literal["https", "http"] = Field(...)
    authorized_hostname: str = Field(..., description="Canonical normalized hostname")
    authorized_port: int = Field(..., ge=1, le=65535, description="Exact authorized destination port")
    authorized_path: str = Field(..., description="Normalized relative endpoint path")
    parameters_sha256: str = Field(..., min_length=64, max_length=64, description="SHA-256 of canonical parameters")
    issued_at: int = Field(..., description="Unix timestamp UTC when manifest was issued")
    expires_at: int = Field(..., description="Unix timestamp UTC when manifest expires")

    model_config = ConfigDict(extra="forbid", strict=True)

    @field_validator("manifest_id", "execution_id", "approval_id", "workspace_id", "service_id")
    @classmethod
    def validate_uuid_fields(cls, v: str, info) -> str:
        try:
            val_uuid = uuid.UUID(v)
            return str(val_uuid)
        except Exception:
            raise ValueError(f"Field '{info.field_name}' must be a valid 36-character UUID string.")

    @field_validator("action_id")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ALLOWED_MANIFEST_ACTIONS:
            raise ValueError(f"Action '{v}' is not in allowed manifest actions {sorted(ALLOWED_MANIFEST_ACTIONS)}.")
        return v

    @field_validator("parameters_sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if not re.match(r"^[0-9a-f]{64}$", v):
            raise ValueError("parameters_sha256 must be a 64-character lowercase hex string.")
        return v

    @field_validator("authorized_path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("authorized_path must start with '/'.")
        if any(bad in v for bad in ("..", "\\", "%", "//", "?", "#")):
            raise ValueError("authorized_path contains forbidden traversal or delimiters.")
        return v

    @model_validator(mode="after")
    def validate_lifecycle_and_environment(self) -> "ExecutionManifest":
        # Scheme check: in staging and production, HTTP is strictly forbidden
        if self.environment in ("staging", "production") and self.authorized_scheme != "https":
            raise ValueError(
                f"Plain HTTP is strictly forbidden in '{self.environment}' environment. "
                "Only 'https' is permitted."
            )

        # In development, HTTP is permitted ONLY for authorized localhost origins
        if self.authorized_scheme == "http":
            clean_host = self.authorized_hostname.lower()
            if clean_host not in ("127.0.0.1", "localhost", "host.docker.internal", "[::1]"):
                raise ValueError(
                    f"HTTP scheme is restricted to localhost in development. Host '{clean_host}' is prohibited."
                )

        # Lifetime validation: max 120 seconds
        if self.expires_at <= self.issued_at:
            raise ValueError(f"expires_at ({self.expires_at}) must be greater than issued_at ({self.issued_at}).")

        lifetime = self.expires_at - self.issued_at
        if lifetime > MAX_MANIFEST_LIFETIME_SECONDS:
            raise ValueError(
                f"Manifest validity window ({lifetime}s) exceeds maximum allowed lifetime "
                f"({MAX_MANIFEST_LIFETIME_SECONDS}s)."
            )

        return self


def sign_manifest(
    manifest: ExecutionManifest,
    private_key: Union[ed25519.Ed25519PrivateKey, str, bytes],
) -> str:
    """
    Sign an ExecutionManifest using Ed25519 over RFC 8785 canonical bytes.
    Returns URL-safe base64-encoded signature.
    """
    # Load private key if passed as string or bytes
    if isinstance(private_key, str):
        key_bytes = base64.b64decode(private_key.strip())
        priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    elif isinstance(private_key, bytes):
        priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        priv_obj = private_key
    else:
        raise ManifestSecurityError(f"Unsupported private key type: {type(private_key)}")

    # Canonicalize manifest dictionary to RFC 8785 bytes
    manifest_dict = manifest.model_dump()
    canonical_bytes = canonicalize(manifest_dict)

    # Sign canonical bytes with Ed25519
    sig_bytes = priv_obj.sign(canonical_bytes)
    return base64.urlsafe_b64encode(sig_bytes).decode("ascii")


def verify_manifest(
    manifest_data: Union[Dict[str, Any], ExecutionManifest],
    signature_b64: str,
    public_keys: Dict[str, Union[ed25519.Ed25519PublicKey, str, bytes]],
    expected_environment: str,
    now_utc_ts: Optional[int] = None,
    expected_audience: str = "sentinelops.execution",
) -> ExecutionManifest:
    """
    Independently verify an ExecutionManifest's cryptographic signature,
    temporal validity, environment, and audience binding.

    Raises ManifestSecurityError if any check fails.
    """
    if not signature_b64 or not isinstance(signature_b64, str):
        raise ManifestSecurityError("Missing or invalid manifest signature.")

    # 1. Parse into strict ExecutionManifest model
    try:
        if isinstance(manifest_data, ExecutionManifest):
            manifest = manifest_data
        else:
            manifest = ExecutionManifest.model_validate(manifest_data)
    except Exception as e:
        raise ManifestSecurityError(f"Manifest schema validation failed: {e}")

    # 2. Audience and Issuer verification
    if manifest.issuer != "sentinelops.control-plane":
        raise ManifestSecurityError(f"Invalid manifest issuer '{manifest.issuer}'.")
    if manifest.audience != expected_audience:
        raise ManifestSecurityError(
            f"Invalid manifest audience '{manifest.audience}'. Expected '{expected_audience}'."
        )

    # 3. Environment verification
    norm_env = expected_environment.lower().strip()
    if manifest.environment != norm_env:
        raise ManifestSecurityError(
            f"Environment mismatch: manifest issued for '{manifest.environment}', "
            f"but current environment is '{norm_env}'."
        )

    # 4. Temporal validity check
    current_ts = now_utc_ts if now_utc_ts is not None else int(time.time())

    # Clock skew allowance on issued_at: issued_at cannot be in the future by > 5 seconds
    if manifest.issued_at > current_ts + CLOCK_SKEW_TOLERANCE_SECONDS:
        raise ManifestSecurityError(
            f"Manifest issued_at ({manifest.issued_at}) is in the future (current: {current_ts})."
        )

    # Expiry check
    if current_ts > manifest.expires_at:
        raise ManifestSecurityError(
            f"Manifest has expired at {manifest.expires_at} (current: {current_ts}, "
            f"expired by {current_ts - manifest.expires_at}s)."
        )

    # 5. Public Key Resolution by key_id
    raw_pub = public_keys.get(manifest.key_id)
    if not raw_pub:
        raise ManifestSecurityError(
            f"Unknown key_id '{manifest.key_id}'. No corresponding public verification key configured."
        )

    if isinstance(raw_pub, str):
        pub_bytes = base64.b64decode(raw_pub.strip())
        pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    elif isinstance(raw_pub, bytes):
        pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
    elif isinstance(raw_pub, ed25519.Ed25519PublicKey):
        pub_obj = raw_pub
    else:
        raise ManifestSecurityError(f"Unsupported public key type: {type(raw_pub)}")

    # 6. Decode signature
    try:
        sig_bytes = base64.urlsafe_b64decode(signature_b64.encode("ascii"))
        if len(sig_bytes) != 64:
            raise ValueError(f"Invalid signature length: {len(sig_bytes)} (expected 64 bytes)")
    except Exception as e:
        raise ManifestSecurityError(f"Malformed base64 signature: {e}")

    # 7. Canonicalize manifest and verify Ed25519 signature
    canonical_bytes = canonicalize(manifest.model_dump())
    try:
        pub_obj.verify(sig_bytes, canonical_bytes)
    except InvalidSignature:
        raise ManifestSecurityError("Cryptographic signature verification failed: signature does not match manifest.")

    return manifest
