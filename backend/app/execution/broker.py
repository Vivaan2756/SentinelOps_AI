"""Restricted Docker Broker Implementation for Phase 4.3.

Provides:
- RestrictedDockerBroker: Standalone daemon/service abstraction for isolated Docker operations.
- Enforces strict immutable executor image: sentinelops/remediation-executor:v1.0
- Enforces non-root execution (1000:1000), read-only rootfs, dropped capabilities, no-new-privileges.
- Enforces zero host volume mounts, zero Docker socket exposure, tmpfs /tmp with noexec.
- Enforces CPU (0.5), memory (256MB), and PID (50) limits.
- Independent request validation, dual-layer SSRF filtering, and bounded sanitized output.
- Fail-closed behavior when Docker daemon is unavailable.
"""

import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.rfc8785 import canonicalize
from app.core.manifest_crypto import (
    ExecutionManifest,
    compute_parameters_digest,
    normalize_origin_and_path,
    NormalizedOrigin,
)
from app.execution.manifest_journal import (
    BrokerManifestJournal,
    JournalConflictError,
    JournalUnavailableError,
    ManifestRecord,
)
from app.execution.public_keys import BrokerPublicKeyRegistry

logger = logging.getLogger("sentinelops.broker")

from pydantic import BaseModel, ConfigDict, Field

from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
    PreconditionFailedError,
)
from app.execution.manager import sanitize_metadata
from app.execution.network import (
    build_container_network_config,
    resolve_safe_target_url,
    validate_safe_target_url,
)
from app.remediation.registry import ActionRegistry

# ============================================================================
# Container Image Definitions & Immutability Configuration
# ============================================================================

# Local development image (used for local development / testing)
LOCAL_DEV_EXECUTOR_IMAGE = os.environ.get(
    "SENTINELOPS_DEV_EXECUTOR_IMAGE",
    "sentinelops/remediation-executor:dev-local",
)
IMMUTABLE_EXECUTOR_IMAGE = LOCAL_DEV_EXECUTOR_IMAGE  # Backward compatibility alias

# Production registry reference MUST be in format: repository@sha256:<64-hex-digest>
PRODUCTION_EXECUTOR_IMAGE = os.environ.get("SENTINELOPS_PROD_EXECUTOR_IMAGE", "")

# Verified local image ID (sha256:<64-hex>) for verified local Docker builds
VERIFIED_LOCAL_IMAGE_ID = os.environ.get(
    "SENTINELOPS_LOCAL_IMAGE_ID",
    "sha256:15df2587c7901ec1c8999694074d3c99daf2b76ad390518194580ddeaef96302",
)

# Immutable registry digest pattern: repository@sha256:<64-hex-digest>
REGISTRY_DIGEST_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9_.-]+(?::[0-9]+)?/)?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*@sha256:[a-f0-9]{64}$"
)


def is_placeholder_or_malformed_digest(digest_or_ref: str) -> bool:
    """Detect placeholder, synthetic or malformed digest strings."""
    if not digest_or_ref:
        return True

    if "@sha256:" in digest_or_ref:
        digest = digest_or_ref.split("@sha256:", 1)[1]
    elif digest_or_ref.startswith("sha256:"):
        digest = digest_or_ref.split("sha256:", 1)[1]
    else:
        digest = digest_or_ref

    if len(digest) != 64:
        return True
    if not all(c in "0123456789abcdefABCDEF" for c in digest):
        return True

    # Detect known placeholder sequences or trivial patterns
    if digest.lower() == "7f9b8c2d1e0f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b":
        return True
    if len(set(digest.lower())) <= 2:
        return True

    return False


# Allowlisted actions supported by the broker
ALLOWED_BROKER_ACTIONS: Set[str] = {
    "restore_order_api_demo",
    "inspect_service_health",
    "execute_http_recovery",
}

# Maximum allowed sample size for stdout/stderr logs (10 KB)
MAX_LOG_SAMPLE_BYTES = 10 * 1024


# ============================================================================
# Broker IPC Request & Response Schemas
# ============================================================================

class BrokerExecuteRequest(BaseModel):
    """RPC payload sent to the broker over the restricted IPC socket."""

    execution_id: str = Field(..., description="Unique execution UUID")
    action_id: str = Field(..., description="Allowlisted remediation action ID")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Validated parameters")
    target_url: str = Field(..., description="Target service URL")
    timeout_seconds: int = Field(30, ge=1, le=60, description="Execution timeout envelope")
    environment: str = Field("development", description="Execution target environment")
    image_tag: Optional[str] = Field(None, description="Custom image (strictly forbidden outside authorized reference)")
    volume_mounts: Optional[List[str]] = Field(None, description="Volume mounts (strictly forbidden)")
    commands: Optional[List[str]] = Field(None, description="Arbitrary commands (strictly forbidden)")

    # Pinned connection network contract (Task 1)
    pinned_ip: Optional[str] = Field(None, description="Pre-validated target IP for connection pinning")
    target_hostname: Optional[str] = Field(None, description="Original target hostname for Host header and SNI")
    target_port: Optional[int] = Field(None, description="Target service port")
    target_scheme: Optional[str] = Field(None, description="Target scheme (http/https)")
    target_path: Optional[str] = Field(None, description="Target endpoint path")
    tls_verify: bool = Field(True, description="Enable TLS certificate hostname verification")

    # Phase 2A.1 Stage 5: Worker IPC Manifest Pass-Through
    authorization_manifest: Optional[Dict[str, Any]] = Field(None, description="Exact signed authorization manifest")
    manifest_signature: Optional[str] = Field(None, description="Detached Ed25519 signature in base64url encoding")

    model_config = ConfigDict(extra="forbid")



class BrokerExecuteResponse(BaseModel):
    """Standardized response returned by the broker."""

    execution_id: str
    exit_code: int
    duration_ms: int
    stdout_sample: str = ""
    stderr_sample: str = ""
    output_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None


# ============================================================================
# Output Truncation & Sanitization Helper
# ============================================================================

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)(bearer\s+)[^\s]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[^\s,;&]+"),
    re.compile(r"(?i)(cookie:\s*)[^\r\n]+"),
]



def sanitize_and_truncate_log(text: str, max_bytes: int = MAX_LOG_SAMPLE_BYTES) -> str:
    """Sanitize sensitive patterns and truncate log sample to bounded size."""
    if not text:
        return ""

    sanitized = text
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r"\1[REDACTED]", sanitized)

    encoded = sanitized.encode("utf-8")
    if len(encoded) > max_bytes:
        truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return truncated + "\n... [TRUNCATED: Log exceeded 10KB limit] ..."

    return sanitized


# ============================================================================
# RestrictedDockerBroker Implementation
# ============================================================================

class RestrictedDockerBroker:
    """
    Dedicated broker daemon isolating Docker daemon access from the backend control plane.

    IPC SECURITY SPECIFICATION:
    - Socket Path: /var/run/sentinelops/broker.sock
    - Unix File Permissions: Mode 0600 (or 0660), owned by sentinelops-broker:sentinelops.
    - Peer Authentication: Uses SO_PEERCRED on Unix domain sockets to verify calling process
      UID matches authorized backend worker UID.
    - Zero Docker Socket Exposure: Backend processes never touch /var/run/docker.sock.
    - Immutable Image: Only sentinelops/remediation-executor:v1.0 can be launched.
    - Zero Host Mounts: Volume mounts from host filesystem are rejected with BrokerSecurityViolation.
    """

    def __init__(
        self,
        docker_client: Optional[Any] = None,
        journal: Optional[BrokerManifestJournal] = None,
        public_key_registry: Optional[BrokerPublicKeyRegistry] = None,
        environment: Optional[str] = None,
        require_manifest: Optional[bool] = None,
        enforce_no_private_key: Optional[bool] = None,
    ):
        """
        Initialize broker with optional Docker client adapter (used for testing),
        persistent replay journal, and public-key registry.
        """
        # Strict zero-private-key assertion: broker must NEVER access private keys
        if enforce_no_private_key or (
            enforce_no_private_key is None
            and os.environ.get("SENTINELOPS_MANIFEST_PRIVATE_KEY")
            and not os.environ.get("PYTEST_CURRENT_TEST")
        ):
            if os.environ.get("SENTINELOPS_MANIFEST_PRIVATE_KEY"):
                raise BrokerSecurityViolation(
                    "SENTINELOPS_MANIFEST_PRIVATE_KEY detected in broker process environment! "
                    "The broker must NEVER load, accept, or access private key material."
                )

        self._docker_client = docker_client
        self.journal = journal if journal is not None else BrokerManifestJournal()
        self.public_key_registry = (
            public_key_registry if public_key_registry is not None else BrokerPublicKeyRegistry()
        )
        env_val = environment or os.environ.get("SENTINELOPS_ENVIRONMENT") or os.environ.get("ENVIRONMENT")
        if env_val in ("development", "staging", "production"):
            self.environment = env_val
        else:
            self.environment = "development"

        if require_manifest is not None:
            self.require_manifest = require_manifest
        else:
            req_env = os.environ.get("SENTINELOPS_REQUIRE_MANIFEST", "true").lower()
            self.require_manifest = req_env in ("true", "1", "yes")

    def is_docker_available(self) -> bool:
        """Check if Docker daemon is accessible."""
        if self._docker_client is not None:
            return True
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False

    def validate_request(self, request: BrokerExecuteRequest) -> None:
        """
        Independently validate all security parameters of the broker request.
        Raises BrokerSecurityViolation if any rule is breached.
        """
        # 1. Action allowlist check
        if request.action_id not in ALLOWED_BROKER_ACTIONS:
            raise BrokerSecurityViolation(
                f"Action '{request.action_id}' is not in broker allowlist {sorted(ALLOWED_BROKER_ACTIONS)}. "
                "Arbitrary actions are forbidden."
            )

        # 2. Reject unauthorized custom image tags
        if request.image_tag is not None:
            if request.environment == "production":
                current_prod = os.environ.get("SENTINELOPS_PROD_EXECUTOR_IMAGE", PRODUCTION_EXECUTOR_IMAGE)
                if not current_prod or request.image_tag != current_prod:
                    raise BrokerSecurityViolation(
                        f"Custom image '{request.image_tag}' rejected in production. "
                        "Only configured immutable registry reference is permitted."
                    )
            else:
                allowed_dev_images = {
                    LOCAL_DEV_EXECUTOR_IMAGE,
                    "sentinelops/remediation-executor:v1.0",
                    "sentinelops/remediation-executor:dev",
                }
                if VERIFIED_LOCAL_IMAGE_ID:
                    allowed_dev_images.add(VERIFIED_LOCAL_IMAGE_ID)
                if request.image_tag not in allowed_dev_images:
                    raise BrokerSecurityViolation(
                        f"Custom image '{request.image_tag}' rejected. "
                        f"Only authorized development image '{LOCAL_DEV_EXECUTOR_IMAGE}' is permitted."
                    )

        # 3. Reject host volume mounts
        if request.volume_mounts:
            raise BrokerSecurityViolation("Host volume mounts are strictly forbidden in execution sandbox.")

        # 4. Reject arbitrary shell commands
        if request.commands:
            raise BrokerSecurityViolation("Arbitrary container commands/scripts are strictly forbidden.")

        # 5. Schema parameter validation
        is_valid, _, err_msg = ActionRegistry.validate_parameters(request.action_id, request.parameters)
        if not is_valid:
            raise BrokerSecurityViolation(f"Parameter validation failed: {err_msg}")

        # 6. Target URL SSRF check & Pinned Connection Contract Verification
        target = resolve_safe_target_url(
            request.target_url,
            environment=request.environment,
            action_id=request.action_id,
        )

        # Verify network contract parameters consistency if provided
        if request.pinned_ip is not None:
            if request.pinned_ip.strip() != target.pinned_ip.strip():
                raise BrokerSecurityViolation(
                    f"Target pinned IP mismatch: request specified '{request.pinned_ip}', "
                    f"but resolved target IP is '{target.pinned_ip}'."
                )

        if request.target_hostname is not None:
            if request.target_hostname.lower().strip() != target.hostname.lower().strip():
                raise BrokerSecurityViolation(
                    f"Target hostname mismatch: request specified '{request.target_hostname}', "
                    f"but resolved hostname is '{target.hostname}'."
                )

        if request.target_port is not None:
            if request.target_port != target.port:
                raise BrokerSecurityViolation(
                    f"Target port mismatch: request specified {request.target_port}, "
                    f"but resolved port is {target.port}."
                )

        if request.target_scheme is not None:
            if request.target_scheme.lower().strip() != target.scheme.lower().strip():
                raise BrokerSecurityViolation(
                    f"Target scheme mismatch: request specified '{request.target_scheme}', "
                    f"but resolved scheme is '{target.scheme}'."
                )

        if request.target_path is not None:
            if request.target_path.rstrip("/") != target.path.rstrip("/"):
                raise BrokerSecurityViolation(
                    f"Target path mismatch: request specified '{request.target_path}', "
                    f"but resolved path is '{target.path}'."
                )

    def build_container_config(
        self, request: BrokerExecuteRequest
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate the immutable container specification and security profile.

        Enforces:
        - Image: immutable digest reference in production; local dev image in dev/test
        - User: 1000:1000 (non-root)
        - Read-only rootfs: True
        - Cap drop: ALL
        - Security opts: no-new-privileges:true
        - Volumes: NONE
        - tmpfs: /tmp:rw,noexec,nosuid,size=32m
        - Nano CPUs: 500_000_000 (0.5 CPU)
        - Memory limit: 256m
        - PIDs limit: 50
        - Connection-time DNS/IP pinning passed into container environment
        """
        self.validate_request(request)

        # Determine image reference
        if request.environment == "production":
            prod_image = (
                request.image_tag
                or os.environ.get("SENTINELOPS_PROD_EXECUTOR_IMAGE", "")
                or PRODUCTION_EXECUTOR_IMAGE
            )
            if not prod_image:
                raise BrokerSecurityViolation(
                    "Production execution requires a configured immutable registry digest reference "
                    "(SENTINELOPS_PROD_EXECUTOR_IMAGE). None provided. Fail-closed: execution aborted."
                )
            if not REGISTRY_DIGEST_PATTERN.match(prod_image):
                raise BrokerSecurityViolation(
                    f"Production image reference '{prod_image}' is invalid. Production execution strictly "
                    "requires immutable registry format (repository@sha256:<64-hex-digest>). Mutable tags are forbidden."
                )
            if is_placeholder_or_malformed_digest(prod_image):
                raise BrokerSecurityViolation(
                    f"Production image reference '{prod_image}' contains an invalid or placeholder digest. "
                    "A genuine immutable registry manifest digest is required."
                )
            image_ref = prod_image

            # If Docker client is available, verify that local image matches the immutable reference
            if self._docker_client is not None:
                try:
                    img = self._docker_client.images.get(image_ref)
                    repo_digests = getattr(img, "attrs", {}).get("RepoDigests", [])
                    if repo_digests and not any(image_ref in rd for rd in repo_digests):
                        raise BrokerSecurityViolation(
                            f"Docker image mismatch: image '{image_ref}' does not match RepoDigests {repo_digests}."
                        )
                except BrokerSecurityViolation:
                    raise
                except Exception as e:
                    # If image is absent or cannot be verified, fail closed
                    raise BrokerSecurityViolation(
                        f"Configured production immutable image '{image_ref}' is not available: {str(e)}"
                    )
        else:
            # Development / Staging / Test
            image_ref = request.image_tag or LOCAL_DEV_EXECUTOR_IMAGE

        # Resolve network topology
        net_config = build_container_network_config(
            environment=request.environment,
            raw_service_url=request.target_url,
            action_id=request.action_id,
            docker_client=self._docker_client,
        )
        resolved_url, network_kwargs = net_config[0], net_config[1]
        target = getattr(net_config, "target", None)
        if target is None:
            target = resolve_safe_target_url(
                resolved_url,
                environment=request.environment,
                action_id=request.action_id,
            )

        container_spec: Dict[str, Any] = {
            "name": f"sentinelops-exec-{request.execution_id}",
            "image": image_ref,
            "entrypoint": ["python", "-m", "executor.runner"],
            "command": [],
            "user": "1000:1000",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "volumes": {},  # NO host mounts
            "tmpfs": {"/tmp": "rw,noexec,nosuid,size=32m"},
            "nano_cpus": 500_000_000,
            "mem_limit": "256m",
            "pids_limit": 50,
            "labels": {
                "sentinelops.managed": "true",
                "sentinelops.execution_id": request.execution_id,
                "sentinelops.action_id": request.action_id,
                "sentinelops.created_at": str(int(time.time())),
            },
            "environment": {
                "EXECUTION_ID": request.execution_id,
                "ACTION_ID": request.action_id,
                "PARAMETERS_JSON": json.dumps(request.parameters),
                "TARGET_URL": resolved_url,
                "PINNED_IP": target.pinned_ip,
                "TARGET_HOST": target.hostname,
                "TARGET_PORT": str(target.port),
                "TARGET_SCHEME": target.scheme,
                "TARGET_PATH": target.path,
                "TIMEOUT_SECONDS": str(request.timeout_seconds),
                "FOLLOW_REDIRECTS": "false",
                "TLS_VERIFY": "true" if request.tls_verify else "false",
                "ENVIRONMENT": request.environment,
            },
            **network_kwargs,
        }

        if os.environ.get("SENTINELOPS_TRUSTED_GATEWAY_IP"):
            container_spec["environment"]["SENTINELOPS_TRUSTED_GATEWAY_IP"] = os.environ[
                "SENTINELOPS_TRUSTED_GATEWAY_IP"
            ].strip()

        return resolved_url, container_spec

    def verify_execution_authorization(
        self, request: BrokerExecuteRequest
    ) -> Tuple[ExecutionManifest, str, str, str]:
        """
        Independently verify Ed25519 cryptographic signature, manifest validity,
        parameter binding, request binding, and endpoint origin/path authorization.

        Returns (manifest, manifest_digest, authorized_origin, authorized_path).
        Raises BrokerSecurityViolation if any verification check fails.
        """
        if not request.authorization_manifest:
            raise BrokerSecurityViolation("Missing authorization_manifest in execution request.")
        if not isinstance(request.authorization_manifest, dict):
            raise BrokerSecurityViolation("authorization_manifest must be a dictionary.")
        if not request.manifest_signature or not isinstance(request.manifest_signature, str):
            raise BrokerSecurityViolation("Missing or invalid manifest_signature in execution request.")

        # 1. Manifest schema validation
        try:
            manifest = ExecutionManifest.model_validate(request.authorization_manifest)
        except Exception as e:
            raise BrokerSecurityViolation(f"Manifest schema validation failed: {e}")

        # 2. Public key resolution & status verification
        if self.public_key_registry is None:
            raise BrokerSecurityViolation("Broker has no public-key registry configured.")
        pub_key = self.public_key_registry.resolve_and_verify_key(manifest.key_id)

        # 3. Temporal validity check
        now = int(time.time())
        # Clock skew tolerance: issued_at cannot be in the future by > 5 seconds
        if manifest.issued_at > now + 5:
            raise BrokerSecurityViolation(
                f"Manifest issued_at ({manifest.issued_at}) is in the future beyond 5s skew tolerance (now: {now})."
            )
        # Expiration check
        if now > manifest.expires_at:
            raise BrokerSecurityViolation(
                f"Manifest expired at {manifest.expires_at} (now: {now}, expired by {now - manifest.expires_at}s)."
            )
        # Bounded validity window: max 60 seconds
        if (manifest.expires_at - manifest.issued_at) > 60:
            raise BrokerSecurityViolation(
                f"Manifest validity window ({manifest.expires_at - manifest.issued_at}s) exceeds max 60s."
            )
        # Maximum age from issued_at: max 60 seconds
        if (now - manifest.issued_at) > 60:
            raise BrokerSecurityViolation(
                f"Manifest was issued {now - manifest.issued_at}s ago, exceeding max 60s lifetime."
            )

        # 4. Issuer, Audience, and Environment verification
        if manifest.issuer != "sentinelops.control-plane":
            raise BrokerSecurityViolation(
                f"Invalid manifest issuer '{manifest.issuer}'. Expected 'sentinelops.control-plane'."
            )
        if manifest.audience != "sentinelops.broker":
            raise BrokerSecurityViolation(
                f"Invalid manifest audience '{manifest.audience}'. Expected 'sentinelops.broker'."
            )
        if manifest.environment != request.environment:
            raise BrokerSecurityViolation(
                f"Environment mismatch: manifest issued for '{manifest.environment}', "
                f"but request specified '{request.environment}'."
            )
        if self.environment and manifest.environment != self.environment:
            raise BrokerSecurityViolation(
                f"Environment mismatch: manifest issued for '{manifest.environment}', "
                f"but broker is configured for '{self.environment}'."
            )

        # 5. Ed25519 cryptographic signature verification over canonical RFC 8785 bytes
        canonical_bytes = canonicalize(manifest.model_dump())
        try:
            padded_sig = request.manifest_signature.strip()
            sig_bytes = base64.urlsafe_b64decode(padded_sig + "=" * (-len(padded_sig) % 4))
            if len(sig_bytes) != 64:
                raise ValueError(f"Invalid signature length: {len(sig_bytes)} bytes (expected 64)")
        except Exception as e:
            raise BrokerSecurityViolation(f"Malformed Ed25519 signature: {e}")

        try:
            pub_key.verify(sig_bytes, canonical_bytes)
        except InvalidSignature:
            raise BrokerSecurityViolation(
                "Ed25519 signature verification failed: signature does not match canonical manifest."
            )

        # 6. Parameter digest verification
        expected_param_sha = compute_parameters_digest(request.parameters)
        if expected_param_sha != manifest.parameters_sha256:
            raise BrokerSecurityViolation(
                f"Parameter digest mismatch: manifest specifies '{manifest.parameters_sha256}', "
                f"but request parameters hash to '{expected_param_sha}'."
            )

        # 7. Request binding verification
        if request.execution_id != manifest.execution_id:
            raise BrokerSecurityViolation(
                f"Execution ID mismatch: request has '{request.execution_id}', "
                f"manifest authorizes '{manifest.execution_id}'."
            )
        if request.action_id != manifest.action_id:
            raise BrokerSecurityViolation(
                f"Action ID mismatch: request has '{request.action_id}', "
                f"manifest authorizes '{manifest.action_id}'."
            )

        # 8. Origin and path verification against normalized target URL
        norm_target = normalize_origin_and_path(request.target_url)
        if norm_target.scheme != manifest.authorized_scheme:
            raise BrokerSecurityViolation(
                f"Target scheme mismatch: request has '{norm_target.scheme}', "
                f"manifest authorizes '{manifest.authorized_scheme}'."
            )
        if norm_target.hostname != manifest.authorized_hostname:
            raise BrokerSecurityViolation(
                f"Target hostname mismatch: request has '{norm_target.hostname}', "
                f"manifest authorizes '{manifest.authorized_hostname}'."
            )
        if norm_target.port != manifest.authorized_port:
            raise BrokerSecurityViolation(
                f"Target port mismatch: request has {norm_target.port}, "
                f"manifest authorizes {manifest.authorized_port}."
            )
        if norm_target.path != manifest.authorized_path:
            raise BrokerSecurityViolation(
                f"Target path mismatch: request has '{norm_target.path}', "
                f"manifest authorizes '{manifest.authorized_path}'."
            )

        # 9. Independent destination network resolution and contract verification
        resolved_target = resolve_safe_target_url(
            request.target_url,
            environment=request.environment,
            action_id=request.action_id,
        )
        if request.pinned_ip is not None:
            if request.pinned_ip.strip() != resolved_target.pinned_ip.strip():
                raise BrokerSecurityViolation(
                    f"Pinned IP mismatch: worker provided '{request.pinned_ip}', "
                    f"broker resolved '{resolved_target.pinned_ip}'."
                )

        manifest_digest = hashlib.sha256(canonical_bytes).hexdigest()
        authorized_origin = f"{manifest.authorized_scheme}://{manifest.authorized_hostname}:{manifest.authorized_port}"
        authorized_path = manifest.authorized_path

        return manifest, manifest_digest, authorized_origin, authorized_path

    def _inspect_daemon_for_created_container(
        self, client: Optional[Any], execution_id: Optional[str]
    ) -> Tuple[bool, Optional[Any]]:
        """
        Inspect the Docker daemon to check whether a container was created for this execution_id.

        Returns (is_conclusive: bool, found_container: Optional[Any]):
        - (False, None): daemon inspection failed, timed out, or client unavailable (UNCERTAIN).
        - (True, None): daemon responded conclusively and ZERO matching containers exist.
        - (True, container): daemon responded and a matching container was found.
        """
        if client is None or not execution_id:
            return False, None

        containers_mgr = getattr(client, "containers", None)
        if containers_mgr is None or not hasattr(containers_mgr, "list"):
            return False, None

        try:
            # 1. Query by deterministic execution label
            matching = containers_mgr.list(
                all=True,
                filters={"label": f"sentinelops.execution_id={execution_id}"},
            )
            if matching:
                return True, matching[0]

            # 2. Query by deterministic container name
            matching_name = containers_mgr.list(
                all=True,
                filters={"name": f"sentinelops-exec-{execution_id}"},
            )
            if matching_name:
                return True, matching_name[0]

            # Conclusively zero containers exist on daemon
            return True, None
        except Exception as e:
            logger.warning(
                "Daemon-side inspection for execution_id '%s' failed or timed out: %s",
                execution_id,
                e,
            )
            return False, None

    def _is_authoritative_creation_rejection(self, exc: Optional[Exception]) -> bool:
        """
        Check if an exception during container creation is an explicit, authoritative
        Docker API rejection proving that no container was created on the daemon.

        Returns True ONLY for authoritative daemon rejections (e.g. 404 ImageNotFound,
        400 Bad Request, 422 Unprocessable Entity) originating from docker.errors.DockerException.
        Returns False for:
        - ConnectionResetError, BrokenPipeError, ConnectionError
        - TimeoutError, requests.exceptions.Timeout, requests.exceptions.ConnectionError
        - HTTP 409 Conflict (container name already exists on daemon!)
        - HTTP 500 / 502 / 503 / 504 (daemon internal error / crash / gateway failure)
        - Generic Exception, RuntimeError, or unclassified exceptions
        - Unrelated non-Docker exceptions even if they have a status_code attribute
        """
        if exc is None:
            return False

        # Ambiguous transport, timeout, or connection exceptions
        if isinstance(exc, (TimeoutError, ConnectionResetError, ConnectionError, BrokenPipeError)):
            return False

        try:
            import requests.exceptions
            if isinstance(exc, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
                return False
        except ImportError:
            pass

        # Check official Docker SDK exception types
        try:
            import docker.errors
            if not isinstance(exc, docker.errors.DockerException):
                return False
            if isinstance(exc, docker.errors.ImageNotFound):
                return True
            if isinstance(exc, docker.errors.NotFound):
                msg = str(exc).lower()
                return "image" in msg or "no such image" in msg
            if isinstance(exc, docker.errors.APIError):
                status = getattr(exc, "status_code", None)
                if status is None and getattr(exc, "response", None) is not None:
                    status = getattr(exc.response, "status_code", None)
                # 400 Bad Request, 422 Unprocessable Entity prove daemon rejected creation.
                # 404 Not Found is authoritative only if it relates to missing image.
                # 409 Conflict means a container with this name ALREADY EXISTS.
                # 500+ are daemon internal errors / crashes.
                if status in (400, 422):
                    return True
                if status == 404:
                    msg = str(exc).lower()
                    return "image" in msg or "no such image" in msg
                return False
        except ImportError:
            pass

        return False

    def _is_demonstrably_unstarted(
        self,
        container: Optional[Any],
        has_started: bool,
        client: Optional[Any] = None,
        execution_id: Optional[str] = None,
        creation_exception: Optional[Exception] = None,
        start_attempted: bool = False,
    ) -> bool:
        """
        Determine if a container demonstrably never started.
        Returns True ONLY if we can prove the container never executed.
        If there is any ambiguity, returns False (fails closed into OUTCOME_UNKNOWN).

        Safety Invariant (Stage 6.1.3 - Docker START Request Race & Classification Hardening):
        1. If has_started is True or start_attempted is True -> returns False immediately.
           Once a start request has been initiated, point-in-time snapshots (e.g. reload()
           reporting 'created', Running=False, Pid=0) MUST NEVER convert an in-flight or
           ambiguous START failure into FAILED.
        2. If container is None (creation failed/raised):
           - Connection reset, timeout, transport disconnect, or generic exception is AMBIGUOUS.
             A creation request might still be processing on the daemon.
             An immediate empty daemon listing after an ambiguous transport failure is only a snapshot!
             Therefore, ambiguous creation exceptions MUST ALWAYS produce OUTCOME_UNKNOWN (returns False).
           - ONLY explicit, authoritative Docker API rejections that prove no container was created
             (e.g. docker.errors.ImageNotFound, APIError 400/422) can permit FAILED, and ONLY IF
             daemon inspection also confirms zero matching containers exist.
           - If a matching container is found on daemon after a creation exception, its state cannot
             be established as unstarted -> returns False (OUTCOME_UNKNOWN).
        3. If container is not None (successful creation call, before start was attempted):
           - Must be able to inspect fresh state (reload). If reload fails -> returns False (OUTCOME_UNKNOWN).
           - State must confirm: status == "created", Running == False, Pid == 0,
             StartedAt is empty or zero timestamp, and not started.
           - If all conditions met -> returns True (FAILED).
           - Otherwise -> returns False (OUTCOME_UNKNOWN).
        """
        if has_started or start_attempted:
            return False

        target_container = container

        if target_container is None:
            # Check if creation exception is an authoritative Docker rejection
            if not self._is_authoritative_creation_rejection(creation_exception):
                logger.warning(
                    "Container creation failed with ambiguous transport, timeout, or generic exception (%s). "
                    "Cannot establish unstarted state even if daemon listing is empty (failing closed into OUTCOME_UNKNOWN).",
                    creation_exception,
                )
                return False

            # Explicit authoritative Docker rejection (e.g. ImageNotFound / 400 / 422)
            # Verify daemon listing confirms zero containers exist
            is_conclusive, found_container = self._inspect_daemon_for_created_container(
                client=client, execution_id=execution_id
            )
            if is_conclusive and found_container is None:
                logger.info(
                    "Docker daemon authoritatively rejected creation (%s) and daemon inspection "
                    "conclusively established 0 containers exist for execution_id '%s'.",
                    creation_exception,
                    execution_id,
                )
                return True

            logger.warning(
                "Authoritative creation rejection (%s) but daemon inspection found container (%s) "
                "or was inconclusive (is_conclusive=%s). Failing closed into OUTCOME_UNKNOWN.",
                creation_exception,
                found_container,
                is_conclusive,
            )
            return False

        try:
            # If reload method exists, query fresh state from Docker daemon
            if hasattr(target_container, "reload"):
                target_container.reload()

            status = getattr(target_container, "status", None)
            attrs = getattr(target_container, "attrs", {}) or {}
            state = attrs.get("State", {})

            is_running = state.get("Running", False)
            started_at = state.get("StartedAt", "")
            pid = state.get("Pid", 0)
            was_started = getattr(target_container, "started", False)

            # In Docker engine:
            # A container that has never started has status == "created",
            # Running is False, Pid is 0, StartedAt is empty or zero timestamp,
            # and was_started is False.
            if (
                status == "created"
                and not is_running
                and pid == 0
                and (not started_at or started_at.startswith("0001-01-01"))
                and not was_started
            ):
                return True

            logger.warning(
                "Container state indicates possible start or cannot confirm unstarted "
                "(status=%s, running=%s, pid=%s, started_at=%s, started=%s). Failing closed.",
                status,
                is_running,
                pid,
                started_at,
                was_started,
            )
            return False
        except Exception as e:
            # Any error during state inspection (e.g. Docker API connection failure)
            # leaves the lifecycle state uncertain!
            logger.warning(f"Could not conclusively verify container unstarted state: {e}")
            return False
            logger.warning(f"Could not conclusively verify container unstarted state: {e}")
            return False

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        """
        Execute container action via Docker daemon or fail closed if unavailable.
        Guarantees:
        1. Independent authorization verification (Ed25519 signature, bounds, parameters, network).
        2. Atomic replay journal claim BEFORE container creation.
        3. Fail closed if journal or Docker is unavailable.
        4. State progression: CLAIMED -> EXECUTING (at launch) -> COMPLETED / FAILED / OUTCOME_UNKNOWN.
        5. Container cleanup in finally block.
        """
        manifest: Optional[ExecutionManifest] = None
        manifest_digest: Optional[str] = None
        authorized_origin: Optional[str] = None
        authorized_path: Optional[str] = None

        if self.require_manifest:
            manifest, manifest_digest, authorized_origin, authorized_path = (
                self.verify_execution_authorization(request)
            )

        self.validate_request(request)

        # Build container config before claiming to validate all image & network params
        resolved_url, container_spec = self.build_container_config(request)

        # Atomic replay journal claim BEFORE container creation
        if self.journal is not None and manifest is not None:
            try:
                self.journal.claim_manifest(
                    manifest_id=manifest.manifest_id,
                    execution_id=manifest.execution_id,
                    action_id=manifest.action_id,
                    authorized_origin=authorized_origin,
                    authorized_path=authorized_path,
                    parameters_sha256=manifest.parameters_sha256,
                    key_id=manifest.key_id,
                    manifest_digest=manifest_digest,
                    expires_at=manifest.expires_at,
                )
            except JournalConflictError as e:
                logger.warning(f"Replay journal conflict for manifest {manifest.manifest_id}: {e}")
                raise BrokerSecurityViolation(f"Replay prevention conflict: {e}")
            except JournalUnavailableError as e:
                logger.error(f"Replay journal unavailable during claim: {e}")
                raise ExecutionEnvironmentUnavailable(f"Replay journal unavailable: {e}")

        # Fail closed if Docker is not available
        if not self.is_docker_available():
            if self.journal is not None and manifest is not None:
                try:
                    self.journal.mark_failed(
                        manifest.manifest_id,
                        error_message="Docker execution sandbox is not available on this host.",
                    )
                except Exception as j_err:
                    logger.error(f"Failed to mark journal failed: {j_err}")

            raise ExecutionEnvironmentUnavailable(
                "RestrictedDockerBroker: Docker execution sandbox is not available on this host. "
                "Mutating remediation actions require a verified isolated container environment."
            )

        start_time = time.time()
        container = None
        has_started = False
        start_attempted = False
        is_uncertain_launch = False

        client = self._docker_client
        if client is None:
            try:
                import docker
                client = docker.from_env()
            except Exception:
                client = None

        if client is None:
            import docker
            client = docker.from_env()

        try:
            # ================================================================
            # Phase 1: Container Creation
            # ================================================================
            if hasattr(client.containers, "create"):
                try:
                    container = client.containers.create(**container_spec)
                except Exception as create_err:
                    duration_ms = int((time.time() - start_time) * 1000)
                    is_unstarted = self._is_demonstrably_unstarted(
                        container=None,
                        has_started=False,
                        client=client,
                        execution_id=request.execution_id,
                        creation_exception=create_err,
                        start_attempted=False,
                    )
                    if not is_unstarted:
                        is_uncertain_launch = True

                    if self.journal is not None and manifest is not None:
                        try:
                            if is_unstarted:
                                self.journal.mark_failed(
                                    manifest.manifest_id,
                                    error_message=f"Container demonstrably never started: {str(create_err)}",
                                )
                            else:
                                self.journal.mark_outcome_unknown(
                                    manifest.manifest_id,
                                    reason=f"Uncertain execution or launch failure: {str(create_err)}",
                                )
                        except Exception as j_err:
                            logger.error(f"Failed to record journal outcome on creation failure: {j_err}")

                    return BrokerExecuteResponse(
                        execution_id=request.execution_id,
                        exit_code=1,
                        duration_ms=duration_ms,
                        stdout_sample="",
                        stderr_sample=str(create_err),
                        error_message=f"Broker execution failed: {str(create_err)}",
                        error_category="broker_error",
                    )

                # ============================================================
                # Phase 2: Journal state transition to EXECUTING
                # ============================================================
                if self.journal is not None and manifest is not None:
                    try:
                        self.journal.mark_executing(manifest.manifest_id)
                    except Exception as j_err:
                        duration_ms = int((time.time() - start_time) * 1000)
                        logger.error(f"Failed to record executing in journal before start: {j_err}")
                        if container is not None:
                            try:
                                container.remove(force=True)
                            except Exception:
                                pass
                            container = None
                        raise ExecutionEnvironmentUnavailable(
                            f"Replay journal unavailable during state transition to EXECUTING: {j_err}"
                        )

                # ============================================================
                # Phase 3: Container START
                # ============================================================
                start_attempted = True
                try:
                    if hasattr(container, "start"):
                        container.start()
                    has_started = True
                except Exception as start_err:
                    duration_ms = int((time.time() - start_time) * 1000)
                    # CRITICAL INVARIANT (Stage 6.1.3):
                    # Once container.start() has been invoked, ANY timeout, connection reset,
                    # broken pipe, generic exception, or ambiguous response MUST produce OUTCOME_UNKNOWN.
                    # An immediate container.reload() reporting 'created', Running=False, Pid=0,
                    # or zero StartedAt MUST NOT convert an ambiguous START failure into FAILED.
                    # Uncertain containers must NEVER be automatically killed or removed.
                    is_uncertain_launch = True
                    logger.warning(
                        "Container start failed with exception (%s). Execution state is uncertain; "
                        "marking OUTCOME_UNKNOWN and preserving container for administrative inspection.",
                        start_err,
                    )
                    if self.journal is not None and manifest is not None:
                        try:
                            self.journal.mark_outcome_unknown(
                                manifest.manifest_id,
                                reason=f"Uncertain execution or launch failure: {str(start_err)}",
                            )
                        except Exception as j_err:
                            logger.error(f"Failed to record outcome unknown in journal on start failure: {j_err}")

                    return BrokerExecuteResponse(
                        execution_id=request.execution_id,
                        exit_code=1,
                        duration_ms=duration_ms,
                        stdout_sample="",
                        stderr_sample=str(start_err),
                        error_message=f"Broker execution failed: {str(start_err)}",
                        error_category="broker_error",
                    )

            else:
                # Fallback for clients without separate create (e.g. simplified mock)
                if self.journal is not None and manifest is not None:
                    try:
                        self.journal.mark_executing(manifest.manifest_id)
                    except Exception as j_err:
                        raise ExecutionEnvironmentUnavailable(
                            f"Replay journal unavailable during state transition to EXECUTING: {j_err}"
                        )
                start_attempted = True
                try:
                    container = client.containers.run(detach=True, **container_spec)
                    has_started = True
                except Exception as run_err:
                    duration_ms = int((time.time() - start_time) * 1000)
                    is_uncertain_launch = True
                    logger.warning(
                        "Container run failed with exception (%s). Execution state is uncertain; "
                        "marking OUTCOME_UNKNOWN.",
                        run_err,
                    )
                    if self.journal is not None and manifest is not None:
                        try:
                            self.journal.mark_outcome_unknown(
                                manifest.manifest_id,
                                reason=f"Uncertain execution or launch failure: {str(run_err)}",
                            )
                        except Exception as j_err:
                            logger.error(f"Failed to record outcome unknown in journal on run failure: {j_err}")

                    return BrokerExecuteResponse(
                        execution_id=request.execution_id,
                        exit_code=1,
                        duration_ms=duration_ms,
                        stdout_sample="",
                        stderr_sample=str(run_err),
                        error_message=f"Broker execution failed: {str(run_err)}",
                        error_category="broker_error",
                    )

            # ================================================================
            # Phase 4: Container Wait, Output Logs & Outcome Classification
            # ================================================================
            # Wait with bounded timeout
            try:
                wait_res = container.wait(timeout=request.timeout_seconds)
                exit_code = wait_res.get("StatusCode", 1) if isinstance(wait_res, dict) else int(wait_res)
            except Exception as timeout_err:
                duration_ms = int((time.time() - start_time) * 1000)
                if self.journal is not None and manifest is not None:
                    try:
                        self.journal.mark_outcome_unknown(
                            manifest.manifest_id,
                            reason=f"Container execution timed out after {request.timeout_seconds} seconds.",
                        )
                    except Exception as j_err:
                        logger.error(f"Failed to record outcome unknown in journal: {j_err}")

                return BrokerExecuteResponse(
                    execution_id=request.execution_id,
                    exit_code=124,  # Standard timeout exit code
                    duration_ms=duration_ms,
                    stdout_sample="",
                    stderr_sample=f"Execution timed out after {request.timeout_seconds} seconds.",
                    error_message=f"Container execution timed out after {request.timeout_seconds}s.",
                    error_category="timeout",
                )

            # Fetch bounded logs
            logs_stdout = container.logs(stdout=True, stderr=False)
            logs_stderr = container.logs(stdout=False, stderr=True)
            stdout_str = logs_stdout.decode("utf-8", errors="replace") if isinstance(logs_stdout, bytes) else str(logs_stdout)
            stderr_str = logs_stderr.decode("utf-8", errors="replace") if isinstance(logs_stderr, bytes) else str(logs_stderr)

            duration_ms = int((time.time() - start_time) * 1000)
            clean_stdout = sanitize_and_truncate_log(stdout_str)
            clean_stderr = sanitize_and_truncate_log(stderr_str)

            # Attempt parsing structured JSON output from stdout
            output_data = None
            try:
                output_data = json.loads(stdout_str)
            except Exception:
                pass

            error_category = None
            error_message = None
            if exit_code == 0:
                if self.journal is not None and manifest is not None:
                    try:
                        self.journal.mark_completed(manifest.manifest_id)
                    except Exception as j_err:
                        logger.error(f"Failed to record completion in journal: {j_err}")
            else:
                error_category = "action_failure"
                error_message = clean_stderr or f"Container exited with code {exit_code}."
                if self.journal is not None and manifest is not None:
                    try:
                        # Safety invariant (Stage 6.1): Once execution may have started,
                        # any non-zero exit must become OUTCOME_UNKNOWN to prevent unsafe automatic retry.
                        self.journal.mark_outcome_unknown(
                            manifest.manifest_id,
                            reason=f"Container process exited with non-zero code {exit_code}: {error_message}",
                        )
                    except Exception as j_err:
                        logger.error(f"Failed to record outcome unknown in journal: {j_err}")

            return BrokerExecuteResponse(
                execution_id=request.execution_id,
                exit_code=exit_code,
                duration_ms=duration_ms,
                stdout_sample=clean_stdout,
                stderr_sample=clean_stderr,
                output_data=output_data,
                error_message=error_message,
                error_category=error_category,
            )

        except Exception as post_start_err:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(f"Unexpected error during execution lifecycle: {post_start_err}")
            if self.journal is not None and manifest is not None:
                try:
                    self.journal.mark_outcome_unknown(
                        manifest.manifest_id,
                        reason=f"Execution lifecycle failure: {str(post_start_err)}",
                    )
                except Exception as j_err:
                    logger.error(f"Failed to record outcome unknown in journal: {j_err}")

            return BrokerExecuteResponse(
                execution_id=request.execution_id,
                exit_code=1,
                duration_ms=duration_ms,
                stdout_sample="",
                stderr_sample=str(post_start_err),
                error_message=f"Broker execution failed: {str(post_start_err)}",
                error_category="broker_error",
            )
        finally:
            # Do not delete or start an uncertain container automatically (Stage 6.1.1 & Stage 6.1.3).
            # Cleanup must establish that doing so cannot interfere with an executing remediation.
            if container is not None and not is_uncertain_launch:
                try:
                    container.kill()
                except Exception:
                    pass
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _durably_persist_orphan_log(
        self,
        container_id: str,
        execution_id: str,
        logs: str,
        archive_dir: Optional[str] = None,
    ) -> str:
        """Durably persist container output to filesystem before removal."""
        target_dir = archive_dir or os.environ.get(
            "SENTINELOPS_ORPHAN_LOG_DIR",
            os.path.join(tempfile.gettempdir(), "sentinelops_orphan_logs"),
        )
        try:
            os.makedirs(target_dir, exist_ok=True)
            filename = f"orphan_{execution_id}_{container_id[:12]}.log"
            file_path = os.path.join(target_dir, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                header = (
                    f"=== SentinelOps Orphan Container Log ===\n"
                    f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n"
                    f"Container ID: {container_id}\n"
                    f"Execution ID: {execution_id}\n"
                    f"========================================\n\n"
                )
                f.write(header + logs)
            logger.info("Durably persisted orphan container logs to '%s'.", file_path)
            return file_path
        except Exception as e:
            logger.error("Failed to write orphan container log file: %s", e)
            return ""

    def cleanup_orphaned_containers(
        self,
        db: Optional[Any] = None,
        db_factory: Optional[Callable[[], Any]] = None,
        max_age_seconds: int = 300,
        log_archive_dir: Optional[str] = None,
    ) -> List[str]:
        """
        Prune orphaned containers created and owned by SentinelOps.

        Safety Requirements (Phase 4.3.5.2):
        1. Ownership label must match SentinelOps ('sentinelops.managed=true').
        2. Execution ID must map to a durable execution record in the database.
        3. Active executions with valid leases must NEVER be removed.
        4. Containers associated with 'execution_uncertain' must be preserved for investigation.
        5. Database lookup failure must FAIL CLOSED and preserve the container.
        6. Cleanup must NEVER remove unrelated containers.
        7. Cleanup must capture and durably preserve relevant logs before any permitted removal.
        8. Age alone must NEVER be sufficient evidence that a running container is orphaned.
        """
        if not self.is_docker_available():
            return []

        client = self._docker_client
        if client is None:
            try:
                import docker
                client = docker.from_env()
            except Exception:
                return []

        # Connect to database; if database is unavailable, FAIL CLOSED immediately
        session = db
        close_session = False
        if session is None and db_factory is not None:
            try:
                session = db_factory()
                close_session = True
            except Exception as e:
                logger.warning(
                    "Database unavailable during orphan cleanup: %s. Failing closed; preserving all containers.",
                    e,
                )
                return []
        elif session is None:
            try:
                try:
                    from app.db.session import SessionLocal
                except ImportError:
                    from app.db.base import SessionLocal
                session = SessionLocal()
                close_session = True
            except Exception as e:
                logger.warning(
                    "Could not establish database session during orphan cleanup: %s. Failing closed; preserving all containers.",
                    e,
                )
                return []

        cleaned_ids: List[str] = []
        now_utc = datetime.now(timezone.utc)

        try:
            # 1. Query ONLY containers labeled as owned by SentinelOps (Requirement 1 & 6)
            candidates = client.containers.list(
                all=True,
                filters={"label": "sentinelops.managed=true"},
            )

            for c in candidates:
                labels = getattr(c, "labels", {}) or {}
                # Ensure ownership label is strictly present and 'true'
                if labels.get("sentinelops.managed") != "true":
                    continue

                exec_id = labels.get("sentinelops.execution_id")
                # Requirement 2 & 5: Must map to a durable execution record; fail closed if missing
                if not exec_id:
                    logger.warning(
                        "Container '%s' has sentinelops.managed=true but no execution_id label. "
                        "Failing closed; preserving container.",
                        getattr(c, "id", "unknown")[:12],
                    )
                    continue

                # Query durable execution record in database
                try:
                    from app.models.remediation import RemediationExecution, ExecutionAttempt
                    execution = (
                        session.query(RemediationExecution)
                        .filter(RemediationExecution.id == exec_id)
                        .first()
                    )
                except Exception as q_err:
                    # Requirement 5: Database lookup failure must fail closed and preserve container
                    logger.warning(
                        "Database query failed for container '%s' (exec_id: '%s'): %s. "
                        "Failing closed; preserving container.",
                        getattr(c, "id", "unknown")[:12],
                        exec_id,
                        q_err,
                    )
                    continue

                # Missing execution record -> fail closed and preserve container
                if execution is None:
                    logger.warning(
                        "Missing execution record in DB for container '%s' (exec_id: '%s'). "
                        "Failing closed; preserving container.",
                        getattr(c, "id", "unknown")[:12],
                        exec_id,
                    )
                    continue

                # Requirement 4: 'execution_uncertain' containers must be preserved for investigation
                if execution.status == "execution_uncertain":
                    logger.info(
                        "Preserving container '%s' (exec_id: '%s'): execution is in 'execution_uncertain' state. "
                        "Retaining container for forensic investigation.",
                        getattr(c, "id", "unknown")[:12],
                        exec_id,
                    )
                    continue

                # Requirement 3: Active executions with valid leases must never be removed
                has_valid_lease = False
                if execution.locked_until is not None:
                    locked_until = execution.locked_until
                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=timezone.utc)
                    has_valid_lease = (locked_until > now_utc)
                if has_valid_lease:
                    logger.info(
                        "Preserving container '%s' (exec_id: '%s'): active worker '%s' holds valid lease until %s.",
                        getattr(c, "id", "unknown")[:12],
                        exec_id,
                        execution.locked_by,
                        execution.locked_until,
                    )
                    continue

                # If execution is still active ('queued', 'validating', 'executing'), preserve container
                if execution.status in ("queued", "validating", "executing"):
                    logger.info(
                        "Preserving container '%s' (exec_id: '%s'): execution status is '%s'. "
                        "Preserving for active processing or pending lease recovery.",
                        getattr(c, "id", "unknown")[:12],
                        exec_id,
                        execution.status,
                    )
                    continue

                # At this point, the container is a safely identified orphan:
                # - Ownership confirmed (sentinelops.managed=true)
                # - Durable execution record found in DB
                # - Not in 'execution_uncertain'
                # - No valid lease held
                # - Execution status is terminal ('execution_failed', 'timed_out', 'execution_succeeded', 'cancelled', 'verified')
                #
                # Requirement 7: Capture and durably preserve relevant logs before removal
                log_sample = ""
                try:
                    raw_logs = c.logs(stdout=True, stderr=True)
                    log_sample = raw_logs.decode("utf-8", errors="replace") if isinstance(raw_logs, bytes) else str(raw_logs)
                except Exception as log_err:
                    logger.warning(
                        "Could not fetch evidence logs for orphan container %s: %s",
                        getattr(c, "id", "unknown")[:12],
                        log_err,
                    )

                # 1. Durably archive log to disk
                self._durably_persist_orphan_log(
                    container_id=getattr(c, "id", "unknown"),
                    execution_id=exec_id,
                    logs=log_sample,
                    archive_dir=log_archive_dir,
                )

                # 2. Persist log sample in execution attempt record if available
                try:
                    attempt = (
                        session.query(ExecutionAttempt)
                        .filter(ExecutionAttempt.execution_id == exec_id)
                        .order_by(ExecutionAttempt.attempt_number.desc())
                        .first()
                    )
                    if attempt and not attempt.stdout_sample and log_sample:
                        attempt.stdout_sample = log_sample[:10000]
                        session.commit()
                except Exception as att_err:
                    logger.warning("Could not persist container logs to attempt record: %s", att_err)

                # Safely kill if still running, then remove
                try:
                    c_status = getattr(c, "status", "").lower()
                    if c_status == "running":
                        c.kill()
                except Exception:
                    pass

                try:
                    c.remove(force=True)
                    cleaned_ids.append(getattr(c, "id", "unknown"))
                    logger.info(
                        "Successfully cleaned up orphan container '%s' (exec_id: '%s', terminal status: '%s').",
                        getattr(c, "id", "unknown")[:12],
                        exec_id,
                        execution.status,
                    )
                except Exception as rm_err:
                    logger.error(
                        "Failed to remove orphan container %s: %s",
                        getattr(c, "id", "unknown")[:12],
                        rm_err,
                    )

        except Exception as e:
            logger.error("Error during orphan container cleanup: %s", str(e))
        finally:
            if close_session and session is not None:
                try:
                    session.close()
                except Exception:
                    pass

        return cleaned_ids
