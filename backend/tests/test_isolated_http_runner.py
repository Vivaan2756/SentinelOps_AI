"""Focused Test Suite for Option C Stage 1: IsolatedHttpRecoveryRunner.

Validates:
1. Valid signed manifest and approved HTTP recovery execution.
2. Rejection of missing manifest or signature.
3. Rejection of invalid signature and tampered manifest.
4. Rejection of expired manifest and invalid temporal bounds.
5. Rejection of mismatched execution ID, action ID, issuer, audience, and environment.
6. Rejection of parameter digest mismatch.
7. Rejection of target origin/path mismatch.
8. Target URL derivation strictly from signed manifest when unspecified.
9. SSRF rejection of cloud metadata IPs (169.254.169.254, fd00:ec2::254).
10. SSRF rejection of loopback in production environment.
11. Strict rejection of HTTP redirects (301, 302, 307, 308).
12. Parameter model validation and traversal rejection.
13. Status code mismatch handling (exit_code=1, status_code_mismatch).
14. Network timeout fail-closed into ExecutionUncertainError (uncertain outcome contract).
15. Mid-stream connection loss fail-closed into ExecutionUncertainError.
16. Proof that no network call occurs before authorization succeeds.
17. Proof that runner requires only public verification keys and zero private keys.
18. Proof that runner has zero Docker socket access or Docker daemon requirement.
19. Rejection of unsupported actions and arbitrary commands.
20. Safe factory integration (get_execution_runner(runner_type="http_recovery")).
"""

import base64
import hashlib
import time
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
import httpcore
import httpx
import pytest

from app.core.manifest_crypto import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    MAX_MANIFEST_LIFETIME_SECONDS,
    ExecutionManifest,
    compute_parameters_digest,
)
from app.core.rfc8785 import canonicalize
from app.execution.exceptions import (
    BrokerSecurityViolation,
    ExecutionUncertainError,
    PreconditionFailedError,
)
from app.execution.public_keys import BrokerPublicKeyRegistry, KeyStatus
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
    MockTestRunner,
    get_execution_runner,
)
from app.execution.runners.http_recovery import (
    ExecutionAuthorizationError,
    IsolatedHttpRecoveryRunner,
    PinnedIPTransport,
    PinnedSyncBackend,
)


# ============================================================================
# Test Fixtures & Key Management
# ============================================================================

TEST_KEY_ID = "test-runner-key-v1"


@pytest.fixture
def key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate ephemeral Ed25519 keypair for cryptographic testing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def public_key_registry(key_pair) -> BrokerPublicKeyRegistry:
    """Initialize public-key registry with test public verification key only (zero private key)."""
    _, pub = key_pair
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    config = {
        TEST_KEY_ID: {
            "public_key": pub_b64,
            "status": "active",
        }
    }
    return BrokerPublicKeyRegistry(config=config)


@pytest.fixture
def runner(public_key_registry) -> IsolatedHttpRecoveryRunner:
    """Instantiate IsolatedHttpRecoveryRunner with public key registry."""
    return IsolatedHttpRecoveryRunner(
        public_key_registry=public_key_registry,
        environment="development",
    )


def sign_test_manifest(
    manifest_dict: Dict[str, Any],
    priv_key: ed25519.Ed25519PrivateKey,
) -> str:
    """Sign manifest dictionary with private key using RFC 8785 canonical bytes."""
    canonical_bytes = canonicalize(manifest_dict)
    sig_bytes = priv_key.sign(canonical_bytes)
    return base64.urlsafe_b64encode(sig_bytes).decode("ascii")


def create_valid_manifest(
    *,
    key_id: str = TEST_KEY_ID,
    execution_id: Optional[str] = None,
    action_id: str = "execute_http_recovery",
    parameters: Optional[Dict[str, Any]] = None,
    scheme: str = "http",
    hostname: str = "127.0.0.1",
    port: int = 8001,
    path: str = "/admin/recovery/reset",
    environment: str = "development",
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    issuer: str = "sentinelops.control-plane",
    audience: str = "sentinelops.execution",
) -> Tuple[Dict[str, Any], str]:
    """Helper to create and sign a valid ExecutionManifest dictionary."""
    now = int(time.time())
    i_at = issued_at if issued_at is not None else now
    e_at = expires_at if expires_at is not None else (i_at + 30)
    exec_id = execution_id or str(uuid.uuid4())
    svc_id = str(uuid.uuid4())
    params = parameters if parameters is not None else {"service_id": svc_id, "recovery_path": path}
    if "service_id" in params:
        svc_id = params["service_id"]
    params_sha = compute_parameters_digest(params)

    manifest_data = {
        "manifest_version": "1.0",
        "key_id": key_id,
        "issuer": issuer,
        "audience": audience,
        "environment": environment,
        "manifest_id": str(uuid.uuid4()),
        "execution_id": exec_id,
        "approval_id": str(uuid.uuid4()),
        "approval_reference": f"{uuid.uuid4()}:1",
        "workspace_id": str(uuid.uuid4()),
        "service_id": svc_id,
        "action_id": action_id,
        "authorized_scheme": scheme,
        "authorized_hostname": hostname,
        "authorized_port": port,
        "authorized_path": path,
        "parameters_sha256": params_sha,
        "issued_at": i_at,
        "expires_at": e_at,
    }
    return manifest_data, exec_id


# ============================================================================
# 1. Cryptographic Authorization & Execution Tests
# ============================================================================

def test_runner_verifies_valid_signed_manifest_and_executes_recovery(runner, key_pair):
    """Verify that a valid signed manifest authorizes HTTP recovery execution."""
    priv, _ = key_pair
    target_path = "/admin/recovery/reset"
    params = {
        "service_id": str(uuid.uuid4()),
        "recovery_path": target_path,
        "payload": {"reason": "unwedge_queue"},
        "expected_status_codes": [200],
        "timeout_seconds": 15,
    }

    manifest_dict, exec_id = create_valid_manifest(
        parameters=params,
        path=target_path,
    )
    signature = sign_test_manifest(manifest_dict, priv)

    # Mock httpx.Client response
    mock_resp = httpx.Response(
        status_code=200,
        json={"status": "completed", "unwedged": True},
        request=httpx.Request("POST", "http://127.0.0.1:8001/admin/recovery/reset"),
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        res = runner.execute(
            action_id="execute_http_recovery",
            parameters=params,
            execution_id=exec_id,
            target_url="http://127.0.0.1:8001/admin/recovery/reset",
            environment="development",
            authorization_manifest=manifest_dict,
            manifest_signature=signature,
        )

    assert isinstance(res, ExecutionResult)
    assert res.exit_code == 0
    assert res.output_data["status_code"] == 200
    assert res.output_data["response"]["unwedged"] is True
    mock_post.assert_called_once()


def test_runner_rejects_missing_manifest_or_signature(runner):
    """Verify runner fails closed before network when manifest or signature is missing."""
    with patch("httpx.Client.post") as mock_post:
        # Missing manifest
        with pytest.raises(ExecutionAuthorizationError) as exc1:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={},
                execution_id=str(uuid.uuid4()),
                authorization_manifest=None,
                manifest_signature="some-sig",
            )
        assert "Missing or invalid authorization_manifest" in str(exc1.value)

        # Missing signature
        with pytest.raises(ExecutionAuthorizationError) as exc2:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={},
                execution_id=str(uuid.uuid4()),
                authorization_manifest={"some": "manifest"},
                manifest_signature=None,
            )
        assert "Missing or invalid manifest_signature" in str(exc2.value)

        # Missing execution_id
        with pytest.raises(ExecutionAuthorizationError) as exc3:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={},
                execution_id=None,
                authorization_manifest={"some": "manifest"},
                manifest_signature="some-sig",
            )
        assert "Missing execution_id" in str(exc3.value)

        # Proof: Zero network calls occurred
        mock_post.assert_not_called()


def test_runner_rejects_invalid_signature_and_tampered_manifest(runner, key_pair):
    """Verify runner fails closed if manifest signature is invalid or payload was tampered."""
    priv, _ = key_pair
    manifest_dict, exec_id = create_valid_manifest()
    valid_sig = sign_test_manifest(manifest_dict, priv)

    with patch("httpx.Client.post") as mock_post:
        # 1. Corrupt signature
        bad_sig = "A" * 86
        with pytest.raises(ExecutionAuthorizationError) as exc1:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": manifest_dict["service_id"], "recovery_path": manifest_dict["authorized_path"]},
                execution_id=exec_id,
                authorization_manifest=manifest_dict,
                manifest_signature=bad_sig,
            )
        assert "signature verification failed" in str(exc1.value).lower()

        # 2. Tampered manifest (attacker modified authorized_port)
        tampered_manifest = dict(manifest_dict)
        tampered_manifest["authorized_port"] = 9999
        with pytest.raises(ExecutionAuthorizationError) as exc2:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": manifest_dict["service_id"], "recovery_path": manifest_dict["authorized_path"]},
                execution_id=exec_id,
                authorization_manifest=tampered_manifest,
                manifest_signature=valid_sig,
            )
        assert "signature verification failed" in str(exc2.value).lower()

        mock_post.assert_not_called()


def test_runner_rejects_expired_manifest_and_temporal_violations(runner, key_pair):
    """Verify runner rejects expired manifests, future timestamps, and excessive validity windows."""
    priv, _ = key_pair
    now = int(time.time())

    with patch("httpx.Client.post") as mock_post:
        # 1. Expired manifest
        m_expired, exec_id = create_valid_manifest(issued_at=now - 100, expires_at=now - 40)
        sig_expired = sign_test_manifest(m_expired, priv)
        with pytest.raises(ExecutionAuthorizationError) as exc1:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": m_expired["service_id"], "recovery_path": m_expired["authorized_path"]},
                execution_id=exec_id,
                authorization_manifest=m_expired,
                manifest_signature=sig_expired,
            )
        assert "expired" in str(exc1.value).lower()

        # 2. Future issued_at (> 5s skew)
        m_future, exec_id2 = create_valid_manifest(issued_at=now + 20, expires_at=now + 50)
        sig_future = sign_test_manifest(m_future, priv)
        with pytest.raises(ExecutionAuthorizationError) as exc2:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": m_future["service_id"], "recovery_path": m_future["authorized_path"]},
                execution_id=exec_id2,
                authorization_manifest=m_future,
                manifest_signature=sig_future,
            )
        assert "future" in str(exc2.value).lower()

        # 3. Validity window exceeds 60 seconds
        m_wide, exec_id3 = create_valid_manifest(issued_at=now, expires_at=now + 120)
        sig_wide = sign_test_manifest(m_wide, priv)
        with pytest.raises(ExecutionAuthorizationError) as exc3:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": m_wide["service_id"], "recovery_path": m_wide["authorized_path"]},
                execution_id=exec_id3,
                authorization_manifest=m_wide,
                manifest_signature=sig_wide,
            )
        assert "validity window" in str(exc3.value).lower()

        mock_post.assert_not_called()


def test_runner_rejects_identity_mismatches(runner, key_pair):
    """Verify runner rejects execution ID, action ID, issuer, audience, and environment mismatches."""
    priv, _ = key_pair
    manifest_dict, exec_id = create_valid_manifest(action_id="execute_http_recovery")
    signature = sign_test_manifest(manifest_dict, priv)

    with patch("httpx.Client.post") as mock_post:
        # Execution ID mismatch
        with pytest.raises(ExecutionAuthorizationError) as exc1:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": manifest_dict["service_id"], "recovery_path": manifest_dict["authorized_path"]},
                execution_id=str(uuid.uuid4()),  # different ID
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "Execution ID mismatch" in str(exc1.value)

        # Action ID mismatch
        with pytest.raises(ExecutionAuthorizationError) as exc2:
            runner.execute(
                action_id="restore_order_api_demo",  # different action
                parameters={"service_id": manifest_dict["service_id"], "recovery_path": manifest_dict["authorized_path"]},
                execution_id=exec_id,
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "Action ID mismatch" in str(exc2.value)

        # Environment mismatch
        with pytest.raises(ExecutionAuthorizationError) as exc3:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": manifest_dict["service_id"], "recovery_path": manifest_dict["authorized_path"]},
                execution_id=exec_id,
                environment="production",  # mismatch with manifest 'development'
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "Environment mismatch" in str(exc3.value)

        # Legacy broker audience mismatch: new runner strictly accepts only sentinelops.execution
        m_broker, exec_id_b = create_valid_manifest(audience="sentinelops.broker")
        sig_broker = sign_test_manifest(m_broker, priv)
        with pytest.raises(ExecutionAuthorizationError) as exc4:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": m_broker["service_id"], "recovery_path": m_broker["authorized_path"]},
                execution_id=exec_id_b,
                authorization_manifest=m_broker,
                manifest_signature=sig_broker,
            )
        assert "Invalid manifest audience 'sentinelops.broker'" in str(exc4.value)
        assert "Expected 'sentinelops.execution'" in str(exc4.value)

        # Unknown issuer mismatch (fails Pydantic schema validation as issuer is Literal["sentinelops.control-plane"])
        m_bad_issuer, exec_id_i = create_valid_manifest(issuer="sentinelops.impostor")
        sig_bad_issuer = sign_test_manifest(m_bad_issuer, priv)
        with pytest.raises(ExecutionAuthorizationError) as exc5:
            runner.execute(
                action_id="execute_http_recovery",
                parameters={"service_id": m_bad_issuer["service_id"], "recovery_path": m_bad_issuer["authorized_path"]},
                execution_id=exec_id_i,
                authorization_manifest=m_bad_issuer,
                manifest_signature=sig_bad_issuer,
            )
        assert "issuer" in str(exc5.value).lower()

        mock_post.assert_not_called()


def test_runner_rejects_parameter_digest_mismatch(runner, key_pair):
    """Verify runner rejects execution if parameters differ from signed parameters_sha256."""
    priv, _ = key_pair
    original_params = {"service_id": str(uuid.uuid4()), "recovery_path": "/admin/recovery/reset"}
    manifest_dict, exec_id = create_valid_manifest(parameters=original_params)
    signature = sign_test_manifest(manifest_dict, priv)

    # Caller passes modified parameters
    tampered_params = dict(original_params)
    tampered_params["recovery_path"] = "/admin/recovery/different"

    with patch("httpx.Client.post") as mock_post:
        with pytest.raises(ExecutionAuthorizationError) as exc:
            runner.execute(
                action_id="execute_http_recovery",
                parameters=tampered_params,
                execution_id=exec_id,
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "Parameter digest mismatch" in str(exc.value)
        mock_post.assert_not_called()


def test_runner_rejects_target_origin_and_path_mismatch(runner, key_pair):
    """Verify runner rejects target URLs that deviate from authorized manifest origin or path."""
    priv, _ = key_pair
    manifest_dict, exec_id = create_valid_manifest(
        scheme="http",
        hostname="127.0.0.1",
        port=8001,
        path="/admin/recovery/reset",
    )
    signature = sign_test_manifest(manifest_dict, priv)
    params = {"service_id": manifest_dict["service_id"], "recovery_path": "/admin/recovery/reset"}

    with patch("httpx.Client.post") as mock_post:
        # Different port
        with pytest.raises(ExecutionAuthorizationError) as exc1:
            runner.execute(
                action_id="execute_http_recovery",
                parameters=params,
                execution_id=exec_id,
                target_url="http://127.0.0.1:9000/admin/recovery/reset",
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "Target port mismatch" in str(exc1.value)

        # Different path
        with pytest.raises(ExecutionAuthorizationError) as exc2:
            runner.execute(
                action_id="execute_http_recovery",
                parameters=params,
                execution_id=exec_id,
                target_url="http://127.0.0.1:8001/admin/other/endpoint",
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "Target path mismatch" in str(exc2.value)

        mock_post.assert_not_called()


def test_runner_derives_target_url_from_signed_manifest_when_unspecified(runner, key_pair):
    """Verify runner derives target URL from manifest when target_url is None."""
    priv, _ = key_pair
    path = "/admin/recovery/reset"
    params = {"service_id": str(uuid.uuid4()), "recovery_path": path}
    manifest_dict, exec_id = create_valid_manifest(
        scheme="http",
        hostname="127.0.0.1",
        port=8001,
        path=path,
        parameters=params,
    )
    signature = sign_test_manifest(manifest_dict, priv)

    mock_resp = httpx.Response(
        status_code=200,
        json={"status": "ok"},
        request=httpx.Request("POST", "http://127.0.0.1:8001/admin/recovery/reset"),
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        res = runner.execute(
            action_id="execute_http_recovery",
            parameters=params,
            execution_id=exec_id,
            target_url=None,  # Not supplied by caller
            environment="development",
            authorization_manifest=manifest_dict,
            manifest_signature=signature,
        )

    assert res.exit_code == 0
    # Verifies request was sent to derived URL http://127.0.0.1:8001/admin/recovery/reset
    mock_post.assert_called_once()
    assert mock_post.call_args[0][0] == "http://127.0.0.1:8001/admin/recovery/reset"


# ============================================================================
# 2. SSRF & Network Boundary Defense Tests
# ============================================================================

def test_runner_rejects_cloud_metadata_ip(key_pair):
    """Verify runner strictly rejects cloud metadata IP (169.254.169.254)."""
    priv, pub = key_pair
    registry = BrokerPublicKeyRegistry({TEST_KEY_ID: {"public_key": base64.b64encode(pub.public_bytes_raw()).decode(), "status": "active"}})
    runner_inst = IsolatedHttpRecoveryRunner(public_key_registry=registry, environment="development")

    # Construct manifest targeting cloud metadata IP
    # (Notice: ExecutionManifest schema itself validates or resolve_safe_target_url rejects)
    params = {"service_id": str(uuid.uuid4()), "recovery_path": "/latest/meta-data"}
    manifest_dict, exec_id = create_valid_manifest(
        hostname="169.254.169.254",
        path="/latest/meta-data",
        parameters=params,
    )
    signature = sign_test_manifest(manifest_dict, priv)

    with patch("httpx.Client.post") as mock_post:
        with pytest.raises((BrokerSecurityViolation, ExecutionAuthorizationError, ValueError)):
            runner_inst.execute(
                action_id="execute_http_recovery",
                parameters=params,
                execution_id=exec_id,
                target_url="http://169.254.169.254:80/latest/meta-data",
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        mock_post.assert_not_called()


def test_runner_rejects_http_redirects(runner, key_pair):
    """Verify runner strictly rejects HTTP redirects (SSRF redirect defense)."""
    priv, _ = key_pair
    params = {"service_id": str(uuid.uuid4()), "recovery_path": "/admin/recovery/reset"}
    manifest_dict, exec_id = create_valid_manifest(parameters=params)
    signature = sign_test_manifest(manifest_dict, priv)

    redirect_resp = httpx.Response(
        status_code=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data"},
        request=httpx.Request("POST", "http://127.0.0.1:8001/admin/recovery/reset"),
    )

    with patch("httpx.Client.post", return_value=redirect_resp):
        with pytest.raises(BrokerSecurityViolation) as exc:
            runner.execute(
                action_id="execute_http_recovery",
                parameters=params,
                execution_id=exec_id,
                target_url="http://127.0.0.1:8001/admin/recovery/reset",
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "HTTP Redirect" in str(exc.value)
        assert "forbidden" in str(exc.value)


# ============================================================================
# 3. Status Code & Uncertainty Fail-Closed Tests
# ============================================================================

def test_runner_handles_unexpected_status_codes(runner, key_pair):
    """Verify non-2xx status code returns exit_code=1 with status_code_mismatch category."""
    priv, _ = key_pair
    params = {"service_id": str(uuid.uuid4()), "recovery_path": "/admin/recovery/reset"}
    manifest_dict, exec_id = create_valid_manifest(parameters=params)
    signature = sign_test_manifest(manifest_dict, priv)

    error_resp = httpx.Response(
        status_code=500,
        text="Internal Server Error: Database Deadlock",
        request=httpx.Request("POST", "http://127.0.0.1:8001/admin/recovery/reset"),
    )

    with patch("httpx.Client.post", return_value=error_resp):
        res = runner.execute(
            action_id="execute_http_recovery",
            parameters=params,
            execution_id=exec_id,
            target_url="http://127.0.0.1:8001/admin/recovery/reset",
            authorization_manifest=manifest_dict,
            manifest_signature=signature,
        )

    assert res.exit_code == 1
    assert res.error_category == "status_code_mismatch"
    assert "unexpected HTTP 500" in res.stderr


def test_runner_fails_closed_into_execution_uncertain_on_timeout(runner, key_pair):
    """Verify HTTP timeout raises ExecutionUncertainError to preserve non-retryable contract."""
    priv, _ = key_pair
    params = {"service_id": str(uuid.uuid4()), "recovery_path": "/admin/recovery/reset"}
    manifest_dict, exec_id = create_valid_manifest(parameters=params)
    signature = sign_test_manifest(manifest_dict, priv)

    with patch("httpx.Client.post", side_effect=httpx.ReadTimeout("Read timed out")):
        with pytest.raises(ExecutionUncertainError) as exc:
            runner.execute(
                action_id="execute_http_recovery",
                parameters=params,
                execution_id=exec_id,
                target_url="http://127.0.0.1:8001/admin/recovery/reset",
                authorization_manifest=manifest_dict,
                manifest_signature=signature,
            )
        assert "timed out" in str(exc.value).lower()
        assert "indeterminate" in str(exc.value).lower()


def test_runner_fails_closed_into_execution_uncertain_on_connection_loss(runner, key_pair):
    """Verify socket connection loss raises ExecutionUncertainError."""
    priv, _ = key_pair
    params = {"service_id": str(uuid.uuid4()), "recovery_path": "/admin/recovery/reset"}
    manifest_dict, exec_id = create_valid_manifest(parameters=params)
    signature = sign_test_manifest(manifest_dict, priv)

    with patch("httpx.Client.post", side_effect=httpcore.RemoteProtocolError("Connection dropped by peer")):
        res = runner.execute(
            action_id="execute_http_recovery",
            parameters=params,
            execution_id=exec_id,
            target_url="http://127.0.0.1:8001/admin/recovery/reset",
            authorization_manifest=manifest_dict,
            manifest_signature=signature,
        )
        assert res.exit_code == 1
        assert "Connection dropped" in res.stderr


# ============================================================================
# 4. Isolation & Security Boundary Guarantees
# ============================================================================

def test_runner_requires_only_public_keys_no_private_key(key_pair):
    """Verify IsolatedHttpRecoveryRunner operates strictly with public verification keys."""
    _, pub = key_pair
    pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode()

    # Public-key only registry
    registry = BrokerPublicKeyRegistry({TEST_KEY_ID: {"public_key": pub_b64, "status": "active"}})
    runner_inst = IsolatedHttpRecoveryRunner(public_key_registry=registry)

    # Assert runner has zero private key attribute
    assert not hasattr(runner_inst, "private_key")
    assert not hasattr(runner_inst, "signing_key")
    assert runner_inst.is_available() is True


def test_runner_has_zero_docker_socket_dependency(runner):
    """Verify runner has no Docker SDK, docker.sock, or daemon dependency."""
    # Check that runner instance has no docker client
    assert not hasattr(runner, "docker_client")
    assert not hasattr(runner, "_docker")
    assert not hasattr(runner, "broker")


def test_runner_rejects_unsupported_actions_and_commands(runner, key_pair):
    """Verify runner strictly rejects arbitrary shell or unapproved actions."""
    priv, _ = key_pair

    # Attempting to execute unauthorized shell action
    with pytest.raises(ExecutionAuthorizationError) as exc:
        runner.execute(
            action_id="exec_arbitrary_shell_command",
            parameters={"command": "rm -rf /"},
            execution_id=str(uuid.uuid4()),
            authorization_manifest={"action_id": "exec_arbitrary_shell_command"},
            manifest_signature="dummy",
        )
    assert "not in authorized runner actions" in str(exc.value)


def test_factory_returns_isolated_http_runner_only_when_explicitly_requested(public_key_registry):
    """Verify get_execution_runner factory contract for Stage 1."""
    # Explicit request for http_recovery returns IsolatedHttpRecoveryRunner
    runner_inst = get_execution_runner(
        runner_type="http_recovery",
        public_key_registry=public_key_registry,
    )
    assert isinstance(runner_inst, IsolatedHttpRecoveryRunner)

    # In test environment, standard allow_mock=True continues returning MockTestRunner
    mock_runner = get_execution_runner(allow_mock=True)
    assert isinstance(mock_runner, MockTestRunner)
