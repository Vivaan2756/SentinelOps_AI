"""Comprehensive Tests for Order API Demo Recovery Authentication (Render Integration).

Validates:
1. Authorized Order API demo recovery sends X-Demo-Token header.
2. Missing worker credential fails safely without pretending recovery succeeded.
3. Generic HTTP recovery (execute_http_recovery) cannot access the demo credential.
4. Other services cannot access the demo credential (service binding enforcement).
5. Other action IDs cannot access the demo credential.
6. Health checks and post-execution verification never receive the token.
7. Existing approval immutability and signed manifest checks continue to work.
8. Execution results, output data, and logs never contain the token.
9. End-to-end worker execution pipeline integration with mock HTTP recovery.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from typing import Any, Dict, Optional, Set, Tuple
from unittest.mock import MagicMock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx
import pytest
from sqlalchemy.orm import Session

from app.core.manifest_crypto import (
    ExecutionManifest,
    compute_parameters_digest,
    sign_manifest,
)
from app.core.rfc8785 import canonicalize
from app.execution.exceptions import (
    BrokerSecurityViolation,
    PreconditionFailedError,
    SecurityConfigurationError,
)
from app.execution.manager import RemediationExecutionManager
from app.execution.manifest_signer import generate_and_sign_execution_manifest
from app.execution.public_keys import BrokerPublicKeyRegistry
from app.execution.runner import ExecutionResult
from app.execution.runners.http_recovery import (
    ExecutionAuthorizationError,
    IsolatedHttpRecoveryRunner,
)
from app.execution.state_machine import ExecutionState
from app.execution.worker import DurableExecutionWorker
from app.models.incident import Incident
from app.models.remediation import PolicyDecision, RemediationApproval, RemediationExecution
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.registry import ActionRegistry


DEMO_TEST_TOKEN = "test-worker-secret-token-xyz987"


@pytest.fixture
def crypto_env():
    """Generates an Ed25519 signing keypair and public key registry."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    key_id = "test-auth-key-1"

    pub_reg = BrokerPublicKeyRegistry({
        key_id: {
            "public_key": pub_b64,
            "status": "active",
        }
    })

    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode("ascii")
    os.environ["SENTINELOPS_MANIFEST_PRIVATE_KEY"] = priv_b64
    os.environ["SENTINELOPS_MANIFEST_KEY_ID"] = key_id

    return {
        "priv": priv,
        "pub_reg": pub_reg,
        "key_id": key_id,
        "priv_b64": priv_b64,
    }


@pytest.fixture
def order_api_service(db_session: Session) -> Dict[str, Any]:
    """Create test workspace, user, and registered order_api demo service."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Demo Auth Workspace",
        slug=f"demo-auth-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws)

    engineer = User(
        id=str(uuid.uuid4()),
        email=f"sre_{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Lead SRE",
        hashed_password="hashed_test_password",
    )
    db_session.add(engineer)

    membership = WorkspaceMembership(
        workspace_id=ws.id,
        user_id=engineer.id,
        role="engineer",
    )
    db_session.add(membership)

    service = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        demo_integration="order_api",
        recovery_endpoint="/demo/restore",
        recovery_method="POST",
        recovery_enabled=True,
        is_active=True,
    )
    db_session.add(service)

    incident = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=service.id,
        title="Simulated DB pool timeout on Order API",
        severity="high",
        status="awaiting_approval",
        trigger="error_budget_burn",
    )
    db_session.add(incident)

    now_utc = datetime.now(timezone.utc)
    decision = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Demo recovery requires approval",
        policy_version="v1.0",
        validated_parameters={"service_id": service.id},
    )
    db_session.add(decision)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=incident.id,
        policy_decision_id=decision.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        validated_parameters={"service_id": service.id},
        risk_level="medium",
        approval_status="approved",
        requested_by=engineer.id,
        requested_at=now_utc - timedelta(minutes=5),
        reviewed_by=engineer.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(approval)
    db_session.commit()

    return {
        "workspace": ws,
        "engineer": engineer,
        "service": service,
        "incident": incident,
        "decision": decision,
        "approval": approval,
    }


def _create_signed_manifest(
    crypto: Dict[str, Any],
    service: Service,
    action_id: str = "restore_order_api_demo",
    authorized_path: str = "/demo/restore",
    parameters: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], str]:
    """Helper to generate and sign an ExecutionManifest dictionary."""
    now = int(datetime.now(timezone.utc).timestamp())
    if parameters is not None:
        params = parameters
    elif action_id == "restore_order_api_demo":
        params = {"service_id": service.id}
    else:
        params = {}
    digest = compute_parameters_digest(params)

    # Parse host/port from health check URL
    import urllib.parse
    parsed = urllib.parse.urlparse(service.health_check_url)

    manifest_obj = ExecutionManifest(
        manifest_version="1.0",
        key_id=crypto["key_id"],
        issuer="sentinelops.control-plane",
        audience="sentinelops.execution",
        environment="development",
        manifest_id=str(uuid.uuid4()),
        execution_id=str(uuid.uuid4()),
        approval_id=str(uuid.uuid4()),
        approval_reference=f"appr-{uuid.uuid4().hex[:6]}:v1",
        workspace_id=service.workspace_id,
        service_id=service.id,
        action_id=action_id,
        authorized_scheme=parsed.scheme or "http",
        authorized_hostname=parsed.hostname or "127.0.0.1",
        authorized_port=parsed.port or (443 if parsed.scheme == "https" else 80),
        authorized_path=authorized_path,
        parameters_sha256=digest,
        issued_at=now,
        expires_at=now + 60,
    )

    canonical_bytes = canonicalize(manifest_obj.model_dump())
    sig_raw = crypto["priv"].sign(canonical_bytes)
    sig_b64 = base64.urlsafe_b64encode(sig_raw).decode("ascii").rstrip("=")
    return manifest_obj.model_dump(), sig_b64


# ============================================================================
# 1. Authorized Order API Demo Recovery Sends X-Demo-Token
# ============================================================================
def test_authorized_demo_recovery_sends_x_demo_token(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """1. Prove authorized restore_order_api_demo attaches X-Demo-Token header."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: str(sid) == str(service.id),
    )

    manifest, sig = _create_signed_manifest(crypto_env, service, action_id="restore_order_api_demo")

    captured_headers: Dict[str, str] = {}

    def mock_post(url, *args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers") or {}
        return httpx.Response(
            status_code=200,
            json={"status": "restored", "failure_active": False},
            request=httpx.Request("POST", str(url)),
        )

    with patch("httpx.Client.post", side_effect=mock_post):
        result = runner.execute(
            action_id="restore_order_api_demo",
            parameters={"service_id": service.id},
            target_url="http://127.0.0.1:8001/demo/restore",
            environment="development",
            execution_id=manifest["execution_id"],
            authorization_manifest=manifest,
            manifest_signature=sig,
        )

    assert result.exit_code == 0
    assert captured_headers.get("X-Demo-Token") == DEMO_TEST_TOKEN


# ============================================================================
# 2. Missing Worker Credential Fails Safely
# ============================================================================
def test_missing_worker_credential_fails_safely(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """2. Prove missing ORDER_API_DEMO_ADMIN_TOKEN fails closed without pretending success."""
    monkeypatch.delenv("ORDER_API_DEMO_ADMIN_TOKEN", raising=False)
    service = order_api_service["service"]

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: str(sid) == str(service.id),
    )

    manifest, sig = _create_signed_manifest(crypto_env, service, action_id="restore_order_api_demo")

    post_called = False

    def mock_post(*args, **kwargs):
        nonlocal post_called
        post_called = True
        return httpx.Response(status_code=200, request=httpx.Request("POST", "http://test"))

    with patch("httpx.Client.post", side_effect=mock_post):
        result = runner.execute(
            action_id="restore_order_api_demo",
            parameters={"service_id": service.id},
            target_url="http://127.0.0.1:8001/demo/restore",
            environment="development",
            execution_id=manifest["execution_id"],
            authorization_manifest=manifest,
            manifest_signature=sig,
        )

    # Must fail closed: exit_code 1, post NEVER called
    assert result.exit_code == 1
    assert result.error_category == "missing_credential"
    assert "ORDER_API_DEMO_ADMIN_TOKEN" in result.error_message
    assert post_called is False


# ============================================================================
# 3. Generic HTTP Recovery Cannot Access Demo Credential
# ============================================================================
def test_generic_http_recovery_cannot_access_demo_credential(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """3. Prove execute_http_recovery never attaches or accesses the demo credential."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: True,
    )

    params = {"service_id": service.id, "recovery_path": "/demo/restore"}
    manifest, sig = _create_signed_manifest(
        crypto_env,
        service,
        action_id="execute_http_recovery",
        authorized_path="/demo/restore",
        parameters=params,
    )

    captured_headers: Dict[str, str] = {}

    def mock_post(url, *args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers") or {}
        return httpx.Response(status_code=200, json={"status": "ok"}, request=httpx.Request("POST", str(url)))

    with patch("httpx.Client.post", side_effect=mock_post):
        result = runner.execute(
            action_id="execute_http_recovery",
            parameters=params,
            target_url="http://127.0.0.1:8001/demo/restore",
            environment="development",
            execution_id=manifest["execution_id"],
            authorization_manifest=manifest,
            manifest_signature=sig,
        )

    assert result.exit_code == 0
    # X-Demo-Token MUST NOT be present in generic recovery request
    assert "X-Demo-Token" not in captured_headers
    assert captured_headers.get("X-Demo-Token") is None


# ============================================================================
# 4. Other Services Cannot Access Demo Credential
# ============================================================================
def test_other_services_cannot_access_demo_credential(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """4. Prove that a service not registered as order_api cannot receive credentials."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    # Authorizer strictly rejects this service ID
    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: False,  # Not authorized
    )

    manifest, sig = _create_signed_manifest(crypto_env, service, action_id="restore_order_api_demo")

    post_called = False

    def mock_post(*args, **kwargs):
        nonlocal post_called
        post_called = True
        return httpx.Response(status_code=200, request=httpx.Request("POST", "http://test"))

    with patch("httpx.Client.post", side_effect=mock_post):
        result = runner.execute(
            action_id="restore_order_api_demo",
            parameters={"service_id": service.id},
            target_url="http://127.0.0.1:8001/demo/restore",
            environment="development",
            execution_id=manifest["execution_id"],
            authorization_manifest=manifest,
            manifest_signature=sig,
        )

    # Must fail closed: authorization denied, post NEVER called
    assert result.exit_code == 1
    assert result.error_category == "authorization_denied"
    assert "not an authorized order_api demo service" in result.error_message
    assert post_called is False


# ============================================================================
# 5. Other Action IDs Cannot Access Demo Credential
# ============================================================================
def test_other_action_ids_cannot_access_demo_credential(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """5. Prove actions other than restore_order_api_demo cannot access demo credential."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: True,
    )

    # inspect_service_health
    manifest, sig = _create_signed_manifest(
        crypto_env,
        service,
        action_id="inspect_service_health",
        authorized_path="/health",
        parameters={},
    )

    captured_headers: Dict[str, str] = {}

    def mock_get(url, *args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers") or {}
        return httpx.Response(status_code=200, text="healthy", request=httpx.Request("GET", str(url)))

    with patch("httpx.Client.get", side_effect=mock_get):
        result = runner.execute(
            action_id="inspect_service_health",
            parameters={},
            target_url="http://127.0.0.1:8001/health",
            environment="development",
            execution_id=manifest["execution_id"],
            authorization_manifest=manifest,
            manifest_signature=sig,
        )

    assert result.exit_code == 0
    assert "X-Demo-Token" not in captured_headers


# ============================================================================
# 6. Verification Runner Never Receives or Injects Token
# ============================================================================
def test_verification_runner_never_receives_token(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """6. Prove the independent verification runner (allow_unauthenticated_probes=True) never sends credentials."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    # Verification runner instance
    verification_runner = IsolatedHttpRecoveryRunner(
        public_key_registry=crypto_env["pub_reg"],
        environment="development",
        allow_unauthenticated_probes=True,
    )

    # Headers resolution directly returns empty dict
    dummy_manifest = ExecutionManifest(
        manifest_version="1.0",
        key_id=crypto_env["key_id"],
        issuer="sentinelops.control-plane",
        audience="sentinelops.execution",
        environment="development",
        manifest_id=str(uuid.uuid4()),
        execution_id=str(uuid.uuid4()),
        approval_id=str(uuid.uuid4()),
        approval_reference="ref-1",
        workspace_id=service.workspace_id,
        service_id=service.id,
        action_id="restore_order_api_demo",
        authorized_scheme="http",
        authorized_hostname="127.0.0.1",
        authorized_port=8001,
        authorized_path="/demo/restore",
        parameters_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        issued_at=int(datetime.now(timezone.utc).timestamp()),
        expires_at=int(datetime.now(timezone.utc).timestamp()) + 60,
    )

    headers = verification_runner._resolve_demo_recovery_headers(
        action_id="restore_order_api_demo",
        manifest=dummy_manifest,
    )
    assert headers == {}


# ============================================================================
# 7. Existing Approval Immutability & Signed Manifest Checks Intact
# ============================================================================
def test_manifest_authorization_mismatch_blocks_credential_injection(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
):
    """7. Prove manifest destination/action mismatch rejects execution before socket dispatch."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: True,
    )

    # Manifest signs /other/path instead of /demo/restore
    manifest, sig = _create_signed_manifest(
        crypto_env,
        service,
        action_id="restore_order_api_demo",
        authorized_path="/other/path",
        parameters={"service_id": service.id},
    )

    with pytest.raises((ExecutionAuthorizationError, BrokerSecurityViolation)):
        runner.execute(
            action_id="restore_order_api_demo",
            parameters={"service_id": service.id},
            target_url="http://127.0.0.1:8001/demo/restore",
            environment="development",
            execution_id=manifest["execution_id"],
            authorization_manifest=manifest,
            manifest_signature=sig,
        )


# ============================================================================
# 8. Execution Results and Logs Never Contain the Token
# ============================================================================
def test_execution_results_and_logs_never_contain_token(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    monkeypatch,
    caplog,
):
    """8. Prove that neither ExecutionResult nor worker logs leak the secret token."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    service = order_api_service["service"]

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
        demo_service_authorizer=lambda sid: True,
    )

    manifest, sig = _create_signed_manifest(crypto_env, service, action_id="restore_order_api_demo")

    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = httpx.Response(
            status_code=200,
            json={"status": "restored", "failure_active": False},
            request=httpx.Request("POST", "http://127.0.0.1:8001/demo/restore"),
        )
        with caplog.at_level(logging.DEBUG):
            result = runner.execute(
                action_id="restore_order_api_demo",
                parameters={"service_id": service.id},
                target_url="http://127.0.0.1:8001/demo/restore",
                environment="development",
                execution_id=manifest["execution_id"],
                authorization_manifest=manifest,
                manifest_signature=sig,
            )

    # ExecutionResult checks
    assert result.exit_code == 0
    assert DEMO_TEST_TOKEN not in (result.stdout or "")
    assert DEMO_TEST_TOKEN not in (result.stderr or "")
    assert DEMO_TEST_TOKEN not in (result.error_message or "")
    assert DEMO_TEST_TOKEN not in json.dumps(result.output_data or {})

    # Log records checks
    for record in caplog.records:
        assert DEMO_TEST_TOKEN not in record.getMessage()


# ============================================================================
# 9. Full Worker Execution Pipeline Integration Test
# ============================================================================
def test_worker_pipeline_executes_authenticated_demo_recovery(
    crypto_env: Dict[str, Any],
    order_api_service: Dict[str, Any],
    db_session: Session,
    monkeypatch,
):
    """9. Prove DurableExecutionWorker executes approved restore_order_api_demo with authentication."""
    monkeypatch.setenv("ORDER_API_DEMO_ADMIN_TOKEN", DEMO_TEST_TOKEN)
    env = order_api_service
    service = env["service"]

    # Create execution record
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec_record.status == ExecutionState.QUEUED.value

    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=crypto_env["pub_reg"],
    )

    worker = DurableExecutionWorker(
        worker_id="test-demo-auth-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
    )

    captured_headers: Dict[str, str] = {}

    def mock_post(url, *args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers") or {}
        return httpx.Response(
            status_code=200,
            json={"status": "restored", "failure_active": False},
            request=httpx.Request("POST", str(url)),
        )

    with patch("httpx.Client.post", side_effect=mock_post):
        claimed_id = worker.run_once(execution_id=exec_record.id)

    assert claimed_id == exec_record.id
    db_session.refresh(exec_record)
    assert exec_record.status in (
        ExecutionState.EXECUTION_SUCCEEDED.value,
        ExecutionState.VERIFIED.value,
        ExecutionState.VERIFICATION_PENDING.value,
    )
    # Proves the worker injected the token through to the mock transport
    assert captured_headers.get("X-Demo-Token") == DEMO_TEST_TOKEN
