"""Tests for Generic External Service HTTP Recovery (Phase 1 / P0.2).

Proves that registered external services can configure and execute generic HTTP recovery:
1. Order API demo recovery continues to work.
2. Differently named registered services can use generic HTTP recovery.
3. The configured recovery endpoint is selected as the authoritative target.
4. Missing recovery configuration is rejected.
5. Unsupported methods are rejected (strictly POST only).
6. A service cannot use another service's recovery configuration.
7. Approved execution target cannot be overridden by client parameters.
8. Existing Option C signing and execution flow remains intact.
9. Existing human approval requirements remain intact.
10. Existing idempotency behavior is preserved.
"""

import base64
import copy
import hashlib
import json
import time
from unittest.mock import patch
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import httpx

from app.core.manifest_crypto import compute_parameters_digest
from app.core.rfc8785 import canonicalize
from app.execution.actions import validate_http_recovery_preconditions, handle_http_recovery
from app.execution.exceptions import PreconditionFailedError
from app.execution.manifest_signer import (
    generate_and_sign_execution_manifest,
    resolve_action_recovery_path,
    ManifestSigningError,
)
from app.execution.public_keys import BrokerPublicKeyRegistry
from app.execution.runners.http_recovery import (
    ExecutionAuthorizationError,
    IsolatedHttpRecoveryRunner,
)
from app.models.remediation import RemediationApproval, RemediationExecution
from app.models.service import Service
from app.models.workspace import Workspace
from app.remediation.registry import ActionRegistry
from app.remediation.playbook_service import PlaybookService
from app.remediation.policy import PolicyEngine


@pytest.fixture
def crypto_keys():
    """Generates an Ed25519 keypair and registers public key with BrokerPublicKeyRegistry."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    key_id = "test-generic-key-1"
    pub_registry = BrokerPublicKeyRegistry({
        key_id: {
            "public_key": pub_b64,
            "status": "active",
        }
    })
    return priv, pub_registry, key_id


@pytest.fixture
def generic_service(db_session: Session, auth_context: dict) -> Service:
    """Creates a custom registered external service with configured recovery endpoint."""
    ws = auth_context["workspace"]
    svc = Service(
        workspace_id=ws.id,
        name="Customer Orders Microservice",
        environment="development",
        health_check_url="http://127.0.0.1:9000/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
        demo_integration=None,
        recovery_endpoint="/admin/recovery/reset",
        recovery_method="POST",
        recovery_enabled=True,
    )
    db_session.add(svc)
    db_session.commit()
    db_session.refresh(svc)
    return svc


# ----------------------------------------------------------------------------
# 1. Order API Recovery Still Works
# ----------------------------------------------------------------------------
def test_order_api_recovery_still_works(client: TestClient, db_session: Session, auth_context: dict):
    """1. Verify Order API demo recovery continues to function without regression."""
    ws = auth_context["workspace"]
    headers = auth_context["headers"]

    # Provision demo Order API service
    demo_payload = {
        "workspace_id": ws.id,
        "name": "Order API Demo",
        "health_check_url": "http://127.0.0.1:8001/health",
        "environment": "development",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
        "demo_integration": "order_api",
    }
    res = client.post("/api/v1/services/provision-demo", json=demo_payload, headers=headers)
    assert res.status_code == 201
    svc_data = res.json()
    assert svc_data["demo_integration"] == "order_api"

    # Check capabilities include restore_order_api_demo (Order API baseline)
    res_caps = client.get(f"/api/v1/services/{svc_data['id']}/capabilities?workspace_id={ws.id}", headers=headers)
    assert res_caps.status_code == 200
    caps = {c["action_id"]: c for c in res_caps.json()["capabilities"]}

    assert caps["restore_order_api_demo"]["is_compatible"] is True
    assert caps["restore_order_api_demo"]["is_executable"] is True

    # Validate that restore_order_api_demo resolves path to /demo/restore
    order_svc = db_session.query(Service).filter(Service.id == svc_data["id"]).first()
    assert order_svc is not None
    resolved_path = resolve_action_recovery_path("restore_order_api_demo", order_svc)
    assert resolved_path == "/demo/restore"


# ----------------------------------------------------------------------------
# 2. Differently Named Service Uses Generic HTTP Recovery
# ----------------------------------------------------------------------------
def test_differently_named_service_generic_recovery(
    client: TestClient, db_session: Session, auth_context: dict, generic_service: Service
):
    """2. Differently named registered service can discover and use generic HTTP recovery."""
    ws = auth_context["workspace"]
    headers = auth_context["headers"]

    # Capability discovery evaluates execute_http_recovery as fully compatible and executable
    res_caps = client.get(
        f"/api/v1/services/{generic_service.id}/capabilities?workspace_id={ws.id}",
        headers=headers,
    )
    assert res_caps.status_code == 200
    caps = {c["action_id"]: c for c in res_caps.json()["capabilities"]}

    # Legacy demo actions MUST be strictly incompatible for generic service
    assert caps["restore_order_api_demo"]["is_compatible"] is False
    assert caps["restart_order_api"]["is_compatible"] is False

    # Generic HTTP recovery MUST be compatible and executable
    http_cap = caps["execute_http_recovery"]
    assert http_cap["is_compatible"] is True
    assert http_cap["is_executable"] is True
    assert http_cap["approval_required"] is True


# ----------------------------------------------------------------------------
# 3. Configured Recovery Endpoint is Actually Selected
# ----------------------------------------------------------------------------
def test_configured_recovery_endpoint_is_selected(generic_service: Service):
    """3. Verify the service's configured recovery endpoint (/admin/recovery/reset) is selected."""
    resolved_path = resolve_action_recovery_path(
        action_id="execute_http_recovery",
        service=generic_service,
        validated_parameters={"service_id": generic_service.id},
    )
    assert resolved_path == "/admin/recovery/reset"

    derived_url = validate_http_recovery_preconditions(
        service=generic_service,
        parameters={"service_id": generic_service.id},
    )
    assert derived_url == "http://127.0.0.1:9000/admin/recovery/reset"


# ----------------------------------------------------------------------------
# 4. Missing Recovery Configuration is Rejected
# ----------------------------------------------------------------------------
def test_missing_recovery_configuration_rejected(db_session: Session, auth_context: dict):
    """4. Service with missing recovery configuration is rejected for HTTP recovery."""
    ws = auth_context["workspace"]
    unconfigured_svc = Service(
        workspace_id=ws.id,
        name="Telemetry Consumer",
        environment="development",
        health_check_url="http://127.0.0.1:9002/health",
        monitoring_method="builtin",
        execution_policy="approval_required",
        demo_integration=None,
        recovery_endpoint=None,
        recovery_enabled=False,
    )
    db_session.add(unconfigured_svc)
    db_session.commit()

    # Precondition validation must fail closed
    with pytest.raises(PreconditionFailedError) as exc_info:
        validate_http_recovery_preconditions(
            service=unconfigured_svc,
            parameters={"service_id": unconfigured_svc.id},
        )
    assert "no authorized recovery endpoint configured" in str(exc_info.value)


# ----------------------------------------------------------------------------
# 5. Unsupported Methods are Rejected (Only POST Supported)
# ----------------------------------------------------------------------------
def test_unsupported_methods_rejected(db_session: Session, auth_context: dict):
    """5. Reject services configured with unsupported HTTP methods (e.g. GET or DELETE)."""
    ws = auth_context["workspace"]
    bad_method_svc = Service(
        workspace_id=ws.id,
        name="Bad Method Microservice",
        environment="development",
        health_check_url="http://127.0.0.1:9003/health",
        monitoring_method="builtin",
        execution_policy="approval_required",
        demo_integration=None,
        recovery_endpoint="/admin/reset",
        recovery_method="DELETE",  # Unsupported method
        recovery_enabled=True,
    )
    db_session.add(bad_method_svc)
    db_session.commit()

    with pytest.raises(PreconditionFailedError) as exc_info:
        validate_http_recovery_preconditions(
            service=bad_method_svc,
            parameters={"service_id": bad_method_svc.id},
        )
    assert "Unsupported recovery method 'DELETE'" in str(exc_info.value)


# ----------------------------------------------------------------------------
# 6. Service Cannot Use Another Service's Recovery Configuration
# ----------------------------------------------------------------------------
def test_cross_service_recovery_configuration_rejected(
    db_session: Session, auth_context: dict, generic_service: Service
):
    """6. Prevent Service A from executing recovery using Service B's identity or parameters."""
    ws = auth_context["workspace"]
    other_svc = Service(
        workspace_id=ws.id,
        name="Billing Service",
        environment="development",
        health_check_url="http://127.0.0.1:9005/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
        demo_integration=None,
        recovery_endpoint="/admin/restart",
        recovery_method="POST",
        recovery_enabled=True,
    )
    db_session.add(other_svc)
    db_session.commit()

    # Precondition validator must reject parameter service_id mismatch with target service
    mismatched_params = {
        "service_id": str(other_svc.id),
        "recovery_path": generic_service.recovery_endpoint,
    }
    with pytest.raises(PreconditionFailedError) as exc_info:
        validate_http_recovery_preconditions(
            service=generic_service,
            parameters=mismatched_params,
        )
    assert "Cross-service target mismatch" in str(exc_info.value)

    # Manifest signer must reject parameter service_id mismatch
    with pytest.raises(ManifestSigningError) as exc_signer:
        resolve_action_recovery_path(
            action_id="execute_http_recovery",
            service=generic_service,
            validated_parameters=mismatched_params,
        )
    assert "Cross-service parameter mismatch" in str(exc_signer.value)

    # PolicyEngine must reject cross-workspace service access
    foreign_ws = Workspace(name="Foreign Workspace", slug=f"foreign-ws-{uuid.uuid4().hex[:6]}")
    db_session.add(foreign_ws)
    db_session.commit()

    foreign_svc = Service(
        workspace_id=foreign_ws.id,
        name="Foreign Service",
        environment="development",
        health_check_url="http://127.0.0.1:9006/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
        demo_integration=None,
        recovery_endpoint="/admin/recover",
        recovery_method="POST",
        recovery_enabled=True,
    )
    db_session.add(foreign_svc)
    db_session.commit()

    from app.remediation.policy import PolicyDecisionType
    policy_res = PolicyEngine.evaluate(
        workspace_id=str(ws.id),
        user_role="operator",
        action_id="execute_http_recovery",
        parameters={"service_id": str(foreign_svc.id), "recovery_path": foreign_svc.recovery_endpoint},
        db=db_session,
    )
    assert policy_res.decision == PolicyDecisionType.REJECTED
    assert "Cross-workspace violation" in policy_res.decision_reason


# ----------------------------------------------------------------------------
# 7. Approved Execution Target Cannot Be Overridden
# ----------------------------------------------------------------------------
def test_approved_execution_target_cannot_be_overridden(generic_service: Service):
    """7. Prove client parameters cannot override the service's authorized recovery endpoint."""
    tampered_params = {
        "service_id": generic_service.id,
        "recovery_path": "/malicious/override/endpoint",
    }

    # Manifest path resolution must fail closed
    with pytest.raises(ManifestSigningError) as exc_manifest:
        resolve_action_recovery_path(
            action_id="execute_http_recovery",
            service=generic_service,
            validated_parameters=tampered_params,
        )
    assert "cannot override service authorized recovery endpoint" in str(exc_manifest.value)

    # Precondition validator must also fail closed
    with pytest.raises(PreconditionFailedError) as exc_pre:
        validate_http_recovery_preconditions(
            service=generic_service,
            parameters=tampered_params,
        )
    assert "cannot override authorized service recovery endpoint" in str(exc_pre.value)


# ----------------------------------------------------------------------------
# 8. Existing Option C Signing and Execution Flow Remains Intact
# ----------------------------------------------------------------------------
def test_option_c_signing_and_execution_intact(
    generic_service: Service, crypto_keys: tuple
):
    """8. Full Ed25519 manifest generation, verification, and Option C execution for generic recovery."""
    priv, pub_reg, key_id = crypto_keys
    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=pub_reg,
    )

    exec_id = str(uuid.uuid4())
    params = {
        "service_id": generic_service.id,
        "recovery_path": generic_service.recovery_endpoint,
        "payload": {"action": "reset_state"},
        "expected_status_codes": [200],
        "timeout_seconds": 30,
    }

    # Build canonical manifest
    now = int(time.time())
    appr_id = str(uuid.uuid4())
    manifest_dict = {
        "manifest_version": "1.0",
        "manifest_id": str(uuid.uuid4()),
        "execution_id": exec_id,
        "approval_id": appr_id,
        "approval_reference": f"{appr_id}:1",
        "workspace_id": str(generic_service.workspace_id),
        "service_id": str(generic_service.id),
        "action_id": "execute_http_recovery",
        "environment": "development",
        "issuer": "sentinelops.control-plane",
        "audience": "sentinelops.execution",
        "key_id": key_id,
        "authorized_scheme": "http",
        "authorized_hostname": "127.0.0.1",
        "authorized_port": 9000,
        "authorized_path": generic_service.recovery_endpoint,
        "parameters_sha256": compute_parameters_digest(params),
        "issued_at": now,
        "expires_at": now + 60,
    }

    # Sign manifest
    canonical_bytes = canonicalize(manifest_dict)
    sig_raw = priv.sign(canonical_bytes)
    sig_b64 = base64.urlsafe_b64encode(sig_raw).decode("ascii").rstrip("=")

    # Mock target service HTTP response
    mock_resp = httpx.Response(
        status_code=200,
        json={"status": "recovered", "service": "customer-orders"},
        request=httpx.Request("POST", f"http://127.0.0.1:9000{generic_service.recovery_endpoint}"),
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        res = runner.execute(
            action_id="execute_http_recovery",
            parameters=params,
            execution_id=exec_id,
            target_url=f"http://127.0.0.1:9000{generic_service.recovery_endpoint}",
            environment="development",
            authorization_manifest=manifest_dict,
            manifest_signature=sig_b64,
        )

    assert res.exit_code == 0
    assert res.output_data["status_code"] == 200
    assert res.output_data["response"]["status"] == "recovered"
    mock_post.assert_called_once()


# ----------------------------------------------------------------------------
# 9. Existing Approval Requirements Remain Intact
# ----------------------------------------------------------------------------
def test_approval_requirements_intact(db_session: Session, generic_service: Service):
    """9. Prove that execute_http_recovery mandates human approval and cannot bypass policy."""
    from app.remediation.policy import PolicyDecisionType
    eval_result = PolicyEngine.evaluate(
        workspace_id=str(generic_service.workspace_id),
        user_role="operator",
        action_id="execute_http_recovery",
        parameters={"service_id": str(generic_service.id), "recovery_path": generic_service.recovery_endpoint},
        db=db_session,
    )
    assert eval_result.approval_required is True
    assert eval_result.decision == PolicyDecisionType.APPROVAL_REQUIRED


# ----------------------------------------------------------------------------
# 10. Existing Idempotency Behavior is Preserved
# ----------------------------------------------------------------------------
def test_idempotency_behavior_preserved(db_session: Session, generic_service: Service):
    """10. Prove that generic recovery playbook seeding and association is idempotent."""
    ws_id = generic_service.workspace_id
    svc_id = generic_service.id

    # First call: creates playbook and association
    pb1 = PlaybookService.ensure_generic_http_recovery_playbook(
        db=db_session,
        workspace_id=ws_id,
        service_id=svc_id,
    )
    assert pb1 is not None

    # Second call: returns existing playbook without creating duplicate records
    pb2 = PlaybookService.ensure_generic_http_recovery_playbook(
        db=db_session,
        workspace_id=ws_id,
        service_id=svc_id,
    )
    assert pb2 is not None
    assert pb1.id == pb2.id
