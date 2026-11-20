"""Comprehensive Test Suite for Control-Plane Manifest Signing (Phase 2A.1 Stage 4).

Covers:
1. Successful manifest generation and signing during create_execution().
2. Valid Ed25519 signature verified with raw public key.
3. Signature verification roundtrip via app.core.manifest_crypto.verify_manifest().
4. Correct RFC 8785 parameter digest matching compute_parameters_digest().
5. Exact service origin and relative recovery path resolution (/demo/restore, /health, custom).
6. Correct workspace, service, execution, and approval binding in manifest.
7. Expiration strictly within 60s (MAX_MANIFEST_LIFETIME_SECONDS = 60).
8. Missing or malformed private key raises error and fails closed (no execution created).
9. Revoked, expired, rejected approval, or inactive/missing service fails before manifest creation.
10. Manifest persistence across database reload (clean session).
11. Idempotent execution retry returns existing execution without overwriting or regenerating manifest.
12. Signing failure rolls back transaction (zero execution records or events in DB).
13. Historical executions without manifests (authorization_manifest=None) remain readable.
"""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
import uuid
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.manifest_crypto import (
    MAX_MANIFEST_LIFETIME_SECONDS,
    ExecutionManifest,
    compute_parameters_digest,
    normalize_origin_and_path,
    verify_manifest,
)
from app.core.rfc8785 import canonicalize
from app.execution.exceptions import PreconditionFailedError
from app.execution.manager import RemediationExecutionManager
from app.execution.manifest_signer import (
    ManifestSigningError,
    generate_and_sign_execution_manifest,
    load_control_plane_signing_key,
    resolve_action_recovery_path,
)
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionEvent,
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership


TEST_PRIV_KEY_B64 = "/+coTws3RSMT0fao4K5hSCP0dr6lz+NozVmUi2+UT/Q="
TEST_PUB_KEY_B64 = "jE+ftCXOyq0MyvIC9XcYlMGAwFZFmnB93JnFiPke9e8="
TEST_KEY_ID = "test-control-plane-key-1"


@pytest.fixture
def manifest_signing_env(db_session: Session):
    """Fixture providing workspace, users, services, incident, and approvals for manifest signing tests."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Manifest Signing WS",
        slug=f"manifest-ws-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws)

    admin = User(
        id=str(uuid.uuid4()),
        email=f"admin_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Admin Signer",
        hashed_password="pw",
    )
    engineer = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Engineer Signer",
        hashed_password="pw",
    )
    db_session.add_all([admin, engineer])

    m_admin = WorkspaceMembership(workspace_id=ws.id, user_id=admin.id, role="admin")
    m_eng = WorkspaceMembership(workspace_id=ws.id, user_id=engineer.id, role="engineer")
    db_session.add_all([m_admin, m_eng])

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )
    svc_inactive = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Inactive API",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        execution_policy="demo",
        is_active=False,
    )
    db_session.add_all([svc, svc_inactive])

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="Payment Service Latency",
        severity="high",
        status="investigating",
        trigger="high_latency",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Requires human approval",
        policy_version="v2.1",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)

    appr_approved = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v2.1",
        requested_by=engineer.id,
        approval_status="approved",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    appr_pending = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v2.1",
        requested_by=engineer.id,
        approval_status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    appr_rejected = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v2.1",
        requested_by=engineer.id,
        approval_status="rejected",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc),
        rejection_reason="Denied by security policy",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    appr_expired = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v2.1",
        requested_by=engineer.id,
        approval_status="approved",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc) - timedelta(hours=2),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    appr_inactive_svc = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc_inactive.id,
        validated_parameters={"service_id": svc_inactive.id},
        risk_level="medium",
        policy_version="v2.1",
        requested_by=engineer.id,
        approval_status="approved",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add_all([appr_approved, appr_pending, appr_rejected, appr_expired, appr_inactive_svc])
    db_session.commit()

    return {
        "ws": ws,
        "admin": admin,
        "engineer": engineer,
        "svc": svc,
        "svc_inactive": svc_inactive,
        "inc": inc,
        "dec": dec,
        "approval": appr_approved,
        "appr_approved": appr_approved,
        "appr_pending": appr_pending,
        "appr_rejected": appr_rejected,
        "appr_expired": appr_expired,
        "appr_inactive_svc": appr_inactive_svc,
        "ws_id": ws.id,
        "approval_id": appr_approved.id,
        "svc_id": svc.id,
    }


def test_manifest_signing_success_and_fields(db_session, manifest_signing_env, monkeypatch):
    """1. Successful manifest generation and signing during create_execution()."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_1",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    assert execution is not None
    assert execution.status == "queued"
    assert execution.manifest_id is not None
    assert len(execution.manifest_id) == 36  # UUID v4
    assert execution.authorization_manifest is not None
    assert isinstance(execution.authorization_manifest, dict)
    assert execution.manifest_signature is not None
    assert len(execution.manifest_signature) > 0
    assert execution.manifest_digest is not None
    assert len(execution.manifest_digest) == 64  # SHA-256 hex
    assert execution.manifest_key_id == TEST_KEY_ID
    assert execution.manifest_expires_at is not None

    # Verify event metadata includes manifest linkage
    event = (
        db_session.query(ExecutionEvent)
        .filter(ExecutionEvent.execution_id == execution.id, ExecutionEvent.event_type == "queued")
        .first()
    )
    assert event is not None
    assert event.metadata_json["manifest_id"] == execution.manifest_id
    assert event.metadata_json["manifest_digest"] == execution.manifest_digest


def test_ed25519_raw_signature_verification(db_session, manifest_signing_env, monkeypatch):
    """2. Valid Ed25519 signature verified with raw public key."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_2",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    pub_bytes = base64.b64decode(TEST_PUB_KEY_B64)
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    sig_bytes = base64.urlsafe_b64decode(execution.manifest_signature.encode("ascii"))

    # Canonicalize the stored authorization_manifest dict
    canonical_bytes = canonicalize(execution.authorization_manifest)

    # Raw Ed25519 verification must succeed without raising InvalidSignature
    pub_key.verify(sig_bytes, canonical_bytes)


def test_manifest_crypto_verify_manifest_roundtrip(db_session, manifest_signing_env, monkeypatch):
    """3. Signature verification roundtrip via app.core.manifest_crypto.verify_manifest()."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_3",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    pub_bytes = base64.b64decode(TEST_PUB_KEY_B64)
    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    # verify_manifest with the public key ring
    verified_manifest = verify_manifest(
        manifest_data=execution.authorization_manifest,
        signature_b64=execution.manifest_signature,
        public_keys={TEST_KEY_ID: pub_key},
        expected_environment="development",
        now_utc_ts=execution.authorization_manifest["issued_at"],
    )
    assert verified_manifest.manifest_id == execution.manifest_id
    assert verified_manifest.execution_id == execution.id
    assert verified_manifest.action_id == "restore_order_api_demo"


def test_manifest_rfc8785_parameter_digest(db_session, manifest_signing_env, monkeypatch):
    """4. Correct RFC 8785 parameter digest matching compute_parameters_digest()."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_4",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    expected_digest = compute_parameters_digest(env["approval"].validated_parameters)
    assert execution.authorization_manifest["parameters_sha256"] == expected_digest

    # Verify key ordering invariance: different key insertion orders must yield identical digest
    dict1 = {"b": 1, "a": "test", "c": [1, 2, 3]}
    dict2 = {"a": "test", "c": [1, 2, 3], "b": 1}
    assert compute_parameters_digest(dict1) == compute_parameters_digest(dict2)


def test_manifest_origin_and_path_resolution(db_session, manifest_signing_env, monkeypatch):
    """5. Exact service origin and relative recovery path resolution."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    # Test 1: restore_order_api_demo -> /demo/restore
    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_5a",
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    manifest = execution.authorization_manifest
    assert manifest["authorized_scheme"] == "http"
    assert manifest["authorized_hostname"] == "127.0.0.1"
    assert manifest["authorized_port"] == 8001
    assert manifest["authorized_path"] == "/demo/restore"

    # Test 2: inspect_service_health path resolution
    resolved_health_path = resolve_action_recovery_path("inspect_service_health", env["svc"], {})
    assert resolved_health_path == "/health"

    # Test 3: execute_http_recovery path resolution
    resolved_recovery_path = resolve_action_recovery_path(
        "execute_http_recovery", env["svc"], {"recovery_path": "/api/v1/reset"}
    )
    assert resolved_recovery_path == "/api/v1/reset"

    # Test 4: execute_http_recovery rejects traversal or missing path
    with pytest.raises(ManifestSigningError):
        resolve_action_recovery_path("execute_http_recovery", env["svc"], {"recovery_path": "../etc/passwd"})
    with pytest.raises(ManifestSigningError):
        resolve_action_recovery_path("execute_http_recovery", env["svc"], {})


def test_manifest_identity_and_approval_bindings(db_session, manifest_signing_env, monkeypatch):
    """6. Correct workspace, service, execution, and approval binding in manifest."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_6",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    manifest = execution.authorization_manifest
    assert manifest["manifest_version"] == "1.0"
    assert manifest["issuer"] == "sentinelops.control-plane"
    assert manifest["audience"] == "sentinelops.execution"
    assert manifest["environment"] == "development"
    assert manifest["manifest_id"] == execution.manifest_id
    assert manifest["execution_id"] == execution.id
    assert manifest["approval_id"] == env["approval"].id
    assert manifest["approval_reference"] == f"{env['approval'].id}:{env['approval'].policy_version}"
    assert manifest["workspace_id"] == env["ws_id"]
    assert manifest["service_id"] == env["svc_id"]
    assert manifest["action_id"] == "restore_order_api_demo"


def test_manifest_strict_60s_lifetime(db_session, manifest_signing_env, monkeypatch):
    """7. Expiration strictly within 60s (MAX_MANIFEST_LIFETIME_SECONDS = 60)."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_manifest_test_7",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    manifest = execution.authorization_manifest
    issued_at = manifest["issued_at"]
    expires_at = manifest["expires_at"]

    assert expires_at - issued_at == 60
    assert expires_at - issued_at == MAX_MANIFEST_LIFETIME_SECONDS

    # Verify execution model datetime column matches (handling SQLite timezone naive storage)
    expected_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
    actual_dt = execution.manifest_expires_at
    if actual_dt.tzinfo is None:
        actual_dt = actual_dt.replace(tzinfo=timezone.utc)
    assert actual_dt == expected_dt


def test_manifest_missing_or_malformed_key_fails_closed(db_session, manifest_signing_env, monkeypatch):
    """8. Missing or malformed private key raises error and fails closed."""
    env = manifest_signing_env

    # 1. Missing private key
    monkeypatch.delenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", raising=False)
    with pytest.raises(PreconditionFailedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["approval_id"],
            idempotency_key="key_missing_key",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert "manifest signing failed" in str(exc_info.value.detail).lower()

    # 2. Malformed private key
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", "not-a-valid-base64-key")
    with pytest.raises(PreconditionFailedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["approval_id"],
            idempotency_key="key_malformed_key",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert "manifest signing failed" in str(exc_info.value.detail).lower()

    # Verify no execution records were committed
    executions = db_session.query(RemediationExecution).filter(RemediationExecution.approval_id == env["approval_id"]).all()
    assert len(executions) == 0


def test_invalid_approvals_fail_before_manifest_signing(db_session, manifest_signing_env, monkeypatch):
    """9. Revoked, expired, rejected approval, or inactive/missing service fails before manifest creation."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    # 1. Pending approval
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["appr_pending"].id,
            idempotency_key="key_pending",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 409

    # 2. Rejected approval
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["appr_rejected"].id,
            idempotency_key="key_rejected",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 409

    # 3. Expired approval
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["appr_expired"].id,
            idempotency_key="key_expired",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 400

    # 4. Inactive service
    with pytest.raises(PreconditionFailedError):
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["appr_inactive_svc"].id,
            idempotency_key="key_inactive_svc",
            triggered_by=env["engineer"],
            user_role="engineer",
        )


def test_manifest_persistence_across_session_reload(db_session, manifest_signing_env, monkeypatch):
    """10. Manifest persistence across database reload (clean session)."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_persistence_test",
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    exec_id = execution.id
    manifest_id = execution.manifest_id
    manifest_digest = execution.manifest_digest
    sig = execution.manifest_signature

    # Query from a clean state
    db_session.expire_all()
    reloaded = db_session.query(RemediationExecution).filter(RemediationExecution.id == exec_id).first()

    assert reloaded is not None
    assert reloaded.manifest_id == manifest_id
    assert reloaded.manifest_digest == manifest_digest
    assert reloaded.manifest_signature == sig
    assert reloaded.authorization_manifest["execution_id"] == exec_id
    assert reloaded.authorization_manifest["manifest_id"] == manifest_id


def test_idempotent_execution_retry_preserves_manifest(db_session, manifest_signing_env, monkeypatch):
    """11. Idempotent execution retry returns existing execution without overwriting or regenerating manifest."""
    env = manifest_signing_env
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", TEST_PRIV_KEY_B64)
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    exec1 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_idempotent_manifest",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # Retry with exact same idempotency_key and approval
    exec2 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        idempotency_key="key_idempotent_manifest",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    assert exec1.id == exec2.id
    assert exec1.manifest_id == exec2.manifest_id
    assert exec1.manifest_signature == exec2.manifest_signature
    assert exec1.manifest_digest == exec2.manifest_digest
    assert exec1.authorization_manifest == exec2.authorization_manifest


def test_manifest_signing_failure_transaction_rollback(db_session, manifest_signing_env, monkeypatch):
    """12. Signing failure rolls back transaction (zero execution records in DB)."""
    env = manifest_signing_env
    # Corrupted key causes signing error
    monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", base64.b64encode(b"short-invalid-key").decode())
    monkeypatch.setenv("SENTINELOPS_MANIFEST_KEY_ID", TEST_KEY_ID)

    with pytest.raises(PreconditionFailedError):
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_id"],
            approval_id=env["approval_id"],
            idempotency_key="key_rollback_test",
            triggered_by=env["engineer"],
            user_role="engineer",
        )

    # Verify no execution record exists in database
    executions = db_session.query(RemediationExecution).filter(RemediationExecution.approval_id == env["approval_id"]).all()
    assert len(executions) == 0

    # Verify no ExecutionEvent exists in database
    events = db_session.query(ExecutionEvent).filter(ExecutionEvent.workspace_id == env["ws_id"]).all()
    assert len(events) == 0


def test_historical_executions_without_manifests_remain_readable(db_session, manifest_signing_env):
    """13. Historical executions without manifests (authorization_manifest=None) remain readable."""
    env = manifest_signing_env
    historical_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc)

    # Insert historical execution record simulating pre-manifest schema
    historical = RemediationExecution(
        id=historical_id,
        workspace_id=env["ws_id"],
        approval_id=env["approval_id"],
        incident_id=env["inc"].id,
        investigation_id=None,
        action_id=env["approval"].action_id,
        target_service_id=env["svc_id"],
        approved_parameters={"service_id": env["svc_id"]},
        status="completed",
        idempotency_key="historical_key_legacy",
        locked_by=None,
        locked_until=None,
        heartbeat_at=None,
        fencing_token=1,
        retry_policy="idempotent",
        triggered_by=env["engineer"].id,
        triggered_at=now_utc,
        timeout_seconds=30,
        attempt_count=1,
        max_attempts=1,
        created_at=now_utc,
        updated_at=now_utc,
        manifest_id=None,
        authorization_manifest=None,
        manifest_signature=None,
        manifest_digest=None,
        manifest_key_id=None,
        manifest_expires_at=None,
    )
    db_session.add(historical)
    db_session.commit()

    # Query through manager
    loaded = RemediationExecutionManager.get_execution(
        execution_id=historical_id,
        workspace_id=env["ws_id"],
        db=db_session,
    )
    assert loaded is not None
    assert loaded.id == historical_id
    assert loaded.authorization_manifest is None
    assert loaded.manifest_id is None
    assert loaded.manifest_signature is None
    assert loaded.manifest_digest is None
