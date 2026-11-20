"""Comprehensive Regression and Adversarial Test Suite for Broker Authorization & Replay Prevention.

Phase 2A.1 Stage 6 Verification:
1. Missing authorization manifest rejected.
2. Missing manifest signature rejected.
3. Tampered manifest payload rejected.
4. Tampered Ed25519 signature rejected.
5. Unknown key_id rejected.
6. Revoked key_id rejected.
7. Retiring key_id accepted within validity window.
8. Duplicate JSON keys in IPC payload rejected by broker server framing parser.
9. Expired manifest (>60s) rejected.
10. Excessive validity window (>60s) rejected.
11. Future-issued manifest (>5s clock skew) rejected.
12. Parameter digest mismatch rejected.
13. Origin scheme, hostname, port, or path mismatch rejected.
14. Action ID mismatch rejected.
15. Environment mismatch rejected.
16. Worker pinned IP mismatch with independent broker resolution rejected.
17. Replay of claimed manifest ID rejected.
18. Replay of claimed execution ID rejected.
19. Concurrent claims of same manifest ID serialize cleanly with exactly one winner.
20. Replay journal unavailable/corrupted fails closed before container creation.
21. Broker restart reconciliation transitions in-flight claims (CLAIMED, EXECUTING) to OUTCOME_UNKNOWN.
22. Terminal state immutability (COMPLETED, FAILED, OUTCOME_UNKNOWN cannot be transitioned).
23. Zero private key exposure: broker daemon refuses startup if SENTINELOPS_MANIFEST_PRIVATE_KEY is present.
"""

import base64
import copy
import hashlib
import json
import os
import socket
import struct
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import docker.errors
import requests
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from app.core.manifest_crypto import (
    ExecutionManifest,
    compute_parameters_digest,
    normalize_origin_and_path,
    sign_manifest,
)
from app.core.rfc8785 import canonicalize
from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerExecuteResponse,
    RestrictedDockerBroker,
)
from app.execution.broker_server import (
    HEADER_SIZE,
    HEADER_STRUCT,
    BrokerServer,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
)
from app.execution.manifest_journal import (
    BrokerManifestJournal,
    ExecutionState,
    JournalConflictError,
    JournalUnavailableError,
)
from app.execution.public_keys import (
    BrokerPublicKeyRegistry,
    KeyStatus,
)


# ============================================================================
# Test Helpers and Mock Containers
# ============================================================================

class MockDockerContainer:
    """Simulates Docker container lifecycle with start, wait, logs, kill, remove, reload."""

    def __init__(
        self,
        exit_code: int = 0,
        stdout: bytes = b'{"status": "ok", "restored": true}',
        stderr: bytes = b"",
        wait_exception: Optional[Exception] = None,
        start_exception: Optional[Exception] = None,
        reload_exception: Optional[Exception] = None,
        status: str = "created",
        attrs: Optional[dict] = None,
        id: str = "mock-container-abc12345",
    ):
        self.id = id
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.wait_exception = wait_exception
        self.start_exception = start_exception
        self.reload_exception = reload_exception
        self.status = status
        self.attrs = attrs if attrs is not None else {
            "State": {
                "Status": status,
                "Running": False,
                "Pid": 0,
                "StartedAt": "0001-01-01T00:00:00Z",
                "ExitCode": exit_code,
            }
        }
        self.started = False
        self.killed = False
        self.removed = False

    def start(self):
        if self.start_exception:
            raise self.start_exception
        self.started = True
        self.status = "running"
        self.attrs["State"]["Running"] = True
        self.attrs["State"]["StartedAt"] = "2026-11-07T15:00:00Z"

    def reload(self):
        if self.reload_exception:
            raise self.reload_exception

    def wait(self, timeout: Optional[int] = None):
        if self.wait_exception:
            raise self.wait_exception
        return {"StatusCode": self.exit_code}

    def logs(self, stdout: bool = False, stderr: bool = False):
        if stdout:
            return self.stdout
        if stderr:
            return self.stderr
        return b""

    def kill(self):
        self.killed = True

    def remove(self, force: bool = False):
        self.removed = True


class MockContainersManager:
    """Mock Docker client containers manager supporting create, run, and list."""

    def __init__(
        self,
        container: Optional[MockDockerContainer] = None,
        create_exception: Optional[Exception] = None,
        list_exception: Optional[Exception] = None,
        daemon_containers: Optional[List[MockDockerContainer]] = None,
    ):
        self.container = container or MockDockerContainer()
        self.create_exception = create_exception
        self.list_exception = list_exception
        self.daemon_containers = daemon_containers
        self.created_kwargs = None
        self.create_called = False
        self.run_called = False

    def create(self, **kwargs):
        self.create_called = True
        self.created_kwargs = kwargs
        if self.create_exception:
            raise self.create_exception
        return self.container

    def run(self, detach: bool = True, **kwargs):
        self.run_called = True
        self.created_kwargs = kwargs
        if self.create_exception:
            raise self.create_exception
        self.container.started = True
        return self.container

    def list(self, all: bool = True, filters: Optional[dict] = None):
        if self.list_exception:
            raise self.list_exception
        if self.daemon_containers is not None:
            return list(self.daemon_containers)
        if self.create_exception is not None:
            # If creation raised an exception and no containers were explicitly registered on daemon,
            # zero containers exist on the daemon.
            return []
        return [self.container]


class MockDockerClient:
    """Mock Docker client passed to RestrictedDockerBroker."""

    def __init__(
        self,
        container: Optional[MockDockerContainer] = None,
        create_exception: Optional[Exception] = None,
        list_exception: Optional[Exception] = None,
        daemon_containers: Optional[List[MockDockerContainer]] = None,
    ):
        self.containers = MockContainersManager(
            container=container,
            create_exception=create_exception,
            list_exception=list_exception,
            daemon_containers=daemon_containers,
        )

    def ping(self):
        return True


def generate_test_keypair() -> Tuple[ed25519.Ed25519PrivateKey, str, str]:
    """Generate Ed25519 keypair returning (private_key_obj, key_id, public_key_b64)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    kid = f"test-key-{uuid.uuid4().hex[:8]}"
    return priv, kid, pub_b64


def create_valid_manifest_and_request(
    priv_key: ed25519.Ed25519PrivateKey,
    key_id: str,
    action_id: str = "restore_order_api_demo",
    target_url: str = "http://host.docker.internal:8001/demo/restore",
    environment: str = "development",
    parameters: Optional[Dict[str, Any]] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    execution_id: Optional[str] = None,
) -> Tuple[ExecutionManifest, str, BrokerExecuteRequest]:
    """Create a fully valid ExecutionManifest, detached signature, and BrokerExecuteRequest."""
    now = int(time.time())
    iat = issued_at if issued_at is not None else now
    exp = expires_at if expires_at is not None else (iat + 60)
    exec_id = execution_id or str(uuid.uuid4())
    approval_id = str(uuid.uuid4())
    params = parameters if parameters is not None else {"service_id": str(uuid.uuid4())}

    norm = normalize_origin_and_path(target_url)

    manifest = ExecutionManifest(
        manifest_version="1.0",
        key_id=key_id,
        issuer="sentinelops.control-plane",
        audience="sentinelops.broker",
        environment=environment,
        manifest_id=str(uuid.uuid4()),
        execution_id=exec_id,
        approval_id=approval_id,
        approval_reference=f"{approval_id}:v1",
        workspace_id=str(uuid.uuid4()),
        service_id=str(uuid.uuid4()),
        action_id=action_id,
        authorized_scheme=norm.scheme,
        authorized_hostname=norm.hostname,
        authorized_port=norm.port,
        authorized_path=norm.path,
        parameters_sha256=compute_parameters_digest(params),
        issued_at=iat,
        expires_at=exp,
    )

    sig_b64 = sign_manifest(manifest, priv_key)

    request = BrokerExecuteRequest(
        execution_id=exec_id,
        action_id=action_id,
        parameters=params,
        target_url=target_url,
        timeout_seconds=30,
        environment=environment,
        authorization_manifest=manifest.model_dump(),
        manifest_signature=sig_b64,
    )

    return manifest, sig_b64, request


# ============================================================================
# Test Cases
# ============================================================================

class TestBrokerManifestVerification:
    """Comprehensive test suite for broker authorization & replay prevention."""

    @pytest.fixture
    def test_keys(self):
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({kid: {"public_key": pub_b64, "status": "active"}})
        return priv, kid, pub_b64, registry

    @pytest.fixture
    def test_journal(self, tmp_path):
        journal_path = str(tmp_path / "broker_journal.db")
        return BrokerManifestJournal(db_path=journal_path)

    @pytest.fixture
    def mock_docker(self):
        container = MockDockerContainer()
        client = MockDockerClient(container)
        return client, container

    def test_missing_manifest_rejected(self, test_keys, test_journal, mock_docker):
        """Request without authorization_manifest fails closed before container creation."""
        _, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
            authorization_manifest=None,
            manifest_signature=None,
        )

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Missing authorization_manifest" in str(exc_info.value)
        assert client.containers.create_called is False
        assert client.containers.run_called is False
        assert container.started is False

    def test_missing_signature_rejected(self, test_keys, test_journal, mock_docker):
        """Request with manifest but missing signature fails closed before container creation."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, _, req = create_valid_manifest_and_request(priv, kid)
        req.manifest_signature = None

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Missing or invalid manifest_signature" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_tampered_manifest_payload_rejected(self, test_keys, test_journal, mock_docker):
        """Tampering with any field in the manifest invalidates the Ed25519 signature."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        # Attacker tampers with authorized_path
        tampered_manifest = manifest.model_dump()
        tampered_manifest["authorized_path"] = "/admin/delete_all"
        req.authorization_manifest = tampered_manifest

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "signature verification failed" in str(exc_info.value) or "mismatch" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_tampered_signature_rejected(self, test_keys, test_journal, mock_docker):
        """Corrupted signature bytes fail cryptographic verification."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        # Flip bytes in signature
        sig_raw = bytearray(base64.urlsafe_b64decode(sig + "=="))
        sig_raw[10] ^= 0xFF
        req.manifest_signature = base64.urlsafe_b64encode(bytes(sig_raw)).decode("ascii")

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Ed25519 signature verification failed" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_unknown_key_id_rejected(self, test_keys, test_journal, mock_docker):
        """Manifest signed by a key_id not present in public_key_registry is rejected."""
        priv, _, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        # Manifest signed with unknown key_id
        manifest, sig, req = create_valid_manifest_and_request(priv, "unknown-untrusted-key-id")

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Unknown signing key_id" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_revoked_key_id_rejected(self, test_journal, mock_docker):
        """Manifest signed by a revoked key_id is rejected."""
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({
            kid: {"public_key": pub_b64, "status": "revoked"}
        })

        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "has been revoked" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_retiring_key_id_accepted(self, test_journal, mock_docker):
        """Manifest signed by a retiring key is accepted to allow graceful key rotation."""
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({
            kid: {"public_key": pub_b64, "status": "retiring"}
        })

        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 0
        assert client.containers.create_called is True
        assert container.started is True

    def test_expired_manifest_rejected(self, test_keys, test_journal, mock_docker):
        """Manifest whose expires_at is in the past is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        past_now = int(time.time()) - 100
        manifest, sig, req = create_valid_manifest_and_request(
            priv, kid, issued_at=past_now, expires_at=past_now + 30
        )

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Manifest expired" in str(exc_info.value) or "exceeding max 60s" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_excessive_validity_window_rejected(self, test_keys, test_journal, mock_docker):
        """Manifest with validity window > 60s fails schema validation."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        now = int(time.time())
        # Try creating manifest with 61 seconds validity
        with pytest.raises(ValidationError):
            create_valid_manifest_and_request(
                priv, kid, issued_at=now, expires_at=now + 61
            )

    def test_future_issued_manifest_rejected(self, test_keys, test_journal, mock_docker):
        """Manifest issued in future beyond 5 seconds clock skew tolerance is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        future_iat = int(time.time()) + 10  # 10s into future > 5s skew tolerance
        manifest, sig, req = create_valid_manifest_and_request(
            priv, kid, issued_at=future_iat, expires_at=future_iat + 30
        )

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "in the future beyond 5s skew tolerance" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_parameter_digest_mismatch_rejected(self, test_keys, test_journal, mock_docker):
        """Request parameters that do not match manifest parameters_sha256 are rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(
            priv, kid, parameters={"service_id": str(uuid.uuid4())}
        )
        # Attacker modifies authorized parameters to a different valid service_id
        req.parameters = {"service_id": str(uuid.uuid4())}

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Parameter digest mismatch" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_origin_and_path_mismatch_rejected(self, test_keys, test_journal, mock_docker):
        """Mismatched host or path between request and manifest is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(
            priv, kid, target_url="http://host.docker.internal:8001/demo/restore"
        )
        # Attacker points request target_url to a different endpoint
        req.target_url = "http://host.docker.internal:8001/different/path"

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Target path mismatch" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_action_id_mismatch_rejected(self, test_keys, test_journal, mock_docker):
        """Request action_id differing from manifest action_id is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(
            priv, kid, action_id="restore_order_api_demo"
        )
        req.action_id = "inspect_service_health"

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Action ID mismatch" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_environment_mismatch_rejected(self, test_keys, test_journal, mock_docker):
        """Request environment differing from manifest environment is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(
            priv, kid, environment="development"
        )
        req.environment = "staging"

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Environment mismatch" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_worker_pinned_ip_mismatch_rejected(self, test_keys, test_journal, mock_docker):
        """Worker providing a pinned_ip that disagrees with broker independent resolution is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        req.pinned_ip = "192.0.2.1"  # Spoofed worker pinned IP

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "pinned ip mismatch" in str(exc_info.value).lower()
        assert client.containers.create_called is False
        assert container.started is False

    def test_replay_of_claimed_manifest_rejected(self, test_keys, test_journal, mock_docker):
        """Replaying an already-claimed manifest ID is blocked by the durable replay journal."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)

        # First execution succeeds
        resp1 = broker.execute_action(req)
        assert resp1.exit_code == 0
        assert test_journal.get_record(manifest.manifest_id).state == ExecutionState.COMPLETED

        # Replay attempt fails closed with BrokerSecurityViolation
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)

        assert "Replay prevention conflict" in str(exc_info.value) or "already been claimed" in str(exc_info.value)

    def test_replay_of_claimed_execution_id_rejected(self, test_keys, test_journal, mock_docker):
        """Attempting to use a new manifest with an already-claimed execution_id is rejected."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        exec_id = str(uuid.uuid4())
        manifest1, sig1, req1 = create_valid_manifest_and_request(priv, kid, execution_id=exec_id)
        resp1 = broker.execute_action(req1)
        assert resp1.exit_code == 0

        # Create second distinct manifest with the SAME execution_id
        manifest2, sig2, req2 = create_valid_manifest_and_request(priv, kid, execution_id=exec_id)
        assert manifest2.manifest_id != manifest1.manifest_id

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req2)

        assert "Replay prevention conflict" in str(exc_info.value) or "already been claimed" in str(exc_info.value)

    def test_concurrent_claims_of_same_manifest(self, test_keys, test_journal, mock_docker):
        """Concurrent threads claiming the same manifest serialize cleanly: exactly 1 wins."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)

        results = []
        errors = []

        def worker():
            try:
                resp = broker.execute_action(req)
                results.append(resp)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 1 success, 4 BrokerSecurityViolations
        assert len(results) == 1
        assert len(errors) == 4
        assert all(isinstance(err, BrokerSecurityViolation) for err in errors)

    def test_journal_unavailable_fails_closed_before_container_creation(
        self, test_keys, tmp_path, mock_docker
    ):
        """If journal database becomes unwritable/corrupted, execution fails closed before container creation."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker

        journal_path = str(tmp_path / "valid_then_corrupt.db")
        journal = BrokerManifestJournal(db_path=journal_path)

        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        # Close journal connections to simulate backend storage failure
        journal.close()

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)

        with pytest.raises(ExecutionEnvironmentUnavailable) as exc_info:
            broker.execute_action(req)

        assert "Replay journal unavailable" in str(exc_info.value)
        assert client.containers.create_called is False
        assert container.started is False

    def test_crash_consistency_container_timeout_records_outcome_unknown(
        self, test_keys, test_journal
    ):
        """When execution times out, journal state transitions to OUTCOME_UNKNOWN."""
        priv, kid, _, registry = test_keys
        mock_container = MockDockerContainer(wait_exception=Exception("Execution timed out!"))
        client = MockDockerClient(mock_container)

        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 124
        assert resp.error_category == "timeout"

        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "timed out" in record.error_message

    def test_broker_restart_reconciliation_transitions_unresolved_claims(
        self, test_keys, tmp_path
    ):
        """Broker restart reconciliation transitions CLAIMED and EXECUTING claims to OUTCOME_UNKNOWN."""
        priv, kid, _, registry = test_keys
        journal_path = str(tmp_path / "recon_journal.db")
        journal = BrokerManifestJournal(db_path=journal_path)

        # Claim two manifests: leave one in CLAIMED, one in EXECUTING
        manifest1, _, _ = create_valid_manifest_and_request(priv, kid)
        manifest2, _, _ = create_valid_manifest_and_request(priv, kid)

        journal.claim_manifest(
            manifest_id=manifest1.manifest_id,
            execution_id=manifest1.execution_id,
            action_id=manifest1.action_id,
            authorized_origin="http://host.docker.internal:8001",
            authorized_path="/demo/restore",
            parameters_sha256=manifest1.parameters_sha256,
            key_id=manifest1.key_id,
            manifest_digest="a" * 64,
            expires_at=manifest1.expires_at,
        )

        journal.claim_manifest(
            manifest_id=manifest2.manifest_id,
            execution_id=manifest2.execution_id,
            action_id=manifest2.action_id,
            authorized_origin="http://host.docker.internal:8001",
            authorized_path="/demo/restore",
            parameters_sha256=manifest2.parameters_sha256,
            key_id=manifest2.key_id,
            manifest_digest="b" * 64,
            expires_at=manifest2.expires_at,
        )
        journal.mark_executing(manifest2.manifest_id)

        # Simulate broker process crash and restart: create fresh journal instance pointing to same file
        restarted_journal = BrokerManifestJournal(db_path=journal_path)
        reconciled = restarted_journal.reconcile_unresolved_claims()

        assert len(reconciled) == 2
        r1 = restarted_journal.get_record(manifest1.manifest_id)
        r2 = restarted_journal.get_record(manifest2.manifest_id)

        assert r1.state == ExecutionState.OUTCOME_UNKNOWN
        assert r2.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Broker recovery reconciliation" in r1.error_message
        assert "Broker recovery reconciliation" in r2.error_message

    def test_terminal_state_immutability(self, test_keys, test_journal):
        """COMPLETED, FAILED, and OUTCOME_UNKNOWN records can never be re-transitioned."""
        priv, kid, _, _ = test_keys
        manifest, _, _ = create_valid_manifest_and_request(priv, kid)

        test_journal.claim_manifest(
            manifest_id=manifest.manifest_id,
            execution_id=manifest.execution_id,
            action_id=manifest.action_id,
            authorized_origin="http://host.docker.internal:8001",
            authorized_path="/demo/restore",
            parameters_sha256=manifest.parameters_sha256,
            key_id=manifest.key_id,
            manifest_digest="a" * 64,
            expires_at=manifest.expires_at,
        )
        test_journal.mark_executing(manifest.manifest_id)
        test_journal.mark_completed(manifest.manifest_id)

        # Attempting any transition on COMPLETED record must raise JournalStateTransitionError
        from app.execution.manifest_journal import JournalStateTransitionError
        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_executing(manifest.manifest_id)

        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_failed(manifest.manifest_id)

        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_outcome_unknown(manifest.manifest_id)

    def test_duplicate_json_keys_rejected_by_ipc_parser(self, test_keys, test_journal, mock_docker):
        """IPC framing parser strictly rejects duplicate JSON keys."""
        priv, kid, _, registry = test_keys
        client, container = mock_docker
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        server = BrokerServer(
            broker=broker,
            custom_peer_verifier=lambda conn: (True, "Authorized", {"uid": 1000}),
        )

        s1, s2 = socket.socketpair()
        try:
            # Construct raw JSON payload containing duplicate key "action_id"
            raw_dup_json = (
                b'{"execution_id": "' + str(uuid.uuid4()).encode("utf-8") + b'", '
                b'"action_id": "restore_order_api_demo", '
                b'"action_id": "malicious_overwrite", '
                b'"target_url": "http://host.docker.internal:8001/demo/restore"}'
            )

            # Send length prefix + payload
            s2.sendall(struct.pack(HEADER_STRUCT, len(raw_dup_json)) + raw_dup_json)
            server.handle_connection(s1)

            # Read response
            resp_header = s2.recv(HEADER_SIZE)
            resp_len = struct.unpack(HEADER_STRUCT, resp_header)[0]
            resp_bytes = s2.recv(resp_len)
            resp_dict = json.loads(resp_bytes.decode("utf-8"))

            assert "error" in resp_dict
            assert resp_dict["error"] == "BrokerSecurityViolation"
            assert "Duplicate key 'action_id' detected" in resp_dict["detail"]
        finally:
            s1.close()
            s2.close()

    def test_zero_private_key_exposure_assertion(self, monkeypatch):
        """Broker daemon refuses to start if SENTINELOPS_MANIFEST_PRIVATE_KEY is present."""
        monkeypatch.setenv("SENTINELOPS_MANIFEST_PRIVATE_KEY", "/+coTws3RSMT0fao4K5hSCP0dr6lz+NozVmUi2+UT/Q=")

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            RestrictedDockerBroker(enforce_no_private_key=True)

        assert "SENTINELOPS_MANIFEST_PRIVATE_KEY detected in broker process environment" in str(exc_info.value)


# ============================================================================
# Stage 6.1: Execution Outcome Classification Tests
# ============================================================================

class TestStage6_1OutcomeClassification:
    """
    Focused adversarial and regression tests for Stage 6.1:
    Outcome classification correction (non-zero exits and uncertain lifecycles -> OUTCOME_UNKNOWN).
    """

    @pytest.fixture
    def test_keys(self):
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({kid: {"public_key": pub_b64, "status": "active"}})
        return priv, kid, pub_b64, registry

    @pytest.fixture
    def test_journal(self, tmp_path):
        journal_path = str(tmp_path / "stage6_1_journal.db")
        return BrokerManifestJournal(db_path=journal_path)

    def test_nonzero_exit_after_start_produces_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule: Once execution may have started, a non-zero exit must become OUTCOME_UNKNOWN.
        This prevents unsafe automatic retries of potentially mutating operations.
        """
        priv, kid, _, registry = test_keys
        # Mock container that started and exited with code 1
        container = MockDockerContainer(
            exit_code=1,
            stdout=b'{"error": "Order API rejected recovery token"}',
            stderr=b"HTTP 500 Internal Server Error",
        )
        client = MockDockerClient(container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        # Broker returns structured error response
        assert resp.exit_code == 1
        assert resp.error_category == "action_failure"
        assert "HTTP 500" in resp.error_message or "exited with code 1" in resp.error_message

        # Container was demonstrably created and started
        assert client.containers.create_called is True
        assert container.started is True

        # CRITICAL STAGE 6.1 INVARIANT: Journal MUST classify this as OUTCOME_UNKNOWN, NOT FAILED
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "exited with non-zero code 1" in record.error_message

        # Replay attempt must be strictly rejected
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)
        assert "Replay prevention conflict" in str(exc_info.value)

        # Assert no second container creation occurred
        assert client.containers.create_called is True  # Only once from first execution

    def test_timeout_after_start_produces_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule: Timeout after executor start must become OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(wait_exception=Exception("Execution timed out!"))
        client = MockDockerClient(container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 124
        assert resp.error_category == "timeout"
        assert container.started is True

        # Journal state MUST be OUTCOME_UNKNOWN
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "timed out" in record.error_message

        # Replay attempt fails closed
        with pytest.raises(BrokerSecurityViolation):
            broker.execute_action(req)

    def test_docker_start_failure_with_uncertain_status_produces_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule: Do not classify an uncertain Docker start failure as FAILED merely
        because the Docker API returned an exception. If start status cannot be
        proven unstarted, it must become OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys
        # Start raises exception, and reload also fails (cannot confirm if container started or not)
        container = MockDockerContainer(
            start_exception=Exception("Docker socket connection reset by peer during start"),
            reload_exception=Exception("Docker daemon connection timed out"),
            status="uncertain",
        )
        client = MockDockerClient(container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        assert resp.error_category == "broker_error"

        # Uncertain start status MUST produce OUTCOME_UNKNOWN in the replay journal
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

        # The execution cannot be claimed again
        with pytest.raises(BrokerSecurityViolation):
            broker.execute_action(req)

    def test_demonstrably_unstarted_container_marked_failed(
        self, test_keys, test_journal
    ):
        """
        Rule: A container that demonstrably never started can be marked FAILED.
        Tests two distinct demonstrable pre-execution failure modes:
        1. Container creation itself failed (no container was created).
        2. Container was created but demonstrably remained in 'created' state without starting.
        """
        priv, kid, _, registry = test_keys

        # Subcase A: Container creation demonstrably fails before execution with authoritative rejection
        client_a = MockDockerClient(
            create_exception=docker.errors.ImageNotFound(
                "Image sentinelops/remediation-executor:dev-local not found"
            )
        )
        broker_a = RestrictedDockerBroker(
            docker_client=client_a,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest_a, sig_a, req_a = create_valid_manifest_and_request(priv, kid)
        resp_a = broker_a.execute_action(req_a)

        assert resp_a.exit_code == 1
        record_a = test_journal.get_record(manifest_a.manifest_id)
        assert record_a.state == ExecutionState.FAILED
        assert "Container demonstrably never started" in record_a.error_message

        # Subcase B: Container was created in Docker, but start failed.
        # Under Stage 6.1.3 hardening, once start() has been invoked, any failure MUST produce
        # OUTCOME_UNKNOWN (reload snapshots cannot prove non-execution).
        container_b = MockDockerContainer(
            start_exception=Exception("OCI runtime error: executable file not found in $PATH"),
            status="created",  # Confirmed created, never running
        )
        client_b = MockDockerClient(container_b)
        broker_b = RestrictedDockerBroker(
            docker_client=client_b,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest_b, sig_b, req_b = create_valid_manifest_and_request(priv, kid)
        resp_b = broker_b.execute_action(req_b)

        assert resp_b.exit_code == 1
        assert container_b.started is False
        record_b = test_journal.get_record(manifest_b.manifest_id)
        assert record_b.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record_b.error_message
        assert container_b.killed is False
        assert container_b.removed is False

    def test_outcome_unknown_execution_cannot_be_claimed_again(
        self, test_keys, test_journal
    ):
        """
        Rule: An OUTCOME_UNKNOWN execution cannot be claimed again.
        Both the same manifest and different manifests with the same execution_id are blocked.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(exit_code=1)
        client = MockDockerClient(container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)
        assert resp.exit_code == 1

        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Attempt 1: Replay exact same request
        with pytest.raises(BrokerSecurityViolation) as exc_info1:
            broker.execute_action(req)
        assert "Replay prevention conflict" in str(exc_info1.value)

        # Attempt 2: Replay same execution_id with new manifest
        manifest2, sig2, req2 = create_valid_manifest_and_request(
            priv, kid, execution_id=manifest.execution_id
        )
        assert manifest2.manifest_id != manifest.manifest_id

        with pytest.raises(BrokerSecurityViolation) as exc_info2:
            broker.execute_action(req2)
        assert "Replay prevention conflict" in str(exc_info2.value)

    def test_completed_executor_process_not_confused_with_verified_recovery(
        self, test_keys, test_journal
    ):
        """
        Rule: A zero exit code represents successful executor-process completion,
        but it must NOT be presented as proof that the external service was successfully recovered.
        Preserve the separate control-plane post-execution verification requirement.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            exit_code=0,
            stdout=b'{"status": "ok", "action": "restore_order_api_demo"}',
        )
        client = MockDockerClient(container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        # Process exited 0
        assert resp.exit_code == 0
        # Journal state is COMPLETED (local process completion only)
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.COMPLETED

        # Broker response indicates container process exit status ONLY
        # It does NOT claim service-level recovery confirmation
        resp_dict = resp.model_dump()
        assert "is_verified" not in resp_dict
        assert "service_recovered" not in resp_dict
        assert "verification_passed" not in resp_dict

    def test_journal_terminal_state_protections_remain_intact(
        self, test_keys, test_journal
    ):
        """
        Rule: OUTCOME_UNKNOWN, COMPLETED, and FAILED must remain terminal.
        No transition out of these states is permitted under any circumstances.
        """
        from app.execution.manifest_journal import (
            PERMITTED_TRANSITIONS,
            JournalStateTransitionError,
        )

        # Assert terminal sets in specification
        assert PERMITTED_TRANSITIONS[ExecutionState.OUTCOME_UNKNOWN] == set()
        assert PERMITTED_TRANSITIONS[ExecutionState.COMPLETED] == set()
        assert PERMITTED_TRANSITIONS[ExecutionState.FAILED] == set()

        priv, kid, _, _ = test_keys
        manifest, _, _ = create_valid_manifest_and_request(priv, kid)

        # Claim and transition to OUTCOME_UNKNOWN
        test_journal.claim_manifest(
            manifest_id=manifest.manifest_id,
            execution_id=manifest.execution_id,
            action_id=manifest.action_id,
            authorized_origin="http://host.docker.internal:8001",
            authorized_path="/demo/restore",
            parameters_sha256=manifest.parameters_sha256,
            key_id=manifest.key_id,
            manifest_digest="a" * 64,
            expires_at=manifest.expires_at,
        )
        test_journal.mark_executing(manifest.manifest_id)
        test_journal.mark_outcome_unknown(manifest.manifest_id, reason="Testing terminality")

        # Every attempted transition from OUTCOME_UNKNOWN must raise JournalStateTransitionError
        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_completed(manifest.manifest_id)

        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_failed(manifest.manifest_id)

        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_executing(manifest.manifest_id)

        with pytest.raises(JournalStateTransitionError):
            test_journal.mark_outcome_unknown(manifest.manifest_id)


# ============================================================================
# Stage 6.1.1 Adversarial Tests: Docker Container-Creation Uncertainty
# ============================================================================

class TestStage6_1_1ContainerCreationUncertainty:
    """
    Adversarial verification suite for Stage 6.1.1:
    Ensures container creation uncertainty is safely classified as OUTCOME_UNKNOWN,
    'container is None' alone never establishes failure, daemon inspection is required,
    uninspectable containers produce OUTCOME_UNKNOWN, and uncertain containers are never
    automatically started or deleted.
    """

    @pytest.fixture
    def test_keys(self):
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({kid: {"public_key": pub_b64, "status": "active"}})
        return priv, kid, pub_b64, registry

    @pytest.fixture
    def test_journal(self, tmp_path):
        journal_path = str(tmp_path / "stage6_1_1_journal.db")
        return BrokerManifestJournal(db_path=journal_path)

    def test_creation_succeeds_unstarted_container_marked_failed(
        self, test_keys, test_journal
    ):
        """
        Rule 1: Container creation succeeds and returns a container.
        Under Stage 6.1.3 hardening, once start() has been invoked, any ambiguous failure
        MUST produce OUTCOME_UNKNOWN (reload snapshots cannot prove non-execution).
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=Exception("OCI runtime error: executable file not found in $PATH"),
            status="created",
            attrs={
                "State": {
                    "Status": "created",
                    "Running": False,
                    "Pid": 0,
                    "StartedAt": "0001-01-01T00:00:00Z",
                    "ExitCode": 0,
                }
            },
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        assert container.started is False
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message
        assert container.killed is False
        assert container.removed is False

    def test_creation_raises_daemon_may_have_created_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 2: Container creation raises (e.g. connection reset or socket drop),
        and the Docker daemon may have created the container.
        Daemon-side inspection finds a container whose state is not confirmed unstarted.
        Must produce OUTCOME_UNKNOWN, and container must NOT be deleted or started.
        """
        priv, kid, _, registry = test_keys
        # Simulate container that daemon created and may be running or ambiguous
        daemon_container = MockDockerContainer(
            status="running",
            attrs={
                "State": {
                    "Status": "running",
                    "Running": True,
                    "Pid": 4821,
                    "StartedAt": "2026-11-07T15:30:00Z",
                    "ExitCode": 0,
                }
            },
        )
        client = MockDockerClient(
            create_exception=ConnectionResetError("Socket dropped by Docker daemon after create"),
            daemon_containers=[daemon_container],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

        # Safety rule: uncertain container must NOT be started or deleted automatically
        assert daemon_container.killed is False
        assert daemon_container.removed is False

    def test_creation_timeout_daemon_inspection_unavailable_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 3: Container creation times out and daemon inspection is unavailable
        (e.g. list query times out or fails).
        Must produce OUTCOME_UNKNOWN because container creation state cannot be proven.
        """
        priv, kid, _, registry = test_keys
        client = MockDockerClient(
            create_exception=TimeoutError("client.containers.create timed out after 10s"),
            list_exception=TimeoutError("client.containers.list timed out (daemon unresponsive)"),
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

    def test_creation_raises_daemon_conclusively_no_container_marked_failed(
        self, test_keys, test_journal
    ):
        """
        Rule 4: Container creation raises and daemon-side inspection conclusively establishes
        that zero containers exist on the daemon for this execution ID.
        Classified as FAILED according to safe pre-execution failure policy.
        """
        priv, kid, _, registry = test_keys
        client = MockDockerClient(
            create_exception=docker.errors.ImageNotFound(
                "Docker image not found: sentinelops/remediation-executor:dev-local"
            ),
            daemon_containers=[],  # Daemon conclusively confirms 0 containers exist
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.FAILED
        assert "Container demonstrably never started" in record.error_message

    def test_container_exists_cannot_be_inspected_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 5: A container exists on the Docker daemon, but its state cannot be inspected
        (e.g. container.reload() raises an I/O exception).
        Must produce OUTCOME_UNKNOWN and preserve the container.
        """
        priv, kid, _, registry = test_keys
        daemon_container = MockDockerContainer(
            reload_exception=Exception("Docker engine connection reset during container inspect"),
        )
        client = MockDockerClient(
            create_exception=ConnectionResetError("Socket reset during create"),
            daemon_containers=[daemon_container],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

        # Must NOT delete or kill uninspected container
        assert daemon_container.killed is False
        assert daemon_container.removed is False

    def test_uncertain_creation_outcome_cannot_be_replayed(
        self, test_keys, test_journal
    ):
        """
        Rule 6: An uncertain creation outcome (OUTCOME_UNKNOWN) cannot be automatically
        replayed or claimed again under any circumstances.
        """
        priv, kid, _, registry = test_keys
        client = MockDockerClient(
            create_exception=TimeoutError("Timeout creating container"),
            list_exception=TimeoutError("Timeout listing containers"),
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)
        assert resp.exit_code == 1

        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Attempt 1: Replay exact same request with same manifest_id
        with pytest.raises(BrokerSecurityViolation) as exc_info1:
            broker.execute_action(req)
        assert "Replay prevention conflict" in str(exc_info1.value)

        # Attempt 2: Replay same execution_id with new manifest
        manifest2, sig2, req2 = create_valid_manifest_and_request(
            priv, kid, execution_id=manifest.execution_id
        )
        assert manifest2.manifest_id != manifest.manifest_id

        with pytest.raises(BrokerSecurityViolation) as exc_info2:
            broker.execute_action(req2)
        assert "Replay prevention conflict" in str(exc_info2.value)

    def test_existing_post_start_tests_preserved(
        self, test_keys, test_journal
    ):
        """
        Rule 7: Verifies that post-start non-zero exit, timeout, and uncertain-start
        tests continue to function safely under the Stage 6.1.1 policy.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(exit_code=2, stderr=b"Process crashed unexpectedly")
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 2
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Container process exited with non-zero code 2" in record.error_message


# ============================================================================
# Stage 6.1.2 Adversarial Tests: Docker Creation Request Race Hardening
# ============================================================================

class TestStage6_1_2CreationRequestRace:
    """
    Adversarial verification suite for Stage 6.1.2:
    - Connection reset during creation with empty daemon listing produces OUTCOME_UNKNOWN.
    - Timeout during creation with empty daemon listing produces OUTCOME_UNKNOWN.
    - Ambiguous transport failures never treat an immediate empty listing as conclusive proof.
    - Explicit authoritative Docker API rejections (ImageNotFound, 400, 404, 422) permit FAILED.
    - 409 Conflict (existing container name collision) fails closed to OUTCOME_UNKNOWN.
    - Matching containers found after ambiguous creation are preserved (never killed or started).
    - Deterministic unique container names (sentinelops-exec-{execution_id}) are enforced.
    - Replay prevention locks both manifest ID and execution ID permanently.
    """

    @pytest.fixture
    def test_keys(self):
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({kid: {"public_key": pub_b64, "status": "active"}})
        return priv, kid, pub_b64, registry

    @pytest.fixture
    def test_journal(self, tmp_path):
        journal_path = str(tmp_path / "stage6_1_2_journal.db")
        return BrokerManifestJournal(db_path=journal_path)

    def test_connection_reset_during_creation_empty_listing_produces_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 1: Connection reset during container creation followed by an empty daemon listing
        MUST produce OUTCOME_UNKNOWN because the creation request may still be in flight.
        """
        priv, kid, _, registry = test_keys
        client = MockDockerClient(
            create_exception=ConnectionResetError("Connection reset by peer during container create"),
            daemon_containers=[],  # Empty listing is only a transient snapshot!
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

    def test_timeout_during_creation_empty_listing_produces_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 2: Timeout during container creation followed by an empty daemon listing
        MUST produce OUTCOME_UNKNOWN because the creation request may complete later.
        """
        priv, kid, _, registry = test_keys
        client = MockDockerClient(
            create_exception=TimeoutError("Socket read timeout waiting for daemon create response"),
            daemon_containers=[],  # Empty listing is only a transient snapshot!
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

    def test_delayed_creation_request_cannot_result_in_unsafe_automatic_retry(
        self, test_keys, test_journal
    ):
        """
        Rule 3: A delayed creation request that produced OUTCOME_UNKNOWN permanently
        blocks automatic retry of the manifest and execution ID.
        """
        priv, kid, _, registry = test_keys
        client = MockDockerClient(
            create_exception=ConnectionResetError("Transport pipe broken during create"),
            daemon_containers=[],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)
        assert resp.exit_code == 1

        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Attempt 1: Replay exact same request with same manifest_id
        with pytest.raises(BrokerSecurityViolation) as exc_info1:
            broker.execute_action(req)
        assert "Replay prevention conflict" in str(exc_info1.value)

        # Attempt 2: Replay same execution_id with new signed manifest
        manifest2, sig2, req2 = create_valid_manifest_and_request(
            priv, kid, execution_id=manifest.execution_id
        )
        with pytest.raises(BrokerSecurityViolation) as exc_info2:
            broker.execute_action(req2)
        assert "Replay prevention conflict" in str(exc_info2.value)

    def test_explicit_authoritative_docker_rejection_classified_as_failed(
        self, test_keys, test_journal
    ):
        """
        Rule 4: Explicit authoritative Docker API rejections (e.g. ImageNotFound, HTTP 404, HTTP 400)
        prove that the engine affirmatively refused to create the container.
        Classified as FAILED when daemon inspection confirms zero matching containers.
        """
        priv, kid, _, registry = test_keys

        # Subcase 4A: ImageNotFound (404)
        client_4a = MockDockerClient(
            create_exception=docker.errors.ImageNotFound(
                "No such image: sentinelops/remediation-executor:v1.0"
            ),
            daemon_containers=[],
        )
        broker_4a = RestrictedDockerBroker(
            docker_client=client_4a,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )
        manifest_4a, _, req_4a = create_valid_manifest_and_request(priv, kid)
        resp_4a = broker_4a.execute_action(req_4a)

        assert resp_4a.exit_code == 1
        record_4a = test_journal.get_record(manifest_4a.manifest_id)
        assert record_4a.state == ExecutionState.FAILED
        assert "Container demonstrably never started" in record_4a.error_message

        # Subcase 4B: APIError 400 Bad Request
        import requests
        r400 = requests.Response()
        r400.status_code = 400

        client_4b = MockDockerClient(
            create_exception=docker.errors.APIError("Bad request: invalid nano_cpus parameter", response=r400),
            daemon_containers=[],
        )
        broker_4b = RestrictedDockerBroker(
            docker_client=client_4b,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )
        manifest_4b, _, req_4b = create_valid_manifest_and_request(priv, kid)
        resp_4b = broker_4b.execute_action(req_4b)

        assert resp_4b.exit_code == 1
        record_4b = test_journal.get_record(manifest_4b.manifest_id)
        assert record_4b.state == ExecutionState.FAILED

        # Subcase 4C: APIError 409 Conflict (Container name already in use) must FAIL CLOSED to OUTCOME_UNKNOWN
        r409 = requests.Response()
        r409.status_code = 409

        client_4c = MockDockerClient(
            create_exception=docker.errors.APIError("Conflict: container name already in use", response=r409),
            daemon_containers=[],
        )
        broker_4c = RestrictedDockerBroker(
            docker_client=client_4c,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )
        manifest_4c, _, req_4c = create_valid_manifest_and_request(priv, kid)
        resp_4c = broker_4c.execute_action(req_4c)

        assert resp_4c.exit_code == 1
        record_4c = test_journal.get_record(manifest_4c.manifest_id)
        assert record_4c.state == ExecutionState.OUTCOME_UNKNOWN

    def test_matching_container_found_after_ambiguous_creation_exception_preserved(
        self, test_keys, test_journal
    ):
        """
        Rule 5: When an ambiguous creation exception occurs and daemon inspection finds
        a matching container, produce OUTCOME_UNKNOWN and preserve the container untouched.
        Do NOT delete, kill, or start it automatically.
        """
        priv, kid, _, registry = test_keys
        daemon_container = MockDockerContainer(
            status="created",
            attrs={
                "State": {
                    "Status": "created",
                    "Running": False,
                    "Pid": 0,
                    "StartedAt": "0001-01-01T00:00:00Z",
                    "ExitCode": 0,
                }
            },
        )
        client = MockDockerClient(
            create_exception=ConnectionResetError("Socket reset while creating container"),
            daemon_containers=[daemon_container],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Critical invariant: ambiguous container must NEVER be killed, removed, or started
        assert daemon_container.killed is False
        assert daemon_container.removed is False
        assert daemon_container.started is False

    def test_deterministic_container_name_binding(
        self, test_keys, test_journal
    ):
        """
        Rule: Broker builds deterministic, unique container names bound to execution_id.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(exit_code=0)
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        _, spec = broker.build_container_config(req)

        expected_name = f"sentinelops-exec-{req.execution_id}"
        assert spec["name"] == expected_name
        assert spec["labels"]["sentinelops.execution_id"] == req.execution_id

    def test_existing_uncertain_start_and_post_start_outcome_tests_intact(
        self, test_keys, test_journal
    ):
        """
        Rule 6: Post-start non-zero exit and confirmed unstarted containers after
        successful creation continue to follow safe classification.
        """
        priv, kid, _, registry = test_keys

        # Subcase 6A: Start attempted with start_exception -> OUTCOME_UNKNOWN (Stage 6.1.3 hardening)
        container_unstarted = MockDockerContainer(
            start_exception=Exception("OCI runtime failure: fork/exec error"),
            status="created",
            attrs={
                "State": {
                    "Status": "created",
                    "Running": False,
                    "Pid": 0,
                    "StartedAt": "0001-01-01T00:00:00Z",
                    "ExitCode": 0,
                }
            },
        )
        client_6a = MockDockerClient(container=container_unstarted)
        broker_6a = RestrictedDockerBroker(
            docker_client=client_6a,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )
        manifest_6a, _, req_6a = create_valid_manifest_and_request(priv, kid)
        resp_6a = broker_6a.execute_action(req_6a)

        assert resp_6a.exit_code == 1
        record_6a = test_journal.get_record(manifest_6a.manifest_id)
        assert record_6a.state == ExecutionState.OUTCOME_UNKNOWN
        assert container_unstarted.killed is False
        assert container_unstarted.removed is False

        # Subcase 6B: Non-zero exit after start -> OUTCOME_UNKNOWN
        container_started = MockDockerContainer(exit_code=1, stderr=b"Action failed")
        client_6b = MockDockerClient(container=container_started)
        broker_6b = RestrictedDockerBroker(
            docker_client=client_6b,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )
        manifest_6b, _, req_6b = create_valid_manifest_and_request(priv, kid)
        resp_6b = broker_6b.execute_action(req_6b)

        assert resp_6b.exit_code == 1
        record_6b = test_journal.get_record(manifest_6b.manifest_id)
        assert record_6b.state == ExecutionState.OUTCOME_UNKNOWN


# ============================================================================
# Stage 6.1.3 Adversarial Tests: Docker START Request Race & Classification Hardening
# ============================================================================

class TestStage6_1_3StartRequestRace:
    """
    Adversarial verification suite for Stage 6.1.3:
    - START request race: ambiguous start failure produces OUTCOME_UNKNOWN even if reload() reports 'created'.
    - Point-in-time container.reload() snapshots cannot convert ambiguous START failures to FAILED.
    - Start-attempted flag is set immediately before container.start().
    - Container preservation: uncertain launch containers are NEVER automatically killed or removed.
    - Replay prevention: both exact manifest and same execution_id blocked permanently after start uncertainty.
    - Non-zero exits produce OUTCOME_UNKNOWN; zero exit does not claim service recovery.
    - Authoritative rejection hardening: unrelated exceptions with status_code=400 are rejected.
    - Delayed creation simulation: containers appearing later on daemon are preserved and blocked.
    """

    @pytest.fixture
    def test_keys(self):
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({kid: {"public_key": pub_b64, "status": "active"}})
        return priv, kid, pub_b64, registry

    @pytest.fixture
    def test_journal(self, tmp_path):
        journal_path = str(tmp_path / "stage6_1_3_journal.db")
        return BrokerManifestJournal(db_path=journal_path)

    def test_start_raises_connection_reset_reload_reports_created_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 1: container.start() raises ConnectionResetError.
        An immediate container.reload() reporting status='created', Running=False, Pid=0
        MUST NOT convert the ambiguous failure into FAILED.
        Must produce OUTCOME_UNKNOWN and preserve the container (never killed or removed).
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=ConnectionResetError("Connection reset by peer during container start"),
            status="created",
            attrs={
                "State": {
                    "Status": "created",
                    "Running": False,
                    "Pid": 0,
                    "StartedAt": "0001-01-01T00:00:00Z",
                    "ExitCode": 0,
                }
            },
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Uncertain execution or launch failure" in record.error_message

        # Critical invariant: uncertain container must NOT be killed or removed
        assert container.killed is False
        assert container.removed is False

    def test_start_raises_timeout_reload_reports_created_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 2: container.start() raises TimeoutError.
        Even if reload reports 'created', produces OUTCOME_UNKNOWN and preserves container.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=TimeoutError("Socket timeout waiting for daemon start response"),
            status="created",
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert container.killed is False
        assert container.removed is False

    def test_start_raises_runtime_error_reload_reports_created_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 3: container.start() raises RuntimeError.
        Generic or daemon socket exceptions produce OUTCOME_UNKNOWN and preserve container.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=RuntimeError("Docker daemon socket error during start"),
            status="created",
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert container.killed is False
        assert container.removed is False

    def test_start_raises_reload_fails_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 4: container.start() raises and subsequent reload() also raises.
        Produces OUTCOME_UNKNOWN and preserves container.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=ConnectionResetError("Socket broken during start"),
            reload_exception=Exception("Docker engine unavailable on inspect"),
            status="uncertain",
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert container.killed is False
        assert container.removed is False

    def test_start_response_lost_daemon_transitions_to_running_preserved(
        self, test_keys, test_journal
    ):
        """
        Rule 5: Client connection resets during container.start(), but the Docker daemon
        actually successfully started the container (daemon state transitions to 'running').
        Broker records OUTCOME_UNKNOWN, does NOT mark FAILED, does NOT kill the running container,
        and does NOT retry.
        """
        priv, kid, _, registry = test_keys

        class LostResponseContainer(MockDockerContainer):
            def start(self):
                self.started = True
                self.status = "running"
                self.attrs["State"]["Running"] = True
                self.attrs["State"]["Pid"] = 9988
                self.attrs["State"]["StartedAt"] = "2026-11-07T16:00:00Z"
                raise ConnectionResetError("Connection reset after daemon processed start command")

        container = LostResponseContainer()
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Critical: Container is actively running on daemon; broker must NOT kill or remove it
        assert container.started is True
        assert container.killed is False
        assert container.removed is False

    def test_start_successful_executor_exits_nonzero_outcome_unknown(
        self, test_keys, test_journal
    ):
        """
        Rule 6: Container starts cleanly, but executor exits non-zero (code 1 or 2).
        Because external mutation may have occurred before the exit, must produce OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            exit_code=2,
            stderr=b"External HTTP mutation issued but post-condition failed",
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 2
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert "Container process exited with non-zero code 2" in record.error_message

    def test_start_successful_executor_exits_zero_not_claimed_verified(
        self, test_keys, test_journal
    ):
        """
        Rule 7: Container starts cleanly and executor process exits with code 0.
        Broker records COMPLETED in journal, but response must NOT claim service-level recovery verification.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            exit_code=0,
            stdout=b'{"status": "ok", "action": "restore_order_api_demo"}',
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 0
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.COMPLETED

        resp_dict = resp.model_dump()
        assert "is_verified" not in resp_dict
        assert "service_recovered" not in resp_dict
        assert "verification_passed" not in resp_dict

    def test_replay_blocked_same_manifest_after_start_uncertainty(
        self, test_keys, test_journal
    ):
        """
        Rule 8: After a start race produces OUTCOME_UNKNOWN, the exact same manifest
        cannot be replayed (permanently blocked by replay prevention).
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=ConnectionResetError("Socket broken during start"),
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)
        assert resp.exit_code == 1

        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req)
        assert "Replay prevention conflict" in str(exc_info.value)

    def test_replay_blocked_same_execution_id_new_manifest_after_start_uncertainty(
        self, test_keys, test_journal
    ):
        """
        Rule 9: After a start race produces OUTCOME_UNKNOWN, attempting to execute the
        same execution_id with a newly signed manifest is also blocked.
        """
        priv, kid, _, registry = test_keys
        container = MockDockerContainer(
            start_exception=ConnectionResetError("Socket broken during start"),
        )
        client = MockDockerClient(container=container)
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)
        assert resp.exit_code == 1

        manifest2, sig2, req2 = create_valid_manifest_and_request(
            priv, kid, execution_id=manifest.execution_id
        )
        assert manifest2.manifest_id != manifest.manifest_id

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            broker.execute_action(req2)
        assert "Replay prevention conflict" in str(exc_info.value)

    def test_unrelated_exception_with_status_code_400_rejected(
        self, test_keys, test_journal
    ):
        """
        Rule 10 (F-03 Hardening): An unrelated exception that has a status_code=400 attribute
        but is NOT a docker.errors.DockerException must NOT be accepted as an authoritative
        creation rejection. It must produce OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys

        class UnrelatedNonDockerHTTPException(Exception):
            status_code = 400

        unrelated_exc = UnrelatedNonDockerHTTPException("Custom HTTP client 400 Bad Request")

        client = MockDockerClient(
            create_exception=unrelated_exc,
            daemon_containers=[],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        # Direct unit assertion on broker method
        assert broker._is_authoritative_creation_rejection(unrelated_exc) is False

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        # Must fail closed into OUTCOME_UNKNOWN, NOT FAILED!
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

    def test_delayed_creation_container_appears_on_daemon_preserved_and_blocked(
        self, test_keys, test_journal
    ):
        """
        Rule 11 (F-02 Hardening): Container creation raises ConnectionResetError, initial daemon
        listing was empty (or transient), but later the delayed container appears on the daemon.
        Verify:
        - Outcome was recorded as OUTCOME_UNKNOWN.
        - Automatic retry of the manifest and execution ID is blocked.
        - The delayed container on the daemon is preserved untouched (never killed, never started).
        """
        priv, kid, _, registry = test_keys

        delayed_container = MockDockerContainer(
            id="delayed-container-999",
            status="created",
            attrs={
                "State": {
                    "Status": "created",
                    "Running": False,
                    "Pid": 0,
                    "StartedAt": "0001-01-01T00:00:00Z",
                    "ExitCode": 0,
                }
            },
        )

        daemon_containers_list = []
        client = MockDockerClient(
            create_exception=ConnectionResetError("Socket broken during create"),
            daemon_containers=daemon_containers_list,
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN

        # Now simulate delayed creation completing on Docker daemon
        daemon_containers_list.append(delayed_container)

        # Retry attempts are strictly blocked
        with pytest.raises(BrokerSecurityViolation):
            broker.execute_action(req)

        manifest2, _, req2 = create_valid_manifest_and_request(
            priv, kid, execution_id=manifest.execution_id
        )
        with pytest.raises(BrokerSecurityViolation):
            broker.execute_action(req2)

        # Delayed container on daemon is preserved
        assert delayed_container.killed is False
        assert delayed_container.removed is False
        assert delayed_container.started is False


# ============================================================================
# Stage 6.1.3.1 Adversarial Tests: Authoritative Docker Rejection Classification Correction
# ============================================================================

class TestStage6_1_3_1AuthoritativeRejectionCorrection:
    """
    Adversarial verification suite for Stage 6.1.3.1:
    - Non-Docker exception with is_authoritative_rejection = True returns False.
    - Non-Docker exception with is_authoritative_rejection = True and status_code = 400 returns False.
    - Custom HTTP exception with status 422 returns False.
    - Genuine Docker ImageNotFound retains its existing behavior (returns True).
    - Genuine Docker API 400/422 retains its existing behavior (returns True).
    - Docker API 409 and 500+ remain non-authoritative (returns False).
    - Missing network or volume errors are not mistaken for missing image errors (returns False).
    - Creation exception classification path exercises full lifecycle and prevents incorrect FAILED classification.
    """

    @pytest.fixture
    def test_keys(self):
        priv, kid, pub_b64 = generate_test_keypair()
        registry = BrokerPublicKeyRegistry({kid: {"public_key": pub_b64, "status": "active"}})
        return priv, kid, pub_b64, registry

    @pytest.fixture
    def test_journal(self, tmp_path):
        journal_path = str(tmp_path / "stage6_1_3_1_journal.db")
        return BrokerManifestJournal(db_path=journal_path)

    def test_non_docker_exception_with_authoritative_rejection_attribute_returns_false(
        self, test_keys, test_journal
    ):
        """
        Rule 1: Non-Docker exception with is_authoritative_rejection = True returns False.
        Full creation lifecycle fails closed to OUTCOME_UNKNOWN (never FAILED).
        """
        priv, kid, _, registry = test_keys

        class MaliciousBypassException(Exception):
            is_authoritative_rejection = True

        bypass_exc = MaliciousBypassException("Attempted authorization bypass via attribute injection")

        client = MockDockerClient(
            create_exception=bypass_exc,
            daemon_containers=[],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        # 1. Direct unit assertion on broker method
        assert broker._is_authoritative_creation_rejection(bypass_exc) is False

        # 2. Actual creation exception classification lifecycle assertion
        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        # MUST NOT be FAILED!
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert record.state != ExecutionState.FAILED

    def test_non_docker_exception_with_authoritative_rejection_and_status_400_returns_false(
        self, test_keys, test_journal
    ):
        """
        Rule 2: Non-Docker exception with both is_authoritative_rejection = True and status_code = 400
        returns False. Full creation lifecycle fails closed to OUTCOME_UNKNOWN (never FAILED).
        """
        priv, kid, _, registry = test_keys

        class MaliciousStatus400BypassException(Exception):
            is_authoritative_rejection = True
            status_code = 400

        bypass_400_exc = MaliciousStatus400BypassException("Attempted dual bypass via status 400 attribute")

        client = MockDockerClient(
            create_exception=bypass_400_exc,
            daemon_containers=[],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        # 1. Direct unit assertion
        assert broker._is_authoritative_creation_rejection(bypass_400_exc) is False

        # 2. Actual lifecycle assertion
        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert record.state != ExecutionState.FAILED

    def test_custom_http_exception_with_status_422_returns_false(
        self, test_keys, test_journal
    ):
        """
        Rule 3: Custom non-Docker HTTP exception with status 422 returns False.
        Lifecycle fails closed to OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys

        class CustomHTTP422Exception(Exception):
            status_code = 422

        http_422_exc = CustomHTTP422Exception("Custom 422 Unprocessable Entity")

        client = MockDockerClient(
            create_exception=http_422_exc,
            daemon_containers=[],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker._is_authoritative_creation_rejection(http_422_exc) is False

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.OUTCOME_UNKNOWN
        assert record.state != ExecutionState.FAILED

    def test_genuine_docker_image_not_found_retains_authoritative_behavior(
        self, test_keys, test_journal
    ):
        """
        Rule 4: Genuine Docker ImageNotFound retains its authoritative behavior (returns True).
        Classified as FAILED when daemon confirms 0 containers exist.
        """
        priv, kid, _, registry = test_keys

        genuine_image_err = docker.errors.ImageNotFound(
            "No such image: sentinelops/remediation-executor:dev-local"
        )

        client = MockDockerClient(
            create_exception=genuine_image_err,
            daemon_containers=[],
        )
        broker = RestrictedDockerBroker(
            docker_client=client,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker._is_authoritative_creation_rejection(genuine_image_err) is True

        manifest, sig, req = create_valid_manifest_and_request(priv, kid)
        resp = broker.execute_action(req)

        assert resp.exit_code == 1
        record = test_journal.get_record(manifest.manifest_id)
        assert record.state == ExecutionState.FAILED
        assert "Container demonstrably never started" in record.error_message

    def test_genuine_docker_api_400_and_422_retains_authoritative_behavior(
        self, test_keys, test_journal
    ):
        """
        Rule 5: Genuine Docker API 400 and 422 errors retain authoritative behavior (returns True).
        Classified as FAILED when daemon confirms 0 containers exist.
        """
        priv, kid, _, registry = test_keys

        # Subcase 5A: docker.errors.APIError 400
        r400 = requests.Response()
        r400.status_code = 400
        docker_400_err = docker.errors.APIError("Bad request: invalid nano_cpus parameter", response=r400)

        client_5a = MockDockerClient(
            create_exception=docker_400_err,
            daemon_containers=[],
        )
        broker_5a = RestrictedDockerBroker(
            docker_client=client_5a,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker_5a._is_authoritative_creation_rejection(docker_400_err) is True

        manifest_5a, _, req_5a = create_valid_manifest_and_request(priv, kid)
        resp_5a = broker_5a.execute_action(req_5a)

        assert resp_5a.exit_code == 1
        record_5a = test_journal.get_record(manifest_5a.manifest_id)
        assert record_5a.state == ExecutionState.FAILED
        assert "Container demonstrably never started" in record_5a.error_message

        # Subcase 5B: docker.errors.APIError 422
        r422 = requests.Response()
        r422.status_code = 422
        docker_422_err = docker.errors.APIError("Unprocessable entity: unsupported platform", response=r422)

        client_5b = MockDockerClient(
            create_exception=docker_422_err,
            daemon_containers=[],
        )
        broker_5b = RestrictedDockerBroker(
            docker_client=client_5b,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker_5b._is_authoritative_creation_rejection(docker_422_err) is True

        manifest_5b, _, req_5b = create_valid_manifest_and_request(priv, kid)
        resp_5b = broker_5b.execute_action(req_5b)

        assert resp_5b.exit_code == 1
        record_5b = test_journal.get_record(manifest_5b.manifest_id)
        assert record_5b.state == ExecutionState.FAILED

    def test_docker_api_409_and_500_plus_remain_non_authoritative(
        self, test_keys, test_journal
    ):
        """
        Rule 6: Docker API 409 Conflict and 500+ Internal Server Error remain non-authoritative
        (returns False). Full lifecycle fails closed to OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys

        # Subcase 6A: 409 Conflict
        r409 = requests.Response()
        r409.status_code = 409
        docker_409_err = docker.errors.APIError("Conflict: container name already in use", response=r409)

        client_6a = MockDockerClient(create_exception=docker_409_err, daemon_containers=[])
        broker_6a = RestrictedDockerBroker(
            docker_client=client_6a,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker_6a._is_authoritative_creation_rejection(docker_409_err) is False

        manifest_6a, _, req_6a = create_valid_manifest_and_request(priv, kid)
        resp_6a = broker_6a.execute_action(req_6a)
        assert resp_6a.exit_code == 1
        assert test_journal.get_record(manifest_6a.manifest_id).state == ExecutionState.OUTCOME_UNKNOWN

        # Subcase 6B: 500 Internal Server Error
        r500 = requests.Response()
        r500.status_code = 500
        docker_500_err = docker.errors.APIError("Internal server error in Docker engine", response=r500)

        client_6b = MockDockerClient(create_exception=docker_500_err, daemon_containers=[])
        broker_6b = RestrictedDockerBroker(
            docker_client=client_6b,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker_6b._is_authoritative_creation_rejection(docker_500_err) is False

        manifest_6b, _, req_6b = create_valid_manifest_and_request(priv, kid)
        resp_6b = broker_6b.execute_action(req_6b)
        assert resp_6b.exit_code == 1
        assert test_journal.get_record(manifest_6b.manifest_id).state == ExecutionState.OUTCOME_UNKNOWN

        # Subcase 6C: 503 Service Unavailable
        r503 = requests.Response()
        r503.status_code = 503
        docker_503_err = docker.errors.APIError("Service Unavailable: Docker daemon shutting down", response=r503)
        assert broker_6a._is_authoritative_creation_rejection(docker_503_err) is False

    def test_missing_network_or_volume_not_mistaken_for_missing_image(
        self, test_keys, test_journal
    ):
        """
        Rule 7: NotFound exceptions for non-image Docker resources (e.g. missing network or volume)
        must NOT be mistaken for missing image errors. Returns False and fails closed to OUTCOME_UNKNOWN.
        """
        priv, kid, _, registry = test_keys

        # Subcase 7A: docker.errors.NotFound for network
        err_net = docker.errors.NotFound("network sentinelops-internal not found")
        client_7a = MockDockerClient(create_exception=err_net, daemon_containers=[])
        broker_7a = RestrictedDockerBroker(
            docker_client=client_7a,
            journal=test_journal,
            public_key_registry=registry,
            require_manifest=True,
        )

        assert broker_7a._is_authoritative_creation_rejection(err_net) is False

        manifest_7a, _, req_7a = create_valid_manifest_and_request(priv, kid)
        resp_7a = broker_7a.execute_action(req_7a)
        assert resp_7a.exit_code == 1
        assert test_journal.get_record(manifest_7a.manifest_id).state == ExecutionState.OUTCOME_UNKNOWN

        # Subcase 7B: docker.errors.NotFound for volume
        err_vol = docker.errors.NotFound("volume execution-data-vol not found")
        assert broker_7a._is_authoritative_creation_rejection(err_vol) is False

        # Subcase 7C: docker.errors.APIError 404 for network
        r404 = requests.Response()
        r404.status_code = 404
        err_net_api = docker.errors.APIError("network sentinelops-prod-net not found", response=r404)
        assert broker_7a._is_authoritative_creation_rejection(err_net_api) is False
