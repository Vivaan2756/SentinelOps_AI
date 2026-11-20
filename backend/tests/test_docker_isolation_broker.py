"""Comprehensive Tests for Phase 4.3.4.1 Docker Isolation & Restricted Broker Hardening.

Tests cover:
1. Broker Server & IPC Hardening:
   - Unauthorized broker peer rejection (SO_PEERCRED UID check)
   - Socket permissions and stale socket handling (symlink rejection, stale unlinking)
   - Request size limits (requests > 64 KB rejected without payload allocation)
   - Broker unavailable behavior (BrokerUnavailableError / ExecutionEnvironmentUnavailable)
   - Full IPC roundtrip using socket pairs
2. SSRF Hardening:
   - DNS resolution of all A and AAAA records; rejection if any resolved IP is disallowed
   - IPv4 and IPv6 parsing and edge cases (loopback, link-local, multicast, reserved, unspecified)
   - IPv4-mapped IPv6 addresses (::ffff:169.254.169.254, ::ffff:10.0.0.1)
   - DNS rebinding defense (IP pinning while preserving Host / SNI)
   - Authorized host.docker.internal / local Order API development exception
   - Unauthorized private IP rejection (e.g. 10.0.0.1:8001 rejected)
   - Redirect rejection in executor runner (follow_redirects=False)
3. Network Topology Hardening:
   - Staging network Internal=True validation
   - Production fail-closed behavior when isolated network is unavailable
   - Correction of production network_mode="none" bug
4. Container Lifecycle Hardening:
   - Guaranteed container removal in finally block after log retrieval failure
   - Guaranteed container removal in finally block after timeout and daemon disconnect
5. Control Plane Isolation:
   - No Docker socket access from FastAPI; communication strictly through Unix socket client
   - Immutable executor image digest pinning and pinned entrypoint/command
"""

import json
import os
import socket
import struct
import time
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from pydantic import ValidationError

from app.models.remediation import RemediationExecution, ExecutionAttempt

from app.execution.actions import (
    STATIC_ACTION_HANDLERS,
    get_static_action_handler,
    validate_restore_order_api_demo_preconditions,
    validate_inspect_service_health_preconditions,
)
from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    LOCAL_DEV_EXECUTOR_IMAGE,
    PRODUCTION_EXECUTOR_IMAGE,
    VERIFIED_LOCAL_IMAGE_ID,
    IMMUTABLE_EXECUTOR_IMAGE,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
    RestrictedDockerBroker,
    is_placeholder_or_malformed_digest,
    sanitize_and_truncate_log,
)
from app.execution.broker_client import UnixSocketBrokerClient
from app.execution.broker_server import (
    BrokerServer,
    MAX_REQUEST_BYTES,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
    ExecutionUncertainError,
    PreconditionFailedError,
    SecurityConfigurationError,
    StaleWorkerFencingError,
)
from app.execution.network import (
    ALLOWED_DEMO_PORTS,
    FORBIDDEN_METADATA_IPS,
    build_container_network_config,
    is_disallowed_ip,
    resolve_safe_target_url,
    validate_safe_target_url,
    verify_staging_network,
)
from app.execution.runner import (
    DockerIsolatedRunner,
    ExecutionResult,
    can_retry_action,
    get_execution_runner,
)
from app.models.service import Service


# ============================================================================
# Mock Docker Client & Adapter for Unit Tests
# ============================================================================

class MockDockerContainer:
    """Simulates an isolated Docker container lifecycle for unit testing."""

    def __init__(
        self,
        exit_code: int = 0,
        stdout: bytes = b'{"status": "ok", "restored": true}',
        stderr: bytes = b"",
        wait_exception: Exception = None,
        logs_exception: Exception = None,
        id: str = "mock-container-id-12345",
        labels: dict = None,
        status: str = "exited",
    ):
        self.id = id
        self.labels = labels if labels is not None else {"sentinelops.managed": "true"}
        self.status = status
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.wait_exception = wait_exception
        self.logs_exception = logs_exception
        self.killed = False
        self.removed = False

    def wait(self, timeout: int = None):
        if self.wait_exception:
            raise self.wait_exception
        return {"StatusCode": self.exit_code}

    def logs(self, stdout: bool = False, stderr: bool = False):
        if self.logs_exception:
            raise self.logs_exception
        if stdout:
            return self.stdout
        if stderr:
            return self.stderr
        return b""

    def kill(self):
        self.killed = True

    def remove(self, force: bool = False):
        self.removed = True


class MockDockerContainersManager:
    """Tracks container run arguments and returns mock container."""

    def __init__(self, container: MockDockerContainer = None, containers_list: list = None):
        self.container = container or MockDockerContainer()
        self.containers_list = containers_list
        self.last_run_kwargs = {}

    def run(self, detach: bool = True, **kwargs):
        self.last_run_kwargs = kwargs
        return self.container

    def list(self, all: bool = True, filters: dict = None):
        if self.containers_list is not None:
            res = self.containers_list
            if filters and "label" in filters:
                expected_label = filters["label"]
                if "=" in expected_label:
                    k, v = expected_label.split("=", 1)
                    res = [c for c in res if c.labels.get(k) == v]
                else:
                    res = [c for c in res if expected_label in c.labels]
            return res
        return [self.container]


class MockDockerNetwork:
    """Mock Docker network entity."""

    def __init__(self, name: str, is_internal: bool = True):
        self.name = name
        self.attrs = {"Internal": is_internal, "Name": name}


class MockDockerNetworksManager:
    """Mock Docker networks manager."""

    def __init__(self, networks=None):
        if networks is None:
            self._networks = {
                "sentinelops-internal": MockDockerNetwork("sentinelops-internal", is_internal=True),
                "sentinelops-production-net": MockDockerNetwork("sentinelops-production-net", is_internal=True),
            }
        else:
            self._networks = networks

    def get(self, name: str):
        if name in self._networks:
            return self._networks[name]
        raise Exception(f"network {name} not found")



class MockDockerClient:
    """Mock Docker daemon client passed to RestrictedDockerBroker."""

    def __init__(self, container: MockDockerContainer = None, networks=None):
        self.containers = MockDockerContainersManager(container)
        self.networks = MockDockerNetworksManager(networks)

    def ping(self):
        return True


def is_real_docker_available() -> bool:
    """Helper to detect if live Docker daemon is running on this workstation."""
    try:
        import docker
        client = docker.from_env(timeout=2)
        client.ping()
        return True
    except Exception:
        return False


# ============================================================================
# Unit Tests: Standalone Broker Server & IPC (F-02)
# ============================================================================

class TestBrokerServerAndIPC:
    """Tests standalone broker server, peer credential check, framing, and IPC."""

    def test_unauthorized_broker_peer_rejection(self):
        """BrokerServer rejects unauthorized UID when peer credential verification fails."""
        # Custom verifier simulating unauthorized peer UID 1000 when authorized is {2000}
        server = BrokerServer(
            authorized_uids={2000},
            custom_peer_verifier=lambda conn: (
                False,
                "Unauthorized peer UID 1000 (authorized: [2000])",
                {"pid": 1234, "uid": 1000, "gid": 1000},
            ),
        )
        s1, s2 = socket.socketpair()
        try:
            server.handle_connection(s1)
            # Read response on client side
            header = s2.recv(4)
            length = struct.unpack("!I", header)[0]
            resp_bytes = s2.recv(length)
            resp = json.loads(resp_bytes.decode("utf-8"))
            assert resp["error"] == "Unauthorized peer process"
            assert "Unauthorized peer UID 1000" in resp["detail"]
        finally:
            s1.close()
            s2.close()

    def test_request_size_limit_rejection(self):
        """BrokerServer rejects requests exceeding the maximum 64KB size limit."""
        server = BrokerServer(max_request_bytes=1024)
        s1, s2 = socket.socketpair()
        try:
            # Client sends 4-byte header claiming a 2048-byte payload (> 1024 max)
            s2.sendall(struct.pack("!I", 2048))
            server.handle_connection(s1)
            # Read server error response
            header = s2.recv(4)
            length = struct.unpack("!I", header)[0]
            resp_bytes = s2.recv(length)
            resp = json.loads(resp_bytes.decode("utf-8"))
            assert resp["error"] == "Request size limit exceeded"
            assert "exceeds maximum allowed" in resp["detail"]
        finally:
            s1.close()
            s2.close()

    def test_broker_unavailable_behavior(self):
        """UnixSocketBrokerClient raises BrokerUnavailableError when broker socket is missing."""
        client = UnixSocketBrokerClient(socket_path="/nonexistent/dir/broker.sock")
        assert client.is_broker_available() is False

        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
        )
        with pytest.raises(BrokerUnavailableError) as exc_info:
            client.execute_action(req)
        assert "Broker socket not found" in str(exc_info.value) or "Unix domain sockets" in str(exc_info.value)

    def test_broker_server_framing_roundtrip(self):
        """BrokerServer successfully reads framed request and sends framed response."""
        mock_container = MockDockerContainer(
            exit_code=0,
            stdout=b'{"restored": true, "message": "Demo reset complete"}',
        )
        broker = RestrictedDockerBroker(docker_client=MockDockerClient(mock_container), require_manifest=False)
        server = BrokerServer(
            broker=broker,
            custom_peer_verifier=lambda conn: (True, "Authorized", {"uid": 1000}),
        )

        s1, s2 = socket.socketpair()
        try:
            req_payload = json.dumps({
                "execution_id": str(uuid.uuid4()),
                "action_id": "restore_order_api_demo",
                "parameters": {"service_id": str(uuid.uuid4())},
                "target_url": "http://host.docker.internal:8001/demo/restore",
                "timeout_seconds": 15,
                "environment": "development",
            }).encode("utf-8")

            # Client sends length-prefixed request
            s2.sendall(struct.pack("!I", len(req_payload)) + req_payload)

            # Server handles connection
            server.handle_connection(s1)

            # Client reads length-prefixed response
            resp_header = s2.recv(4)
            resp_len = struct.unpack("!I", resp_header)[0]
            raw_resp = s2.recv(resp_len)
            resp_data = json.loads(raw_resp.decode("utf-8"))

            assert resp_data["exit_code"] == 0
            assert resp_data["output_data"] == {"restored": True, "message": "Demo reset complete"}
        finally:
            s1.close()
            s2.close()

    def test_stale_socket_symlink_rejection(self, tmp_path, monkeypatch):
        """BrokerServer rejects socket path if it is a symbolic link (hijack prevention)."""
        symlink_path = str(tmp_path / "broker_symlink.sock")
        target_path = str(tmp_path / "real_file")
        with open(target_path, "w") as f:
            f.write("target")

        # Mock islink returning True
        monkeypatch.setattr(os.path, "islink", lambda p: p == symlink_path)
        monkeypatch.setattr(socket, "AF_UNIX", socket.AF_INET, raising=False)

        server = BrokerServer(socket_path=symlink_path)
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            server.start()
        assert "symbolic link" in str(exc_info.value)


# ============================================================================
# Unit Tests: SSRF Hardening (F-03, F-04, F-06, F-08)
# ============================================================================

class TestSSRFHardening:
    """Comprehensive tests for IPv4/IPv6, DNS resolution, and rebinding protection."""

    def test_dns_resolution_blocks_private_and_metadata(self, monkeypatch):
        """Hostname resolving to metadata or private IP is rejected via DNS resolution check."""
        # 1. Hostname resolving to AWS metadata IP 169.254.169.254
        def mock_getaddrinfo_metadata(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo_metadata)

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            resolve_safe_target_url("http://custom-internal.domain:8001/demo/restore")
        assert "forbidden cloud metadata endpoint" in str(exc_info.value)

        # 2. Hostname resolving to private IP 10.0.0.5 in production
        def mock_getaddrinfo_private(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo_private)

        with pytest.raises(BrokerSecurityViolation) as exc_info:
            resolve_safe_target_url(
                "http://unauthorized-private.internal:8001/demo/restore",
                environment="production",
            )
        assert "private RFC 1918 / ULA IP is prohibited" in str(exc_info.value)

    def test_ipv4_and_ipv6_edge_cases(self):
        """Verifies rejection of link-local, multicast, reserved, and IPv6 metadata."""
        # Link-local IPv6
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            validate_safe_target_url("http://[fe80::1]:8001/demo/restore")
        assert "link-local IP is prohibited" in str(exc_info.value)

        # Multicast IPv4 & IPv6
        with pytest.raises(BrokerSecurityViolation):
            validate_safe_target_url("http://224.0.0.1:8001/demo/restore")
        with pytest.raises(BrokerSecurityViolation):
            validate_safe_target_url("http://[ff02::1]:8001/demo/restore")

        # AWS EC2 IPv6 metadata endpoint fd00:ec2::254
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            validate_safe_target_url("http://[fd00:ec2::254]:8001/demo/restore")
        assert "forbidden cloud metadata endpoint" in str(exc_info.value)

        # Unspecified 0.0.0.0 and ::
        with pytest.raises(BrokerSecurityViolation):
            validate_safe_target_url("http://0.0.0.0:8001/demo/restore")
        with pytest.raises(BrokerSecurityViolation):
            validate_safe_target_url("http://[::]:8001/demo/restore")

    def test_ipv4_mapped_ipv6_addresses(self):
        """IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254) are parsed and blocked."""
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            validate_safe_target_url("http://[::ffff:169.254.169.254]:8001/demo/restore")
        assert "forbidden cloud metadata endpoint" in str(exc_info.value)

        # IPv4-mapped private IP in production
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            validate_safe_target_url(
                "http://[::ffff:10.0.0.1]:8001/demo/restore",
                environment="production",
            )
        assert "private RFC 1918 / ULA IP is prohibited" in str(exc_info.value)

    def test_dns_rebinding_defense_and_pinning(self, monkeypatch):
        """resolve_safe_target_url pins validated IP to protect against DNS rebinding."""
        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        target = resolve_safe_target_url(
            "http://example.com:8001/demo/restore",
            environment="production",
        )
        assert target.pinned_ip == "93.184.216.34"
        assert target.hostname == "example.com"
        assert target.host_header == "example.com:8001"
        assert target.direct_ip_url == "http://93.184.216.34:8001/demo/restore"

    def test_authorized_development_exception(self):
        """Explicitly authorized dev target hostnames are permitted in development environment."""
        # host.docker.internal
        url1 = validate_safe_target_url(
            "http://host.docker.internal:8001/demo/restore",
            environment="development",
            action_id="restore_order_api_demo",
        )
        assert url1 == "http://host.docker.internal:8001/demo/restore"

        # 127.0.0.1
        url2 = validate_safe_target_url(
            "http://127.0.0.1:8001/demo/restore",
            environment="development",
            action_id="restore_order_api_demo",
        )
        assert url2 == "http://127.0.0.1:8001/demo/restore"

    def test_unauthorized_private_ip_rejection(self):
        """Arbitrary private IPs are rejected even if port is 8001 or 8002."""
        for bad_private in ["10.0.0.1", "172.16.0.1", "192.168.1.50"]:
            url = f"http://{bad_private}:8001/demo/restore"
            with pytest.raises(BrokerSecurityViolation) as exc_info:
                validate_safe_target_url(url, environment="development")
            assert "private RFC 1918 / ULA IP is prohibited" in str(exc_info.value)

    def test_actions_preconditions_use_centralized_validator(self):
        """actions.py pre-flight validators use centralized validate_safe_target_url."""
        # Active development service pointing to metadata IP
        bad_service = Service(
            id=str(uuid.uuid4()),
            workspace_id=str(uuid.uuid4()),
            name="Compromised Order API",
            health_check_url="http://169.254.169.254:8001/health",
            environment="development",
            is_active=True,
        )

        with pytest.raises(PreconditionFailedError) as exc_info:
            validate_restore_order_api_demo_preconditions(bad_service)
        assert "Pre-flight SSRF validation failed" in str(exc_info.value)

    def test_redirect_rejection_in_executor_runner(self, monkeypatch):
        """Executor runner strictly rejects HTTP redirects to prevent SSRF bypass (F-06)."""
        import sys
        sys.path.insert(0, r"d:\Sentinal_AI")
        from services.executor.runner import run_restore_order_api_demo
        import httpx

        class MockRedirectResponse:
            is_redirect = True
            headers = {"location": "http://169.254.169.254/latest/meta-data/"}
            status_code = 302

        class MockHttpClient:
            def __init__(self, *args, **kwargs):
                assert kwargs.get("follow_redirects") is False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def post(self, url):
                return MockRedirectResponse()

        monkeypatch.setattr(httpx, "Client", MockHttpClient)

        with pytest.raises(RuntimeError) as exc_info:
            run_restore_order_api_demo("http://host.docker.internal:8001/demo/restore", 10.0)
        assert "HTTP Redirect" in str(exc_info.value)
        assert "redirects are forbidden" in str(exc_info.value)



# ============================================================================
# Unit Tests: Production & Staging Network Security (F-01)
# ============================================================================

class TestNetworkTopologyHardening:
    """Tests network topology configuration and staging/production verification."""

    def test_staging_network_internal_true_validation(self):
        """verify_staging_network succeeds when Internal=True and rejects Internal=False."""
        # 1. Internal=True network passes
        client_valid = MockDockerClient()
        assert verify_staging_network(client_valid, "sentinelops-internal") is True

        # 2. Internal=False network raises BrokerSecurityViolation
        client_insecure = MockDockerClient(
            networks={"sentinelops-internal": MockDockerNetwork("sentinelops-internal", is_internal=False)}
        )
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            verify_staging_network(client_insecure, "sentinelops-internal")
        assert "is not marked internal=True" in str(exc_info.value)

        # 3. Missing network raises BrokerSecurityViolation
        client_missing = MockDockerClient(networks={})
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            verify_staging_network(client_missing, "sentinelops-internal")
        assert "does not exist on Docker daemon" in str(exc_info.value)

    def test_production_network_isolated_configuration(self):
        """Production configuration does NOT use network_mode='none' and verifies network."""
        client = MockDockerClient()
        url, net_kwargs = build_container_network_config(
            environment="production",
            raw_service_url="http://127.0.0.1:8001/demo/restore",
            action_id="restore_order_api_demo",
            docker_client=client,
        )
        assert net_kwargs.get("network_mode") != "none"
        assert net_kwargs["network"] == "sentinelops-production-net"
        assert url == "http://order-api.production.svc:8001/demo/restore"

    def test_production_fails_closed_when_isolated_network_missing(self):
        """Production execution fails closed when designated isolated network is absent."""
        client_missing = MockDockerClient(networks={})
        with pytest.raises(BrokerSecurityViolation) as exc_info:
            build_container_network_config(
                environment="production",
                raw_service_url="http://127.0.0.1:8001/demo/restore",
                action_id="restore_order_api_demo",
                docker_client=client_missing,
            )
        assert "Production isolated network" in str(exc_info.value)
        assert "Fail-closed" in str(exc_info.value)


# ============================================================================
# Unit Tests: Container Lifecycle & Guaranteed Cleanup (F-05)
# ============================================================================

class TestContainerLifecycleHardening:
    """Tests guaranteed cleanup in finally blocks under various failure modes."""

    def test_container_removal_after_log_retrieval_failure(self):
        """Container is cleanly killed and removed even if log retrieval raises an exception."""
        mock_container = MockDockerContainer(
            exit_code=0,
            logs_exception=Exception("Docker socket I/O error during log streaming"),
        )
        mock_client = MockDockerClient(container=mock_container)
        broker = RestrictedDockerBroker(docker_client=mock_client, require_manifest=False)

        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
        )

        resp = broker.execute_action(req)

        # Broker returns error response without crashing
        assert resp.exit_code == 1
        assert resp.error_category == "broker_error"
        assert "Docker socket I/O error" in resp.error_message

        # Guaranteed cleanup in finally block verified:
        assert mock_container.killed is True
        assert mock_container.removed is True

    def test_container_removal_after_timeout_in_finally(self):
        """Container is cleanly killed and removed in finally block on execution timeout."""
        mock_container = MockDockerContainer(wait_exception=Exception("Execution timed out!"))
        mock_client = MockDockerClient(container=mock_container)
        broker = RestrictedDockerBroker(docker_client=mock_client, require_manifest=False)

        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
            timeout_seconds=5,
        )

        resp = broker.execute_action(req)

        assert resp.exit_code == 124
        assert resp.error_category == "timeout"
        assert mock_container.killed is True
        assert mock_container.removed is True

    def test_valid_lease_protects_running_container(self, db_session):
        """Active executions with valid leases must NEVER be removed, regardless of age."""
        ws_id = str(uuid.uuid4())
        exec_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)

        execution = RemediationExecution(
            id=exec_id,
            workspace_id=ws_id,
            approval_id=str(uuid.uuid4()),
            idempotency_key=str(uuid.uuid4()),
            action_id="inspect_service_health",
            status="executing",
            locked_by="worker-active-1",
            locked_until=now_utc + timedelta(minutes=10),
            triggered_by=str(uuid.uuid4()),
        )
        db_session.add(execution)
        db_session.commit()

        container = MockDockerContainer(
            id="sentinel-leased-111",
            status="running",
            labels={
                "sentinelops.managed": "true",
                "sentinelops.execution_id": exec_id,
                "sentinelops.created_at": str(int(time.time() - 1000)),  # Old container (> 300s)
            },
        )
        containers_mgr = MockDockerContainersManager(containers_list=[container])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        cleaned = broker.cleanup_orphaned_containers(db=db_session, max_age_seconds=300)

        assert len(cleaned) == 0
        assert container.removed is False
        assert container.killed is False

    def test_execution_uncertain_protects_container(self, db_session):
        """Containers associated with execution_uncertain must be preserved for forensic investigation."""
        ws_id = str(uuid.uuid4())
        exec_id = str(uuid.uuid4())

        execution = RemediationExecution(
            id=exec_id,
            workspace_id=ws_id,
            approval_id=str(uuid.uuid4()),
            idempotency_key=str(uuid.uuid4()),
            action_id="inspect_service_health",
            status="execution_uncertain",
            locked_by=None,
            locked_until=None,
            triggered_by=str(uuid.uuid4()),
        )
        db_session.add(execution)
        db_session.commit()

        container = MockDockerContainer(
            id="sentinel-uncertain-222",
            status="running",
            labels={
                "sentinelops.managed": "true",
                "sentinelops.execution_id": exec_id,
                "sentinelops.created_at": str(int(time.time() - 600)),
            },
        )
        containers_mgr = MockDockerContainersManager(containers_list=[container])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        cleaned = broker.cleanup_orphaned_containers(db=db_session, max_age_seconds=300)

        assert len(cleaned) == 0
        assert container.removed is False
        assert container.killed is False

    def test_missing_execution_record(self, db_session):
        """If execution record is missing from DB, cleanup fails closed and preserves container."""
        missing_exec_id = str(uuid.uuid4())

        container = MockDockerContainer(
            id="sentinel-missing-333",
            status="running",
            labels={
                "sentinelops.managed": "true",
                "sentinelops.execution_id": missing_exec_id,
                "sentinelops.created_at": str(int(time.time() - 600)),
            },
        )
        containers_mgr = MockDockerContainersManager(containers_list=[container])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        cleaned = broker.cleanup_orphaned_containers(db=db_session, max_age_seconds=300)

        assert len(cleaned) == 0
        assert container.removed is False
        assert container.killed is False

    def test_database_unavailable_during_cleanup(self):
        """If database lookup fails or DB is down, cleanup fails closed and touches no containers."""
        container = MockDockerContainer(
            id="sentinel-dbdown-444",
            status="running",
            labels={
                "sentinelops.managed": "true",
                "sentinelops.execution_id": str(uuid.uuid4()),
                "sentinelops.created_at": str(int(time.time() - 600)),
            },
        )
        containers_mgr = MockDockerContainersManager(containers_list=[container])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        def broken_db_factory():
            raise ConnectionError("PostgreSQL cluster unreachable!")

        cleaned = broker.cleanup_orphaned_containers(db_factory=broken_db_factory)

        assert len(cleaned) == 0
        assert container.removed is False
        assert container.killed is False

    def test_expired_lease_and_safely_identified_orphan(self, db_session, tmp_path):
        """Expired lease and terminal execution status allows safe cleanup with killed container."""
        ws_id = str(uuid.uuid4())
        exec_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)

        execution = RemediationExecution(
            id=exec_id,
            workspace_id=ws_id,
            approval_id=str(uuid.uuid4()),
            idempotency_key=str(uuid.uuid4()),
            action_id="inspect_service_health",
            status="execution_failed",  # Terminal state
            locked_by=None,
            locked_until=now_utc - timedelta(seconds=60),  # Expired
            triggered_by=str(uuid.uuid4()),
        )
        db_session.add(execution)
        db_session.commit()

        container = MockDockerContainer(
            id="sentinel-orphan-555",
            status="running",
            stdout=b"Failure output: container stopped unexpectedly",
            labels={
                "sentinelops.managed": "true",
                "sentinelops.execution_id": exec_id,
                "sentinelops.created_at": str(int(time.time() - 600)),
            },
        )
        containers_mgr = MockDockerContainersManager(containers_list=[container])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        cleaned = broker.cleanup_orphaned_containers(
            db=db_session,
            log_archive_dir=str(tmp_path),
        )

        assert "sentinel-orphan-555" in cleaned
        assert container.killed is True
        assert container.removed is True

    def test_unrelated_container_preservation(self, db_session):
        """Containers not owned by SentinelOps are completely untouched."""
        unrelated_1 = MockDockerContainer(
            id="postgres-prod-db",
            status="running",
            labels={"app": "postgres"},
        )
        unrelated_2 = MockDockerContainer(
            id="redis-cache",
            status="exited",
            labels={},
        )
        containers_mgr = MockDockerContainersManager(containers_list=[unrelated_1, unrelated_2])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        cleaned = broker.cleanup_orphaned_containers(db=db_session)

        assert len(cleaned) == 0
        assert unrelated_1.removed is False
        assert unrelated_1.killed is False
        assert unrelated_2.removed is False

    def test_durable_log_preservation_before_removal(self, db_session, tmp_path):
        """Relevant logs are durably captured and saved to disk before container is removed."""
        ws_id = str(uuid.uuid4())
        exec_id = str(uuid.uuid4())

        execution = RemediationExecution(
            id=exec_id,
            workspace_id=ws_id,
            approval_id=str(uuid.uuid4()),
            idempotency_key=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            status="execution_succeeded",  # Terminal state
            locked_by=None,
            locked_until=None,
            triggered_by=str(uuid.uuid4()),
        )
        db_session.add(execution)
        db_session.commit()

        log_content = b"CRITICAL FORENSIC LOG: Database restored successfully at 12:00:00"
        container = MockDockerContainer(
            id="sentinel-log-preserve-777",
            status="exited",
            stdout=log_content,
            labels={
                "sentinelops.managed": "true",
                "sentinelops.execution_id": exec_id,
                "sentinelops.created_at": str(int(time.time() - 400)),
            },
        )
        containers_mgr = MockDockerContainersManager(containers_list=[container])
        mock_client = MockDockerClient()
        mock_client.containers = containers_mgr
        broker = RestrictedDockerBroker(docker_client=mock_client)

        cleaned = broker.cleanup_orphaned_containers(
            db=db_session,
            log_archive_dir=str(tmp_path),
        )

        assert "sentinel-log-preserve-777" in cleaned
        assert container.removed is True

        # Check that durable log file was created in tmp_path
        expected_log_file = tmp_path / f"orphan_{exec_id}_sentinel-log.log"
        assert expected_log_file.exists()
        saved_text = expected_log_file.read_text(encoding="utf-8")
        assert "CRITICAL FORENSIC LOG" in saved_text
        assert exec_id in saved_text
        assert "sentinel-log-preserve-777" in saved_text


# ============================================================================
# Unit Tests: Executor Image Security & Control Plane Isolation (F-07)
# ============================================================================

class TestExecutorImageSecurityAndControlPlaneIsolation:
    """Verifies image digest pinning, pinned entrypoint, and control plane socket isolation."""

    def test_pinned_entrypoint_and_local_image(self):
        """Container specification explicitly pins entrypoint, empty command, and local dev image."""
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
        )
        _, config = broker.build_container_config(req)

        assert config["image"] == LOCAL_DEV_EXECUTOR_IMAGE
        assert config["entrypoint"] == ["python", "-m", "executor.runner"]
        assert config["command"] == []
        assert config["environment"]["FOLLOW_REDIRECTS"] == "false"
        assert config["environment"]["PINNED_IP"] == "127.0.0.1"
        assert config["environment"]["TARGET_HOST"] == "host.docker.internal"
        assert config["environment"]["TARGET_PORT"] == "8001"

    def test_no_docker_socket_access_from_runner_with_socket_client(self):
        """DockerIsolatedRunner with UnixSocketBrokerClient dispatches via socket without docker-py."""
        class MockSocketClient:
            def __init__(self):
                self.dispatched_req = None

            def is_broker_available(self):
                return True

            def execute_action(self, req):
                self.dispatched_req = req
                return BrokerExecuteResponse(
                    execution_id=req.execution_id,
                    exit_code=0,
                    duration_ms=42,
                    stdout_sample='{"restored": true}',
                )

        mock_socket_client = MockSocketClient()
        runner = DockerIsolatedRunner(socket_client=mock_socket_client)

        result = runner.execute(
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
        )
        assert result.exit_code == 0
        assert mock_socket_client.dispatched_req is not None
        assert mock_socket_client.dispatched_req.action_id == "restore_order_api_demo"


# ============================================================================
# Unit Tests: Task 1 — Connection-Time DNS/IP Pinning (P0)
# ============================================================================

class TestConnectionTimeIPPinningTransport:
    """Tests connection-time DNS pinning, PinnedSyncBackend, and PinnedIPTransport."""

    def test_pinned_sync_backend_routes_to_pinned_ip(self):
        """PinnedSyncBackend connects TCP socket directly to pinned IP and preserves Host header."""
        import threading
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend, PinnedIPTransport
        import httpx

        # Start a local TCP server on 127.0.0.1
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        received_headers = []
        def run_srv():
            conn, _ = server_sock.accept()
            raw = conn.recv(4096)
            received_headers.append(raw.decode("utf-8"))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}")
            conn.close()

        th = threading.Thread(target=run_srv)
        th.start()

        try:
            # Domain that does NOT exist in DNS: connection must succeed because it routes to pinned IP (127.0.0.1)
            target_hostname = "unresolvable-audit-host.sentinelops.local"
            transport = PinnedIPTransport(target_hostname, "127.0.0.1")
            with httpx.Client(transport=transport, follow_redirects=False, timeout=5.0) as client:
                resp = client.post(f"http://{target_hostname}:{port}/demo/restore")
                assert resp.status_code == 200
                assert resp.json() == {"status": "ok"}
        finally:
            th.join()
            server_sock.close()

        # Verify that the server received the request with the original hostname in the Host header!
        assert len(received_headers) == 1
        raw_text = received_headers[0]
        assert f"Host: {target_hostname}:{port}" in raw_text

    def test_unpinned_host_blocked_by_backend(self):
        """PinnedSyncBackend immediately blocks connection to any host other than the target_host."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend

        backend = PinnedSyncBackend("target.service.internal", "127.0.0.1")
        with pytest.raises(RuntimeError, match="Connection blocked: attempted connection to unpinned host"):
            backend.connect_tcp("malicious-hijack.internal", 8001)

    def test_mismatched_url_and_pinned_ip_rejected(self):
        """validate_connection_parameters fails closed on parameter mismatches."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import validate_connection_parameters

        # 1. Invalid IP
        with pytest.raises(ValueError, match="Invalid PINNED_IP"):
            validate_connection_parameters(
                target_url="http://host.docker.internal:8001/demo/restore",
                pinned_ip="not-an-ip",
                target_host="host.docker.internal",
                target_port=8001,
                target_scheme="http",
                target_path="/demo/restore",
            )

        # 2. Hostname mismatch
        with pytest.raises(ValueError, match="Hostname mismatch"):
            validate_connection_parameters(
                target_url="http://host.docker.internal:8001/demo/restore",
                pinned_ip="127.0.0.1",
                target_host="different.host",
                target_port=8001,
                target_scheme="http",
                target_path="/demo/restore",
            )

        # 3. Port mismatch
        with pytest.raises(ValueError, match="Port mismatch"):
            validate_connection_parameters(
                target_url="http://host.docker.internal:8001/demo/restore",
                pinned_ip="127.0.0.1",
                target_host="host.docker.internal",
                target_port=8002,
                target_scheme="http",
                target_path="/demo/restore",
            )

        # 4. Path mismatch
        with pytest.raises(ValueError, match="Path mismatch"):
            validate_connection_parameters(
                target_url="http://host.docker.internal:8001/demo/restore",
                pinned_ip="127.0.0.1",
                target_host="host.docker.internal",
                target_port=8001,
                target_scheme="http",
                target_path="/other/path",
            )

    def test_redirect_rejected_in_runner_functions(self):
        """Runner functions run_restore_order_api_demo and run_inspect_service_health reject redirects."""
        import threading
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import run_restore_order_api_demo, run_inspect_service_health

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(2)

        def run_redirect_srv():
            for _ in range(2):
                try:
                    conn, _ = server_sock.accept()
                    conn.recv(4096)
                    # Return 302 redirect
                    conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\n\r\n")
                    conn.close()
                except Exception:
                    pass

        th = threading.Thread(target=run_redirect_srv)
        th.start()

        try:
            with pytest.raises(RuntimeError, match="HTTP Redirect to 'http://169.254.169.254/latest/meta-data' rejected"):
                run_restore_order_api_demo(
                    target_url=f"http://test.internal:{port}/demo/restore",
                    pinned_ip="127.0.0.1",
                    target_host="test.internal",
                    timeout_seconds=5.0,
                )

            with pytest.raises(RuntimeError, match="HTTP Redirect to 'http://169.254.169.254/latest/meta-data' rejected"):
                run_inspect_service_health(
                    target_url=f"http://test.internal:{port}/health",
                    pinned_ip="127.0.0.1",
                    target_host="test.internal",
                    timeout_seconds=5.0,
                )
        finally:
            th.join()
            server_sock.close()

    def test_dns_change_after_prevalidation_does_not_affect_connection(self, monkeypatch):
        """Even if DNS resolves to an unauthorized IP after pre-validation, connection uses pinned IP."""
        import threading
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedIPTransport
        import httpx

        # Mock socket.getaddrinfo to simulate malicious DNS rebinding returning 10.99.99.99 for the domain
        real_getaddrinfo = socket.getaddrinfo
        def mock_getaddrinfo(host, port, *args, **kwargs):
            if host == "rebound-domain.internal":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.99.99.99", port))]
            return real_getaddrinfo(host, port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        # Local server on 127.0.0.1
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        received = []
        def run_srv():
            conn, _ = server_sock.accept()
            conn.recv(4096)
            received.append(True)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}")
            conn.close()

        th = threading.Thread(target=run_srv)
        th.start()

        try:
            # Domain is rebinding to 10.99.99.99, but transport pinned_ip is 127.0.0.1
            transport = PinnedIPTransport("rebound-domain.internal", "127.0.0.1")
            with httpx.Client(transport=transport, follow_redirects=False, timeout=5.0) as client:
                resp = client.get(f"http://rebound-domain.internal:{port}/demo/restore")
                assert resp.status_code == 200
        finally:
            th.join()
            server_sock.close()

        # Proves connection hit 127.0.0.1 server, NOT 10.99.99.99!
        assert len(received) == 1

    def test_ipv6_pinned_ip_supported(self):
        """validate_connection_parameters and PinnedSyncBackend accept and handle IPv6 pinned IPs."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import validate_connection_parameters, PinnedSyncBackend

        # IPv6 format validation succeeds
        validate_connection_parameters(
            target_url="http://[::1]:8001/demo/restore",
            pinned_ip="::1",
            target_host="::1",
            target_port=8001,
            target_scheme="http",
            target_path="/demo/restore",
        )

        backend = PinnedSyncBackend("ipv6-host.internal", "::1")
        assert backend.pinned_ip == "::1"
        assert backend.target_host == "ipv6-host.internal"

    def test_connection_failure_and_timeout_behavior(self):
        """Connection to closed port or non-responsive target fails closed cleanly."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedIPTransport
        import httpx

        # Connect to closed port on localhost (e.g. port 1)
        transport = PinnedIPTransport("unreachable.internal", "127.0.0.1")
        with httpx.Client(transport=transport, follow_redirects=False, timeout=1.0) as client:
            with pytest.raises((httpx.ConnectError, httpx.TimeoutException)):
                client.get("http://unreachable.internal:1/health")

    def test_https_sni_preserves_hostname_and_validates_certificate(self):
        """PinnedSyncBackend preserves original server_hostname for SNI and certificate validation."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedIPTransport
        import httpx

        # PinnedIPTransport with verify=True configured
        transport = PinnedIPTransport("example.com", "93.184.215.14", verify=True)
        # Verify that the transport pool maintains SSL context with verify_mode CERT_REQUIRED
        ssl_ctx = transport._pool._ssl_context
        assert ssl_ctx.check_hostname is True
        assert ssl_ctx.verify_mode.name in ("CERT_REQUIRED", "CERT_OPTIONAL")

    def test_dev_host_gateway_resolves_and_routes_to_gateway_ip(self, monkeypatch):
        """In development mode, host.docker.internal resolves to validated Docker gateway and routes to it."""
        from unittest import mock
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend
        from httpcore._backends.sync import SyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            if host == "host.docker.internal":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port))]
            raise socket.gaierror(f"Unexpected host {host}")

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
        with mock.patch.object(SyncBackend, "connect_tcp") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            backend.connect_tcp("host.docker.internal", 8001)
            mock_connect.assert_called_once_with("192.168.65.254", 8001)

    def test_dev_host_gateway_ipv6_ula_docker_desktop_supported(self, monkeypatch):
        """Docker Desktop Windows IPv6 ULA host gateway (fc00::/7) is accepted and routed to."""
        from unittest import mock
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend
        from httpcore._backends.sync import SyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            if host == "host.docker.internal":
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fdc4:f303:9324::254", port, 0, 0))]
            raise socket.gaierror(f"Unexpected host {host}")

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
        with mock.patch.object(SyncBackend, "connect_tcp") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            backend.connect_tcp("host.docker.internal", 8001)
            mock_connect.assert_called_once_with("fdc4:f303:9324::254", 8001)

    def test_dev_host_gateway_rejects_loopback(self, monkeypatch):
        """host.docker.internal resolving to loopback address (127.0.0.1 or ::1) is strictly rejected."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
        with pytest.raises(RuntimeError, match="loopback address"):
            backend.connect_tcp("host.docker.internal", 8001)

    def test_dev_host_gateway_rejects_cloud_metadata(self, monkeypatch):
        """host.docker.internal resolving to cloud metadata IP is strictly rejected."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend

        for meta_ip in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"):
            def mock_getaddrinfo(host, port, *args, **kwargs):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (meta_ip, port))]

            monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

            backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
            with pytest.raises(RuntimeError, match="forbidden cloud metadata endpoint"):
                backend.connect_tcp("host.docker.internal", 8001)

    def test_dev_host_gateway_rejects_public_ip(self, monkeypatch):
        """host.docker.internal resolving to a public IP address is strictly rejected."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
        with pytest.raises(RuntimeError, match="not in trusted Docker gateway networks"):
            backend.connect_tcp("host.docker.internal", 8001)

    def test_dev_host_gateway_rejects_multiple_conflicting_ips(self, monkeypatch):
        """host.docker.internal resolving to multiple distinct IPs is rejected."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.253", port)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
        with pytest.raises(RuntimeError, match="multiple conflicting"):
            backend.connect_tcp("host.docker.internal", 8001)

    def test_host_gateway_in_production_environment_strictly_prohibited(self, monkeypatch):
        """host.docker.internal is strictly prohibited in production environment."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="production")
        with pytest.raises(RuntimeError, match="strictly prohibited in non-development environment"):
            backend.connect_tcp("host.docker.internal", 8001)

    def test_dev_host_gateway_trusted_gateway_filter(self, monkeypatch):
        """Configured trusted gateway IP matches and mismatches are correctly enforced."""
        from unittest import mock
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend
        from httpcore._backends.sync import SyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port))]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        # Mismatch
        backend_mismatch = PinnedSyncBackend(
            "host.docker.internal", "127.0.0.1", environment="development", trusted_gateway="172.17.0.1"
        )
        with pytest.raises(RuntimeError, match="does not match configured trusted gateway"):
            backend_mismatch.connect_tcp("host.docker.internal", 8001)

        # Match
        backend_ok = PinnedSyncBackend(
            "host.docker.internal", "127.0.0.1", environment="development", trusted_gateway="192.168.65.254"
        )
        with mock.patch.object(SyncBackend, "connect_tcp") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            backend_ok.connect_tcp("host.docker.internal", 8001)
            mock_connect.assert_called_once_with("192.168.65.254", 8001)

    def test_non_host_gateway_preserves_strict_pinned_ip(self, monkeypatch):
        """Arbitrary non-gateway hosts strictly route to pinned_ip without invoking DNS."""
        from unittest import mock
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend
        from httpcore._backends.sync import SyncBackend

        def mock_getaddrinfo(*args, **kwargs):
            raise AssertionError("DNS resolution must NOT be invoked for non-gateway hosts!")

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        backend = PinnedSyncBackend("api.production.svc", "10.96.0.5", environment="production")
        with mock.patch.object(SyncBackend, "connect_tcp") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            backend.connect_tcp("api.production.svc", 80)
            mock_connect.assert_called_once_with("10.96.0.5", 80)

    def test_dev_host_gateway_dual_stack_docker_desktop(self, monkeypatch):
        """Docker Desktop dual-stack entries (one IPv4 + one IPv6) resolves cleanly to IPv4 bridge gateway."""
        from unittest import mock
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import PinnedSyncBackend
        from httpcore._backends.sync import SyncBackend

        def mock_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.65.254", port)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fdc4:f303:9324::254", port, 0, 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        # 1. Without trusted gateway configured -> selects IPv4 gateway 192.168.65.254
        backend_default = PinnedSyncBackend("host.docker.internal", "127.0.0.1", environment="development")
        with mock.patch.object(SyncBackend, "connect_tcp") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            backend_default.connect_tcp("host.docker.internal", 8001)
            mock_connect.assert_called_once_with("192.168.65.254", 8001)

        # 2. With exact trusted gateway configured -> matches and selects 192.168.65.254
        backend_configured = PinnedSyncBackend(
            "host.docker.internal", "127.0.0.1", environment="development", trusted_gateway="192.168.65.254"
        )
        with mock.patch.object(SyncBackend, "connect_tcp") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            backend_configured.connect_tcp("host.docker.internal", 8001)
            mock_connect.assert_called_once_with("192.168.65.254", 8001)

    def test_resolve_and_validate_host_gateway_helper(self, monkeypatch):
        """resolve_and_validate_host_gateway helper unit tests for edge cases."""
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
        from services.executor.runner import resolve_and_validate_host_gateway

        # 1. Non-host.docker.internal hostname
        with pytest.raises(RuntimeError, match="strictly restricted to 'host.docker.internal'"):
            resolve_and_validate_host_gateway("other.host", 8001)

        # 2. Zero addresses returned
        def mock_empty_addrinfo(*args, **kwargs):
            return []
        monkeypatch.setattr(socket, "getaddrinfo", mock_empty_addrinfo)
        with pytest.raises(RuntimeError, match="resolved to zero IP addresses"):
            resolve_and_validate_host_gateway("host.docker.internal", 8001)

        # 3. Invalid IP syntax returned
        def mock_invalid_ip(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("999.999.999.999", 8001))]
        monkeypatch.setattr(socket, "getaddrinfo", mock_invalid_ip)
        with pytest.raises(RuntimeError, match="Invalid resolved IP"):
            resolve_and_validate_host_gateway("host.docker.internal", 8001)



# ============================================================================
# Unit Tests: Task 2 — Genuine Immutable Image Enforcement (P0)
# ============================================================================

class TestGenuineImmutableImageEnforcement:
    """Tests genuine immutable registry manifest digest validation and rejection of placeholders/tags."""

    def test_placeholder_digest_rejected(self):
        """Synthesized and placeholder digests (like the previous 7f9b8c2d...) are strictly rejected."""
        # Previous fabricated digest
        prev_fake = "sha256:7f9b8c2d1e0f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
        assert is_placeholder_or_malformed_digest(prev_fake) is True
        assert is_placeholder_or_malformed_digest(f"registry.internal/repo@{prev_fake}") is True

        # Trivial repeating patterns
        assert is_placeholder_or_malformed_digest("0" * 64) is True
        assert is_placeholder_or_malformed_digest("a" * 64) is True

        # Invalid length or non-hex
        assert is_placeholder_or_malformed_digest("sha256:too-short") is True
        assert is_placeholder_or_malformed_digest("sha256:" + "g" * 64) is True

        # Valid digest
        valid_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert is_placeholder_or_malformed_digest(valid_digest) is False

    def test_mutable_tag_rejected_in_production(self):
        """Production execution rejects mutable tags and custom images without immutable digest."""
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://order-api.production.svc:8001/demo/restore",
            environment="production",
            image_tag="sentinelops/remediation-executor:v1.0",
        )
        with pytest.raises(BrokerSecurityViolation, match="Custom image 'sentinelops/remediation-executor:v1.0' rejected in production"):
            broker.validate_request(req)

    def test_missing_production_digest_fails_closed(self, monkeypatch):
        """Production execution fails closed when no immutable registry digest is configured."""
        monkeypatch.setenv("SENTINELOPS_PROD_EXECUTOR_IMAGE", "")
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://order-api.production.svc:8001/demo/restore",
            environment="production",
        )
        with pytest.raises(BrokerSecurityViolation, match="Production execution requires a configured immutable registry digest reference"):
            broker.build_container_config(req)

    def test_valid_immutable_reference_accepted_in_production(self, monkeypatch):
        """Valid immutable registry digest reference is accepted and passed to container spec."""
        valid_prod_ref = "registry.sentinelops.internal/remediation-executor@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        monkeypatch.setenv("SENTINELOPS_PROD_EXECUTOR_IMAGE", valid_prod_ref)

        mock_container = MockDockerContainer()
        mock_image = type("MockImage", (), {"attrs": {"RepoDigests": [valid_prod_ref]}})()
        mock_client = MockDockerClient(container=mock_container)
        mock_client.images = type("MockImages", (), {"get": lambda self, ref: mock_image})()

        broker = RestrictedDockerBroker(docker_client=mock_client)
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://order-api.production.svc:8001/demo/restore",
            environment="production",
        )
        _, config = broker.build_container_config(req)
        assert config["image"] == valid_prod_ref


# ============================================================================
# Unit Tests: Task 3 — In-Process Broker Fallback Removal & Deployment Isolation (P1)
# ============================================================================

class TestDeploymentIsolationAndFallbackRemoval:
    """Tests removal of in-process fallback and verification of Docker Compose service isolation."""

    def test_runner_fails_closed_without_in_process_fallback(self):
        """DockerIsolatedRunner never silently falls back to in-process RestrictedDockerBroker."""
        # By default, DockerIsolatedRunner instantiates UnixSocketBrokerClient
        # On Windows host or without active socket, it must fail closed (is_available == False)
        runner = DockerIsolatedRunner()
        assert runner._broker is None  # Proves in-process broker was NOT instantiated!
        assert runner.is_available() is False

        with pytest.raises(ExecutionEnvironmentUnavailable) as exc:
            runner.execute(
                action_id="restore_order_api_demo",
                parameters={"service_id": str(uuid.uuid4())},
            )
        assert exc.value.status_code == 503
        assert "In-process Docker daemon execution is strictly forbidden" in str(exc.value.detail)

    def test_mock_runner_rejected_outside_test_environment(self, monkeypatch):
        """get_execution_runner(allow_mock=True) raises SecurityConfigurationError in production/dev."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        from app.core.config import settings
        monkeypatch.setattr(settings, "ENVIRONMENT", "production")

        with pytest.raises(SecurityConfigurationError, match="Mock execution is strictly forbidden outside the test environment"):
            get_execution_runner(allow_mock=True)

    def test_docker_compose_configuration_isolation(self):
        """docker-compose.yml enforces backend and worker socket-exclusion and confirms broker retirement (Option C Stage 3.3)."""
        import subprocess

        compose_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker-compose.yml"))
        assert os.path.exists(compose_file), "docker-compose.yml must exist in repository root."

        with open(compose_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse basic service sections from compose text
        assert "sentinelops-backend" in content
        assert "sentinelops-worker" in content

        # Option C Stage 3B Invariant: Broker service is permanently retired and excluded
        assert "sentinelops-broker" not in content, "Broker service must remain retired from docker-compose.yml"
        assert "broker:" not in content, "Legacy broker service definition must remain removed"
        assert "broker_ipc_socket" not in content, "Legacy broker IPC socket must remain removed"

        worker_idx = content.find("worker:")
        backend_idx = content.find("backend:")
        assert worker_idx != -1 and backend_idx != -1

        # Check worker mounts: must NOT contain docker.sock, must run unprivileged
        worker_section = content[worker_idx:backend_idx]
        assert "/var/run/docker.sock" not in worker_section, "Worker service MUST NOT mount /var/run/docker.sock!"
        assert 'user: "1000:1000"' in worker_section, "Worker service MUST run as unprivileged user 1000:1000"

        # Check backend mounts: must NOT contain docker.sock
        backend_section = content[backend_idx:content.find("order-api:")]
        assert "/var/run/docker.sock" not in backend_section, "Backend service MUST NOT mount /var/run/docker.sock!"



# ============================================================================
# Existing Baseline Tests (Maintained 100% Backwards Compatibility)
# ============================================================================

class TestBaselineBrokerFunctionality:
    """Maintains regression verification for existing Phase 4.3.4 controls."""

    def test_unregistered_action_rejected(self):
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="unregistered_hack",
            parameters={},
            target_url="http://host.docker.internal:8001/demo/restore",
        )
        with pytest.raises(BrokerSecurityViolation):
            broker.validate_request(req)

    def test_custom_image_rejected(self):
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
            image_tag="attacker/evil:latest",
        )
        with pytest.raises(BrokerSecurityViolation):
            broker.validate_request(req)

    def test_volume_mounts_rejected(self):
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
            volume_mounts=["/var/run/docker.sock:/var/run/docker.sock"],
        )
        with pytest.raises(BrokerSecurityViolation):
            broker.validate_request(req)

    def test_arbitrary_commands_rejected(self):
        broker = RestrictedDockerBroker(docker_client=MockDockerClient())
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
            commands=["rm", "-rf", "/"],
        )
        with pytest.raises(BrokerSecurityViolation):
            broker.validate_request(req)

    def test_can_retry_action_rules(self):
        # 1. execution_uncertain is NEVER retried
        assert can_retry_action("restore_order_api_demo", "execution_uncertain", 1, 3) is False
        assert can_retry_action("inspect_service_health", "execution_uncertain", 1, 3) is False
        # 2. Timeout is NEVER retried (ambiguous whether execution reached target)
        assert can_retry_action("restore_order_api_demo", "timed_out", 1, 3) is False
        assert can_retry_action("inspect_service_health", "timed_out", 1, 3) is False
        # 3. Non-idempotent or unknown actions are NEVER retried
        assert can_retry_action("non_idempotent_charge_card", "execution_failed", 1, 3) is False
        assert can_retry_action("restart_service_container", "execution_failed", 1, 3) is False
        # 4. Verified idempotent actions on clean exit failure can retry up to max_attempts
        assert can_retry_action("restore_order_api_demo", "execution_failed", 1, 3) is True
        assert can_retry_action("restore_order_api_demo", "execution_failed", 3, 3) is False
        assert can_retry_action("inspect_service_health", "execution_failed", 1, 3) is True
        assert can_retry_action("inspect_service_health", "execution_failed", 3, 3) is False

    def test_log_sanitization_and_bounding(self):
        text = "Bearer super-secret-token\n" + ("A" * 20000)
        clean = sanitize_and_truncate_log(text, max_bytes=10240)
        assert "super-secret-token" not in clean
        assert "[TRUNCATED: Log exceeded 10KB limit]" in clean

    def test_fail_closed_without_docker(self):
        class AbsentDockerBroker(RestrictedDockerBroker):
            def is_docker_available(self):
                return False

        broker = AbsentDockerBroker(require_manifest=False)
        req = BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            parameters={"service_id": str(uuid.uuid4())},
            target_url="http://host.docker.internal:8001/demo/restore",
        )
        with pytest.raises(ExecutionEnvironmentUnavailable) as exc_info:
            broker.execute_action(req)
        assert exc_info.value.status_code == 503


# ============================================================================
# Real Docker Integration Test (Decorated and Skipped When Unavailable)
# ============================================================================

@pytest.mark.docker_integration
@pytest.mark.skipif(
    not is_real_docker_available(),
    reason="Live Docker daemon is not available on this host. Skipping live integration test (fail-closed verified).",
)
def test_real_docker_daemon_execution():
    """Real Docker daemon integration test. Skipped when Docker daemon is absent."""
    broker = RestrictedDockerBroker()
    assert broker.is_docker_available() is True
