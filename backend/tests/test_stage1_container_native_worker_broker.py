"""Tests for Stage 1: Container-Native Execution Worker and Broker Hardening.

Covers:
- Worker dependency initialization (OperationRegistry, OperationJournal, DispatchCoordinator, BrokerDispatcher).
- Registry and journal path configuration.
- Verification enabled by default for demo/production execution path.
- Explicit verification disablement rejected for non-test execution.
- Invalid verification configuration rejected.
- Missing verification dependencies rejected in non-test execution.
- Broker socket permissions, GID 1000, and authorized_uids={1000} enforcement.
- Authorized UID accepted and unauthorized UID rejected via peer credential verification.
- Isolated test environment: Uses in-memory SQLite and tmp_path; never touches sentinelops_dev.
"""

import json
import os
import socket
import struct
import tempfile
import uuid
import pytest
from unittest.mock import MagicMock, patch

from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerExecuteResponse,
    RestrictedDockerBroker,
)
from app.execution.broker_dispatcher import BrokerDispatcher
from app.execution.broker_server import (
    BrokerServer,
    HEADER_STRUCT,
    MAX_REQUEST_BYTES,
)
from app.execution.dispatch_coordinator import DispatchCoordinator
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    SecurityConfigurationError,
)
from app.execution.journal import OperationJournal
from app.execution.registry import (
    DEFAULT_REGISTRY_PATH,
    OperationRegistry,
)
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
)
from app.execution.verification import PostExecutionVerificationEngine
from app.execution.worker import (
    DEFAULT_JOURNAL_DIR,
    DurableExecutionWorker,
    RunnerBrokerClientAdapter,
    _parse_bool_env,
)


class MockTestRunner(ExecutionRunnerInterface):
    """Mock runner implementing ExecutionRunnerInterface for isolated testing."""

    def __init__(self, is_avail: bool = True):
        self._is_avail = is_avail
        self.call_count = 0

    def is_available(self) -> bool:
        return self._is_avail

    def execute(self, **kwargs) -> ExecutionResult:
        self.call_count += 1
        return ExecutionResult(
            exit_code=0,
            stdout="OK",
            stderr="",
            output_data={"status": "healthy"},
            duration_ms=15,
        )


# ============================================================================
# 1. Worker Dependency Initialization Tests
# ============================================================================

def test_worker_dependency_initialization_with_explicit_paths(tmp_path, db_session):
    """Verify that DurableExecutionWorker automatically wires OperationRegistry, OperationJournal,

    DispatchCoordinator, and BrokerDispatcher using configured persistent paths.
    """
    reg_file = str(tmp_path / "custom_registry.db")
    jour_dir = str(tmp_path / "custom_journal")

    runner = MockTestRunner(is_avail=True)
    worker = DurableExecutionWorker(
        worker_id="test-worker-init",
        runner=runner,
        db_factory=lambda: db_session,
        registry_path=reg_file,
        journal_dir=jour_dir,
        enable_coordinator=True,
    )

    try:
        assert worker.coordinator is not None
        assert isinstance(worker.coordinator, DispatchCoordinator)
        assert worker.coordinator.registry.db_path == os.path.abspath(reg_file)
        assert worker.coordinator.journal.journal_dir == os.path.abspath(jour_dir)

        assert worker.broker_dispatcher is not None
        assert isinstance(worker.broker_dispatcher, BrokerDispatcher)
        assert worker.broker_dispatcher.coordinator is worker.coordinator
        assert isinstance(worker.broker_dispatcher.broker_client, RunnerBrokerClientAdapter)
    finally:
        worker.stop()


def test_worker_dependency_initialization_via_environment_variables(tmp_path, db_session, monkeypatch):
    """Verify that DurableExecutionWorker picks up OPERATION_REGISTRY_PATH and OPERATION_JOURNAL_DIR from env."""
    reg_file = str(tmp_path / "env_registry.db")
    jour_dir = str(tmp_path / "env_journal")

    monkeypatch.setenv("OPERATION_REGISTRY_PATH", reg_file)
    monkeypatch.setenv("OPERATION_JOURNAL_DIR", jour_dir)

    runner = MockTestRunner(is_avail=True)
    worker = DurableExecutionWorker(
        worker_id="test-worker-env",
        runner=runner,
        db_factory=lambda: db_session,
        enable_coordinator=True,
    )

    try:
        assert worker.coordinator is not None
        assert worker.coordinator.registry.db_path == os.path.abspath(reg_file)
        assert worker.coordinator.journal.journal_dir == os.path.abspath(jour_dir)
    finally:
        worker.stop()


def test_worker_accepts_prebuilt_registry_and_journal(tmp_path, db_session):
    """Verify that explicitly injected OperationRegistry and OperationJournal are preserved."""
    reg = OperationRegistry(db_path=str(tmp_path / "prebuilt.db"))
    jour = OperationJournal(journal_dir=str(tmp_path / "prebuilt_jour"))

    runner = MockTestRunner(is_avail=True)
    worker = DurableExecutionWorker(
        worker_id="test-worker-prebuilt",
        runner=runner,
        db_factory=lambda: db_session,
        registry=reg,
        journal=jour,
        enable_coordinator=True,
    )

    try:
        assert worker.coordinator.registry is reg
        assert worker.coordinator.journal is jour
    finally:
        worker.stop()


# ============================================================================
# 2. Strict Environment Parsing & Verification Configuration Tests
# ============================================================================

def test_parse_bool_env_strict():
    """Verify _parse_bool_env parses valid booleans and rejects invalid strings."""
    with patch.dict(os.environ, {"TEST_BOOL": "true"}):
        assert _parse_bool_env("TEST_BOOL", default=False) is True
    with patch.dict(os.environ, {"TEST_BOOL": "1"}):
        assert _parse_bool_env("TEST_BOOL", default=False) is True
    with patch.dict(os.environ, {"TEST_BOOL": "yes"}):
        assert _parse_bool_env("TEST_BOOL", default=False) is True

    with patch.dict(os.environ, {"TEST_BOOL": "false"}):
        assert _parse_bool_env("TEST_BOOL", default=True) is False
    with patch.dict(os.environ, {"TEST_BOOL": "0"}):
        assert _parse_bool_env("TEST_BOOL", default=True) is False
    with patch.dict(os.environ, {"TEST_BOOL": "no"}):
        assert _parse_bool_env("TEST_BOOL", default=True) is False

    with patch.dict(os.environ, {"TEST_BOOL": "not_a_bool"}):
        with pytest.raises(SecurityConfigurationError) as exc_info:
            _parse_bool_env("TEST_BOOL", default=True)
        assert "Invalid boolean value" in str(exc_info.value)


def test_verification_enabled_by_default_in_nontest(tmp_path, db_session, monkeypatch):
    """Verify verification is enabled by default in non-test (development/demo) execution path."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("ENABLE_VERIFICATION", raising=False)
    monkeypatch.setenv("OPERATION_REGISTRY_PATH", str(tmp_path / "dev_reg.db"))
    monkeypatch.setenv("OPERATION_JOURNAL_DIR", str(tmp_path / "dev_jour"))

    runner = MockTestRunner(is_avail=True)
    mock_verifier = MagicMock(spec=PostExecutionVerificationEngine)
    mock_verifier.run_verification_cycle = MagicMock()

    worker = DurableExecutionWorker(
        worker_id="test-worker-dev-default",
        runner=runner,
        db_factory=lambda: db_session,
        verification_engine=mock_verifier,
    )
    try:
        assert worker.enable_verification is True
    finally:
        worker.stop()


def test_explicit_verification_disablement_rejected_in_nontest(tmp_path, db_session, monkeypatch):
    """Verify non-test worker strictly refuses to start if verification is explicitly disabled via env or kwarg."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("OPERATION_REGISTRY_PATH", str(tmp_path / "dev_reg.db"))
    monkeypatch.setenv("OPERATION_JOURNAL_DIR", str(tmp_path / "dev_jour"))

    runner = MockTestRunner(is_avail=True)
    mock_verifier = MagicMock(spec=PostExecutionVerificationEngine)
    mock_verifier.run_verification_cycle = MagicMock()

    # 1. Via kwarg enable_verification=False
    with pytest.raises(SecurityConfigurationError) as exc_info:
        DurableExecutionWorker(
            worker_id="test-worker-reject-kwarg",
            runner=runner,
            db_factory=lambda: db_session,
            enable_verification=False,
            verification_engine=mock_verifier,
        )
    assert "Mandatory post-execution verification cannot be disabled" in str(exc_info.value)

    # 2. Via environment variable ENABLE_VERIFICATION=false
    monkeypatch.setenv("ENABLE_VERIFICATION", "false")
    with pytest.raises(SecurityConfigurationError) as exc_info2:
        DurableExecutionWorker(
            worker_id="test-worker-reject-env",
            runner=runner,
            db_factory=lambda: db_session,
            verification_engine=mock_verifier,
        )
    assert "Mandatory post-execution verification cannot be disabled" in str(exc_info2.value)


def test_invalid_verification_environment_value_rejected(tmp_path, db_session, monkeypatch):
    """Verify invalid ENABLE_VERIFICATION values immediately raise SecurityConfigurationError."""
    monkeypatch.setenv("ENABLE_VERIFICATION", "maybe")
    monkeypatch.setenv("OPERATION_REGISTRY_PATH", str(tmp_path / "bad_env.db"))
    monkeypatch.setenv("OPERATION_JOURNAL_DIR", str(tmp_path / "bad_env_jour"))

    runner = MockTestRunner(is_avail=True)
    with pytest.raises(SecurityConfigurationError) as exc_info:
        DurableExecutionWorker(
            runner=runner,
            db_factory=lambda: db_session,
        )
    assert "Invalid boolean value" in str(exc_info.value)


def test_missing_verification_dependencies_rejected_in_nontest(tmp_path, db_session, monkeypatch):
    """Verify non-test execution rejects invalid verification engine double lacking run_verification_cycle."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("OPERATION_REGISTRY_PATH", str(tmp_path / "prod_reg.db"))
    monkeypatch.setenv("OPERATION_JOURNAL_DIR", str(tmp_path / "prod_jour"))

    runner = MockTestRunner(is_avail=True)

    # Injected object without run_verification_cycle method
    invalid_engine = object()

    with pytest.raises(SecurityConfigurationError) as exc_info:
        DurableExecutionWorker(
            runner=runner,
            db_factory=lambda: db_session,
            verification_engine=invalid_engine,  # type: ignore[arg-type]
        )
    assert "Missing required verification dependency" in str(exc_info.value)


# ============================================================================
# 3. Broker Socket Permissions & SO_PEERCRED Security Tests
# ============================================================================

def test_broker_server_defaults_to_gid_1000_and_uid_1000():
    """Verify BrokerServer defaults to authorized_uids={1000} and socket_gid=1000."""
    server = BrokerServer()
    assert server.authorized_uids == {1000}
    assert server.socket_gid == 1000


def test_broker_server_accepts_environment_uid_and_gid_overrides(monkeypatch):
    """Verify BrokerServer respects SENTINELOPS_AUTHORIZED_UIDS and SENTINELOPS_SOCKET_GID."""
    monkeypatch.setenv("SENTINELOPS_AUTHORIZED_UIDS", "1000, 2000, 3000")
    monkeypatch.setenv("SENTINELOPS_SOCKET_GID", "2000")

    server = BrokerServer()
    assert server.authorized_uids == {1000, 2000, 3000}
    assert server.socket_gid == 2000


def test_broker_server_so_peercred_authorized_uid_accepted():
    """Verify peer credentials check passes when caller UID matches authorized_uids={1000}."""
    server = BrokerServer(
        authorized_uids={1000},
        custom_peer_verifier=lambda conn: (True, "Authorized", {"pid": 555, "uid": 1000, "gid": 1000}),
    )

    s1, s2 = socket.socketpair()
    try:
        is_auth, msg, info = server.verify_peer_credentials(s1)
        assert is_auth is True
        assert msg == "Authorized"
        assert info["uid"] == 1000
    finally:
        s1.close()
        s2.close()


def test_broker_server_so_peercred_unauthorized_uid_rejected():
    """Verify peer credentials check rejects callers with UID not in authorized_uids."""
    server = BrokerServer(
        authorized_uids={1000},
        custom_peer_verifier=lambda conn: (
            False,
            "Unauthorized peer UID 0 (authorized: [1000])",
            {"pid": 1, "uid": 0, "gid": 0},
        ),
    )

    s1, s2 = socket.socketpair()
    try:
        is_auth, msg, info = server.verify_peer_credentials(s1)
        assert is_auth is False
        assert "Unauthorized peer UID 0" in msg
    finally:
        s1.close()
        s2.close()


def test_broker_server_rejects_unauthorized_ipc_payload():
    """Verify handle_connection returns error payload when peer credentials check fails."""
    server = BrokerServer(
        authorized_uids={1000},
        custom_peer_verifier=lambda conn: (
            False,
            "Unauthorized peer UID 9999",
            {"pid": 999, "uid": 9999, "gid": 9999},
        ),
    )

    s1, s2 = socket.socketpair()
    try:
        # Server handles connection in same thread
        server.handle_connection(s1)

        # Client reads framed rejection response
        header = s2.recv(struct.calcsize(HEADER_STRUCT))
        payload_len = struct.unpack(HEADER_STRUCT, header)[0]
        payload = s2.recv(payload_len)

        resp = json.loads(payload.decode("utf-8"))
        assert resp["error"] == "Unauthorized peer process"
        assert "Unauthorized peer UID 9999" in resp["detail"]
    finally:
        s1.close()
        s2.close()
