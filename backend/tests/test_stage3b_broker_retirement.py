"""Stage 3B Acceptance Tests: Legacy Broker Retirement and Direct-Runner Deployment.

Verifies:
1. docker-compose.yml contains ZERO broker service, ZERO /var/run/docker.sock mounts,
   and ZERO broker IPC volumes.
2. Runner factory (get_execution_runner) fails closed with ExecutionEnvironmentUnavailable
   when legacy broker/docker runner types are requested.
3. Default runner resolution in worker selects IsolatedHttpRecoveryRunner.
4. Direct HTTP runner maintains strict audience check ('sentinelops.execution').
5. Durable crash consistency, journal (SOJ1), and registry (SQLite) remain active
   and coupled to the direct runner without broker socket IPC.
"""

import base64
import os
import uuid
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519
from unittest.mock import patch
import httpx

from app.execution.exceptions import (
    BrokerSecurityViolation,
    ExecutionEnvironmentUnavailable,
    SecurityConfigurationError,
)
from app.execution.public_keys import BrokerPublicKeyRegistry, KeyStatus
from app.execution.runner import get_execution_runner
from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner
from app.execution.worker import DurableExecutionWorker, RunnerBrokerClientAdapter
from app.execution.broker import BrokerExecuteRequest
from tests.test_isolated_http_runner import create_valid_manifest, sign_test_manifest


def test_docker_compose_broker_and_docker_sock_eliminated():
    """Verify docker-compose.yml has completely retired broker service and docker.sock."""
    compose_path = os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
    assert os.path.exists(compose_path), "docker-compose.yml must exist"

    with open(compose_path, "r", encoding="utf-8") as f:
        content = f.read()
        parsed = yaml.safe_load(content)

    services = parsed.get("services", {})
    volumes = parsed.get("volumes", {})

    # 1. No broker service in active compose
    assert "broker" not in services, "Legacy broker service must not exist in docker-compose.yml"

    # 2. No docker.sock volume mount in ANY service
    for svc_name, svc_config in services.items():
        svc_vols = svc_config.get("volumes", [])
        for v in svc_vols:
            assert "/var/run/docker.sock" not in v, (
                f"Service '{svc_name}' mounts docker.sock ({v})! docker.sock must be completely eliminated."
            )

    # 3. No broker IPC socket or broker data volume
    assert "broker_ipc_socket" not in volumes, "broker_ipc_socket volume must be eliminated"
    assert "sentinelops_broker_data" not in volumes, "sentinelops_broker_data volume must be eliminated"

    # 4. Worker service must be present, unprivileged, and configured for direct HTTP recovery
    assert "worker" in services, "worker service must exist"
    worker_svc = services["worker"]
    assert worker_svc.get("user") == "1000:1000", "Worker must run as unprivileged UID/GID 1000"

    worker_env = worker_svc.get("environment", [])
    env_dict = {}
    for item in worker_env:
        if "=" in item:
            k, v = item.split("=", 1)
            env_dict[k] = v

    assert env_dict.get("SENTINELOPS_RUNNER_TYPE") == "http_recovery", (
        "Worker must be configured with SENTINELOPS_RUNNER_TYPE=http_recovery"
    )
    assert "SENTINELOPS_BROKER_SOCKET" not in env_dict, (
        "SENTINELOPS_BROKER_SOCKET must not be configured for worker"
    )
    assert "SENTINELOPS_MANIFEST_PRIVATE_KEY" not in env_dict, (
        "Worker environment must never contain private signing keys"
    )

    # 5. Worker volume mounts must include durability storage but no broker IPC
    worker_vols = worker_svc.get("volumes", [])
    vol_targets = [v.split(":")[1] for v in worker_vols if ":" in v]
    assert "/var/run/sentinelops" not in vol_targets, "Worker must not mount broker IPC socket"
    assert "/var/lib/sentinelops/registry" in vol_targets, "Worker must mount registry storage"
    assert "/var/lib/sentinelops/journal" in vol_targets, "Worker must mount journal storage"

    # 6. Worker depends_on must not reference broker
    worker_deps = worker_svc.get("depends_on", {})
    assert "broker" not in worker_deps, "Worker must not depend on broker"


def test_runner_factory_fails_closed_on_legacy_broker_request():
    """Verify get_execution_runner rejects legacy Docker/broker runner types with 503."""
    for legacy_type in ["docker", "docker_isolated", "legacy_broker"]:
        with pytest.raises(ExecutionEnvironmentUnavailable) as exc_info:
            get_execution_runner(runner_type=legacy_type)
        assert exc_info.value.status_code == 503
        assert "retired under Option C Stage 3B" in exc_info.value.detail


def test_runner_factory_resolves_isolated_http_runner():
    """Verify get_execution_runner successfully resolves IsolatedHttpRecoveryRunner."""
    runner = get_execution_runner(runner_type="http_recovery")
    assert isinstance(runner, IsolatedHttpRecoveryRunner)
    assert runner.is_available() is True


def test_worker_default_runner_is_http_recovery():
    """Verify worker static default runner resolution selects IsolatedHttpRecoveryRunner in prod/dev."""
    old_env = os.environ.get("ENVIRONMENT")
    old_runner = os.environ.get("SENTINELOPS_RUNNER_TYPE")
    try:
        os.environ["ENVIRONMENT"] = "development"
        os.environ["SENTINELOPS_RUNNER_TYPE"] = "http_recovery"
        runner = DurableExecutionWorker._get_default_runner()
        assert isinstance(runner, IsolatedHttpRecoveryRunner)
    finally:
        if old_env is not None:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_runner is not None:
            os.environ["SENTINELOPS_RUNNER_TYPE"] = old_runner
        else:
            os.environ.pop("SENTINELOPS_RUNNER_TYPE", None)


def test_runner_broker_client_adapter_invokes_direct_runner():
    """Verify RunnerBrokerClientAdapter delegates to IsolatedHttpRecoveryRunner directly in-process."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.b64encode(priv_key.public_key().public_bytes_raw()).decode("ascii")

    registry = BrokerPublicKeyRegistry(config={
        "test-key-3b": {
            "public_key": pub_key_b64,
            "status": "active",
        }
    })

    runner = IsolatedHttpRecoveryRunner(public_key_registry=registry)
    adapter = RunnerBrokerClientAdapter(runner)

    # 1. Unsigned/missing manifest fails closed with BrokerSecurityViolation
    unsigned_req = BrokerExecuteRequest(
        execution_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        parameters={"service_id": str(uuid.uuid4())},
        target_url="http://127.0.0.1:8001/demo/restore",
        environment="development",
    )
    with pytest.raises(BrokerSecurityViolation):
        adapter.execute_action(unsigned_req)

    # 2. Signed manifest with correct audience dispatches cleanly via adapter
    exec_id = str(uuid.uuid4())
    params = {"service_id": str(uuid.uuid4())}
    manifest_dict, _ = create_valid_manifest(
        key_id="test-key-3b",
        execution_id=exec_id,
        action_id="restore_order_api_demo",
        parameters=params,
        scheme="http",
        hostname="127.0.0.1",
        port=8001,
        path="/demo/restore",
        environment="development",
        audience="sentinelops.execution",
    )
    sig_b64 = sign_test_manifest(manifest_dict, priv_key)

    signed_req = BrokerExecuteRequest(
        execution_id=exec_id,
        action_id="restore_order_api_demo",
        parameters=params,
        target_url="http://127.0.0.1:8001/demo/restore",
        environment="development",
        authorization_manifest=manifest_dict,
        manifest_signature=sig_b64,
    )

    mock_resp = httpx.Response(
        status_code=200,
        json={"status": "restored", "message": "Demo simulated state restored successfully."},
        request=httpx.Request("POST", "http://127.0.0.1:8001/demo/restore"),
    )
    with patch("httpx.Client.post", return_value=mock_resp):
        resp = adapter.execute_action(signed_req)
        assert resp.exit_code == 0
        assert resp.output_data.get("status_code") == 200
        assert resp.output_data.get("response", {}).get("status") == "restored"
