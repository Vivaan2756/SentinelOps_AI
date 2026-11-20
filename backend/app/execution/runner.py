"""Isolated Runner Abstraction & Safety Boundaries for Phase 4.3.

Defines:
- ExecutionRunnerInterface (Protocol / ABC for future DockerIsolatedRunner)
- ExecutionResult dataclass
- MockTestRunner (strictly restricted to test environment, cannot mutate services)
- Fail-closed runner factory raising ExecutionEnvironmentUnavailable
"""

import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from app.core.config import settings
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
    ExecutionUncertainError,
    SecurityConfigurationError,
)


@dataclass
class ExecutionResult:
    """Standardized result returned by execution runners."""

    exit_code: int
    duration_ms: int
    stdout: str = ""
    stderr: str = ""
    output_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None


class ExecutionRunnerInterface(ABC):
    """Abstract interface defining the execution runner contract."""

    @abstractmethod
    def execute(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        timeout_seconds: int = 30,
        target_url: Optional[str] = None,
        environment: str = "development",
        execution_id: Optional[str] = None,
        authorization_manifest: Optional[Dict[str, Any]] = None,
        manifest_signature: Optional[str] = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """Execute an allowlisted remediation action inside the isolated sandbox."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the execution sandbox is reachable and healthy."""
        pass


class MockTestRunner(ExecutionRunnerInterface):
    """
    Deterministic in-memory mock runner strictly for CI and unit tests.

    CRITICAL SAFETY RULES:
    1. Only usable when ENVIRONMENT == 'test'. Attempting to instantiate or execute
       outside tests raises SecurityConfigurationError.
    2. CANNOT execute real mutating network requests or subprocess calls.
    3. Never used as a fallback for production or development execution.
    """

    def __init__(self, canned_result: Optional[ExecutionResult] = None):
        self._verify_test_environment()
        self._canned_result = canned_result or ExecutionResult(
            exit_code=0,
            duration_ms=45,
            stdout="MockTestRunner synthetic execution succeeded (in-memory test mock).",
            output_data={"mock_executed": True},
        )

    @staticmethod
    def _verify_test_environment() -> None:
        """Ensure runner is running strictly inside a designated test environment."""
        env_from_os = os.environ.get("ENVIRONMENT", "").lower()
        env_from_settings = getattr(settings, "ENVIRONMENT", "").lower()
        if env_from_os != "test" or env_from_settings != "test":
            raise SecurityConfigurationError(
                "MockTestRunner is strictly classified as a test mock and forbidden "
                "outside automated test environments (ENVIRONMENT != 'test'). "
                "It cannot be used as a production or development execution fallback."
            )

    def execute(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        timeout_seconds: int = 30,
        target_url: Optional[str] = None,
        environment: str = "development",
        execution_id: Optional[str] = None,
        authorization_manifest: Optional[Dict[str, Any]] = None,
        manifest_signature: Optional[str] = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """Return deterministic canned result without performing any real mutation."""
        self._verify_test_environment()
        return self._canned_result

    def is_available(self) -> bool:
        """Returns True if test environment is verified."""
        try:
            self._verify_test_environment()
            return True
        except SecurityConfigurationError:
            return False


class DockerIsolatedRunner(ExecutionRunnerInterface):
    """
    [DEPRECATED - Stage 3B Legacy Broker Retirement]
    Historical isolated execution runner delegating to RestrictedDockerBroker.
    Retained solely for unit-level compatibility with legacy broker test fixtures.
    Under Option C, direct unprivileged IsolatedHttpRecoveryRunner is the standard execution path.

    Enforces:
    - Dispatch strictly through RestrictedDockerBroker or UnixSocketBrokerClient
    - Timeout envelope bounds
    - Bounded and sanitized stdout/stderr
    - Never automatically retries uncertain mutating actions
    - Fails closed when Docker daemon or broker is unavailable
    """

    def __init__(
        self,
        broker: Optional[Any] = None,
        socket_client: Optional[Any] = None,
    ):
        from app.execution.broker_client import UnixSocketBrokerClient

        self._socket_client = socket_client
        self._broker = broker

        # Outside explicit test fixtures (where a mock/fake broker is explicitly injected),
        # runner communicates STRICTLY via UnixSocketBrokerClient.
        # Automatic fallback to in-process RestrictedDockerBroker is strictly prohibited.
        if self._socket_client is None and self._broker is None:
            self._socket_client = UnixSocketBrokerClient()

    def is_available(self) -> bool:
        """Return True only if broker IPC socket (or explicitly injected test broker) is reachable."""
        if self._broker is not None:
            return self._broker.is_docker_available()
        if self._socket_client is not None:
            return self._socket_client.is_broker_available()
        return False

    def execute(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        timeout_seconds: int = 30,
        target_url: Optional[str] = None,
        environment: str = "development",
        execution_id: Optional[str] = None,
        authorization_manifest: Optional[Dict[str, Any]] = None,
        manifest_signature: Optional[str] = None,
    ) -> ExecutionResult:
        """Dispatch action to RestrictedDockerBroker or Unix socket broker client."""
        from app.execution.broker import BrokerExecuteRequest

        if not self.is_available():
            raise ExecutionEnvironmentUnavailable(
                "Docker broker daemon IPC socket is not available at '/var/run/sentinelops/broker.sock'. "
                "In-process Docker daemon execution is strictly forbidden. "
                "Mutating remediation actions require the isolated broker service."
            )

        exec_id = execution_id or str(uuid.uuid4())
        default_url = target_url or "http://host.docker.internal:8001/demo/restore"

        req = BrokerExecuteRequest(
            execution_id=exec_id,
            action_id=action_id,
            parameters=parameters,
            target_url=default_url,
            timeout_seconds=timeout_seconds,
            environment=environment,
            authorization_manifest=authorization_manifest,
            manifest_signature=manifest_signature,
        )

        try:
            if self._socket_client is not None:
                resp = self._socket_client.execute_action(req)
            else:
                resp = self._broker.execute_action(req)
        except BrokerUnavailableError as e:
            # Broker connection dropped during execution -> uncertain outcome
            raise ExecutionUncertainError(
                f"Lost connection to execution broker during action '{action_id}'. Outcome is uncertain: {str(e)}"
            )

        return ExecutionResult(
            exit_code=resp.exit_code,
            duration_ms=resp.duration_ms,
            stdout=resp.stdout_sample,
            stderr=resp.stderr_sample,
            output_data=resp.output_data,
            error_message=resp.error_message,
            error_category=resp.error_category,
        )


# Actions whose idempotency and retry-safety have been explicitly verified
RETRY_SAFE_ACTIONS: Set[str] = {
    "inspect_service_health",      # Read-only diagnostic, fully idempotent
    "restore_order_api_demo",      # In-memory demo reset, idempotent on clean failed exit
}


def can_retry_action(
    action_id: str,
    status: str,
    attempt_count: int,
    max_attempts: int,
) -> bool:
    """
    Safety invariant: Never automatically retry an action unless its idempotency
    and retry safety are explicitly established.
    """
    # 1. Action MUST be explicitly verified as retry-safe and idempotent
    if action_id not in RETRY_SAFE_ACTIONS:
        return False

    # 2. execution_uncertain is NEVER retryable automatically
    if status == "execution_uncertain":
        return False

    # 3. Actions on timeout cannot be blindly retried (ambiguous whether execution reached target)
    if status == "timed_out":
        return False

    # 4. Standard retry if attempts remaining and clean failed exit
    if attempt_count < max_attempts and status == "execution_failed":
        return True

    return False


def get_execution_runner(
    *,
    allow_mock: bool = False,
    broker: Optional[Any] = None,
    runner_type: Optional[str] = None,
    public_key_registry: Optional[Any] = None,
) -> ExecutionRunnerInterface:
    """
    Runner factory for Option C / Stage 3.

    Safety invariants:
    - If runner_type == 'http_recovery', returns IsolatedHttpRecoveryRunner.
    - If allow_mock=True AND running strictly in test environment, returns MockTestRunner.
    - Legacy Docker execution path ('docker', 'docker_isolated', 'legacy_broker') is retired;
      fails closed with ExecutionEnvironmentUnavailable.
    - Default unconfigured runner fails closed if Docker sandbox is unavailable.
    - Under NO circumstances falls back to executing mutating actions on the host OS.
    """
    effective_runner_type = (runner_type or os.environ.get("SENTINELOPS_RUNNER_TYPE", "")).lower().strip()
    if effective_runner_type == "http_recovery":
        from app.execution.public_keys import BrokerPublicKeyRegistry
        from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner
        reg = public_key_registry or BrokerPublicKeyRegistry()
        return IsolatedHttpRecoveryRunner(public_key_registry=reg)

    if effective_runner_type in ("docker", "docker_isolated", "legacy_broker"):
        raise ExecutionEnvironmentUnavailable(
            "Legacy Docker broker execution path has been permanently retired under Option C Stage 3B. "
            "Mutating remediation actions must use the direct unprivileged IsolatedHttpRecoveryRunner. "
            "Docker socket access is no longer authorized or supported."
        )

    env_from_os = os.environ.get("ENVIRONMENT", "").lower()
    env_from_settings = getattr(settings, "ENVIRONMENT", "").lower()
    is_test_env = env_from_os == "test" and env_from_settings == "test"

    if allow_mock:
        if not is_test_env:
            raise SecurityConfigurationError("Mock execution is strictly forbidden outside the test environment.")
        return MockTestRunner()

    runner = DockerIsolatedRunner(broker=broker)
    if not runner.is_available():
        raise ExecutionEnvironmentUnavailable(
            "Docker execution sandbox is not available on this host. Mutating remediation "
            "actions require a verified isolated container environment and cannot be executed in-process."
        )

    return runner
