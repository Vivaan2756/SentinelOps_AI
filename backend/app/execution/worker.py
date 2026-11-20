"""Durable Background Execution Worker for Option C.

Consumes queued remediation executions from PostgreSQL and dispatches them
through the direct unprivileged IsolatedHttpRecoveryRunner with durable local
SOJ1 journaling, SQLite OperationRegistry tracking, and Ed25519 manifest verification.

Enforces:
1. Only approved, unexpired approvals enter execution.
2. Approval parameters remain immutable.
3. Database transactions are closed during container execution (no connection holding).
4. Monotonic fencing tokens protect against stale worker updates.
5. In-flight worker crash recovery marks outcomes as execution_uncertain (no blind retries).
6. Pre-dispatch worker crash recovery re-claims and re-validates safely.
7. Background heartbeat updates lease liveness.
8. Bounded polling and graceful shutdown.
"""

import copy
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Generator, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_dispatcher import (
    BrokerDispatcher,
    BrokerDispatchResult,
)
from app.execution.dispatch_coordinator import (
    CoordinatorConflictError,
    CoordinatorError,
    CoordinatorInvalidStateError,
    CoordinatorUncertaintyError,
    CoordinatorValidationError,
    DispatchCoordinator,
    PreDispatchState,
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
from app.execution.manager import (
    RemediationExecutionManager,
    _is_expired,
    sanitize_metadata,
)
from app.execution.journal import OperationJournal
from app.execution.registry import (
    DEFAULT_REGISTRY_PATH,
    OperationRecord,
    OperationRegistry,
    OperationStatus,
    RegistryConflictError,
    RegistryError,
)
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
    can_retry_action,
    get_execution_runner,
)
from app.execution.state_machine import ExecutionState, is_terminal_state, validate_state_transition
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
)
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.remediation.registry import ActionRegistry

logger = get_logger(__name__)

# Canonical infinite hold timestamp to block worker claims on uncertain outcomes
HOLD_EXPIRATION_TIMESTAMP = datetime(9999, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)

# Default persistent storage paths for OperationRegistry and OperationJournal
DEFAULT_JOURNAL_DIR = "/var/lib/sentinelops/journal"

SIGNING_SECRET_ENV_KEYS = (
    "SENTINELOPS_MANIFEST_PRIVATE_KEY",
    "MANIFEST_PRIVATE_KEY",
    "REMEDIATION_SIGNING_PRIVATE_KEY",
    "MANIFEST_SIGNING_PRIVATE_KEY",
)


def scrub_worker_signing_secrets() -> None:
    """
    Defense-in-depth secret isolation for execution worker (FINDING-2.1-03).
    Removes any signing private keys from worker environment upon worker process startup.
    When running embedded in the control-plane process (local demo mode),
    the control plane signing key is preserved for proposal signing.
    """
    if os.environ.get("SENTINELOPS_EMBEDDED_WORKER", "").lower() in ("true", "1", "yes"):
        return
    for k in SIGNING_SECRET_ENV_KEYS:
        if k in os.environ:
            del os.environ[k]


def sanitize_db_url(url: str) -> str:
    """Sanitize database URL by masking password component."""
    import re
    return re.sub(r":([^:@]+)@", ":***@", url)


PROHIBITED_WORKER_PASSWORDS = (
    "sentinelops_worker_password",
    "password",
    "change_me",
    "worker_password",
    "admin",
    "root",
    "123456",
)


def get_worker_db_session_factory(environment: Optional[str] = None):
    """
    Produce database session factory for worker process (FINDING-2.1-02 / Stage 3.1 / Stage 3.2 AUDIT-3.1-04).

    Enforces:
    1. In non-test environments, WORKER_DATABASE_URL is strictly mandatory.
       Administrative DATABASE_URL fallback is prohibited.
    2. Static committed passwords (e.g. 'sentinelops_worker_password') and trivial
       placeholders are rejected with SecurityConfigurationError.
    3. Worker database identity enforcement:
       When connecting to PostgreSQL, worker must authenticate strictly as the restricted
       role 'sentinelops_worker'. Prohibited identities (postgres, sentinelops_user, root, admin)
       are rejected with SecurityConfigurationError.
    4. Runtime role verification:
       When connecting to PostgreSQL, executes 'SELECT current_user;' and validates that the actual
       authenticated PostgreSQL role is 'sentinelops_worker'. Fails closed if there is a mismatch.
    5. Credentials are sanitized and never exposed in logs or exception messages.
    """
    env = (environment or os.environ.get("ENVIRONMENT", "")).strip().lower()
    is_test_env = (env == "test")
    raw_worker_db_url = os.environ.get("WORKER_DATABASE_URL", "").strip()

    if not raw_worker_db_url:
        if is_test_env:
            return SessionLocal
        raise SecurityConfigurationError(
            "Worker database credentials missing. WORKER_DATABASE_URL must be explicitly configured "
            "in non-test environments. Administrative database fallback is strictly forbidden."
        )

    # Check for committed/insecure placeholder passwords
    for prohibited in PROHIBITED_WORKER_PASSWORDS:
        if f":{prohibited}@" in raw_worker_db_url:
            raise SecurityConfigurationError(
                "Insecure or default placeholder password detected in WORKER_DATABASE_URL. "
                "A secure deployment-provided secret is required."
            )

    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    try:
        url_obj = make_url(raw_worker_db_url)
    except Exception as e:
        sanitized = sanitize_db_url(raw_worker_db_url)
        raise SecurityConfigurationError(
            f"Invalid WORKER_DATABASE_URL format '{sanitized}': {e}"
        ) from None

    # AUDIT-3.1-04 & Stage 3.3: Strict username and non-empty password enforcement
    if url_obj.drivername.startswith("postgresql"):
        username = url_obj.username
        if username != "sentinelops_worker":
            raise SecurityConfigurationError(
                f"Worker database connection must authenticate as restricted role 'sentinelops_worker'. "
                f"Prohibited or unauthorized username '{username}' rejected."
            )
        if not url_obj.password or not str(url_obj.password).strip():
            raise SecurityConfigurationError(
                "Worker database connection requires a non-empty password. "
                "WORKER_DATABASE_URL or WORKER_DB_PASSWORD must provide valid credentials. Failing closed."
            )

    connect_args = {}
    if raw_worker_db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    try:
        worker_engine = create_engine(
            raw_worker_db_url,
            pool_pre_ping=True,
            connect_args=connect_args,
        )

        # AUDIT-3.1-04: Connection-time role verification for PostgreSQL
        if url_obj.drivername.startswith("postgresql"):
            with worker_engine.connect() as conn:
                actual_user = conn.execute(text("SELECT current_user;")).scalar()
                if actual_user != "sentinelops_worker":
                    raise SecurityConfigurationError(
                        f"Worker database connection role mismatch: connected as '{actual_user}', "
                        f"but restricted role 'sentinelops_worker' is required."
                    )

        return sessionmaker(autocommit=False, autoflush=False, bind=worker_engine)
    except SecurityConfigurationError:
        raise
    except Exception as e:
        sanitized = sanitize_db_url(raw_worker_db_url)
        raise SecurityConfigurationError(
            f"Failed to initialize worker database session factory with URL '{sanitized}': {e}"
        ) from None



def _parse_bool_env(var_name: str, default: bool) -> bool:
    """Parse a boolean environment variable strictly, raising SecurityConfigurationError on invalid values."""
    raw = os.environ.get(var_name)
    if raw is None:
        return default
    val = raw.strip().lower()
    if val in ("true", "1", "yes", "t", "on"):
        return True
    if val in ("false", "0", "no", "f", "off"):
        return False
    raise SecurityConfigurationError(
        f"Invalid boolean value for environment variable '{var_name}': '{raw}'. "
        "Allowed values: 'true', 'false', '1', '0', 'yes', 'no'."
    )


class RunnerBrokerClientAdapter:
    """Adapts an ExecutionRunnerInterface into a broker client for BrokerDispatcher."""

    def __init__(self, runner: ExecutionRunnerInterface):
        self.runner = runner

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        if not self.runner.is_available():
            raise BrokerUnavailableError("Execution runner is unavailable.")

        try:
            res = self.runner.execute(
                action_id=request.action_id,
                parameters=request.parameters,
                timeout_seconds=request.timeout_seconds,
                target_url=request.target_url,
                environment=request.environment,
                execution_id=request.execution_id,
                authorization_manifest=request.authorization_manifest,
                manifest_signature=request.manifest_signature,
            )
        except TypeError as te:
            if "unexpected keyword argument" in str(te):
                res = self.runner.execute(
                    action_id=request.action_id,
                    parameters=request.parameters,
                    timeout_seconds=request.timeout_seconds,
                    target_url=request.target_url,
                    environment=request.environment,
                    execution_id=request.execution_id,
                )
            else:
                raise
        return BrokerExecuteResponse(
            execution_id=request.execution_id,
            exit_code=res.exit_code,
            duration_ms=res.duration_ms or 0,
            stdout_sample=res.stdout or "",
            stderr_sample=res.stderr or "",
            output_data=res.output_data or {},
            error_message=res.error_message,
            error_category=res.error_category,
        )


class DurableExecutionWorker:
    """
    PostgreSQL-backed durable execution worker (Option C).
    Consumes queued remediation jobs, enforces worker leases, heartbeats,
    and dispatches isolated execution via direct unprivileged IsolatedHttpRecoveryRunner.
    """

    def __init__(
        self,
        *,
        worker_id: Optional[str] = None,
        runner: Optional[ExecutionRunnerInterface] = None,
        db_factory: Optional[Callable[[], Session]] = None,
        db: Optional[Session] = None,
        poll_interval: float = 1.0,
        lease_seconds: int = 90,
        heartbeat_interval: float = 20.0,
        shutdown_grace_period: float = 30.0,
        workspace_id: Optional[str] = None,
        coordinator: Optional[DispatchCoordinator] = None,
        broker_dispatcher: Optional[BrokerDispatcher] = None,
        verification_engine: Optional[PostExecutionVerificationEngine] = None,
        enable_verification: Optional[bool] = None,
        enable_coordinator: Optional[bool] = None,
        registry: Optional[OperationRegistry] = None,
        journal: Optional[OperationJournal] = None,
        registry_path: Optional[str] = None,
        journal_dir: Optional[str] = None,
        target_execution_id: Optional[str] = None,
        one_shot: bool = False,
    ):
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.runner = runner or self._get_default_runner()
        self._external_db = db
        if self._external_db is None and db_factory is not None:
            try:
                s1 = db_factory()
                s2 = db_factory()
                if s1 is s2:
                    self._external_db = s1
                else:
                    s1.close()
                    s2.close()
            except Exception:
                pass
        self.db_factory = db_factory or get_worker_db_session_factory()
        self.poll_interval = poll_interval
        self.lease_seconds = lease_seconds
        self.heartbeat_interval = heartbeat_interval
        self.shutdown_grace_period = shutdown_grace_period
        self.workspace_id = workspace_id

        # Targeted single-execution & one-shot configuration (Stage 3B)
        self.target_execution_id = (
            target_execution_id
            if target_execution_id is not None
            else os.environ.get("TARGET_EXECUTION_ID")
        )
        if self.target_execution_id:
            self.target_execution_id = self.target_execution_id.strip()

        env_one_shot = os.environ.get("ONE_SHOT")
        if env_one_shot is not None:
            self.one_shot = _parse_bool_env("ONE_SHOT", default=False)
        else:
            self.one_shot = one_shot or bool(self.target_execution_id)

        # Determine environment
        env_from_os = os.environ.get("ENVIRONMENT")
        if env_from_os is not None:
            is_test_env = (env_from_os.strip().lower() == "test")
        else:
            env_from_settings = getattr(settings, "ENVIRONMENT", "").strip().lower()
            is_test_env = (env_from_settings == "test")

        if not is_test_env or os.environ.get("SCRUB_SIGNING_SECRETS") == "true":
            scrub_worker_signing_secrets()

        # --------------------------------------------------------------------
        # Mandatory Verification Configuration (Stage 1)
        # --------------------------------------------------------------------
        # Strict parsing of ENABLE_VERIFICATION environment variable:
        # - Default is True for demo/production paths
        # - Invalid values raise SecurityConfigurationError
        raw_env_ver = os.environ.get("ENABLE_VERIFICATION")
        if raw_env_ver is not None:
            env_ver_setting = _parse_bool_env("ENABLE_VERIFICATION", default=True)
        else:
            env_ver_setting = None

        if enable_verification is not None:
            self.enable_verification = bool(enable_verification)
        elif env_ver_setting is not None:
            self.enable_verification = env_ver_setting
        elif verification_engine is not None:
            self.enable_verification = True
        else:
            self.enable_verification = not is_test_env

        # Non-test fail-closed validation: mandatory verification cannot be disabled
        if not is_test_env:
            if not self.enable_verification:
                raise SecurityConfigurationError(
                    "Mandatory post-execution verification cannot be disabled in non-test execution environment."
                )

        # Verification engine wiring and dependency check
        self.verification_engine = verification_engine
        if self.enable_verification:
            if self.verification_engine is None:
                try:
                    from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner
                    if isinstance(self.runner, IsolatedHttpRecoveryRunner):
                        verification_runner = IsolatedHttpRecoveryRunner(
                            public_key_registry=self.runner.public_key_registry,
                            environment=self.runner.environment,
                            trusted_gateway=self.runner.trusted_gateway,
                            allow_unauthenticated_probes=True,
                        )
                    else:
                        verification_runner = self.runner
                    self.verification_engine = PostExecutionVerificationEngine(
                        runner=verification_runner,
                    )
                except Exception as e:
                    if not is_test_env:
                        raise SecurityConfigurationError(
                            f"Failed to initialize mandatory PostExecutionVerificationEngine: {e}"
                        ) from e
            elif not is_test_env and not hasattr(self.verification_engine, "run_verification_cycle"):
                raise SecurityConfigurationError(
                    f"Missing required verification dependency 'run_verification_cycle' on {type(self.verification_engine)}"
                )

        # Non-test runner availability check
        if not is_test_env:
            if self.runner is None or not hasattr(self.runner, "is_available"):
                raise SecurityConfigurationError("Valid execution runner is required in non-test environment.")

        # --------------------------------------------------------------------
        # Coordinator & Broker Dispatcher Construction
        # --------------------------------------------------------------------
        self.coordinator = coordinator
        self.broker_dispatcher = broker_dispatcher
        self._owns_coordinator = False

        if enable_coordinator is not None:
            self.enable_coordinator = enable_coordinator
        elif coordinator is not None or broker_dispatcher is not None:
            self.enable_coordinator = True
        else:
            self.enable_coordinator = (not is_test_env)

        if self.enable_coordinator:
            if self.coordinator is None:
                if self.broker_dispatcher is not None:
                    self.coordinator = self.broker_dispatcher.coordinator
                else:
                    # Resolve OperationRegistry with persistent configured path
                    if registry is not None:
                        resolved_reg = registry
                    else:
                        reg_path = registry_path or os.environ.get("OPERATION_REGISTRY_PATH", DEFAULT_REGISTRY_PATH)
                        resolved_reg = OperationRegistry(db_path=reg_path)

                    # Resolve OperationJournal with persistent configured path
                    if journal is not None:
                        resolved_jour = journal
                    else:
                        jour_dir_path = journal_dir or os.environ.get("OPERATION_JOURNAL_DIR", DEFAULT_JOURNAL_DIR)
                        resolved_jour = OperationJournal(journal_dir=jour_dir_path)

                    self.coordinator = DispatchCoordinator(
                        registry=resolved_reg,
                        journal=resolved_jour,
                    )
                    self._owns_coordinator = True
                    try:
                        self.coordinator.initialize()
                    except Exception as e:
                        if not is_test_env:
                            raise SecurityConfigurationError(
                                f"Failed to initialize DispatchCoordinator (registry/journal): {e}"
                            ) from e
                        logger.warning("Coordinator initialization warning in test environment: %s", e)

            if self.broker_dispatcher is None:
                self.broker_dispatcher = BrokerDispatcher(
                    coordinator=self.coordinator,
                    broker_client=RunnerBrokerClientAdapter(self.runner),
                )

        # Distinct shutdown event signaling the worker to halt job acquisition (stop-claiming)
        self._stop_claiming_event = threading.Event()
        self._stop_event = self._stop_claiming_event  # Backward-compatible alias
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._active_execution_id: Optional[str] = None
        self._active_fencing_token: Optional[int] = None
        self._active_dispatched: bool = False
        self._active_heartbeat_thread: Optional[threading.Thread] = None
        self._active_heartbeat_stop: Optional[threading.Event] = None

    @contextmanager
    def _get_db(self) -> Generator[Session, None, None]:
        """Yield database session, ensuring short sessions in production without closing test fixtures."""
        if self._external_db is not None:
            yield self._external_db
        else:
            session = self.db_factory()
            try:
                yield session
            finally:
                session.close()

    @staticmethod
    def _get_default_runner() -> ExecutionRunnerInterface:
        """Resolve runner, honoring test environment mock runner if configured."""
        env = os.environ.get("ENVIRONMENT", "").lower()
        if env == "test":
            try:
                return get_execution_runner(allow_mock=True)
            except Exception:
                pass

        runner_type = os.environ.get("SENTINELOPS_RUNNER_TYPE", "http_recovery").lower().strip()
        if runner_type == "http_recovery":
            return get_execution_runner(runner_type="http_recovery")
        return get_execution_runner(allow_mock=False)

    @property
    def is_running(self) -> bool:
        """Return True if worker loop is currently running."""
        return self._is_running

    @property
    def is_stop_claiming_set(self) -> bool:
        """Return True if worker has been signaled to stop claiming new jobs."""
        return self._stop_claiming_event.is_set()

    def start(self) -> None:
        """Start worker polling loop in background thread."""
        if self._is_running:
            return
        self._stop_claiming_event.clear()
        self._is_running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name=f"WorkerLoop-{self.worker_id}",
            daemon=True,
        )
        self._thread.start()
        logger.info("Worker '%s' started polling.", self.worker_id)

    def stop(self, timeout: Optional[float] = None) -> bool:
        """
        Signal graceful shutdown and wait for in-flight tasks to yield within grace period.

        Shutdown Contract:
        1. Immediately stop claiming new jobs (sets _stop_claiming_event).
        2. In-flight jobs continue running and renewing leases via heartbeat during grace period.
        3. Heartbeat thread is decoupled from _stop_claiming_event and persists until runner exits.
        4. Does not falsely mark unfinished work successful or failed.
        5. If the grace period expires, preserves execution_uncertain semantics where
           dispatch has already occurred (left for lease recovery).
        6. Does not claim graceful completion if the worker thread is still alive.

        Returns:
            True if worker thread exited cleanly within the grace period.
            False if grace period expired while worker thread remains alive.
        """
        if getattr(self, "_owns_coordinator", False) and self.coordinator:
            try:
                if hasattr(self.coordinator, "journal") and hasattr(self.coordinator.journal, "close"):
                    self.coordinator.journal.close()
            except Exception:
                pass

        if not self._is_running:
            return True

        effective_timeout = timeout if timeout is not None else self.shutdown_grace_period
        logger.info(
            "Worker '%s' stopping gracefully (grace period: %.1fs)...",
            self.worker_id,
            effective_timeout,
        )
        # 1. Immediately cease claiming new jobs
        self._stop_claiming_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=effective_timeout)

        if self._thread and self._thread.is_alive():
            logger.warning(
                "Worker '%s' shutdown grace period (%.1fs) expired while execution '%s' "
                "(token: %s, dispatched: %s) is still in progress. Worker thread remains alive; "
                "leaving in-flight execution in 'executing' for lease recovery to resolve as 'execution_uncertain'.",
                self.worker_id,
                effective_timeout,
                self._active_execution_id,
                self._active_fencing_token,
                self._active_dispatched,
            )
            return False

        if getattr(self, "_owns_coordinator", False) and self.coordinator:
            try:
                if hasattr(self.coordinator, "journal") and hasattr(self.coordinator.journal, "close"):
                    self.coordinator.journal.close()
            except Exception:
                pass

        self._is_running = False
        logger.info("Worker '%s' stopped cleanly.", self.worker_id)
        return True

    def _run_loop(self) -> None:
        """Internal worker loop polling for queued executions."""
        if self.one_shot:
            logger.info(
                "Worker '%s' running in ONE-SHOT mode (target: %s).",
                self.worker_id,
                self.target_execution_id or "next eligible",
            )
            try:
                self.run_once(execution_id=self.target_execution_id)
            except Exception as e:
                logger.error("Error during one-shot worker execution: %s", str(e), exc_info=True)
            finally:
                self._stop_claiming_event.set()
                self._is_running = False
            return

        while not self._stop_claiming_event.is_set():
            try:
                job_id = self.run_once()
                if not job_id:
                    self._stop_claiming_event.wait(self.poll_interval)
            except Exception as e:
                logger.error("Error in worker polling loop: %s", str(e), exc_info=True)
                self._stop_claiming_event.wait(self.poll_interval)
        self._is_running = False

    def run_target(self, target_execution_id: str) -> Optional[str]:
        """
        Run a single targeted execution cycle for the specified execution ID.
        Strictly enforces that ONLY target_execution_id can be claimed from PostgreSQL.
        Never polls again, never touches any other queued jobs, and exits immediately.
        Returns target_execution_id if claimed and processed, or None if the target
        was not claimable (e.g. not queued, already locked, missing, or terminal).
        """
        if not target_execution_id or not target_execution_id.strip():
            raise ValueError("target_execution_id must be a non-empty string.")
        logger.info(
            "Worker '%s' initiating targeted one-shot execution for ID: '%s'.",
            self.worker_id,
            target_execution_id.strip(),
        )
        return self.run_once(execution_id=target_execution_id.strip())

    def run_once(self, execution_id: Optional[str] = None) -> Optional[str]:
        """
        Poll and process a single eligible execution job or recover an expired lease.
        If execution_id (or self.target_execution_id) is specified, claims ONLY that
        exact execution via authoritative SQL filter.
        Returns execution_id if a job was processed/claimed, or None if queue is empty,
        target is not claimable, or if shutdown stop-claiming is active.
        """
        if self._stop_claiming_event.is_set():
            return None

        effective_target_id = execution_id or self.target_execution_id

        with self._get_db() as db:
            execution = RemediationExecutionManager.claim_next_execution(
                worker_id=self.worker_id,
                lease_seconds=self.lease_seconds,
                workspace_id=self.workspace_id,
                execution_id=effective_target_id,
                db=db,
            )
            if not execution:
                return None

            claimed_id = execution.id
            fencing_token = execution.fencing_token
            logger.info(
                "Worker '%s' claimed execution '%s' (token: %d, targeted: %s).",
                self.worker_id,
                claimed_id,
                fencing_token,
                bool(effective_target_id),
            )

        self._active_execution_id = claimed_id
        self._active_fencing_token = fencing_token
        try:
            self._process_claimed_execution(execution_id=claimed_id, fencing_token=fencing_token)
        finally:
            self._active_execution_id = None
            self._active_fencing_token = None
            self._active_dispatched = False
        return claimed_id

    def _process_claimed_execution(self, execution_id: str, fencing_token: int) -> None:
        """
        Execute full lifecycle for a claimed execution job:
        1. Pre-flight validation (short DB session)
        2. Container dispatch with background heartbeat (NO open DB transaction)
        3. Result finalization (short DB session)
        """
        # ====================================================================
        # Phase 1: Pre-flight Validation (Short DB session)
        # ====================================================================
        validation_passed = False
        action_id: str = ""
        parameters: Dict[str, Any] = {}
        timeout_seconds: int = 30
        target_url: Optional[str] = None
        target_env: str = "development"
        workspace_id: str = ""
        incident_id: Optional[str] = None
        approval_id: str = ""
        attempt_number: int = 1
        now_utc = datetime.now(timezone.utc)
        authorization_manifest: Optional[Dict[str, Any]] = None
        manifest_signature: Optional[str] = None
        manifest_id: Optional[str] = None
        manifest_digest: Optional[str] = None

        with self._get_db() as db:
            try:
                execution = (
                    db.query(RemediationExecution)
                    .filter(RemediationExecution.id == execution_id)
                    .first()
                )
                if not execution:
                    logger.error("Execution '%s' not found during validation.", execution_id)
                    return

                if execution.fencing_token != fencing_token:
                    logger.warning(
                        "Worker '%s' aborted validation: fencing token mismatch (%d != %d).",
                        self.worker_id,
                        execution.fencing_token,
                        fencing_token,
                    )
                    return

                workspace_id = execution.workspace_id
                incident_id = execution.incident_id
                action_id = execution.action_id
                approval_id = execution.approval_id
                attempt_number = execution.attempt_count
                timeout_seconds = execution.timeout_seconds
                parameters = copy.deepcopy(execution.approved_parameters or {})

                # 1. Approval validation
                approval = (
                    db.query(RemediationApproval)
                    .filter(RemediationApproval.id == execution.approval_id)
                    .first()
                )
                if not approval:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="approval_not_found",
                        message="Approval record missing or deleted.",
                    )
                    return

                if approval.approval_status != "approved":
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="approval_not_approved",
                        message=f"Approval status is '{approval.approval_status}', not 'approved'.",
                    )
                    return

                if approval.approval_status == "expired" or _is_expired(approval.expires_at, now_utc):
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="approval_expired",
                        message=f"Approval '{approval.id}' expired at {approval.expires_at}.",
                    )
                    return

                # Workspace, action, service and parameter immutability re-validation (Stage 3B requirement)
                if approval.workspace_id != execution.workspace_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="workspace_mismatch",
                        message=f"Approval workspace '{approval.workspace_id}' does not match execution workspace '{execution.workspace_id}'.",
                    )
                    return

                if approval.action_id != execution.action_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="action_mismatch",
                        message=f"Approval action '{approval.action_id}' does not match execution action '{execution.action_id}'.",
                    )
                    return

                if approval.target_service_id != execution.target_service_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="service_mismatch",
                        message=f"Approval target service '{approval.target_service_id}' does not match execution target service '{execution.target_service_id}'.",
                    )
                    return

                if approval.validated_parameters != (execution.approved_parameters or {}):
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="parameters_tampered",
                        message="Approved parameters do not match approval record. Execution aborted.",
                    )
                    return

                # Phase 2A.1 Stage 5: Authorization Manifest Pass-Through Pre-flight Validation
                # 1. Manifest and signature presence
                if execution.authorization_manifest is None or execution.manifest_signature is None:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="missing_authorization_manifest",
                        message="Execution lacks signed authorization manifest or detached signature.",
                    )
                    return

                if not isinstance(execution.authorization_manifest, dict):
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="invalid_authorization_manifest",
                        message="Authorization manifest payload must be a JSON object dictionary.",
                    )
                    return

                if not isinstance(execution.manifest_signature, str) or not execution.manifest_signature.strip():
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="missing_authorization_manifest",
                        message="Authorization manifest signature must be a non-empty string.",
                    )
                    return

                if (
                    not execution.manifest_id
                    or not execution.manifest_digest
                    or not execution.manifest_key_id
                ):
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="incomplete_authorization_data",
                        message="Execution is missing manifest_id, manifest_digest, or manifest_key_id.",
                    )
                    return

                # 2. Strict identity binding between RemediationExecution and AuthorizationManifest
                raw_manifest = execution.authorization_manifest
                if raw_manifest.get("execution_id") != execution.id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_execution_mismatch",
                        message=f"Manifest execution_id '{raw_manifest.get('execution_id')}' does not match execution id '{execution.id}'.",
                    )
                    return

                if raw_manifest.get("workspace_id") != execution.workspace_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_workspace_mismatch",
                        message=f"Manifest workspace_id '{raw_manifest.get('workspace_id')}' does not match execution workspace '{execution.workspace_id}'.",
                    )
                    return

                if raw_manifest.get("approval_id") != execution.approval_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_approval_mismatch",
                        message=f"Manifest approval_id '{raw_manifest.get('approval_id')}' does not match execution approval '{execution.approval_id}'.",
                    )
                    return

                if raw_manifest.get("action_id") != execution.action_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_action_mismatch",
                        message=f"Manifest action_id '{raw_manifest.get('action_id')}' does not match execution action '{execution.action_id}'.",
                    )
                    return

                if execution.target_service_id and raw_manifest.get("service_id") != execution.target_service_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_service_mismatch",
                        message=f"Manifest service_id '{raw_manifest.get('service_id')}' does not match execution target_service_id '{execution.target_service_id}'.",
                    )
                    return

                if raw_manifest.get("manifest_id") != execution.manifest_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_identity_mismatch",
                        message=f"Manifest manifest_id '{raw_manifest.get('manifest_id')}' does not match execution manifest_id '{execution.manifest_id}'.",
                    )
                    return

                if raw_manifest.get("key_id") != execution.manifest_key_id:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="manifest_identity_mismatch",
                        message=f"Manifest key_id '{raw_manifest.get('key_id')}' does not match execution manifest_key_id '{execution.manifest_key_id}'.",
                    )
                    return

                # 2. Target service validation
                target_service = None
                if execution.target_service_id:
                    target_service = (
                        db.query(Service)
                        .filter(Service.id == execution.target_service_id)
                        .first()
                    )
                    if not target_service or not target_service.is_active:
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="service_inactive",
                            message=f"Target service '{execution.target_service_id}' is inactive or not found.",
                        )
                        return

                    # Pre-dispatch check on service execution_policy
                    raw_policy = target_service.execution_policy
                    if raw_policy is None or not str(raw_policy).strip():
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="invalid_execution_policy",
                            message=f"Target service '{execution.target_service_id}' has null or missing execution policy. Failing closed.",
                        )
                        return
                    svc_policy = str(raw_policy).strip().lower()
                    if svc_policy not in ("demo", "approval_required", "observe_only"):
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="invalid_execution_policy",
                            message=f"Target service '{execution.target_service_id}' has invalid execution policy '{raw_policy}'. Failing closed.",
                        )
                        return
                    if svc_policy == "observe_only":
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="observe_only_policy",
                            message=f"Target service '{execution.target_service_id}' execution policy is 'observe_only'. Operational remediation cannot be dispatched.",
                        )
                        return
                    if svc_policy == "demo" and (target_service.environment or "").strip().lower() != "development":
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="demo_unsupported_environment",
                            message=f"Target service '{execution.target_service_id}' has 'demo' execution policy in unsupported environment '{target_service.environment}'.",
                        )
                        return
                    target_env = target_service.environment or "development"
                    target_url = target_service.health_check_url

                    # Service binding check: reject approval bound to another service
                    param_svc_id = (parameters or {}).get("service_id")
                    if param_svc_id and param_svc_id != target_service.id:
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="service_mismatch",
                            message=f"Parameter service_id '{param_svc_id}' does not match target service '{target_service.id}'.",
                        )
                        return

                    # Derive exact recovery URL for execute_http_recovery
                    if action_id == "execute_http_recovery":
                        from app.remediation.schemas import build_recovery_url
                        svc_rec_endpoint = getattr(target_service, "recovery_endpoint", None)
                        svc_rec_enabled = getattr(target_service, "recovery_enabled", False)
                        svc_rec_method = (getattr(target_service, "recovery_method", "POST") or "POST").upper()
                        param_path = (parameters or {}).get("recovery_path")

                        if svc_rec_endpoint:
                            if not svc_rec_enabled:
                                self._fail_execution_preflight(
                                    db=db,
                                    execution=execution,
                                    fencing_token=fencing_token,
                                    category="recovery_disabled",
                                    message=f"Recovery is disabled for service '{target_service.name}'.",
                                )
                                return
                            if param_path and param_path.strip() != svc_rec_endpoint.strip():
                                self._fail_execution_preflight(
                                    db=db,
                                    execution=execution,
                                    fencing_token=fencing_token,
                                    category="target_override_rejected",
                                    message="Execution parameters cannot override authorized service recovery endpoint.",
                                )
                                return
                            effective_path = svc_rec_endpoint
                        elif param_path:
                            effective_path = param_path
                        else:
                            self._fail_execution_preflight(
                                db=db,
                                execution=execution,
                                fencing_token=fencing_token,
                                category="missing_recovery_config",
                                message=f"Service '{target_service.name}' has no authorized recovery endpoint configured.",
                            )
                            return

                        if svc_rec_method != "POST":
                            self._fail_execution_preflight(
                                db=db,
                                execution=execution,
                                fencing_token=fencing_token,
                                category="unsupported_method",
                                message=f"Unsupported recovery method '{svc_rec_method}'. Only POST is supported.",
                            )
                            return

                        try:
                            target_url = build_recovery_url(target_service.health_check_url, effective_path)
                        except Exception as e:
                            self._fail_execution_preflight(
                                db=db,
                                execution=execution,
                                fencing_token=fencing_token,
                                category="invalid_parameters",
                                message=f"Failed to derive recovery URL: {e}",
                            )
                            return

                # 3. Parameter schema validation
                is_valid, _, err_msg = ActionRegistry.validate_parameters(action_id, parameters)
                if not is_valid:
                    self._fail_execution_preflight(
                        db=db,
                        execution=execution,
                        fencing_token=fencing_token,
                        category="invalid_parameters",
                        message=f"Approved parameters failed schema validation: {err_msg}",
                    )
                    return

                # Snapshot authorization manifest and detached signature for dispatch pass-through
                authorization_manifest = copy.deepcopy(execution.authorization_manifest)
                manifest_signature = str(execution.manifest_signature)
                manifest_id = str(execution.manifest_id)
                manifest_digest = str(execution.manifest_digest)

                # Option C Stage 2: Authoritative Cryptographic Authorization Pre-Flight Verification
                if hasattr(self.runner, "verify_authorization"):
                    try:
                        self.runner.verify_authorization(
                            action_id=action_id,
                            parameters=parameters,
                            execution_id=execution.id,
                            target_url=target_url,
                            environment=target_env,
                            authorization_manifest=authorization_manifest,
                            manifest_signature=manifest_signature,
                        )
                    except Exception as auth_err:
                        self._fail_execution_preflight(
                            db=db,
                            execution=execution,
                            fencing_token=fencing_token,
                            category="authorization_failed",
                            message=f"Manifest cryptographic authorization verification failed: {auth_err}",
                        )
                        return

                # Advance state to EXECUTING and record attempt
                now_utc = datetime.now(timezone.utc)
                execution.status = ExecutionState.EXECUTING.value
                execution.updated_at = now_utc

                attempt = ExecutionAttempt(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    attempt_number=execution.attempt_count,
                    status="running",
                    worker_id=self.worker_id,
                    fencing_token=fencing_token,
                    started_at=now_utc,
                )
                db.add(attempt)

                event = ExecutionEvent(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    workspace_id=workspace_id,
                    event_type="executing",
                    message=f"Worker '{self.worker_id}' dispatching action '{action_id}' (attempt {execution.attempt_count}).",
                    metadata_json=sanitize_metadata({
                        "action_id": action_id,
                        "attempt_number": execution.attempt_count,
                        "worker_id": self.worker_id,
                        "fencing_token": fencing_token,
                    }),
                    timestamp=now_utc,
                )
                db.add(event)
                db.commit()
                validation_passed = True
            except StaleWorkerFencingError:
                logger.warning("Fencing token conflict during validation of %s.", execution_id)
                return

        if not validation_passed:
            return

        # ====================================================================
        # Phase 2: Dispatch Execution with Lease Heartbeat (NO DB transaction held)
        # ====================================================================
        if self.enable_coordinator and self.coordinator and self.broker_dispatcher:
            # ----------------------------------------------------------------
            # Milestone E.3.4 Coordinated Dispatch Pipeline (12 Stages)
            # ----------------------------------------------------------------
            # Stage 4: Local operation reservation in SQLite OperationRegistry
            op_record: Optional[OperationRecord] = None
            try:
                op_record = self.coordinator.reserve_operation(
                    execution_id=execution_id,
                    workspace_id=workspace_id,
                    approval_id=approval_id,
                    attempt_number=attempt_number,
                    fencing_token=fencing_token,
                    metadata={"action_id": action_id, "target_url": target_url or "http://localhost/health"},
                )
            except Exception as res_err:
                logger.error("Pre-dispatch SQLite reservation failed for execution '%s': %s", execution_id, res_err)
                with self._get_db() as db:
                    self._fail_execution_preflight(
                        db=db,
                        execution_id=execution_id,
                        fencing_token=fencing_token,
                        category="pre_dispatch_persistence_failure",
                        message=f"Local registry reservation failed: {res_err}",
                    )
                return

            # Stage 5: Persist DISPATCH_PREPARED to binary OperationJournal
            try:
                _, op_record = self.coordinator.prepare_dispatch(
                    operation_id=op_record.operation_id,
                    execution_id=execution_id,
                    fencing_token=fencing_token,
                    workspace_id=workspace_id,
                    metadata={"action_id": action_id, "target_url": target_url or "http://localhost/health"},
                )
            except Exception as prep_err:
                logger.error("Pre-dispatch journal write failed for execution '%s': %s", execution_id, prep_err)
                with self._get_db() as db:
                    self._fail_execution_preflight(
                        db=db,
                        execution_id=execution_id,
                        fencing_token=fencing_token,
                        category="pre_dispatch_persistence_failure",
                        message=f"Journal DISPATCH_PREPARED write failed: {prep_err}",
                    )
                return

            # Stage 6: Revalidate database state & fencing immediately before dispatch
            pre_check_ok = False
            with self._get_db() as db:
                reval_exec = (
                    db.query(RemediationExecution)
                    .filter(RemediationExecution.id == execution_id)
                    .first()
                )
                if not reval_exec or reval_exec.fencing_token != fencing_token:
                    logger.warning(
                        "Worker '%s' aborting dispatch: fencing token mismatch on execution '%s'.",
                        self.worker_id,
                        execution_id,
                    )
                    return
                if reval_exec.status != ExecutionState.EXECUTING.value:
                    logger.warning(
                        "Worker '%s' aborting dispatch: execution '%s' status '%s' is not 'executing'.",
                        self.worker_id,
                        execution_id,
                        reval_exec.status,
                    )
                    return
                reval_app = (
                    db.query(RemediationApproval)
                    .filter(RemediationApproval.id == reval_exec.approval_id)
                    .first()
                )
                if not reval_app or reval_app.approval_status != "approved" or _is_expired(reval_app.expires_at, datetime.now(timezone.utc)):
                    logger.warning(
                        "Worker '%s' aborting dispatch: approval expired or invalidated for execution '%s'.",
                        self.worker_id,
                        execution_id,
                    )
                    self._fail_execution_preflight(
                        db=db,
                        execution_id=execution_id,
                        fencing_token=fencing_token,
                        category="approval_expired",
                        message="Approval expired immediately before dispatch.",
                    )
                    return

                if reval_exec.manifest_id != manifest_id or reval_exec.manifest_digest != manifest_digest:
                    logger.warning(
                        "Worker '%s' aborting dispatch: manifest altered on execution '%s'.",
                        self.worker_id,
                        execution_id,
                    )
                    self._fail_execution_preflight(
                        db=db,
                        execution_id=execution_id,
                        fencing_token=fencing_token,
                        category="manifest_tampered",
                        message="Authorization manifest altered between claim and dispatch.",
                    )
                    return

                pre_check_ok = True

            if not pre_check_ok:
                return

            # Stages 7-9: Start heartbeat, dispatch via BrokerDispatcher
            execution_heartbeat_stop = threading.Event()
            stale_detected = threading.Event()
            self._active_heartbeat_stop = execution_heartbeat_stop

            heartbeat_thread = threading.Thread(
                target=self._heartbeat_worker,
                args=(execution_id, fencing_token, execution_heartbeat_stop, stale_detected),
                name=f"Heartbeat-{execution_id}",
                daemon=True,
            )
            self._active_heartbeat_thread = heartbeat_thread
            heartbeat_thread.start()

            dispatch_res: Optional[BrokerDispatchResult] = None
            dispatch_exc: Optional[Exception] = None

            self._active_dispatched = True
            try:
                dispatch_res = self.broker_dispatcher.dispatch_action(
                    execution_id=execution_id,
                    workspace_id=workspace_id,
                    approval_id=approval_id,
                    attempt_number=attempt_number,
                    fencing_token=fencing_token,
                    action_id=action_id,
                    target_url=target_url or "http://localhost/health",
                    parameters=parameters,
                    timeout_seconds=timeout_seconds,
                    environment=target_env,
                    operation_id=op_record.operation_id,
                    raise_on_error=False,
                    authorization_manifest=authorization_manifest,
                    manifest_signature=manifest_signature,
                )
            except Exception as exc:
                dispatch_exc = exc
            finally:
                execution_heartbeat_stop.set()
                heartbeat_thread.join(timeout=5.0)
                self._active_heartbeat_thread = None
                self._active_heartbeat_stop = None

            # Phase 3: Finalize Outcome (Short DB session)
            if stale_detected.is_set():
                logger.critical(
                    "Worker '%s' was fenced off during execution of '%s'. Discarding result to prevent split-brain.",
                    self.worker_id,
                    execution_id,
                )
                return

            with self._get_db() as db:
                self._finalize_coordinated_outcome(
                    db=db,
                    execution_id=execution_id,
                    fencing_token=fencing_token,
                    action_id=action_id,
                    dispatch_result=dispatch_res,
                    dispatch_error=dispatch_exc,
                    timeout_seconds=timeout_seconds,
                    incident_id=incident_id,
                    workspace_id=workspace_id,
                )
            return

        # Legacy Phase 4.3.5 direct runner execution path
        # NOTE ON SHUTDOWN OWNERSHIP CONTRACT:
        # The heartbeat stop event is tied exclusively to execution lifecycle/completion
        # and fencing token loss, deliberately decoupled from self._stop_claiming_event.
        # This ensures that when worker.stop() is called, the heartbeat thread continues
        # actively renewing the lease throughout the in-flight execution during the shutdown
        # grace period until the runner finishes or ownership is lost.
        execution_heartbeat_stop = threading.Event()
        stale_detected = threading.Event()
        self._active_heartbeat_stop = execution_heartbeat_stop

        heartbeat_thread = threading.Thread(
            target=self._heartbeat_worker,
            args=(execution_id, fencing_token, execution_heartbeat_stop, stale_detected),
            name=f"Heartbeat-{execution_id}",
            daemon=True,
        )
        self._active_heartbeat_thread = heartbeat_thread
        heartbeat_thread.start()

        exec_result: Optional[ExecutionResult] = None
        exec_error: Optional[Exception] = None

        self._active_dispatched = True
        try:
            try:
                exec_result = self.runner.execute(
                    action_id=action_id,
                    parameters=parameters,
                    timeout_seconds=timeout_seconds,
                    target_url=target_url,
                    environment=target_env,
                    execution_id=execution_id,
                    authorization_manifest=authorization_manifest,
                    manifest_signature=manifest_signature,
                )
            except TypeError as te:
                if "unexpected keyword argument" in str(te):
                    exec_result = self.runner.execute(
                        action_id=action_id,
                        parameters=parameters,
                        timeout_seconds=timeout_seconds,
                        target_url=target_url,
                        environment=target_env,
                        execution_id=execution_id,
                    )
                else:
                    raise
        except Exception as exc:
            exec_error = exc
        finally:
            execution_heartbeat_stop.set()
            heartbeat_thread.join(timeout=5.0)
            self._active_heartbeat_thread = None
            self._active_heartbeat_stop = None

        # ====================================================================
        # Phase 3: Finalize Outcome (Short DB session)
        # ====================================================================
        if stale_detected.is_set():
            logger.critical(
                "Worker '%s' was fenced off during execution of '%s'. Discarding result to prevent split-brain.",
                self.worker_id,
                execution_id,
            )
            return

        with self._get_db() as db:
            self._finalize_execution_outcome(
                db=db,
                execution_id=execution_id,
                fencing_token=fencing_token,
                action_id=action_id,
                exec_result=exec_result,
                exec_error=exec_error,
                timeout_seconds=timeout_seconds,
                incident_id=incident_id,
                workspace_id=workspace_id,
            )

    def _fail_execution_preflight(
        self,
        *,
        db: Session,
        fencing_token: int,
        category: str,
        message: str,
        execution: Optional[RemediationExecution] = None,
        execution_id: Optional[str] = None,
    ) -> None:
        """Mark execution as failed during pre-flight validation."""
        if execution is None and execution_id is not None:
            execution = (
                db.query(RemediationExecution)
                .filter(RemediationExecution.id == execution_id)
                .first()
            )
        if not execution:
            return

        now_utc = datetime.now(timezone.utc)
        execution.status = ExecutionState.EXECUTION_FAILED.value
        execution.error_category = category
        execution.error_message = message
        execution.completed_at = now_utc
        execution.locked_by = None
        execution.locked_until = None
        execution.updated_at = now_utc

        event = ExecutionEvent(
            id=str(uuid.uuid4()),
            execution_id=execution.id,
            workspace_id=execution.workspace_id,
            event_type="execution_failed",
            message=f"Execution rejected in pre-flight validation ({category}): {message}",
            metadata_json=sanitize_metadata({
                "error_category": category,
                "error_message": message,
                "fencing_token": fencing_token,
            }),
            timestamp=now_utc,
        )
        db.add(event)
        db.commit()
        logger.warning(
            "Execution '%s' failed pre-flight (%s): %s",
            execution.id,
            category,
            message,
        )

    def _finalize_coordinated_outcome(
        self,
        *,
        db: Session,
        execution_id: str,
        fencing_token: int,
        action_id: str,
        dispatch_result: Optional[BrokerDispatchResult],
        dispatch_error: Optional[Exception],
        timeout_seconds: int,
        incident_id: Optional[str],
        workspace_id: str,
    ) -> None:
        """Finalize outcome for an execution dispatched through the Local Coordinator and Broker."""
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .first()
        )
        if not execution:
            return

        if execution.fencing_token != fencing_token:
            logger.critical(
                "Coordinated finalization rejected: fencing token mismatch on execution '%s' (%d != %d).",
                execution_id,
                execution.fencing_token,
                fencing_token,
            )
            return

        if execution.status != ExecutionState.EXECUTING.value:
            logger.critical(
                "Coordinated finalization rejected: execution '%s' status is '%s', not 'executing'.",
                execution_id,
                execution.status,
            )
            return

        now_utc = datetime.now(timezone.utc)
        attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution_id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )

        # --------------------------------------------------------------------
        # Outcome 1: Uncertain dispatch (timeout, disconnect, malformed response after DOCKER_CALL_STARTED)
        # --------------------------------------------------------------------
        if dispatch_error is not None or dispatch_result is None or dispatch_result.is_uncertain:
            reason = (
                dispatch_result.error_message
                if dispatch_result and dispatch_result.error_message
                else str(dispatch_error or "Unknown dispatch error after start marker")
            )
            cat = (
                dispatch_result.error_category
                if dispatch_result and dispatch_result.error_category
                else "execution_uncertain"
            )
            if attempt:
                attempt.status = "uncertain"
                attempt.completed_at = now_utc
                attempt.error_category = cat
                attempt.error_message = reason

            execution.status = ExecutionState.EXECUTION_UNCERTAIN.value
            execution.locked_by = "HOLD:EXECUTION_UNCERTAIN"
            execution.locked_until = HOLD_EXPIRATION_TIMESTAMP
            execution.completed_at = now_utc
            execution.updated_at = now_utc
            execution.error_category = cat
            execution.uncertain_reason = reason

            output_meta = execution.execution_output or {}
            output_meta["uncertainty_hold"] = {
                "hold_type": "HOLD:EXECUTION_UNCERTAIN",
                "hold_reason": reason,
                "held_at": now_utc.isoformat(),
                "original_worker_id": self.worker_id,
                "fenced_fencing_token": execution.fencing_token,
            }
            execution.execution_output = sanitize_metadata(output_meta)

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_uncertain",
                message=f"Execution reached uncertain state: {reason}",
                metadata_json=sanitize_metadata({
                    "action_id": action_id,
                    "error_category": cat,
                    "fencing_token": fencing_token,
                    "hold_type": "HOLD:EXECUTION_UNCERTAIN",
                }),
                timestamp=now_utc,
            )
            db.add(event)

            if incident_id:
                inc_event = IncidentEvent(
                    incident_id=incident_id,
                    event_type="action",
                    message=f"Remediation action '{action_id}' reached uncertain state. Incident remains active.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "action_id": action_id,
                        "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)
            db.commit()

        # --------------------------------------------------------------------
        # Outcome 2: Clean Failure (Non-zero exit code)
        # --------------------------------------------------------------------
        elif dispatch_result.exit_code != 0:
            cat = dispatch_result.error_category or "container_exit_nonzero"
            msg = dispatch_result.error_message or f"Process exited with non-zero code {dispatch_result.exit_code}."

            if attempt:
                attempt.status = "failed"
                attempt.completed_at = now_utc
                attempt.duration_ms = dispatch_result.duration_ms
                attempt.exit_code = dispatch_result.exit_code
                attempt.stdout_sample = dispatch_result.stdout
                attempt.stderr_sample = dispatch_result.stderr
                attempt.error_message = msg
                attempt.error_category = cat

            execution.status = ExecutionState.EXECUTION_FAILED.value
            execution.error_category = cat
            execution.error_message = msg
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_failed",
                message=f"Action '{action_id}' failed (exit code {dispatch_result.exit_code}): {msg}",
                metadata_json=sanitize_metadata({
                    "action_id": action_id,
                    "exit_code": dispatch_result.exit_code,
                    "error_category": cat,
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)
            db.commit()

        # --------------------------------------------------------------------
        # Outcome 3: Clean Execution Success (Exit code 0)
        # --------------------------------------------------------------------
        else:
            if attempt:
                attempt.status = "succeeded"
                attempt.completed_at = now_utc
                attempt.duration_ms = dispatch_result.duration_ms
                attempt.exit_code = 0
                attempt.stdout_sample = dispatch_result.stdout
                attempt.stderr_sample = dispatch_result.stderr

            execution.status = ExecutionState.EXECUTION_SUCCEEDED.value
            execution.execution_output = sanitize_metadata(
                dispatch_result.output_data or {"stdout": dispatch_result.stdout}
            )
            execution.completed_at = now_utc
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_succeeded",
                message=f"Action '{action_id}' executed successfully in {dispatch_result.duration_ms}ms.",
                metadata_json=sanitize_metadata({
                    "action_id": action_id,
                    "duration_ms": dispatch_result.duration_ms,
                    "exit_code": 0,
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

            if incident_id:
                inc_event = IncidentEvent(
                    incident_id=incident_id,
                    event_type="action",
                    message=f"Remediation action '{action_id}' executed successfully.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "action_id": action_id,
                        "status": ExecutionState.EXECUTION_SUCCEEDED.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)

            if self.enable_verification:
                # Stage 11: Transition to verification_pending
                validate_state_transition(execution.status, ExecutionState.VERIFICATION_PENDING.value)
                execution.status = ExecutionState.VERIFICATION_PENDING.value
                execution.verification_status = "pending"
                execution.completed_at = None
                execution.locked_by = self.worker_id
                execution.locked_until = now_utc + timedelta(seconds=self.lease_seconds)
                execution.heartbeat_at = now_utc
                execution.updated_at = now_utc

                v_pending_event = ExecutionEvent(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    workspace_id=workspace_id,
                    event_type="verification_pending",
                    message=f"Remediation '{action_id}' succeeded; starting post-execution verification.",
                    metadata_json=sanitize_metadata({
                        "action_id": action_id,
                        "worker_id": self.worker_id,
                        "fencing_token": fencing_token,
                    }),
                    timestamp=now_utc,
                )
                db.add(v_pending_event)
                db.commit()

                # Stage 12: Read-only PostExecutionVerificationEngine invocation
                engine = self.verification_engine or PostExecutionVerificationEngine(
                    runner=self.runner,
                )
                v_runner = getattr(engine, "_runner", None) or self.runner
                try:
                    summary = engine.run_verification_cycle(
                        db=db,
                        execution_id=execution.id,
                        workspace_id=workspace_id,
                        worker_id=self.worker_id,
                        fencing_token=fencing_token,
                        runner=v_runner,
                        recover_incident=True,
                    )
                    logger.info(
                        "Verification cycle finished for execution '%s': %s",
                        execution_id,
                        summary.outcome.value,
                    )
                except Exception as ver_err:
                    logger.error("Verification cycle failed for execution '%s': %s", execution_id, ver_err)
            else:
                env_check = os.environ.get("ENVIRONMENT", "").strip().lower()
                if env_check != "test":
                    raise SecurityConfigurationError(
                        "Execution cannot be finalized without verification outside the test environment."
                    )
                execution.locked_by = None
                execution.locked_until = None
                db.commit()

        logger.info(
            "Finalized coordinated execution '%s' -> status: '%s'.",
            execution_id,
            execution.status,
        )

    def _heartbeat_worker(
        self,
        execution_id: str,
        fencing_token: int,
        stop_event: threading.Event,
        stale_detected: threading.Event,
    ) -> None:
        """Background thread updating lease expiration at regular intervals."""
        while not stop_event.is_set():
            if stop_event.wait(self.heartbeat_interval):
                break
            with self._get_db() as db:
                try:
                    RemediationExecutionManager.heartbeat_lease(
                        execution_id=execution_id,
                        worker_id=self.worker_id,
                        expected_fencing_token=fencing_token,
                        lease_seconds=self.lease_seconds,
                        db=db,
                    )
                    logger.debug(
                        "Worker '%s' heartbeated execution '%s' (token: %d).",
                        self.worker_id,
                        execution_id,
                        fencing_token,
                    )
                except StaleWorkerFencingError as e:
                    logger.critical(
                        "Worker '%s' heartbeat rejected for execution '%s': %s",
                        self.worker_id,
                        execution_id,
                        str(e),
                    )
                    stale_detected.set()
                    break
                except Exception as e:
                    logger.warning("Heartbeat update failed temporarily: %s", str(e))

    def _finalize_execution_outcome(
        self,
        *,
        db: Session,
        execution_id: str,
        fencing_token: int,
        action_id: str,
        exec_result: Optional[ExecutionResult],
        exec_error: Optional[Exception],
        timeout_seconds: int,
        incident_id: Optional[str],
        workspace_id: str,
    ) -> None:
        """Commit the final execution outcome and attempts with fencing protection."""
        execution = (
            db.query(RemediationExecution)
            .filter(RemediationExecution.id == execution_id)
            .first()
        )
        if not execution:
            return

        if execution.fencing_token != fencing_token:
            logger.critical(
                "Finalization rejected: fencing token mismatch on execution '%s' (%d != %d).",
                execution_id,
                execution.fencing_token,
                fencing_token,
            )
            return

        if execution.status != ExecutionState.EXECUTING.value:
            logger.critical(
                "Finalization rejected: execution '%s' status is '%s', not 'executing'.",
                execution_id,
                execution.status,
            )
            return

        now_utc = datetime.now(timezone.utc)
        attempt = (
            db.query(ExecutionAttempt)
            .filter(
                ExecutionAttempt.execution_id == execution_id,
                ExecutionAttempt.attempt_number == execution.attempt_count,
            )
            .first()
        )

        # --------------------------------------------------------------------
        # Outcome 1: Successful Execution (Exit Code 0)
        # --------------------------------------------------------------------
        if exec_result is not None and exec_result.exit_code == 0:
            if attempt:
                attempt.status = "succeeded"
                attempt.completed_at = now_utc
                attempt.duration_ms = exec_result.duration_ms
                attempt.exit_code = 0
                attempt.stdout_sample = exec_result.stdout
                attempt.stderr_sample = exec_result.stderr

            execution.status = ExecutionState.EXECUTION_SUCCEEDED.value
            execution.execution_output = sanitize_metadata(
                exec_result.output_data or {"stdout": exec_result.stdout}
            )
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_succeeded",
                message=f"Action '{action_id}' executed successfully in {exec_result.duration_ms}ms.",
                metadata_json=sanitize_metadata({
                    "action_id": action_id,
                    "duration_ms": exec_result.duration_ms,
                    "exit_code": 0,
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

            if incident_id:
                inc_event = IncidentEvent(
                    incident_id=incident_id,
                    event_type="action",
                    message=f"Remediation action '{action_id}' executed successfully.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "action_id": action_id,
                        "status": ExecutionState.EXECUTION_SUCCEEDED.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)

        # --------------------------------------------------------------------
        # Outcome 2: Clean Failure (Non-zero Exit Code)
        # --------------------------------------------------------------------
        elif exec_result is not None and exec_result.exit_code != 0:
            category = exec_result.error_category or "container_exit_nonzero"
            msg = exec_result.error_message or f"Process exited with non-zero code {exec_result.exit_code}."

            if attempt:
                attempt.status = "failed"
                attempt.completed_at = now_utc
                attempt.duration_ms = exec_result.duration_ms
                attempt.exit_code = exec_result.exit_code
                attempt.stdout_sample = exec_result.stdout
                attempt.stderr_sample = exec_result.stderr
                attempt.error_message = msg
                attempt.error_category = category

            execution.status = ExecutionState.EXECUTION_FAILED.value
            execution.error_category = category
            execution.error_message = msg
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_failed",
                message=f"Action '{action_id}' failed (exit code {exec_result.exit_code}): {msg}",
                metadata_json=sanitize_metadata({
                    "action_id": action_id,
                    "exit_code": exec_result.exit_code,
                    "error_category": category,
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

            # Check if retry safety allows queuing next attempt
            if can_retry_action(action_id, ExecutionState.EXECUTION_FAILED.value, execution.attempt_count, execution.max_attempts):
                execution.status = ExecutionState.QUEUED.value
                execution.completed_at = None
                retry_event = ExecutionEvent(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    workspace_id=workspace_id,
                    event_type="retry_scheduled",
                    message=f"Execution attempt {execution.attempt_count} failed; re-queued for retry.",
                    metadata_json=sanitize_metadata({
                        "attempt_count": execution.attempt_count,
                        "max_attempts": execution.max_attempts,
                    }),
                    timestamp=now_utc,
                )
                db.add(retry_event)

        # --------------------------------------------------------------------
        # Outcome 3: Execution Uncertainty (Broker disconnect / ambiguous error)
        # --------------------------------------------------------------------
        elif isinstance(exec_error, ExecutionUncertainError):
            uncertain_msg = str(exec_error)
            if attempt:
                attempt.status = "uncertain"
                attempt.completed_at = now_utc
                attempt.error_category = "execution_uncertain"
                attempt.error_message = uncertain_msg

            execution.status = ExecutionState.EXECUTION_UNCERTAIN.value
            execution.error_category = "execution_uncertain"
            execution.uncertain_reason = uncertain_msg
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_uncertain",
                message=f"Execution reached uncertain state: {uncertain_msg}",
                metadata_json=sanitize_metadata({
                    "action_id": action_id,
                    "error_category": "execution_uncertain",
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

            if incident_id:
                inc_event = IncidentEvent(
                    incident_id=incident_id,
                    event_type="action",
                    message=f"Remediation action '{action_id}' reached uncertain state.",
                    metadata_json=json.dumps({
                        "execution_id": execution.id,
                        "action_id": action_id,
                        "status": ExecutionState.EXECUTION_UNCERTAIN.value,
                    }),
                    timestamp=now_utc,
                )
                db.add(inc_event)

        # --------------------------------------------------------------------
        # Outcome 4: Timeout Error
        # --------------------------------------------------------------------
        elif isinstance(exec_error, TimeoutError) or (
            exec_result and exec_result.error_category == "timeout"
        ):
            timeout_msg = f"Execution timed out after {timeout_seconds} seconds."
            if attempt:
                attempt.status = "timed_out"
                attempt.completed_at = now_utc
                attempt.error_category = "timeout"
                attempt.error_message = timeout_msg

            execution.status = ExecutionState.TIMED_OUT.value
            execution.error_category = "timeout"
            execution.error_message = timeout_msg
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="timed_out",
                message=timeout_msg,
                metadata_json=sanitize_metadata({
                    "timeout_seconds": timeout_seconds,
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

        # --------------------------------------------------------------------
        # Outcome 5: Broker Unavailable / Environment Failure
        # --------------------------------------------------------------------
        elif isinstance(exec_error, (ExecutionEnvironmentUnavailable, BrokerUnavailableError)):
            unavailable_msg = str(exec_error)
            if attempt:
                attempt.status = "failed"
                attempt.completed_at = now_utc
                attempt.error_category = "broker_unavailable"
                attempt.error_message = unavailable_msg

            execution.status = ExecutionState.EXECUTION_FAILED.value
            execution.error_category = "broker_unavailable"
            execution.error_message = unavailable_msg
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_failed",
                message=f"Execution environment unavailable: {unavailable_msg}",
                metadata_json=sanitize_metadata({
                    "error_category": "broker_unavailable",
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

        # --------------------------------------------------------------------
        # Outcome 6: General / Unexpected Exception -> Mark Uncertain
        # --------------------------------------------------------------------
        else:
            unexpected_msg = f"Unexpected exception during execution: {str(exec_error)}"
            if attempt:
                attempt.status = "uncertain"
                attempt.completed_at = now_utc
                attempt.error_category = "unexpected_error"
                attempt.error_message = unexpected_msg

            execution.status = ExecutionState.EXECUTION_UNCERTAIN.value
            execution.error_category = "unexpected_error"
            execution.uncertain_reason = unexpected_msg
            execution.completed_at = now_utc
            execution.locked_by = None
            execution.locked_until = None
            execution.updated_at = now_utc

            event = ExecutionEvent(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                workspace_id=workspace_id,
                event_type="execution_uncertain",
                message=unexpected_msg,
                metadata_json=sanitize_metadata({
                    "error_category": "unexpected_error",
                    "fencing_token": fencing_token,
                }),
                timestamp=now_utc,
            )
            db.add(event)

        db.commit()
        logger.info(
            "Finalized execution '%s' -> status: '%s'.",
            execution_id,
            execution.status,
        )


# Backward-compatible alias
ExecutionWorker = DurableExecutionWorker


def main() -> None:
    """CLI entrypoint for standalone worker process."""
    scrub_worker_signing_secrets()
    import argparse

    parser = argparse.ArgumentParser(description="SentinelOps Durable Background Execution Worker")
    parser.add_argument(
        "--execution-id",
        type=str,
        default=os.environ.get("TARGET_EXECUTION_ID"),
        help="Target a specific execution ID for one-shot execution.",
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        default=_parse_bool_env("ONE_SHOT", default=False) if os.environ.get("ONE_SHOT") else False,
        help="Run in one-shot mode (exits after claiming at most one job).",
    )
    args = parser.parse_args()

    target_execution_id = args.execution_id.strip() if args.execution_id else None
    one_shot = args.one_shot or bool(target_execution_id)

    worker = DurableExecutionWorker(
        target_execution_id=target_execution_id,
        one_shot=one_shot,
    )

    def handle_signal(sig, frame):
        logger.info("Signal %s received; shutting down worker...", sig)
        clean = worker.stop()
        sys.exit(0 if clean else 1)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if worker.one_shot:
        logger.info(
            "Starting SentinelOps Targeted Worker (%s) in ONE-SHOT mode (target: %s)...",
            worker.worker_id,
            worker.target_execution_id or "next eligible",
        )
        claimed_id = worker.run_target(worker.target_execution_id) if worker.target_execution_id else worker.run_once()
        if claimed_id:
            logger.info("One-shot execution completed successfully for job '%s'.", claimed_id)
            sys.exit(0)
        else:
            logger.warning(
                "One-shot execution found no eligible job for target '%s'. Exiting cleanly.",
                worker.target_execution_id,
            )
            sys.exit(0)

    logger.info("Starting SentinelOps Durable Execution Worker (%s)...", worker.worker_id)
    worker.start()

    try:
        while worker.is_running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        clean = worker.stop()
        sys.exit(0 if clean else 1)


if __name__ == "__main__":
    main()
