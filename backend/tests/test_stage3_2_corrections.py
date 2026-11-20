"""Stage 3.2 Security Acceptance & Concurrency Tests.

Verifies:
1. AUDIT-3.1-02: Explicit demo-service classification (service names never imply demo mode).
2. AUDIT-3.1-03: Optional PostgreSQL container profile secret propagation.
3. AUDIT-3.1-04: Worker database identity enforcement (strict sentinelops_worker role).
4. Manifest journal concurrency: Race safety under heavy multi-threaded contention.
"""

import os
import re
import threading
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from app.execution.actions import (
    handle_restore_order_api_demo,
    validate_restore_order_api_demo_preconditions,
)
from app.execution.exceptions import (
    PreconditionFailedError,
    SecurityConfigurationError,
)
from app.execution.manifest_journal import (
    BrokerManifestJournal,
    ExecutionState,
    JournalConflictError,
)
from app.execution.runner import ExecutionResult, MockTestRunner
from app.execution.verification import (
    PostExecutionVerificationEngine,
    ProbeStatus,
)
from app.execution.worker import get_worker_db_session_factory, sanitize_db_url
from app.models.remediation import RemediationExecution
from app.models.service import Service
from app.remediation.registry import ActionRegistry
from app.schemas.service import ServiceCreate


# ============================================================================
# AUDIT-3.1-02: Explicit Demo-Service Classification
# ============================================================================


class TestAudit3102ExplicitDemoClassification:
    """Verifies that demo classification is NEVER inferred solely by service name."""

    @pytest.mark.parametrize(
        "service_name",
        ["Order API", "order-api", "Order API Live PG", "demo-order-service", "order_api"],
    )
    def test_service_name_alone_does_not_enable_demo_action(self, service_name):
        """Services named 'Order API' or variants without demo_integration reject demo actions."""
        service = Service(
            id=str(uuid.uuid4()),
            workspace_id=str(uuid.uuid4()),
            name=service_name,
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="builtin",
            execution_policy="demo",
            demo_integration=None,
            is_active=True,
        )

        assert not ActionRegistry.is_demo_service(service, "order_api")
        assert not ActionRegistry.is_action_supported_for_service("restore_order_api_demo", service)

        with pytest.raises(PreconditionFailedError) as exc_info:
            validate_restore_order_api_demo_preconditions(service)
        assert "not supported" in str(exc_info.value)

    def test_explicit_demo_integration_enables_demo_action(self):
        """Service with demo_integration='order_api' in development allows demo action."""
        service = Service(
            id=str(uuid.uuid4()),
            workspace_id=str(uuid.uuid4()),
            name="Custom Order Service",
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="prometheus",
            execution_policy="demo",
            demo_integration="order_api",
            is_active=True,
        )

        assert ActionRegistry.is_demo_service(service, "order_api")
        assert ActionRegistry.is_action_supported_for_service("restore_order_api_demo", service)

    def test_demo_integration_rejected_in_production_or_staging(self):
        """Schema validation rejects demo_integration outside development environment."""
        with pytest.raises(ValidationError) as exc_info:
            ServiceCreate(
                name="Production Order API",
                environment="production",
                health_check_url="https://api.example.com/health",
                monitoring_method="prometheus",
                execution_policy="demo",
                demo_integration="order_api",
                workspace_id=str(uuid.uuid4()),
            )
        assert "demo_integration is only permitted in the 'development' environment" in str(exc_info.value)

    def test_demo_integration_allowed_with_approval_required_or_observe_only(self):
        """demo_integration is permitted with approval_required or observe_only policies in development."""
        svc_create = ServiceCreate(
            name="Dev Order API",
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="prometheus",
            execution_policy="approval_required",
            demo_integration="order_api",
            workspace_id=str(uuid.uuid4()),
        )
        assert svc_create.demo_integration == "order_api"

    def test_generic_service_verification_skips_demo_probes(self):
        """Generic service named 'Order API' (no demo_integration) skips /demo/status probe."""
        service = Service(
            id=str(uuid.uuid4()),
            workspace_id=str(uuid.uuid4()),
            name="Order API",
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="builtin",
            execution_policy="demo",
            demo_integration=None,
            is_active=True,
        )

        mock_runner = MagicMock(spec=MockTestRunner)
        mock_runner.is_available.return_value = True
        mock_runner.execute.return_value = ExecutionResult(
            exit_code=0,
            duration_ms=20,
            output_data={
                "endpoints": {
                    "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}}
                }
            },
        )

        engine = PostExecutionVerificationEngine(runner=mock_runner)
        probe = engine.execute_single_probe(
            runner=mock_runner,
            service=service,
            probe_number=1,
            probe_type="baseline",
            action_id="execute_http_recovery",
        )

        assert probe.passed
        assert "demo_status" in probe.probe_output
        assert probe.probe_output["demo_status"]["status"] == "skipped"

    def test_http_recovery_never_forces_demo_checks(self):
        """execute_http_recovery action NEVER marks is_demo_service as True."""
        service = Service(
            id=str(uuid.uuid4()),
            workspace_id=str(uuid.uuid4()),
            name="Order API",
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="builtin",
            execution_policy="demo",
            demo_integration="order_api",  # Even with explicit demo_integration!
            is_active=True,
        )

        mock_runner = MagicMock(spec=MockTestRunner)
        mock_runner.is_available.return_value = True
        mock_runner.execute.return_value = ExecutionResult(
            exit_code=0,
            duration_ms=20,
            output_data={
                "endpoints": {
                    "health": {"status_code": 200, "success": True, "output_data": {"status": "ok"}}
                }
            },
        )

        engine = PostExecutionVerificationEngine(runner=mock_runner)
        probe = engine.execute_single_probe(
            runner=mock_runner,
            service=service,
            probe_number=1,
            probe_type="baseline",
            action_id="execute_http_recovery",  # Generic HTTP action
        )

        # For execute_http_recovery, demo probe is ALWAYS skipped
        assert probe.probe_output["demo_status"]["status"] == "skipped"


# ============================================================================
# AUDIT-3.1-03: Optional PostgreSQL Container Profile Secret Propagation
# ============================================================================


class TestAudit3103ComposeSecretPropagation:
    """Verifies that docker-compose.yml propagates WORKER_DB_PASSWORD to db container."""

    def test_compose_db_environment_has_required_worker_secret(self):
        """Ensure docker-compose.yml defines WORKER_DB_PASSWORD under db.environment."""
        compose_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker-compose.yml"))
        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Match db service block
        assert "services:" in content
        assert "container-isolated-db" in content
        # Stage 3.3 (FINDING-3.2-01): Optional profile uses :- to allow external DB without failing compose config
        assert "WORKER_DB_PASSWORD: ${WORKER_DB_PASSWORD:-}" in content


# ============================================================================
# AUDIT-3.1-04: Worker Database Identity Enforcement
# ============================================================================


class TestAudit3104WorkerDatabaseIdentity:
    """Verifies strict enforcement of sentinelops_worker role identity."""

    @pytest.mark.parametrize(
        "invalid_username",
        ["postgres", "sentinelops_user", "root", "admin", "sentinelops_admin", "app_user"],
    )
    def test_prohibited_database_usernames_rejected(self, invalid_username, monkeypatch):
        """Worker rejects any database identity other than sentinelops_worker."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        url = f"postgresql://{invalid_username}:some_valid_secret_123@localhost:5432/sentinelops_dev"
        monkeypatch.setenv("WORKER_DATABASE_URL", url)

        with pytest.raises(SecurityConfigurationError) as exc_info:
            get_worker_db_session_factory()
        assert "must authenticate as restricted role 'sentinelops_worker'" in str(exc_info.value)
        assert invalid_username in str(exc_info.value)

    def test_valid_sentinelops_worker_identity_accepted(self, monkeypatch):
        """Worker accepts sentinelops_worker username format."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        url = "postgresql://sentinelops_worker:valid_secure_secret_pass99@localhost:5432/sentinelops_dev"
        monkeypatch.setenv("WORKER_DATABASE_URL", url)

        with patch("sqlalchemy.create_engine") as mock_engine:
            mock_conn = MagicMock()
            mock_conn.execute.return_value.scalar.return_value = "sentinelops_worker"
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            factory = get_worker_db_session_factory()
            assert factory is not None

    def test_connection_time_role_mismatch_fails_closed(self, monkeypatch):
        """Worker fails closed if PostgreSQL session current_user != sentinelops_worker."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        url = "postgresql://sentinelops_worker:valid_secure_secret_pass99@localhost:5432/sentinelops_dev"
        monkeypatch.setenv("WORKER_DATABASE_URL", url)

        with patch("sqlalchemy.create_engine") as mock_engine:
            mock_conn = MagicMock()
            mock_conn.execute.return_value.scalar.return_value = "postgres"  # Mismatch!
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            with pytest.raises(SecurityConfigurationError) as exc_info:
                get_worker_db_session_factory()
            assert "Worker database connection role mismatch" in str(exc_info.value)
            assert "connected as 'postgres'" in str(exc_info.value)

    def test_prohibited_passwords_rejected(self, monkeypatch):
        """Worker rejects default or placeholder passwords."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        url = "postgresql://sentinelops_worker:sentinelops_worker_password@localhost:5432/sentinelops_dev"
        monkeypatch.setenv("WORKER_DATABASE_URL", url)

        with pytest.raises(SecurityConfigurationError) as exc_info:
            get_worker_db_session_factory()
        assert "Insecure or default placeholder password detected" in str(exc_info.value)

    def test_credentials_sanitized_in_errors(self):
        """sanitize_db_url properly masks credentials."""
        url = "postgresql://sentinelops_worker:super_secret_password_123@db.internal:5432/prod_db"
        sanitized = sanitize_db_url(url)
        assert "super_secret_password_123" not in sanitized
        assert ":***@" in sanitized


# ============================================================================
# Manifest Journal Concurrency Stress Test
# ============================================================================


class TestManifestJournalConcurrency:
    """Verifies that concurrent claim attempts are robust and race-free."""

    def test_manifest_journal_high_concurrency_race(self, tmp_path):
        """Verify 20 concurrent threads racing on the exact same manifest."""
        db_path = str(tmp_path / "concurrent_test.db")
        # Pre-initialize journal storage
        init_j = BrokerManifestJournal(db_path=db_path, timeout=10.0)
        init_j.close()

        manifest_id = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())
        now = int(time.time())
        expires_at = now + 120
        sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sample_digest = "c744f6f17e082c5f1c911bc93efb8e21a415a77be60c9ea4ca4187f5d96ca446"

        successes = []
        conflicts = []
        errors = []
        num_threads = 20
        barrier = threading.Barrier(num_threads)

        def worker(worker_id):
            try:
                j = BrokerManifestJournal(db_path=db_path, timeout=10.0)
                try:
                    barrier.wait(timeout=5.0)
                    rec = j.claim_manifest(
                        manifest_id=manifest_id,
                        execution_id=execution_id,
                        action_id="execute_http_recovery",
                        authorized_origin="https://order-api.internal:8001",
                        authorized_path="/api/v1/orders/recovery",
                        parameters_sha256=sample_sha256,
                        key_id="key-ed25519-v1",
                        manifest_digest=sample_digest,
                        expires_at=expires_at,
                    )
                    successes.append((worker_id, rec))
                except JournalConflictError as e:
                    conflicts.append((worker_id, str(e)))
                except Exception as e:
                    errors.append((worker_id, f"{type(e).__name__}: {e}"))
                finally:
                    j.close()
            except Exception as e:
                errors.append((worker_id, f"Init error: {type(e).__name__}: {e}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Unexpected errors: {errors}"
        assert len(successes) == 1, f"Expected exactly 1 claim, got {len(successes)}"
        assert len(conflicts) == num_threads - 1, f"Expected {num_threads - 1} conflicts, got {len(conflicts)}"
