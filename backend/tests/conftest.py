"""Pytest test configuration and fixtures."""

import os
import subprocess
import sys
import uuid
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force test environment variables before importing app
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DETECTOR_POLLER_ENABLED"] = "false"
os.environ["SENTINELOPS_STRICT_MIGRATION_GUARD"] = "true"
os.environ.setdefault("SENTINELOPS_MANIFEST_PRIVATE_KEY", "/+coTws3RSMT0fao4K5hSCP0dr6lz+NozVmUi2+UT/Q=")
os.environ.setdefault("SENTINELOPS_MANIFEST_KEY_ID", "test-control-plane-key-1")

from app.db.base import Base
from app.db.guard import (
    ProtectedDatabaseError,
    assert_safe_migration_target,
    extract_database_name,
    is_protected_database,
)
from app.db.session import get_db
from app.core.security import get_password_hash, create_access_token
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.main import app

# Create in-memory SQLite engine for fast, isolated unit tests
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create test database tables once per test session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def preserve_signing_key_for_control_plane():
    """
    Ensure each test function begins and ends with the control-plane signing key in os.environ.
    This prevents in-process worker scrubbing during one test from poisoning subsequent control-plane tests.
    """
    signing_key = "/+coTws3RSMT0fao4K5hSCP0dr6lz+NozVmUi2+UT/Q="
    key_id = "test-control-plane-key-1"
    if "SENTINELOPS_MANIFEST_PRIVATE_KEY" not in os.environ:
        os.environ["SENTINELOPS_MANIFEST_PRIVATE_KEY"] = signing_key
    if "SENTINELOPS_MANIFEST_KEY_ID" not in os.environ:
        os.environ["SENTINELOPS_MANIFEST_KEY_ID"] = key_id
    yield
    if "SENTINELOPS_MANIFEST_PRIVATE_KEY" not in os.environ:
        os.environ["SENTINELOPS_MANIFEST_PRIVATE_KEY"] = signing_key
    if "SENTINELOPS_MANIFEST_KEY_ID" not in os.environ:
        os.environ["SENTINELOPS_MANIFEST_KEY_ID"] = key_id


@pytest.fixture
def db_session():
    """Yield an isolated database session per test function."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """Provide a FastAPI TestClient with database session dependency overridden."""
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_context(db_session):
    """Creates a user, workspace, admin membership, and valid JWT auth headers."""
    user = User(
        email=f"tester-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Test Engineer",
        hashed_password=get_password_hash("ValidPass123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()

    workspace = Workspace(
        name="Test Ops",
        slug=f"test-ops-{uuid.uuid4().hex[:6]}",
        description="Testing workspace",
    )
    db_session.add(workspace)
    db_session.flush()

    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role="admin",
    )
    db_session.add(membership)
    db_session.commit()

    token = create_access_token({"sub": user.id, "email": user.email})
    headers = {"Authorization": f"Bearer {token}"}

    return {
        "user": user,
        "workspace": workspace,
        "membership": membership,
        "token": token,
        "headers": headers,
    }


# ============================================================================
# Shared Isolated PostgreSQL Infrastructure for Integration Tests
# ============================================================================

def assert_safe_test_database_url(url: str) -> None:
    """Strictly assert that a database URL targets an authorized isolated test database."""
    if not url:
        raise ProtectedDatabaseError("Database URL cannot be empty.")
    assert_safe_migration_target(url)
    db_name = extract_database_name(url)
    if not db_name.startswith(("sentinelops_test_", "test_")):
        raise ProtectedDatabaseError(
            f"Access rejected: Test database name '{db_name}' must begin with 'sentinelops_test_' or 'test_'."
        )
    if "sentinelops_dev" in url.lower():
        raise ProtectedDatabaseError("Access rejected: Attempted to target live development database 'sentinelops_dev'.")


def get_admin_postgres_url() -> str:
    """Resolve administrative PostgreSQL connection URL targeting the standard 'postgres' catalog."""
    if os.environ.get("POSTGRES_ADMIN_URL"):
        return os.environ["POSTGRES_ADMIN_URL"]

    raw_url = None
    env_file = r"d:\Sentinal_AI\backend\.env"
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            for line in f:
                line_str = line.strip()
                if line_str.startswith("DATABASE_URL="):
                    raw_url = line_str.split("=", 1)[1]
                    break

    if not raw_url:
        raw_url = os.environ.get("DATABASE_URL", "postgresql+psycopg://postgres:veduvivu@127.0.0.1:5432/postgres")

    # Replace the database name with 'postgres' (the standard PostgreSQL administrative database)
    prefix = raw_url.rsplit("/", 1)[0]
    return f"{prefix}/postgres"


@contextmanager
def isolated_test_database(prefix: str = "sentinelops_test_integration_", tmp_path=None):
    """
    Context manager to provision, validate, and tear down an ephemeral PostgreSQL test database.
    Never connects to or modifies sentinelops_dev or protected databases.
    Fails immediately if PostgreSQL provisioning fails.
    """
    admin_url = get_admin_postgres_url()
    test_db_name = f"{prefix}{uuid.uuid4().hex[:10]}"
    base_prefix = admin_url.rsplit("/", 1)[0]
    test_db_url = f"{base_prefix}/{test_db_name}"

    # Independent fail-closed safety checks
    assert_safe_test_database_url(test_db_url)

    admin_engine = None
    try:
        admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as conn:
            conn.execute(text(f"CREATE DATABASE {test_db_name}"))
    except Exception as e:
        if admin_engine:
            admin_engine.dispose()
        raise RuntimeError(f"Failed to provision isolated PostgreSQL test database '{test_db_name}': {e}") from e

    # Apply all Alembic migrations to head so schema is complete with all constraints
    backend_dir = r"d:\Sentinal_AI\backend"
    migration_env = os.environ.copy()
    migration_env["DATABASE_URL"] = test_db_url
    migration_env["ENVIRONMENT"] = "test"
    migration_env["SENTINELOPS_STRICT_MIGRATION_GUARD"] = "true"

    venv_python = os.path.join(backend_dir, ".venv", "Scripts", "python.exe")
    py_exec = venv_python if os.path.exists(venv_python) else sys.executable

    res = subprocess.run(
        [py_exec, "-m", "alembic", "upgrade", "head"],
        cwd=backend_dir,
        env=migration_env,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        with admin_engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {test_db_name}"))
        admin_engine.dispose()
        raise RuntimeError(
            f"Failed to migrate isolated test database '{test_db_name}' to head:\n{res.stderr}\n{res.stdout}"
        )

    try:
        yield test_db_url
    finally:
        try:
            with admin_engine.connect() as conn:
                conn.execute(text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    f"WHERE datname = '{test_db_name}' AND pid <> pg_backend_pid()"
                ))
                conn.execute(text(f"DROP DATABASE IF EXISTS {test_db_name}"))
        except Exception:
            pass
        finally:
            admin_engine.dispose()


@pytest.fixture(scope="session")
def isolated_pg_url():
    """Session-scoped fixture provisioning one isolated PostgreSQL database for integration tests."""
    with isolated_test_database(prefix="sentinelops_test_integration_") as url:
        yield url


@pytest.fixture(scope="session")
def isolated_pg_engine(isolated_pg_url):
    """Session-scoped SQLAlchemy engine connected to the isolated test database."""
    assert_safe_test_database_url(isolated_pg_url)
    engine = create_engine(isolated_pg_url, pool_size=10, max_overflow=5)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def isolated_pg_session_factory(isolated_pg_engine):
    """Session-scoped sessionmaker factory for the isolated test database."""
    return sessionmaker(bind=isolated_pg_engine, autoflush=False)


@pytest.fixture(scope="session")
def isolated_pg_seed_data(isolated_pg_session_factory):
    """Ensure baseline synthetic workspace and user exist in the isolated PostgreSQL database."""
    Session = isolated_pg_session_factory
    db = Session()
    try:
        ws_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())
        ws = Workspace(
            id=ws_id,
            name="Integration Baseline Workspace",
            slug=f"integration-baseline-{ws_id[:6]}",
            description="Baseline workspace for isolated PG tests",
        )
        db.add(ws)
        db.flush()

        user = User(
            id=user_id,
            email=f"integration_tester_{user_id[:6]}@isolated.local",
            full_name="Integration Tester",
            hashed_password=get_password_hash("ValidPass123!"),
            is_active=True,
        )
        db.add(user)
        db.flush()

        membership = WorkspaceMembership(
            workspace_id=ws.id,
            user_id=user.id,
            role="admin",
        )
        db.add(membership)
        db.commit()
        return {"workspace_id": ws_id, "user_id": user_id}
    finally:
        db.close()
