"""Tests for Database Migration Protection Guard (app.db.guard).

Proves that destructive migration commands and tests strictly refuse to operate on:
- sentinelops_dev (live development database)
- Any production or staging database
- Any database lacking the authorized test prefix
- Any protected system database
"""

import os
import sys
import subprocess
import pytest
from app.db.guard import (
    assert_safe_migration_target,
    is_protected_database,
    ProtectedDatabaseError,
    extract_database_name,
    PROTECTED_DATABASE_NAMES,
)


def test_extract_database_name():
    """Verify clean extraction of database names across URL formats."""
    assert extract_database_name("postgresql://user:pass@localhost:5432/sentinelops_dev") == "sentinelops_dev"
    assert extract_database_name("postgresql+psycopg://user:pass@127.0.0.1:5432/sentinelops_test_123") == "sentinelops_test_123"
    assert extract_database_name("sqlite:///:memory:") == ":memory:"
    assert extract_database_name("sqlite:///C:/path/to/test.db").endswith("test.db")


def test_reject_live_dev_database():
    """Explicitly verify rejection of live development database sentinelops_dev."""
    dev_url = "postgresql+psycopg://postgres:veduvivu@127.0.0.1:5432/sentinelops_dev"
    protected, reason = is_protected_database(dev_url)
    assert protected is True
    assert "sentinelops_dev" in reason

    with pytest.raises(ProtectedDatabaseError, match="sentinelops_dev"):
        assert_safe_migration_target(dev_url)


def test_reject_production_and_staging_databases():
    """Verify rejection of production and staging database URLs."""
    forbidden_urls = [
        "postgresql://prod_user:secret@db.prod.internal:5432/sentinelops_prod",
        "postgresql://user:pass@localhost:5432/sentinelops_production",
        "postgresql://user:pass@localhost:5432/sentinelops_staging",
        "postgresql://user:pass@localhost:5432/sentinelops_stage",
        "postgresql://user:pass@localhost:5432/staging_db",
        "postgresql://user:pass@localhost:5432/prod_analytics",
    ]
    for url in forbidden_urls:
        protected, reason = is_protected_database(url)
        assert protected is True, f"Expected {url} to be protected!"
        with pytest.raises(ProtectedDatabaseError):
            assert_safe_migration_target(url)


def test_reject_system_and_other_protected_databases():
    """Verify rejection of default postgres database and non-test application databases."""
    for db_name in PROTECTED_DATABASE_NAMES:
        url = f"postgresql://user:pass@localhost:5432/{db_name}"
        protected, reason = is_protected_database(url)
        assert protected is True
        with pytest.raises(ProtectedDatabaseError):
            assert_safe_migration_target(url)


def test_reject_arbitrary_unprefixed_databases():
    """Verify rejection of databases that do not start with sentinelops_test_ or test_."""
    unprefixed_urls = [
        "postgresql://user:pass@localhost:5432/my_app_database",
        "postgresql://user:pass@localhost:5432/customer_data",
        "postgresql://user:pass@localhost:5432/warehouse",
    ]
    for url in unprefixed_urls:
        protected, reason = is_protected_database(url)
        assert protected is True
        with pytest.raises(ProtectedDatabaseError, match="authorized test prefix"):
            assert_safe_migration_target(url)


def test_reject_untrusted_sqlite_files():
    """Verify rejection of SQLite databases containing dev/prod keywords without test."""
    untrusted_sqlite = [
        "sqlite:///C:/app/dev.db",
        "sqlite:///D:/data/production.sqlite3",
        "sqlite:///staging.db",
        "sqlite:///sentinelops.db",
    ]
    for url in untrusted_sqlite:
        protected, reason = is_protected_database(url)
        assert protected is True
        with pytest.raises(ProtectedDatabaseError):
            assert_safe_migration_target(url)


def test_accept_isolated_ephemeral_test_databases():
    """Verify that ephemeral databases matching test prefixes are accepted."""
    valid_test_urls = [
        "postgresql+psycopg://postgres:veduvivu@127.0.0.1:5432/sentinelops_test_mig_12345",
        "postgresql://user:pass@localhost:5432/test_isolated_db",
        "sqlite:///:memory:",
        "sqlite:///C:/tmp/test_migration.db",
        "sqlite:///tmp/isolated_migration_test.db",
    ]
    for url in valid_test_urls:
        protected, reason = is_protected_database(url)
        assert protected is False, f"Expected {url} to be permitted, got reason: {reason}"
        # Does not raise
        assert_safe_migration_target(url)


def test_alembic_cli_fails_closed_when_guard_triggered(tmp_path):
    """
    Subprocess test: Prove that invoking Alembic with SENTINELOPS_STRICT_MIGRATION_GUARD=true
    against sentinelops_dev aborts with ProtectedDatabaseError and non-zero exit code.
    """
    backend_dir = r"D:\Sentinal_AI\backend"
    guarded_env = {
        **os.environ,
        "DATABASE_URL": "postgresql+psycopg://postgres:veduvivu@127.0.0.1:5432/sentinelops_dev",
        "SENTINELOPS_STRICT_MIGRATION_GUARD": "true",
    }

    # Attempt to run alembic current or downgrade against sentinelops_dev
    res = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=backend_dir,
        capture_output=True,
        text=True,
        env=guarded_env,
    )

    # Must fail closed with non-zero exit code
    assert res.returncode != 0
    # Error output must contain safety guard message
    combined_output = (res.stderr or "") + (res.stdout or "")
    assert "ProtectedDatabaseError" in combined_output or "CRITICAL SAFETY VIOLATION" in combined_output
    assert "sentinelops_dev" in combined_output
