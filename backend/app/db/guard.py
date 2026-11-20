"""Database Protection Guard for Alembic Migrations and Destructive Operations.

Enforces strict isolation to ensure destructive operations (such as Alembic downgrades,
table drops, and test database resets) NEVER execute against protected databases:
- sentinelops_dev (live local development database)
- Production and staging databases
- Any database not explicitly designated as an isolated test database.
"""

from typing import Set, Tuple
from urllib.parse import urlparse
from sqlalchemy.engine import make_url


class ProtectedDatabaseError(RuntimeError):
    """Raised when a destructive database operation attempts to target a protected database."""
    pass


# Exact database names that are strictly protected against destructive test operations
PROTECTED_DATABASE_NAMES: Set[str] = {
    "sentinelops_dev",
    "sentinelops",
    "sentinelops_prod",
    "sentinelops_production",
    "sentinelops_staging",
    "sentinelops_stage",
    "postgres",
    "flavor_unlimited_db",
    "disaster_response_db",
}

# Substring keywords forbidden in test database names for destructive operations
FORBIDDEN_DB_SUBSTRINGS: Tuple[str, ...] = (
    "dev",
    "prod",
    "production",
    "staging",
    "stage",
)

# Mandatory prefixes for isolated test databases
ALLOWED_TEST_DB_PREFIXES: Tuple[str, ...] = (
    "sentinelops_test_",
    "test_",
)


def extract_database_name(db_url: str) -> str:
    """Extract database name or path cleanly from a database connection URL."""
    if not db_url:
        return ""
    try:
        parsed_sa = make_url(db_url)
        return (parsed_sa.database or "").strip()
    except Exception:
        # Fallback to standard urlparse
        parsed = urlparse(db_url)
        path = parsed.path.lstrip("/")
        return path.split("?")[0].strip()


def is_protected_database(db_url: str) -> Tuple[bool, str]:
    """
    Evaluate whether a database URL points to a protected database.
    Returns (is_protected, reason).
    """
    if not db_url:
        return True, "Database URL is empty."

    url_str = db_url.strip().lower()

    # 1. SQLite handling
    if url_str.startswith("sqlite"):
        db_path = extract_database_name(db_url).lower()
        if db_path in (":memory:", ""):
            return False, "In-memory SQLite is safe."
        # If file-based SQLite, reject if filename contains protected keywords
        for sub in FORBIDDEN_DB_SUBSTRINGS:
            if sub in db_path and "test" not in db_path:
                return True, f"SQLite database file '{db_path}' contains forbidden keyword '{sub}' without 'test'."
        if not ("test" in db_path or "tmp" in db_path):
            return True, f"SQLite database file '{db_path}' does not contain 'test' or 'tmp' in filename."
        return False, "Isolated test SQLite file."

    # 2. PostgreSQL and other client/server databases
    db_name = extract_database_name(db_url).lower()

    if not db_name:
        return True, "Target database name is missing from connection URL."

    # Explicit protection for sentinelops_dev
    if db_name == "sentinelops_dev":
        return True, "Refusing destructive operation against live development database 'sentinelops_dev'."

    # Membership in protected database list
    if db_name in PROTECTED_DATABASE_NAMES:
        return True, f"Database '{db_name}' is in protected databases allowlist {sorted(PROTECTED_DATABASE_NAMES)}."

    # Forbidden substrings (e.g. dev, prod, staging)
    for sub in FORBIDDEN_DB_SUBSTRINGS:
        if sub in db_name:
            return True, f"Database name '{db_name}' contains forbidden environment keyword '{sub}'."

    # Mandatory test prefix enforcement
    if not any(db_name.startswith(pfx) for pfx in ALLOWED_TEST_DB_PREFIXES):
        return True, (
            f"Database name '{db_name}' does not start with an authorized test prefix "
            f"({', '.join(ALLOWED_TEST_DB_PREFIXES)}). Only ephemeral test databases are permitted."
        )

    return False, "Database target is an authorized ephemeral test database."


def assert_safe_migration_target(db_url: str) -> None:
    """
    Enforce that a migration or destructive database operation targets only an authorized
    ephemeral test database. Raises ProtectedDatabaseError if any violation is detected.
    """
    protected, reason = is_protected_database(db_url)
    if protected:
        raise ProtectedDatabaseError(
            f"CRITICAL SAFETY VIOLATION: Refusing to execute destructive migration/database operation. {reason}"
        )
