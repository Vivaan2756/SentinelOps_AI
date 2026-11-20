"""Dedicated worker role and minimum privilege setup (Phase 3A Stage 3A.2 / FINDING-2.1-02)

Revision ID: 0011_dedicated_worker_role
Revises: 0010_manifest_signing
Create Date: 2026-11-09 20:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = "0011_dedicated_worker_role"
down_revision: Union[str, None] = "0010_manifest_signing"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        import os
        worker_password = os.environ.get("WORKER_DB_PASSWORD")
        env = os.environ.get("ENVIRONMENT", "").strip().lower()
        if not worker_password:
            if env != "test":
                raise ValueError(
                    "WORKER_DB_PASSWORD environment variable is required to create sentinelops_worker role. "
                    "Committed default passwords are forbidden."
                )
            worker_password = "ephemeral_test_worker_password_stage31"
        if worker_password in ("sentinelops_worker_password", "password", "change_me"):
            raise ValueError(
                "Insecure or default WORKER_DB_PASSWORD is forbidden for sentinelops_worker role."
            )
        escaped_password = worker_password.replace("'", "''")
        # Create dedicated role if not present, or update password
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinelops_worker') THEN
                    CREATE ROLE sentinelops_worker WITH LOGIN PASSWORD '{escaped_password}';
                ELSE
                    ALTER ROLE sentinelops_worker WITH PASSWORD '{escaped_password}';
                END IF;
            END
            $$;
            """
        )
        # Usage on schema
        op.execute("GRANT USAGE ON SCHEMA public TO sentinelops_worker;")

        # Minimum required execution and coordination grants
        op.execute("GRANT SELECT, UPDATE ON remediation_executions TO sentinelops_worker;")
        op.execute("GRANT SELECT, INSERT, UPDATE ON execution_attempts TO sentinelops_worker;")
        op.execute("GRANT SELECT, INSERT ON execution_events TO sentinelops_worker;")
        op.execute("GRANT SELECT ON remediation_approvals TO sentinelops_worker;")
        op.execute("GRANT SELECT, UPDATE ON incidents TO sentinelops_worker;")
        op.execute("GRANT SELECT, INSERT ON incident_events TO sentinelops_worker;")
        op.execute("GRANT SELECT ON services TO sentinelops_worker;")
        op.execute("GRANT SELECT ON investigations TO sentinelops_worker;")
        op.execute("GRANT SELECT, INSERT, UPDATE ON verification_cycles TO sentinelops_worker;")
        op.execute("GRANT SELECT, INSERT, UPDATE ON verification_probe_results TO sentinelops_worker;")
        op.execute("GRANT SELECT ON workspaces TO sentinelops_worker;")
        op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinelops_worker;")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM sentinelops_worker;")
        op.execute("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM sentinelops_worker;")
        op.execute("REVOKE USAGE ON SCHEMA public FROM sentinelops_worker;")
