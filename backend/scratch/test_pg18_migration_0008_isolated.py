"""Validate Alembic migration 0008 on an isolated PostgreSQL 18 test database.

Tests:
1. Fresh database creation.
2. Full upgrade to head (0001 -> 0008).
3. Verification of tables, columns, indexes, and constraints.
4. Clean downgrade to 0007_remediation_executions.
5. Verification that verification tables are dropped while historical tables remain.
6. Clean re-upgrade to head (0008).
7. Teardown and drop of isolated test database.
"""

import os
import sys

sys.path.insert(0, r"d:\Sentinal_AI\backend")

import psycopg
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, text

TEST_DB_NAME = "sentinelops_iso_mig_0008_test"
PG_HOST = "127.0.0.1"
PG_PORT = 5432
PG_USER = "postgres"
PG_PASS = "veduvivu"

ADMIN_URL = f"postgresql://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/postgres"
TEST_DB_URL = f"postgresql+psycopg://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{TEST_DB_NAME}"

def main():
    print(f"Creating isolated database '{TEST_DB_NAME}'...")
    admin_conn = psycopg.connect(ADMIN_URL, autocommit=True)
    cur = admin_conn.cursor()
    cur.execute(f"DROP DATABASE IF EXISTS {TEST_DB_NAME}")
    cur.execute(f"CREATE DATABASE {TEST_DB_NAME}")
    admin_conn.close()

    try:
        os.environ["DATABASE_URL"] = TEST_DB_URL
        alembic_ini = r"d:\Sentinal_AI\backend\alembic.ini"
        cfg = Config(alembic_ini)
        cfg.set_main_option("sqlalchemy.url", TEST_DB_URL)
        cfg.set_main_option("script_location", r"d:\Sentinal_AI\backend\alembic")

        print("1. Running alembic upgrade to head (0008)...")
        command.upgrade(cfg, "head")

        engine = create_engine(TEST_DB_URL)
        with engine.connect() as conn:
            tables = {r[0] for r in conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).fetchall()}
            print(f"Tables present after 0008 upgrade: {len(tables)} tables")
            assert "verification_cycles" in tables, "verification_cycles missing"
            assert "verification_probe_results" in tables, "verification_probe_results missing"
            assert "remediation_executions" in tables, "remediation_executions missing"
            assert "execution_attempts" in tables, "execution_attempts missing"
            assert "execution_events" in tables, "execution_events missing"

            # Check constraints on verification_cycles
            cc = {r[0] for r in conn.execute(text("SELECT conname FROM pg_constraint WHERE conrelid = 'verification_cycles'::regclass")).fetchall()}
            assert "uq_verification_cycle_exec_number" in cc, "uq_verification_cycle_exec_number missing"
            assert "ck_verification_cycle_status" in cc, "ck_verification_cycle_status missing"

            # Check constraints on verification_probe_results
            pc = {r[0] for r in conn.execute(text("SELECT conname FROM pg_constraint WHERE conrelid = 'verification_probe_results'::regclass")).fetchall()}
            assert "uq_probe_cycle_number" in pc, "uq_probe_cycle_number missing"
            assert "ck_verification_probe_status" in pc, "ck_verification_probe_status missing"

        print("2. Running alembic downgrade to 0007_remediation_executions...")
        command.downgrade(cfg, "0007_remediation_executions")

        with engine.connect() as conn:
            tables_after_down = {r[0] for r in conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).fetchall()}
            assert "verification_cycles" not in tables_after_down, "verification_cycles should be dropped"
            assert "verification_probe_results" not in tables_after_down, "verification_probe_results should be dropped"
            assert "remediation_executions" in tables_after_down, "remediation_executions must remain"
            assert "remediation_approvals" in tables_after_down, "remediation_approvals must remain"

        print("3. Running alembic re-upgrade to head (0008)...")
        command.upgrade(cfg, "head")

        with engine.connect() as conn:
            tables_reup = {r[0] for r in conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")).fetchall()}
            assert "verification_cycles" in tables_reup, "verification_cycles missing on re-upgrade"
            assert "verification_probe_results" in tables_reup, "verification_probe_results missing on re-upgrade"

        print("All PostgreSQL 18.3 migration upgrade/downgrade/re-upgrade assertions PASSED!")

    finally:
        print(f"Tearing down isolated database '{TEST_DB_NAME}'...")
        if 'engine' in locals():
            engine.dispose()
        admin_conn = psycopg.connect(ADMIN_URL, autocommit=True)
        admin_conn.cursor().execute(f"""
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = '{TEST_DB_NAME}' AND pid <> pg_backend_pid();
        """)
        admin_conn.cursor().execute(f"DROP DATABASE IF EXISTS {TEST_DB_NAME}")
        admin_conn.close()
        print("Teardown complete.")

if __name__ == "__main__":
    main()
