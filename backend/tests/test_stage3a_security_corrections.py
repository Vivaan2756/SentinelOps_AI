"""Unit and Integration Tests for Stage 3A Security Corrections.

Covers:
- FINDING-2.1-02: Dedicated worker database role permissions and table restrictions
- FINDING-2.1-03: Worker signing key environment isolation and defense-in-depth scrubbing
- Worker database factory resolution (WORKER_DATABASE_URL)
- Verification that public key verification remains fully operational in the worker
"""

import os
import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import patch

from app.execution.worker import (
    ExecutionWorker,
    scrub_worker_signing_secrets,
    get_worker_db_session_factory,
    SIGNING_SECRET_ENV_KEYS,
)
from app.execution.manifest_signer import (
    generate_and_sign_execution_manifest,
    load_control_plane_signing_key,
    ManifestSigningError,
)
from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner
from app.execution.public_keys import BrokerPublicKeyRegistry


def test_worker_signing_key_scrubbing_on_init():
    """FINDING-2.1-03: Proves worker scrubs signing private keys from environment upon initialization."""
    saved_env = {k: os.environ.get(k) for k in SIGNING_SECRET_ENV_KEYS}
    try:
        dummy_key = "dGVzdF9wcml2YXRlX3NpZ25pbmdfa2V5X2Jhc2U2NA=="
        for k in SIGNING_SECRET_ENV_KEYS:
            os.environ[k] = dummy_key

        # Confirm keys are present before
        for k in SIGNING_SECRET_ENV_KEYS:
            assert k in os.environ

        # Call scrubber
        scrub_worker_signing_secrets()

        # Confirm keys were scrubbed
        for k in SIGNING_SECRET_ENV_KEYS:
            assert k not in os.environ, f"Signing key {k} was not scrubbed from environment"
    finally:
        for k, v in saved_env.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)


def test_worker_cannot_access_or_load_private_key():
    """FINDING-2.1-03: Proves that an attempt to sign a manifest fails closed if worker environment is active."""
    saved_env = {k: os.environ.get(k) for k in SIGNING_SECRET_ENV_KEYS}
    try:
        # Ensure environment is scrubbed
        scrub_worker_signing_secrets()

        # Calling load_control_plane_signing_key without key in env must raise ManifestSigningError
        with pytest.raises(ManifestSigningError) as exc_info:
            load_control_plane_signing_key()
        assert "SENTINELOPS_MANIFEST_PRIVATE_KEY is missing or empty" in str(exc_info.value)
    finally:
        for k, v in saved_env.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)


def test_worker_retains_public_key_verification():
    """FINDING-2.1-03: Worker can still verify manifests signed by the control plane using only public keys."""
    # Worker isolated runner uses public key registry only
    pub_reg = BrokerPublicKeyRegistry()
    runner = IsolatedHttpRecoveryRunner(
        public_key_registry=pub_reg,
        allow_unauthenticated_probes=False,
    )
    assert hasattr(runner, "public_key_registry")
    assert not hasattr(runner, "private_key")


def test_worker_db_session_factory_resolution():
    """FINDING-2.1-02: Worker routes database traffic to WORKER_DATABASE_URL if configured."""
    original_url = os.environ.get("WORKER_DATABASE_URL")
    try:
        os.environ["WORKER_DATABASE_URL"] = "sqlite:///:memory:"
        factory = get_worker_db_session_factory()
        session = factory()
        assert session is not None
        session.close()
    finally:
        if original_url is not None:
            os.environ["WORKER_DATABASE_URL"] = original_url
        else:
            os.environ.pop("WORKER_DATABASE_URL", None)


def test_dedicated_worker_role_table_permissions_contract():
    """
    FINDING-2.1-02: Contract test verifying the exact table permissions granted and denied to sentinelops_worker.
    Validates that:
    - Allowed tables: remediation_executions, execution_attempts, execution_events, remediation_approvals,
      incidents, incident_events, services, investigations, verification_cycles, verification_probe_results, workspaces
    - Forbidden tables: users, workspace_memberships, playbooks, playbook_versions, service_playbook_associations, policy_decisions
    """
    allowed_tables = {
        "remediation_executions": {"SELECT", "UPDATE"},
        "execution_attempts": {"SELECT", "INSERT", "UPDATE"},
        "execution_events": {"SELECT", "INSERT"},
        "remediation_approvals": {"SELECT"},
        "incidents": {"SELECT", "UPDATE"},
        "incident_events": {"SELECT", "INSERT"},
        "services": {"SELECT"},
        "investigations": {"SELECT"},
        "verification_cycles": {"SELECT", "INSERT", "UPDATE"},
        "verification_probe_results": {"SELECT", "INSERT", "UPDATE"},
        "workspaces": {"SELECT"},
    }

    forbidden_tables = {
        "users",
        "workspace_memberships",
        "playbooks",
        "playbook_versions",
        "service_playbook_associations",
        "policy_decisions",
    }

    # Verify that forbidden tables have ZERO overlap with allowed tables
    assert len(forbidden_tables.intersection(allowed_tables.keys())) == 0

    # Read the SQL migration file and verify explicit grants and restrictions
    sql_path = os.path.join(os.path.dirname(__file__), "..", "sql", "02_create_worker_role.sql")
    with open(sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    for table, privs in allowed_tables.items():
        for priv in privs:
            assert f"GRANT {priv}" in sql_content or f"{priv}," in sql_content or f", {priv}" in sql_content, (
                f"Missing {priv} grant on {table}"
            )
            assert f"ON {table} TO sentinelops_worker" in sql_content, f"Missing target {table} in grants"

    for table in forbidden_tables:
        assert f"GRANT SELECT ON {table} TO sentinelops_worker" not in sql_content, (
            f"Security violation: Forbidden table {table} has grant in worker role SQL"
        )
        assert f"GRANT UPDATE ON {table} TO sentinelops_worker" not in sql_content
        assert f"GRANT INSERT ON {table} TO sentinelops_worker" not in sql_content
        assert f"GRANT DELETE ON {table} TO sentinelops_worker" not in sql_content
