"""Unit and integration tests for create_test_users.py provisioning script."""

import os
import sys
import subprocess
import pytest
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from scripts.create_test_users import (
    validate_password_complexity,
    provision_account,
    ROLE_ENGINEER,
    ROLE_VIEWER,
    PROTECTED_ADMIN_EMAIL,
)


def test_password_complexity_rules():
    """Verify password complexity validation enforcement."""
    # Blank / whitespace
    valid, msg = validate_password_complexity("")
    assert not valid
    assert "empty" in msg.lower()

    # Too short (< 8 chars)
    valid, msg = validate_password_complexity("Ab1!")
    assert not valid
    assert "8 characters" in msg.lower()

    # Missing digits
    valid, msg = validate_password_complexity("LettersOnlyHere!")
    assert not valid
    assert "digit" in msg.lower()

    # Missing letters
    valid, msg = validate_password_complexity("1234567890!")
    assert not valid
    assert "letter" in msg.lower()

    # Valid passwords
    valid, _ = validate_password_complexity("SentinelEng2026!")
    assert valid
    valid, _ = validate_password_complexity("ViewerPass99")
    assert valid


def test_provision_account_admin_protection(db_session: Session):
    """Verify that attempting to overwrite the Admin account raises ValueError."""
    ws = db_session.query(Workspace).first()
    if not ws:
        ws = Workspace(name="Test WS", slug="test-ws-protect")
        db_session.add(ws)
        db_session.commit()

    with pytest.raises(ValueError, match="Safety violation"):
        provision_account(
            db=db_session,
            workspace=ws,
            email=PROTECTED_ADMIN_EMAIL,
            full_name="Attacker",
            role=ROLE_ENGINEER,
            supplied_password="ValidPass123!",
        )


def test_provision_account_idempotency(db_session: Session):
    """Verify idempotent creation of user and membership."""
    ws = db_session.query(Workspace).filter(Workspace.slug == "demo-sre-workspace").first()
    if not ws:
        ws = Workspace(name="Demo SRE Workspace", slug="demo-sre-workspace")
        db_session.add(ws)
        db_session.commit()

    test_eng_email = "test-idempotent-eng@sentinelops.local"
    test_view_email = "test-idempotent-view@sentinelops.local"

    # Clean up any leftover records
    for em in (test_eng_email, test_view_email):
        existing = db_session.query(User).filter(User.email == em).first()
        if existing:
            db_session.delete(existing)
    db_session.commit()

    # First run: Newly created
    acc_status1, mem_status1 = provision_account(
        db=db_session,
        workspace=ws,
        email=test_eng_email,
        full_name="Idempotent Engineer",
        role=ROLE_ENGINEER,
        supplied_password="ValidEngPass123!",
    )
    assert acc_status1 == "Newly created"
    assert mem_status1 == "Newly created"
    db_session.commit()

    # Second run: Already existed
    acc_status2, mem_status2 = provision_account(
        db=db_session,
        workspace=ws,
        email=test_eng_email,
        full_name="Idempotent Engineer",
        role=ROLE_ENGINEER,
        supplied_password="ValidEngPass123!",
    )
    assert acc_status2 == "Already existed"
    assert mem_status2 == "Already existed"

    # Verify database state
    user = db_session.query(User).filter(User.email == test_eng_email).first()
    assert user is not None
    assert user.is_active is True

    membership = (
        db_session.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == ws.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    assert membership is not None
    assert membership.role == "engineer"

    # Cleanup
    db_session.delete(user)
    db_session.commit()


def test_production_environment_refusal():
    """Verify script refuses execution when ENVIRONMENT is set to production."""
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "scripts", "create_test_users.py")
    )
    env = os.environ.copy()
    env["ENVIRONMENT"] = "production"

    result = subprocess.run(
        [sys.executable, script_path],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "SECURITY REFUSAL" in result.stderr
