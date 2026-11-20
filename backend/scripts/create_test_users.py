"""SentinelOps AI — Local Development Test Account Provisioning Script.

Provisions Engineer and Viewer test accounts into the existing demo workspace
for role-based testing and evaluation.

STRICT SAFETY CONSTRAINTS:
1. Restricted strictly to local development environments; refuses to run in production.
2. Reuses existing bcrypt password hashing and database session management.
3. Does not modify the existing Admin account.
4. Does not create a new workspace (targets existing demo workspace).
5. Strictly idempotent: rerunning creates no duplicate accounts or memberships.
6. Passwords are never hardcoded, never printed, and never stored plaintext.
7. Prompts securely using getpass with complexity validation.
"""

import sys
import os
import argparse
import getpass
from typing import Tuple, Optional

# Ensure backend root is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.session import SessionLocal
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership

# Security: Allowed development environments
ALLOWED_ENVIRONMENTS = {"development", "dev", "test", "testing", "local"}
DISALLOWED_ENVIRONMENTS = {"production", "prod", "live", "staging"}

# Role constants
ROLE_ENGINEER = "engineer"
ROLE_VIEWER = "viewer"
PROTECTED_ADMIN_EMAIL = "sre@sentinelops.local"


def verify_local_environment() -> None:
    """Enforce that script executes strictly in local development environments."""
    env = (os.getenv("ENVIRONMENT") or settings.ENVIRONMENT or "").strip().lower()
    if env in DISALLOWED_ENVIRONMENTS or env not in ALLOWED_ENVIRONMENTS:
        print(
            "\n[SECURITY REFUSAL] Refusing execution: create_test_users.py is strictly restricted "
            "to local development environments.",
            file=sys.stderr,
        )
        print(
            f"Detected environment: '{env}'. Permitted environments: {', '.join(sorted(ALLOWED_ENVIRONMENTS))}.\n",
            file=sys.stderr,
        )
        sys.exit(1)


def validate_password_complexity(password: str) -> Tuple[bool, str]:
    """Validate password against security policy.

    Requirements:
    - Minimum length: 8 characters
    - Must contain at least one alphabetic character (a-z, A-Z)
    - Must contain at least one numeric digit (0-9)
    - Cannot be empty or purely whitespace
    """
    if not password or len(password.strip()) == 0:
        return False, "Password cannot be empty or whitespace"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one alphabetic letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one numeric digit (0-9)"
    return True, "Valid"


def acquire_password(
    role_title: str,
    email: str,
    supplied_password: Optional[str] = None,
) -> str:
    """Acquire and validate password via secure getpass prompt or environment variable."""
    # Check if provided via argument or env var (for automation/headless testing)
    if supplied_password:
        valid, err_msg = validate_password_complexity(supplied_password)
        if not valid:
            print(f"[ERROR] Supplied password for {role_title} ({email}) invalid: {err_msg}", file=sys.stderr)
            sys.exit(1)
        return supplied_password

    # Interactive getpass prompt
    print(f"\n[Password Setup] Enter secure password for {role_title} ({email})")
    print("Policy: At least 8 characters, containing both letters and numbers.")

    while True:
        try:
            pwd = getpass.getpass(f"Password for {role_title} [{email}]: ")
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

        valid, err_msg = validate_password_complexity(pwd)
        if not valid:
            print(f"  [Validation Error] {err_msg}. Please re-enter.")
            continue

        try:
            confirm = getpass.getpass(f"Confirm password for {role_title}: ")
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

        if pwd != confirm:
            print("  [Validation Error] Passwords do not match. Please re-enter.")
            continue

        return pwd


def provision_account(
    db,
    workspace: Workspace,
    email: str,
    full_name: str,
    role: str,
    supplied_password: Optional[str] = None,
    reset_passwords: bool = False,
) -> Tuple[str, str]:
    """Provision a user account and assign workspace membership idempotently.

    Returns:
        (account_status, membership_status)
    """
    normalized_email = email.lower().strip()

    # Safety check: Protect Admin account from modification
    if normalized_email == PROTECTED_ADMIN_EMAIL:
        raise ValueError(
            f"Safety violation: Attempted to modify protected Admin account '{PROTECTED_ADMIN_EMAIL}'."
        )

    # 1. User Account Idempotency
    user = db.query(User).filter(User.email == normalized_email).first()
    if user is None:
        raw_password = acquire_password(role.capitalize(), normalized_email, supplied_password)
        user = User(
            email=normalized_email,
            full_name=full_name,
            hashed_password=get_password_hash(raw_password),
            is_active=True,
        )
        db.add(user)
        db.flush()
        account_status = "Newly created"
    else:
        if reset_passwords:
            raw_password = acquire_password(role.capitalize(), normalized_email, supplied_password)
            user.hashed_password = get_password_hash(raw_password)
            account_status = "Already existed (password updated)"
        else:
            account_status = "Already existed"

    # 2. Workspace Membership Idempotency
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    if membership is None:
        membership = WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=role,
        )
        db.add(membership)
        membership_status = "Newly created"
    else:
        if membership.role != role:
            membership.role = role
            membership_status = f"Already existed (role updated to {role})"
        else:
            membership_status = "Already existed"

    return account_status, membership_status


def main() -> None:
    """Parse options, validate environment, and run provisioning."""
    parser = argparse.ArgumentParser(
        description="SentinelOps AI - Local Development Test Account Provisioning Script"
    )
    parser.add_argument(
        "--workspace-slug",
        default="demo-sre-workspace",
        help="Target existing workspace slug (default: demo-sre-workspace)",
    )
    parser.add_argument(
        "--engineer-email",
        default="engineer@sentinelops.local",
        help="Email address for Engineer test account",
    )
    parser.add_argument(
        "--engineer-name",
        default="Demo SRE Engineer",
        help="Display name for Engineer test account",
    )
    parser.add_argument(
        "--engineer-password",
        default=os.getenv("ENGINEER_PASSWORD"),
        help="Password for Engineer (reads ENGINEER_PASSWORD env var if set, else prompts securely)",
    )
    parser.add_argument(
        "--viewer-email",
        default="viewer@sentinelops.local",
        help="Email address for Viewer test account",
    )
    parser.add_argument(
        "--viewer-name",
        default="Demo SRE Viewer",
        help="Display name for Viewer test account",
    )
    parser.add_argument(
        "--viewer-password",
        default=os.getenv("VIEWER_PASSWORD"),
        help="Password for Viewer (reads VIEWER_PASSWORD env var if set, else prompts securely)",
    )
    parser.add_argument(
        "--reset-passwords",
        action="store_true",
        help="Prompt for new passwords even if accounts already exist",
    )

    args = parser.parse_args()

    # Step 1: Environment Safety Guard
    verify_local_environment()

    # Step 2: Prevent collisions with Admin or between test accounts
    engineer_email = args.engineer_email.lower().strip()
    viewer_email = args.viewer_email.lower().strip()

    if engineer_email == PROTECTED_ADMIN_EMAIL or viewer_email == PROTECTED_ADMIN_EMAIL:
        print(
            f"[ERROR] Cannot use the existing Admin account email '{PROTECTED_ADMIN_EMAIL}' for test accounts.",
            file=sys.stderr,
        )
        sys.exit(1)

    if engineer_email == viewer_email:
        print("[ERROR] Engineer and Viewer emails must be different.", file=sys.stderr)
        sys.exit(1)

    # Step 3: Database Session and Workspace Lookup
    db = SessionLocal()
    try:
        workspace = (
            db.query(Workspace)
            .filter(Workspace.slug == args.workspace_slug.strip())
            .first()
        )
        if not workspace:
            print(
                f"[ERROR] Target workspace with slug '{args.workspace_slug}' does not exist.",
                file=sys.stderr,
            )
            print(
                "Refusing to create a new workspace. Please run database migrations or initial demo seed first.",
                file=sys.stderr,
            )
            sys.exit(1)

        ws_name = str(workspace.name)
        ws_slug = str(workspace.slug)

        # Step 4: Provision Accounts
        eng_acc_status, eng_mem_status = provision_account(
            db=db,
            workspace=workspace,
            email=engineer_email,
            full_name=args.engineer_name,
            role=ROLE_ENGINEER,
            supplied_password=args.engineer_password,
            reset_passwords=args.reset_passwords,
        )

        viewer_acc_status, viewer_mem_status = provision_account(
            db=db,
            workspace=workspace,
            email=viewer_email,
            full_name=args.viewer_name,
            role=ROLE_VIEWER,
            supplied_password=args.viewer_password,
            reset_passwords=args.reset_passwords,
        )

        # Commit transaction
        db.commit()

        # Step 5: Format and Display Output Summary (Never printing passwords)
        print("\n" + "=" * 70)
        print("SentinelOps AI - Test Account Provisioning Summary")
        print("=" * 70)
        print(f"Environment : {settings.ENVIRONMENT}")
        print(f"Workspace   : {ws_name} (slug: {ws_slug})")
        print("-" * 70)
        print("1. Engineer Account:")
        print(f"   - Email          : {engineer_email}")
        print(f"   - Role           : {ROLE_ENGINEER}")
        print(f"   - Workspace      : {ws_name}")
        print(f"   - Account Status : {eng_acc_status}")
        print(f"   - Member Status  : {eng_mem_status}")
        print("-" * 70)
        print("2. Viewer Account:")
        print(f"   - Email          : {viewer_email}")
        print(f"   - Role           : {ROLE_VIEWER}")
        print(f"   - Workspace      : {ws_name}")
        print(f"   - Account Status : {viewer_acc_status}")
        print(f"   - Member Status  : {viewer_mem_status}")
        print("=" * 70)
        print("Note: Passwords are encrypted with bcrypt and are not displayed.")
        print("=" * 70 + "\n")

    except Exception as exc:
        db.rollback()
        print(f"\n[FATAL ERROR] Provisioning failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
