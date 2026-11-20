"""Authentication endpoints for login, session info, and demo seed."""

from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    UserResponse,
    UserWorkspaceMembership,
)
from app.api.deps import get_current_user
from app.core.config import settings

router = APIRouter()


def _get_user_workspaces(user_id: str, db: Session) -> List[UserWorkspaceMembership]:
    """Helper to query a user's accessible workspaces with their roles."""
    memberships = (
        db.query(WorkspaceMembership)
        .filter(WorkspaceMembership.user_id == user_id)
        .all()
    )
    result = []
    for m in memberships:
        ws = db.query(Workspace).filter(Workspace.id == m.workspace_id).first()
        if ws:
            result.append(
                UserWorkspaceMembership(
                    workspace_id=ws.id,
                    workspace_name=ws.name,
                    workspace_slug=ws.slug,
                    role=m.role,
                )
            )
    return result


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate user and issue access token",
)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Validate credentials and return JWT bearer token with user and workspace context."""
    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    access_token = create_access_token({"sub": user.id, "email": user.email})
    workspaces = _get_user_workspaces(user.id, db)

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        workspaces=workspaces,
    )


@router.get(
    "/me",
    summary="Get current user and accessible workspaces",
)
def get_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the profile and workspaces of the currently authenticated user."""
    workspaces = _get_user_workspaces(current_user.id, db)
    return {
        "user": UserResponse.model_validate(current_user),
        "workspaces": workspaces,
    }


@router.post(
    "/seed-demo",
    summary="Idempotently seed default local demo user and workspace",
    description="Creates a local development account for testing if not already present. Strictly disabled outside development/test.",
)
def seed_demo(db: Session = Depends(get_db)):
    """Seed default SRE demo user and workspace for development and testing."""
    allowed_envs = {"development", "dev", "test", "testing", "local"}
    if settings.ENVIRONMENT.lower() not in allowed_envs:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo seeding is strictly disabled in production and non-development environments.",
        )

    demo_email = "sre@sentinelops.local"
    demo_password = "SentinelOps2026!"
    ws_slug = "demo-sre-workspace"

    # 1. Create or get workspace
    workspace = db.query(Workspace).filter(Workspace.slug == ws_slug).first()
    if not workspace:
        workspace = Workspace(
            name="Demo SRE Workspace",
            slug=ws_slug,
            description="Default SRE operational workspace for demonstration",
        )
        db.add(workspace)
        db.commit()
        db.refresh(workspace)

    # 2. Create or get user
    user = db.query(User).filter(User.email == demo_email).first()
    if not user:
        user = User(
            email=demo_email,
            full_name="Lead SRE Engineer",
            hashed_password=get_password_hash(demo_password),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # 3. Create or get membership (admin)
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    if not membership:
        membership = WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role="admin",
        )
        db.add(membership)
        db.commit()

    return {
        "status": "ready",
        "demo_user": {
            "email": demo_email,
            "password": demo_password,
            "full_name": user.full_name,
        },
        "workspace": {
            "id": workspace.id,
            "name": workspace.name,
            "slug": workspace.slug,
            "role": "admin",
        },
    }
