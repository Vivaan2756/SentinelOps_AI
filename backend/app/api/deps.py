"""FastAPI dependency injection for authentication and workspace authorization."""

from typing import Optional
from fastapi import Depends, HTTPException, Query, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.security import decode_access_token
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership

security_scheme = HTTPBearer(auto_error=False)

ROLE_LEVELS = {
    "admin": 3,
    "engineer": 2,
    "viewer": 1,
}


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate Bearer JWT token and return active User entity."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload["sub"]
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account.",
        )

    return user


def check_workspace_role(
    workspace_id: str,
    user_id: str,
    db: Session,
    min_role: Optional[str] = None,
) -> WorkspaceMembership:
    """Check that user belongs to workspace and has at least min_role."""
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{workspace_id}' not found.",
        )

    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.user_id == user_id,
        )
        .first()
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: User is not a member of this workspace.",
        )

    if min_role:
        user_level = ROLE_LEVELS.get(membership.role.lower(), 0)
        required_level = ROLE_LEVELS.get(min_role.lower(), 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: Action requires '{min_role}' role or higher.",
            )

    return membership


class RequireWorkspaceRole:
    """Dependency for endpoints receiving workspace_id as a parameter."""
    def __init__(self, min_role: Optional[str] = None):
        self.min_role = min_role

    def __call__(
        self,
        workspace_id: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> WorkspaceMembership:
        return check_workspace_role(
            workspace_id=workspace_id,
            user_id=current_user.id,
            db=db,
            min_role=self.min_role,
        )
