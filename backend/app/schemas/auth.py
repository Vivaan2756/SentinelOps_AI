"""Authentication and authorization schemas."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """User credentials for authentication."""
    email: str = Field(..., json_schema_extra={"example": "sre@sentinelops.local"})
    password: str = Field(..., min_length=6, json_schema_extra={"example": "SentinelOps2026!"})


class Token(BaseModel):
    """Bearer access token schema."""
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """Safe user profile response without credentials."""
    id: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserWorkspaceMembership(BaseModel):
    """Workspace context assigned to a user."""
    workspace_id: str
    workspace_name: str
    workspace_slug: str
    role: str  # admin, engineer, viewer


class LoginResponse(BaseModel):
    """Complete authentication response."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    workspaces: List[UserWorkspaceMembership]
