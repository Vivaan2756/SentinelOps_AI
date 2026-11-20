"""Workspace schemas for multi-tenant isolation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, json_schema_extra={"example": "Core Production SRE"})
    slug: str = Field(..., min_length=2, max_length=100, json_schema_extra={"example": "core-prod-sre"})
    description: Optional[str] = Field(None, max_length=255)


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    role: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
