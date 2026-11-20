"""Incident schemas per blueprint specifications."""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


class IncidentBase(BaseModel):
    """Common incident attributes."""
    title: str = Field(..., max_length=255, description="Brief incident title")
    severity: Literal["critical", "high", "medium", "low"] = Field(
        default="high", description="Incident severity level"
    )
    status: Literal[
        "detected",
        "investigating",
        "awaiting_approval",
        "investigation_failed",
        "remediating",
        "verifying",
        "recovered",
        "closed",
    ] = Field(default="detected", description="Incident lifecycle state")
    trigger: str = Field(
        ..., max_length=255, description="Alert rule or trigger condition"
    )
    summary: Optional[str] = Field(None, description="Detailed incident summary or notes")


class IncidentCreate(IncidentBase):
    """Schema for opening a new incident."""
    workspace_id: str = Field(..., description="Workspace ID")
    service_id: str = Field(..., description="Affected service ID")


class IncidentResponse(IncidentBase):
    """Schema for incident data presentation."""
    id: str
    workspace_id: str
    service_id: str
    detected_at: datetime
    recovered_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class IncidentCloseRequest(BaseModel):
    """Schema for formally closing an incident."""
    resolution_notes: str = Field(
        ...,
        min_length=1,
        description="Detailed notes explaining how the incident was resolved and verified",
    )
    workspace_id: Optional[str] = Field(
        None,
        description="Optional workspace ID for tenant scoping",
    )

    @field_validator("resolution_notes")
    @classmethod
    def validate_notes(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Resolution notes cannot be empty or whitespace.")
        return v.strip()
