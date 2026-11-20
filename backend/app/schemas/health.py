"""Health check response schemas."""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class DatabaseHealth(BaseModel):
    """Database connectivity health status."""
    connected: bool = Field(..., description="Whether the database responded to a heartbeat query")
    message: str = Field(..., description="Sanitized status message")


class HealthResponse(BaseModel):
    """Overall system health check response."""
    status: str = Field(..., description="'healthy' or 'degraded'")
    service: str = Field(..., description="Service identifier")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC check timestamp"
    )
    database: Optional[DatabaseHealth] = Field(None, description="Database status diagnostics")
