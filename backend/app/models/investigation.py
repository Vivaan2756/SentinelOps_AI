"""Investigation and root-cause analysis models for Agentic SRE."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

if TYPE_CHECKING:
    from app.models.workspace import Workspace
    from app.models.incident import Incident

# Use JSON with JSONB variant for PostgreSQL
JSONType = JSON().with_variant(postgresql.JSONB, "postgresql")


class Investigation(Base):
    """
    Investigation record tracking the LangGraph agentic diagnosis lifecycle.
    Stores real evidence references, evaluated hypotheses, structured summary,
    model metadata, and token usage metrics.
    """
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending"
    )  # "pending", "running", "completed", "partially_completed", "failed"
    model_name: Mapped[str] = mapped_column(
        String(100), nullable=False, default="gemini-2.5-flash"
    )
    prompt_version: Mapped[str] = mapped_column(
        String(50), nullable=False, default="v1.0"
    )

    # Structured investigation telemetry & reasoning artifacts
    evidence: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=False, default=list
    )
    hypotheses: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=False, default=list
    )
    summary: Mapped[Dict[str, Any] | None] = mapped_column(
        JSONType, nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_usage: Mapped[Dict[str, Any] | None] = mapped_column(
        JSONType, nullable=True
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="investigations")
    workspace: Mapped["Workspace"] = relationship("Workspace", back_populates="investigations")

    @property
    def remediation_recommendation(self) -> Optional[Dict[str, Any]]:
        """Extract structured dynamic remediation recommendation from summary JSONB if present."""
        if self.summary and isinstance(self.summary, dict):
            return self.summary.get("remediation_recommendation")
        return None
