"""Dynamic Remediation Playbook domain models for Phase 4.1.

Blueprint Section 8 & Phase 4.1:
- User-configurable remediation playbooks scoped to workspaces.
- Versioned configuration history preserving immutable snapshots.
- Service-to-playbook associations with workspace isolation.
- Allowlisted action template references (no arbitrary shell/code execution).
- Fail-closed activation and priority ordering.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

if TYPE_CHECKING:
    from app.models.workspace import Workspace
    from app.models.user import User
    from app.models.service import Service

JSONType = JSON().with_variant(postgresql.JSONB, "postgresql")


class Playbook(Base):
    """
    User-configurable remediation playbook entity.
    Belongs strictly to a workspace.
    Tracks active status, metadata, and points to current version.
    """
    __tablename__ = "playbooks"
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_playbooks_workspace_name"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, default="service_recovery"
    )  # service_recovery, diagnostics, monitoring
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
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
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
    creator: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by], lazy="select")
    versions: Mapped[List["PlaybookVersion"]] = relationship(
        "PlaybookVersion",
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="PlaybookVersion.version_number.desc()",
        lazy="select",
    )
    service_associations: Mapped[List["ServicePlaybookAssociation"]] = relationship(
        "ServicePlaybookAssociation",
        back_populates="playbook",
        cascade="all, delete-orphan",
        lazy="select",
    )

    @property
    def active_version(self) -> Optional["PlaybookVersion"]:
        """Return the PlaybookVersion matching current_version."""
        for v in self.versions:
            if v.version_number == self.current_version:
                return v
        return self.versions[0] if self.versions else None


class PlaybookVersion(Base):
    """
    Immutable versioned snapshot of a playbook specification.
    Captures action template ID, supported scenarios, parameter schemas,
    verification criteria, risk classification, and approval requirements.
    """
    __tablename__ = "playbook_versions"
    __table_args__ = (
        UniqueConstraint("playbook_id", "version_number", name="uq_playbook_version_number"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    playbook_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    action_template_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Supported scenarios (e.g. ["http_5xx_rate_exceeded", "latency_spike", "*"])
    supported_scenarios: Mapped[List[str]] = mapped_column(
        JSONType, nullable=False, default=list
    )

    # Parameter constraints and default values validated against action template schema
    parameter_schema: Mapped[Dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )

    # Structured or text verification criteria
    verification_criteria: Mapped[Dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )

    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )  # low, medium, high
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    change_summary: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    playbook: Mapped["Playbook"] = relationship("Playbook", back_populates="versions")
    creator: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by], lazy="select")


class ServicePlaybookAssociation(Base):
    """
    Multi-tenant binding between a service and a playbook within the same workspace.
    Supports priority ordering and individual activation status.
    """
    __tablename__ = "service_playbook_associations"
    __table_args__ = (
        UniqueConstraint("service_id", "playbook_id", name="uq_service_playbook"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    service_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=False, index=True
    )
    playbook_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
    service: Mapped["Service"] = relationship("Service", lazy="select")
    playbook: Mapped["Playbook"] = relationship("Playbook", back_populates="service_associations")
    creator: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by], lazy="select")
