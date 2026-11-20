"""Service domain model per blueprint specifications."""

import uuid
from datetime import datetime, timezone
from typing import List, TYPE_CHECKING, Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

if TYPE_CHECKING:
    from app.models.workspace import Workspace
    from app.models.incident import Incident


class Service(Base):
    """
    Monitored service entity registered within a workspace.
    Blueprint Section 7:
    - Service name: 2-100 characters
    - Environment: development, staging, production
    - Health-check URL: validated string format, no automatic probing
    - Monitoring method: prometheus, opentelemetry, or builtin
    - Execution policy: demo, approval_required, or observe_only
    - Demo integration: explicit identifier (e.g. order_api) for demo recovery
    """
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(
        String(50), nullable=False, default="development"
    )  # development, staging, production
    health_check_url: Mapped[str] = mapped_column(String(500), nullable=False)
    monitoring_method: Mapped[str] = mapped_column(
        String(50), nullable=False, default="prometheus"
    )  # prometheus, opentelemetry, builtin
    execution_policy: Mapped[str] = mapped_column(
        String(50), nullable=False, default="demo"
    )  # demo, approval_required, observe_only
    demo_integration: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True, default=None, index=True
    )  # explicit demo classification: e.g. "order_api"
    recovery_endpoint: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, default=None
    )  # authorized relative recovery path (e.g. /demo/restore, /admin/recovery/reset)
    recovery_method: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True, default=None
    )  # authorized HTTP method for recovery (initially POST)
    recovery_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # whether recovery is explicitly configured and authorized
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    health_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="unknown"
    )  # healthy, degraded, unhealthy, unknown
    last_checked_at: Mapped[datetime | None] = mapped_column(
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
    workspace: Mapped["Workspace"] = relationship("Workspace", back_populates="services")
    incidents: Mapped[List["Incident"]] = relationship(
        "Incident", back_populates="service", cascade="all, delete-orphan"
    )
