"""Verification Cycle and Probe Result domain models for Phase 4.3.6.

Tracks verification cycles, individual probe results, deadlines, and sanitized probe outputs.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
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
    from app.models.remediation import RemediationExecution

JSONType = JSON().with_variant(postgresql.JSONB, "postgresql")


class VerificationCycle(Base):
    """
    Durable record of a synthetic verification cycle executed for a remediation execution.
    Tracks cycle number, start time, deadline, probe requirements, and status.
    """
    __tablename__ = "verification_cycles"
    __table_args__ = (
        UniqueConstraint("execution_id", "cycle_number", name="uq_verification_cycle_exec_number"),
        CheckConstraint(
            "status IN ('pending', 'running', 'passed', 'failed', 'timed_out', 'uncertain')",
            name="ck_verification_cycle_status",
        ),
        Index("ix_verification_cycles_workspace_id", "workspace_id"),
        Index("ix_verification_cycles_execution_id", "execution_id"),
        Index("ix_verification_cycles_status", "status"),
        Index("ix_verification_cycles_deadline_at", "deadline_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remediation_executions.id", ondelete="CASCADE"), nullable=False
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    cycle_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="pending"
    )  # pending, running, passed, failed, timed_out, uncertain
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    deadline_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verifying_worker_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    probes_required: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    probes_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    probes_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cycle_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    execution: Mapped["RemediationExecution"] = relationship(
        "RemediationExecution", back_populates="verification_cycles"
    )
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
    probes: Mapped[List["VerificationProbeResult"]] = relationship(
        "VerificationProbeResult",
        back_populates="cycle",
        cascade="all, delete-orphan",
        order_by="VerificationProbeResult.probe_number",
    )


class VerificationProbeResult(Base):
    """
    Granular result record for an individual synthetic verification probe.
    Enforces deterministic identity (id) and idempotency across probe executions.
    """
    __tablename__ = "verification_probe_results"
    __table_args__ = (
        UniqueConstraint("cycle_id", "probe_number", name="uq_probe_cycle_number"),
        CheckConstraint(
            "status IN ('passed', 'failed', 'error', 'timeout')",
            name="ck_verification_probe_status",
        ),
        Index("ix_verification_probes_cycle_id", "cycle_id"),
        Index("ix_verification_probes_execution_id", "execution_id"),
        Index("ix_verification_probes_workspace_id", "workspace_id"),
        Index("ix_verification_probes_status", "status"),
    )

    id: Mapped[str] = mapped_column(
        String(100), primary_key=True  # Deterministic probe ID
    )
    cycle_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("verification_cycles.id", ondelete="CASCADE"), nullable=False
    )
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remediation_executions.id", ondelete="CASCADE"), nullable=False
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    probe_number: Mapped[int] = mapped_column(Integer, nullable=False)
    probe_type: Mapped[str] = mapped_column(String(50), nullable=False, default="http_health")
    target_url: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # passed, failed, error, timeout
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    probe_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    cycle: Mapped["VerificationCycle"] = relationship(
        "VerificationCycle", back_populates="probes"
    )
    execution: Mapped["RemediationExecution"] = relationship(
        "RemediationExecution", back_populates="verification_probes"
    )
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
