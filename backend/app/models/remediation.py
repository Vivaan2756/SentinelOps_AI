"""Remediation and Policy Decision database models per Phase 4.1 specification."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, TYPE_CHECKING
from sqlalchemy import String, Text, DateTime, ForeignKey, JSON, Index, Integer, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

if TYPE_CHECKING:
    from app.models.workspace import Workspace
    from app.models.user import User
    from app.models.service import Service
    from app.models.incident import Incident
    from app.models.investigation import Investigation
    from app.models.verification import VerificationCycle, VerificationProbeResult

JSONType = JSON().with_variant(postgresql.JSONB, "postgresql")


class PolicyDecision(Base):
    """
    Immutable audit record capturing every remediation policy evaluation.
    Logs caller, target workspace/service, action ID, risk level, parameters,
    and deterministic decision rationale.
    """
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_service_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("services.id", ondelete="SET NULL"), nullable=True, index=True
    )
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)  # low, medium, high
    decision: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # allowed, approval_required, rejected
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1.0")
    validated_parameters: Mapped[Dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Computed convenience properties for schema serialization
    @property
    def evaluated_at(self) -> datetime:
        return self.timestamp

    @property
    def approval_required(self) -> bool:
        return self.decision == "approval_required"

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
    user: Mapped["User | None"] = relationship("User", lazy="select")
    target_service: Mapped["Service | None"] = relationship("Service", lazy="select")


class RemediationApproval(Base):
    """
    Human-in-the-loop approval request for remediation proposals.
    Blueprint Section 8 & Phase 4.2:
    - Binds exact action, target service, and validated parameters
    - Strictly separates authorization from execution (Phase 4.3)
    - Records requesting engineer, reviewer, status, timestamps, and expiration
    """
    __tablename__ = "remediation_approvals"
    __table_args__ = (
        Index(
            "uq_pending_policy_decision",
            "policy_decision_id",
            unique=True,
            postgresql_where=text("approval_status = 'pending'"),
            sqlite_where=text("approval_status = 'pending'"),
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    investigation_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    policy_decision_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("policy_decisions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_service_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("services.id", ondelete="SET NULL"), nullable=True, index=True
    )
    validated_parameters: Mapped[Dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)  # low, medium, high
    policy_version: Mapped[str] = mapped_column(String(20), nullable=False, default="v1.0")

    requested_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    approval_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="pending", index=True
    )  # pending, approved, rejected, expired, cancelled
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    reviewed_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
    incident: Mapped["Incident | None"] = relationship("Incident", lazy="select")
    investigation: Mapped["Investigation | None"] = relationship("Investigation", lazy="select")
    policy_decision: Mapped["PolicyDecision"] = relationship("PolicyDecision", lazy="select")
    target_service: Mapped["Service | None"] = relationship("Service", lazy="select")
    requester: Mapped["User | None"] = relationship(
        "User", foreign_keys=[requested_by], lazy="select"
    )
    reviewer: Mapped["User | None"] = relationship(
        "User", foreign_keys=[reviewed_by], lazy="select"
    )

    @property
    def is_expired(self) -> bool:
        """Helper to determine whether pending approval has passed its expiry deadline."""
        if self.approval_status != "pending" or not self.expires_at:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp


class RemediationExecution(Base):
    """
    Controlled Remediation Execution entity tracking the execution lifecycle
    of an approved proposal (or pre-approved low-risk proposal).
    Phase 4.3 Architecture:
    - Binds 1-to-1 to an approved proposal (or policy decision)
    - Enforces idempotency per workspace
    - Manages worker leases, stale-worker fencing tokens, and execution timeouts
    - Records safe sanitized outputs, verification outcomes, and failure states
    """
    __tablename__ = "remediation_executions"
    __table_args__ = (
        # Invariant 1: One execution per approval (prevents approval replay)
        Index("uq_execution_approval", "approval_id", unique=True),
        # Invariant 2: Idempotency uniqueness within a workspace
        Index("uq_execution_idempotency", "workspace_id", "idempotency_key", unique=True),
        # Polling queue index for durable worker with SKIP LOCKED
        Index("ix_execution_queue", "status", "locked_until", "triggered_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approval_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remediation_approvals.id", ondelete="RESTRICT"), nullable=False
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    investigation_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Action & Target Service Binding
    action_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_service_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("services.id", ondelete="SET NULL"), nullable=True, index=True
    )
    approved_parameters: Mapped[Dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )

    # State Machine: 11 explicit states
    # queued, validating, executing, execution_succeeded, execution_failed,
    # timed_out, execution_uncertain, verification_pending, verified, verification_failed, cancelled
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="queued", index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)

    # Worker Lease & Fencing Token for durable claim engine
    locked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retry_policy: Mapped[str] = mapped_column(String(20), nullable=False, default="idempotent")

    # Audit & Operators
    triggered_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Execution & Verification Results (Sanitized / Zero secrets)
    execution_output: Mapped[Dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    verification_status: Mapped[str | None] = mapped_column(String(30), nullable=True)  # pending, verified, failed
    verification_output: Mapped[Dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    uncertain_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Phase 2A.1 Stage 4: Control-Plane Manifest Signing & Persistence
    manifest_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    authorization_manifest: Mapped[Dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    manifest_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    manifest_digest: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    manifest_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
    approval: Mapped["RemediationApproval"] = relationship("RemediationApproval", lazy="select")
    incident: Mapped["Incident | None"] = relationship("Incident", lazy="select")
    investigation: Mapped["Investigation | None"] = relationship("Investigation", lazy="select")
    target_service: Mapped["Service | None"] = relationship("Service", lazy="select")
    triggerer: Mapped["User"] = relationship("User", foreign_keys=[triggered_by], lazy="select")
    attempts: Mapped[List["ExecutionAttempt"]] = relationship(
        "ExecutionAttempt", back_populates="execution", cascade="all, delete-orphan", order_by="ExecutionAttempt.attempt_number"
    )
    events: Mapped[List["ExecutionEvent"]] = relationship(
        "ExecutionEvent", back_populates="execution", cascade="all, delete-orphan", order_by="ExecutionEvent.timestamp"
    )
    verification_cycles: Mapped[List["VerificationCycle"]] = relationship(
        "VerificationCycle", back_populates="execution", cascade="all, delete-orphan", order_by="VerificationCycle.cycle_number"
    )
    verification_probes: Mapped[List["VerificationProbeResult"]] = relationship(
        "VerificationProbeResult", back_populates="execution", cascade="all, delete-orphan", order_by="VerificationProbeResult.executed_at"
    )


class ExecutionAttempt(Base):
    """
    Individual container/worker execution attempt record.
    Tracks duration, exit codes, and sanitized logs per attempt.
    """
    __tablename__ = "execution_attempts"
    __table_args__ = (
        Index("uq_attempt_execution_number", "execution_id", "attempt_number", unique=True),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remediation_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="running", index=True
    )  # running, succeeded, failed, timed_out, uncertain
    worker_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)

    stdout_sample: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_sample: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_category: Mapped[str | None] = mapped_column(String(50), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    execution: Mapped["RemediationExecution"] = relationship("RemediationExecution", back_populates="attempts")


class ExecutionEvent(Base):
    """
    Fine-grained timeline and audit events for a remediation execution.
    Associates directly with both parent execution and workspace for tenant-scoped querying.
    """
    __tablename__ = "execution_events"
    __table_args__ = (
        Index("ix_execution_events_exec_time", "execution_id", "timestamp"),
        Index("ix_execution_events_ws_time", "workspace_id", "timestamp"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remediation_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[Dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    # Relationships
    execution: Mapped["RemediationExecution"] = relationship("RemediationExecution", back_populates="events")
    workspace: Mapped["Workspace"] = relationship("Workspace", lazy="select")
