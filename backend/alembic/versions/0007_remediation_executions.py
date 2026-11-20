"""Create remediation execution tables for Phase 4.3.2

Revision ID: 0007_remediation_executions
Revises: 0006_pending_approval_uq
Create Date: 2026-10-30 18:48:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = '0007_remediation_executions'
down_revision: Union[str, None] = '0006_pending_approval_uq'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use JSON with JSONB variant for PostgreSQL
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    # 1. Create remediation_executions table
    op.create_table(
        'remediation_executions',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('approval_id', sa.String(length=36), sa.ForeignKey('remediation_approvals.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('investigation_id', sa.String(length=36), sa.ForeignKey('investigations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_id', sa.String(length=100), nullable=False),
        sa.Column('target_service_id', sa.String(length=36), sa.ForeignKey('services.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_parameters', json_col, server_default='{}', nullable=False),
        sa.Column('status', sa.String(length=30), server_default='queued', nullable=False),
        sa.Column('idempotency_key', sa.String(length=64), nullable=False),
        sa.Column('locked_by', sa.String(length=100), nullable=True),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('fencing_token', sa.Integer(), server_default='0', nullable=False),
        sa.Column('retry_policy', sa.String(length=20), server_default='idempotent', nullable=False),
        sa.Column('triggered_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('triggered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('timeout_seconds', sa.Integer(), server_default='30', nullable=False),
        sa.Column('attempt_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('max_attempts', sa.Integer(), server_default='1', nullable=False),
        sa.Column('execution_output', json_col, nullable=True),
        sa.Column('verification_status', sa.String(length=30), nullable=True),
        sa.Column('verification_output', json_col, nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_category', sa.String(length=50), nullable=True),
        sa.Column('uncertain_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint(
            "status IN ('queued', 'validating', 'executing', 'execution_succeeded', 'execution_failed', 'timed_out', 'execution_uncertain', 'verification_pending', 'verified', 'verification_failed', 'cancelled')",
            name='ck_execution_status',
        ),
        sa.CheckConstraint(
            "retry_policy IN ('idempotent', 'non_idempotent')",
            name='ck_execution_retry_policy',
        ),
        sa.CheckConstraint(
            "verification_status IS NULL OR verification_status IN ('pending', 'verified', 'failed')",
            name='ck_execution_verification_status',
        ),
    )

    op.create_index('uq_execution_approval', 'remediation_executions', ['approval_id'], unique=True)
    op.create_index('uq_execution_idempotency', 'remediation_executions', ['workspace_id', 'idempotency_key'], unique=True)
    op.create_index('ix_execution_queue', 'remediation_executions', ['status', 'locked_until', 'triggered_at'])
    op.create_index('ix_remediation_executions_workspace_id', 'remediation_executions', ['workspace_id'])
    op.create_index('ix_remediation_executions_incident_id', 'remediation_executions', ['incident_id'])
    op.create_index('ix_remediation_executions_investigation_id', 'remediation_executions', ['investigation_id'])
    op.create_index('ix_remediation_executions_action_id', 'remediation_executions', ['action_id'])
    op.create_index('ix_remediation_executions_target_service_id', 'remediation_executions', ['target_service_id'])
    op.create_index('ix_remediation_executions_status', 'remediation_executions', ['status'])
    op.create_index('ix_remediation_executions_locked_until', 'remediation_executions', ['locked_until'])
    op.create_index('ix_remediation_executions_triggered_by', 'remediation_executions', ['triggered_by'])
    op.create_index('ix_remediation_executions_triggered_at', 'remediation_executions', ['triggered_at'])

    # 2. Create execution_attempts table
    op.create_table(
        'execution_attempts',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('execution_id', sa.String(length=36), sa.ForeignKey('remediation_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('attempt_number', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=30), server_default='running', nullable=False),
        sa.Column('worker_id', sa.String(length=100), nullable=True),
        sa.Column('fencing_token', sa.Integer(), server_default='0', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('stdout_sample', sa.Text(), nullable=True),
        sa.Column('stderr_sample', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_category', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint(
            "status IN ('running', 'succeeded', 'failed', 'timed_out', 'uncertain')",
            name='ck_attempt_status',
        ),
    )

    op.create_index('uq_attempt_execution_number', 'execution_attempts', ['execution_id', 'attempt_number'], unique=True)
    op.create_index('ix_execution_attempts_execution_id', 'execution_attempts', ['execution_id'])
    op.create_index('ix_execution_attempts_status', 'execution_attempts', ['status'])

    # 3. Create execution_events table
    op.create_table(
        'execution_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('execution_id', sa.String(length=36), sa.ForeignKey('remediation_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('metadata_json', json_col, nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    op.create_index('ix_execution_events_execution_id', 'execution_events', ['execution_id'])
    op.create_index('ix_execution_events_workspace_id', 'execution_events', ['workspace_id'])
    op.create_index('ix_execution_events_event_type', 'execution_events', ['event_type'])
    op.create_index('ix_execution_events_timestamp', 'execution_events', ['timestamp'])
    op.create_index('ix_execution_events_exec_time', 'execution_events', ['execution_id', 'timestamp'])
    op.create_index('ix_execution_events_ws_time', 'execution_events', ['workspace_id', 'timestamp'])


def downgrade() -> None:
    # 3. Drop execution_events
    op.drop_index('ix_execution_events_ws_time', table_name='execution_events')
    op.drop_index('ix_execution_events_exec_time', table_name='execution_events')
    op.drop_index('ix_execution_events_timestamp', table_name='execution_events')
    op.drop_index('ix_execution_events_event_type', table_name='execution_events')
    op.drop_index('ix_execution_events_workspace_id', table_name='execution_events')
    op.drop_index('ix_execution_events_execution_id', table_name='execution_events')
    op.drop_table('execution_events')

    # 2. Drop execution_attempts
    op.drop_index('ix_execution_attempts_status', table_name='execution_attempts')
    op.drop_index('ix_execution_attempts_execution_id', table_name='execution_attempts')
    op.drop_index('uq_attempt_execution_number', table_name='execution_attempts')
    op.drop_table('execution_attempts')

    # 1. Drop remediation_executions
    op.drop_index('ix_remediation_executions_triggered_at', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_triggered_by', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_locked_until', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_status', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_target_service_id', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_action_id', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_investigation_id', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_incident_id', table_name='remediation_executions')
    op.drop_index('ix_remediation_executions_workspace_id', table_name='remediation_executions')
    op.drop_index('ix_execution_queue', table_name='remediation_executions')
    op.drop_index('uq_execution_idempotency', table_name='remediation_executions')
    op.drop_index('uq_execution_approval', table_name='remediation_executions')
    op.drop_table('remediation_executions')
