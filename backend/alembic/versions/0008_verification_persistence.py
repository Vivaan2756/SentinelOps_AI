"""Create verification persistence tables for Phase 4.3.6 Milestone A

Revision ID: 0008_verification_persistence
Revises: 0007_remediation_executions
Create Date: 2026-10-31 18:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = '0008_verification_persistence'
down_revision: Union[str, None] = '0007_remediation_executions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use JSON with JSONB variant for PostgreSQL
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    # 1. Create verification_cycles table
    op.create_table(
        'verification_cycles',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('execution_id', sa.String(length=36), sa.ForeignKey('remediation_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cycle_number', sa.Integer(), server_default='1', nullable=False),
        sa.Column('status', sa.String(length=30), server_default='pending', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deadline_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('fencing_token', sa.Integer(), server_default='0', nullable=False),
        sa.Column('verifying_worker_id', sa.String(length=100), nullable=True),
        sa.Column('probes_required', sa.Integer(), server_default='3', nullable=False),
        sa.Column('probes_passed', sa.Integer(), server_default='0', nullable=False),
        sa.Column('probes_failed', sa.Integer(), server_default='0', nullable=False),
        sa.Column('cycle_metadata', json_col, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.UniqueConstraint('execution_id', 'cycle_number', name='uq_verification_cycle_exec_number'),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'passed', 'failed', 'timed_out', 'uncertain')",
            name='ck_verification_cycle_status',
        ),
    )

    op.create_index('ix_verification_cycles_workspace_id', 'verification_cycles', ['workspace_id'])
    op.create_index('ix_verification_cycles_execution_id', 'verification_cycles', ['execution_id'])
    op.create_index('ix_verification_cycles_status', 'verification_cycles', ['status'])
    op.create_index('ix_verification_cycles_deadline_at', 'verification_cycles', ['deadline_at'])

    # 2. Create verification_probe_results table
    op.create_table(
        'verification_probe_results',
        sa.Column('id', sa.String(length=100), primary_key=True),
        sa.Column('cycle_id', sa.String(length=36), sa.ForeignKey('verification_cycles.id', ondelete='CASCADE'), nullable=False),
        sa.Column('execution_id', sa.String(length=36), sa.ForeignKey('remediation_executions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('probe_number', sa.Integer(), nullable=False),
        sa.Column('probe_type', sa.String(length=50), server_default='http_health', nullable=False),
        sa.Column('target_url', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('passed', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('probe_output', json_col, nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.UniqueConstraint('cycle_id', 'probe_number', name='uq_probe_cycle_number'),
        sa.CheckConstraint(
            "status IN ('passed', 'failed', 'error', 'timeout')",
            name='ck_verification_probe_status',
        ),
    )

    op.create_index('ix_verification_probes_cycle_id', 'verification_probe_results', ['cycle_id'])
    op.create_index('ix_verification_probes_execution_id', 'verification_probe_results', ['execution_id'])
    op.create_index('ix_verification_probes_workspace_id', 'verification_probe_results', ['workspace_id'])
    op.create_index('ix_verification_probes_status', 'verification_probe_results', ['status'])


def downgrade() -> None:
    # 2. Drop verification_probe_results
    op.drop_index('ix_verification_probes_status', table_name='verification_probe_results')
    op.drop_index('ix_verification_probes_workspace_id', table_name='verification_probe_results')
    op.drop_index('ix_verification_probes_execution_id', table_name='verification_probe_results')
    op.drop_index('ix_verification_probes_cycle_id', table_name='verification_probe_results')
    op.drop_table('verification_probe_results')

    # 1. Drop verification_cycles
    op.drop_index('ix_verification_cycles_deadline_at', table_name='verification_cycles')
    op.drop_index('ix_verification_cycles_status', table_name='verification_cycles')
    op.drop_index('ix_verification_cycles_execution_id', table_name='verification_cycles')
    op.drop_index('ix_verification_cycles_workspace_id', table_name='verification_cycles')
    op.drop_table('verification_cycles')
