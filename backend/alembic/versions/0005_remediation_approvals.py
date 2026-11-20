"""Create remediation_approvals table for Human Approval Workflow Phase 4.2

Revision ID: 0005_remediation_approvals
Revises: 0004_remediation_policy_tables
Create Date: 2026-10-30 16:47:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0005_remediation_approvals'
down_revision: Union[str, None] = '0004_remediation_policy_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use JSON with JSONB variant for PostgreSQL
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    op.create_table(
        'remediation_approvals',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('investigation_id', sa.String(length=36), sa.ForeignKey('investigations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('policy_decision_id', sa.String(length=36), sa.ForeignKey('policy_decisions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action_id', sa.String(length=100), nullable=False),
        sa.Column('target_service_id', sa.String(length=36), sa.ForeignKey('services.id', ondelete='SET NULL'), nullable=True),
        sa.Column('validated_parameters', json_col, server_default='{}', nullable=False),
        sa.Column('risk_level', sa.String(length=20), nullable=False),
        sa.Column('policy_version', sa.String(length=20), server_default='v1.0', nullable=False),
        sa.Column('requested_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approval_status', sa.String(length=30), server_default='pending', nullable=False),
        sa.Column('requested_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('reviewed_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_remediation_approvals_workspace_id', 'remediation_approvals', ['workspace_id'])
    op.create_index('ix_remediation_approvals_incident_id', 'remediation_approvals', ['incident_id'])
    op.create_index('ix_remediation_approvals_investigation_id', 'remediation_approvals', ['investigation_id'])
    op.create_index('ix_remediation_approvals_policy_decision_id', 'remediation_approvals', ['policy_decision_id'])
    op.create_index('ix_remediation_approvals_action_id', 'remediation_approvals', ['action_id'])
    op.create_index('ix_remediation_approvals_target_service_id', 'remediation_approvals', ['target_service_id'])
    op.create_index('ix_remediation_approvals_requested_by', 'remediation_approvals', ['requested_by'])
    op.create_index('ix_remediation_approvals_approval_status', 'remediation_approvals', ['approval_status'])
    op.create_index('ix_remediation_approvals_requested_at', 'remediation_approvals', ['requested_at'])
    op.create_index('ix_remediation_approvals_expires_at', 'remediation_approvals', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_remediation_approvals_expires_at', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_requested_at', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_approval_status', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_requested_by', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_target_service_id', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_action_id', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_policy_decision_id', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_investigation_id', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_incident_id', table_name='remediation_approvals')
    op.drop_index('ix_remediation_approvals_workspace_id', table_name='remediation_approvals')
    op.drop_table('remediation_approvals')
