"""Create policy_decisions table for Remediation Foundation Phase 4.1

Revision ID: 0004_remediation_policy_tables
Revises: 0003_investigation_tables
Create Date: 2026-10-30 16:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0004_remediation_policy_tables'
down_revision: Union[str, None] = '0003_investigation_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use JSON with JSONB variant for PostgreSQL
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    op.create_table(
        'policy_decisions',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_id', sa.String(length=100), nullable=False),
        sa.Column('target_service_id', sa.String(length=36), sa.ForeignKey('services.id', ondelete='SET NULL'), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=False),
        sa.Column('decision', sa.String(length=30), nullable=False),
        sa.Column('decision_reason', sa.Text(), nullable=False),
        sa.Column('policy_version', sa.String(length=20), server_default='v1.0', nullable=False),
        sa.Column('validated_parameters', json_col, server_default='{}', nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_policy_decisions_workspace_id', 'policy_decisions', ['workspace_id'])
    op.create_index('ix_policy_decisions_user_id', 'policy_decisions', ['user_id'])
    op.create_index('ix_policy_decisions_action_id', 'policy_decisions', ['action_id'])
    op.create_index('ix_policy_decisions_target_service_id', 'policy_decisions', ['target_service_id'])
    op.create_index('ix_policy_decisions_timestamp', 'policy_decisions', ['timestamp'])


def downgrade() -> None:
    op.drop_index('ix_policy_decisions_timestamp', table_name='policy_decisions')
    op.drop_index('ix_policy_decisions_target_service_id', table_name='policy_decisions')
    op.drop_index('ix_policy_decisions_action_id', table_name='policy_decisions')
    op.drop_index('ix_policy_decisions_user_id', table_name='policy_decisions')
    op.drop_index('ix_policy_decisions_workspace_id', table_name='policy_decisions')
    op.drop_table('policy_decisions')
