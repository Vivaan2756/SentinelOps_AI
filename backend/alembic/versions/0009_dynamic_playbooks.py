"""Create dynamic playbooks and service association tables for Phase 4.1

Revision ID: 0009_dynamic_playbooks
Revises: 0008_verification_persistence
Create Date: 2026-11-03 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = '0009_dynamic_playbooks'
down_revision: Union[str, None] = '0008_verification_persistence'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use JSON with JSONB variant for PostgreSQL
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    # 1. Create playbooks table
    op.create_table(
        'playbooks',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=50), server_default='service_recovery', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('current_version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.UniqueConstraint('workspace_id', 'name', name='uq_playbooks_workspace_name'),
    )

    op.create_index('ix_playbooks_workspace_id', 'playbooks', ['workspace_id'])
    op.create_index('ix_playbooks_is_active', 'playbooks', ['is_active'])

    # 2. Create playbook_versions table
    op.create_table(
        'playbook_versions',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('playbook_id', sa.String(length=36), sa.ForeignKey('playbooks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version_number', sa.Integer(), server_default='1', nullable=False),
        sa.Column('action_template_id', sa.String(length=100), nullable=False),
        sa.Column('supported_scenarios', json_col, server_default='[]', nullable=False),
        sa.Column('parameter_schema', json_col, server_default='{}', nullable=False),
        sa.Column('verification_criteria', json_col, server_default='{}', nullable=False),
        sa.Column('risk_level', sa.String(length=20), server_default='medium', nullable=False),
        sa.Column('approval_required', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), server_default='30', nullable=False),
        sa.Column('change_summary', sa.String(length=255), nullable=True),
        sa.Column('created_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.UniqueConstraint('playbook_id', 'version_number', name='uq_playbook_version_number'),
    )

    op.create_index('ix_playbook_versions_playbook_id', 'playbook_versions', ['playbook_id'])
    op.create_index('ix_playbook_versions_action', 'playbook_versions', ['action_template_id'])

    # 3. Create service_playbook_associations table
    op.create_table(
        'service_playbook_associations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('service_id', sa.String(length=36), sa.ForeignKey('services.id', ondelete='CASCADE'), nullable=False),
        sa.Column('playbook_id', sa.String(length=36), sa.ForeignKey('playbooks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('priority', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.UniqueConstraint('service_id', 'playbook_id', name='uq_service_playbook'),
    )

    op.create_index('ix_spa_workspace_id', 'service_playbook_associations', ['workspace_id'])
    op.create_index('ix_spa_service_id', 'service_playbook_associations', ['service_id'])
    op.create_index('ix_spa_playbook_id', 'service_playbook_associations', ['playbook_id'])
    op.create_index('ix_spa_is_active', 'service_playbook_associations', ['is_active'])


def downgrade() -> None:
    op.drop_table('service_playbook_associations')
    op.drop_table('playbook_versions')
    op.drop_table('playbooks')
