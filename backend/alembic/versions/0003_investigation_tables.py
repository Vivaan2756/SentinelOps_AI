"""Create investigations table for Agentic AI Incident Investigation

Revision ID: 0003_investigation_tables
Revises: 0002_service_health_fields
Create Date: 2026-10-30 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0003_investigation_tables'
down_revision: Union[str, None] = '0002_service_health_fields'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use JSON with JSONB variant for PostgreSQL
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    op.create_table(
        'investigations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('workspace_id', sa.String(length=36), sa.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='pending', nullable=False),
        sa.Column('model_name', sa.String(length=100), server_default='gemini-2.5-flash', nullable=False),
        sa.Column('prompt_version', sa.String(length=50), server_default='v1.0', nullable=False),
        sa.Column('evidence', json_col, server_default='[]', nullable=False),
        sa.Column('hypotheses', json_col, server_default='[]', nullable=False),
        sa.Column('summary', json_col, nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('token_usage', json_col, nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('ix_investigations_incident_id', 'investigations', ['incident_id'])
    op.create_index('ix_investigations_workspace_id', 'investigations', ['workspace_id'])


def downgrade() -> None:
    op.drop_index('ix_investigations_workspace_id', table_name='investigations')
    op.drop_index('ix_investigations_incident_id', table_name='investigations')
    op.drop_table('investigations')
