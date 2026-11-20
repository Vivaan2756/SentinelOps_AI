"""Add health_status and last_checked_at to services

Revision ID: 0002_service_health_fields
Revises: 0001_initial_schema
Create Date: 2026-10-29 21:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0002_service_health_fields'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'services',
        sa.Column('health_status', sa.String(length=20), server_default='unknown', nullable=False),
    )
    op.add_column(
        'services',
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('services', 'last_checked_at')
    op.drop_column('services', 'health_status')
