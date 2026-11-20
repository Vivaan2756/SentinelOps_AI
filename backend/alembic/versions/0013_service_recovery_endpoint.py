"""Add recovery_endpoint, recovery_method, recovery_enabled to services (Stage 4 / P0.2)

Revision ID: 0013_service_recovery_endpoint
Revises: 0012_service_demo_integration
Create Date: 2026-11-12 21:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = "0013_service_recovery_endpoint"
down_revision: Union[str, None] = "0012_service_demo_integration"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("services", sa.Column("recovery_endpoint", sa.String(length=255), nullable=True))
    op.add_column("services", sa.Column("recovery_method", sa.String(length=10), nullable=True))
    op.add_column("services", sa.Column("recovery_enabled", sa.Boolean(), server_default="false", nullable=False))


def downgrade() -> None:
    op.drop_column("services", "recovery_enabled")
    op.drop_column("services", "recovery_method")
    op.drop_column("services", "recovery_endpoint")
