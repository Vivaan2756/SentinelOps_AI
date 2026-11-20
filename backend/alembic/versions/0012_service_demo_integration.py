"""Add demo_integration column to services (Stage 3.2 / AUDIT-3.1-02)

Revision ID: 0012_service_demo_integration
Revises: 0011_dedicated_worker_role
Create Date: 2026-11-09 21:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = "0012_service_demo_integration"
down_revision: Union[str, None] = "0011_dedicated_worker_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("services", sa.Column("demo_integration", sa.String(length=50), nullable=True))
    op.create_index(op.f("ix_services_demo_integration"), "services", ["demo_integration"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_services_demo_integration"), table_name="services")
    op.drop_column("services", "demo_integration")
