"""Add manifest signing and persistence columns to remediation_executions (Phase 2A.1 Stage 4)

Revision ID: 0010_manifest_signing
Revises: 0009_dynamic_playbooks
Create Date: 2026-11-07 19:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = "0010_manifest_signing"
down_revision: Union[str, None] = "0009_dynamic_playbooks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    json_col = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

    op.add_column("remediation_executions", sa.Column("manifest_id", sa.String(length=36), nullable=True))
    op.add_column("remediation_executions", sa.Column("authorization_manifest", json_col, nullable=True))
    op.add_column("remediation_executions", sa.Column("manifest_signature", sa.Text(), nullable=True))
    op.add_column("remediation_executions", sa.Column("manifest_digest", sa.String(length=64), nullable=True))
    op.add_column("remediation_executions", sa.Column("manifest_key_id", sa.String(length=64), nullable=True))
    op.add_column("remediation_executions", sa.Column("manifest_expires_at", sa.DateTime(timezone=True), nullable=True))

    op.create_index("ix_remediation_executions_manifest_id", "remediation_executions", ["manifest_id"])
    op.create_index("ix_remediation_executions_manifest_digest", "remediation_executions", ["manifest_digest"])


def downgrade() -> None:
    op.drop_index("ix_remediation_executions_manifest_digest", table_name="remediation_executions")
    op.drop_index("ix_remediation_executions_manifest_id", table_name="remediation_executions")

    op.drop_column("remediation_executions", "manifest_expires_at")
    op.drop_column("remediation_executions", "manifest_key_id")
    op.drop_column("remediation_executions", "manifest_digest")
    op.drop_column("remediation_executions", "manifest_signature")
    op.drop_column("remediation_executions", "authorization_manifest")
    op.drop_column("remediation_executions", "manifest_id")
