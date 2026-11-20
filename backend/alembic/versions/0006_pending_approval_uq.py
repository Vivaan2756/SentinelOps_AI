"""Add partial unique index uq_pending_policy_decision on remediation_approvals

Revision ID: 0006_pending_approval_uq
Revises: 0005_remediation_approvals
Create Date: 2026-10-30 17:36:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic (<= 32 chars).
revision: str = '0006_pending_approval_uq'
down_revision: Union[str, None] = '0005_remediation_approvals'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Defensively handle any duplicate pending records if present:
    # Safely transition older duplicate pending approvals to 'expired'
    # so historical records are NOT deleted and uniqueness is satisfied.
    conn = op.get_bind()
    conn.execute(sa.text("""
        UPDATE remediation_approvals
        SET approval_status = 'expired'
        WHERE id IN (
            SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY policy_decision_id
                           ORDER BY requested_at DESC, id DESC
                       ) as rn
                FROM remediation_approvals
                WHERE approval_status = 'pending'
            ) sub
            WHERE rn > 1
        );
    """))

    # 2. Create partial unique index ensuring only one 'pending' approval per policy decision
    op.create_index(
        'uq_pending_policy_decision',
        'remediation_approvals',
        ['policy_decision_id'],
        unique=True,
        postgresql_where=sa.text("approval_status = 'pending'"),
        sqlite_where=sa.text("approval_status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_index(
        'uq_pending_policy_decision',
        table_name='remediation_approvals',
        postgresql_where=sa.text("approval_status = 'pending'"),
        sqlite_where=sa.text("approval_status = 'pending'"),
    )
