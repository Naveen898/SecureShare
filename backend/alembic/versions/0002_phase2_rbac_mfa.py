"""phase 2 rbac mfa

Revision ID: 0002_phase2_rbac_mfa
Revises: 0001_initial_schema
Create Date: 2025-10-20 00:00:00.000000

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0002_phase2_rbac_mfa'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('mfa_temp_code', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('mfa_temp_expires_at', sa.DateTime(timezone=True), nullable=True))
    # Remove server_default after set
    with op.batch_alter_table('users') as batch_op:
        batch_op.alter_column('mfa_enabled', server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('mfa_temp_expires_at')
        batch_op.drop_column('mfa_temp_code')
        batch_op.drop_column('mfa_enabled')
