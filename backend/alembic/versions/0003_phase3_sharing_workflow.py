"""phase 3 sharing & workflow

Revision ID: 0003_phase3_sharing_workflow
Revises: 0002_phase2_rbac_mfa
Create Date: 2025-10-20 00:00:00.000000

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0003_phase3_sharing_workflow'
down_revision = '0002_phase2_rbac_mfa'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('employee_id', sa.String(), nullable=True))
        batch_op.create_index('ix_users_employee_id', ['employee_id'], unique=True)
    with op.batch_alter_table('departments') as batch_op:
        batch_op.add_column(sa.Column('pin_hash', sa.String(), nullable=True))
    with op.batch_alter_table('file_metadata') as batch_op:
        batch_op.add_column(sa.Column('comments', sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('file_metadata') as batch_op:
        batch_op.drop_column('comments')
    with op.batch_alter_table('departments') as batch_op:
        batch_op.drop_column('pin_hash')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_index('ix_users_employee_id')
        batch_op.drop_column('employee_id')
