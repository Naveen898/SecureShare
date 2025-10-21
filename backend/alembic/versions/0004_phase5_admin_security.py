"""
Phase 5: scan status, security settings, user lockout

Revision ID: 0004_phase5_admin_security
Revises: 0003_phase3_sharing_workflow
Create Date: 2025-10-20
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0004_phase5_admin_security'
down_revision = '0003_phase3_sharing_workflow'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('file_metadata') as batch_op:
        batch_op.add_column(sa.Column('scan_status', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('scan_details', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=True))

    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('lockout_until', sa.DateTime(timezone=True), nullable=True))
        batch_op.alter_column('failed_login_attempts', server_default=None)

    op.create_table(
        'security_settings',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('enforce_mfa_admin', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('enforce_mfa_all', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('min_password_length', sa.Integer(), nullable=False, server_default='8'),
        sa.Column('password_regex', sa.String(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('(CURRENT_TIMESTAMP)')),
    )


def downgrade():
    op.drop_table('security_settings')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('failed_login_attempts')
        batch_op.drop_column('lockout_until')
    with op.batch_alter_table('file_metadata') as batch_op:
        batch_op.drop_column('scan_status')
        batch_op.drop_column('scan_details')
        batch_op.drop_column('scanned_at')
