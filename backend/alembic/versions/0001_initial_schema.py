"""initial schema

Revision ID: 0001_initial
Revises: 
Create Date: 2025-09-15 00:00:00
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reset_token', sa.String(), nullable=True),
        sa.Column('reset_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('department_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='active'),
    )
    op.create_index('ix_users_id', 'users', ['id'], unique=False)
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_reset_token', 'users', ['reset_token'], unique=False)

    # departments
    op.create_table(
        'departments',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_departments_name', 'departments', ['name'], unique=True)

    # roles
    op.create_table(
        'roles',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ux_roles_name', 'roles', ['name'], unique=True)

    # user_roles
    op.create_table(
        'user_roles',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('user_id', 'role_id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
    )

    # file_metadata
    op.create_table(
        'file_metadata',
        sa.Column('file_id', sa.String(), primary_key=True),
        sa.Column('orig_name', sa.String(), nullable=False),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(), nullable=True),
        sa.Column('secret_hash', sa.String(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('deleted', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    sa.Column('secret_attempts', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('owner_user_id', sa.Integer(), nullable=True),
        sa.Column('department_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['owner_user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['department_id'], ['departments.id']),
    )
    op.create_index('ix_file_metadata_file_id', 'file_metadata', ['file_id'], unique=False)
    op.create_index('ix_file_metadata_owner_user_id', 'file_metadata', ['owner_user_id'], unique=False)
    op.create_index('ix_file_metadata_department_id', 'file_metadata', ['department_id'], unique=False)

    # file_access_logs
    op.create_table(
        'file_access_logs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('file_id', sa.String(), nullable=False),
        sa.Column('actor_user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=32), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('meta', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['file_id'], ['file_metadata.file_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id']),
    )
    op.create_index('ix_file_access_logs_file_id', 'file_access_logs', ['file_id'], unique=False)
    op.create_index('ix_file_access_logs_actor_user_id', 'file_access_logs', ['actor_user_id'], unique=False)

    # transfer_requests
    op.create_table(
        'transfer_requests',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('file_id', sa.String(), nullable=False),
        sa.Column('from_department_id', sa.Integer(), nullable=True),
        sa.Column('to_department_id', sa.Integer(), nullable=True),
        sa.Column('requester_user_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='PENDING'),
        sa.Column('decided_by_user_id', sa.Integer(), nullable=True),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reason', sa.String(length=256), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['file_id'], ['file_metadata.file_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['from_department_id'], ['departments.id']),
        sa.ForeignKeyConstraint(['to_department_id'], ['departments.id']),
        sa.ForeignKeyConstraint(['requester_user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['decided_by_user_id'], ['users.id']),
    )
    op.create_index('ix_transfer_requests_file_id', 'transfer_requests', ['file_id'], unique=False)
    op.create_index('ix_transfer_requests_requester_user_id', 'transfer_requests', ['requester_user_id'], unique=False)

    # file_recipients
    op.create_table(
        'file_recipients',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('file_id', sa.String(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('notified_sent', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.ForeignKeyConstraint(['file_id'], ['file_metadata.file_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_file_recipients_file_id', 'file_recipients', ['file_id'], unique=False)
    op.create_index('ix_file_recipients_user_id', 'file_recipients', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_file_recipients_user_id', table_name='file_recipients')
    op.drop_index('ix_file_recipients_file_id', table_name='file_recipients')
    op.drop_table('file_recipients')

    op.drop_index('ix_transfer_requests_requester_user_id', table_name='transfer_requests')
    op.drop_index('ix_transfer_requests_file_id', table_name='transfer_requests')
    op.drop_table('transfer_requests')

    op.drop_index('ix_file_access_logs_actor_user_id', table_name='file_access_logs')
    op.drop_index('ix_file_access_logs_file_id', table_name='file_access_logs')
    op.drop_table('file_access_logs')

    op.drop_index('ix_file_metadata_department_id', table_name='file_metadata')
    op.drop_index('ix_file_metadata_owner_user_id', table_name='file_metadata')
    op.drop_index('ix_file_metadata_file_id', table_name='file_metadata')
    op.drop_table('file_metadata')

    op.drop_table('user_roles')

    op.drop_index('ux_roles_name', table_name='roles')
    op.drop_table('roles')

    op.drop_index('ix_departments_name', table_name='departments')
    op.drop_table('departments')

    op.drop_index('ix_users_reset_token', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_index('ix_users_id', table_name='users')
    op.drop_table('users')
