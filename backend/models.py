from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.dialects.sqlite import DATETIME as SQLITE_DT  # compatibility placeholder
from sqlalchemy.sql import func
from db import Base
import uuid
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)

class FileMetadata(Base):
    __tablename__ = 'file_metadata'
    file_id = Column(String, primary_key=True, index=True)
    orig_name = Column(String, nullable=False)
    size = Column(Integer, nullable=False)
    content_type = Column(String, nullable=True)
    secret_hash = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    # Use Python-side default to ensure value is provided even if DB has no server default
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    deleted = Column(Boolean, default=False, nullable=False)
    secret_attempts = Column(Integer, default=0, nullable=False)
    comments = Column(String, nullable=True)
    # Scan status (Phase 5)
    scan_status = Column(String(16), nullable=True)  # CLEAN, INFECTED, SKIPPED
    scan_details = Column(String, nullable=True)
    scanned_at = Column(DateTime(timezone=True), nullable=True)
    # Org mode additions (may be null for legacy rows)
    owner_user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    department_id = Column(Integer, ForeignKey('departments.id'), nullable=True, index=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    email = Column(String, nullable=True, unique=True)
    employee_id = Column(String, nullable=True, unique=True, index=True)
    # Use Python-side default to ensure value is provided even if DB has no server default
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    reset_token = Column(String, nullable=True, index=True)
    reset_expires_at = Column(DateTime(timezone=True), nullable=True)
    # Org mode
    department_id = Column(Integer, ForeignKey('departments.id'), nullable=True, index=True)
    status = Column(String, default='active', nullable=False)
    # MFA (Phase 2)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_temp_code = Column(String, nullable=True)
    mfa_temp_expires_at = Column(DateTime(timezone=True), nullable=True)
    # Security (Phase 5)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime(timezone=True), nullable=True)


class Department(Base):
    __tablename__ = 'departments'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    pin_hash = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(32), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class UserRole(Base):
    __tablename__ = 'user_roles'
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class FileAccessLog(Base):
    __tablename__ = 'file_access_logs'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String, ForeignKey('file_metadata.file_id', ondelete='CASCADE'), index=True, nullable=False)
    actor_user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    action = Column(String(32), nullable=False)  # upload, download, denied, request, approve, reject, revoke
    ip = Column(String(64), nullable=True)
    ts = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    meta = Column(JSON, nullable=True)


class TransferRequest(Base):
    __tablename__ = 'transfer_requests'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String, ForeignKey('file_metadata.file_id', ondelete='CASCADE'), nullable=False, index=True)
    from_department_id = Column(Integer, ForeignKey('departments.id'), nullable=True, index=True)
    to_department_id = Column(Integer, ForeignKey('departments.id'), nullable=True, index=True)
    requester_user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    status = Column(String(16), default='PENDING', nullable=False)  # PENDING, APPROVED, REJECTED
    decided_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    reason = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class FileRecipient(Base):
    __tablename__ = 'file_recipients'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String, ForeignKey('file_metadata.file_id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    notified_sent = Column(Boolean, default=False, nullable=False)


class SecuritySettings(Base):
    __tablename__ = 'security_settings'
    id = Column(Integer, primary_key=True, autoincrement=True)
    enforce_mfa_admin = Column(Boolean, default=False, nullable=False)
    enforce_mfa_all = Column(Boolean, default=False, nullable=False)
    min_password_length = Column(Integer, default=8, nullable=False)
    password_regex = Column(String, nullable=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
