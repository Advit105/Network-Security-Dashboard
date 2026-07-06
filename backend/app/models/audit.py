"""Audit log of security-relevant events.

Security decision: every authentication event (login success/failure, logout,
MFA enable/verify, lockout, password reset) is recorded with actor, IP, and user
agent. This is the backbone of monitoring and incident response — it lets you
spot repeated failures, logins from new locations, and reconstruct a timeline.
We deliberately never store passwords, tokens, or MFA codes here.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AuditEvent(str, enum.Enum):
    register = "register"
    login_success = "login_success"
    login_failure = "login_failure"
    login_locked = "login_locked"
    mfa_challenge = "mfa_challenge"
    mfa_enabled = "mfa_enabled"
    mfa_disabled = "mfa_disabled"
    mfa_failure = "mfa_failure"
    session_revoked = "session_revoked"
    logout = "logout"
    token_refresh = "token_refresh"
    token_reuse_detected = "token_reuse_detected"
    password_reset_requested = "password_reset_requested"
    password_reset_completed = "password_reset_completed"
    access_denied = "access_denied"
    role_changed = "role_changed"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable: some events (failed login for unknown email) have no user.
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True, nullable=True)
    event: Mapped[AuditEvent] = mapped_column(Enum(AuditEvent, name="audit_event"), index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    suspicious: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True, nullable=False)
