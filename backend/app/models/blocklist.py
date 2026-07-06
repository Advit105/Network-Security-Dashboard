"""Per-user blocklist entries.

Security decisions
------------------
* Every row is owned by a user_id (FK, cascade on user delete). All queries in the
  service filter by the authenticated user's id, so one user can never read or
  mutate another's entries (IDOR-safe by construction).
* (user_id, ip) is unique so the same IP can't be double-added for one user, but
  different users may independently block the same IP.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Severity(str, enum.Enum):
    danger = "danger"
    warn = "warn"
    info = "info"


class BlocklistEntry(Base):
    __tablename__ = "blocklist_entries"
    __table_args__ = (UniqueConstraint("user_id", "ip", name="uq_blocklist_user_ip"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False)  # fits IPv6
    reason: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="blocklist_severity"), default=Severity.danger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
