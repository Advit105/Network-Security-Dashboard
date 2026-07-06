"""Refresh-token sessions.

Security decisions
------------------
* One row per issued refresh token. The token itself is stored only as a SHA-256
  hash (token_hash) — a DB leak yields no usable tokens.
* Refresh rotation with reuse detection: on refresh we mark the current row
  `rotated_at` and issue a new one linked by `family_id`. If a token that was
  already rotated is presented again, it's a replay (token theft) → we revoke the
  whole family. This is the OWASP-recommended refresh-token pattern.
* `revoked_at` lets logout and admin actions invalidate sessions immediately —
  something stateless JWT refresh tokens cannot do.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # All refresh tokens descended from one login share a family_id (reuse detection).
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
