"""Refresh-token session service: issue, rotate (with reuse detection), revoke.

Security decision: this implements the OWASP refresh-token rotation pattern.
Each refresh mints a new token and invalidates the old one. Presenting an
already-rotated token means it was stolen and replayed → we revoke the entire
token family, forcing re-authentication everywhere.
"""
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.security import generate_opaque_token, hash_token
from app.models.session import Session

settings = get_settings()


def _now() -> datetime:
    return datetime.now(UTC)


async def issue_session(
    db: AsyncSession, *, user_id: uuid.UUID, ip: str | None, user_agent: str | None,
    family_id: uuid.UUID | None = None,
) -> str:
    """Create a session row, return the RAW refresh token (only stored hashed)."""
    raw = generate_opaque_token(32)
    db.add(
        Session(
            user_id=user_id,
            family_id=family_id or uuid.uuid4(),
            token_hash=hash_token(raw),
            ip_address=ip,
            user_agent=(user_agent or "")[:400] or None,
            expires_at=_now() + timedelta(seconds=settings.refresh_token_ttl_seconds),
        )
    )
    await db.flush()
    return raw


async def _revoke_family(db: AsyncSession, family_id: uuid.UUID) -> None:
    await db.execute(
        update(Session)
        .where(Session.family_id == family_id, Session.revoked_at.is_(None))
        .values(revoked_at=_now())
    )


@dataclass(frozen=True)
class RefreshOutcome:
    raw_token: str | None
    user_id: uuid.UUID | None
    reuse_detected: bool


async def rotate_session(
    db: AsyncSession, *, raw_refresh: str, ip: str | None, user_agent: str | None
) -> RefreshOutcome:
    row = (
        await db.execute(select(Session).where(Session.token_hash == hash_token(raw_refresh)))
    ).scalar_one_or_none()

    if row is None:
        return RefreshOutcome(None, None, reuse_detected=False)

    # Reuse detection: token already rotated or revoked → theft. Kill the family.
    if row.rotated_at is not None or row.revoked_at is not None:
        await _revoke_family(db, row.family_id)
        return RefreshOutcome(None, row.user_id, reuse_detected=True)

    if row.expires_at <= _now():
        return RefreshOutcome(None, row.user_id, reuse_detected=False)

    # Rotate: mark current used, issue a new token in the same family.
    row.rotated_at = _now()
    new_raw = await issue_session(
        db, user_id=row.user_id, ip=ip, user_agent=user_agent, family_id=row.family_id
    )
    return RefreshOutcome(new_raw, row.user_id, reuse_detected=False)


async def revoke_by_raw(db: AsyncSession, raw_refresh: str) -> None:
    row = (
        await db.execute(select(Session).where(Session.token_hash == hash_token(raw_refresh)))
    ).scalar_one_or_none()
    if row and row.revoked_at is None:
        row.revoked_at = _now()


async def revoke_all_for_user(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(
        update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None)).values(revoked_at=_now())
    )


async def list_active_for_user(db: AsyncSession, user_id: uuid.UUID) -> list[Session]:
    """All live rows for the user; the API layer groups them into device
    families (each login = one family; each rotation adds a row to it)."""
    return list(
        (
            await db.execute(
                select(Session)
                .where(
                    Session.user_id == user_id,
                    Session.revoked_at.is_(None),
                    Session.expires_at > _now(),
                )
                .order_by(Session.created_at)
            )
        )
        .scalars()
        .all()
    )


async def family_of_raw(db: AsyncSession, raw_refresh: str) -> uuid.UUID | None:
    row = (
        await db.execute(select(Session).where(Session.token_hash == hash_token(raw_refresh)))
    ).scalar_one_or_none()
    return row.family_id if row else None


async def revoke_family_for_user(db: AsyncSession, user_id: uuid.UUID, family_id: uuid.UUID) -> bool:
    """Revoke one device family — scoped to the owner so a user can never
    revoke another user's session (IDOR-safe). Returns False if nothing matched."""
    result = await db.execute(
        update(Session)
        .where(
            Session.user_id == user_id,
            Session.family_id == family_id,
            Session.revoked_at.is_(None),
        )
        .values(revoked_at=_now())
    )
    return result.rowcount > 0
