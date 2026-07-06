"""Audit + suspicious-activity helpers.

Security decision: centralize audit writes so every auth path logs consistently.
`record` never persists secrets. `count_recent_failures` powers lockout and
suspicious-activity flagging (repeated failures from an IP/account).
"""
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent, AuditLog


async def record(
    db: AsyncSession,
    *,
    event: AuditEvent,
    user_id: uuid.UUID | None = None,
    email: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: str | None = None,
    suspicious: bool = False,
) -> None:
    db.add(
        AuditLog(
            event=event,
            user_id=user_id,
            email=email,
            ip_address=ip,
            user_agent=(user_agent or "")[:400] or None,
            detail=(detail or "")[:500] or None,
            suspicious=suspicious,
        )
    )
    await db.flush()


async def count_recent_failures(db: AsyncSession, *, email: str, within_seconds: int = 900) -> int:
    since = datetime.now(UTC) - timedelta(seconds=within_seconds)
    stmt = (
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.event == AuditEvent.login_failure,
            AuditLog.email == email,
            AuditLog.created_at >= since,
        )
    )
    return int((await db.execute(stmt)).scalar_one())
