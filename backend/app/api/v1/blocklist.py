"""Per-user blocklist resource API.

Every handler scopes queries to the authenticated user (`caller.id`), so a user
can only ever see or modify their own entries — IDOR is prevented by construction,
not by an after-the-fact ownership check. Mutations require CSRF; all endpoints
are rate-limited via the global limiter and require authentication.
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_csrf
from app.db import get_db
from app.models.blocklist import BlocklistEntry
from app.schemas.blocklist import BlocklistCreate, BlocklistOut

router = APIRouter(prefix="/blocklist", tags=["blocklist"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.get("", response_model=list[BlocklistOut])
async def list_blocklist(caller: CurrentUser, db: Db) -> list[BlocklistOut]:
    rows = (
        await db.execute(
            select(BlocklistEntry)
            .where(BlocklistEntry.user_id == caller.id)
            .order_by(BlocklistEntry.created_at.desc())
        )
    ).scalars().all()
    return [BlocklistOut.model_validate(r) for r in rows]


@router.post("", response_model=BlocklistOut, status_code=201, dependencies=[Depends(require_csrf)])
async def add_blocklist(body: BlocklistCreate, caller: CurrentUser, db: Db) -> BlocklistOut:
    entry = BlocklistEntry(user_id=caller.id, ip=body.ip, reason=body.reason, severity=body.severity)
    db.add(entry)
    try:
        await db.commit()
    except IntegrityError:
        # Unique (user_id, ip) violated — the caller already blocked this IP.
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="IP already in your blocklist")
    await db.refresh(entry)
    return BlocklistOut.model_validate(entry)


@router.delete("/{entry_id}", status_code=204, dependencies=[Depends(require_csrf)])
async def delete_blocklist(entry_id: uuid.UUID, caller: CurrentUser, db: Db) -> None:
    # Scoped to the caller: deleting another user's row matches nothing → 404.
    result = await db.execute(
        delete(BlocklistEntry).where(
            BlocklistEntry.id == entry_id, BlocklistEntry.user_id == caller.id
        )
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
