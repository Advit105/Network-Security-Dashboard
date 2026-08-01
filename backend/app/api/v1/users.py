"""User endpoints demonstrating RBAC and IDOR-safe access control.

Security decisions
------------------
* GET /users/me returns only the caller's own record (no id in the path → no
  IDOR surface).
* GET /users/{id} enforces ownership OR admin: a user may only read their own
  record unless they are an admin. This is the canonical IDOR defence — verify
  ownership server-side before returning any object, never trust the id alone.
* Admin-only routes are gated by require_role(Role.admin), enforced server-side.
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_csrf, require_role
from app.db import get_db
from app.models.audit import AuditEvent
from app.models.user import Role, User
from app.schemas.auth import UserOut
from app.schemas.user import RoleUpdateRequest
from app.services import audit
from app.services.sessions import revoke_all_for_user

router = APIRouter(prefix="/users", tags=["users"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: uuid.UUID, caller: CurrentUser, db: Db) -> UserOut:
    # IDOR guard: only self or admin.
    if caller.role != Role.admin and caller.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return UserOut.model_validate(target)


@router.get("", response_model=list[UserOut], dependencies=[Depends(require_role(Role.admin))])
async def list_users(db: Db, limit: int = 50, offset: int = 0) -> list[UserOut]:
    limit = max(1, min(limit, 200))  # bound page size
    offset = max(0, offset)          # negative OFFSET is a DB error → would 500
    rows = (await db.execute(select(User).order_by(User.created_at.desc()).limit(limit).offset(offset))).scalars().all()
    return [UserOut.model_validate(u) for u in rows]


@router.put(
    "/{user_id}/role",
    response_model=UserOut,
    dependencies=[Depends(require_role(Role.admin)), Depends(require_csrf)],
)
async def set_role(user_id: uuid.UUID, body: RoleUpdateRequest, admin: CurrentUser, db: Db) -> UserOut:
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    target.role = body.role
    # Force re-auth so the new role is reflected in freshly-minted access tokens.
    await revoke_all_for_user(db, target.id)
    await audit.record(db, event=AuditEvent.role_changed, user_id=admin.id, email=admin.email,
                       detail=f"role of {target.id} set to {body.role.value}")
    await db.commit()
    await db.refresh(target)
    return UserOut.model_validate(target)
