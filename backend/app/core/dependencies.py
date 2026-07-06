"""Auth dependencies: current user, RBAC, and CSRF enforcement.

Security decisions
------------------
* get_current_user validates the access JWT (signature + expiry) on EVERY
  protected request and re-loads the user, so a disabled/deleted account loses
  access immediately rather than until token expiry.
* require_role enforces RBAC SERVER-SIDE only. The client's token carries a role
  claim for convenience, but authorization is decided here, never by the client.
* require_csrf implements double-submit: the csrf cookie must equal the
  X-CSRF-Token header (constant-time compare) on all state-changing requests.
"""
import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cookies import ACCESS_COOKIE, CSRF_COOKIE
from app.core.security import constant_time_equals
from app.core.tokens import TokenError, decode_access_token
from app.db import get_db
from app.models.user import Role, User

_UNAUTH = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def get_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        # Fall back to bearer for non-browser API clients.
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
    if not token:
        raise _UNAUTH

    try:
        payload = decode_access_token(token)
        user_id = uuid.UUID(payload["sub"])
    except (TokenError, ValueError, KeyError):
        raise _UNAUTH

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise _UNAUTH
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(*allowed: Role):
    """RBAC guard. Usage: Depends(require_role(Role.admin))."""
    async def _guard(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return _guard


async def require_csrf(
    request: Request,
    x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    if not cookie or not x_csrf_token or not constant_time_equals(cookie, x_csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed")
