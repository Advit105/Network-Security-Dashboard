"""Authentication endpoints.

Flow summary
------------
register → login (password) → [if MFA] mfa/verify → session cookies issued
refresh (rotates tokens) · logout (revokes) · mfa/enroll+enable · password reset.

Security decisions are annotated per-endpoint. Cross-cutting guarantees:
* All inputs are validated by strict Pydantic schemas (mass-assignment safe).
* All DB access is parameterized (no SQL injection).
* Errors are generic to the client; details go to the audit log / server logs.
* Tokens live in HttpOnly+Secure+SameSite=Strict cookies; mutations require CSRF.
"""
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.cookies import REFRESH_COOKIE, clear_auth_cookies, set_auth_cookies
from app.core.crypto import decrypt, encrypt
from app.core.dependencies import CurrentUser, require_csrf
from app.core.rate_limit import (
    LOGIN_LIMIT, MFA_VERIFY_LIMIT, REGISTER_LIMIT, RESET_REQUEST_LIMIT, limiter,
)
from app.core.security import (
    generate_opaque_token, hash_password, hash_token, needs_rehash, verify_password,
)
from app.core.tokens import (
    TokenError, create_access_token, create_mfa_challenge_token, decode_access_token,
    decode_mfa_challenge_token,
)
from app.core import totp
from app.core.rate_limit import client_ip
from app.db import get_db
from app.models.audit import AuditEvent
from app.models.password_reset import PasswordResetToken
from app.models.user import Role, User
from app.schemas.auth import (
    DeviceSession, DeviceSessionList, LoginRequest, LoginResult, MFADisableRequest,
    MFAEnableConfirmRequest, MFAEnrollStart, MFAVerifyRequest,
    MessageOut, PasswordResetConfirm, PasswordResetRequest, RegisterRequest, SessionInfo, UserOut,
)
from app.core.cookies import CSRF_COOKIE
from app.services import audit, sessions
from app.services.email import send_password_reset

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])

Db = Annotated[AsyncSession, Depends(get_db)]


def _ctx(request: Request) -> tuple[str, str | None]:
    return client_ip(request), request.headers.get("user-agent")


async def _issue_login(db: AsyncSession, resp: Response, user: User, request: Request) -> tuple[UserOut, str]:
    """Mint access JWT + rotating refresh session + CSRF, set cookies.
    Returns (user, csrf_token) so the SPA can capture the token from the body."""
    ip, ua = _ctx(request)
    access = create_access_token(user_id=str(user.id), role=user.role.value)
    refresh = await sessions.issue_session(db, user_id=user.id, ip=ip, user_agent=ua)
    csrf = generate_opaque_token(24)
    set_auth_cookies(resp, access_token=access, refresh_token=refresh, csrf_token=csrf)
    return UserOut.model_validate(user), csrf


# ── Register ─────────────────────────────────────────────────────────────────
@router.post("/register", response_model=UserOut, status_code=201)
@limiter.limit(REGISTER_LIMIT)
async def register(request: Request, body: RegisterRequest, db: Db) -> UserOut:
    # Security: new accounts always get the least-privileged role server-side.
    # The schema cannot carry a role, so a client cannot self-assign admin.
    email = body.email.lower()
    exists = (await db.execute(select(User.id).where(User.email == email))).first()
    if exists:
        # Do not reveal which emails are registered beyond the unavoidable minimum.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(email=email, password_hash=hash_password(body.password), role=Role.viewer)
    db.add(user)
    await db.flush()
    ip, ua = _ctx(request)
    await audit.record(db, event=AuditEvent.register, user_id=user.id, email=email, ip=ip, user_agent=ua)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


# ── Session bootstrap (page load) ────────────────────────────────────────────
@router.get("/session", response_model=SessionInfo)
async def session(request: Request, db: Db) -> SessionInfo:
    """Tells the SPA whether it's logged in and hands back the CSRF token to use.
    A cross-origin SPA can't read the API-origin CSRF cookie, so we echo it here.
    Unauthenticated callers just get authenticated=false (never an error)."""
    token = request.cookies.get("access_token")
    if not token:
        return SessionInfo(authenticated=False)
    try:
        payload = decode_access_token(token)
        user = (await db.execute(select(User).where(User.id == uuid.UUID(payload["sub"])))).scalar_one_or_none()
    except (TokenError, ValueError, KeyError):
        user = None
    if not user or not user.is_active:
        return SessionInfo(authenticated=False)
    return SessionInfo(
        authenticated=True,
        user=UserOut.model_validate(user),
        csrf_token=request.cookies.get(CSRF_COOKIE),
    )


# ── Login (password step) ────────────────────────────────────────────────────
@router.post("/login", response_model=LoginResult)
@limiter.limit(LOGIN_LIMIT)
async def login(request: Request, response: Response, body: LoginRequest, db: Db) -> LoginResult:
    email = body.email.lower()
    ip, ua = _ctx(request)
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()

    # Account lockout: block even correct passwords while locked.
    if user and user.locked_until and user.locked_until > datetime.now(UTC):
        await audit.record(db, event=AuditEvent.login_locked, user_id=user.id, email=email, ip=ip,
                           user_agent=ua, suspicious=True)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Account temporarily locked. Try again later.")

    # Constant-time-ish verify; verify_password handles the unknown-user case so
    # timing does not reveal whether the email exists.
    ok = verify_password(body.password, user.password_hash if user else None)

    if not user or not ok:
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = datetime.now(UTC) + timedelta(seconds=settings.lockout_seconds)
                user.failed_login_count = 0
        recent = await audit.count_recent_failures(db, email=email)
        await audit.record(db, event=AuditEvent.login_failure, user_id=user.id if user else None,
                           email=email, ip=ip, user_agent=ua, suspicious=recent >= 3)
        await db.commit()
        # Identical generic error whether user missing or password wrong.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    # Success: reset lockout counters; opportunistically upgrade the hash.
    user.failed_login_count = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    # If MFA is enabled, do NOT log in yet — issue a short-lived challenge token.
    if user.mfa_enabled:
        await audit.record(db, event=AuditEvent.mfa_challenge, user_id=user.id, email=email, ip=ip, user_agent=ua)
        await db.commit()
        return LoginResult(mfa_required=True, mfa_token=create_mfa_challenge_token(user_id=str(user.id)))

    out, csrf = await _issue_login(db, response, user, request)
    await audit.record(db, event=AuditEvent.login_success, user_id=user.id, email=email, ip=ip, user_agent=ua)
    await db.commit()
    return LoginResult(mfa_required=False, user=out, csrf_token=csrf)


# ── MFA verify (second step) ─────────────────────────────────────────────────
@router.post("/mfa/verify", response_model=LoginResult)
@limiter.limit(MFA_VERIFY_LIMIT)
async def mfa_verify(request: Request, response: Response, body: MFAVerifyRequest, db: Db) -> LoginResult:
    try:
        payload = decode_mfa_challenge_token(body.mfa_token)
        user_id = uuid.UUID(payload["sub"])
    except (TokenError, ValueError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    ip, ua = _ctx(request)
    if not user or not user.mfa_enabled or not user.mfa_secret_enc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA session")

    if not totp.verify_code(decrypt(user.mfa_secret_enc), body.code):
        await audit.record(db, event=AuditEvent.mfa_failure, user_id=user.id, email=user.email, ip=ip,
                           user_agent=ua, suspicious=True)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")

    out, csrf = await _issue_login(db, response, user, request)
    await audit.record(db, event=AuditEvent.login_success, user_id=user.id, email=user.email, ip=ip,
                       user_agent=ua, detail="mfa")
    await db.commit()
    return LoginResult(mfa_required=False, user=out, csrf_token=csrf)


# ── Refresh (rotation + reuse detection) ─────────────────────────────────────
@router.post("/refresh", response_model=MessageOut, dependencies=[Depends(require_csrf)])
async def refresh(request: Request, response: Response, db: Db) -> MessageOut:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No session")
    ip, ua = _ctx(request)

    outcome = await sessions.rotate_session(db, raw_refresh=raw, ip=ip, user_agent=ua)
    if outcome.reuse_detected:
        await audit.record(db, event=AuditEvent.token_reuse_detected, user_id=outcome.user_id, ip=ip,
                           user_agent=ua, suspicious=True, detail="refresh token replay; family revoked")
        await db.commit()
        clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalidated")
    if not outcome.raw_token or not outcome.user_id:
        clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    user = (await db.execute(select(User).where(User.id == outcome.user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    access = create_access_token(user_id=str(user.id), role=user.role.value)
    csrf = generate_opaque_token(24)
    set_auth_cookies(response, access_token=access, refresh_token=outcome.raw_token, csrf_token=csrf)
    await audit.record(db, event=AuditEvent.token_refresh, user_id=user.id, email=user.email, ip=ip, user_agent=ua)
    await db.commit()
    return MessageOut(detail="refreshed")


# ── Logout ───────────────────────────────────────────────────────────────────
@router.post("/logout", response_model=MessageOut, dependencies=[Depends(require_csrf)])
async def logout(request: Request, response: Response, db: Db) -> MessageOut:
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        await sessions.revoke_by_raw(db, raw)  # server-side invalidation
    ip, ua = _ctx(request)
    await audit.record(db, event=AuditEvent.logout, ip=ip, user_agent=ua)
    await db.commit()
    clear_auth_cookies(response)
    return MessageOut(detail="logged out")


# ── MFA enrollment (requires an authenticated session + CSRF) ────────────────
@router.post("/mfa/enroll", response_model=MFAEnrollStart, dependencies=[Depends(require_csrf)])
async def mfa_enroll(user: CurrentUser, db: Db) -> MFAEnrollStart:
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA already enabled")
    secret = totp.generate_secret()
    # Store encrypted immediately; it becomes active only after confirm.
    user.mfa_secret_enc = encrypt(secret)
    await db.commit()
    return MFAEnrollStart(secret=secret, otpauth_uri=totp.provisioning_uri(secret, user.email))


@router.post("/mfa/enable", response_model=MessageOut, dependencies=[Depends(require_csrf)])
async def mfa_enable(request: Request, body: MFAEnableConfirmRequest, user: CurrentUser, db: Db) -> MessageOut:
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA already enabled")
    if not user.mfa_secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Start enrollment first")
    if not totp.verify_code(decrypt(user.mfa_secret_enc), body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    user.mfa_enabled = True
    ip, ua = _ctx(request)
    await audit.record(db, event=AuditEvent.mfa_enabled, user_id=user.id, email=user.email, ip=ip, user_agent=ua)
    await db.commit()
    return MessageOut(detail="MFA enabled")


@router.post("/mfa/disable", response_model=MessageOut, dependencies=[Depends(require_csrf)])
async def mfa_disable(request: Request, body: MFADisableRequest, user: CurrentUser, db: Db) -> MessageOut:
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    if not user.mfa_secret_enc or not totp.verify_code(decrypt(user.mfa_secret_enc), body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    ip, ua = _ctx(request)
    await audit.record(db, event=AuditEvent.mfa_disabled, user_id=user.id, email=user.email, ip=ip, user_agent=ua)
    await db.commit()
    return MessageOut(detail="MFA disabled")


# ── Device sessions (list / revoke) ──────────────────────────────────────────
@router.get("/sessions", response_model=DeviceSessionList)
async def list_sessions(request: Request, user: CurrentUser, db: Db) -> DeviceSessionList:
    """The caller's signed-in devices. Rows are grouped by refresh-token family:
    one family per login, one extra row per rotation — so first row = sign-in
    time and the newest row = last activity."""
    rows = await sessions.list_active_for_user(db, user.id)
    raw = request.cookies.get(REFRESH_COOKIE)
    current_family = await sessions.family_of_raw(db, raw) if raw else None

    families: dict = {}
    for r in rows:
        f = families.get(r.family_id)
        if f is None:
            families[r.family_id] = {
                "family_id": r.family_id,
                "created_at": r.created_at,
                "last_active": r.created_at,
                "ip_address": r.ip_address,
                "user_agent": r.user_agent,
            }
        else:
            f["last_active"] = r.created_at
            f["ip_address"] = r.ip_address or f["ip_address"]
            f["user_agent"] = r.user_agent or f["user_agent"]

    out = [
        DeviceSession(**f, current=(f["family_id"] == current_family))
        for f in families.values()
    ]
    # Current device first, then most recently active.
    out.sort(key=lambda s: s.last_active, reverse=True)
    out.sort(key=lambda s: not s.current)
    return DeviceSessionList(sessions=out)


@router.delete("/sessions/{family_id}", response_model=MessageOut, dependencies=[Depends(require_csrf)])
async def revoke_session(family_id: uuid.UUID, request: Request, user: CurrentUser, db: Db) -> MessageOut:
    # Ownership is enforced in the query itself (user_id + family_id) — a valid
    # UUID belonging to someone else 404s identically to a nonexistent one.
    ok = await sessions.revoke_family_for_user(db, user.id, family_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    ip, ua = _ctx(request)
    await audit.record(db, event=AuditEvent.session_revoked, user_id=user.id, email=user.email, ip=ip, user_agent=ua)
    await db.commit()
    return MessageOut(detail="Session revoked")


# ── Password reset ───────────────────────────────────────────────────────────
@router.post("/password-reset/request", response_model=MessageOut)
@limiter.limit(RESET_REQUEST_LIMIT)
async def password_reset_request(request: Request, body: PasswordResetRequest, db: Db) -> MessageOut:
    email = body.email.lower()
    ip, ua = _ctx(request)
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user:
        # Invalidate any prior unused tokens, then issue a fresh single-use one.
        prior = (await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)
            )
        )).scalars().all()
        for p in prior:
            p.used_at = datetime.now(UTC)
        raw = generate_opaque_token(32)
        db.add(PasswordResetToken(
            user_id=user.id, token_hash=hash_token(raw),
            expires_at=datetime.now(UTC) + timedelta(seconds=settings.password_reset_ttl_seconds),
        ))
        await audit.record(db, event=AuditEvent.password_reset_requested, user_id=user.id, email=email,
                           ip=ip, user_agent=ua)
        await db.commit()
        try:
            send_password_reset(email, raw)
        except Exception:  # never leak mail-server errors to the client
            pass
    # Always the same response → no account enumeration.
    return MessageOut(detail="If that email exists, a reset link has been sent.")


@router.post("/password-reset/confirm", response_model=MessageOut)
async def password_reset_confirm(request: Request, body: PasswordResetConfirm, db: Db) -> MessageOut:
    row = (await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(body.token))
    )).scalar_one_or_none()
    if not row or row.used_at is not None or row.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    user = (await db.execute(select(User).where(User.id == row.user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    user.password_hash = hash_password(body.new_password)
    row.used_at = datetime.now(UTC)
    # Security: reset invalidates all existing sessions (in case of prior compromise).
    await sessions.revoke_all_for_user(db, user.id)
    ip, ua = _ctx(request)
    await audit.record(db, event=AuditEvent.password_reset_completed, user_id=user.id, email=user.email,
                       ip=ip, user_agent=ua)
    await db.commit()
    return MessageOut(detail="Password updated. Please log in.")
