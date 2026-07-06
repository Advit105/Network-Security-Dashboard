"""JWT access tokens.

Security decisions
------------------
* Access tokens are short-lived (default 15 min) JWTs signed with HS256 using a
  server-only secret. Every protected request re-validates the signature AND the
  expiry server-side — we never trust claims without verification.
* We pin the accepted algorithm on decode to defeat the classic "alg: none" and
  algorithm-confusion attacks (a token claiming a different alg is rejected).
* `iat`/`exp`/`jti` are always set. `jti` lets us correlate/revoke if needed.
* Refresh tokens are deliberately NOT JWTs — they are opaque, hashed at rest, and
  revocable in the DB (see models/session.py), because stateless refresh tokens
  cannot be invalidated on logout.
"""
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from app.config import get_settings
from app.core.security import generate_opaque_token

settings = get_settings()


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired, or has a bad signature."""


def create_access_token(*, user_id: str, role: str, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
        "jti": generate_opaque_token(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_mfa_challenge_token(*, user_id: str) -> str:
    """Very short-lived token proving the password step passed, pending TOTP.
    Deliberately separate 'type' so it cannot be used as an access token."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "type": "mfa",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": generate_opaque_token(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_mfa_challenge_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid mfa token") from exc
    if payload.get("type") != "mfa":
        raise TokenError("wrong token type")
    return payload


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],  # pin algorithm — no alg confusion
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid token") from exc

    if payload.get("type") != "access":
        raise TokenError("wrong token type")
    return payload
