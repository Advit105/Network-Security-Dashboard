"""Request/response schemas for auth.

Security decisions
------------------
* Input schemas are strict allow-lists (`extra="forbid"`) — unknown fields are
  rejected, which structurally prevents mass-assignment (e.g. a client cannot
  sneak `role=admin` or `is_active=true` into registration).
* Password policy is validated server-side; never rely on the client.
* Output schemas expose only safe fields — never the hash, MFA secret, or lockout
  internals.
"""
import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.user import Role

_STRICT = ConfigDict(extra="forbid")

# OWASP-aligned minimum. Tune length/classes to your policy.
_PW_MIN = 12


def _validate_password_strength(v: str) -> str:
    if len(v) < _PW_MIN:
        raise ValueError(f"password must be at least {_PW_MIN} characters")
    if not re.search(r"[a-z]", v) or not re.search(r"[A-Z]", v):
        raise ValueError("password must include upper and lower case letters")
    if not re.search(r"\d", v):
        raise ValueError("password must include a digit")
    if not re.search(r"[^A-Za-z0-9]", v):
        raise ValueError("password must include a symbol")
    return v


class RegisterRequest(BaseModel):
    model_config = _STRICT
    email: EmailStr
    password: str = Field(min_length=_PW_MIN, max_length=200)

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        return _validate_password_strength(v)


class LoginRequest(BaseModel):
    model_config = _STRICT
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class MFAVerifyRequest(BaseModel):
    model_config = _STRICT
    # Short-lived challenge token issued after password step when MFA is required.
    mfa_token: str = Field(min_length=10, max_length=500)
    code: str = Field(min_length=6, max_length=6)


class MFAEnableConfirmRequest(BaseModel):
    model_config = _STRICT
    code: str = Field(min_length=6, max_length=6)


class PasswordResetRequest(BaseModel):
    model_config = _STRICT
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    model_config = _STRICT
    token: str = Field(min_length=10, max_length=500)
    new_password: str = Field(min_length=_PW_MIN, max_length=200)

    @field_validator("new_password")
    @classmethod
    def _pw(cls, v: str) -> str:
        return _validate_password_strength(v)


# ── Responses (safe projections only) ──
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    # Plain str on output: emails are validated as EmailStr on the way IN; the
    # response model must not RE-validate stored data (that would 500 the endpoint
    # on any legacy/edge row instead of just rendering what's persisted).
    email: str
    role: Role
    mfa_enabled: bool
    email_verified: bool
    created_at: datetime


class LoginResult(BaseModel):
    """Either a completed login (mfa_required=False) or an MFA challenge."""
    mfa_required: bool
    mfa_token: str | None = None
    user: UserOut | None = None
    # Returned so a cross-origin SPA can echo it in X-CSRF-Token (it cannot read
    # the cookie set on the API's origin). Present only on completed logins.
    csrf_token: str | None = None


class SessionInfo(BaseModel):
    """Page-load bootstrap: who am I + the CSRF token to use for mutations."""
    authenticated: bool
    user: UserOut | None = None
    csrf_token: str | None = None


class MFAEnrollStart(BaseModel):
    secret: str
    otpauth_uri: str


class MFADisableRequest(BaseModel):
    model_config = _STRICT
    # Disabling MFA is itself a sensitive action — require a current TOTP code
    # so a hijacked (but unlocked) session cannot silently weaken the account.
    code: str = Field(min_length=6, max_length=6)


class DeviceSession(BaseModel):
    """One signed-in device (a refresh-token family)."""
    family_id: uuid.UUID
    created_at: datetime      # when this device signed in
    last_active: datetime     # most recent token rotation
    ip_address: str | None
    user_agent: str | None
    current: bool             # is this the session making the request?


class DeviceSessionList(BaseModel):
    sessions: list[DeviceSession]


class MessageOut(BaseModel):
    detail: str
