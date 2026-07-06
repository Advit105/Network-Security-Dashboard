"""TOTP-based MFA (RFC 6238).

Security decisions
------------------
* Standard 30-second TOTP so any authenticator app (Google Authenticator, Authy,
  1Password) works — no proprietary lock-in.
* `valid_window=1` accepts the adjacent 30s step to tolerate clock skew, but no
  wider, to keep the brute-force space small.
* Verification is rate-limited and audit-logged at the API layer; a 6-digit code
  with lockout is not feasibly guessable.
"""
import pyotp

from app.config import get_settings

settings = get_settings()


def generate_secret() -> str:
    """Base32 secret to be encrypted before storage (see core/crypto.py)."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_email: str) -> str:
    """otpauth:// URI the client renders as a QR code for enrollment."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_email, issuer_name=settings.app_name
    )


def verify_code(secret: str, code: str) -> bool:
    if not code or not code.strip().isdigit():
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
