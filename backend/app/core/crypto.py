"""Symmetric encryption for sensitive fields at rest.

Security decision: TOTP secrets are the shared key that generates a user's 2FA
codes. Storing them in plaintext means a DB leak defeats MFA for every user. We
encrypt them with Fernet (AES-128-CBC + HMAC authentication) using a key held
only in the environment, so leaked ciphertext is useless without FERNET_KEY.
"""
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

settings = get_settings()
_fernet = Fernet(settings.fernet_key.encode("utf-8"))


def encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    try:
        return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:  # tampered or wrong key
        raise ValueError("could not decrypt value") from exc
