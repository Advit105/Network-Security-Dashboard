"""Password hashing, opaque-token hashing, and constant-time comparison.

Security decisions
------------------
* Argon2id for passwords: memory-hard, the current OWASP-recommended default,
  far more resistant to GPU/ASIC cracking than bcrypt/PBKDF2.
* A dummy verification path defeats user-enumeration via timing: logging in with
  an unknown email costs roughly the same time as a known one.
* Opaque tokens (refresh / password-reset) are stored only as SHA-256 hashes, so
  a database leak does not hand an attacker usable tokens. They are compared in
  constant time to prevent timing attacks.
"""
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Tuned per OWASP Password Storage Cheat Sheet (adjust to your hardware).
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

# Precomputed hash of a random password, used to burn ~equal time when the user
# does not exist (anti-enumeration). Generated once at import.
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Constant-ish time verify. If stored_hash is None (unknown user), still
    perform a verification against a dummy hash so timing does not leak existence."""
    if stored_hash is None:
        try:
            _ph.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        return False
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if params changed since this hash was made — rehash on next login."""
    try:
        return _ph.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False


def generate_opaque_token(nbytes: int = 32) -> str:
    """Cryptographically-random URL-safe token (refresh / reset)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 of an opaque token for at-rest storage / lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
