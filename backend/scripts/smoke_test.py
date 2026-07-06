"""Import + wiring smoke test — no database required.

Validates that every module imports, the security primitives round-trip, and the
FastAPI app assembles all routes/schemas/dependencies (OpenAPI builds).
"""
import os

# Provide throwaway secrets so config loads without a real .env.
os.environ.setdefault("JWT_SECRET", "x" * 64)
# Point at a port that refuses instantly — DB-touching endpoints fail fast (500)
# so the rate-limit check below doesn't hang waiting on a real connection.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:1/db")
from cryptography.fernet import Fernet  # noqa: E402
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())

from app.core.security import (  # noqa: E402
    hash_password, verify_password, hash_token, constant_time_equals, generate_opaque_token,
)
from app.core.tokens import (  # noqa: E402
    create_access_token, decode_access_token, create_mfa_challenge_token, decode_mfa_challenge_token, TokenError,
)
from app.core import totp, crypto  # noqa: E402
from app.main import app  # noqa: E402

failures = []

def check(name, cond, extra=""):
    print(("  ok  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        failures.append(name)

# ── Password hashing ──
h = hash_password("Str0ng#Password!!")
check("argon2 hash verifies", verify_password("Str0ng#Password!!", h))
check("argon2 rejects wrong pw", not verify_password("nope", h))
check("unknown-user verify returns False (no crash)", not verify_password("x", None))

# ── Tokens ──
at = create_access_token(user_id="abc", role="admin")
payload = decode_access_token(at)
check("access token round-trips", payload["sub"] == "abc" and payload["role"] == "admin")
try:
    decode_access_token(at + "tamper"); check("tampered token rejected", False)
except TokenError:
    check("tampered token rejected", True)
mt = create_mfa_challenge_token(user_id="abc")
check("mfa token has type mfa", decode_mfa_challenge_token(mt)["type"] == "mfa")
try:
    decode_access_token(mt); check("mfa token rejected as access", False)
except TokenError:
    check("mfa token rejected as access", True)

# ── TOTP + Fernet at rest ──
secret = totp.generate_secret()
import pyotp
code = pyotp.TOTP(secret).now()
check("valid TOTP accepted", totp.verify_code(secret, code))
check("bad TOTP rejected", not totp.verify_code(secret, "000000"))
enc = crypto.encrypt(secret)
check("fernet round-trips secret", crypto.decrypt(enc) == secret and enc != secret)

# ── Opaque token / constant-time ──
tok = generate_opaque_token()
check("token hash is deterministic", hash_token(tok) == hash_token(tok))
check("constant_time_equals works", constant_time_equals("a", "a") and not constant_time_equals("a", "b"))

# ── App wiring / OpenAPI ──
schema = app.openapi()
paths = set(schema["paths"].keys())
expected = {
    "/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/mfa/verify",
    "/api/v1/auth/refresh", "/api/v1/auth/logout", "/api/v1/auth/mfa/enroll",
    "/api/v1/auth/mfa/enable", "/api/v1/auth/password-reset/request",
    "/api/v1/auth/password-reset/confirm", "/api/v1/users/me", "/api/v1/users/{user_id}",
    "/api/v1/users", "/api/v1/users/{user_id}/role", "/health",
}
missing = expected - paths
check(f"all {len(expected)} routes registered", not missing)
if missing:
    print("    missing:", missing)

# ── Security headers present on a real response ──
from starlette.testclient import TestClient  # noqa: E402
# raise_server_exceptions=False so the global 500 handler's response is returned
# (mirrors production) instead of the exception propagating into the test.
client = TestClient(app, raise_server_exceptions=False)
r = client.get("/health")
hdrs = r.headers
check("health 200", r.status_code == 200)
check("CSP header set", "content-security-policy" in hdrs)
check("X-Frame-Options DENY", hdrs.get("x-frame-options") == "DENY")
check("nosniff set", hdrs.get("x-content-type-options") == "nosniff")

# ── CSRF + auth guards actually block ──
r2 = client.post("/api/v1/auth/logout")  # no cookie, no CSRF
check("logout without CSRF blocked (403)", r2.status_code == 403)
r3 = client.get("/api/v1/users/me")  # no auth
check("users/me without auth blocked (401)", r3.status_code == 401)
# register rejects extra fields (mass-assignment safe) and weak input server-side
r4 = client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "Str0ng#Password!!", "role": "admin"})
check("register rejects extra 'role' field (422)", r4.status_code == 422)
r5 = client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "weak"})
check("register rejects weak password (422)", r5.status_code == 422)

# Rate limiter fires (login is limited to 10/min). Override the DB dependency with
# a fast stub so the pre-limit calls fail instantly (no network) and the limiter's
# 429 is exercised deterministically.
from app.db import get_db  # noqa: E402

async def _stub_db():
    class _S:
        async def execute(self, *a, **k):
            raise RuntimeError("stubbed db")
        async def commit(self): ...
        async def flush(self): ...
        async def refresh(self, *a, **k): ...
        def add(self, *a, **k): ...
    yield _S()

app.dependency_overrides[get_db] = _stub_db
statuses = [
    client.post("/api/v1/auth/login", json={"email": "z@z.com", "password": "whatever12A!"}).status_code
    for _ in range(14)
]
app.dependency_overrides.clear()
check("rate limiter returns 429 when exceeded", 429 in statuses, str(statuses))

print()
if failures:
    print(f"SMOKE TEST FAILED: {len(failures)} check(s) failed -> {failures}")
    raise SystemExit(1)
print("SMOKE TEST PASSED — all checks green")
