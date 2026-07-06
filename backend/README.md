# SentinelX Auth API

A standalone, production-oriented authentication & authorization service built
with **FastAPI + PostgreSQL**. Security-first: every decision is documented inline
in the code and summarized below.

> Status: **Authentication system (phase 1)** — register, login, MFA/TOTP, session
> management with refresh rotation, account lockout, password reset, RBAC, and an
> IDOR-safe user API. Payments and external OAuth are intentionally out of scope
> for this phase.

---

## Quick start (development)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Generate real secrets and paste them into .env:
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(64))"
python -c "from cryptography.fernet import Fernet; print('FERNET_KEY=' + Fernet.generate_key().decode())"

# Start Postgres (example with Docker):
docker run -d --name sentinel-pg -e POSTGRES_USER=sentinel \
  -e POSTGRES_PASSWORD=sentinel -e POSTGRES_DB=sentinel_auth -p 5432:5432 postgres:16

python -m scripts.init_db                     # create tables (dev; use Alembic in prod)
ADMIN_PASSWORD='ChangeMe!Str0ng#Pass' python -m scripts.create_admin admin@example.com

# --no-server-header strips uvicorn's Server header (it's added after middleware).
uvicorn app.main:app --reload --no-server-header    # http://localhost:8000 (docs at /docs)
```

## Endpoints (v1, under `/api/v1`)

| Method | Path | Purpose | Guard |
|---|---|---|---|
| POST | `/auth/register` | Create account (always `viewer`) | rate-limited |
| POST | `/auth/login` | Password step → session **or** MFA challenge | rate-limited, lockout |
| POST | `/auth/mfa/verify` | Complete login with TOTP code | rate-limited |
| POST | `/auth/refresh` | Rotate tokens (reuse detection) | cookie + CSRF |
| POST | `/auth/logout` | Revoke current session | cookie + CSRF |
| POST | `/auth/mfa/enroll` | Begin TOTP enrollment (QR/secret) | auth + CSRF |
| POST | `/auth/mfa/enable` | Confirm + activate TOTP | auth + CSRF |
| POST | `/auth/password-reset/request` | Email a reset link (no enumeration) | rate-limited |
| POST | `/auth/password-reset/confirm` | Set new password, revoke sessions | single-use token |
| GET | `/users/me` | Current user | auth |
| GET | `/users/{id}` | One user (self or admin — IDOR-safe) | auth |
| GET | `/users` | List users | **admin** |
| PUT | `/users/{id}/role` | Change a role | **admin** + CSRF |

### Authenticated request contract (browser clients)
Tokens live in **HttpOnly + Secure + SameSite=Strict** cookies, so JS never touches
them. For any state-changing request (`POST/PUT/DELETE`), read the non-HttpOnly
`csrf_token` cookie and echo it in the `X-CSRF-Token` header (double-submit CSRF).
Non-browser clients may instead send `Authorization: Bearer <access_token>`.

---

## Security decisions (summary)

**Passwords** — Argon2id (memory-hard, OWASP default). Never stored in plaintext;
opportunistically re-hashed when parameters change. Unknown-user logins run a dummy
verify so response timing can't reveal whether an email exists.

**Sessions & tokens** — Short-lived **access JWT** (15 min, signature + expiry
validated on every request, algorithm pinned to defeat `alg` confusion) plus an
**opaque refresh token** stored only as a SHA-256 hash and revocable server-side.
Refresh uses **rotation with reuse detection**: replaying a rotated token revokes
the whole token family (theft response). Logout and password reset revoke sessions
immediately — something stateless JWTs can't do.

**MFA/2FA** — Standard TOTP (RFC 6238) compatible with any authenticator app. The
TOTP secret is **encrypted at rest** with Fernet (key in env), so a DB leak doesn't
defeat MFA. Verification tolerates ±1 time-step for clock skew and is rate-limited.

**Account lockout** — After N failed logins (default 5) the account locks for a
window (default 15 min), throttling brute force per-account on top of per-IP rate
limits. Repeated failures are flagged `suspicious` in the audit log.

**Authorization (RBAC)** — Roles `viewer < analyst < admin`, enforced **server-side
only** via `require_role`. The public register path can't assign a role, so there's
no privilege escalation over the network; the first admin is bootstrapped via CLI.

**IDOR** — Object access verifies ownership (or admin) before returning anything;
`/users/me` avoids an id in the path entirely.

**Input validation & injection** — All inputs pass strict Pydantic schemas
(`extra="forbid"` → mass-assignment safe). All DB access is parameterized via
SQLAlchemy — no string-built SQL, so SQL injection isn't reachable. JSON responses
+ strict CSP make stored-XSS payloads inert for API consumers.

**CSRF** — Cookie auth is paired with a double-submit CSRF token on every mutation,
plus SameSite=Strict cookies.

**Transport & headers** — HSTS (prod), CSP `default-src 'none'`, `X-Frame-Options:
DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and the
`Server` header stripped. Set `COOKIE_SECURE=true` behind HTTPS in production.

**Secrets** — Loaded from env via pydantic-settings; `.env` is git-ignored, only
`.env.example` is committed. No credentials in source.

**Rate limiting** — Every endpoint is limited (slowapi); tightest on auth routes.
Use a Redis `RATE_LIMIT_STORAGE_URI` in production so limits hold across workers.

**Error handling** — A global handler logs real errors server-side and returns a
neutral message; stack traces and internals are never exposed.

**Monitoring / incident response** — Every auth event is written to `audit_logs`
(actor, IP, user agent, `suspicious` flag) — see [SECURITY.md](SECURITY.md) for the
incident-response runbook and the flags to alert on.

---

## What needs your input before the next phase

These were deferred and need a decision (flagged per your brief):

1. **Email provider** — dev prints reset emails to the console. For production pick
   SMTP (set `EMAIL_TRANSPORT=smtp` + creds) or I can add Resend/SendGrid.
2. **Email verification on signup** — model supports `email_verified`; the enforced
   verify-before-login flow isn't wired yet. Want it required?
3. **OAuth / social login (PKCE)** — not built; say which providers if you want it.
4. **Deployment target** (Docker/Fly/Render/AWS) — determines the Alembic + CI +
   TLS/HSTS wiring I'd add next.

Next phases per your ordering: **APIs** (expand resource endpoints on this RBAC
base) → **integrations** (email provider, OAuth PKCE, webhook signature verify).

---

## Testing

Two scripts, verified this build:

```bash
# 1) Wiring + security-primitive smoke test (no DB). Rate limiter ON — asserts 429.
JWT_SECRET=$(python -c 'import secrets;print(secrets.token_urlsafe(64))') \
FERNET_KEY=$(python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())') \
python -m scripts.smoke_test          # 22 checks

# 2) End-to-end against a real Postgres. Rate limiter OFF so the flow's many
#    logins aren't throttled (per-account lockout is still asserted separately).
docker run -d --name pg -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel \
  -e POSTGRES_DB=sentinel_auth -p 55432:5432 postgres:16
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@localhost:55432/sentinel_auth \
JWT_SECRET=... FERNET_KEY=... RATE_LIMIT_ENABLED=false \
  python -m scripts.init_db && python -m scripts.e2e_test   # 32 checks
```

The e2e covers: registration (role forced to viewer), password login, MFA
enroll/enable + challenge/verify, refresh **rotation with reuse detection + family
revocation**, account lockout (429 after 5 failures), password reset (no
enumeration, single-use, session revocation), and RBAC + IDOR (viewer 403 vs admin
200, cross-user read blocked).
