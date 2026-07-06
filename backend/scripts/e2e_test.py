"""Database-backed end-to-end test of the real auth flows.

Runs the ASGI app in-process (httpx ASGITransport) against a live Postgres.
Requires DATABASE_URL to point at a reachable DB with tables created
(scripts.init_db). Prints a pass/fail line per assertion.

Usage:
    DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@localhost:55432/sentinel_auth \
    JWT_SECRET=... FERNET_KEY=... .venv/bin/python -m scripts.e2e_test
"""
import asyncio
import os
import uuid

import httpx
import pyotp
from sqlalchemy import select

failures: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    print(("  ok  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        failures.append(name)


def csrf_headers(client: httpx.AsyncClient) -> dict:
    tok = client.cookies.get("csrf_token")
    return {"X-CSRF-Token": tok} if tok else {}


async def main() -> None:
    # Import after env is set by the caller.
    from app.main import app
    from app.db import SessionLocal
    from app.models.user import User

    base = "http://testserver/api/v1"
    transport = httpx.ASGITransport(app=app)

    uniq = uuid.uuid4().hex[:8]
    email = f"alice-{uniq}@example.com"
    password = "Str0ng#Password!42"

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        # ── Register (role forced to viewer) ──
        r = await c.post(f"{base}/auth/register", json={"email": email, "password": password})
        check("register 201", r.status_code == 201, r.text)
        check("registered role is viewer", r.json().get("role") == "viewer")

        # ── Login (no MFA yet) → cookies + CSRF set ──
        r = await c.post(f"{base}/auth/login", json={"email": email, "password": password})
        check("login 200", r.status_code == 200, r.text)
        check("login not mfa_required", r.json().get("mfa_required") is False)
        check("access_token cookie set", "access_token" in c.cookies)
        check("csrf_token cookie set", "csrf_token" in c.cookies)

        # ── /users/me works with cookie ──
        r = await c.get(f"{base}/users/me")
        check("users/me 200 with cookie", r.status_code == 200, r.text)
        my_id = r.json()["id"]

        # ── MFA enroll + enable ──
        r = await c.post(f"{base}/auth/mfa/enroll", headers=csrf_headers(c))
        check("mfa enroll 200", r.status_code == 200, r.text)
        secret = r.json()["secret"]
        code = pyotp.TOTP(secret).now()
        r = await c.post(f"{base}/auth/mfa/enable", json={"code": code}, headers=csrf_headers(c))
        check("mfa enable 200", r.status_code == 200, r.text)

        # ── Logout, then login requires MFA ──
        r = await c.post(f"{base}/auth/logout", headers=csrf_headers(c))
        check("logout 200", r.status_code == 200, r.text)
        c.cookies.clear()

        r = await c.post(f"{base}/auth/login", json={"email": email, "password": password})
        check("login now mfa_required", r.status_code == 200 and r.json().get("mfa_required") is True, r.text)
        mfa_token = r.json()["mfa_token"]
        check("no session before MFA verify", "access_token" not in c.cookies)

        # Wrong code rejected
        r = await c.post(f"{base}/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"})
        check("mfa verify wrong code 401", r.status_code == 401)

        # Correct code completes login
        code = pyotp.TOTP(secret).now()
        r = await c.post(f"{base}/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code})
        check("mfa verify 200", r.status_code == 200, r.text)
        check("session issued after MFA", "access_token" in c.cookies)

        # ── Refresh rotates the cookie over HTTP ──
        old_refresh = c.cookies.get("refresh_token")
        r = await c.post(f"{base}/auth/refresh", headers=csrf_headers(c))
        check("refresh 200", r.status_code == 200, r.text)
        new_refresh = c.cookies.get("refresh_token")
        check("refresh token rotated", old_refresh and new_refresh and old_refresh != new_refresh)

    # ── Refresh reuse detection (authoritative, service-level) ──
    # Verified directly against the rotation service so the result is unambiguous
    # (httpx's cookie jar can't reliably hold two same-name cookies for replay).
    from app.services import sessions as sess
    async with SessionLocal() as db:
        u = (await db.execute(select(User).where(User.email == email))).scalar_one()
        raw1 = await sess.issue_session(db, user_id=u.id, ip=None, user_agent=None)
        await db.commit()
    async with SessionLocal() as db:
        out = await sess.rotate_session(db, raw_refresh=raw1, ip=None, user_agent=None)
        await db.commit()
        raw2 = out.raw_token
        check("rotate issues a new token", bool(raw2) and raw2 != raw1 and not out.reuse_detected)
    async with SessionLocal() as db:
        out = await sess.rotate_session(db, raw_refresh=raw1, ip=None, user_agent=None)  # replay old
        await db.commit()
        check("replay of rotated token → reuse detected", out.reuse_detected and out.raw_token is None)
    async with SessionLocal() as db:
        out = await sess.rotate_session(db, raw_refresh=raw2, ip=None, user_agent=None)  # family revoked
        await db.commit()
        check("family revoked: rotated token also rejected", out.raw_token is None)

    # ── Account lockout (fresh client) ──
    lock_email = f"bob-{uniq}@example.com"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        await c.post(f"{base}/auth/register", json={"email": lock_email, "password": password})
        codes = []
        for _ in range(5):
            r = await c.post(f"{base}/auth/login", json={"email": lock_email, "password": "Wrong#Password1!"})
            codes.append(r.status_code)
        # 6th attempt (even with correct password) should be locked → 429
        r = await c.post(f"{base}/auth/login", json={"email": lock_email, "password": password})
        check("account locks after 5 failures (429)", r.status_code == 429, f"prev={codes} last={r.status_code}")

    # ── Password reset (console transport) ──
    reset_email = f"carol-{uniq}@example.com"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        await c.post(f"{base}/auth/register", json={"email": reset_email, "password": password})
        r = await c.post(f"{base}/auth/password-reset/request", json={"email": reset_email})
        check("reset request 200 (no enumeration)", r.status_code == 200)
        # Non-existent email returns the SAME response.
        r2 = await c.post(f"{base}/auth/password-reset/request", json={"email": f"nobody-{uniq}@example.com"})
        check("reset request identical for unknown email", r2.status_code == 200 and r2.json() == r.json())

        # Pull the raw token from the DB (in real life it's emailed).
        from app.models.password_reset import PasswordResetToken
        from app.core.security import hash_token
        # We can't reverse the hash; instead re-issue via a known token path:
        # generate a token the same way the endpoint does by reading the row and
        # crafting a matching plaintext is impossible, so verify via a fresh token.
        async with SessionLocal() as db:
            urow = (await db.execute(select(User).where(User.email == reset_email))).scalar_one()
            # Directly mint a reset token row we control, to test /confirm.
            from datetime import UTC, datetime, timedelta
            from app.core.security import generate_opaque_token
            raw = generate_opaque_token(32)
            db.add(PasswordResetToken(
                user_id=urow.id, token_hash=hash_token(raw),
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            ))
            await db.commit()

        new_pw = "Even#Str0nger!99"
        r = await c.post(f"{base}/auth/password-reset/confirm", json={"token": raw, "new_password": new_pw})
        check("reset confirm 200", r.status_code == 200, r.text)
        # Token is single-use.
        r = await c.post(f"{base}/auth/password-reset/confirm", json={"token": raw, "new_password": new_pw})
        check("reset token single-use (400 on reuse)", r.status_code == 400)
        # Login with new password works.
        r = await c.post(f"{base}/auth/login", json={"email": reset_email, "password": new_pw})
        check("login with new password 200", r.status_code == 200, r.text)

    # ── RBAC + IDOR (Bearer auth — the documented non-browser path) ──
    # Using the access token as a Bearer header keeps GET auth unambiguous (no
    # cookie-path juggling). CSRF is only required for mutations, not these GETs.
    from app.models.user import Role

    admin_email = f"admin-{uniq}@example.com"

    async def bearer_login(client: httpx.AsyncClient, mail: str, pw: str) -> dict:
        r = await client.post(f"{base}/auth/login", json={"email": mail, "password": pw})
        assert r.status_code == 200 and r.json().get("mfa_required") is False, r.text
        return {"Authorization": f"Bearer {client.cookies.get('access_token')}"}

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        # Register admin-to-be and promote via DB (mirrors scripts.create_admin).
        await c.post(f"{base}/auth/register", json={"email": admin_email, "password": password})
        async with SessionLocal() as db:
            arow = (await db.execute(select(User).where(User.email == admin_email))).scalar_one()
            arow.role = Role.admin
            await db.commit()
            admin_id = str(arow.id)

        # carol (reset_email) is a viewer.
        viewer_hdr = await bearer_login(c, reset_email, "Even#Str0nger!99")
        r = await c.get(f"{base}/users/me", headers=viewer_hdr)
        check("viewer /users/me 200", r.status_code == 200, r.text)
        carol_id = r.json()["id"]

        r = await c.get(f"{base}/users", headers=viewer_hdr)
        check("RBAC: viewer GET /users 403", r.status_code == 403, r.text)
        r = await c.get(f"{base}/users/{admin_id}", headers=viewer_hdr)
        check("IDOR: viewer reading another user 403", r.status_code == 403, r.text)
        r = await c.get(f"{base}/users/{carol_id}", headers=viewer_hdr)
        check("viewer reading own record 200", r.status_code == 200, r.text)

        admin_hdr = await bearer_login(c, admin_email, password)
        r = await c.get(f"{base}/users", headers=admin_hdr)
        check("RBAC: admin GET /users 200", r.status_code == 200, r.text)
        r = await c.get(f"{base}/users/{carol_id}", headers=admin_hdr)
        check("admin reading another user 200 (allowed)", r.status_code == 200, r.text)

    print()
    if failures:
        print(f"E2E FAILED: {len(failures)} check(s) -> {failures}")
        raise SystemExit(1)
    print("E2E PASSED — all auth flows verified against Postgres")


if __name__ == "__main__":
    asyncio.run(main())
