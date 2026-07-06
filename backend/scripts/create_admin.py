"""Bootstrap the first admin account.

Security decision: the public /register endpoint can ONLY create least-privileged
`viewer` accounts, so there is no way to self-assign admin over the network. The
first admin is created out-of-band here, by someone with shell/DB access.

Usage:
    python -m scripts.create_admin admin@example.com
It reads the password from the ADMIN_PASSWORD env var (never pass secrets on argv,
they leak into shell history and process listings).
"""
import asyncio
import os
import sys

from sqlalchemy import select

from app.core.security import hash_password
from app.db import SessionLocal
from app.models.user import Role, User


async def main(email: str) -> None:
    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        print("Set ADMIN_PASSWORD in the environment first.")
        sys.exit(1)

    # Validate the same way the API does, so we can't create an account that
    # would be rejected at the login schema (e.g. reserved .local domains).
    from email_validator import EmailNotValidError, validate_email
    try:
        email = validate_email(email, check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        print(f"Invalid email: {exc}")
        sys.exit(1)

    async with SessionLocal() as db:
        existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if existing:
            existing.role = Role.admin
            existing.email_verified = True
            await db.commit()
            print(f"Promoted existing user {email} to admin.")
            return
        db.add(User(email=email, password_hash=hash_password(password), role=Role.admin, email_verified=True))
        await db.commit()
        print(f"Created admin {email}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ADMIN_PASSWORD=... python -m scripts.create_admin <email>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
