"""Async database engine and session.

Security decision: all data access goes through SQLAlchemy's ORM / Core with
bound parameters. We never build SQL by string concatenation, which structurally
prevents SQL injection.
"""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,   # drop dead connections instead of erroring mid-request
    echo=False,           # never echo SQL in prod (could leak data to logs)
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: one session per request, always closed."""
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
