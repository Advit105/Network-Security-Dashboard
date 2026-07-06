"""Create database tables (development convenience).

For production, use Alembic migrations instead of create_all so schema changes are
versioned and reviewable. Run: python -m scripts.init_db
"""
import asyncio

from app.db import Base, engine
from app import models  # noqa: F401  (import registers all models on Base.metadata)


async def main() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Tables created.")


if __name__ == "__main__":
    asyncio.run(main())
