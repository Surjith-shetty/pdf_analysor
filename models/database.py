"""
models/database.py
Async SQLAlchemy engine + session factory.
All DB operations use async sessions for non-blocking I/O.
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from config.settings import settings
from models.db_models import Base

# Resolve DB path relative to project root so all server processes share one file
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_db_url = settings.database_url
if _db_url.startswith("sqlite") and "///./" in _db_url:
    _db_file = _db_url.split("///./", 1)[1]
    _db_url = f"sqlite+aiosqlite:///{os.path.join(_PROJECT_ROOT, _db_file)}"

engine = create_async_engine(_db_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_db():
    """Create all tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """FastAPI dependency for DB sessions."""
    async with AsyncSessionLocal() as session:
        yield session
