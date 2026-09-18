"""Async database engine factory for Vigil AI.

Selects the correct backend driver based on the VIGIL_DB_URL:
  - sqlite+aiosqlite://  →  local development (default)
  - postgresql+asyncpg:// →  production / Neon cloud deployment

Rules.md: If the DB is unavailable at startup, log the error and refuse to start.
          Do NOT fall back to an in-memory database.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from vigil.config.loader import load_config

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the singleton async database engine."""
    global _engine
    if _engine is None:
        config = load_config()
        _engine = create_async_engine(
            config.database.url,
            echo=False,  # set to True for SQL query logging during development
            # SQLite-specific: enable WAL mode for concurrent reads
            connect_args={"check_same_thread": False}
            if "sqlite" in config.database.url
            else {},
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the singleton session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield a database session per request."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
