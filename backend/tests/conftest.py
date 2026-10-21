"""Pytest configuration for Vigil AI backend tests.

Shared fixtures and global patches for the entire test suite.

Key responsibilities:
  1. Redirect the global async DB engine to an in-memory SQLite database
     with all ORM tables created, so that the audit writer and session
     manager can function correctly during unit tests.
  2. Ensure each test that uses DB-backed tools gets a clean DB state.

Test categories:
  - unit/           — isolated unit tests
  - integration/    — tests against SQLite test DB
"""

from __future__ import annotations

import asyncio
import pytest

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


# ---------------------------------------------------------------------------
# Session-scoped in-memory engine — created ONCE for the whole test run.
# All tables are created once; tests share the schema but may write rows.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop_policy():
    """Use the default event loop policy (required by pytest-asyncio ≥ 0.23)."""
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def patch_db_to_inmemory(tmp_path_factory):
    """Redirect the Vigil DB singleton to a shared in-memory SQLite DB.

    This fixture runs once for the entire test session.  It:
      1. Creates an in-memory async SQLite engine.
      2. Creates all ORM tables.
      3. Monkeypatches vigil.db.session._engine and _session_factory.
      4. Patches get_async_session() to use the test engine.

    This ensures the AuditWriter, SessionManager, and all @contained_tool
    functions can write to a DB without failing with 'no such table'.
    """
    import vigil.db.session as db_session_module
    from vigil.db.models import Base

    # Use a file-based SQLite in tmp so it persists across the session
    # but is unique per test run.
    tmp = tmp_path_factory.mktemp("vigil_test_db")
    db_path = tmp / "vigil_test.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"

    # Create engine and tables synchronously using a temporary event loop.
    async def _setup():
        engine = create_async_engine(db_url, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return engine

    loop = asyncio.new_event_loop()
    engine = loop.run_until_complete(_setup())
    loop.close()

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Monkeypatch the module-level singletons so everything downstream uses them.
    old_engine = db_session_module._engine
    old_factory = db_session_module._session_factory

    db_session_module._engine = engine
    db_session_module._session_factory = factory

    yield  # tests run here

    # Restore originals after the session ends.
    db_session_module._engine = old_engine
    db_session_module._session_factory = old_factory

    # Clean up the test engine.
    async def _teardown():
        await engine.dispose()

    loop2 = asyncio.new_event_loop()
    loop2.run_until_complete(_teardown())
    loop2.close()
