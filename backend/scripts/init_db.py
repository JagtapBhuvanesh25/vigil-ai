"""Database initialisation script for Vigil AI.

Usage:
    python scripts/init_db.py

What it does:
  1. Validates that VIGIL_API_KEY and VIGIL_JWT_SECRET are not placeholder values.
  2. Runs `alembic upgrade head` to create / migrate the database schema.
  3. Prints the DB path and table count to confirm success.

Rules.md: If secrets are placeholders, refuse to run.
Rules.md: If DB is unreachable, log the error and exit non-zero. Never fall back
          to in-memory.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path

# Allow running from the backend/ directory directly
sys.path.insert(0, str(Path(__file__).parent.parent))

_PLACEHOLDER_API_KEY = "CHANGE_ME_VIGIL_API_KEY"
_PLACEHOLDER_JWT_SECRET = "CHANGE_ME_JWT_SECRET_AT_LEAST_32_CHARS"


def _check_secrets() -> None:
    """Refuse to initialise if secret placeholders are still in use."""
    from dotenv import load_dotenv

    load_dotenv()
    api_key = os.environ.get("VIGIL_API_KEY", _PLACEHOLDER_API_KEY)
    jwt_secret = os.environ.get("VIGIL_JWT_SECRET", _PLACEHOLDER_JWT_SECRET)

    if api_key == _PLACEHOLDER_API_KEY:
        print(
            "ERROR: VIGIL_API_KEY is still the placeholder value.\n"
            "Copy .env.example to .env and set a real key.",
            file=sys.stderr,
        )
        sys.exit(1)

    if jwt_secret == _PLACEHOLDER_JWT_SECRET:
        print(
            "ERROR: VIGIL_JWT_SECRET is still the placeholder value.\n"
            "Copy .env.example to .env and set a real secret.",
            file=sys.stderr,
        )
        sys.exit(1)


def _run_alembic() -> None:
    """Run alembic upgrade head to apply all pending migrations."""
    backend_dir = Path(__file__).parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(backend_dir),
        capture_output=False,
    )
    if result.returncode != 0:
        print("ERROR: Alembic migration failed. See output above.", file=sys.stderr)
        sys.exit(result.returncode)


async def _verify_tables() -> None:
    """Connect to the DB and verify expected tables exist."""
    from sqlalchemy import inspect, text

    from vigil.db.session import get_engine

    engine = get_engine()
    async with engine.connect() as conn:
        # SQLite: query sqlite_master; PostgreSQL: use information_schema
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        )
        tables = [row[0] for row in result.fetchall()]

    expected = {
        "sessions",
        "audit_log",
        "emails",
        "threat_intel",
        "escalations",
        "config_versions",
    }
    missing = expected - set(tables)
    if missing:
        print(f"ERROR: Expected tables are missing after migration: {missing}", file=sys.stderr)
        sys.exit(1)

    await engine.dispose()
    print(f"Database initialised. Tables present: {sorted(tables)}")


def main() -> None:
    """Initialise the Vigil AI database."""
    print("Vigil AI — Database Initialisation")
    print("=" * 40)

    _check_secrets()
    print("[OK] Secrets validated.")
    print("Running Alembic migrations...")
    _run_alembic()
    print("[OK] Migrations applied.")

    asyncio.run(_verify_tables())
    print("[OK] All tables verified.")
    print("\nDatabase is ready. Run `make dev` to start the platform.")


if __name__ == "__main__":
    main()
