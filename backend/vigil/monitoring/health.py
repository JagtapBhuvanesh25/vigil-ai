"""Health check functions for Vigil AI system components.

Used by GET /health to report the live status of:
  - Database (SQLite / PostgreSQL)
  - Ollama LLM server
"""

import asyncio

from sqlalchemy import text

from vigil.config.loader import load_config
from vigil.db.session import get_engine


async def check_database() -> dict:
    """Verify database connectivity by running a trivial query.

    Returns a dict with {"status": "ok"} or {"status": "error", "detail": "..."}.
    Fail-safe: any exception returns error status; never raises.
    """
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": str(exc)}


async def check_ollama() -> dict:
    """Ping the Ollama server to check if it is reachable.

    Returns {"status": "ok"} or {"status": "unavailable", "detail": "..."}.
    A missing Ollama server is not fatal in Phase 1 — the agent framework is
    not built yet. The health endpoint reports it as "unavailable" rather than
    causing a startup failure.
    """
    try:
        import urllib.request

        config = load_config()
        url = config.ollama.url.rstrip("/") + "/api/tags"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:  # noqa: S310
            if resp.status == 200:
                return {"status": "ok"}
            return {"status": "unavailable", "detail": f"HTTP {resp.status}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "detail": str(exc)}


async def full_health_check() -> dict:
    """Run all health checks concurrently and return aggregated results."""
    db_result, ollama_result = await asyncio.gather(
        check_database(),
        check_ollama(),
    )
    overall = "ok" if db_result["status"] == "ok" else "degraded"
    return {
        "status": overall,
        "db": db_result["status"],
        "ollama": ollama_result["status"],
    }
