"""Vigil AI — FastAPI Application Entry Point.

Startup sequence (Rules.md invariants):
  1. Validate secrets are not placeholders → refuse to start if they are.
  2. Verify database is reachable → refuse to start if it is not.
  3. Register all API routers.
  4. Expose GET /health for system status monitoring.
"""

import logging

from dotenv import load_dotenv

# Load .env before FastAPI startup handlers run so VIGIL_* env vars are available.
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vigil.api.auth import validate_secrets_on_startup
from vigil.monitoring.health import full_health_check

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Vigil AI",
    description=(
        "Containment-Aware AI Security Platform — "
        "six-layer runtime containment for LLM agents."
    ),
    version="0.5.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Register routers ───────────────────────────────────────────────────────────
from vigil.api.routers.sessions import router as sessions_router  # noqa: E402
from vigil.api.routers.emails import router as emails_router  # noqa: E402
from vigil.api.routers.analyzer import router as analyzer_router  # noqa: E402
from vigil.api.routers.threat_intel import router as threat_intel_router  # noqa: E402

app.include_router(sessions_router)
app.include_router(emails_router)
app.include_router(analyzer_router)
app.include_router(threat_intel_router)


# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the Next.js dashboard (any localhost port during development).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup() -> None:
    """Run startup checks.

    Rules.md: Refuse to start if secrets are placeholders or DB is unreachable.
    """
    # 1. Secret validation (fail hard if placeholders remain)
    validate_secrets_on_startup()
    logger.info("Vigil AI: secrets validated.")

    # 2. Database connectivity check
    from vigil.monitoring.health import check_database

    db_status = await check_database()
    if db_status["status"] != "ok":
        raise RuntimeError(
            f"Database is not reachable at startup: {db_status.get('detail')}. "
            "Run `make init-db` to initialise the database."
        )
    logger.info("Vigil AI: database OK.")
    logger.info("Vigil AI startup complete — containment engine ready.")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """Clean up resources on shutdown."""
    from vigil.db.session import get_engine

    engine = get_engine()
    await engine.dispose()
    logger.info("Vigil AI: database connections closed.")


# ── Health Endpoint ────────────────────────────────────────────────────────────
@app.get(
    "/health",
    summary="System health check",
    tags=["System"],
    response_model=dict,
)
async def health() -> dict:
    """Return live health status of all Vigil AI components.

    Returns:
        JSON object with top-level 'status' and per-component entries.
        status: 'ok' when all critical components are healthy.
                'degraded' when non-critical components (e.g. Ollama) are down.
    """
    return await full_health_check()
