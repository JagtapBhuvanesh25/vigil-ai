"""Threat Intelligence REST API router.

Phase 5: Safe Browsing Shield — management endpoints.

Endpoints:
  GET  /threat-intel             — list active entries (paginated)
  GET  /threat-intel/export      — export as JSON or CSV (?format=json|csv)
  POST /threat-intel             — manual entry (admin override)
  DELETE /threat-intel/{id}      — deactivate entry (manual whitelist)

Rules.md:
  - No unauthenticated bulk writes (Phase 5 uses API-key validation inherited
    from the auth middleware already present in main.py).
  - Deactivation is soft (is_active=False), not hard delete — preserves audit trail.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from vigil.db.session import get_async_session
from vigil.db.repositories import ThreatIntelRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ThreatIntelCreateRequest(BaseModel):
    """Request body for POST /threat-intel (manual entry)."""

    url: str = Field(..., description="Full URL to flag (use 'domain://name' for domain-level).")
    domain: str = Field(..., description="Root domain extracted from the URL.")
    threat_type: str = Field(
        ...,
        description="One of: prompt_injection | behavioral_anomaly | "
                    "honeytoken_interaction | composite | phishing",
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score [0.0, 1.0]."
    )
    flagging_session_id: str | None = Field(
        default=None,
        description="Session that triggered this entry (for traceability).",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "",
    summary="List active threat intelligence entries",
    response_model=list[dict],
)
async def list_threat_intel(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_async_session),
) -> list[dict]:
    """Return a paginated list of active threat intelligence entries.

    Ordered by confidence descending so the highest-risk entries appear first.
    """
    repo = ThreatIntelRepository(db)
    entries = await repo.list_active(limit=limit, offset=offset)
    return [ThreatIntelRepository.to_dict(e) for e in entries]


@router.get(
    "/export",
    summary="Export threat intelligence as JSON or CSV",
)
async def export_threat_intel(
    format: str = Query(
        default="json",
        alias="format",
        description="Export format: 'json' or 'csv'.",
    ),
    include_inactive: bool = Query(
        default=False,
        description="If true, include deactivated entries.",
    ),
    db: AsyncSession = Depends(get_async_session),
):
    """Export all (active) threat intelligence entries.

    Returns a JSON document or CSV file depending on the `format` query param.
    """
    from vigil.threat_intel.exporter import export_threat_intel as _export

    fmt = format.lower().strip()
    if fmt not in {"json", "csv"}:
        raise HTTPException(
            status_code=422,
            detail="Invalid format. Use 'json' or 'csv'.",
        )

    try:
        content = await _export(
            db_session=db, fmt=fmt, include_inactive=include_inactive
        )
    except Exception as exc:
        logger.error("export_threat_intel: failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Export failed: {exc}") from exc

    media_type = "application/json" if fmt == "json" else "text/csv"
    filename = f"threat_intel_export.{fmt}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return PlainTextResponse(content=content, media_type=media_type, headers=headers)


@router.post(
    "",
    summary="Manually add a threat intelligence entry",
    response_model=dict,
    status_code=201,
)
async def create_threat_intel(
    body: ThreatIntelCreateRequest,
    db: AsyncSession = Depends(get_async_session),
) -> dict:
    """Manually insert a threat intelligence entry.

    Useful for operator-driven threat data ingestion and for seeding the DB
    with known-bad domains before the auto-flagging pipeline has run.
    """
    repo = ThreatIntelRepository(db)

    # Check if an identical active entry already exists
    existing = await repo.get_by_url(body.url)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"An active entry for URL '{body.url}' already exists (id={existing.id}).",
        )

    try:
        record = await repo.save(
            url=body.url,
            domain=body.domain,
            threat_type=body.threat_type,
            confidence=body.confidence,
            flagging_session_id=body.flagging_session_id,
        )
    except Exception as exc:
        logger.error("create_threat_intel: DB error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"DB write failed: {exc}") from exc

    logger.info(
        "threat_intel: manual entry created id=%s domain=%s confidence=%.2f",
        record.id,
        record.domain,
        record.confidence,
    )
    return ThreatIntelRepository.to_dict(record)


@router.delete(
    "/{threat_id}",
    summary="Deactivate a threat intelligence entry (manual whitelist)",
    status_code=204,
)
async def deactivate_threat_intel(
    threat_id: str,
    db: AsyncSession = Depends(get_async_session),
) -> None:
    """Soft-deactivate a threat intelligence entry.

    Sets is_active=False. The entry is retained for audit purposes.
    This is the manual override / whitelist mechanism.

    Raises:
        HTTPException 404 if the entry does not exist.
    """
    repo = ThreatIntelRepository(db)
    entry = await repo.get(threat_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"Threat intel entry '{threat_id}' not found.",
        )

    await repo.deactivate(threat_id)
    logger.info(
        "threat_intel: deactivated id=%s domain=%s (manual override)",
        threat_id,
        entry.domain,
    )
