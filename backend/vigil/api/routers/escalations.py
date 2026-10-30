"""Phase 6 — Escalations REST API Router.

Tier 4 human-in-the-loop interface.

Endpoints:
  GET  /escalations                  — list pending + resolved escalations
  GET  /escalations/{id}             — get single escalation detail
  POST /escalations/{id}/approve     — approve: resume session one tier lower
  POST /escalations/{id}/deny        — deny: kill session permanently
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vigil.db.session import get_db
from vigil.db.models import Escalation, Session as SessionModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/escalations", tags=["Escalations"])


def _serialize(e: Escalation) -> dict[str, Any]:
    context: dict = {}
    if e.context_json:
        try:
            context = json.loads(e.context_json)
        except Exception:
            context = {"raw": e.context_json}

    return {
        "id": e.id,
        "session_id": e.session_id,
        "triggered_at": e.triggered_at.isoformat() if e.triggered_at else None,
        "resolved_at": e.resolved_at.isoformat() if e.resolved_at else None,
        "resolved_by": e.resolved_by,
        "resolution": e.resolution,
        "context": context,
        "is_pending": e.resolved_at is None,
    }


@router.get("", summary="List all escalations")
async def list_escalations(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return all escalations, pending first then resolved newest-first."""
    result = await db.execute(
        select(Escalation).order_by(Escalation.triggered_at.desc())
    )
    all_esc = result.scalars().all()
    pending = [e for e in all_esc if e.resolved_at is None]
    resolved = [e for e in all_esc if e.resolved_at is not None]
    return {
        "pending_count": len(pending),
        "resolved_count": len(resolved),
        "pending": [_serialize(e) for e in pending],
        "resolved": [_serialize(e) for e in resolved],
    }


@router.get("/{escalation_id}", summary="Get single escalation")
async def get_escalation(
    escalation_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    result = await db.execute(
        select(Escalation).where(Escalation.id == escalation_id)
    )
    esc = result.scalar_one_or_none()
    if esc is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    return _serialize(esc)


@router.post("/{escalation_id}/approve", summary="Approve Tier 4 escalation")
async def approve_escalation(
    escalation_id: str,
    resolved_by: str = "operator",
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Approve the escalation: mark resolved, drop session from Tier 4 to Tier 3."""
    result = await db.execute(
        select(Escalation).where(Escalation.id == escalation_id)
    )
    esc = result.scalar_one_or_none()
    if esc is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    if esc.resolved_at is not None:
        raise HTTPException(status_code=409, detail="Escalation already resolved")

    esc.resolved_at = datetime.now(timezone.utc)
    esc.resolved_by = resolved_by
    esc.resolution = "approved"

    # Drop session tier from 4 → 3 and update risk to 79 (top of Tier 3)
    session_result = await db.execute(
        select(SessionModel).where(SessionModel.id == esc.session_id)
    )
    session = session_result.scalar_one_or_none()
    if session:
        session.current_tier = 3
        session.current_risk = 79.0
        # Also update in-memory state
        try:
            from vigil.core.session.manager import _active_sessions
            if esc.session_id in _active_sessions:
                _active_sessions[esc.session_id]["current_tier"] = 3
                _active_sessions[esc.session_id]["current_risk"] = 79.0
        except Exception:
            pass

    await db.commit()
    logger.info("escalation approved: %s by %s", escalation_id, resolved_by)
    return {"escalation_id": escalation_id, "resolution": "approved", "new_tier": 3}


@router.post("/{escalation_id}/deny", summary="Deny Tier 4 escalation (kill session)")
async def deny_escalation(
    escalation_id: str,
    resolved_by: str = "operator",
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Deny the escalation: terminate the session permanently."""
    result = await db.execute(
        select(Escalation).where(Escalation.id == escalation_id)
    )
    esc = result.scalar_one_or_none()
    if esc is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    if esc.resolved_at is not None:
        raise HTTPException(status_code=409, detail="Escalation already resolved")

    esc.resolved_at = datetime.now(timezone.utc)
    esc.resolved_by = resolved_by
    esc.resolution = "denied"

    # Terminate the session
    session_result = await db.execute(
        select(SessionModel).where(SessionModel.id == esc.session_id)
    )
    session = session_result.scalar_one_or_none()
    if session:
        session.status = "terminated"
        try:
            from vigil.core.session.manager import _active_sessions
            if esc.session_id in _active_sessions:
                _active_sessions[esc.session_id]["status"] = "terminated"
        except Exception:
            pass

    await db.commit()
    logger.info("escalation denied: %s by %s — session terminated", escalation_id, resolved_by)
    return {"escalation_id": escalation_id, "resolution": "denied", "session_status": "terminated"}
