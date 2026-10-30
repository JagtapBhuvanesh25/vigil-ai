"""Phase 6 — Audit Log REST API Router.

Endpoints:
  GET  /audit              — paginated audit log (all sessions or filtered)
  GET  /audit/{session_id} — audit chain for a specific session
  POST /audit/verify       — verify chain integrity (Algorithm 3)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from vigil.db.session import get_db
from vigil.db.models import AuditLog
from vigil.core.audit.verifier import AuditVerifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["Audit"])


def _serialize_entry(entry: AuditLog) -> dict[str, Any]:
    return {
        "id": entry.id,
        "session_id": entry.session_id,
        "seq_no": entry.seq_no,
        "event_type": entry.event_type,
        "payload_json": entry.payload_json,
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@router.get("", summary="List audit log entries (paginated)")
async def list_audit_log(
    session_id: str | None = Query(None, description="Filter by session ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return paginated audit log entries, newest first."""
    offset = (page - 1) * page_size

    q = select(AuditLog).order_by(AuditLog.id.desc())
    count_q = select(func.count()).select_from(AuditLog)

    if session_id:
        q = q.where(AuditLog.session_id == session_id)
        count_q = count_q.where(AuditLog.session_id == session_id)

    total_result = await db.execute(count_q)
    total = total_result.scalar_one()

    result = await db.execute(q.offset(offset).limit(page_size))
    entries = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "entries": [_serialize_entry(e) for e in entries],
    }


@router.get("/{session_id}", summary="Get audit chain for a session")
async def get_session_audit(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return all audit entries for a session in chronological order."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.session_id == session_id)
        .order_by(AuditLog.seq_no.asc())
    )
    entries = result.scalars().all()
    return {
        "session_id": session_id,
        "count": len(entries),
        "entries": [_serialize_entry(e) for e in entries],
    }


@router.post("/verify", summary="Verify audit chain integrity")
async def verify_chain(
    session_id: str | None = Query(None, description="Session to verify (omit for all)"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run Algorithm 3 verifier over the audit chain.

    Returns:
        valid: True if chain is intact
        tampered_at_seq: seq_no of first broken entry (None if valid)
        total_verified: number of entries checked
    """
    verifier = AuditVerifier()

    if session_id:
        # Verify one session using the verifier's built-in DB access
        vr = await verifier.verify(session_id)
        return {
            "valid": vr.is_valid,
            "tampered_session": session_id if not vr.is_valid else None,
            "tampered_at_seq": vr.tampered_seq_no,
            "total_verified": vr.entries_checked,
            "error": vr.error,
        }

    # Verify all sessions
    result = await db.execute(select(AuditLog.session_id).distinct())
    session_ids = [row[0] for row in result.all()]

    total_verified = 0
    tampered_session = None
    tampered_at_seq = None

    for sid in session_ids:
        vr = await verifier.verify(sid)
        total_verified += vr.entries_checked
        if not vr.is_valid:
            tampered_session = sid
            tampered_at_seq = vr.tampered_seq_no
            break

    return {
        "valid": tampered_session is None,
        "tampered_session": tampered_session,
        "tampered_at_seq": tampered_at_seq,
        "total_verified": total_verified,
    }
