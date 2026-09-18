"""Crash-safe session state checkpoint and recovery.

When the Vigil API restarts unexpectedly, sessions that were mid-flight
can be recovered from the audit log.  This module scans the audit log
for the last known state (risk, tier) and restores it to the in-memory
session cache.

Rules.md: Per-session salt must survive a restart — stored in the sessions table.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def recover_session_state(session_id: str) -> dict[str, Any] | None:
    """Recover session state from the audit log after a crash.

    Reads the last audit entry for the session and extracts the risk/tier
    values from the payload_json.  Falls back to DB session record values
    if the audit log has no entries.

    Args:
        session_id: Session to recover.

    Returns:
        Recovered state dict, or None if recovery is impossible.
    """
    from vigil.db.session import get_async_session
    from vigil.db.models import AuditLog, Session as SessionModel
    from sqlalchemy import select

    try:
        async with get_async_session() as db:
            # Get the latest audit entry.
            result = await db.execute(
                select(AuditLog)
                .where(AuditLog.session_id == session_id)
                .order_by(AuditLog.seq_no.desc())
                .limit(1)
            )
            last_entry = result.scalar_one_or_none()

            # Get the session record for salt and metadata.
            session_result = await db.execute(
                select(SessionModel).where(SessionModel.id == session_id)
            )
            record = session_result.scalar_one_or_none()

            if record is None:
                logger.warning("checkpoint: session %s not found in DB", session_id)
                return None

            risk = record.current_risk
            tier = record.current_tier

            # If there are audit entries, the last one has the most recent risk/tier.
            if last_entry is not None:
                try:
                    payload = json.loads(last_entry.payload_json)
                    risk = payload.get("risk_after", risk)
                    tier = payload.get("tier_after", tier)
                except (json.JSONDecodeError, KeyError) as exc:
                    logger.warning(
                        "checkpoint: could not parse audit payload for session %s: %s",
                        session_id,
                        exc,
                    )

            state = {
                "id": session_id,
                "session_salt": record.session_salt,
                "current_risk": risk,
                "current_tier": tier,
                "status": record.status,
                "agent_type": record.agent_type,
                "deception_registry": {},  # Honeytokens are not recoverable — session must be re-planted.
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "recovered": True,
            }
            logger.info(
                "checkpoint: recovered session=%s risk=%.1f tier=%d", session_id, risk, tier
            )
            return state

    except Exception as exc:  # noqa: BLE001
        logger.error("checkpoint: recovery failed for session %s: %s", session_id, exc)
        return None
