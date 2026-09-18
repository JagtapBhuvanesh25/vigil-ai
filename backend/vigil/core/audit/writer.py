"""Algorithm 3 — SHA-256 hash-chained audit log writer (Layer 6).

Each audit entry covers a TraceEvent and is linked to the previous entry via
a SHA-256 hash chain, making the log tamper-evident.

Hash chain formula (Architecture.md Eq. 2):
    H0 = SHA-256("GENESIS")
    Hn = SHA-256(prev_hash || seq_no || session_id || event_type || payload_json)

Rules.md invariants:
  - Audit entry MUST be committed to DB BEFORE the corresponding tool action.
  - Audit failure → deny the tool call (fail restrictive).
  - No raw argument content stored — only hashed TraceEvent data.
"""

from __future__ import annotations

import hashlib
import json
import logging

from vigil.core.interceptor.trace import TraceEvent

logger = logging.getLogger(__name__)

# Genesis hash — the anchor of every session's hash chain.
GENESIS_HASH = hashlib.sha256(b"GENESIS").hexdigest()


def compute_entry_hash(
    prev_hash: str,
    seq_no: int,
    session_id: str,
    event_type: str,
    payload_json: str,
) -> str:
    """Compute a single hash-chain entry hash.

    H_n = SHA-256(prev_hash || seq_no || session_id || event_type || payload_json)

    Args:
        prev_hash:    Hash of the previous entry (or GENESIS_HASH for first entry).
        seq_no:       Monotonically increasing sequence number within the session.
        session_id:   Owning session identifier.
        event_type:   Event type string (e.g. 'risk_update', 'tier_decision').
        payload_json: JSON-serialised payload (no raw argument content).

    Returns:
        64-character lowercase hex SHA-256 digest.
    """
    raw = f"{prev_hash}|{seq_no}|{session_id}|{event_type}|{payload_json}".encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def build_payload(trace: TraceEvent) -> str:
    """Serialise a TraceEvent into a JSON payload for audit storage.

    Only metadata is stored — never raw argument values (Rules.md).

    Args:
        trace: The intercepted tool call event.

    Returns:
        JSON string containing audit-safe fields.
    """
    payload = {
        "trace_id": trace.trace_id,
        "tool_name": trace.tool_name,
        "args_hash": trace.args_hash,
        "allowed": trace.allowed,
        "denial_reason": trace.denial_reason,
        "risk_before": trace.risk_before,
        "risk_after": trace.risk_after,
        "tier_before": trace.tier_before,
        "tier_after": trace.tier_after,
        "timestamp": trace.timestamp.isoformat(),
    }
    return json.dumps(payload, sort_keys=True)


class AuditWriter:
    """SHA-256 hash-chained audit log writer.

    Appends entries to the audit_log table, maintaining a per-session hash
    chain.  Each write operation is atomic — if the DB write fails, the
    caller must deny the tool call (Rules.md fail-safe rule).

    Attributes:
        None (uses the shared async DB session factory).
    """

    async def append(self, session_id: str, trace: TraceEvent) -> None:
        """Append an audit entry for a TraceEvent.

        Computes the hash chain, builds the payload, and writes to DB.
        This MUST be called before the tool action executes.

        Args:
            session_id: The owning session ID.
            trace:      The intercepted tool call event.

        Raises:
            Exception: Propagated from DB if write fails — caller must
                       deny the tool call.
        """
        from vigil.db.session import get_async_session
        from vigil.db.models import AuditLog

        event_type = "risk_update"
        if not trace.allowed:
            event_type = "tier_decision"

        payload_json = build_payload(trace)

        async with get_async_session() as session:
            # Get the previous entry to build the chain.
            from sqlalchemy import select, func

            result = await session.execute(
                select(AuditLog)
                .where(AuditLog.session_id == session_id)
                .order_by(AuditLog.seq_no.desc())
                .limit(1)
            )
            prev_entry = result.scalar_one_or_none()

            if prev_entry is None:
                prev_hash = GENESIS_HASH
                seq_no = 0
            else:
                prev_hash = prev_entry.entry_hash
                seq_no = prev_entry.seq_no + 1

            entry_hash = compute_entry_hash(
                prev_hash=prev_hash,
                seq_no=seq_no,
                session_id=session_id,
                event_type=event_type,
                payload_json=payload_json,
            )

            entry = AuditLog(
                session_id=session_id,
                seq_no=seq_no,
                event_type=event_type,
                payload_json=payload_json,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            session.add(entry)
            await session.commit()

            logger.debug(
                "audit: wrote entry seq=%d session=%s event=%s hash=%.8s...",
                seq_no,
                session_id,
                event_type,
                entry_hash,
            )
