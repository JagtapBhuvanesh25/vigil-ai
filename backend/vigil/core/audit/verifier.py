"""Algorithm 3 — Audit chain independent verifier (Layer 6).

Independently verifies the integrity of the SHA-256 hash-chained audit log
for a session WITHOUT requiring access to a running Vigil runtime.

Algorithm 3 (Architecture.md):
    For each entry n in the chain:
        1. Recompute H_n from stored fields.
        2. Assert H_n == stored entry_hash.
        3. Assert stored prev_hash == entry_{n-1}.entry_hash (or GENESIS_HASH for n=0).

Any single-byte modification to any field in any entry will cause the
recomputed hash to differ → tamper detected.

Rules.md invariant 12:
    Audit integrity is independently verifiable offline without a running Vigil.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from vigil.core.audit.writer import GENESIS_HASH, compute_entry_hash

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of an audit chain verification run.

    Attributes:
        session_id:      Session that was verified.
        entries_checked: Total number of entries verified.
        is_valid:        True if every entry passed.
        tampered_seq_no: Sequence number of the first corrupted entry, or None.
        error:           Human-readable error description, or None.
    """
    session_id: str
    entries_checked: int
    is_valid: bool
    tampered_seq_no: int | None = None
    error: str | None = None


class AuditVerifier:
    """Algorithm 3 — Independent hash-chain verifier.

    Reads the audit log for a session from the database and re-derives every
    hash to confirm the chain is intact.

    Attributes:
        None (stateless — reads DB on demand).
    """

    async def verify(self, session_id: str) -> VerificationResult:
        """Verify the complete audit chain for a session.

        Reads all entries ordered by seq_no and checks:
          - Entry 0's prev_hash == GENESIS_HASH.
          - Each entry's entry_hash matches recomputed hash.
          - Each entry's prev_hash matches previous entry's entry_hash.

        Args:
            session_id: Session whose audit chain should be verified.

        Returns:
            VerificationResult with is_valid=True if chain is intact.
        """
        from vigil.db.session import get_async_session
        from vigil.db.models import AuditLog
        from sqlalchemy import select

        try:
            async with get_async_session() as db:
                result = await db.execute(
                    select(AuditLog)
                    .where(AuditLog.session_id == session_id)
                    .order_by(AuditLog.seq_no.asc())
                )
                entries = result.scalars().all()

            if not entries:
                return VerificationResult(
                    session_id=session_id,
                    entries_checked=0,
                    is_valid=True,
                    error="No entries found — chain is trivially valid",
                )

            expected_prev_hash = GENESIS_HASH

            for i, entry in enumerate(entries):
                # 1. Check prev_hash linkage.
                if entry.prev_hash != expected_prev_hash:
                    logger.error(
                        "audit verifier: CHAIN BROKEN at seq=%d session=%s "
                        "expected_prev=%.8s... got=%.8s...",
                        entry.seq_no,
                        session_id,
                        expected_prev_hash,
                        entry.prev_hash,
                    )
                    return VerificationResult(
                        session_id=session_id,
                        entries_checked=i + 1,
                        is_valid=False,
                        tampered_seq_no=entry.seq_no,
                        error=f"prev_hash mismatch at seq={entry.seq_no}",
                    )

                # 2. Recompute entry_hash and compare.
                recomputed = compute_entry_hash(
                    prev_hash=entry.prev_hash,
                    seq_no=entry.seq_no,
                    session_id=entry.session_id,
                    event_type=entry.event_type,
                    payload_json=entry.payload_json,
                )

                if recomputed != entry.entry_hash:
                    logger.error(
                        "audit verifier: TAMPER DETECTED at seq=%d session=%s",
                        entry.seq_no,
                        session_id,
                    )
                    return VerificationResult(
                        session_id=session_id,
                        entries_checked=i + 1,
                        is_valid=False,
                        tampered_seq_no=entry.seq_no,
                        error=f"entry_hash mismatch at seq={entry.seq_no} — data tampered",
                    )

                expected_prev_hash = entry.entry_hash

            logger.info(
                "audit verifier: chain VALID — %d entries verified for session=%s",
                len(entries),
                session_id,
            )
            return VerificationResult(
                session_id=session_id,
                entries_checked=len(entries),
                is_valid=True,
            )

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "audit verifier: exception verifying session=%s: %s", session_id, exc
            )
            return VerificationResult(
                session_id=session_id,
                entries_checked=0,
                is_valid=False,
                error=f"Verification exception: {exc}",
            )
