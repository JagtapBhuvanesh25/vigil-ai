"""Confidence scoring and time-decay for Threat Intelligence entries.

Phase 5: Safe Browsing Shield — confidence lifecycle management.

Decay model (Rules.md-compatible):
  - Linear decay: ~0.05 per 7-day period.
  - Hard floor: 0.10 (an entry never decays to zero — it must be explicitly deactivated).
  - Entries below floor are deactivated by the scheduler (moved to is_active=False).
  - Each new trigger resets confidence to max(current, 0.70) to model re-reinforcement.

Usage::
    # Compute decayed confidence for a single entry
    decayed = compute_decayed_confidence(original=0.80, days_elapsed=7.0)
    # → ~0.75

    # Run the decay scheduler over all active entries in the DB
    deactivated = await run_decay_pass(db_session)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ── Decay constants ─────────────────────────────────────────────────────────
DECAY_RATE_PER_7_DAYS: float = 0.05   # Linear decay rate per week
CONFIDENCE_FLOOR: float = 0.10         # Minimum confidence — never decay below this
DEACTIVATION_THRESHOLD: float = 0.10  # Deactivate when confidence hits the floor
TRIGGER_BOOST_FLOOR: float = 0.70     # Minimum confidence after a new trigger
DECAY_INTERVAL_DAYS: float = 7.0      # Decay period in days


def compute_decayed_confidence(original: float, days_elapsed: float) -> float:
    """Compute time-decayed confidence for a single threat intel entry.

    Uses a linear decay model: confidence decreases by DECAY_RATE_PER_7_DAYS
    for every 7 days elapsed since last_triggered. Clamped at CONFIDENCE_FLOOR.

    Args:
        original:     The entry's current confidence score [0.0, 1.0].
        days_elapsed: Days since the entry was last triggered or updated.

    Returns:
        Decayed confidence in [CONFIDENCE_FLOOR, 1.0].

    Example:
        >>> compute_decayed_confidence(0.80, 7.0)
        0.75
        >>> compute_decayed_confidence(0.80, 100.0)  # many weeks → floor
        0.1
    """
    periods = days_elapsed / DECAY_INTERVAL_DAYS
    decayed = original - (DECAY_RATE_PER_7_DAYS * periods)
    return max(decayed, CONFIDENCE_FLOOR)


def should_deactivate(confidence: float) -> bool:
    """Return True if a decayed confidence score should trigger deactivation.

    An entry is deactivated when its confidence reaches the floor — it no longer
    provides a meaningful signal but stays in the audit trail as is_active=False.

    Args:
        confidence: Current (potentially decayed) confidence score.

    Returns:
        True if confidence ≤ DEACTIVATION_THRESHOLD.
    """
    return confidence <= DEACTIVATION_THRESHOLD


def reinforce_confidence(current: float) -> float:
    """Compute new confidence after a repeat trigger (re-reinforcement).

    When an already-flagged URL is encountered again, we bump confidence to
    at least TRIGGER_BOOST_FLOOR to model continued malicious activity.

    Args:
        current: Current confidence score.

    Returns:
        New confidence = max(current, TRIGGER_BOOST_FLOOR), capped at 1.0.
    """
    return min(max(current, TRIGGER_BOOST_FLOOR), 1.0)


async def run_decay_pass(db_session: AsyncSession) -> list[str]:
    """Apply the decay model to every active ThreatIntel entry in the DB.

    For each active entry:
      1. Compute days since last_triggered.
      2. Compute decayed confidence.
      3. If decayed confidence ≤ DEACTIVATION_THRESHOLD → deactivate.
      4. Otherwise update confidence in place.

    This is meant to be called by a background scheduler (e.g. nightly cron).
    Rules.md: This is a maintenance task, not a real-time path.

    Args:
        db_session: An active async SQLAlchemy session.

    Returns:
        List of ThreatIntel UUIDs that were deactivated during this pass.
    """
    from sqlalchemy import select, update
    from vigil.db.models import ThreatIntel

    now = datetime.now(timezone.utc)
    deactivated_ids: list[str] = []

    try:
        result = await db_session.execute(
            select(ThreatIntel).where(ThreatIntel.is_active.is_(True))
        )
        entries = list(result.scalars().all())

        for entry in entries:
            last = entry.last_triggered or entry.first_seen
            if last is None:
                continue
            # Ensure timezone-aware for subtraction
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            days_elapsed = (now - last).total_seconds() / 86_400.0
            if days_elapsed < 0:
                continue

            decayed = compute_decayed_confidence(entry.confidence, days_elapsed)

            if should_deactivate(decayed):
                await db_session.execute(
                    update(ThreatIntel)
                    .where(ThreatIntel.id == entry.id)
                    .values(is_active=False, confidence=CONFIDENCE_FLOOR)
                )
                deactivated_ids.append(entry.id)
                logger.info(
                    "decay_pass: deactivated %s (domain=%s, confidence=%.2f → floor)",
                    entry.id,
                    entry.domain,
                    entry.confidence,
                )
            else:
                await db_session.execute(
                    update(ThreatIntel)
                    .where(ThreatIntel.id == entry.id)
                    .values(confidence=round(decayed, 4))
                )

        await db_session.commit()
        logger.info(
            "decay_pass: processed %d entries, deactivated %d",
            len(entries),
            len(deactivated_ids),
        )

    except Exception as exc:  # noqa: BLE001
        logger.error("decay_pass: unexpected error — rolling back: %s", exc)
        await db_session.rollback()

    return deactivated_ids


__all__ = [
    "CONFIDENCE_FLOOR",
    "DECAY_RATE_PER_7_DAYS",
    "DEACTIVATION_THRESHOLD",
    "TRIGGER_BOOST_FLOOR",
    "compute_decayed_confidence",
    "should_deactivate",
    "reinforce_confidence",
    "run_decay_pass",
]
