"""Domain-level blacklist aggregation for the Safe Browsing Shield.

Phase 5: Domain blacklisting — if 3+ distinct URLs are flagged for the same
registered domain within a 24-hour rolling window, the entire domain is
automatically blocked at confidence 0.95.

This implements the domain-level threat escalation path described in
usecase_requirements.md UC3 FR4 and Phases.md Phase 5.

Rules.md:
  - Domain block is irreversible via this module (only manual override via API).
  - Fail-safe: DB fault → log error, do NOT silently skip blacklist check.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ── Domain blacklist constants ────────────────────────────────────────────────
DOMAIN_BLOCK_THRESHOLD: int = 3           # Minimum distinct URL flags
DOMAIN_BLOCK_WINDOW_HOURS: float = 24.0   # Rolling window in hours
DOMAIN_BLOCK_CONFIDENCE: float = 0.95    # Auto-block confidence
DOMAIN_BLOCK_THREAT_TYPE: str = "composite"  # Threat type for domain-level entries


def extract_registered_domain(domain: str) -> str:
    """Extract the registered (eTLD+1) domain from a hostname.

    For simplicity, takes the last two labels of the hostname as the
    registered domain. Full PSL parsing is not required for Phase 5.

    Examples:
        "paypa1-secure.evil.ru" → "evil.ru"
        "evil.ru" → "evil.ru"
        "sub.sub.phish.tk" → "phish.tk"

    Args:
        domain: A hostname string (no scheme or path).

    Returns:
        The registered domain (two rightmost labels).
    """
    labels = domain.lower().strip().split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return domain.lower().strip()


async def check_and_apply_domain_block(
    domain: str,
    db_session: AsyncSession,
) -> bool:
    """Check if a domain should be auto-blocked and apply the block if so.

    Counts distinct active URL flags for the registered domain created within
    the last DOMAIN_BLOCK_WINDOW_HOURS hours. If count ≥ DOMAIN_BLOCK_THRESHOLD,
    inserts a domain-level wildcard entry at DOMAIN_BLOCK_CONFIDENCE.

    Args:
        domain:     The full domain that was just flagged.
        db_session: An active async SQLAlchemy session.

    Returns:
        True if a domain-level block was applied, False otherwise.
    """
    from sqlalchemy import select, func
    from vigil.db.models import ThreatIntel

    registered = extract_registered_domain(domain)
    window_start = datetime.now(timezone.utc) - timedelta(hours=DOMAIN_BLOCK_WINDOW_HOURS)

    try:
        # Count distinct URLs flagged for any subdomain of this registered domain
        # that are recent and active.
        result = await db_session.execute(
            select(func.count(ThreatIntel.id))
            .where(
                ThreatIntel.domain.like(f"%{registered}"),
                ThreatIntel.is_active.is_(True),
                ThreatIntel.first_seen >= window_start,
            )
        )
        flag_count = result.scalar_one() or 0

        if flag_count < DOMAIN_BLOCK_THRESHOLD:
            logger.debug(
                "blacklist: domain=%s has %d flags (threshold=%d) — no block",
                registered,
                flag_count,
                DOMAIN_BLOCK_THRESHOLD,
            )
            return False

        # Check if a domain-level block already exists
        existing_result = await db_session.execute(
            select(ThreatIntel)
            .where(
                ThreatIntel.domain == registered,
                ThreatIntel.url == f"domain://{registered}",
                ThreatIntel.is_active.is_(True),
            )
            .limit(1)
        )
        existing = existing_result.scalar_one_or_none()

        if existing is not None:
            logger.debug(
                "blacklist: domain-level block for %s already exists", registered
            )
            return False

        # Apply domain-level block
        import uuid

        block_entry = ThreatIntel(
            id=str(uuid.uuid4()),
            url=f"domain://{registered}",
            domain=registered,
            threat_type=DOMAIN_BLOCK_THREAT_TYPE,
            confidence=DOMAIN_BLOCK_CONFIDENCE,
            trigger_count=flag_count,
            is_active=True,
        )
        db_session.add(block_entry)
        await db_session.commit()

        logger.warning(
            "blacklist: AUTO-BLOCKED domain=%s after %d flags in %.0fh window "
            "(confidence=%.2f)",
            registered,
            flag_count,
            DOMAIN_BLOCK_WINDOW_HOURS,
            DOMAIN_BLOCK_CONFIDENCE,
        )
        return True

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "blacklist: DB error during domain check for %s: %s", registered, exc
        )
        await db_session.rollback()
        return False


async def is_domain_blocked(
    domain: str,
    db_session: AsyncSession,
) -> tuple[bool, float]:
    """Check whether a registered domain has an active block entry.

    Args:
        domain:     Domain to check (full hostname or registered domain).
        db_session: An active async SQLAlchemy session.

    Returns:
        (is_blocked, confidence) tuple. confidence is 0.0 if not blocked.
    """
    from sqlalchemy import select
    from vigil.db.models import ThreatIntel

    registered = extract_registered_domain(domain)

    try:
        result = await db_session.execute(
            select(ThreatIntel)
            .where(
                ThreatIntel.url == f"domain://{registered}",
                ThreatIntel.is_active.is_(True),
            )
            .limit(1)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False, 0.0
        return True, entry.confidence

    except Exception as exc:  # noqa: BLE001
        logger.error("blacklist: is_domain_blocked DB error for %s: %s", domain, exc)
        # Fail restrictive: treat DB fault as blocked
        return True, 1.0


__all__ = [
    "DOMAIN_BLOCK_THRESHOLD",
    "DOMAIN_BLOCK_WINDOW_HOURS",
    "DOMAIN_BLOCK_CONFIDENCE",
    "extract_registered_domain",
    "check_and_apply_domain_block",
    "is_domain_blocked",
]
