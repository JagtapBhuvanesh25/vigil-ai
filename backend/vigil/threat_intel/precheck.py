"""URL pre-check logic for the Threat Intelligence module.

Phase 4: Provides precheck_url() — the core lookup that runs BEFORE every
http_get / web_search tool call. This satisfies:
  - Rules.md Invariant 9: every URL call must pre-check the threat DB first.
  - usecase_requirements.md UC3 FR1/FR2/FR3: block ≥ 0.7, warn 0.4–0.69, pass otherwise.

The pre-check does NOT make network requests — it is a pure DB lookup.
Rules.md: If the threat_intel DB is unavailable → fail restrictive (BLOCK).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from vigil.db.repositories import ThreatIntelRepository

logger = logging.getLogger(__name__)


class PreCheckAction(str, Enum):
    """Result action from a URL pre-check query."""

    BLOCK = "block"    # confidence ≥ 0.7 → deny tool call
    WARN = "warn"      # confidence 0.4–0.69 → allow but pre-elevate risk (+15)
    PASS = "pass"      # not in DB, or confidence < 0.4 → allow normally


# Risk pre-elevation delta applied on WARN (see FR3: +15 points)
WARN_RISK_DELTA: float = 15.0


@dataclass
class PreCheckResult:
    """Structured result returned by precheck_url().

    Attributes:
        action:       BLOCK | WARN | PASS
        confidence:   Confidence score from DB entry (0.0 if not found)
        reason:       Human-readable reason string for audit log
        threat_type:  Threat type from DB entry (empty string if not found)
        matched_url:  The URL or domain entry that matched (empty if no match)
    """

    action: PreCheckAction
    confidence: float
    reason: str
    threat_type: str = ""
    matched_url: str = ""


def extract_domain(url: str) -> str:
    """Extract the root domain from a URL string.

    Examples:
        "https://evil.ru/path" → "evil.ru"
        "http://paypa1-secure.evil.ru/" → "paypa1-secure.evil.ru"
        "evil.ru" → "evil.ru"

    Args:
        url: A URL string (with or without scheme).

    Returns:
        The netloc (hostname) component, lowercased.
    """
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.netloc.lower().strip()
    except Exception:
        return url.lower().strip()


async def precheck_url(url: str, db_session) -> PreCheckResult:
    """Query the Threat Intelligence DB and return a pre-check result.

    Rules.md Invariant 9: Must run before EVERY outbound network call.
    Rules.md §9 (Fail-Safe on DB fault): If DB unavailable → BLOCK.

    Confidence thresholds (usecase_requirements.md UC3):
        ≥ 0.70 → BLOCK
        0.40–0.69 → WARN (+15 risk delta applied by caller)
        < 0.40 → PASS

    Args:
        url:        The target URL from the tool call arguments.
        db_session: An active async SQLAlchemy session.

    Returns:
        A PreCheckResult with the recommended action and metadata.
    """
    domain = extract_domain(url)

    try:
        repo = ThreatIntelRepository(db_session)

        # 1. Exact URL match
        entry = await repo.get_by_url(url)

        # 2. Fall back to domain match if no exact URL hit
        if entry is None and domain:
            domain_entries = await repo.get_by_domain(domain)
            if domain_entries:
                # Use the highest-confidence active entry for the domain
                entry = max(
                    (e for e in domain_entries if e.is_active),
                    key=lambda e: e.confidence,
                    default=None,
                )

        if entry is None or not entry.is_active:
            return PreCheckResult(
                action=PreCheckAction.PASS,
                confidence=0.0,
                reason="URL not in threat intelligence database — request allowed.",
            )

        # Entry found — apply threshold logic
        conf = entry.confidence

        if conf >= 0.70:
            return PreCheckResult(
                action=PreCheckAction.BLOCK,
                confidence=conf,
                reason=f"URL blocked: confidence {conf:.2f} ≥ 0.70 in threat_intel "
                       f"(type: {entry.threat_type}).",
                threat_type=entry.threat_type,
                matched_url=entry.url,
            )
        elif conf >= 0.40:
            return PreCheckResult(
                action=PreCheckAction.WARN,
                confidence=conf,
                reason=f"URL suspicious: confidence {conf:.2f} in threat_intel "
                       f"(type: {entry.threat_type}). Risk pre-elevated +{WARN_RISK_DELTA}.",
                threat_type=entry.threat_type,
                matched_url=entry.url,
            )
        else:
            return PreCheckResult(
                action=PreCheckAction.PASS,
                confidence=conf,
                reason=f"URL in DB but low confidence {conf:.2f} — request allowed.",
                threat_type=entry.threat_type,
                matched_url=entry.url,
            )

    except Exception as exc:
        # Rules.md: DB fault → fail restrictive. NEVER pass-all.
        logger.error(
            "threat_intel DB unavailable during URL pre-check for %s: %s — BLOCKING (fail-safe).",
            url,
            exc,
        )
        return PreCheckResult(
            action=PreCheckAction.BLOCK,
            confidence=1.0,
            reason=f"Threat intelligence DB unavailable (fail-safe BLOCK): {exc}",
        )


__all__ = ["PreCheckAction", "PreCheckResult", "extract_domain", "precheck_url"]
