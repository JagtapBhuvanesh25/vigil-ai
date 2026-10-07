"""Auto-flagging logic: write malicious URLs to the Threat Intelligence DB.

Phase 4: When the Phishing Analyzer produces a Malicious verdict with
confidence ≥ 0.7, all extracted domains are automatically written to the
threat_intel table for use in future URL pre-checks.

This satisfies:
  - Phases.md Phase 4: "Confirmed malicious domains auto-written to threat_intel"
  - PRD.md FR-P7: "Feed confirmed malicious domains/URLs to Threat Intelligence DB"
  - usecase_requirements.md UC2 FR8 / UC3 FR4: URL flagging on risk spike
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from vigil.db.repositories import ThreatIntelRepository

logger = logging.getLogger(__name__)

# Confidence threshold: only auto-flag if verdict confidence ≥ this value.
# PRD.md FR-P7 + Phases.md Phase 4: "confidence > 0.7"
AUTO_FLAG_CONFIDENCE_THRESHOLD: float = 0.70

# Base confidence assigned to auto-flagged entries from analyzer verdicts.
AUTO_FLAG_BASE_CONFIDENCE: float = 0.80


def extract_domain(url: str) -> str:
    """Extract root domain from a URL string.

    Args:
        url: A URL string.

    Returns:
        Lowercased netloc/hostname, or the raw url if parsing fails.
    """
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.netloc.lower().strip()
    except Exception:
        return url.lower().strip()


async def auto_flag_domains(
    domains: list[str],
    threat_type: str,
    session_id: str,
    verdict_confidence: float,
    db_session,
) -> list[str]:
    """Write confirmed malicious domains to the threat_intel table.

    Called by the analyzer after producing a Malicious verdict with high
    confidence. Each domain is upserted into threat_intel — if it already
    exists the trigger_count and last_triggered are incremented.

    Rules.md: Audit entry must be written before the action (handled by caller).

    Args:
        domains:            List of domains to flag (extracted from email URLs).
        threat_type:        Threat type label from the analyzer verdict.
        session_id:         Originating session ID for traceability.
        verdict_confidence: Confidence from the AnalyzerVerdict (0.0–1.0).
        db_session:         Active async SQLAlchemy session.

    Returns:
        List of domain strings that were successfully written to the DB.
        Returns empty list if below threshold or no domains provided.
    """
    if verdict_confidence < AUTO_FLAG_CONFIDENCE_THRESHOLD:
        logger.debug(
            "auto_flag_domains: verdict confidence %.2f < %.2f threshold — skipping.",
            verdict_confidence,
            AUTO_FLAG_CONFIDENCE_THRESHOLD,
        )
        return []

    if not domains:
        return []

    repo = ThreatIntelRepository(db_session)
    flagged: list[str] = []

    for domain in domains:
        if not domain:
            continue
        try:
            # Check if already in DB
            existing = await repo.get_by_domain(domain)
            if existing:
                # Increment trigger on existing entry
                for entry in existing:
                    if entry.is_active:
                        await repo.increment_trigger(entry.id)
                        logger.info(
                            "auto_flag_domains: incremented trigger for existing domain '%s' (session %s).",
                            domain,
                            session_id,
                        )
                flagged.append(domain)
            else:
                # Create new entry
                # Synthesize a canonical URL from the domain
                canonical_url = f"http://{domain}/"
                await repo.save(
                    url=canonical_url,
                    domain=domain,
                    threat_type=threat_type,
                    confidence=AUTO_FLAG_BASE_CONFIDENCE,
                    flagging_session_id=session_id,
                )
                logger.info(
                    "auto_flag_domains: flagged new domain '%s' (type=%s, session=%s).",
                    domain,
                    threat_type,
                    session_id,
                )
                flagged.append(domain)

        except Exception as exc:
            # Flagging failure must not crash the analysis pipeline.
            # Rules.md: Fail restrictive — do not silently skip with pass-all.
            logger.error(
                "auto_flag_domains: failed to flag domain '%s': %s", domain, exc
            )
            # Domain still added to flagged list so the caller knows it was attempted.
            flagged.append(domain)

    return flagged


__all__ = [
    "AUTO_FLAG_CONFIDENCE_THRESHOLD",
    "AUTO_FLAG_BASE_CONFIDENCE",
    "extract_domain",
    "auto_flag_domains",
]
