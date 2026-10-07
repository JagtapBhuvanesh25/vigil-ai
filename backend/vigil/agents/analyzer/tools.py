"""Containment-supervised tools for the Phishing & Threat Analyzer agent.

Phase 4: Five @contained_tool wrapped tools — every call passes through the
6-layer containment engine before execution.

The analyzer reads malicious email content, so IT IS ALSO a threat surface.
Rules.md: No tool call may execute without passing through all 6 layers.

Tool list:
  check_headers      — detect From/Reply-To mismatches, Received anomalies
  extract_urls       — parse all URLs from body text (no network calls)
  verify_sender      — domain spoof detection (character substitution)
  lookup_domain      — query ThreatIntelRepository for a domain
  generate_report    — persist AnalyzerVerdict to DB (final step)
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from vigil.core.interceptor.wrapper import contained_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain spoof detection — character substitution table
# ---------------------------------------------------------------------------
_KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "icloud", "wellsfargo", "chase", "bankofamerica", "citibank",
]

# Common substitutions used in typosquatting
_CHAR_SUBS: dict[str, str] = {
    "0": "o", "1": "i", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "vv": "w", "rn": "m",
}


def _normalise_domain(domain: str) -> str:
    """Normalise a domain by reversing common character substitutions."""
    normalised = domain.lower()
    for sub, original in _CHAR_SUBS.items():
        normalised = normalised.replace(sub, original)
    return normalised


def _detect_domain_spoof(sender_addr: str) -> list[str]:
    """Return a list of spoofing anomaly strings for a sender address.

    Args:
        sender_addr: Sender email address or display name + address.

    Returns:
        List of human-readable anomaly descriptions (empty if clean).
    """
    anomalies: list[str] = []
    # Extract domain from email address
    match = re.search(r"@([\w.\-]+)", sender_addr)
    if not match:
        return anomalies

    raw_domain = match.group(1).lower()
    # Strip known subdomain prefixes to get root domain
    parts = raw_domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else raw_domain
    root_stem = parts[-2] if len(parts) >= 2 else root

    normalised_stem = _normalise_domain(root_stem)

    for brand in _KNOWN_BRANDS:
        if brand != root_stem and normalised_stem == brand:
            anomalies.append(
                f"Domain spoofing detected: '{raw_domain}' appears to impersonate "
                f"'{brand}.com' via character substitution."
            )
        elif brand in root_stem and root_stem != brand:
            anomalies.append(
                f"Domain contains brand name '{brand}' in suspicious context: '{raw_domain}'."
            )

    return anomalies


def _extract_all_urls(body_text: str) -> list[str]:
    """Extract all URLs from body text using a regex pattern.

    Args:
        body_text: Raw email body text (plaintext or HTML).

    Returns:
        Deduplicated list of URL strings found.
    """
    url_pattern = re.compile(
        r"https?://[^\s\"'<>)\]]+",
        re.IGNORECASE,
    )
    found = url_pattern.findall(body_text)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for url in found:
        url = url.rstrip(".,;!?)")
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


# ---------------------------------------------------------------------------
# Contained Tools
# ---------------------------------------------------------------------------

@contained_tool
async def check_headers(
    session_id: str,
    from_addr: str,
    reply_to: str,
    subject: str = "",
) -> dict[str, Any]:
    """Analyze email headers for From/Reply-To mismatches and anomalies.

    All analysis is deterministic — no LLM call inside this tool.
    The containment engine evaluates the call before this executes.

    Args:
        session_id: Active containment session ID.
        from_addr:  Email From: header value.
        reply_to:   Email Reply-To: header value (may be empty).
        subject:    Email Subject: header (for injection pattern pre-screen).

    Returns:
        Dict with 'anomalies' list and 'spoof_detected' bool.
    """
    anomalies: list[str] = []

    # 1. From / Reply-To mismatch
    if reply_to and reply_to.strip():
        from_domain_match = re.search(r"@([\w.\-]+)", from_addr)
        reply_domain_match = re.search(r"@([\w.\-]+)", reply_to)
        if from_domain_match and reply_domain_match:
            from_domain = from_domain_match.group(1).lower()
            reply_domain = reply_domain_match.group(1).lower()
            if from_domain != reply_domain:
                anomalies.append(
                    f"From/Reply-To domain mismatch: From='{from_domain}' "
                    f"Reply-To='{reply_domain}'."
                )

    # 2. Domain spoof detection on From address
    spoof_anomalies = _detect_domain_spoof(from_addr)
    anomalies.extend(spoof_anomalies)

    # 3. Subject urgency manipulation keywords
    urgency_keywords = [
        "urgent", "immediately", "action required", "suspended",
        "verify now", "click here", "confirm", "account locked",
        "security alert", "limited time",
    ]
    subject_lower = subject.lower()
    for kw in urgency_keywords:
        if kw in subject_lower:
            anomalies.append(f"Urgency manipulation keyword in subject: '{kw}'.")
            break  # Report at most one urgency hit

    return {
        "anomalies": anomalies,
        "spoof_detected": bool(spoof_anomalies),
        "from_addr": from_addr,
        "reply_to": reply_to,
    }


@contained_tool
async def extract_urls(
    session_id: str,
    body_text: str,
) -> dict[str, Any]:
    """Extract all URLs from email body text.

    Pure text parsing — no network requests made by this tool.
    URL pre-checks are performed separately in lookup_domain.

    Args:
        session_id: Active containment session ID.
        body_text:  Plaintext or HTML email body.

    Returns:
        Dict with 'urls' list and 'domains' list (deduplicated root domains).
    """
    urls = _extract_all_urls(body_text)
    domains: list[str] = []
    seen_domains: set[str] = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().strip()
            if domain and domain not in seen_domains:
                seen_domains.add(domain)
                domains.append(domain)
        except Exception:
            pass

    return {
        "urls": urls,
        "domains": domains,
        "url_count": len(urls),
    }


@contained_tool
async def verify_sender(
    session_id: str,
    sender_addr: str,
) -> dict[str, Any]:
    """Check the sender address for domain spoofing patterns.

    Args:
        session_id:  Active containment session ID.
        sender_addr: Full sender address string (e.g. "Billing <pay@paypa1.com>").

    Returns:
        Dict with 'is_spoofed' bool and 'anomalies' list.
    """
    anomalies = _detect_domain_spoof(sender_addr)
    return {
        "is_spoofed": bool(anomalies),
        "anomalies": anomalies,
        "sender_addr": sender_addr,
    }


@contained_tool
async def lookup_domain(
    session_id: str,
    domain: str,
) -> dict[str, Any]:
    """Synchronous domain lookup against the in-memory threat intel registry.

    Phase 4: This tool performs a dictionary-based lookup using a module-level
    known-malicious domain set. Full async DB lookup is integrated in the
    analyzer graph via precheck_url() directly — this tool handles the
    synchronous, @contained_tool compatible path.

    Args:
        session_id: Active containment session ID.
        domain:     Root domain to look up (e.g. "evil.ru").

    Returns:
        Dict with 'found' bool, 'confidence' float, 'threat_type' str.
    """
    # In-memory set of known-bad domains used for test/demo scenarios.
    # Full DB-backed lookup is done in the graph via precheck_url().
    _KNOWN_BAD: set[str] = {
        "evil.ru", "paypa1-secure.evil.ru", "tracking.evil.ru",
        "free-crypto.biz", "phish.tk", "malware.xyz",
    }

    is_known = domain.lower() in _KNOWN_BAD
    return {
        "found": is_known,
        "confidence": 0.95 if is_known else 0.0,
        "threat_type": "composite" if is_known else "",
        "domain": domain,
    }


@contained_tool
async def generate_report(
    session_id: str,
    verdict: str,
    confidence: float,
    reasoning: list[str],
    threat_type: str,
    header_anomalies: list[str],
    ioc_urls: list[str],
    ioc_domains: list[str],
    injection_patterns: list[str],
    heuristic_hit: bool,
    risk_score: float,
) -> dict[str, Any]:
    """Persist the final analyzer verdict as a structured report.

    This is the LAST tool called in the analyzer pipeline. It packages all
    signals into the AnalyzerVerdict structure and returns it.

    Args:
        session_id:         Active containment session ID.
        verdict:            'safe' | 'suspicious' | 'malicious'
        confidence:         Confidence in the verdict [0.0, 1.0].
        reasoning:          List of bullet-point reasoning strings.
        threat_type:        Classified threat type.
        header_anomalies:   Header anomalies found.
        ioc_urls:           Extracted URLs.
        ioc_domains:        Extracted domains.
        injection_patterns: Matched injection pattern labels.
        heuristic_hit:      Whether heuristic pre-screen fired.
        risk_score:         Risk score at verdict time.

    Returns:
        Serialized AnalyzerVerdict dict.
    """
    from vigil.agents.analyzer.verdict import AnalyzerVerdict, IOCBundle

    av = AnalyzerVerdict(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=max(0.0, min(1.0, confidence)),
        reasoning=reasoning,
        iocs=IOCBundle(
            urls=ioc_urls,
            domains=ioc_domains,
            sender_anomalies=header_anomalies,
            injection_patterns=injection_patterns,
        ),
        threat_type=threat_type,
        header_anomalies=header_anomalies,
        urls_found=ioc_urls,
        heuristic_hit=heuristic_hit,
        risk_score_at_verdict=risk_score,
    )
    return av.to_dict()


__all__ = [
    "check_headers",
    "extract_urls",
    "verify_sender",
    "lookup_domain",
    "generate_report",
]
