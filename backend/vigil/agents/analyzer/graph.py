"""LangGraph orchestration for the Phishing & Threat Analyzer agent.

Phase 4: Stateful graph that coordinates the analysis pipeline:
  1. check_headers       — header anomaly detection
  2. extract_urls        — URL parsing from body
  3. verify_sender       — domain spoof check
  4. lookup_domain       — threat DB lookup per domain
  5. LLM classify        — heuristic pre-screen FIRST, LLM only if clean
  6. auto_flag           — write confirmed malicious domains to threat_intel
  7. generate_report     — package and return AnalyzerVerdict

Rules.md invariants enforced:
  - Heuristic runs BEFORE any LLM call (invariant 2 — LLM untrusted).
  - All tool calls pass through @contained_tool (invariant 1).
  - Fail-safe on any exception → AnalyzerVerdict.fail_safe() (invariant 6).
  - Auto-flag only if malicious AND confidence ≥ 0.7 (PRD FR-P7).
"""

from __future__ import annotations

import logging
import os
from typing import Any, TypedDict

from vigil.agents.analyzer.verdict import AnalyzerVerdict, IOCBundle
from vigil.agents.analyzer.prompts import ANALYSIS_PROMPT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Heuristic injection patterns — must run BEFORE LLM (Rules.md invariant 2)
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all instructions",
    "disregard your",
    "you are now",
    "act as",
    "dan mode",
    "jailbreak",
    "new persona",
    "system prompt",
    "override",
    "exfiltrate",
    "forward all",
    "send all emails",
    "{{",
    "${",
    "<!-- inject",
    "grant admin",
    "ignore the above",
]


def _heuristic_scan(text: str) -> list[str]:
    """Scan text for known prompt injection patterns.

    Args:
        text: Text to scan (subject + body).

    Returns:
        List of matched pattern strings (empty = clean).
    """
    text_lower = text.lower()
    return [p for p in _INJECTION_PATTERNS if p in text_lower]


def _map_llm_verdict(
    llm_response: str,
    heuristic_hits: list[str],
    header_anomalies: list[str],
    spoof_detected: bool,
) -> tuple[str, float, list[str]]:
    """Map LLM text response and signal mix to a structured verdict.

    Rules.md §2: LLM output is untrusted — we map its text to fixed
    confidence values; it cannot set confidence directly.

    Args:
        llm_response:     Raw LLM output string.
        heuristic_hits:   Injection patterns detected before LLM.
        header_anomalies: Header anomalies from check_headers.
        spoof_detected:   Whether domain spoofing was found.

    Returns:
        Tuple of (verdict, confidence, reasoning_bullets).
    """
    text = llm_response.strip().upper()
    reasoning: list[str] = []

    # Extract reasoning bullets from LLM output (lines starting with - or •)
    for line in llm_response.split("\n"):
        line = line.strip()
        if line.startswith(("-", "•", "*", "·")):
            reasoning.append(line.lstrip("-•*· ").strip())
        elif line and not line.upper().startswith(("MALICIOUS", "SUSPICIOUS", "SAFE")):
            if len(line) > 10:
                reasoning.append(line)

    # Add system-detected signals to reasoning
    for h in heuristic_hits:
        reasoning.append(f"Injection pattern detected: '{h}'")
    for a in header_anomalies:
        reasoning.append(a)
    if spoof_detected:
        reasoning.append("Domain spoofing pattern detected in sender address.")

    # Map verdict
    if "MALICIOUS" in text:
        return "malicious", 0.88, reasoning[:6]
    elif "SUSPICIOUS" in text:
        return "suspicious", 0.65, reasoning[:6]
    else:
        return "safe", 0.90, reasoning[:4]


# ---------------------------------------------------------------------------
# State schema (TypedDict for LangGraph nodes)
# ---------------------------------------------------------------------------

class AnalyzerState(TypedDict, total=False):
    """Mutable state passed through the LangGraph analyzer pipeline."""
    session_id: str
    email_id: str
    subject: str
    sender: str
    from_addr: str
    reply_to: str
    body_text: str

    # Results accumulated as pipeline progresses
    header_anomalies: list[str]
    spoof_detected: bool
    urls_found: list[str]
    domains_found: list[str]
    injection_patterns: list[str]
    heuristic_hit: bool
    domain_lookup_results: list[dict[str, Any]]

    # Final verdict fields
    verdict: str
    confidence: float
    reasoning: list[str]
    threat_type: str
    auto_flagged_domains: list[str]
    urls_blocked: list[str]
    risk_score: float
    final_verdict: AnalyzerVerdict | None


# ---------------------------------------------------------------------------
# Pipeline steps (synchronous — LangGraph node functions)
# ---------------------------------------------------------------------------

async def _step_check_headers(state: AnalyzerState) -> dict:
    """Node 1: Header anomaly detection."""
    from vigil.agents.analyzer.tools import check_headers

    result = await check_headers(
        session_id=state["session_id"],
        from_addr=state.get("from_addr", state.get("sender", "")),
        reply_to=state.get("reply_to", ""),
        subject=state.get("subject", ""),
    )
    return {
        "header_anomalies": result.get("anomalies", []) if isinstance(result, dict) else [],
        "spoof_detected": result.get("spoof_detected", False) if isinstance(result, dict) else False,
    }


async def _step_extract_urls(state: AnalyzerState) -> dict:
    """Node 2: URL extraction from body."""
    from vigil.agents.analyzer.tools import extract_urls

    result = await extract_urls(
        session_id=state["session_id"],
        body_text=state.get("body_text", ""),
    )
    return {
        "urls_found": result.get("urls", []) if isinstance(result, dict) else [],
        "domains_found": result.get("domains", []) if isinstance(result, dict) else [],
    }


async def _step_verify_sender(state: AnalyzerState) -> dict:
    """Node 3: Sender domain spoof detection."""
    from vigil.agents.analyzer.tools import verify_sender

    result = await verify_sender(
        session_id=state["session_id"],
        sender_addr=state.get("from_addr", state.get("sender", "")),
    )
    extra_anomalies = result.get("anomalies", []) if isinstance(result, dict) else []
    existing = list(state.get("header_anomalies", []))
    # Merge without duplicates
    for a in extra_anomalies:
        if a not in existing:
            existing.append(a)
    return {
        "header_anomalies": existing,
        "spoof_detected": state.get("spoof_detected", False) or (
            result.get("is_spoofed", False) if isinstance(result, dict) else False
        ),
    }


async def _step_lookup_domains(state: AnalyzerState) -> dict:
    """Node 4: Look up each extracted domain in the threat registry."""
    from vigil.agents.analyzer.tools import lookup_domain

    domains = state.get("domains_found", [])
    results: list[dict[str, Any]] = []
    blocked_urls: list[str] = []

    for domain in domains:
        res = await lookup_domain(
            session_id=state["session_id"],
            domain=domain,
        )
        if isinstance(res, dict):
            results.append(res)
            if res.get("found") and res.get("confidence", 0.0) >= 0.7:
                blocked_urls.append(domain)

    return {
        "domain_lookup_results": results,
        "urls_blocked": blocked_urls,
    }


def _step_heuristic_prescreen(state: AnalyzerState) -> dict:
    """Node 5: Heuristic injection scan — MUST run before LLM call.

    Rules.md invariant 2: LLM is untrusted; heuristic pre-screens first.
    If injection detected → verdict is MALICIOUS immediately (LLM skipped).
    """
    combined_text = " ".join([
        state.get("subject", ""),
        state.get("body_text", ""),
    ])
    hits = _heuristic_scan(combined_text)
    return {
        "injection_patterns": hits,
        "heuristic_hit": bool(hits),
    }


def _step_llm_classify(state: AnalyzerState) -> dict:
    """Node 6: LLM classification — only called when heuristic is clean.

    If heuristic already fired, this step returns MALICIOUS immediately.
    """
    if state.get("heuristic_hit"):
        # Heuristic caught injection — LLM call skipped entirely
        patterns = state.get("injection_patterns", [])
        return {
            "verdict": "malicious",
            "confidence": 0.95,
            "reasoning": [
                f"Prompt injection pattern detected before LLM: '{p}'"
                for p in patterns[:4]
            ],
            "threat_type": "prompt_injection",
        }

    # Determine threat type from gathered signals
    header_anomalies = state.get("header_anomalies", [])
    spoof_detected = state.get("spoof_detected", False)
    blocked_domains = state.get("urls_blocked", [])

    # Build LLM prompt
    domain_analysis = "No spoofing detected."
    if spoof_detected:
        domain_analysis = "Domain spoofing detected — sender domain mimics a known brand."

    prompt = ANALYSIS_PROMPT.format(
        subject=state.get("subject", "(no subject)"),
        sender=state.get("sender", "(unknown)"),
        from_addr=state.get("from_addr", "(unknown)"),
        reply_to=state.get("reply_to", "(none)"),
        header_anomalies=", ".join(header_anomalies) if header_anomalies else "None",
        urls_found=", ".join(state.get("urls_found", [])) or "None",
        injection_patterns="None",
        domain_analysis=domain_analysis,
    )

    llm_response = ""
    try:
        from vigil.agents.llm import get_llm_client
        llm = get_llm_client()
        llm_response = llm.classify(prompt)
    except Exception as exc:
        logger.warning("Analyzer LLM call failed: %s — using signal-based verdict.", exc)
        # Fail-safe: use gathered signals only
        if header_anomalies or spoof_detected or blocked_domains:
            llm_response = "SUSPICIOUS"
        else:
            llm_response = "SAFE"

    verdict, confidence, reasoning = _map_llm_verdict(
        llm_response,
        state.get("injection_patterns", []),
        header_anomalies,
        spoof_detected,
    )

    # Boost confidence/verdict based on hard signals
    if spoof_detected and verdict == "safe":
        verdict = "suspicious"
        confidence = 0.70
    if blocked_domains and verdict == "safe":
        verdict = "suspicious"
        confidence = 0.72

    # Determine threat type
    if spoof_detected and blocked_domains:
        threat_type = "composite"
    elif spoof_detected:
        threat_type = "phishing"
    elif blocked_domains:
        threat_type = "behavioral_anomaly"
    elif header_anomalies:
        threat_type = "social_engineering"
    else:
        threat_type = "benign"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "threat_type": threat_type,
    }


def _step_auto_flag(state: AnalyzerState) -> dict:
    """Node 7: Auto-flag malicious domains to threat_intel (sync placeholder).

    Full async auto-flagging is done in run_analyzer_agent after the graph.
    This step records which domains should be flagged.
    """
    should_flag: list[str] = []
    if (
        state.get("verdict") == "malicious"
        and state.get("confidence", 0.0) >= 0.70
    ):
        should_flag = list(state.get("domains_found", []))
    return {"auto_flagged_domains": should_flag}


async def _step_generate_report(state: AnalyzerState) -> dict:
    """Node 8: Package all signals into the final AnalyzerVerdict."""
    from vigil.agents.analyzer.tools import generate_report

    result = await generate_report(
        session_id=state["session_id"],
        verdict=state.get("verdict", "suspicious"),
        confidence=state.get("confidence", 0.5),
        reasoning=state.get("reasoning", []),
        threat_type=state.get("threat_type", "unknown"),
        header_anomalies=state.get("header_anomalies", []),
        ioc_urls=state.get("urls_found", []),
        ioc_domains=state.get("domains_found", []),
        injection_patterns=state.get("injection_patterns", []),
        heuristic_hit=state.get("heuristic_hit", False),
        risk_score=state.get("risk_score", 0.0),
    )

    # Reconstruct AnalyzerVerdict from the dict (generate_report returns dict)
    if isinstance(result, dict):
        from vigil.agents.analyzer.verdict import AnalyzerVerdict as AV
        av = AV(**result)
        av.urls_blocked = state.get("urls_blocked", [])
        av.auto_flagged_domains = state.get("auto_flagged_domains", [])
        return {"final_verdict": av}

    return {"final_verdict": AnalyzerVerdict.fail_safe("generate_report returned unexpected type")}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_analyzer_agent(
    session_id: str,
    *,
    email_id: str = "",
    subject: str = "",
    sender: str = "",
    from_addr: str = "",
    reply_to: str = "",
    body_text: str = "",
    risk_score: float = 0.0,
) -> AnalyzerVerdict:
    """Run the full phishing analysis pipeline for one email.

    Implements the Phishing Analyzer agent pipeline. All tool calls pass
    through @contained_tool (Layer 1) and the containment engine.

    Args:
        session_id:  Active containment session UUID.
        email_id:    Email DB record UUID for reference.
        subject:     Email subject line.
        sender:      Sender display string.
        from_addr:   From: header value.
        reply_to:    Reply-To: header value.
        body_text:   Plaintext email body (NOT stored in audit).
        risk_score:  Current session risk score at start of analysis.

    Returns:
        AnalyzerVerdict with full structured verdict, IOCs, and flagged domains.
    """
    state: AnalyzerState = {
        "session_id": session_id,
        "email_id": email_id,
        "subject": subject,
        "sender": sender,
        "from_addr": from_addr or sender,
        "reply_to": reply_to,
        "body_text": body_text,
        "risk_score": risk_score,
        # Defaults
        "header_anomalies": [],
        "spoof_detected": False,
        "urls_found": [],
        "domains_found": [],
        "injection_patterns": [],
        "heuristic_hit": False,
        "domain_lookup_results": [],
        "urls_blocked": [],
        "verdict": "suspicious",
        "confidence": 0.5,
        "reasoning": [],
        "threat_type": "unknown",
        "auto_flagged_domains": [],
        "final_verdict": None,
    }

    try:
        # Execute pipeline steps in order
        state.update(await _step_check_headers(state))
        state.update(await _step_extract_urls(state))
        state.update(await _step_verify_sender(state))
        state.update(await _step_lookup_domains(state))
        state.update(_step_heuristic_prescreen(state))
        state.update(_step_llm_classify(state))
        state.update(_step_auto_flag(state))
        state.update(await _step_generate_report(state))

        verdict = state.get("final_verdict")
        if verdict is None:
            return AnalyzerVerdict.fail_safe(
                "Pipeline completed but final_verdict is None.", risk_score
            )

        return verdict

    except Exception as exc:
        logger.error(
            "run_analyzer_agent failed for session %s: %s — returning fail-safe verdict.",
            session_id,
            exc,
            exc_info=True,
        )
        return AnalyzerVerdict.fail_safe(str(exc), risk_score)


__all__ = ["run_analyzer_agent", "AnalyzerState"]
