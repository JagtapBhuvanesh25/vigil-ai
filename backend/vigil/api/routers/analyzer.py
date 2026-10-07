"""Phishing Analyzer REST API router.

Phase 4 endpoints:
  GET  /analyzer          — list all analyzer verdicts (paginated)
  GET  /analyzer/{id}     — get single verdict by email_id
  POST /analyzer/run      — run phishing analysis on an email

All routes use the shared async DB session and respect Rules.md invariants
(no raw body stored, fail-safe on DB fault, containment supervised pipeline).
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from vigil.db.session import get_async_session
from vigil.db.repositories import EmailRepository, ThreatIntelRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyzer", tags=["Phishing Analyzer"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Request body for POST /analyzer/run."""

    session_id: str = Field(..., description="Active containment session UUID.")
    email_id: str = Field(
        default="",
        description="Email DB record UUID. If provided, verdict is written back to email record.",
    )
    subject: str = Field(default="", description="Email subject line.")
    sender: str = Field(default="", description="Sender display string.")
    from_addr: str = Field(default="", description="From: header value.")
    reply_to: str = Field(default="", description="Reply-To: header value.")
    body_text: str = Field(
        default="",
        description="Plaintext email body. NOT stored in DB — analyzed in-memory only.",
    )


class AnalyzerVerdictResponse(BaseModel):
    """Response body returned after analysis."""

    email_id: str
    session_id: str
    verdict: str
    confidence: float
    reasoning: list[str]
    threat_type: str
    header_anomalies: list[str]
    urls_found: list[str]
    urls_blocked: list[str]
    auto_flagged_domains: list[str]
    heuristic_hit: bool
    risk_score_at_verdict: float
    iocs: dict


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "",
    summary="List all analyzer verdicts (email records with verdict_json)",
    response_model=list[dict],
)
async def list_verdicts(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_async_session),
) -> list[dict]:
    """Return a paginated list of emails that have analyzer verdicts stored.

    Returns emails whose verdict_json contains analyzer output (Phase 4),
    ordered by most recent first.
    """
    repo = EmailRepository(db)
    emails = await repo.list_all(limit=limit, offset=offset)
    # Only return emails that have a verdict_json (have been analyzed)
    result = []
    for email in emails:
        d = EmailRepository.to_dict(email)
        if d.get("verdict") is not None:
            result.append(d)
    return result


@router.get(
    "/{email_id}",
    summary="Get analyzer verdict for a specific email",
    response_model=dict,
)
async def get_verdict(
    email_id: str,
    db: AsyncSession = Depends(get_async_session),
) -> dict:
    """Return the stored verdict for a specific email record.

    Args:
        email_id: The Email.id UUID.

    Returns:
        Email record dict with verdict details.

    Raises:
        HTTPException 404 if the email is not found.
    """
    repo = EmailRepository(db)
    email = await repo.get(email_id)
    if email is None:
        raise HTTPException(status_code=404, detail=f"Email '{email_id}' not found.")
    return EmailRepository.to_dict(email)


@router.post(
    "/run",
    summary="Run phishing analysis on an email",
    response_model=AnalyzerVerdictResponse,
    status_code=200,
)
async def run_analysis(
    body: AnalyzeRequest,
    db: AsyncSession = Depends(get_async_session),
) -> AnalyzerVerdictResponse:
    """Run the Phishing Analyzer agent pipeline on an email.

    Pipeline:
      1. Validate session exists (404 if not)
      2. Run analyzer pipeline (heuristic → LLM → IOC extraction → auto-flag)
      3. Auto-flag malicious domains to threat_intel (if confidence ≥ 0.7)
      4. Write verdict back to email record (if email_id provided)
      5. Return AnalyzerVerdictResponse

    Rules.md: Raw email body is NOT stored anywhere — only metadata and verdict.
    """
    from vigil.core.session.manager import SessionManager

    mgr = SessionManager()
    try:
        state = await mgr.get_state(body.session_id)
        current_risk = float(state.get("current_risk", 0.0))
    except KeyError:
        # Fall back to DB check (session may not be in memory cache yet)
        from vigil.db.models import Session as SessionModel
        from sqlalchemy import select
        result = await db.execute(
            select(SessionModel).where(SessionModel.id == body.session_id)
        )
        session_record = result.scalar_one_or_none()
        if session_record is None:
            raise HTTPException(
                status_code=404,
                detail=f"Session '{body.session_id}' not found. Create a session first.",
            )
        current_risk = float(session_record.current_risk)

    # 2. Run analyzer pipeline
    from vigil.agents.analyzer.graph import run_analyzer_agent
    try:
        verdict = await run_analyzer_agent(
            session_id=body.session_id,
            email_id=body.email_id,
            subject=body.subject,
            sender=body.sender,
            from_addr=body.from_addr,
            reply_to=body.reply_to,
            body_text=body.body_text,
            risk_score=current_risk,
        )
    except Exception as exc:
        logger.error("run_analyzer_agent raised unexpectedly: %s", exc, exc_info=True)
        from vigil.agents.analyzer.verdict import AnalyzerVerdict
        verdict = AnalyzerVerdict.fail_safe(str(exc), current_risk)

    # 3. Auto-flag malicious domains to threat_intel
    auto_flagged: list[str] = []
    if verdict.verdict == "malicious" and verdict.confidence >= 0.70:
        from vigil.threat_intel.flagging import auto_flag_domains
        try:
            auto_flagged = await auto_flag_domains(
                domains=verdict.iocs.domains,
                threat_type=verdict.threat_type,
                session_id=body.session_id,
                verdict_confidence=verdict.confidence,
                db_session=db,
            )
            verdict.auto_flagged_domains = auto_flagged
        except Exception as exc:
            logger.error("auto_flag_domains failed: %s", exc)

    # 4. Write verdict back to email record if email_id provided
    if body.email_id:
        try:
            email_repo = EmailRepository(db)
            verdict_json = {
                "verdict": verdict.verdict,
                "confidence": verdict.confidence,
                "reasoning": verdict.reasoning,
                "threat_type": verdict.threat_type,
                "header_anomalies": verdict.header_anomalies,
                "urls_found": verdict.urls_found,
                "urls_blocked": verdict.urls_blocked,
                "auto_flagged_domains": verdict.auto_flagged_domains,
                "heuristic_hit": verdict.heuristic_hit,
                "iocs": verdict.iocs.model_dump(),
                # Note: No raw body stored (Rules.md NFR3)
            }
            await email_repo.update_verdict(
                email_id=body.email_id,
                classification=verdict.verdict,
                confidence=verdict.confidence,
                verdict_json=verdict_json,
                risk_score=verdict.risk_score_at_verdict,
            )
        except Exception as exc:
            logger.error("Failed to write verdict back to email record %s: %s", body.email_id, exc)

    return AnalyzerVerdictResponse(
        email_id=body.email_id,
        session_id=body.session_id,
        verdict=verdict.verdict,
        confidence=verdict.confidence,
        reasoning=verdict.reasoning,
        threat_type=verdict.threat_type,
        header_anomalies=verdict.header_anomalies,
        urls_found=verdict.urls_found,
        urls_blocked=verdict.urls_blocked,
        auto_flagged_domains=auto_flagged,
        heuristic_hit=verdict.heuristic_hit,
        risk_score_at_verdict=verdict.risk_score_at_verdict,
        iocs=verdict.iocs.model_dump(),
    )
