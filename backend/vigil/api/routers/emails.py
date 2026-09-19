"""Emails API router — Phase 3 Email Intelligence Agent endpoints.

Endpoints:
    GET  /emails                — List processed emails (paginated, optional session filter)
    GET  /emails/{email_id}     — Get a single email record with verdict
    POST /emails/analyze        — Analyze an email through the containment-supervised agent

Architecture.md § 7:
    POST /emails/analyze → Run agent pipeline, persist verdict, return classification.

Rules.md invariants:
    - LLM output is an untrusted signal: the containment system computes verdicts.
    - Every tool call passes through containment (@contained_tool).
    - verdict_json must NOT contain raw email body — metadata only.
    - Fail-safe: any exception resolves to HTTP 500 (never passes unclassified).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from vigil.db.repositories import EmailRepository
from vigil.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/emails", tags=["Emails"])


# ── Request / Response models ──────────────────────────────────────────────────


class AnalyzeEmailRequest(BaseModel):
    """Request body for POST /emails/analyze."""

    session_id: str
    email_id: str
    subject: str = ""
    sender: str = ""
    body_text: str = ""


class VerdictSchema(BaseModel):
    """Structured classification verdict embedded in EmailResponse."""

    verdict: str
    confidence: float
    reasoning: str
    heuristic_hit: bool = False
    draft_body: str | None = None
    actions_taken: list[str] = []


class EmailResponse(BaseModel):
    """Response schema for a single email record."""

    id: str
    session_id: str
    message_id: str
    subject: str
    sender: str
    classification: str
    confidence: float
    verdict: dict[str, Any] | None = None
    risk_score: float
    created_at: str | None = None


class AnalyzeEmailResponse(BaseModel):
    """Response for POST /emails/analyze."""

    email_db_id: str
    session_id: str
    email_id: str
    classification: str
    confidence: float
    reasoning: str
    heuristic_hit: bool
    draft_body: str | None
    actions_taken: list[str]
    risk_score: float


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=list[EmailResponse],
    summary="List analyzed emails",
)
async def list_emails(
    session_id: str | None = Query(default=None, description="Filter by session UUID"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Return a paginated list of analyzed email records.

    Optionally filter by session_id.  Results are ordered by created_at desc.

    Args:
        session_id: Optional UUID to filter by owning session.
        limit:      Maximum number of records (1–200, default 50).
        offset:     Number of records to skip (for pagination).

    Returns:
        List of email summary dicts (no raw body content).
    """
    repo = EmailRepository(db)
    try:
        if session_id:
            records = await repo.list_by_session(session_id=session_id, limit=limit)
        else:
            records = await repo.list_all(limit=limit, offset=offset)
    except Exception as exc:
        logger.error("emails: list failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list emails: {exc}",
        ) from exc

    return [EmailRepository.to_dict(r) for r in records]


@router.get(
    "/{email_id}",
    response_model=EmailResponse,
    summary="Get a single email record",
)
async def get_email(
    email_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve a single email record by its UUID (Email.id).

    Args:
        email_id: The Email.id UUID string.

    Returns:
        Email metadata and verdict (no raw body).

    Raises:
        404: If the email does not exist.
    """
    repo = EmailRepository(db)
    try:
        record = await repo.get(email_id)
    except Exception as exc:
        logger.error("emails: get failed for id=%s: %s", email_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve email: {exc}",
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email {email_id} not found",
        )

    return EmailRepository.to_dict(record)


@router.post(
    "/analyze",
    status_code=status.HTTP_200_OK,
    response_model=AnalyzeEmailResponse,
    summary="Analyze an email through the containment-supervised agent",
)
async def analyze_email(
    body: AnalyzeEmailRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run the Email Intelligence Agent pipeline on a provided email.

    Pipeline:
      1. Validate session exists (containment must be active).
      2. Persist email record as 'pending' in DB.
      3. Run `run_email_agent()` — classify → act → done (all tools contained).
      4. Update the DB record with the final verdict.
      5. Return the classification result.

    Rules.md:
      - All tool calls inside run_email_agent() pass through @contained_tool.
      - LLM output is an untrusted signal: verdict mapped by classifier, not LLM.
      - verdict_json stored in DB must NOT contain raw email body.
      - Any exception → HTTP 500 (fail-safe: never silently pass).

    Args:
        body: {session_id, email_id, subject, sender, body_text}

    Returns:
        Classification result including verdict, confidence, draft_body, actions_taken.

    Raises:
        404: If the session does not exist.
        500: On any containment or agent error (fail-safe).
    """
    from vigil.agents.email.graph import run_email_agent
    from vigil.core.session.manager import SessionManager

    session_manager = SessionManager()

    # 1. Validate session exists and retrieve honeytoken.
    try:
        session_state = await session_manager.get_state(body.session_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {body.session_id} not found. Create a session first.",
        )
    except Exception as exc:
        logger.error("emails: analyze — session lookup failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Session lookup failed: {exc}",
        ) from exc

    # Retrieve email honeytoken from session (planted at session creation).
    deception_registry: dict[str, str] = session_state.get("deception_registry", {})
    email_honeytoken: str | None = None
    for token_value, token_type in deception_registry.items():
        if token_type == "email":
            email_honeytoken = token_value
            break

    repo = EmailRepository(db)

    # 2. Save 'pending' record (fail-fast if DB is unavailable).
    try:
        email_record = await repo.save(
            session_id=body.session_id,
            message_id=body.email_id,
            subject=body.subject,
            sender=body.sender,
            classification="pending",
            confidence=0.0,
            verdict_json=None,
            risk_score=0.0,
        )
    except Exception as exc:
        logger.error("emails: failed to save pending record: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create email record: {exc}",
        ) from exc

    # 3. Run the containment-supervised email agent pipeline.
    try:
        result = await run_email_agent(
            session_id=body.session_id,
            email_id=body.email_id,
            subject=body.subject,
            sender=body.sender,
            body_text=body.body_text,
            email_honeytoken=email_honeytoken,
        )
    except Exception as exc:
        logger.error(
            "emails: agent pipeline failed for session=%s email=%s: %s",
            body.session_id,
            body.email_id,
            exc,
        )
        # Fail-safe: mark as suspicious, do not pass silently.
        result = {
            "verdict": "suspicious",
            "confidence": 0.5,
            "reasoning": f"Agent pipeline error: {exc}. Fail-safe: treating as Suspicious.",
            "heuristic_hit": False,
            "draft_body": None,
            "actions_taken": [],
        }

    # Extract fields from result.
    classification = result.get("verdict", "suspicious")
    confidence = float(result.get("confidence", 0.5))
    reasoning = result.get("reasoning", "")
    heuristic_hit = bool(result.get("heuristic_hit", False))
    draft_body = result.get("draft_body")
    actions_taken = result.get("actions_taken", [])

    # Retrieve current session risk score (set by Algorithm 1 during tool calls).
    try:
        updated_state = await session_manager.get_state(body.session_id)
        risk_score = float(updated_state.get("current_risk", 0.0))
    except Exception:  # noqa: BLE001
        risk_score = 0.0

    # 4. Build verdict_json — metadata ONLY (no raw body per Rules.md).
    verdict_json: dict[str, Any] = {
        "verdict": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "heuristic_hit": heuristic_hit,
        "actions_taken": actions_taken,
        # Include subject for display but NOT body_text (raw content excluded).
        "subject": body.subject,
        "sender": body.sender,
    }

    # Persist final verdict to DB.
    try:
        await repo.update_verdict(
            email_record.id,
            classification=classification,
            confidence=confidence,
            verdict_json=verdict_json,
            risk_score=risk_score,
        )
    except Exception as exc:
        # Non-fatal: we still return the result even if DB update fails.
        logger.error("emails: verdict update failed (non-fatal): %s", exc)

    logger.info(
        "emails: analyzed session=%s email=%s verdict=%s confidence=%.2f",
        body.session_id,
        body.email_id,
        classification,
        confidence,
    )

    return {
        "email_db_id": email_record.id,
        "session_id": body.session_id,
        "email_id": body.email_id,
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "heuristic_hit": heuristic_hit,
        "draft_body": draft_body,
        "actions_taken": actions_taken,
        "risk_score": risk_score,
    }
