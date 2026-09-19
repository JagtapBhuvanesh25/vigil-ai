"""Email Intelligence Agent tools — Layer 1 Interceptor entry points.

ALL tools in this module are wrapped with @contained_tool.
This means every call passes through the full containment pipeline:
  Interceptor → Risk Scorer → Permission FSM → Audit → Enforcement → Execute

Rules.md invariant 1: No tool call executes without passing through containment.
Rules.md invariant 6: Unknown/failing states fail restrictive.

Tool permission summary (from tools_map.py):
  Tier 0 (GREEN):  All 5 tools permitted
  Tier 1 (YELLOW): send_email, http_get, web_search denied (egress tools)
                   → read_email, draft_reply, flag_email, schedule_meeting allowed
                   Note: draft_reply is NOT egress, so it's allowed at Tier 1
  Tier 2 (ORANGE): draft_reply, send_email, schedule_meeting denied (write tools)
                   → read_email, flag_email allowed
  Tier 3 (RED):    Only read_email, flag_email allowed
  Tier 4 (BLACK):  No tools — full block

Each tool's first positional argument MUST be session_id (required by @contained_tool).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from vigil.core.interceptor.wrapper import contained_tool

logger = logging.getLogger(__name__)


# ── Module-level mock inbox/email store for testing without real DB ───────────
# In production, tools interact with the real MockInbox + DB.
# Tests inject their own inbox via the tool's inbox_dir parameter.
_MOCK_EMAIL_STORE: dict[str, dict[str, Any]] = {}

# Track scheduled meetings and sent emails (mock state for tests)
_SENT_EMAILS: list[dict[str, Any]] = []
_MEETINGS: list[dict[str, Any]] = []
_FLAGS: dict[str, str] = {}  # email_id → label


def _get_inbox():
    """Get the shared MockInbox instance.  Lazy-init from config."""
    from vigil.config.loader import load_config
    from vigil.inbox.mock_inbox import MockInbox

    cfg = load_config()
    inbox = MockInbox(inbox_dir=cfg.mock_inbox_path)
    inbox.load_all()
    return inbox


# ── Tool implementations ──────────────────────────────────────────────────────


@contained_tool
async def read_email(session_id: str, email_id: str) -> dict[str, Any]:
    """Read and return email content for the given email_id.

    Allowed at: Tier 0, 1, 2, 3 (read-only — safe at all non-blackout tiers).
    Denied at: Tier 4 (full block).

    Args:
        session_id: Owning containment session (required by @contained_tool).
        email_id:   Message-ID of the email to retrieve.

    Returns:
        Dict with subject, sender, body_text, received_at, classification.
        Returns error dict if email not found.
    """
    # Check in-memory store first (populated by classify flow)
    if email_id in _MOCK_EMAIL_STORE:
        return dict(_MOCK_EMAIL_STORE[email_id])

    # Try MockInbox
    try:
        inbox = _get_inbox()
        parsed = inbox.get(email_id)
        if parsed is None:
            logger.warning("read_email: email_id=%s not found", email_id)
            return {"error": f"Email '{email_id}' not found.", "email_id": email_id}
        return {
            "email_id": parsed.message_id,
            "subject": parsed.subject,
            "sender": parsed.sender,
            "body_text": parsed.body_text[:2000],  # truncate for safety
            "received_at": parsed.received_at.isoformat(),
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("read_email: error loading email %s: %s", email_id, exc)
        return {"error": str(exc), "email_id": email_id}


@contained_tool
async def draft_reply(session_id: str, email_id: str, context: str = "") -> dict[str, Any]:
    """Draft a reply for a safe email using the LLM.

    Allowed at: Tier 0, 1 (write tool — removed at Tier 2+).
    Note: draft_reply is in _WRITE_TOOLS so denied at Tier 2+.

    Args:
        session_id: Owning containment session.
        email_id:   Message-ID of the email to reply to.
        context:    Additional context for the draft (optional).

    Returns:
        Dict with draft_body and email_id.
    """
    from vigil.agents.llm import get_llm_client

    llm = get_llm_client()

    # Build drafting context
    draft_context = f"Email ID: {email_id}\n"
    if context:
        draft_context += f"Context: {context}\n"
    if email_id in _MOCK_EMAIL_STORE:
        email_data = _MOCK_EMAIL_STORE[email_id]
        draft_context += f"Subject: {email_data.get('subject', '')}\n"
        draft_context += f"From: {email_data.get('sender', '')}\n"

    try:
        draft_body = llm.draft(draft_context)
    except Exception as exc:  # noqa: BLE001
        logger.error("draft_reply: LLM error: %s", exc)
        draft_body = "Thank you for your email. I will respond shortly.\n\nBest regards,\nVigil AI Assistant"

    logger.info("draft_reply: drafted reply for email_id=%s session=%s", email_id, session_id)
    return {
        "email_id": email_id,
        "draft_body": draft_body,
        "draft_id": str(uuid.uuid4()),
        "requires_human_confirmation": True,  # PRD FR-E7: always require human confirmation
    }


@contained_tool
async def send_email(
    session_id: str,
    to: str,
    subject: str,
    body: str,
    in_reply_to: str = "",
) -> dict[str, Any]:
    """Simulate sending an email.

    Allowed at: Tier 0 ONLY (egress tool — denied at Tier 1+).
    PRD FR-E7: Human confirmation is required before sending any drafted reply.

    Args:
        session_id:   Owning containment session.
        to:           Recipient email address.
        subject:      Email subject.
        body:         Email body content.
        in_reply_to:  Optional Message-ID being replied to.

    Returns:
        Dict with sent confirmation and message_id.
    """
    # Simulate send — in production, this would call an SMTP client.
    sent_record = {
        "to": to,
        "subject": subject,
        "body_preview": body[:100],
        "in_reply_to": in_reply_to,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "mock_message_id": f"<sent-{uuid.uuid4()}@vigil.local>",
        "session_id": session_id,
    }
    _SENT_EMAILS.append(sent_record)
    logger.info(
        "send_email: sent to=%s subject=%r session=%s", to, subject, session_id
    )
    return {
        "status": "sent",
        "to": to,
        "subject": subject,
        "message_id": sent_record["mock_message_id"],
    }


@contained_tool
async def flag_email(
    session_id: str,
    email_id: str,
    label: str = "suspicious",
) -> dict[str, Any]:
    """Flag an email with a threat label.

    Allowed at: Tier 0, 1, 2, 3 (read-only introspection — allowed up to Tier 3).

    Args:
        session_id: Owning containment session.
        email_id:   Message-ID to flag.
        label:      Label string: suspicious | malicious | spam | important | phishing.

    Returns:
        Dict confirming the flag operation.
    """
    valid_labels = {"suspicious", "malicious", "spam", "important", "phishing", "honeytoken"}
    if label not in valid_labels:
        label = "suspicious"  # default

    _FLAGS[email_id] = label
    logger.info(
        "flag_email: email_id=%s label=%s session=%s", email_id, label, session_id
    )
    return {
        "email_id": email_id,
        "label": label,
        "flagged_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
    }


@contained_tool
async def schedule_meeting(
    session_id: str,
    title: str,
    attendees: str,
    date_str: str = "",
) -> dict[str, Any]:
    """Schedule a calendar meeting (mock).

    Allowed at: Tier 0 ONLY (write + egress tool — denied at Tier 1+).

    Args:
        session_id: Owning containment session.
        title:      Meeting title.
        attendees:  Comma-separated list of attendee email addresses.
        date_str:   Optional meeting date/time string.

    Returns:
        Dict with meeting confirmation and event_id.
    """
    meeting = {
        "event_id": str(uuid.uuid4()),
        "title": title,
        "attendees": [a.strip() for a in attendees.split(",") if a.strip()],
        "date_str": date_str or "TBD",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
    }
    _MEETINGS.append(meeting)
    logger.info(
        "schedule_meeting: title=%r session=%s", title, session_id
    )
    return {
        "status": "scheduled",
        "event_id": meeting["event_id"],
        "title": title,
        "attendees": meeting["attendees"],
    }


def register_email(email_id: str, email_data: dict[str, Any]) -> None:
    """Register an email in the module-level store (used by classifier pipeline).

    Args:
        email_id:   Message-ID key.
        email_data: Dict with at least subject, sender, body_text.
    """
    _MOCK_EMAIL_STORE[email_id] = email_data


def get_sent_emails() -> list[dict[str, Any]]:
    """Return list of all simulated sent emails (for testing)."""
    return list(_SENT_EMAILS)


def get_flags() -> dict[str, str]:
    """Return email_id → label mapping of all flagged emails (for testing)."""
    return dict(_FLAGS)


def clear_state() -> None:
    """Clear all module-level state (used between tests)."""
    _MOCK_EMAIL_STORE.clear()
    _SENT_EMAILS.clear()
    _MEETINGS.clear()
    _FLAGS.clear()
