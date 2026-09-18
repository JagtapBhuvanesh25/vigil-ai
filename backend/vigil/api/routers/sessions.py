"""Sessions API router — Phase 2 session management endpoints.

Endpoints:
    POST  /sessions          — Create a new agent containment session
    GET   /sessions          — List all sessions
    GET   /sessions/{id}     — Get session state (risk, tier, events)
    POST  /sessions/{id}/run — (stub) Trigger agent run on a session

Architecture.md § 7:
    POST /sessions → Create new agent session
    GET  /sessions → List all sessions with status
    GET  /sessions/{id} → Get session state (risk, tier, events)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from vigil.core.session.manager import SessionManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sessions", tags=["Sessions"])
_manager = SessionManager()


# ── Request / Response models ──────────────────────────────────────────────────


class CreateSessionRequest(BaseModel):
    """Request body for POST /sessions."""

    agent_type: str = "email"


class SessionResponse(BaseModel):
    """Response schema for a single session."""

    id: str
    status: str
    current_tier: int
    current_risk: float
    agent_type: str
    created_at: str | None = None


class CreateSessionResponse(SessionResponse):
    """Extended response for newly created sessions (includes honeytoken count)."""

    honeytokens_planted: int


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateSessionResponse,
    summary="Create a new containment session",
)
async def create_session(body: CreateSessionRequest) -> dict[str, Any]:
    """Create a new agent containment session.

    Assigns a session ID, generates a per-session salt, plants all
    honeytokens, and persists to the database.  Honeytokens are planted
    BEFORE the endpoint returns — satisfying Rules.md invariant 5.

    Returns:
        Session state including the count of planted honeytokens.
    """
    try:
        state = await _manager.create_session(agent_type=body.agent_type)
    except Exception as exc:
        logger.error("sessions: failed to create session: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create session: {exc}",
        ) from exc

    return {
        "id": state["id"],
        "status": state["status"],
        "current_tier": state["current_tier"],
        "current_risk": state["current_risk"],
        "agent_type": state["agent_type"],
        "created_at": state.get("created_at"),
        "honeytokens_planted": len(state.get("deception_registry", {})),
    }


@router.get(
    "",
    response_model=list[SessionResponse],
    summary="List all containment sessions",
)
async def list_sessions() -> list[dict[str, Any]]:
    """Return a list of recent sessions ordered by created_at desc.

    Returns:
        List of session summaries (id, status, tier, risk, agent_type).
    """
    try:
        return await _manager.list_sessions(limit=100)
    except Exception as exc:
        logger.error("sessions: failed to list sessions: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list sessions: {exc}",
        ) from exc


@router.get(
    "/{session_id}",
    response_model=SessionResponse,
    summary="Get session state",
)
async def get_session(session_id: str) -> dict[str, Any]:
    """Retrieve current state for a specific session.

    Args:
        session_id: UUID of the session.

    Returns:
        Session state dict (risk, tier, status, agent_type).

    Raises:
        404: If the session does not exist.
    """
    try:
        state = await _manager.get_state(session_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    except Exception as exc:
        logger.error("sessions: failed to get session %s: %s", session_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve session: {exc}",
        ) from exc

    return {
        "id": state["id"],
        "status": state["status"],
        "current_tier": state["current_tier"],
        "current_risk": state["current_risk"],
        "agent_type": state["agent_type"],
        "created_at": state.get("created_at"),
    }


@router.post(
    "/{session_id}/run",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Run agent on a session (Phase 3 stub)",
)
async def run_session(session_id: str) -> dict[str, str]:
    """Trigger an agent run on a session.

    Phase 3 stub — returns 202 Accepted.
    Full email agent implementation is Phase 3.

    Args:
        session_id: UUID of the session to run.
    """
    # Validate session exists.
    try:
        await _manager.get_state(session_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )

    return {
        "status": "accepted",
        "session_id": session_id,
        "message": "Agent run accepted — Phase 3 email agent not yet implemented",
    }
