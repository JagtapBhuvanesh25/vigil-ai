"""Session Manager — lifecycle and state management for agent sessions.

Each Vigil AI containment session has:
  - A unique ID and per-session salt.
  - A mutable risk score and permission tier.
  - A honeytoken registry (planted BEFORE the first tool call).
  - A crash-safe checkpoint record in the DB.

Rules.md invariants:
  - Honeytokens must be planted before the first tool call (enforced here).
  - Per-session salt must be generated at creation and survive restarts.
  - Session state is isolated — no cross-session contamination.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from vigil.core.deception.registry import HoneytokenRegistry
from vigil.core.interceptor.hashing import generate_session_salt

logger = logging.getLogger(__name__)

# In-memory registry of active sessions.
# In a multi-process deployment, this would be backed by Redis or the DB.
# For Phase 2 (single-process), the in-memory store is sufficient.
_active_sessions: dict[str, dict[str, Any]] = {}


class SessionManager:
    """Manages the lifecycle and state of agent containment sessions.

    Provides CRUD operations for session state and enforces that honeytokens
    are planted before any tool call can execute.

    Attributes:
        None (uses shared module-level _active_sessions dict + DB).
    """

    async def create_session(
        self,
        agent_type: str = "email",
    ) -> dict[str, Any]:
        """Create a new agent containment session.

        Sequence:
          1. Generate session ID and per-session salt.
          2. Plant honeytokens (required before first tool call).
          3. Persist to DB.
          4. Cache in memory.

        Args:
            agent_type: Type of agent running ('email', 'analyzer', 'browsing').

        Returns:
            Dict containing the new session state.
        """
        session_id = str(uuid.uuid4())
        salt = generate_session_salt()

        # Plant honeytokens (Rules.md: before first tool call).
        registry = HoneytokenRegistry(session_id=session_id)
        deception_registry = registry.plant()

        state: dict[str, Any] = {
            "id": session_id,
            "session_salt": salt,
            "current_risk": 0.0,
            "current_tier": 0,
            "status": "active",
            "agent_type": agent_type,
            "deception_registry": deception_registry,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Persist to DB.
        try:
            await self._persist_session(session_id=session_id, state=state)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "session: DB persist failed for new session %s: %s", session_id, exc
            )
            raise

        # Cache in memory.
        _active_sessions[session_id] = state

        logger.info(
            "session: created session=%s agent=%s honeytokens=%d",
            session_id,
            agent_type,
            len(deception_registry),
        )
        return state

    async def get_state(self, session_id: str) -> dict[str, Any]:
        """Retrieve the current state for a session.

        First checks the in-memory cache, then falls back to DB.

        Args:
            session_id: Session to retrieve.

        Returns:
            Session state dict.

        Raises:
            KeyError: If the session does not exist.
        """
        if session_id in _active_sessions:
            return _active_sessions[session_id]

        # Attempt DB recovery.
        state = await self._load_from_db(session_id)
        if state is None:
            raise KeyError(f"Session {session_id} not found")

        _active_sessions[session_id] = state
        return state

    async def update_risk_and_tier(
        self,
        session_id: str,
        risk: float,
        tier: int,
    ) -> None:
        """Update the risk score and tier for an active session.

        Args:
            session_id: Session to update.
            risk:       New risk score Rt.
            tier:       New permission tier.
        """
        if session_id not in _active_sessions:
            await self.get_state(session_id)  # Load from DB.

        _active_sessions[session_id]["current_risk"] = risk
        _active_sessions[session_id]["current_tier"] = tier

        # Async DB update (best-effort — in-memory is source of truth for speed).
        try:
            await self._update_db_state(session_id=session_id, risk=risk, tier=tier)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "session: DB update failed for session=%s: %s (in-memory still current)",
                session_id,
                exc,
            )

    async def terminate_session(self, session_id: str) -> None:
        """Mark a session as completed and evict from memory.

        Args:
            session_id: Session to terminate.
        """
        if session_id in _active_sessions:
            _active_sessions[session_id]["status"] = "completed"
        try:
            await self._mark_completed_in_db(session_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("session: failed to mark completed in DB: %s", exc)
        _active_sessions.pop(session_id, None)
        logger.info("session: terminated session=%s", session_id)

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _persist_session(self, session_id: str, state: dict[str, Any]) -> None:
        """Write a new session record to the DB."""
        from vigil.db.session import get_async_session
        from vigil.db.models import Session as SessionModel

        async with get_async_session() as db:
            record = SessionModel(
                id=session_id,
                status=state["status"],
                current_tier=state["current_tier"],
                current_risk=state["current_risk"],
                agent_type=state["agent_type"],
                session_salt=state["session_salt"],
            )
            db.add(record)
            await db.commit()

    async def _load_from_db(self, session_id: str) -> dict[str, Any] | None:
        """Load session state from the DB."""
        from vigil.db.session import get_async_session
        from vigil.db.models import Session as SessionModel
        from sqlalchemy import select

        async with get_async_session() as db:
            result = await db.execute(
                select(SessionModel).where(SessionModel.id == session_id)
            )
            record = result.scalar_one_or_none()
            if record is None:
                return None
            return {
                "id": record.id,
                "session_salt": record.session_salt,
                "current_risk": record.current_risk,
                "current_tier": record.current_tier,
                "status": record.status,
                "agent_type": record.agent_type,
                "deception_registry": {},  # Reloaded from checkpoint separately.
                "created_at": record.created_at.isoformat() if record.created_at else None,
            }

    async def _update_db_state(
        self, session_id: str, risk: float, tier: int
    ) -> None:
        """Update risk/tier in the DB."""
        from vigil.db.session import get_async_session
        from vigil.db.models import Session as SessionModel
        from sqlalchemy import update

        async with get_async_session() as db:
            await db.execute(
                update(SessionModel)
                .where(SessionModel.id == session_id)
                .values(current_risk=risk, current_tier=tier)
            )
            await db.commit()

    async def _mark_completed_in_db(self, session_id: str) -> None:
        """Mark session status as 'completed' in the DB."""
        from vigil.db.session import get_async_session
        from vigil.db.models import Session as SessionModel
        from sqlalchemy import update

        async with get_async_session() as db:
            await db.execute(
                update(SessionModel)
                .where(SessionModel.id == session_id)
                .values(status="completed")
            )
            await db.commit()

    async def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return a list of recent sessions from the DB.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of session state dicts ordered by created_at desc.
        """
        from vigil.db.session import get_async_session
        from vigil.db.models import Session as SessionModel
        from sqlalchemy import select

        async with get_async_session() as db:
            result = await db.execute(
                select(SessionModel)
                .order_by(SessionModel.created_at.desc())
                .limit(limit)
            )
            records = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "status": r.status,
                    "current_tier": r.current_tier,
                    "current_risk": r.current_risk,
                    "agent_type": r.agent_type,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in records
            ]
