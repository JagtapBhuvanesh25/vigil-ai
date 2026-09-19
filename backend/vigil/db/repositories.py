"""CRUD repository stubs for Vigil AI.

Each repository class wraps database operations for one ORM model.
Phase 1: Stubs only — full implementation in Phase 2 (sessions) and Phase 3 (emails).
Phase 3: EmailRepository fully implemented.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vigil.db.models import AuditLog, Email, Escalation, Session, ThreatIntel


class SessionRepository:
    """CRUD operations for the Session table."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialise with an async database session."""
        self._db = db


class AuditRepository:
    """CRUD operations for the AuditLog table (append-only)."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialise with an async database session."""
        self._db = db


class EmailRepository:
    """CRUD operations for the Email table.

    All methods are async and use the injected AsyncSession.
    Rules.md: Do not store raw email body content — only metadata (message_id,
    risk_score, verdict_json).  The verdict_json field holds a structured dict
    with classification details, NOT the raw email body.
    """

    def __init__(self, db: AsyncSession) -> None:
        """Initialise with an async database session.

        Args:
            db: An active async SQLAlchemy session.
        """
        self._db = db

    async def save(
        self,
        *,
        session_id: str,
        message_id: str,
        subject: str = "",
        sender: str = "",
        classification: str = "pending",
        confidence: float = 0.0,
        verdict_json: dict[str, Any] | None = None,
        risk_score: float = 0.0,
    ) -> Email:
        """Insert a new Email record into the database.

        Args:
            session_id:      Owning containment session UUID.
            message_id:      RFC 2822 Message-ID of the email.
            subject:         Email subject line.
            sender:          Sender display name + address string.
            classification:  Initial classification: pending | safe | suspicious | malicious | honeytoken.
            confidence:      Classifier confidence [0.0, 1.0].
            verdict_json:    Structured verdict dict (NOT raw body). May be None for pending records.
            risk_score:      Risk score at time of classification.

        Returns:
            The persisted Email ORM object (with generated UUID).
        """
        import uuid

        record = Email(
            id=str(uuid.uuid4()),
            session_id=session_id,
            message_id=message_id,
            subject=subject,
            sender=sender,
            classification=classification,
            confidence=confidence,
            verdict_json=json.dumps(verdict_json) if verdict_json is not None else None,
            risk_score=risk_score,
        )
        self._db.add(record)
        await self._db.commit()
        await self._db.refresh(record)
        return record

    async def get(self, email_id: str) -> Email | None:
        """Retrieve a single Email record by its primary key (UUID).

        Args:
            email_id: The Email.id UUID string.

        Returns:
            Email ORM object if found, None otherwise.
        """
        result = await self._db.execute(
            select(Email).where(Email.id == email_id)
        )
        return result.scalar_one_or_none()

    async def get_by_message_id(self, message_id: str) -> Email | None:
        """Retrieve an Email record by RFC 2822 Message-ID.

        Args:
            message_id: The email's Message-ID header value (normalised).

        Returns:
            Email ORM object if found, None otherwise.
        """
        result = await self._db.execute(
            select(Email).where(Email.message_id == message_id)
        )
        return result.scalar_one_or_none()

    async def list_by_session(
        self,
        session_id: str,
        limit: int = 50,
    ) -> list[Email]:
        """Return all emails belonging to a specific session.

        Args:
            session_id: Filter by this session UUID.
            limit:      Maximum number of records to return.

        Returns:
            List of Email ORM objects ordered by created_at descending.
        """
        result = await self._db.execute(
            select(Email)
            .where(Email.session_id == session_id)
            .order_by(Email.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_all(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Email]:
        """Return a paginated list of all email records.

        Args:
            limit:  Maximum number of records to return (default 50).
            offset: Number of records to skip (for pagination).

        Returns:
            List of Email ORM objects ordered by created_at descending.
        """
        result = await self._db.execute(
            select(Email)
            .order_by(Email.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def update_verdict(
        self,
        email_id: str,
        *,
        classification: str,
        confidence: float,
        verdict_json: dict[str, Any],
        risk_score: float,
    ) -> None:
        """Update the classification verdict fields for an existing Email record.

        Called after the email agent pipeline completes.
        Rules.md: verdict_json must contain only metadata — NOT the raw email body.

        Args:
            email_id:       The Email.id UUID to update.
            classification: Final verdict: safe | suspicious | malicious | honeytoken.
            confidence:     Classifier confidence [0.0, 1.0].
            verdict_json:   Structured verdict dict (subject, reasoning, actions_taken, etc.).
            risk_score:     Risk score computed by Algorithm 1 at classification time.
        """
        await self._db.execute(
            update(Email)
            .where(Email.id == email_id)
            .values(
                classification=classification,
                confidence=confidence,
                verdict_json=json.dumps(verdict_json),
                risk_score=risk_score,
            )
        )
        await self._db.commit()

    async def update_classification(
        self,
        email_id: str,
        classification: str,
    ) -> None:
        """Update just the classification state field.

        Lightweight helper for status transitions (e.g., pending → processing).

        Args:
            email_id:       The Email.id UUID to update.
            classification: New classification string.
        """
        await self._db.execute(
            update(Email)
            .where(Email.id == email_id)
            .values(classification=classification)
        )
        await self._db.commit()

    @staticmethod
    def to_dict(record: Email) -> dict[str, Any]:
        """Serialize an Email ORM object to a response-safe dict.

        Rules.md: Raw email body is NOT included — only metadata and verdict.

        Args:
            record: Email ORM object to serialize.

        Returns:
            Dict safe for API responses (no raw body content).
        """
        verdict: dict[str, Any] | None = None
        if record.verdict_json:
            try:
                verdict = json.loads(record.verdict_json)
            except (json.JSONDecodeError, TypeError):
                verdict = None

        return {
            "id": record.id,
            "session_id": record.session_id,
            "message_id": record.message_id,
            "subject": record.subject,
            "sender": record.sender,
            "classification": record.classification,
            "confidence": record.confidence,
            "verdict": verdict,
            "risk_score": record.risk_score,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }


class ThreatIntelRepository:
    """CRUD operations for the ThreatIntel table."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialise with an async database session."""
        self._db = db


class EscalationRepository:
    """CRUD operations for the Escalation table."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialise with an async database session."""
        self._db = db


__all__ = [
    "SessionRepository",
    "AuditRepository",
    "EmailRepository",
    "ThreatIntelRepository",
    "EscalationRepository",
]
