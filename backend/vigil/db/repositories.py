"""CRUD repository stubs for Vigil AI.

Each repository class wraps database operations for one ORM model.
Phase 1: Stubs only — full implementation in Phase 2 (sessions) and Phase 3 (emails).
"""

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
    """CRUD operations for the Email table."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialise with an async database session."""
        self._db = db


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
