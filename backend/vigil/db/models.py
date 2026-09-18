"""SQLAlchemy ORM models for Vigil AI.

Defines all six database tables from Architecture.md:
  - sessions
  - audit_log (hash-chained)
  - emails
  - threat_intel
  - escalations
  - config_versions

Rules.md: Do not break audit_log schema — use Alembic migrations for changes.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all Vigil AI ORM models."""

    pass


class Session(Base):
    """An agent containment session.

    One session per email processing job or browsing task.
    Risk scores, honeytokens, and audit entries are all scoped to this session.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    status: Mapped[str] = mapped_column(
        String(16), default="active"
    )  # active | completed | escalated | terminated
    current_tier: Mapped[int] = mapped_column(Integer, default=0)
    current_risk: Mapped[float] = mapped_column(Float, default=0.0)
    agent_type: Mapped[str] = mapped_column(
        String(32), default="email"
    )  # email | analyzer | browsing
    session_salt: Mapped[str] = mapped_column(
        String(64), default=""
    )  # Per-session random salt for argument hashing

    # Relationships
    audit_entries: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="session", cascade="all, delete-orphan"
    )
    emails: Mapped[list["Email"]] = relationship(
        "Email", back_populates="session", cascade="all, delete-orphan"
    )
    escalations: Mapped[list["Escalation"]] = relationship(
        "Escalation", back_populates="session", cascade="all, delete-orphan"
    )


class AuditLog(Base):
    """Tamper-evident audit log entry (SHA-256 hash-chained).

    Rules.md invariant: Entry must be written and committed BEFORE the
    corresponding tool action executes. Never after.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=False, index=True
    )
    seq_no: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # risk_update | tier_decision | url_precheck | email_classified | escalation_event
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    session: Mapped["Session"] = relationship("Session", back_populates="audit_entries")


class Email(Base):
    """A processed email and its threat classification verdict."""

    __tablename__ = "emails"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=False, index=True
    )
    message_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(512), default="")
    sender: Mapped[str] = mapped_column(String(256), default="")
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    classification: Mapped[str] = mapped_column(
        String(32), default="pending"
    )  # pending | safe | suspicious | malicious | honeytoken
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    verdict_json: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # structured verdict — not raw email body
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    session: Mapped["Session"] = relationship("Session", back_populates="emails")


class ThreatIntel(Base):
    """Threat Intelligence DB entry — a blacklisted URL or domain.

    The Safe Browsing Shield reads this table on every outbound URL request.
    """

    __tablename__ = "threat_intel"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    threat_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # prompt_injection | behavioral_anomaly | honeytoken_interaction | composite
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_triggered: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    trigger_count: Mapped[int] = mapped_column(Integer, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    flagging_session_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=True
    )


class Escalation(Base):
    """Tier 4 escalation record — human approval required.

    Rules.md invariant: Tier 4 blocks ALL agent actions until a human
    operator approves or denies through this record.
    """

    __tablename__ = "escalations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=False, index=True
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resolution: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )  # approved | denied
    context_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    session: Mapped["Session"] = relationship("Session", back_populates="escalations")


class ConfigVersion(Base):
    """Versioned snapshot of the system configuration at a point in time.

    Written when hot-reload is triggered so that audit entries can reference
    the config that was active when a decision was made.
    """

    __tablename__ = "config_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    config_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
