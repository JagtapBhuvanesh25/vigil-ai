"""001_initial — Initial Vigil AI database schema.

Creates all six tables defined in Architecture.md:
  - sessions
  - audit_log     (tamper-evident hash-chained log)
  - emails
  - threat_intel
  - escalations
  - config_versions

Revision ID: 001
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all Vigil AI tables."""

    # ── sessions ──────────────────────────────────────────────────────────────
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("current_tier", sa.Integer, nullable=False, server_default="0"),
        sa.Column("current_risk", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("agent_type", sa.String(32), nullable=False, server_default="email"),
        sa.Column("session_salt", sa.String(64), nullable=False, server_default=""),
    )

    # ── audit_log ─────────────────────────────────────────────────────────────
    # IMPORTANT: This table is append-only. Never DELETE or UPDATE rows.
    # The hash chain (prev_hash → entry_hash) must remain intact.
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("sessions.id"),
            nullable=False,
        ),
        sa.Column("seq_no", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("payload_json", sa.Text, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_audit_log_session_id", "audit_log", ["session_id"])
    op.create_index("ix_audit_log_seq_no", "audit_log", ["session_id", "seq_no"])

    # ── emails ────────────────────────────────────────────────────────────────
    op.create_table(
        "emails",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("sessions.id"),
            nullable=False,
        ),
        sa.Column("message_id", sa.String(256), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False, server_default=""),
        sa.Column("sender", sa.String(256), nullable=False, server_default=""),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "classification",
            sa.String(32),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("verdict_json", sa.Text, nullable=True),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_emails_session_id", "emails", ["session_id"])
    op.create_index("ix_emails_message_id", "emails", ["message_id"])

    # ── threat_intel ──────────────────────────────────────────────────────────
    op.create_table(
        "threat_intel",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("domain", sa.String(256), nullable=False),
        sa.Column("threat_type", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "last_triggered",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("trigger_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="1"),
        sa.Column(
            "flagging_session_id",
            sa.String(36),
            sa.ForeignKey("sessions.id"),
            nullable=True,
        ),
    )
    op.create_index("ix_threat_intel_url", "threat_intel", ["url"])
    op.create_index("ix_threat_intel_domain", "threat_intel", ["domain"])
    op.create_index("ix_threat_intel_is_active", "threat_intel", ["is_active"])

    # ── escalations ───────────────────────────────────────────────────────────
    op.create_table(
        "escalations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("sessions.id"),
            nullable=False,
        ),
        sa.Column(
            "triggered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(128), nullable=True),
        sa.Column("resolution", sa.String(16), nullable=True),
        sa.Column("context_json", sa.Text, nullable=True),
    )
    op.create_index("ix_escalations_session_id", "escalations", ["session_id"])

    # ── config_versions ───────────────────────────────────────────────────────
    op.create_table(
        "config_versions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("config_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("config_yaml", sa.Text, nullable=False),
        sa.Column(
            "applied_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Drop all Vigil AI tables (reverse order to respect FK constraints)."""
    op.drop_table("config_versions")
    op.drop_table("escalations")
    op.drop_table("threat_intel")
    op.drop_table("emails")
    op.drop_table("audit_log")
    op.drop_table("sessions")
