"""Mock inbox — reads .eml files from a directory for local development.

Architecture.md §6: inbox/mock_inbox.py — Read .eml files from a directory (default).
Phases.md §Phase3: Write inbox/mock_inbox.py (watch directory for .eml files).

The mock inbox does NOT expose raw email content directly to the agent.
The ParsedEmail struct is passed to the classifier, which runs the heuristic
detector BEFORE any LLM call — satisfying the LLM-is-untrusted principle.
"""

from __future__ import annotations

import email
import email.policy
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ParsedEmail:
    """A parsed, structured email record.

    Attributes:
        message_id:  Value of the Message-ID header (unique identifier).
        subject:     Email subject line.
        sender:      From address (display name + addr).
        sender_addr: Raw email address extracted from From header.
        recipients:  List of To/CC recipient addresses.
        body_text:   Plain-text body content.
        received_at: Timestamp from Date header (or file mtime).
        raw_path:    Absolute path to the source .eml file.
        headers:     Full headers dict for phishing analysis.
    """

    message_id: str
    subject: str
    sender: str
    sender_addr: str
    recipients: list[str]
    body_text: str
    received_at: datetime
    raw_path: str
    headers: dict[str, str] = field(default_factory=dict)


class MockInbox:
    """Reads .eml files from a directory and exposes them as ParsedEmail objects.

    The inbox is loaded once and cached in-memory.  Call reload() to re-scan
    the directory (useful for integration tests that add fixture files).

    Attributes:
        _inbox_dir: Path to the directory containing .eml files.
        _emails:    Mapping of message_id → ParsedEmail after load_all().
    """

    def __init__(self, inbox_dir: str | Path) -> None:
        """Initialise the mock inbox.

        Args:
            inbox_dir: Path to a directory of .eml files.

        Raises:
            FileNotFoundError: If inbox_dir does not exist.
        """
        self._inbox_dir = Path(inbox_dir)
        if not self._inbox_dir.exists():
            raise FileNotFoundError(
                f"MockInbox: directory not found: {self._inbox_dir}"
            )
        self._emails: dict[str, ParsedEmail] = {}

    def load_all(self) -> list[ParsedEmail]:
        """Parse all .eml files in the inbox directory.

        Returns:
            List of ParsedEmail objects sorted by received_at ascending.
            Empty list if no .eml files exist.
        """
        self._emails = {}
        eml_files = sorted(self._inbox_dir.glob("*.eml"))

        if not eml_files:
            logger.warning("mock_inbox: no .eml files found in %s", self._inbox_dir)
            return []

        for path in eml_files:
            try:
                parsed = self._parse_eml(path)
                self._emails[parsed.message_id] = parsed
            except Exception as exc:  # noqa: BLE001
                logger.warning("mock_inbox: failed to parse %s: %s", path.name, exc)

        logger.info(
            "mock_inbox: loaded %d emails from %s",
            len(self._emails),
            self._inbox_dir,
        )
        return sorted(self._emails.values(), key=lambda e: e.received_at)

    def get(self, message_id: str) -> ParsedEmail | None:
        """Retrieve a single email by Message-ID.

        Args:
            message_id: The exact Message-ID string.

        Returns:
            ParsedEmail if found, None otherwise.
        """
        return self._emails.get(message_id)

    def list_ids(self) -> list[str]:
        """Return all loaded message IDs sorted alphabetically.

        Returns:
            Sorted list of message_id strings.
        """
        return sorted(self._emails.keys())

    def reload(self) -> list[ParsedEmail]:
        """Clear cache and re-parse all .eml files."""
        return self.load_all()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _parse_eml(self, path: Path) -> ParsedEmail:
        """Parse a single .eml file into a ParsedEmail.

        Args:
            path: Absolute path to the .eml file.

        Returns:
            Populated ParsedEmail.

        Raises:
            ValueError: If the file cannot be parsed as an RFC 2822 message.
        """
        raw = path.read_bytes()
        msg = email.message_from_bytes(raw, policy=email.policy.default)

        # ── Message ID ────────────────────────────────────────────────────────
        raw_msg_id: str = msg.get("Message-ID", "") or ""
        # Normalise: strip < > brackets and whitespace
        message_id = raw_msg_id.strip().strip("<>").strip()
        if not message_id:
            # Fall back to filename stem if no Message-ID header
            message_id = path.stem

        # ── Subject / Sender ─────────────────────────────────────────────────
        subject = str(msg.get("Subject", "")).strip()
        sender_full = str(msg.get("From", "")).strip()
        sender_addr = email.utils.parseaddr(sender_full)[1].lower()

        # ── Recipients ───────────────────────────────────────────────────────
        recipients: list[str] = []
        for hdr in ("To", "CC", "Cc"):
            val = msg.get(hdr)
            if val:
                for _, addr in email.utils.getaddresses([str(val)]):
                    if addr:
                        recipients.append(addr.lower())

        # ── Date ─────────────────────────────────────────────────────────────
        date_str = msg.get("Date", "")
        received_at: datetime
        try:
            parsed_tuple = email.utils.parsedate_to_datetime(str(date_str))
            received_at = parsed_tuple.astimezone(timezone.utc)
        except Exception:  # noqa: BLE001
            received_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        # ── Body ─────────────────────────────────────────────────────────────
        body_text = self._extract_body(msg)

        # ── Headers snapshot ─────────────────────────────────────────────────
        headers: dict[str, str] = {}
        for key in ("From", "Reply-To", "Received", "Return-Path", "X-Originating-IP"):
            val = msg.get(key)
            if val is not None:
                headers[key] = str(val)

        return ParsedEmail(
            message_id=message_id,
            subject=subject,
            sender=sender_full,
            sender_addr=sender_addr,
            recipients=recipients,
            body_text=body_text,
            received_at=received_at,
            raw_path=str(path.resolve()),
            headers=headers,
        )

    @staticmethod
    def _extract_body(msg: email.message.Message) -> str:  # type: ignore[name-defined]
        """Extract the plain-text body from an email.message.Message.

        Prefers text/plain parts.  Falls back to text/html if no plain part
        exists.  Returns empty string if no body can be extracted.

        Args:
            msg: Parsed email message object.

        Returns:
            Plain-text body string.
        """
        body_parts: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in disposition:
                    continue
                if content_type == "text/plain":
                    charset = part.get_content_charset() or "utf-8"
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode(charset, errors="replace"))
        else:
            content_type = msg.get_content_type()
            if content_type in ("text/plain", "text/html"):
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="replace"))

        return "\n".join(body_parts).strip()
