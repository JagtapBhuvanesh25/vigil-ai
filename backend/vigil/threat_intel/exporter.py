"""JSON and CSV export for active Threat Intelligence entries.

Phase 5: Safe Browsing Shield — export module.

Supports two formats:
  - JSON: a list of threat intel dicts, wrapped in an export envelope.
  - CSV:  RFC 4180 compliant, with a header row matching ThreatIntelRepository.to_dict keys.

Rules.md: Export includes only is_active=True entries by default to avoid
leaking deactivated (whitelisted) intelligence in bulk dumps.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ── CSV column order ──────────────────────────────────────────────────────────
CSV_COLUMNS: list[str] = [
    "id",
    "url",
    "domain",
    "threat_type",
    "confidence",
    "trigger_count",
    "is_active",
    "flagging_session_id",
    "first_seen",
    "last_triggered",
]


async def export_threat_intel(
    db_session: AsyncSession,
    fmt: str = "json",
    include_inactive: bool = False,
    limit: int = 10_000,
) -> str:
    """Export Threat Intelligence entries to JSON or CSV string.

    Args:
        db_session:       An active async SQLAlchemy session.
        fmt:              Output format — "json" or "csv" (case-insensitive).
        include_inactive: If True, include deactivated entries too. Default False.
        limit:            Maximum entries to export (safety cap). Default 10,000.

    Returns:
        A string containing the full export in the requested format.

    Raises:
        ValueError: If fmt is not "json" or "csv".
    """
    from sqlalchemy import select
    from vigil.db.models import ThreatIntel
    from vigil.db.repositories import ThreatIntelRepository

    fmt = fmt.lower().strip()
    if fmt not in {"json", "csv"}:
        raise ValueError(f"Unsupported export format '{fmt}'. Use 'json' or 'csv'.")

    query = select(ThreatIntel).order_by(ThreatIntel.confidence.desc()).limit(limit)
    if not include_inactive:
        query = query.where(ThreatIntel.is_active.is_(True))

    result = await db_session.execute(query)
    entries = list(result.scalars().all())

    rows = [ThreatIntelRepository.to_dict(e) for e in entries]

    if fmt == "json":
        return _to_json(rows)
    return _to_csv(rows)


def _to_json(rows: list[dict]) -> str:
    """Serialize rows to a JSON string with an export envelope.

    Args:
        rows: List of threat intel dicts from ThreatIntelRepository.to_dict.

    Returns:
        JSON string with envelope: {exported_at, count, entries}.
    """
    envelope = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "entries": rows,
    }
    return json.dumps(envelope, indent=2, default=str)


def _to_csv(rows: list[dict]) -> str:
    """Serialize rows to a CSV string.

    Args:
        rows: List of threat intel dicts from ThreatIntelRepository.to_dict.

    Returns:
        RFC 4180 CSV string with header row matching CSV_COLUMNS.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=CSV_COLUMNS,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


__all__ = ["CSV_COLUMNS", "export_threat_intel"]
