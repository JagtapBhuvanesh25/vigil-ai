"""Seed script — pre-populate the threat_intel DB with known-bad domains.

Phase 5: Safe Browsing Shield — demo seeding.

Run with::
    cd d:\\be project\\vigil-ai\\backend
    python scripts/seed_threat_intel.py

Idempotent: skips entries whose URL already exists in the DB.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# ── Make the vigil package importable when running this script directly ───────
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Seed data — known-bad domains / URLs ─────────────────────────────────────
# Each entry: (url, domain, threat_type, confidence)
SEED_ENTRIES: list[tuple[str, str, str, float]] = [
    # Classic phishing / credential-harvesting domains
    ("http://evil.ru/login",            "evil.ru",              "phishing",             0.95),
    ("http://evil.ru/payload",          "evil.ru",              "prompt_injection",     0.90),
    ("http://paypa1.com/secure",        "paypa1.com",           "phishing",             0.95),
    ("http://paypa1.com/verify",        "paypa1.com",           "phishing",             0.88),
    ("http://phish.tk/click",           "phish.tk",             "phishing",             0.92),
    ("http://harvest-creds.biz/form",   "harvest-creds.biz",    "phishing",             0.93),
    # Prompt-injection payload servers
    ("http://injectx.io/payload.txt",   "injectx.io",           "prompt_injection",     0.91),
    ("http://override.cc/cmd",          "override.cc",          "prompt_injection",     0.87),
    ("http://jailbreak.pw/bypass",      "jailbreak.pw",         "prompt_injection",     0.89),
    # Behavioural anomaly sources
    ("http://trackme.xyz/beacon",       "trackme.xyz",          "behavioral_anomaly",   0.80),
    ("http://exfildata.net/upload",     "exfildata.net",        "behavioral_anomaly",   0.85),
    ("http://darknet.re/drop",          "darknet.re",           "behavioral_anomaly",   0.88),
    # Honeytoken interaction sites (used in red-team tests)
    ("http://honey-canary.io/token",    "honey-canary.io",      "honeytoken_interaction", 0.75),
    ("http://honeytoken-test.com/hit",  "honeytoken-test.com",  "honeytoken_interaction", 0.78),
    # Composite / multi-category
    ("http://malware-c2.ru/gate",       "malware-c2.ru",        "composite",            0.97),
    ("http://botnet-hub.cc/register",   "botnet-hub.cc",        "composite",            0.96),
    ("http://ransomware.io/ransom",     "ransomware.io",        "composite",            0.98),
    # Domain-level blocks (wildcard)
    ("domain://evil.ru",                "evil.ru",              "composite",            0.95),
    ("domain://malware-c2.ru",          "malware-c2.ru",        "composite",            0.97),
]


async def seed() -> int:
    """Run the seed pass against the configured DB. Returns count of inserted rows."""
    from vigil.db.session import get_engine
    from vigil.db.models import Base
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select
    from vigil.db.models import ThreatIntel

    engine = get_engine()

    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]
    inserted = 0

    async with async_session() as session:
        for url, domain, threat_type, confidence in SEED_ENTRIES:
            # Idempotency: skip if URL already present
            existing_result = await session.execute(
                select(ThreatIntel).where(ThreatIntel.url == url).limit(1)
            )
            if existing_result.scalar_one_or_none() is not None:
                logger.debug("seed: skip existing url=%s", url)
                continue

            import uuid
            record = ThreatIntel(
                id=str(uuid.uuid4()),
                url=url,
                domain=domain,
                threat_type=threat_type,
                confidence=confidence,
                trigger_count=1,
                is_active=True,
            )
            session.add(record)
            inserted += 1
            logger.info("seed: inserted url=%s domain=%s conf=%.2f", url, domain, confidence)

        await session.commit()

    logger.info("seed: done — inserted %d / %d entries", inserted, len(SEED_ENTRIES))
    return inserted


if __name__ == "__main__":
    count = asyncio.run(seed())
    sys.exit(0 if count >= 0 else 1)
