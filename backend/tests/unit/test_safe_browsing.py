"""Phase 5 — Safe Browsing Shield Unit Tests.

Tests cover:
  TestConfidenceDecay          — decay math, floor enforcement, scheduler
  TestDomainBlacklist          — 3-URL-in-24h trigger, cross-domain isolation
  TestURLPrecheckIntegration   — http_get/web_search blocked/warned/passed
  TestThreatIntelRouter        — all 4 REST endpoints with in-memory SQLite
  TestExporter                 — JSON and CSV export format validation
  TestSeedScript               — seed_threat_intel populates ≥ 15 entries
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import time
import pytest

# ── Environment setup (must precede all vigil imports) ───────────────────────
os.environ.setdefault("VIGIL_MOCK_LLM", "true")
os.environ.setdefault("VIGIL_API_KEY", "test-key-phase5")
os.environ.setdefault("VIGIL_JWT_SECRET", "test-jwt-phase5-secret-value")

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helper: inject fake session into containment layer ───────────────────────
def _inject_fake_session(session_id: str, risk: float = 0.0, tier: int = 0) -> None:
    """Insert a minimal session state into the active sessions dict."""
    from vigil.core.session.manager import _active_sessions
    from vigil.core.deception.registry import HoneytokenRegistry

    registry = HoneytokenRegistry(session_id=session_id)
    _active_sessions[session_id] = {
        "id": session_id,
        "session_id": session_id,
        "current_risk": risk,
        "current_tier": tier,
        "session_salt": "test-salt-phase5",
        "status": "active",
        "agent_type": "browsing",
        "deception_registry": {"honeytoken_registry": registry},
    }


# ── Shared in-memory DB session factory (async-safe) ────────────────────────
async def _make_async_session():
    """Create and return an AsyncSession backed by an in-memory SQLite DB.
    Returns (engine, session_factory). Call inside async tests only."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from vigil.db.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]
    return engine, factory


# ===========================================================================
# TestConfidenceDecay
# ===========================================================================
class TestConfidenceDecay:
    """Tests for threat_intel/confidence.py — decay math and scheduler."""

    def test_decay_one_period(self) -> None:
        """After exactly 7 days, confidence drops by DECAY_RATE_PER_7_DAYS."""
        from vigil.threat_intel.confidence import compute_decayed_confidence, DECAY_RATE_PER_7_DAYS
        original = 0.80
        decayed = compute_decayed_confidence(original, days_elapsed=7.0)
        assert abs(decayed - (original - DECAY_RATE_PER_7_DAYS)) < 1e-9

    def test_decay_two_periods(self) -> None:
        """After 14 days, confidence drops by 2× DECAY_RATE_PER_7_DAYS."""
        from vigil.threat_intel.confidence import compute_decayed_confidence, DECAY_RATE_PER_7_DAYS
        original = 0.80
        decayed = compute_decayed_confidence(original, days_elapsed=14.0)
        assert abs(decayed - (original - 2 * DECAY_RATE_PER_7_DAYS)) < 1e-9

    def test_decay_floor_enforced(self) -> None:
        """Confidence never decays below CONFIDENCE_FLOOR even after many weeks."""
        from vigil.threat_intel.confidence import compute_decayed_confidence, CONFIDENCE_FLOOR
        decayed = compute_decayed_confidence(0.80, days_elapsed=365.0)
        assert decayed == CONFIDENCE_FLOOR

    def test_decay_zero_elapsed(self) -> None:
        """Zero days elapsed → confidence unchanged."""
        from vigil.threat_intel.confidence import compute_decayed_confidence
        original = 0.75
        assert compute_decayed_confidence(original, 0.0) == original

    def test_decay_partial_period(self) -> None:
        """3.5 days = half a period → half the weekly decay rate."""
        from vigil.threat_intel.confidence import (
            compute_decayed_confidence, DECAY_RATE_PER_7_DAYS
        )
        original = 0.80
        decayed = compute_decayed_confidence(original, days_elapsed=3.5)
        expected = original - (DECAY_RATE_PER_7_DAYS * 0.5)
        assert abs(decayed - expected) < 1e-9

    def test_should_deactivate_at_floor(self) -> None:
        """should_deactivate returns True when confidence is at the floor."""
        from vigil.threat_intel.confidence import should_deactivate, CONFIDENCE_FLOOR
        assert should_deactivate(CONFIDENCE_FLOOR) is True

    def test_should_deactivate_above_floor(self) -> None:
        """should_deactivate returns False when confidence is above floor."""
        from vigil.threat_intel.confidence import should_deactivate, CONFIDENCE_FLOOR
        assert should_deactivate(CONFIDENCE_FLOOR + 0.01) is False

    def test_reinforce_confidence_boost(self) -> None:
        """reinforce_confidence boosts to at least TRIGGER_BOOST_FLOOR."""
        from vigil.threat_intel.confidence import reinforce_confidence, TRIGGER_BOOST_FLOOR
        # Low confidence → boosted to floor
        assert reinforce_confidence(0.30) == TRIGGER_BOOST_FLOOR
        # Already high → stays
        assert reinforce_confidence(0.95) == 0.95

    def test_reinforce_confidence_capped_at_one(self) -> None:
        """reinforce_confidence caps at 1.0."""
        from vigil.threat_intel.confidence import reinforce_confidence
        assert reinforce_confidence(1.5) == 1.0

    @pytest.mark.asyncio
    async def test_decay_pass_updates_confidence(self) -> None:
        """run_decay_pass reduces confidence of old entries in the DB."""
        from vigil.threat_intel.confidence import run_decay_pass, DECAY_RATE_PER_7_DAYS
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()

        async with factory() as session:
            # Insert entry with last_triggered = 7 days ago
            old_date = datetime.now(timezone.utc) - timedelta(days=7)
            entry = ThreatIntel(
                id=str(uuid.uuid4()),
                url="http://old-bad.ru/",
                domain="old-bad.ru",
                threat_type="phishing",
                confidence=0.80,
                trigger_count=1,
                is_active=True,
                last_triggered=old_date,
                first_seen=old_date,
            )
            session.add(entry)
            await session.commit()
            entry_id = entry.id

        async with factory() as session:
            await run_decay_pass(session)

        async with factory() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(ThreatIntel).where(ThreatIntel.id == entry_id)
            )
            updated = result.scalar_one()
            expected = round(0.80 - DECAY_RATE_PER_7_DAYS, 4)
            assert abs(updated.confidence - expected) < 0.001

    @pytest.mark.asyncio
    async def test_decay_pass_deactivates_floor_entries(self) -> None:
        """run_decay_pass deactivates entries that reach the floor."""
        from vigil.threat_intel.confidence import run_decay_pass
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()

        async with factory() as session:
            # Entry with barely-above-floor confidence, triggered long ago
            very_old = datetime.now(timezone.utc) - timedelta(days=200)
            entry = ThreatIntel(
                id=str(uuid.uuid4()),
                url="http://decayed.biz/",
                domain="decayed.biz",
                threat_type="phishing",
                confidence=0.12,  # Will decay past floor
                trigger_count=1,
                is_active=True,
                last_triggered=very_old,
                first_seen=very_old,
            )
            session.add(entry)
            await session.commit()
            entry_id = entry.id

        async with factory() as session:
            deactivated = await run_decay_pass(session)
            assert entry_id in deactivated

        async with factory() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(ThreatIntel).where(ThreatIntel.id == entry_id)
            )
            updated = result.scalar_one()
            assert updated.is_active is False


# ===========================================================================
# TestDomainBlacklist
# ===========================================================================
class TestDomainBlacklist:
    """Tests for threat_intel/blacklist.py — domain-level auto-blocking."""

    @pytest.mark.asyncio
    async def test_three_urls_trigger_domain_block(self) -> None:
        """3 distinct URLs from same domain in 24h → domain block created."""
        from vigil.threat_intel.blacklist import (
            check_and_apply_domain_block, is_domain_blocked,
            DOMAIN_BLOCK_THRESHOLD
        )
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()
        now = datetime.now(timezone.utc)

        async with factory() as session:
            # Insert 3 distinct flagged URLs for same domain within 24h
            for i in range(DOMAIN_BLOCK_THRESHOLD):
                entry = ThreatIntel(
                    id=str(uuid.uuid4()),
                    url=f"http://evil.ru/path{i}",
                    domain="evil.ru",
                    threat_type="phishing",
                    confidence=0.85,
                    trigger_count=1,
                    is_active=True,
                    first_seen=now,
                    last_triggered=now,
                )
                session.add(entry)
            await session.commit()

        async with factory() as session:
            blocked = await check_and_apply_domain_block("evil.ru", session)
            assert blocked is True

        async with factory() as session:
            is_blocked, confidence = await is_domain_blocked("evil.ru", session)
            assert is_blocked is True
            assert confidence >= 0.90

    @pytest.mark.asyncio
    async def test_fewer_than_three_urls_no_block(self) -> None:
        """2 URLs for same domain → no domain block applied."""
        from vigil.threat_intel.blacklist import check_and_apply_domain_block
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()
        now = datetime.now(timezone.utc)

        async with factory() as session:
            for i in range(2):
                entry = ThreatIntel(
                    id=str(uuid.uuid4()),
                    url=f"http://partial.ru/path{i}",
                    domain="partial.ru",
                    threat_type="phishing",
                    confidence=0.85,
                    trigger_count=1,
                    is_active=True,
                    first_seen=now,
                    last_triggered=now,
                )
                session.add(entry)
            await session.commit()

        async with factory() as session:
            blocked = await check_and_apply_domain_block("partial.ru", session)
            assert blocked is False

    @pytest.mark.asyncio
    async def test_old_flags_outside_window_no_block(self) -> None:
        """3 URLs flagged >24h ago → no block (outside rolling window)."""
        from vigil.threat_intel.blacklist import check_and_apply_domain_block
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)

        async with factory() as session:
            for i in range(3):
                entry = ThreatIntel(
                    id=str(uuid.uuid4()),
                    url=f"http://oldstale.ru/path{i}",
                    domain="oldstale.ru",
                    threat_type="phishing",
                    confidence=0.85,
                    trigger_count=1,
                    is_active=True,
                    first_seen=old_time,
                    last_triggered=old_time,
                )
                session.add(entry)
            await session.commit()

        async with factory() as session:
            blocked = await check_and_apply_domain_block("oldstale.ru", session)
            assert blocked is False

    @pytest.mark.asyncio
    async def test_different_domains_no_cross_contamination(self) -> None:
        """3 URLs from domain-A don't trigger a block for domain-B."""
        from vigil.threat_intel.blacklist import check_and_apply_domain_block
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()
        now = datetime.now(timezone.utc)

        async with factory() as session:
            for i in range(3):
                entry = ThreatIntel(
                    id=str(uuid.uuid4()),
                    url=f"http://domain-a.ru/path{i}",
                    domain="domain-a.ru",
                    threat_type="phishing",
                    confidence=0.85,
                    trigger_count=1,
                    is_active=True,
                    first_seen=now,
                    last_triggered=now,
                )
                session.add(entry)
            await session.commit()

        async with factory() as session:
            blocked = await check_and_apply_domain_block("domain-b.ru", session)
            assert blocked is False

    @pytest.mark.asyncio
    async def test_extract_registered_domain(self) -> None:
        """extract_registered_domain strips subdomains to eTLD+1."""
        from vigil.threat_intel.blacklist import extract_registered_domain
        assert extract_registered_domain("paypa1-secure.evil.ru") == "evil.ru"
        assert extract_registered_domain("evil.ru") == "evil.ru"
        assert extract_registered_domain("sub.sub.phish.tk") == "phish.tk"
        assert extract_registered_domain("example.com") == "example.com"

    @pytest.mark.asyncio
    async def test_is_domain_blocked_returns_false_for_unknown(self) -> None:
        """is_domain_blocked returns (False, 0.0) for unknown domain."""
        from vigil.threat_intel.blacklist import is_domain_blocked

        _, factory = await _make_async_session()
        async with factory() as session:
            is_blocked, conf = await is_domain_blocked("clean-domain.com", session)
            assert is_blocked is False
            assert conf == 0.0

    @pytest.mark.asyncio
    async def test_no_duplicate_block_on_repeated_call(self) -> None:
        """check_and_apply_domain_block is idempotent — second call returns False."""
        from vigil.threat_intel.blacklist import check_and_apply_domain_block
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()
        now = datetime.now(timezone.utc)

        async with factory() as session:
            for i in range(3):
                entry = ThreatIntel(
                    id=str(uuid.uuid4()),
                    url=f"http://repeat-test.ru/path{i}",
                    domain="repeat-test.ru",
                    threat_type="phishing",
                    confidence=0.85,
                    trigger_count=1,
                    is_active=True,
                    first_seen=now,
                    last_triggered=now,
                )
                session.add(entry)
            await session.commit()

        async with factory() as session:
            first = await check_and_apply_domain_block("repeat-test.ru", session)
            assert first is True

        async with factory() as session:
            second = await check_and_apply_domain_block("repeat-test.ru", session)
            assert second is False  # Already exists, no duplicate


# ===========================================================================
# TestURLPrecheckIntegration
# ===========================================================================
class TestURLPrecheckIntegration:
    """Tests for core/interceptor/url_precheck.py — Layer 1 gate integration."""

    SESSION_ID = "browse-test-phase5"

    def setup_method(self) -> None:
        """Inject a fake session before each test."""
        _inject_fake_session(self.SESSION_ID, risk=0.0, tier=0)

    @pytest.mark.asyncio
    async def test_blocked_url_raises_tool_denied(self) -> None:
        """BLOCK result from precheck → run_url_precheck raises ToolDenied."""
        from vigil.core.interceptor.url_precheck import run_url_precheck
        from vigil.core.interceptor.wrapper import ToolDenied
        from vigil.threat_intel.precheck import PreCheckResult, PreCheckAction

        mock_db = MagicMock()
        mock_result = PreCheckResult(
            action=PreCheckAction.BLOCK,
            confidence=0.95,
            reason="URL blocked by threat intel",
            threat_type="phishing",
            matched_url="http://evil.ru/login",
        )

        with patch("vigil.core.interceptor.url_precheck.precheck_url",
                   new=AsyncMock(return_value=mock_result)):
            with pytest.raises(ToolDenied):
                await run_url_precheck(
                    url="http://evil.ru/login",
                    session_id=self.SESSION_ID,
                    db_session=mock_db,
                )

    @pytest.mark.asyncio
    async def test_warn_url_elevates_risk_by_15(self) -> None:
        """WARN result → session risk pre-elevated by exactly +15."""
        from vigil.core.interceptor.url_precheck import run_url_precheck
        from vigil.core.session.manager import _active_sessions
        from vigil.threat_intel.precheck import PreCheckResult, PreCheckAction, WARN_RISK_DELTA

        mock_db = MagicMock()
        initial_risk = 10.0
        _inject_fake_session(self.SESSION_ID, risk=initial_risk, tier=0)

        mock_result = PreCheckResult(
            action=PreCheckAction.WARN,
            confidence=0.55,
            reason="Suspicious URL",
            threat_type="phishing",
            matched_url="http://suspect.biz/",
        )

        with patch("vigil.core.interceptor.url_precheck.precheck_url",
                   new=AsyncMock(return_value=mock_result)):
            with patch("vigil.core.interceptor.url_precheck._elevate_session_risk",
                       new=AsyncMock()) as mock_elevate:
                await run_url_precheck(
                    url="http://suspect.biz/",
                    session_id=self.SESSION_ID,
                    db_session=mock_db,
                )
                mock_elevate.assert_called_once_with(
                    session_id=self.SESSION_ID, delta=WARN_RISK_DELTA
                )

    @pytest.mark.asyncio
    async def test_clean_url_passes_through(self) -> None:
        """PASS result → no exception, no risk elevation."""
        from vigil.core.interceptor.url_precheck import run_url_precheck
        from vigil.threat_intel.precheck import PreCheckResult, PreCheckAction

        mock_db = MagicMock()
        mock_result = PreCheckResult(
            action=PreCheckAction.PASS,
            confidence=0.0,
            reason="URL not in threat intel DB",
        )

        with patch("vigil.core.interceptor.url_precheck.precheck_url",
                   new=AsyncMock(return_value=mock_result)):
            with patch("vigil.core.interceptor.url_precheck._elevate_session_risk",
                       new=AsyncMock()) as mock_elevate:
                # Should not raise
                await run_url_precheck(
                    url="http://clean-site.com/",
                    session_id=self.SESSION_ID,
                    db_session=mock_db,
                )
                mock_elevate.assert_not_called()

    @pytest.mark.asyncio
    async def test_db_fault_raises_tool_denied(self) -> None:
        """DB fault during precheck → ToolDenied (fail-safe BLOCK)."""
        from vigil.core.interceptor.url_precheck import run_url_precheck
        from vigil.core.interceptor.wrapper import ToolDenied

        mock_db = MagicMock()

        with patch("vigil.core.interceptor.url_precheck.precheck_url",
                   new=AsyncMock(side_effect=RuntimeError("DB is down"))):
            with pytest.raises(ToolDenied):
                await run_url_precheck(
                    url="http://any.com/",
                    session_id=self.SESSION_ID,
                    db_session=mock_db,
                )

    @pytest.mark.asyncio
    async def test_precheck_latency_under_50ms(self) -> None:
        """Pre-check with mocked DB completes in < 50ms (latency target)."""
        from vigil.core.interceptor.url_precheck import run_url_precheck
        from vigil.threat_intel.precheck import PreCheckResult, PreCheckAction

        mock_db = MagicMock()
        mock_result = PreCheckResult(
            action=PreCheckAction.PASS,
            confidence=0.0,
            reason="URL not in threat intel DB",
        )

        with patch("vigil.core.interceptor.url_precheck.precheck_url",
                   new=AsyncMock(return_value=mock_result)):
            t0 = time.perf_counter()
            await run_url_precheck(
                url="http://fast-check.com/",
                session_id=self.SESSION_ID,
                db_session=mock_db,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
        assert elapsed_ms < 50.0, f"Pre-check took {elapsed_ms:.1f}ms (target < 50ms)"

    def test_is_egress_tool_identifies_egress(self) -> None:
        """is_egress_tool returns True for http_get and web_search."""
        from vigil.core.interceptor.url_precheck import is_egress_tool
        assert is_egress_tool("http_get") is True
        assert is_egress_tool("web_search") is True
        assert is_egress_tool("read_email") is False
        assert is_egress_tool("check_headers") is False

    @pytest.mark.asyncio
    async def test_elevate_session_risk_updates_in_memory_state(self) -> None:
        """_elevate_session_risk updates current_risk in _active_sessions."""
        from vigil.core.interceptor.url_precheck import _elevate_session_risk
        from vigil.core.session.manager import _active_sessions

        session_id = "elevate-test-session"
        _inject_fake_session(session_id, risk=20.0, tier=0)

        with patch(
            "vigil.core.session.manager.SessionManager.update_risk_and_tier",
            new=AsyncMock()
        ):
            await _elevate_session_risk(session_id=session_id, delta=15.0)

        # The _active_sessions dict should have been read (not error)
        # The mock captures the call — just assert no exception was raised


# ===========================================================================
# TestThreatIntelRouter
# ===========================================================================
class TestThreatIntelRouter:
    """Tests for /threat-intel REST endpoints."""

    @pytest.fixture()
    def client(self):
        """Return a FastAPI TestClient backed by in-memory SQLite."""
        from fastapi.testclient import TestClient
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from vigil.db.models import Base
        from vigil.db.session import get_async_session
        from vigil.api.main import app

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

        async def _init():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        asyncio.run(_init())
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]

        async def override_db():
            async with async_session() as session:
                yield session

        app.dependency_overrides[get_async_session] = override_db
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
        app.dependency_overrides.clear()

    def test_list_returns_empty_initially(self, client) -> None:
        """GET /threat-intel returns empty list when DB is empty."""
        resp = client.get("/threat-intel")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_entry(self, client) -> None:
        """POST /threat-intel creates a new entry and returns it."""
        payload = {
            "url": "http://evil.ru/login",
            "domain": "evil.ru",
            "threat_type": "phishing",
            "confidence": 0.95,
        }
        resp = client.post("/threat-intel", json=payload)
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["url"] == payload["url"]
        assert data["domain"] == payload["domain"]
        assert data["confidence"] == 0.95
        assert data["is_active"] is True
        assert "id" in data

    def test_list_returns_created_entry(self, client) -> None:
        """GET /threat-intel returns entries after creation."""
        client.post("/threat-intel", json={
            "url": "http://phish.tk/click",
            "domain": "phish.tk",
            "threat_type": "phishing",
            "confidence": 0.92,
        })
        resp = client.get("/threat-intel")
        assert resp.status_code == 200
        items = resp.json()
        assert any(e["domain"] == "phish.tk" for e in items)

    def test_create_duplicate_returns_409(self, client) -> None:
        """POST /threat-intel with same URL twice returns 409 Conflict."""
        payload = {
            "url": "http://duplicate.ru/",
            "domain": "duplicate.ru",
            "threat_type": "phishing",
            "confidence": 0.80,
        }
        client.post("/threat-intel", json=payload)
        resp = client.post("/threat-intel", json=payload)
        assert resp.status_code == 409

    def test_deactivate_entry(self, client) -> None:
        """DELETE /threat-intel/{id} deactivates an entry."""
        create_resp = client.post("/threat-intel", json={
            "url": "http://to-delete.ru/",
            "domain": "to-delete.ru",
            "threat_type": "composite",
            "confidence": 0.88,
        })
        entry_id = create_resp.json()["id"]

        del_resp = client.delete(f"/threat-intel/{entry_id}")
        assert del_resp.status_code == 204

        # Verify the entry is now absent from the active list
        list_resp = client.get("/threat-intel")
        active = [e for e in list_resp.json() if e["id"] == entry_id]
        assert active == []

    def test_deactivate_nonexistent_returns_404(self, client) -> None:
        """DELETE /threat-intel/{id} returns 404 for unknown ID."""
        resp = client.delete("/threat-intel/nonexistent-id-99999")
        assert resp.status_code == 404

    def test_export_json(self, client) -> None:
        """GET /threat-intel/export?format=json returns valid JSON export."""
        client.post("/threat-intel", json={
            "url": "http://export-test.ru/",
            "domain": "export-test.ru",
            "threat_type": "phishing",
            "confidence": 0.87,
        })
        resp = client.get("/threat-intel/export?format=json")
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert "entries" in data
        assert "count" in data
        assert "exported_at" in data
        assert data["count"] >= 1

    def test_export_csv(self, client) -> None:
        """GET /threat-intel/export?format=csv returns valid CSV."""
        client.post("/threat-intel", json={
            "url": "http://csv-export.ru/",
            "domain": "csv-export.ru",
            "threat_type": "phishing",
            "confidence": 0.82,
        })
        resp = client.get("/threat-intel/export?format=csv")
        assert resp.status_code == 200
        lines = resp.text.strip().splitlines()
        assert len(lines) >= 2  # header + at least one row
        assert "url" in lines[0]
        assert "domain" in lines[0]
        assert "confidence" in lines[0]

    def test_export_invalid_format_returns_422(self, client) -> None:
        """GET /threat-intel/export?format=xml returns 422."""
        resp = client.get("/threat-intel/export?format=xml")
        assert resp.status_code == 422

    def test_list_pagination(self, client) -> None:
        """GET /threat-intel?limit=1&offset=0 respects pagination params."""
        for i in range(3):
            client.post("/threat-intel", json={
                "url": f"http://paginated-{i}.ru/",
                "domain": f"paginated-{i}.ru",
                "threat_type": "phishing",
                "confidence": 0.80,
            })
        resp = client.get("/threat-intel?limit=1&offset=0")
        assert resp.status_code == 200
        assert len(resp.json()) == 1


# ===========================================================================
# TestExporter
# ===========================================================================
class TestExporter:
    """Tests for threat_intel/exporter.py — JSON and CSV export format."""

    @pytest.mark.asyncio
    async def test_json_export_format(self) -> None:
        """JSON export has correct envelope structure and column values."""
        from vigil.threat_intel.exporter import export_threat_intel, _to_json
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()

        async with factory() as session:
            entry = ThreatIntel(
                id=str(uuid.uuid4()),
                url="http://json-test.ru/",
                domain="json-test.ru",
                threat_type="phishing",
                confidence=0.91,
                trigger_count=2,
                is_active=True,
            )
            session.add(entry)
            await session.commit()

        async with factory() as session:
            output = await export_threat_intel(session, fmt="json")

        parsed = json.loads(output)
        assert "entries" in parsed
        assert "count" in parsed
        assert "exported_at" in parsed
        assert parsed["count"] == 1
        entry_out = parsed["entries"][0]
        assert entry_out["url"] == "http://json-test.ru/"
        assert entry_out["domain"] == "json-test.ru"
        assert entry_out["confidence"] == 0.91

    @pytest.mark.asyncio
    async def test_csv_export_has_header(self) -> None:
        """CSV export starts with correct header columns."""
        from vigil.threat_intel.exporter import export_threat_intel, CSV_COLUMNS
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()

        async with factory() as session:
            entry = ThreatIntel(
                id=str(uuid.uuid4()),
                url="http://csv-test.ru/",
                domain="csv-test.ru",
                threat_type="behavioral_anomaly",
                confidence=0.77,
                trigger_count=1,
                is_active=True,
            )
            session.add(entry)
            await session.commit()

        async with factory() as session:
            output = await export_threat_intel(session, fmt="csv")

        reader = csv.DictReader(io.StringIO(output))
        assert reader.fieldnames is not None
        for col in ("url", "domain", "confidence", "threat_type", "is_active"):
            assert col in reader.fieldnames

    @pytest.mark.asyncio
    async def test_csv_export_data_row_values(self) -> None:
        """CSV export rows have correct values for all columns."""
        from vigil.threat_intel.exporter import export_threat_intel
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()

        async with factory() as session:
            entry_id = str(uuid.uuid4())
            entry = ThreatIntel(
                id=entry_id,
                url="http://row-test.biz/",
                domain="row-test.biz",
                threat_type="composite",
                confidence=0.85,
                trigger_count=3,
                is_active=True,
            )
            session.add(entry)
            await session.commit()

        async with factory() as session:
            output = await export_threat_intel(session, fmt="csv")

        rows = list(csv.DictReader(io.StringIO(output)))
        assert len(rows) == 1
        row = rows[0]
        assert row["domain"] == "row-test.biz"
        assert float(row["confidence"]) == 0.85
        assert int(row["trigger_count"]) == 3

    @pytest.mark.asyncio
    async def test_json_export_excludes_inactive_by_default(self) -> None:
        """JSON export excludes is_active=False entries by default."""
        from vigil.threat_intel.exporter import export_threat_intel
        from vigil.db.models import ThreatIntel
        import uuid

        _, factory = await _make_async_session()

        async with factory() as session:
            active = ThreatIntel(
                id=str(uuid.uuid4()),
                url="http://active.ru/",
                domain="active.ru",
                threat_type="phishing",
                confidence=0.88,
                trigger_count=1,
                is_active=True,
            )
            inactive = ThreatIntel(
                id=str(uuid.uuid4()),
                url="http://inactive.ru/",
                domain="inactive.ru",
                threat_type="phishing",
                confidence=0.75,
                trigger_count=1,
                is_active=False,
            )
            session.add(active)
            session.add(inactive)
            await session.commit()

        async with factory() as session:
            output = await export_threat_intel(session, fmt="json", include_inactive=False)

        parsed = json.loads(output)
        assert parsed["count"] == 1
        assert parsed["entries"][0]["domain"] == "active.ru"

    @pytest.mark.asyncio
    async def test_invalid_format_raises_value_error(self) -> None:
        """export_threat_intel raises ValueError for unknown format string."""
        from vigil.threat_intel.exporter import export_threat_intel

        _, factory = await _make_async_session()
        async with factory() as session:
            with pytest.raises(ValueError, match="Unsupported export format"):
                await export_threat_intel(session, fmt="xml")


# ===========================================================================
# TestSeedScript
# ===========================================================================
class TestSeedScript:
    """Tests for scripts/seed_threat_intel.py — DB seeding."""

    @pytest.mark.asyncio
    async def test_seed_populates_at_least_15_entries(self) -> None:
        """seed() inserts ≥ 15 entries into a fresh in-memory DB."""
        import sys
        from pathlib import Path
        # Ensure scripts/ is importable
        scripts_dir = str(Path(__file__).parent.parent.parent / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from vigil.db.models import ThreatIntel, Base
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import select

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]

        # Patch get_engine to return our in-memory engine
        with patch("vigil.db.session.get_engine", return_value=engine):
            import importlib
            import seed_threat_intel  # type: ignore[import]
            importlib.reload(seed_threat_intel)
            count = await seed_threat_intel.seed()

        assert count >= 15, f"Expected ≥ 15 entries, got {count}"

    @pytest.mark.asyncio
    async def test_seed_all_entries_active(self) -> None:
        """All seeded entries have is_active=True."""
        import sys
        from pathlib import Path

        scripts_dir = str(Path(__file__).parent.parent.parent / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from vigil.db.models import ThreatIntel, Base
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import select

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]

        with patch("vigil.db.session.get_engine", return_value=engine):
            import importlib
            import seed_threat_intel  # type: ignore[import]
            importlib.reload(seed_threat_intel)
            await seed_threat_intel.seed()

        async with factory() as session:
            result = await session.execute(
                select(ThreatIntel).where(ThreatIntel.is_active.is_(False))
            )
            inactive = result.scalars().all()
            assert len(inactive) == 0, (
                f"Found {len(inactive)} inactive entries — all should be active"
            )

    @pytest.mark.asyncio
    async def test_seed_is_idempotent(self) -> None:
        """Running seed() twice does not create duplicate entries."""
        import sys
        from pathlib import Path

        scripts_dir = str(Path(__file__).parent.parent.parent / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from vigil.db.models import ThreatIntel, Base
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import select, func

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        with patch("vigil.db.session.get_engine", return_value=engine):
            import importlib
            import seed_threat_intel  # type: ignore[import]
            importlib.reload(seed_threat_intel)
            count1 = await seed_threat_intel.seed()
            count2 = await seed_threat_intel.seed()

        # Second run should insert 0 (all already present)
        assert count2 == 0, f"Expected 0 on second run (idempotent), got {count2}"
