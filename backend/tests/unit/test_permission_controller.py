"""Unit tests for the Permission FSM (Algorithm 2).

Tests cover (Phases.md testing criteria):
  - Immediate restrict: higher-risk tier is applied immediately.
  - Hysteresis: 5 consecutive below-threshold events needed to restore.
  - Tier 4 lock: once Tier 4, stays Tier 4 regardless of risk.
  - bands.py: risk_to_tier boundary conditions.
  - tools_map.py: correct tool sets per tier.
"""

import pytest
from vigil.core.permission.controller import PermissionController
from vigil.core.permission.bands import risk_to_tier, tier_label
from vigil.core.permission.tools_map import allowed_tools, is_tool_allowed


class TestRiskToTier:
    """Test the tier boundary lookup (bands.py)."""

    def test_tier_0_boundaries(self):
        assert risk_to_tier(0.0) == 0
        assert risk_to_tier(10.0) == 0
        assert risk_to_tier(19.0) == 0

    def test_tier_1_boundaries(self):
        assert risk_to_tier(20.0) == 1
        assert risk_to_tier(30.0) == 1
        assert risk_to_tier(39.0) == 1

    def test_tier_2_boundaries(self):
        assert risk_to_tier(40.0) == 2
        assert risk_to_tier(50.0) == 2
        assert risk_to_tier(59.0) == 2

    def test_tier_3_boundaries(self):
        assert risk_to_tier(60.0) == 3
        assert risk_to_tier(70.0) == 3
        assert risk_to_tier(79.0) == 3

    def test_tier_4_boundaries(self):
        assert risk_to_tier(80.0) == 4
        assert risk_to_tier(100.0) == 4

    def test_negative_risk_fails_restrictive(self):
        """Negative risk → most restrictive tier (fail-safe)."""
        assert risk_to_tier(-1.0) == 4

    def test_tier_labels(self):
        assert tier_label(0) == "GREEN"
        assert tier_label(4) == "BLACK"


class TestToolPermissions:
    """Test the tool permission map (tools_map.py)."""

    def test_tier_0_all_tools_allowed(self):
        tools = allowed_tools(0)
        assert "send_email" in tools
        assert "http_get" in tools
        assert "draft_reply" in tools

    def test_tier_1_no_egress(self):
        """Tier 1: send_email and http_get must be blocked."""
        assert not is_tool_allowed("send_email", 1)
        assert not is_tool_allowed("http_get", 1)
        assert not is_tool_allowed("web_search", 1)
        # Read should still be allowed.
        assert is_tool_allowed("read_email", 1)

    def test_tier_2_read_only(self):
        """Tier 2: no writes, no network."""
        assert not is_tool_allowed("draft_reply", 2)
        assert not is_tool_allowed("send_email", 2)
        assert not is_tool_allowed("schedule_meeting", 2)
        assert is_tool_allowed("read_email", 2)

    def test_tier_3_introspection_only(self):
        """Tier 3: only read_email and flag_email."""
        assert is_tool_allowed("read_email", 3)
        assert is_tool_allowed("flag_email", 3)
        assert not is_tool_allowed("draft_reply", 3)
        assert not is_tool_allowed("http_get", 3)

    def test_tier_4_no_tools(self):
        """Tier 4: no tools permitted."""
        assert allowed_tools(4) == frozenset()
        assert not is_tool_allowed("read_email", 4)

    def test_unknown_tool_denied_at_all_tiers(self):
        """Unknown tool names are never in the allowed set."""
        for tier in range(5):
            assert not is_tool_allowed("exec_shell", tier)


class TestPermissionFSMImmediateRestrict:
    """Phases.md: verify immediate restrict."""

    def test_immediate_restrict_tier0_to_tier4(self):
        """FAST RESTRICT: Tier 0 → Tier 4 immediately on high risk."""
        controller = PermissionController()
        # Risk of 80 → tier 4, current is tier 0.
        new_tier = controller.evaluate(risk=80.0, current_tier=0, session_id="test-restrict-1")
        assert new_tier == 4

    def test_immediate_restrict_tier0_to_tier2(self):
        controller = PermissionController()
        new_tier = controller.evaluate(risk=45.0, current_tier=0, session_id="test-restrict-2")
        assert new_tier == 2


class TestPermissionFSMHysteresis:
    """Phases.md: verify 5-event hysteresis before restore."""

    def test_hysteresis_5_events_to_restore(self):
        """SLOW RESTORE: must accumulate 5 consecutive below-threshold events."""
        controller = PermissionController()
        session_id = "test-hysteresis-restore"

        # Push to Tier 2 (risk=40).
        tier = controller.evaluate(risk=40.0, current_tier=0, session_id=session_id)
        assert tier == 2

        # Now 4 below-threshold events (risk=10, maps to tier 0).
        # Should stay at Tier 2 for all 4.
        for i in range(4):
            tier = controller.evaluate(risk=10.0, current_tier=tier, session_id=session_id)
            assert tier == 2, f"Expected Tier 2 at event {i+1}, got {tier}"

        # 5th event — should restore to Tier 0.
        tier = controller.evaluate(risk=10.0, current_tier=tier, session_id=session_id)
        assert tier == 0, f"Expected Tier 0 after 5 events, got {tier}"

    def test_hysteresis_resets_on_upward_move(self):
        """Any upward move resets the hysteresis counter."""
        controller = PermissionController()
        session_id = "test-hysteresis-reset"

        # Push to Tier 2 (risk=40).
        tier = controller.evaluate(risk=40.0, current_tier=0, session_id=session_id)
        assert tier == 2

        # 3 below-threshold events (risk=10, target=tier 0).
        for _ in range(3):
            tier = controller.evaluate(risk=10.0, current_tier=tier, session_id=session_id)
        assert tier == 2  # Not restored yet (only 3/5 events).

        # Upward move (risk=45 → tier 2 = same tier, counter resets by staying up).
        # We simulate an upward spike to tier 3 then back down.
        tier = controller.evaluate(risk=60.0, current_tier=tier, session_id=session_id)
        assert tier == 3  # Moved up — counter reset.

        # Step back down to tier 2 range.
        tier = controller.evaluate(risk=40.0, current_tier=tier, session_id=session_id)
        # Tier 3 → target tier 2 — starts new hysteresis counter.
        assert tier == 3  # One event — not yet restored.

        # Need 4 more below-threshold events (total 5 from this point).
        for i in range(4):
            tier = controller.evaluate(risk=40.0, current_tier=tier, session_id=session_id)
        assert tier == 2, f"Expected Tier 2 after 5 events, got {tier}"



class TestPermissionFSMTier4Lock:
    """Tier 4 must be locked — only human operator can release."""

    def test_tier4_does_not_self_restore(self):
        """Even with risk=0, tier 4 stays locked."""
        controller = PermissionController()
        session_id = "test-tier4-lock"

        for _ in range(20):  # Many below-threshold events.
            tier = controller.evaluate(risk=0.0, current_tier=4, session_id=session_id)
            assert tier == 4, "Tier 4 must not self-restore"
