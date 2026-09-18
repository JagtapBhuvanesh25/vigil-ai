"""Unit tests for the Enforcement Adapter (Layer 4).

Tests cover:
  - Application-level enforcement: tool allowed/denied at each tier.
  - Tier 4 full block — no tool is permitted.
  - Unknown tools are denied at all tiers.
  - Seccomp profile files exist on disk.
  - Container pool structure (2 containers per tier = 10 total) — no Docker needed.
"""

import json
from pathlib import Path

import pytest
from vigil.core.enforcement.adapter import EnforcementAdapter
from vigil.core.enforcement.pool import ContainerPool, CONTAINERS_PER_TIER, TIERS


class TestEnforcementAdapterApplicationLevel:
    def _a(self):
        return EnforcementAdapter()

    def test_read_email_allowed_tier0(self):
        assert self._a().is_allowed("read_email", 0) is True

    def test_send_email_allowed_tier0(self):
        assert self._a().is_allowed("send_email", 0) is True

    def test_send_email_denied_tier1(self):
        """Tier 1 strips egress tools."""
        assert self._a().is_allowed("send_email", 1) is False

    def test_http_get_denied_tier1(self):
        assert self._a().is_allowed("http_get", 1) is False

    def test_read_email_allowed_tier1(self):
        assert self._a().is_allowed("read_email", 1) is True

    def test_draft_reply_denied_tier2(self):
        """Tier 2 strips write tools."""
        assert self._a().is_allowed("draft_reply", 2) is False

    def test_read_email_allowed_tier3(self):
        assert self._a().is_allowed("read_email", 3) is True

    def test_schedule_meeting_denied_tier3(self):
        assert self._a().is_allowed("schedule_meeting", 3) is False

    def test_all_tools_denied_tier4(self):
        """Tier 4: full blackout."""
        adapter = self._a()
        for tool in ["read_email", "draft_reply", "send_email", "http_get", "flag_email"]:
            assert adapter.is_allowed(tool, 4) is False, f"{tool} should be denied at Tier 4"

    def test_unknown_tool_denied_all_tiers(self):
        adapter = self._a()
        for tier in range(5):
            assert adapter.is_allowed("exec_shell", tier) is False


class TestSeccompProfiles:
    """Verify seccomp profile files are present and valid JSON."""

    _PROFILES_DIR = (
        Path(__file__).parent.parent.parent
        / "vigil" / "core" / "enforcement" / "profiles"
    )

    def test_all_tier_profiles_exist(self):
        for tier in range(5):
            p = self._PROFILES_DIR / f"tier{tier}_seccomp.json"
            assert p.exists(), f"Missing profile: {p}"

    def test_profiles_are_valid_json(self):
        for tier in range(5):
            p = self._PROFILES_DIR / f"tier{tier}_seccomp.json"
            data = json.loads(p.read_text())
            assert "defaultAction" in data, f"tier{tier}: missing defaultAction"

    def test_tier4_profile_is_most_restrictive(self):
        """Tier 4 profile must use SCMP_ACT_KILL as default."""
        p = self._PROFILES_DIR / "tier4_seccomp.json"
        data = json.loads(p.read_text())
        assert data["defaultAction"] == "SCMP_ACT_KILL"

    def test_tier0_profile_is_permissive(self):
        """Tier 0 profile must use SCMP_ACT_ALLOW as default."""
        p = self._PROFILES_DIR / "tier0_seccomp.json"
        data = json.loads(p.read_text())
        assert data["defaultAction"] == "SCMP_ACT_ALLOW"


class TestAppArmorProfiles:
    """Verify AppArmor profile files are present."""

    _APPARMOR_DIR = (
        Path(__file__).parent.parent.parent
        / "vigil" / "core" / "enforcement" / "profiles" / "apparmor"
    )

    def test_all_apparmor_profiles_exist(self):
        for tier in range(5):
            p = self._APPARMOR_DIR / f"tier{tier}.profile"
            assert p.exists(), f"Missing AppArmor profile: {p}"


class TestContainerPool:
    """Test container pool structure without requiring Docker.

    Phases.md: pool initialises 2 containers per tier (10 total).
    """

    def test_containers_per_tier_constant(self):
        """CONTAINERS_PER_TIER must be 2 per spec."""
        assert CONTAINERS_PER_TIER == 2

    def test_total_tiers(self):
        """Must have 5 tiers (0–4)."""
        assert len(TIERS) == 5
        assert set(TIERS) == {0, 1, 2, 3, 4}

    def test_expected_total_containers(self):
        """10 containers total: 2 per tier * 5 tiers."""
        assert CONTAINERS_PER_TIER * len(TIERS) == 10

    def test_pool_empty_before_init(self):
        pool = ContainerPool()
        # Before initialize(), pool must be empty.
        for tier in range(5):
            assert pool.pool_size(tier) == 0

    def test_pool_not_available_before_init(self):
        pool = ContainerPool()
        assert pool.is_available() is False
