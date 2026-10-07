"""Tool permission map — Layer 3, tier → allowed tools.

Defines which tools are permitted at each containment tier.
Higher tiers remove tools progressively (additive restriction).

Tier 0 (GREEN):  All tools permitted.
Tier 1 (YELLOW): Network egress removed (send_email, http_get, web_search).
Tier 2 (ORANGE): Writes also removed (only read-only tools remain).
Tier 3 (RED):    Only introspection (read_email, flag_email).
Tier 4 (BLACK):  No tools — full block + human escalation.

Rules.md:
  - Unknown tool names are NOT in any set → denied at all tiers.
  - Fail-safe: if the map cannot be consulted, deny the call.
"""

from __future__ import annotations

# Canonical set of all known tools.
_ALL_TOOLS: frozenset[str] = frozenset({
    # Phase 3 — Email Secretary
    "read_email",
    "draft_reply",
    "send_email",
    "flag_email",
    "schedule_meeting",
    "http_get",
    "web_search",
    # Phase 4 — Phishing Analyzer
    "check_headers",
    "extract_urls",
    "verify_sender",
    "lookup_domain",
    "generate_report",
})

# Tools that require network egress.
_EGRESS_TOOLS: frozenset[str] = frozenset({"send_email", "http_get", "web_search"})

# Tools that write or mutate state.
_WRITE_TOOLS: frozenset[str] = frozenset({"draft_reply", "send_email", "schedule_meeting"})

# Analyzer tools that write verdict data to DB (restricted at high risk tiers).
_ANALYZER_WRITE_TOOLS: frozenset[str] = frozenset({"generate_report"})

# Analyzer read-only tools (permitted at all non-blackout tiers).
_ANALYZER_READ_TOOLS: frozenset[str] = frozenset({
    "check_headers", "extract_urls", "verify_sender", "lookup_domain",
})

# Allowed tool sets per tier.
_TIER_TOOLS: dict[int, frozenset[str]] = {
    0: _ALL_TOOLS,
    1: _ALL_TOOLS - _EGRESS_TOOLS,
    2: _ALL_TOOLS - _EGRESS_TOOLS - _WRITE_TOOLS,
    3: frozenset({"read_email", "flag_email"}) | _ANALYZER_READ_TOOLS | _ANALYZER_WRITE_TOOLS,
    4: frozenset(),  # No tools permitted.
}


def allowed_tools(tier: int) -> frozenset[str]:
    """Return the set of tools permitted at the given tier.

    Args:
        tier: Integer tier in {0, 1, 2, 3, 4}.

    Returns:
        Frozenset of tool names.  Returns empty frozenset for unknown tiers
        (fail restrictive — Rules.md).
    """
    return _TIER_TOOLS.get(tier, frozenset())


def is_tool_allowed(tool_name: str, tier: int) -> bool:
    """Check whether a specific tool is permitted at the given tier.

    Args:
        tool_name: Tool name string.
        tier:      Current permission tier.

    Returns:
        True if permitted, False otherwise.
        Returns False for any unknown tier or unknown tool (fail-safe).
    """
    return tool_name in allowed_tools(tier)
