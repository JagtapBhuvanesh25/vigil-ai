"""Phishing & Threat Analyzer agent package.

Phase 4: Dedicated structured-verdict analyzer supervised by the 6-layer
containment engine. This agent is itself a threat surface — every tool it
calls passes through @contained_tool.

Exports:
    run_analyzer_agent — async entry point (analogous to run_email_agent)
"""

from vigil.agents.analyzer.graph import run_analyzer_agent

__all__ = ["run_analyzer_agent"]
