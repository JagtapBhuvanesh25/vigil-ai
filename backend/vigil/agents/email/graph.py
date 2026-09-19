"""Email Intelligence Agent — LangGraph orchestration.

Architecture.md §6: agents/email/graph.py — LangGraph agent definition.
Phases.md §Phase3: Write agents/email/graph.py (LangGraph agent).

The graph:
  classify → act → done

Node responsibilities:
  classify: Run EmailClassifier on parsed email. Set verdict in state.
  act:      Based on verdict, call appropriate contained tools.
            SAFE → read_email + draft_reply
            SUSPICIOUS → read_email + flag_email
            MALICIOUS → flag_email (risk already elevated by classifier)
            HONEYTOKEN → flag_email (Tier 4 will be triggered by deception detector)
  done:     Assemble final result dict.

Rules.md: LangGraph node functions call ONLY @contained_tool-wrapped tools.
          No LangGraph node may bypass containment or modify risk/tier state directly.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, TypedDict

logger = logging.getLogger(__name__)


# ── State schema ─────────────────────────────────────────────────────────────


class EmailAgentState(TypedDict, total=False):
    """Mutable state passed between LangGraph nodes.

    Fields:
        session_id:    Owning containment session.
        email_id:      Message-ID of the email being processed.
        subject:       Email subject.
        sender:        Email sender address.
        body_text:     Email plain-text body.
        verdict:       Classification result: safe | suspicious | malicious | honeytoken | pending.
        confidence:    Float in [0.0, 1.0] — classifier confidence.
        reasoning:     Human-readable reasoning for the verdict.
        heuristic_hit: True if injection pattern detected.
        draft_body:    Draft reply (only for SAFE emails).
        actions_taken: List of tool names that were called.
        error:         Error message if any node failed.
    """

    session_id: str
    email_id: str
    subject: str
    sender: str
    body_text: str
    email_honeytoken: str | None
    verdict: str
    confidence: float
    reasoning: str
    heuristic_hit: bool
    draft_body: str | None
    actions_taken: list[str]
    error: str | None


# ── Node functions ─────────────────────────────────────────────────────────────


async def _classify_node(state: EmailAgentState) -> EmailAgentState:
    """Classify the email using EmailClassifier.

    Uses heuristic pre-screen BEFORE LLM (Rules.md: LLM is untrusted).
    Checks honeytoken sender BEFORE heuristic.

    Args:
        state: Current graph state.

    Returns:
        Updated state with verdict, confidence, reasoning set.
    """
    from vigil.agents.email.classifier import EmailClassifier

    try:
        classifier = EmailClassifier()
        result = classifier.classify(
            subject=state.get("subject", ""),
            body=state.get("body_text", ""),
            sender_addr=state.get("sender", ""),
            email_honeytoken=state.get("email_honeytoken"),
        )
        return {
            **state,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "reasoning": result.reasoning,
            "heuristic_hit": result.heuristic_hit,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("graph: classify_node failed: %s — fail-safe SUSPICIOUS", exc)
        return {
            **state,
            "verdict": "suspicious",
            "confidence": 0.5,
            "reasoning": f"Classifier error: {exc}. Treating as Suspicious (fail-safe).",
            "heuristic_hit": False,
            "error": str(exc),
        }


async def _act_node(state: EmailAgentState) -> EmailAgentState:
    """Execute tools appropriate for the email verdict.

    Tool selection per verdict:
      SAFE       → read_email + draft_reply (offer reply)
      SUSPICIOUS → read_email + flag_email (restrict, no send)
      MALICIOUS  → flag_email only (tools restricted by tier escalation)
      HONEYTOKEN → flag_email only (Tier 4 will be triggered by deception detector)

    All tools pass through @contained_tool — containment enforces tier restrictions.

    Args:
        state: Current graph state (verdict must be set).

    Returns:
        Updated state with draft_body and actions_taken.
    """
    from vigil.agents.email.tools import draft_reply, flag_email, read_email

    session_id = state["session_id"]
    email_id = state.get("email_id", "")
    verdict = state.get("verdict", "suspicious")
    actions_taken: list[str] = []
    draft_body: str | None = None

    try:
        if verdict == "safe":
            # Read email content
            await read_email(session_id=session_id, email_id=email_id)
            actions_taken.append("read_email")

            # Draft reply (may be denied at Tier 2+, but Safe verdict usually stays at Tier 0)
            try:
                draft_result = await draft_reply(
                    session_id=session_id,
                    email_id=email_id,
                    context=f"Safe email classified with confidence {state.get('confidence', 0):.2f}",
                )
                draft_body = draft_result.get("draft_body")
                actions_taken.append("draft_reply")
            except Exception as draft_exc:
                logger.warning(
                    "graph: draft_reply denied or failed for session=%s: %s",
                    session_id,
                    draft_exc,
                )

        elif verdict in ("suspicious", "pending"):
            # Read but don't send — containment may already have raised tier
            try:
                await read_email(session_id=session_id, email_id=email_id)
                actions_taken.append("read_email")
            except Exception:  # noqa: BLE001
                pass

            # Flag as suspicious
            try:
                await flag_email(
                    session_id=session_id,
                    email_id=email_id,
                    label="suspicious",
                )
                actions_taken.append("flag_email:suspicious")
            except Exception as flag_exc:
                logger.warning("graph: flag_email denied: %s", flag_exc)

        elif verdict in ("malicious", "honeytoken"):
            # Flag as malicious/honeytoken — send/write tools blocked by tier
            label = "honeytoken" if verdict == "honeytoken" else "malicious"
            try:
                await flag_email(
                    session_id=session_id,
                    email_id=email_id,
                    label=label,
                )
                actions_taken.append(f"flag_email:{label}")
            except Exception as flag_exc:
                logger.warning("graph: flag_email denied at tier: %s", flag_exc)

    except Exception as exc:  # noqa: BLE001
        logger.error("graph: act_node error: %s", exc)
        return {**state, "actions_taken": actions_taken, "draft_body": draft_body, "error": str(exc)}

    return {**state, "actions_taken": actions_taken, "draft_body": draft_body}


def _done_node(state: EmailAgentState) -> EmailAgentState:
    """Assemble final result — no tool calls, no side effects.

    Args:
        state: Final graph state.

    Returns:
        State unchanged (done node is a passthrough).
    """
    logger.info(
        "graph: done session=%s email=%s verdict=%s actions=%s",
        state.get("session_id"),
        state.get("email_id"),
        state.get("verdict"),
        state.get("actions_taken"),
    )
    return state


# ── Graph builder ──────────────────────────────────────────────────────────────


def build_email_agent_graph():
    """Build and compile the email intelligence agent LangGraph.

    Returns:
        Compiled LangGraph StateGraph ready to invoke with an initial state dict.

    Note:
        If langgraph is not installed, returns None (tests use classify + tools
        directly without the graph; Rules.md: testable without all deps).
    """
    try:
        from langgraph.graph import END, StateGraph

        workflow = StateGraph(EmailAgentState)

        # Add nodes
        workflow.add_node("classify", _classify_node)
        workflow.add_node("act", _act_node)
        workflow.add_node("done", _done_node)

        # Wire edges: classify → act → done → END
        workflow.set_entry_point("classify")
        workflow.add_edge("classify", "act")
        workflow.add_edge("act", "done")
        workflow.add_edge("done", END)

        return workflow.compile()

    except ImportError:
        logger.warning(
            "graph: langgraph not installed — graph unavailable. "
            "Use run_email_agent() for direct invocation."
        )
        return None


# ── Direct invocation (no LangGraph dep required) ────────────────────────────


async def run_email_agent(
    session_id: str,
    email_id: str,
    subject: str,
    sender: str,
    body_text: str,
    email_honeytoken: str | None = None,
) -> dict[str, Any]:
    """Run the email agent pipeline without requiring LangGraph.

    Executes classify → act → done sequentially (no graph dependency).
    Used by the emails API router and tests.

    Args:
        session_id:       Owning containment session.
        email_id:         Message-ID of the email.
        subject:          Email subject.
        sender:           Parsed sender address.
        body_text:        Email body text.
        email_honeytoken: Session's planted honeytoken email address (optional).

    Returns:
        Final state dict with verdict, confidence, reasoning, draft_body, actions_taken.
    """
    graph = build_email_agent_graph()

    initial_state: EmailAgentState = {
        "session_id": session_id,
        "email_id": email_id,
        "subject": subject,
        "sender": sender,
        "body_text": body_text,
        "email_honeytoken": email_honeytoken,
        "verdict": "pending",
        "confidence": 0.0,
        "reasoning": "",
        "heuristic_hit": False,
        "draft_body": None,
        "actions_taken": [],
        "error": None,
    }

    if graph is not None:
        try:
            final_state = await graph.ainvoke(initial_state)
            return dict(final_state)
        except Exception as exc:  # noqa: BLE001
            logger.error("graph: ainvoke failed: %s — falling back to direct", exc)

    # Direct invocation fallback
    state = await _classify_node(initial_state)
    state = await _act_node(state)
    state = _done_node(state)
    return dict(state)
