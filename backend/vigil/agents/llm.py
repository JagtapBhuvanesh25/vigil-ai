"""Shared LLM client wrapper for all Vigil AI agents.

Architecture.md §6: agents/llm.py — Shared Ollama client wrapper.
Rules.md §3: LLM output is an untrusted signal. The LLM classifies and drafts;
             it does NOT control security tiers, permissions, or risk scores.

When VIGIL_MOCK_LLM=true (or config.mock_llm is True), a deterministic MockLLM
is used instead of Ollama. This allows all tests to pass without Ollama running,
satisfying the local-first / zero-dependency test requirement.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ── Injection keywords that MockLLM uses to simulate malicious detection ──────
_INJECTION_KEYWORDS: frozenset[str] = frozenset(
    {
        "ignore previous instructions",
        "ignore all instructions",
        "forget previous instructions",
        "dan mode",
        "jailbreak",
        "act as an unrestricted",
        "bypass all restrictions",
        "system: override",
        "grant admin access",
        "you are now in",
        "new instruction",
        "execute:",
        "exfiltrate",
        "{{",
        "forward all emails",
        "send me your credentials",
    }
)

_SAFE_KEYWORDS: frozenset[str] = frozenset(
    {"meeting", "invoice", "update", "confirm", "schedule", "collaboration", "attached"}
)


class MockLLM:
    """Deterministic mock LLM for tests — no Ollama required.

    Classifies based on keyword matching:
    - Any injection keyword → MALICIOUS
    - Any safe keyword (and no injection) → SAFE
    - Otherwise → SUSPICIOUS

    For draft generation, returns a simple canned reply.

    Rules.md: Even the mock LLM is untrusted. Its output is processed through
    the same classifier pipeline (heuristic pre-screen, confidence mapping).
    """

    def classify(self, text: str) -> str:
        """Return SAFE, SUSPICIOUS, or MALICIOUS based on keyword matching.

        Args:
            text: Email body or subject to classify.

        Returns:
            One of: 'SAFE', 'SUSPICIOUS', 'MALICIOUS'
        """
        lower = text.lower()
        for kw in _INJECTION_KEYWORDS:
            if kw in lower:
                logger.debug("mock_llm: injection keyword detected: %r", kw)
                return "MALICIOUS"
        for kw in _SAFE_KEYWORDS:
            if kw in lower:
                return "SAFE"
        return "SUSPICIOUS"

    def draft(self, context: str) -> str:
        """Return a canned draft reply.

        Args:
            context: Email subject/body context for the reply.

        Returns:
            A draft reply string.
        """
        # Extract subject hint from context if present
        subject_match = re.search(r"Subject:\s*(.+?)(?:\n|$)", context)
        subject_hint = subject_match.group(1).strip() if subject_match else "your message"
        return (
            f"Thank you for reaching out regarding {subject_hint}.\n\n"
            "I have received your email and will get back to you shortly.\n\n"
            "Best regards,\nVigil AI Assistant"
        )


class OllamaLLM:
    """Real Ollama LLM client using langchain-ollama.

    Requires Ollama running at the configured URL with the model pulled.
    Falls back to MockLLM behavior if the import fails (warn only).
    """

    def __init__(self, url: str, model: str, temperature: float = 0.1) -> None:
        """Initialise the Ollama client.

        Args:
            url:         Ollama server URL (e.g. http://localhost:11434)
            model:       Model name (e.g. qwen2.5:7b)
            temperature: Sampling temperature [0.0, 1.0]
        """
        self._url = url
        self._model = model
        self._temperature = temperature
        self._llm = None
        try:
            from langchain_ollama import ChatOllama

            self._llm = ChatOllama(
                base_url=url,
                model=model,
                temperature=temperature,
            )
            logger.info("ollama_llm: connected model=%s url=%s", model, url)
        except ImportError:
            logger.warning(
                "ollama_llm: langchain-ollama not installed. Falling back to MockLLM."
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ollama_llm: failed to connect to Ollama at %s: %s. "
                "Falling back to MockLLM.",
                url,
                exc,
            )

    def classify(self, text: str) -> str:
        """Classify email body via Ollama.

        Args:
            text: Email body/subject to classify.

        Returns:
            One of: 'SAFE', 'SUSPICIOUS', 'MALICIOUS'
            Falls back to MockLLM on any error (fail-safe).
        """
        if self._llm is None:
            return MockLLM().classify(text)
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            from vigil.agents.email.prompts import CLASSIFICATION_PROMPT

            messages = [
                SystemMessage(content=CLASSIFICATION_PROMPT),
                HumanMessage(content=text[:4096]),  # cap to avoid token overflow
            ]
            response = self._llm.invoke(messages)
            raw = response.content.strip().upper()
            # Extract first word only (LLM may be verbose despite instructions)
            first_word = raw.split()[0] if raw else "SUSPICIOUS"
            if first_word in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
                return first_word
            logger.warning("ollama_llm: unexpected classify response %r", raw)
            return "SUSPICIOUS"  # fail-safe
        except Exception as exc:  # noqa: BLE001
            logger.error("ollama_llm: classify error: %s. Using SUSPICIOUS.", exc)
            return "SUSPICIOUS"  # fail-safe

    def draft(self, context: str) -> str:
        """Draft a reply via Ollama.

        Args:
            context: Composed prompt with email context.

        Returns:
            Draft reply string.  Falls back to canned reply on error.
        """
        if self._llm is None:
            return MockLLM().draft(context)
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            from vigil.agents.email.prompts import DRAFTING_PROMPT

            messages = [
                SystemMessage(content=DRAFTING_PROMPT),
                HumanMessage(content=context[:4096]),
            ]
            response = self._llm.invoke(messages)
            return response.content.strip()
        except Exception as exc:  # noqa: BLE001
            logger.error("ollama_llm: draft error: %s. Using canned reply.", exc)
            return MockLLM().draft(context)


def get_llm_client() -> MockLLM | OllamaLLM:
    """Return the appropriate LLM client based on configuration.

    If VIGIL_MOCK_LLM=true or config.mock_llm is True, returns MockLLM.
    Otherwise returns OllamaLLM (connected to configured Ollama instance).

    Returns:
        MockLLM or OllamaLLM instance.
    """
    try:
        from vigil.config.loader import load_config

        cfg = load_config()
        if cfg.mock_llm:
            logger.info("llm: mock mode enabled — using MockLLM")
            return MockLLM()
        return OllamaLLM(
            url=cfg.ollama.url,
            model=cfg.ollama.model,
            temperature=cfg.ollama.temperature,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("llm: config load failed (%s). Using MockLLM.", exc)
        return MockLLM()
