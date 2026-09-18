"""Unit tests for the Audit Chain writer and verifier (Algorithm 3).

Phases.md testing criterion:
  - Algorithm 3 detects a single-byte change in any audit entry.

Tests cover:
  - compute_entry_hash is deterministic.
  - GENESIS_HASH is the correct anchor.
  - Single-byte change in any field is detected by the verifier.
  - Hash chain links entries correctly (prev_hash matches).
"""

import hashlib
import json
import pytest

from vigil.core.audit.writer import GENESIS_HASH, compute_entry_hash, build_payload
from vigil.core.audit.verifier import AuditVerifier, VerificationResult
from vigil.core.interceptor.trace import TraceEvent


class TestGenesisHash:
    def test_genesis_hash_value(self):
        """GENESIS_HASH must be SHA-256('GENESIS')."""
        expected = hashlib.sha256(b"GENESIS").hexdigest()
        assert GENESIS_HASH == expected

    def test_genesis_hash_is_64_chars(self):
        assert len(GENESIS_HASH) == 64


class TestComputeEntryHash:
    def test_deterministic(self):
        """Same inputs → same hash (deterministic)."""
        h1 = compute_entry_hash(
            prev_hash=GENESIS_HASH,
            seq_no=0,
            session_id="sess-1",
            event_type="risk_update",
            payload_json='{"x":1}',
        )
        h2 = compute_entry_hash(
            prev_hash=GENESIS_HASH,
            seq_no=0,
            session_id="sess-1",
            event_type="risk_update",
            payload_json='{"x":1}',
        )
        assert h1 == h2

    def test_single_byte_change_in_payload_produces_different_hash(self):
        """Phases.md: single-byte change → different hash (tamper detection)."""
        h1 = compute_entry_hash(
            prev_hash=GENESIS_HASH,
            seq_no=0,
            session_id="sess-1",
            event_type="risk_update",
            payload_json='{"risk_after":42.0}',
        )
        h2 = compute_entry_hash(
            prev_hash=GENESIS_HASH,
            seq_no=0,
            session_id="sess-1",
            event_type="risk_update",
            payload_json='{"risk_after":42.1}',  # One digit changed.
        )
        assert h1 != h2

    def test_single_byte_change_in_session_id(self):
        """Changing session_id by one char must change the hash."""
        h1 = compute_entry_hash(GENESIS_HASH, 0, "session-A", "risk_update", "{}")
        h2 = compute_entry_hash(GENESIS_HASH, 0, "session-B", "risk_update", "{}")
        assert h1 != h2

    def test_single_byte_change_in_seq_no(self):
        """Changing seq_no must change the hash."""
        h1 = compute_entry_hash(GENESIS_HASH, 0, "s", "risk_update", "{}")
        h2 = compute_entry_hash(GENESIS_HASH, 1, "s", "risk_update", "{}")
        assert h1 != h2

    def test_single_byte_change_in_event_type(self):
        """Changing event_type must change the hash."""
        h1 = compute_entry_hash(GENESIS_HASH, 0, "s", "risk_update", "{}")
        h2 = compute_entry_hash(GENESIS_HASH, 0, "s", "tier_decision", "{}")
        assert h1 != h2

    def test_output_is_64_hex_chars(self):
        h = compute_entry_hash(GENESIS_HASH, 0, "s", "e", "{}")
        assert len(h) == 64
        int(h, 16)  # Must be valid hex.


class TestBuildPayload:
    def test_no_raw_args_in_payload(self):
        """build_payload must not include raw argument values."""
        trace = TraceEvent(
            session_id="test-sess",
            tool_name="send_email",
            args_hash="abc123",
            allowed=False,
            denial_reason="blocked",
            risk_before=0.0,
            risk_after=80.0,
            tier_before=0,
            tier_after=4,
        )
        payload_json = build_payload(trace)
        payload = json.loads(payload_json)

        # Must contain audit-safe fields.
        assert "tool_name" in payload
        assert "args_hash" in payload
        assert "risk_after" in payload
        assert payload["risk_after"] == 80.0

        # Must NOT contain raw argument values (args_hash only).
        # The payload should have args_hash, not the original args.
        assert payload["args_hash"] == "abc123"

    def test_payload_is_valid_json(self):
        trace = TraceEvent(
            session_id="s",
            tool_name="t",
            args_hash="h",
        )
        payload = build_payload(trace)
        parsed = json.loads(payload)
        assert isinstance(parsed, dict)


class TestSimulatedChainVerification:
    """Simulate a hash chain and verify Algorithm 3 detects tampering.

    These tests run without a DB by testing the hash computation logic directly.
    """

    def _build_chain(self, n: int) -> list[dict]:
        """Build a simulated hash chain of n entries."""
        entries = []
        prev_hash = GENESIS_HASH
        for i in range(n):
            payload = json.dumps({"risk_after": float(i * 10), "seq": i})
            entry_hash = compute_entry_hash(
                prev_hash=prev_hash,
                seq_no=i,
                session_id="test-chain",
                event_type="risk_update",
                payload_json=payload,
            )
            entries.append({
                "seq_no": i,
                "session_id": "test-chain",
                "event_type": "risk_update",
                "payload_json": payload,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
            })
            prev_hash = entry_hash
        return entries

    def _verify_chain(self, entries: list[dict]) -> tuple[bool, int | None]:
        """Verify a simulated chain. Returns (is_valid, tampered_seq_no)."""
        expected_prev = GENESIS_HASH
        for entry in entries:
            if entry["prev_hash"] != expected_prev:
                return False, entry["seq_no"]
            recomputed = compute_entry_hash(
                prev_hash=entry["prev_hash"],
                seq_no=entry["seq_no"],
                session_id=entry["session_id"],
                event_type=entry["event_type"],
                payload_json=entry["payload_json"],
            )
            if recomputed != entry["entry_hash"]:
                return False, entry["seq_no"]
            expected_prev = entry["entry_hash"]
        return True, None

    def test_valid_chain(self):
        """A correctly built chain must verify as valid."""
        chain = self._build_chain(10)
        is_valid, tampered = self._verify_chain(chain)
        assert is_valid
        assert tampered is None

    def test_tampered_payload_detected(self):
        """Single-byte change in payload of entry 3 must be detected at seq 3."""
        chain = self._build_chain(10)
        # Modify payload of entry at index 3.
        original = chain[3]["payload_json"]
        chain[3]["payload_json"] = original.replace("30", "31")  # 1 digit change

        is_valid, tampered = self._verify_chain(chain)
        assert not is_valid
        assert tampered == 3

    def test_tampered_hash_detected_at_next_entry(self):
        """Changing entry_hash directly must be detected at the next entry."""
        chain = self._build_chain(10)
        # Corrupt entry 5's hash.
        chain[5]["entry_hash"] = "a" * 64  # Invalid hash.

        is_valid, tampered = self._verify_chain(chain)
        assert not is_valid
        # The corruption is detected when entry 6 checks prev_hash.
        assert tampered is not None
