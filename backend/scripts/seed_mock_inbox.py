"""Seed script — loads sample .eml fixtures into the mock inbox.

Phase 1: Stub only. Will be populated with realistic fixture emails in Phase 3
when the Email Intelligence Agent is built.

Usage:
    python scripts/seed_mock_inbox.py
"""

import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "emails"


def main() -> None:
    """Print fixture directory location. No-op in Phase 1."""
    print("Vigil AI — Seed Mock Inbox")
    print("=" * 40)
    print(f"Fixture directory: {FIXTURES_DIR.resolve()}")
    eml_files = list(FIXTURES_DIR.glob("*.eml"))
    if eml_files:
        print(f"Found {len(eml_files)} .eml fixture(s):")
        for f in eml_files:
            print(f"  - {f.name}")
    else:
        print("No .eml fixtures found. Add fixture files to:")
        print(f"  {FIXTURES_DIR.resolve()}")
        print("Seed complete (no-op in Phase 1).")


if __name__ == "__main__":
    main()
