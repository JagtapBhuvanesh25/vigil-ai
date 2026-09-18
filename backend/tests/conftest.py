"""Pytest configuration for Vigil AI backend tests.

Phase 1: No tests yet. This file sets asyncio_mode so that pytest-asyncio
works correctly when Phase 2+ tests are added.

Test categories (to be added in later phases):
  - unit/           — isolated unit tests (no DB, no network)
  - integration/    — tests against SQLite test DB
"""

import pytest


# Phase 1: No shared fixtures yet.
# This file intentionally left mostly empty.
# Tests will be added in Phase 2 (containment engine unit tests).
