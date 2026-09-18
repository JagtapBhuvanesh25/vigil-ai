"""Phase 1 smoke tests — verifies the package is importable and config loads."""

from vigil import __version__
from vigil.config.loader import load_config
from vigil.config.schema import VigilConfig


def test_version_exists():
    """The vigil package must export a version string."""
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_config_loads():
    """Config must load without errors and return a VigilConfig instance."""
    cfg = load_config()
    assert isinstance(cfg, VigilConfig)


def test_config_scoring_defaults():
    """Risk scoring weights must be within expected ranges per Architecture.md."""
    cfg = load_config()
    assert 0.90 <= cfg.scoring.decay_lambda <= 0.99
    assert cfg.scoring.weight_deception > cfg.scoring.weight_anomaly  # wb > wa (honeytokens spike more)
    assert cfg.scoring.weight_heuristic > 0


def test_config_tier_boundaries():
    """Tier boundaries must form a contiguous, non-overlapping range."""
    cfg = load_config()
    assert cfg.tiers.tier_0_max + 1 == cfg.tiers.tier_1_min
    assert cfg.tiers.tier_1_max + 1 == cfg.tiers.tier_2_min
    assert cfg.tiers.tier_2_max + 1 == cfg.tiers.tier_3_min
    assert cfg.tiers.tier_3_max + 1 == cfg.tiers.tier_4_min
