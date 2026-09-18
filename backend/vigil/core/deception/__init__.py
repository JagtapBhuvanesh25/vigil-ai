"""Layer 5 — Deception Engine package."""
from vigil.core.deception.catalog import HONEYTOKEN_CATALOG, HoneytokenType, HoneytokenTemplate
from vigil.core.deception.randomizer import make_honeytoken_value, generate_token_suffix
from vigil.core.deception.registry import HoneytokenRegistry

__all__ = [
    "HONEYTOKEN_CATALOG",
    "HoneytokenType",
    "HoneytokenTemplate",
    "make_honeytoken_value",
    "generate_token_suffix",
    "HoneytokenRegistry",
]
