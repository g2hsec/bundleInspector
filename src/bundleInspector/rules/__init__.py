"""Rule engine module - pattern matching and detection."""

from bundleInspector.rules.base import BaseRule, RuleResult
from bundleInspector.rules.engine import RuleEngine

__all__ = [
    "RuleEngine",
    "BaseRule",
    "RuleResult",
]
