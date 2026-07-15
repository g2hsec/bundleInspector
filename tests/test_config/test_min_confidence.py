"""RuleConfig.min_confidence must fail CLOSED on a typo (a bad value previously loaded silently and
disabled confidence filtering entirely), while still never dropping a detector finding whose own
confidence is outside the {low,medium,high} set."""

import pytest
from pydantic import ValidationError

from bundleInspector.config import Config, RuleConfig
from bundleInspector.rules.base import RuleResult
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category, Confidence, Severity


def _rr(confidence, severity=Severity.HIGH):
    return RuleResult(
        rule_id="r", category=Category.ENDPOINT, severity=severity,
        confidence=confidence, title="t", description="d",
        extracted_value="v", value_type="x", line=1, column=0,
    )


def test_invalid_min_confidence_rejected_at_construction():
    for bad in ("hgih", "med", "", "none", "critical"):
        with pytest.raises(ValidationError):
            RuleConfig(min_confidence=bad)


def test_min_confidence_normalized_case_insensitive():
    assert RuleConfig(min_confidence="HIGH").min_confidence == "high"
    assert RuleConfig(min_confidence=" Medium ").min_confidence == "medium"
    assert RuleConfig().min_confidence == "low"  # default unchanged


def test_from_file_rejects_bad_min_confidence(tmp_path):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("rules:\n  min_confidence: bogus\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        Config.from_file(cfg)


def test_high_min_confidence_still_filters_low_results():
    """The defect fix must not break filtering: with min=high a LOW result is dropped, HIGH kept."""
    engine = RuleEngine(RuleConfig(min_confidence="high"))
    assert engine._meets_confidence_threshold(_rr(Confidence.LOW, Severity.LOW)) is False
    assert engine._meets_confidence_threshold(_rr(Confidence.HIGH)) is True


def test_unusual_result_confidence_is_never_dropped():
    """Branch (A) leniency preserved: a detector result whose confidence is outside the enum set
    passes the threshold (we never silently discard a detector finding)."""
    class _Conf:
        value = "unknown"
    engine = RuleEngine(RuleConfig(min_confidence="high"))
    assert engine._meets_confidence_threshold(_rr(_Conf())) is True


def test_runtime_bad_min_confidence_warns_and_keeps_findings():
    """Defense-in-depth: a bad min_confidence assigned directly on the instance (bypassing pydantic)
    falls back to 'low' -- nothing dropped -- instead of silently disabling filtering."""
    engine = RuleEngine(RuleConfig())
    object.__setattr__(engine.config, "min_confidence", "typo")  # exercise runtime defense
    assert engine._meets_confidence_threshold(_rr(Confidence.LOW, Severity.LOW)) is True
