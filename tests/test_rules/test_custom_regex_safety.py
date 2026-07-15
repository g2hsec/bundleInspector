"""Resource-safety and completeness tests for user-controlled custom regexes."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from bundleInspector.config import RuleConfig
from bundleInspector.core.security import MAX_PATTERN_LENGTH
from bundleInspector.parser.ir_builder import IRBuilder
from bundleInspector.parser.js_parser import JSParser
from bundleInspector.rules import custom
from bundleInspector.rules.base import AnalysisContext, BaseRule
from bundleInspector.rules.custom import (
    CustomAstPatternRule,
    CustomDeclarativeRuleSpec,
    CustomRegexMatcherRule,
    CustomRegexRule,
    CustomRuleLoadDiagnostic,
    CustomRuleSpec,
    CustomSemanticRule,
    load_custom_rules,
)
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import IntermediateRepresentation


def _ir_and_context(source: str) -> tuple[IntermediateRepresentation, AnalysisContext]:
    parsed = JSParser().parse(source)
    assert parsed.success
    assert parsed.ast is not None
    ir = IRBuilder().build(parsed.ast, "file:///custom-regex.js", "custom-regex-hash")
    context = AnalysisContext(
        file_url="file:///custom-regex.js",
        file_hash="custom-regex-hash",
        source_content=source,
    )
    return ir, context


def _timeout_events(context: AnalysisContext) -> list[dict[str, object]]:
    events = context.metadata.get("analysis_incomplete", [])
    assert isinstance(events, list)
    return [event for event in events if event.get("reason") == "regex_timeout"]


def test_custom_regex_timeout_preserves_prior_results_and_is_disclosed(monkeypatch):
    monkeypatch.setattr(custom, "CUSTOM_REGEX_TIMEOUT_SECONDS", 0.01)
    source = f"/* SAFE */ const value = '{'a' * 20_000}!';"
    ir, context = _ir_and_context(source)
    rule = CustomRegexRule(
        CustomRuleSpec(
            id="timeout-after-result",
            title="timeout after result",
            category="debug",
            pattern=r"SAFE|(a|aa)+$",
        )
    )

    started = time.perf_counter()
    results = list(rule.match(ir, context))
    elapsed = time.perf_counter() - started

    assert [result.extracted_value for result in results] == ["SAFE"]
    assert elapsed < 0.75
    assert len(_timeout_events(context)) == 1
    assert _timeout_events(context)[0]["partial_results"] is True


def _regex_rule() -> tuple[BaseRule, IntermediateRepresentation, AnalysisContext]:
    source = f"const value = '{'a' * 20_000}!';"
    ir, context = _ir_and_context(source)
    spec = CustomRuleSpec(
        id="timeout-regex",
        title="timeout regex",
        category="debug",
        pattern=r"(a|aa)+$",
    )
    return CustomRegexRule(spec), ir, context


def _regex_matcher_rule() -> tuple[BaseRule, IntermediateRepresentation, AnalysisContext]:
    source = f"const value = '{'a' * 20_000}!';"
    ir, context = _ir_and_context(source)
    spec = CustomDeclarativeRuleSpec.model_validate(
        {
            "id": "timeout-regex-matcher",
            "title": "timeout regex matcher",
            "category": "debug",
            "matcher": {"type": "regex", "pattern": r"(a|aa)+$"},
        }
    )
    return CustomRegexMatcherRule(spec), ir, context


def _ast_rule() -> tuple[BaseRule, IntermediateRepresentation, AnalysisContext]:
    identifier = f"{'a' * 20_000}b"
    ir, context = _ir_and_context(f"const {identifier} = 'value';")
    spec = CustomDeclarativeRuleSpec.model_validate(
        {
            "id": "timeout-ast",
            "title": "timeout ast",
            "category": "debug",
            "matcher": {
                "type": "ast_pattern",
                "pattern": {
                    "kind": "VariableDeclarator",
                    "id_name_regex": r"(a|aa)+$",
                    "init": {"type": "LiteralString", "capture_as": "value"},
                },
            },
        }
    )
    return CustomAstPatternRule(spec), ir, context


def _semantic_rule() -> tuple[BaseRule, IntermediateRepresentation, AnalysisContext]:
    source = f"const value = '{'a' * 20_000}!';"
    ir, context = _ir_and_context(source)
    spec = CustomDeclarativeRuleSpec.model_validate(
        {
            "id": "timeout-semantic",
            "title": "timeout semantic",
            "category": "debug",
            "matcher": {
                "type": "semantic",
                "logic": {
                    "any": [
                        {
                            "and": [
                                {
                                    "regex_on_init": {
                                        "pattern": r"(a|aa)+$",
                                        "capture_as": "value",
                                    }
                                }
                            ]
                        }
                    ]
                },
            },
        }
    )
    return CustomSemanticRule(spec), ir, context


@pytest.mark.parametrize(
    "factory",
    [_regex_rule, _regex_matcher_rule, _ast_rule, _semantic_rule],
)
def test_every_custom_rule_family_enforces_timeout(
    monkeypatch,
    factory: Callable[[], tuple[BaseRule, IntermediateRepresentation, AnalysisContext]],
):
    monkeypatch.setattr(custom, "CUSTOM_REGEX_TIMEOUT_SECONDS", 0.01)
    rule, ir, context = factory()

    started = time.perf_counter()
    assert list(rule.match(ir, context)) == []
    elapsed = time.perf_counter() - started

    assert elapsed < 0.75
    assert len(_timeout_events(context)) == 1


@pytest.mark.parametrize("rule_family", ["legacy", "declarative"])
def test_zero_width_match_cap_is_global_per_rule_and_event_is_deduplicated(
    monkeypatch,
    rule_family: str,
):
    monkeypatch.setattr(custom, "_MAX_MATCHES_PER_RULE", 4)
    source = "const first = 'abc'; const second = 'def'; const third = 'ghi';"
    ir, context = _ir_and_context(source)
    if rule_family == "legacy":
        rule: BaseRule = CustomRegexRule(
            CustomRuleSpec(
                id="zero-width-legacy",
                title="zero width legacy",
                category="debug",
                pattern=r"(?=(.))",
                scope="string_literal",
                extract_group=1,
            )
        )
    else:
        spec = CustomDeclarativeRuleSpec.model_validate(
            {
                "id": "zero-width-declarative",
                "title": "zero width declarative",
                "category": "debug",
                "matcher": {
                    "type": "regex",
                    "pattern": r"(?=(.))",
                    "scope": "string_literal",
                    "capture_group": 1,
                },
            }
        )
        rule = CustomRegexMatcherRule(spec)

    results = list(rule.match(ir, context))
    events = context.metadata.get("analysis_incomplete", [])

    assert len(results) == 4
    assert isinstance(events, list)
    assert [event["reason"] for event in events] == ["regex_match_cap"]


@pytest.mark.parametrize("length_delta", [-1, 0, 1])
def test_custom_regex_pattern_length_boundary(length_delta: int):
    pattern = "a" * (MAX_PATTERN_LENGTH + length_delta)
    payload = {
        "id": "length-boundary",
        "title": "length boundary",
        "category": "debug",
        "pattern": pattern,
    }

    if length_delta <= 0:
        assert CustomRuleSpec.model_validate(payload).pattern == pattern
    else:
        with pytest.raises(ValidationError, match="pattern length exceeds"):
            CustomRuleSpec.model_validate(payload)


def test_custom_rule_load_diagnostics_reach_analysis_context(tmp_path):
    rule_path = tmp_path / "partial-rules.json"
    rule_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "valid",
                        "title": "valid",
                        "category": "debug",
                        "pattern": "valid",
                    },
                    {
                        "id": "valid",
                        "title": "duplicate",
                        "category": "debug",
                        "pattern": "duplicate",
                    },
                    {
                        "id": "invalid",
                        "title": "invalid",
                        "category": "debug",
                        "pattern": "(",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    diagnostics: list[CustomRuleLoadDiagnostic] = []

    rules = load_custom_rules(rule_path, diagnostics=diagnostics)

    assert [rule.id for rule in rules] == ["valid"]
    assert [diagnostic.reason for diagnostic in diagnostics] == [
        "custom_rule_duplicate_id",
        "custom_rule_invalid",
    ]

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    ir, context = _ir_and_context("const valid = true;")
    engine.analyze(ir, context)
    events = context.metadata.get("analysis_incomplete", [])
    assert isinstance(events, list)
    assert [event["reason"] for event in events] == [
        "custom_rule_duplicate_id",
        "custom_rule_invalid",
    ]


@pytest.mark.parametrize("payload", [None, {"rules": {"id": "not-a-list"}}])
def test_invalid_custom_rule_document_schema_is_disclosed(tmp_path, payload):
    rule_path = tmp_path / "invalid-document.json"
    rule_path.write_text(json.dumps(payload), encoding="utf-8")
    diagnostics: list[CustomRuleLoadDiagnostic] = []

    assert load_custom_rules(rule_path, diagnostics=diagnostics) == []
    assert [diagnostic.reason for diagnostic in diagnostics] == [
        "custom_rule_document_load_error"
    ]

    engine = RuleEngine(RuleConfig(custom_rules_file=rule_path))
    engine.register_defaults()
    ir, context = _ir_and_context("const value = true;")
    engine.analyze(ir, context)
    events = context.metadata.get("analysis_incomplete", [])
    assert isinstance(events, list)
    assert [event["reason"] for event in events] == ["custom_rule_document_load_error"]
