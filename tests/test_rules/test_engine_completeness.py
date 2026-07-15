"""Completeness disclosure for contained rule-engine failures."""

from __future__ import annotations

from collections.abc import Iterator

from bundleInspector.config import RuleConfig
from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Finding,
    IntermediateRepresentation,
    Severity,
)


def _result(value: str, line: int = 1) -> RuleResult:
    return RuleResult(
        rule_id="engine-test",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="engine test",
        description="engine test result",
        extracted_value=value,
        value_type="url",
        line=line,
        column=0,
    )


def _analyze(rule: BaseRule) -> tuple[list[Finding], AnalysisContext]:
    ir = IntermediateRepresentation(file_url="file:///engine.js", file_hash="engine-hash")
    context = AnalysisContext(
        file_url=ir.file_url,
        file_hash=ir.file_hash,
        source_content="first\nsecond",
    )
    engine = RuleEngine(RuleConfig(enabled_categories=["endpoint"]))
    engine.register(rule)
    return engine.analyze(ir, context), context


def _events(context: AnalysisContext) -> list[dict[str, object]]:
    incomplete = context.metadata.get("analysis_incomplete", [])
    assert isinstance(incomplete, list)
    return [
        event
        for event in incomplete
        if event.get("reason") == "rule_execution_error"
    ]


class _CreationFailureRule(BaseRule):
    id = "creation-failure"

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        del ir, context
        raise RuntimeError("sensitive creation detail")


class _IterationFailureRule(BaseRule):
    id = "iteration-failure"

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        del ir, context
        yield _result("/preserved")
        raise RuntimeError("sensitive iteration detail")


class _ConversionFailureRule(BaseRule):
    id = "conversion-failure"

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        del ir, context
        yield _result("/preserved")
        yield _result("/invalid", line=2)
        yield _result("/invalid", line=2)

    def to_finding(
        self,
        result: RuleResult,
        context: AnalysisContext,
    ) -> Finding:
        if result.extracted_value == "/invalid":
            raise ValueError("sensitive conversion detail")
        return super().to_finding(result, context)


def test_matcher_creation_error_is_disclosed_without_exception_message():
    findings, context = _analyze(_CreationFailureRule())

    assert findings == []
    assert _events(context) == [
        {
            "component": "rule_engine",
            "rule_id": "creation-failure",
            "phase": "matcher_creation",
            "reason": "rule_execution_error",
            "partial_results": True,
            "error_type": "RuntimeError",
        }
    ]


def test_matcher_iteration_error_preserves_prior_results_and_is_disclosed():
    findings, context = _analyze(_IterationFailureRule())

    assert [finding.extracted_value for finding in findings] == ["/preserved"]
    assert len(_events(context)) == 1
    assert _events(context)[0]["phase"] == "matcher_iteration"


def test_result_conversion_errors_preserve_results_and_are_deduplicated():
    findings, context = _analyze(_ConversionFailureRule())

    assert [finding.extracted_value for finding in findings] == ["/preserved"]
    assert len(_events(context)) == 1
    assert _events(context)[0]["phase"] == "result_conversion"

