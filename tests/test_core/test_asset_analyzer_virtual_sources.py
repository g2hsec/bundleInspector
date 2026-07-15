"""Virtual ``sourcesContent`` completeness, identity, and provenance regressions."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

import bundleInspector.parser.export_scopes as export_scopes
from bundleInspector.config import Config, CrawlerConfig, ParserConfig
from bundleInspector.core import asset_analysis
from bundleInspector.core import asset_analyzer as asset_analyzer_module
from bundleInspector.core.asset_analyzer import AssetAnalyzer
from bundleInspector.core.dedup import DedupCache
from bundleInspector.core.orchestrator import Orchestrator
from bundleInspector.correlator.graph import CorrelationGraph
from bundleInspector.normalizer.line_mapping import LineMapper
from bundleInspector.normalizer.sourcemap import SourceMapInfo
from bundleInspector.parser.ir_builder import IRBuilder, build_ir
from bundleInspector.parser.js_parser import JSParser, parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    JSAsset,
    Severity,
)


def _analyzer() -> AssetAnalyzer:
    config = Config()
    engine = RuleEngine(config.rules)
    engine.register_defaults()
    return AssetAnalyzer(
        JSParser.from_parser_config(config.parser),
        IRBuilder.from_parser_config(config.parser),
        engine,
        DedupCache(),
    )


def _sourcemap(entries: list[tuple[str, str]]) -> SourceMapInfo:
    return SourceMapInfo(
        url=None,
        content=None,
        is_inline=True,
        sources=[path for path, _ in entries],
        sources_content=[content for _, content in entries],
        mappings="",
    )


def _asset(source: str) -> JSAsset:
    content = source.encode()
    return JSAsset(
        url="https://example.test/bundle.js",
        content=content,
        content_hash=hashlib.sha256(content).hexdigest()[:16],
        is_first_party=True,
    )


def _generated_endpoint(value: str) -> Finding:
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        title="Generated endpoint",
        extracted_value=value,
        value_type="api_endpoint",
        evidence=Evidence(
            file_url="https://example.test/bundle.js",
            file_hash="generated-hash",
            line=7,
            column=4,
        ),
    )
    finding.metadata["method"] = "GET"
    return finding


def _semantic_snapshot(findings: list[Finding]) -> list[tuple[Any, ...]]:
    return sorted(
        (
            finding.rule_id,
            finding.value_type,
            finding.extracted_value,
            finding.metadata.get("method"),
            finding.evidence.file_url,
            finding.evidence.line,
            finding.metadata.get("source_occurrences"),
        )
        for finding in findings
    )


async def _noop(*_args: Any, **_kwargs: Any) -> None:
    return None


class _ExplodingLineMapper(LineMapper):
    """Picklable mapper used to exercise the real ProcessPool enrichment failure path."""

    def get_original(self, _line: int, _column: int) -> tuple[int, int]:
        raise RuntimeError("sensitive-enrichment-detail")


def test_tsx_sources_content_preserves_endpoint_sink_and_confirmed_taint() -> None:
    source = (
        "interface P { q: string }; const q: string = location.hash; "
        'const C = () => <div data-api="/api/tsx-source" '
        "dangerouslySetInnerHTML={{__html:q}} />;"
    )
    events: list[dict[str, Any]] = []

    findings = _analyzer()._analyze_virtual_sources(
        _sourcemap([("src/Component.tsx", source)]),
        True,
        incomplete_events=events,
    )

    assert events == []
    assert any(f.extracted_value == "/api/tsx-source" for f in findings)
    assert any(f.value_type == "dom_html_sink" and f.extracted_value == "innerHTML=" for f in findings)
    taint = next(f for f in findings if f.value_type == "taint_flow")
    assert taint.metadata["confirmed"] is True
    assert taint.metadata["source_kind"] == "location"
    assert taint.metadata["sink"] == "innerhtml="
    assert taint.evidence.original_file_url == "src/Component.tsx"


def test_asset_and_virtual_source_paths_forward_explicit_language_hints(monkeypatch) -> None:
    analyzer = _analyzer()
    original_parse = analyzer.parser.parse
    calls: list[str | None] = []

    def _recording_parse(source, *, language_hint=None):
        calls.append(language_hint)
        return original_parse(source, language_hint=language_hint)

    monkeypatch.setattr(analyzer.parser, "parse", _recording_parse)
    asset = JSAsset(
        url="file:///module.mts",
        content=b'const endpoint: string = "/api/mts"; fetch(endpoint);',
        language_hint="typescript",
    )
    asset.compute_hash()

    analyzer.analyze_asset_standalone(asset, None, None)
    assert calls == ["typescript"]

    calls.clear()
    analyzer._analyze_virtual_sources(
        _sourcemap(
            [
                ("src/legacy.cts", 'fetch("/api/cts");'),
                ("src/View.jsx", 'const View = () => <div data-api="/api/jsx" />;'),
            ]
        ),
        True,
    )
    assert calls == ["jsx", "typescript"]


def test_partial_tsx_sources_content_survives_parallel_worker_contract() -> None:
    malformed = (
        "interface P { q: string }; const C = () => "
        "<div dangerouslySetInnerHTML={{__html: location.hash}} "
    )
    config = Config()
    asset_analysis.init_worker(config)

    result = asset_analysis.analyze_asset_task_with_telemetry(
        (
            0,
            _asset('fetch("/api/generated");'),
            None,
            _sourcemap([("src/Broken.tsx", malformed)]),
            config,
        )
    )
    index, parse_success, parse_errors, _, findings, events = result

    assert index == 0
    assert parse_success is True
    assert any("virtual source analysis incomplete" in error for error in parse_errors)
    parser_event = next(event for event in events if event.get("component") == "virtual_source_parser")
    assert parser_event["reason"] == "partial"
    assert parser_event["backend"] == "tree-sitter-tsx"
    assert "syntax_error_nodes" in parser_event["capability_gaps"]
    assert any(f.extracted_value == "/api/generated" for f in findings)


def test_prebuilt_ir_records_virtual_source_incompleteness_in_context() -> None:
    generated = 'fetch("/api/generated");'
    parsed = parse_js(generated)
    assert parsed.ast is not None
    context = AnalysisContext(
        file_url="bundle.js",
        file_hash="generated-hash",
        source_content=generated,
    )
    malformed = "const View = () => <div dangerouslySetInnerHTML={{__html: value}} "

    _analyzer().analyze_prebuilt_ir(
        build_ir(parsed.ast, context.file_url, context.file_hash),
        context,
        sourcemap=_sourcemap([("src/Broken.tsx", malformed)]),
    )

    events = context.metadata.get("analysis_incomplete", [])
    assert any(event.get("component") == "virtual_source_parser" for event in events)


def test_standalone_enrichment_failure_preserves_findings_and_emits_safe_telemetry() -> None:
    asset = _asset('fetch("/api/enrichment-standalone");')
    events: list[dict[str, Any]] = []

    findings = _analyzer().analyze_asset_standalone(
        asset,
        _ExplodingLineMapper(),
        None,
        events,
    )

    assert any(f.extracted_value == "/api/enrichment-standalone" for f in findings)
    assert events == [{
        "component": "asset_enrichment",
        "reason": "failed",
        "partial_results": True,
    }]
    assert asset.parse_errors == [
        "asset analysis incomplete (component=asset_enrichment; reason=failed)",
    ]
    assert "sensitive-enrichment-detail" not in json.dumps(
        {"events": events, "parse_errors": asset.parse_errors}
    )


def test_prebuilt_enrichment_failure_preserves_findings_and_context_event() -> None:
    source = 'fetch("/api/enrichment-prebuilt");'
    parsed = parse_js(source)
    assert parsed.ast is not None
    context = AnalysisContext(
        file_url="bundle.js",
        file_hash="generated-hash",
        source_content=source,
    )

    findings = _analyzer().analyze_prebuilt_ir(
        build_ir(parsed.ast, context.file_url, context.file_hash),
        context,
        line_mapper=_ExplodingLineMapper(),
    )

    assert any(f.extracted_value == "/api/enrichment-prebuilt" for f in findings)
    assert context.metadata["analysis_incomplete"] == [{
        "component": "asset_enrichment",
        "reason": "failed",
        "partial_results": True,
    }]
    assert "sensitive-enrichment-detail" not in json.dumps(context.metadata)


def test_enrichment_recursion_error_uses_the_common_incomplete_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = 'import api from "./api"; fetch("/api/recursion");'
    parsed = parse_js(source)
    assert parsed.ast is not None
    ir = build_ir(parsed.ast, "f.js", "h")
    analyzer = _analyzer()

    def recurse(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        raise RecursionError("sensitive-recursion-detail")

    monkeypatch.setattr(analyzer, "_collect_import_alias_bindings", recurse)
    context = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    findings = analyzer.analyze_prebuilt_ir(ir, context)

    assert any(finding.extracted_value == "/api/recursion" for finding in findings)
    assert context.metadata["analysis_incomplete"] == [{
        "component": "asset_enrichment",
        "reason": "failed",
        "partial_results": True,
    }]
    assert "sensitive-recursion-detail" not in json.dumps(context.metadata)


def test_final_ir_partial_event_is_standalone_prebuilt_invariant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(export_scopes, "_MAX_EXPORT_AST_NODES", 8)
    source = 'const api = require("./api"); fetch("/api/ir-partial");'
    event = {
        "component": "intermediate_representation",
        "reason": "truncated",
        "partial_results": True,
    }

    asset = _asset(source)
    standalone_events: list[dict[str, Any]] = []
    standalone = _analyzer().analyze_asset_standalone(
        asset,
        None,
        None,
        standalone_events,
    )

    parsed = parse_js(source)
    assert parsed.ast is not None
    context = AnalysisContext(
        file_url=asset.url,
        file_hash=asset.content_hash,
        source_content=source,
    )
    prebuilt = _analyzer().analyze_prebuilt_ir(
        build_ir(parsed.ast, asset.url, asset.content_hash),
        context,
    )

    assert any(f.extracted_value == "/api/ir-partial" for f in standalone)
    assert any(f.extracted_value == "/api/ir-partial" for f in prebuilt)
    assert standalone_events == [event]
    assert context.metadata["analysis_incomplete"] == [event]
    assert asset.parse_errors == [
        "export scope analysis incomplete (ast node cap=8)",
    ]


def test_same_virtual_path_with_changed_content_changes_evidence_hash() -> None:
    analyzer = _analyzer()
    first = analyzer._analyze_one_virtual_source(
        "src/api.js",
        'fetch("/api/stable");',
        True,
    )
    second = analyzer._analyze_one_virtual_source(
        "src/api.js",
        'const revision = 2; fetch("/api/stable");',
        True,
    )
    first_endpoint = next(f for f in first if f.extracted_value == "/api/stable")
    second_endpoint = next(f for f in second if f.extracted_value == "/api/stable")

    assert first_endpoint.evidence.file_hash != second_endpoint.evidence.file_hash
    expected = hashlib.sha256(b'src/api.js\0fetch("/api/stable");').hexdigest()[:16]
    assert first_endpoint.evidence.file_hash == expected
    assert asset_analyzer_module._virtual_source_hash("src/api.js", "\ud800") != (
        asset_analyzer_module._virtual_source_hash("src/api.js", "\ud801")
    )


def test_generated_duplicate_keeps_one_finding_and_unions_all_source_locations() -> None:
    parent = _generated_endpoint("/api/shared")
    sources = _sourcemap(
        [
            ("src/z.js", '\n\nfetch("/api/shared");'),
            ("src/a.js", 'fetch("/api/shared");'),
        ]
    )

    virtual = _analyzer()._analyze_virtual_sources(sources, True, [parent])

    assert not any(f.extracted_value == "/api/shared" for f in virtual)
    occurrences = parent.metadata["source_occurrences"]
    assert parent.metadata["source_occurrences_total"] == 3
    assert {(item["kind"], item["file_url"], item["line"]) for item in occurrences} == {
        ("generated", "https://example.test/bundle.js", 7),
        ("virtual_source", "src/a.js", 1),
        ("virtual_source", "src/z.js", 3),
    }


def test_virtual_duplicate_output_and_provenance_are_source_order_invariant() -> None:
    entries = [
        ("src/z.js", '\nfetch("/api/duplicate");'),
        ("src/a.js", 'fetch("/api/duplicate");'),
    ]
    analyzer = _analyzer()

    forward = analyzer._analyze_virtual_sources(_sourcemap(entries), True)
    reverse = analyzer._analyze_virtual_sources(_sourcemap(list(reversed(entries))), True)

    forward_matches = [f for f in forward if f.extracted_value == "/api/duplicate"]
    reverse_matches = [f for f in reverse if f.extracted_value == "/api/duplicate"]
    assert len(forward_matches) == len(reverse_matches) == 1
    assert forward_matches[0].evidence.file_url == reverse_matches[0].evidence.file_url == "src/a.js"
    assert forward_matches[0].metadata["source_occurrences_total"] == 2
    assert _semantic_snapshot(forward) == _semantic_snapshot(reverse)


def test_provenance_cap_is_explicitly_disclosed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(asset_analyzer_module, "_MAX_SOURCE_OCCURRENCES", 1)
    events: list[dict[str, Any]] = []
    findings = _analyzer()._analyze_virtual_sources(
        _sourcemap(
            [
                ("src/a.js", 'fetch("/api/capped-occurrence");'),
                ("src/b.js", 'fetch("/api/capped-occurrence");'),
            ]
        ),
        True,
        incomplete_events=events,
    )
    finding = next(f for f in findings if f.extracted_value == "/api/capped-occurrence")

    assert finding.metadata["source_occurrences_total"] == 2
    assert len(finding.metadata["source_occurrences"]) == 1
    assert finding.metadata["source_occurrences_truncated"] is True
    assert any(
        event.get("component") == "virtual_source_provenance"
        and event.get("reason") == "occurrence_cap"
        for event in events
    )


@pytest.mark.asyncio
async def test_virtual_source_partial_report_is_serial_parallel_invariant(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = (
        "interface P { q: string }; const C = () => "
        "<div dangerouslySetInnerHTML={{__html: location.hash}} "
    )
    sourcemap = _sourcemap([("src/Broken.tsx", malformed)])

    async def run(parallel: bool) -> tuple[Any, ...]:
        config = Config(
            cache_dir=tmp_path,
            job_id=f"virtual-report-{str(parallel).lower()}",
            crawler=CrawlerConfig(use_headless=False),
            parser=ParserConfig(beautify=False, resolve_sourcemaps=False),
        )
        orchestrator = Orchestrator(config)
        orchestrator._seed_urls = ["https://example.test"]
        monkeypatch.setattr(orchestrator, "_persist_ast", _noop)
        monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
        monkeypatch.setattr(orchestrator, "_persist_report", _noop)
        if parallel:
            monkeypatch.setenv("BUNDLEINSPECTOR_PARALLEL", "2")
        else:
            monkeypatch.delenv("BUNDLEINSPECTOR_PARALLEL", raising=False)

        asset = _asset('fetch("/api/generated");')
        if not parallel:
            await orchestrator._stage_parse([asset])
        orchestrator._sourcemaps[asset.content_hash] = sourcemap
        findings = await orchestrator._stage_analyze([asset])
        report = await orchestrator._stage_report(
            orchestrator._seed_urls,
            [asset],
            findings,
            CorrelationGraph(),
        )
        issue_snapshot = sorted(
            (
                issue.code,
                issue.stage,
                issue.message,
                issue.details,
            )
            for issue in report.completeness.issues
        )
        finding_snapshot = sorted(
            (finding.rule_id, finding.value_type, finding.extracted_value)
            for finding in report.findings
        )
        return (
            report.completeness.status,
            issue_snapshot,
            finding_snapshot,
            sorted(asset.parse_errors),
        )

    serial = await run(False)
    parallel = await run(True)

    assert serial == parallel
    assert any(value == "/api/generated" for _, _, value in serial[2])
    assert any("virtual source" in error for error in serial[3])


@pytest.mark.asyncio
async def test_enrichment_failure_report_is_serial_parallel_invariant(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run(parallel: bool) -> tuple[Any, ...]:
        config = Config(
            cache_dir=tmp_path,
            job_id=f"enrichment-report-{str(parallel).lower()}",
            crawler=CrawlerConfig(use_headless=False),
            parser=ParserConfig(beautify=False, resolve_sourcemaps=False),
        )
        orchestrator = Orchestrator(config)
        orchestrator._seed_urls = ["https://example.test"]
        monkeypatch.setattr(orchestrator, "_persist_ast", _noop)
        monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
        monkeypatch.setattr(orchestrator, "_persist_report", _noop)
        if parallel:
            monkeypatch.setenv("BUNDLEINSPECTOR_PARALLEL", "2")
        else:
            monkeypatch.delenv("BUNDLEINSPECTOR_PARALLEL", raising=False)

        asset = _asset('fetch("/api/enrichment-report");')
        if not parallel:
            await orchestrator._stage_parse([asset])
        orchestrator._line_mappers[asset.content_hash] = _ExplodingLineMapper()
        findings = await orchestrator._stage_analyze([asset])
        report = await orchestrator._stage_report(
            orchestrator._seed_urls,
            [asset],
            findings,
            CorrelationGraph(),
        )
        return (
            report.completeness.status,
            sorted(
                (
                    issue.code,
                    issue.stage,
                    issue.message,
                    json.dumps(issue.details, sort_keys=True),
                )
                for issue in report.completeness.issues
            ),
            sorted(
                (finding.rule_id, finding.value_type, finding.extracted_value)
                for finding in report.findings
            ),
            sorted(asset.parse_errors),
        )

    serial = await run(False)
    parallel = await run(True)

    assert serial == parallel
    assert any(value == "/api/enrichment-report" for _, _, value in serial[2])
    assert {code for code, *_ in serial[1]} == {
        "asset_analysis_incomplete",
        "finding_enrichment_failed",
    }
    assert serial[3] == [
        "asset analysis incomplete (component=asset_enrichment; reason=failed)",
    ]
    assert "sensitive-enrichment-detail" not in json.dumps(serial)


@pytest.mark.asyncio
async def test_zero_finding_serial_analysis_still_projects_final_ir_partial(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(export_scopes, "_MAX_EXPORT_AST_NODES", 2)
    monkeypatch.delenv("BUNDLEINSPECTOR_PARALLEL", raising=False)
    source = 'const api = require("./api");'
    standalone_asset = _asset(source)
    standalone_events: list[dict[str, Any]] = []
    standalone_findings = _analyzer().analyze_asset_standalone(
        standalone_asset,
        None,
        None,
        standalone_events,
    )

    config = Config(
        cache_dir=tmp_path,
        job_id="zero-finding-ir-partial",
        crawler=CrawlerConfig(use_headless=False),
        parser=ParserConfig(beautify=False, resolve_sourcemaps=False),
    )
    orchestrator = Orchestrator(config)
    monkeypatch.setattr(orchestrator, "_persist_ast", _noop)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
    serial_asset = _asset(source)
    await orchestrator._stage_parse([serial_asset])
    serial_findings = await orchestrator._stage_analyze([serial_asset])

    assert standalone_findings == serial_findings == []
    assert standalone_events == [{
        "component": "intermediate_representation",
        "reason": "truncated",
        "partial_results": True,
    }]
    assert serial_asset.parse_errors == standalone_asset.parse_errors == [
        "export scope analysis incomplete (ast node cap=2)",
    ]
    ir_issue = next(
        issue for issue in orchestrator._completeness_issues if issue.code == "ir_truncated"
    )
    assert ir_issue.details == standalone_events[0]


@pytest.mark.parametrize(("count", "skipped"), [(1, 0), (2, 0), (3, 1)])
def test_virtual_source_count_budget_has_n_boundary_and_permutation_invariance(
    monkeypatch: pytest.MonkeyPatch,
    count: int,
    skipped: int,
) -> None:
    monkeypatch.setattr(asset_analyzer_module, "_MAX_VIRTUAL_SOURCES", 2)

    def run(entries: list[tuple[str, str]]) -> tuple[list[str], list[dict[str, Any]]]:
        analyzer = _analyzer()
        seen: list[str] = []

        def analyze_one(
            source_path: str,
            _content: str,
            _is_first_party: bool,
            *,
            incomplete_events: list[dict[str, Any]] | None = None,
        ) -> list[Finding]:
            assert incomplete_events is not None
            seen.append(source_path)
            return []

        monkeypatch.setattr(analyzer, "_analyze_one_virtual_source", analyze_one)
        events: list[dict[str, Any]] = []
        assert analyzer._analyze_virtual_sources(
            _sourcemap(entries),
            True,
            incomplete_events=events,
        ) == []
        return seen, events

    entries = [(f"src/{index}.js", f"const value = {index};") for index in range(count)]
    forward = run(entries)
    reverse = run(list(reversed(entries)))
    assert forward == reverse
    assert len(forward[0]) == count - skipped
    if skipped:
        assert forward[1] == [{
            "component": "virtual_source_analysis",
            "reason": "budget_exceeded",
            "partial_results": True,
            "source_count": count,
            "analyzed_count": 2,
            "skipped_count": skipped,
            "source_cap": 2,
            "byte_cap": asset_analyzer_module._MAX_VIRTUAL_SOURCE_BYTES,
            "analyzed_bytes": len("const value = 0;") + len("const value = 1;"),
        }]
    else:
        assert forward[1] == []
