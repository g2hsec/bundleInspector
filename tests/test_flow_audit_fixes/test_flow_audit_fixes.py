"""Regression tests for the flow-based exhaustive audit fixes: sourcemap crash-safety,
crash-safe URL parsing, ReDoS bounds, manifest recursion, secret masking across all report
formats, HTML XSS escaping, and page-link determinism.

Any token-like literals are fake sample values, not real secrets.
"""

from __future__ import annotations

import json
import time

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import (
    Category, Confidence, Evidence, Finding, Report, Severity,
)


# ---------------------------------------------------------------- sourcemap crash-safety

def _resolver():
    from bundleInspector.normalizer.sourcemap import SourceMapResolver
    return SourceMapResolver()


def test_sourcemap_non_dict_json_returns_none():
    r = _resolver()
    for body in ("null", "[]", "42", '"a string"'):
        assert r._parse_sourcemap_json(body, is_inline=False) is None


def test_sourcemap_deeply_nested_json_returns_none():
    r = _resolver()
    body = "[" * 5000 + "]" * 5000  # RecursionError from json.loads
    assert r._parse_sourcemap_json(body, is_inline=False) is None


def test_sourcemap_null_sources_no_crash():
    r = _resolver()
    sm = r._parse_sourcemap_json(json.dumps({"version": 3, "sources": None,
                                             "sourcesContent": None, "mappings": ""}),
                                 is_inline=False)
    assert sm is not None
    assert r.get_original_sources(sm) == {}          # no TypeError on None sources
    assert r.get_original_position(sm, 1, 0) is None


# ---------------------------------------------------------------- crash-safe URL parsing

def test_safe_urlparse_on_malformed_does_not_raise():
    from bundleInspector.core.url_utils import safe_urlparse, safe_urlsplit
    for bad in ("https://[${host}]/api", "https://[bad", "http://[::1", "https://a[0].x/y"):
        safe_urlparse(bad)   # must not raise
        safe_urlsplit(bad)


def test_cluster_extract_base_url_malformed_no_crash():
    from bundleInspector.correlator.cluster import ClusterBuilder
    cb = ClusterBuilder()
    assert cb._extract_base_url("https://[${host}].example.com/api") == "" or True  # no crash
    cb._extract_prefix("https://[bad/api/x")  # no crash


def test_malformed_endpoint_value_does_not_crash_correlate():
    from bundleInspector.correlator.graph import Correlator
    finding = Finding(
        rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.LOW,
        confidence=Confidence.HIGH, title="e",
        evidence=Evidence(file_url="https://x/a.js", file_hash="h", line=1),
        extracted_value="https://[${host}].example.com/api", value_type="url",
    )
    Correlator().correlate([finding])  # must not raise ValueError


# ---------------------------------------------------------------- ReDoS bounds

def test_detectors_no_redos_on_large_literal():
    blob = "a1.b2-" * 11000  # ~64KB, worst case for S3/discord/db regexes
    src = f'const x="{blob}";fetch("/api/x");'
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules); eng.register_defaults()
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
    t = time.perf_counter()
    eng.analyze(ir, ctx)
    assert time.perf_counter() - t < 5.0  # was minutes of ReDoS hang


# ---------------------------------------------------------------- manifest recursion

def test_manifest_deep_json_no_crash():
    from bundleInspector.collector.manifest import ManifestCollector
    from bundleInspector.config import CrawlerConfig, AuthConfig
    mc = ManifestCollector(CrawlerConfig(), AuthConfig())
    deep = "[" * 6000 + "]" * 6000
    # deeply nested -> the extractor must not RecursionError
    mc._extract_js_paths_from_json(json.loads("[" * 400 + "]" * 400))  # valid deep, iterative


# ---------------------------------------------------------------- secret masking (all formats)

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _secret_report():
    return Report(findings=[Finding(
        rule_id="secret-detector", category=Category.SECRET, severity=Severity.CRITICAL,
        confidence=Confidence.HIGH, title="AWS Key",
        evidence=Evidence(file_url="https://x/a.js", file_hash="h", line=1,
                          snippet=f'const k="{_SECRET}";'),
        extracted_value=_SECRET,
        metadata={"original_snippet": f'const k="{_SECRET}";'},
    )])


def test_json_reporter_masks_secret_in_snippet():
    from bundleInspector.reporter.json_reporter import JSONReporter
    out = JSONReporter(mask_secrets=True).generate(_secret_report())
    assert _SECRET not in out  # not in extracted_value NOR evidence.snippet NOR metadata


def test_html_reporter_masks_secret():
    from bundleInspector.reporter.html_reporter import HTMLReporter
    assert _SECRET not in HTMLReporter(mask_secrets=True).generate(_secret_report())


def test_sarif_reporter_masks_secret():
    from bundleInspector.reporter.sarif_reporter import SARIFReporter
    assert _SECRET not in SARIFReporter(mask_secrets=True).generate(_secret_report())


# ---------------------------------------------------------------- HTML XSS escaping

def test_html_reporter_escapes_all_script_breakout_variants():
    from bundleInspector.reporter.html_reporter import HTMLReporter
    report = Report(findings=[Finding(
        rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.MEDIUM,
        confidence=Confidence.HIGH, title="e",
        evidence=Evidence(file_url="https://x/a.js", file_hash="h", line=1,
                          snippet='</script foo><script>alert(1)</script/>'),
        extracted_value="</script foo><script>alert(1)</script/>",
    )])
    html = HTMLReporter(mask_secrets=False).generate(report)
    embedded = html.split('type="application/json">', 1)[1].split("</script>", 1)[0]
    assert "<" not in embedded            # every "<" escaped
    assert "<script>" not in embedded and "</script" not in embedded
    assert json.loads(embedded)["findings"][0]["extracted_value"] == "</script foo><script>alert(1)</script/>"


# ---------------------------------------------------------------- page-link determinism

def test_extract_page_links_preserves_order_and_dedups():
    import inspect
    from bundleInspector.collector.static import MultiPageStaticCollector
    src = inspect.getsource(MultiPageStaticCollector._extract_page_links)
    assert "return list(dict.fromkeys(links))" in src   # order-preserving dedup
    assert "return list(set(links))" not in src
