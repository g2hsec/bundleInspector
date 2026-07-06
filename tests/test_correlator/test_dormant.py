"""enh2: dormant / hidden endpoint detection.

An endpoint declared in the JS bundle but never called during the headless crawl is
AJAX-reachable bypass surface. Purely additive (tags + raises severity of sensitive hidden
paths), FP-safe (no-op without an observation baseline; endpoints on uncontacted hosts are
left alone), and idempotent.
"""

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category, Severity
from bundleInspector.correlator.dormant import (
    annotate_dormant_endpoints,
    build_observed_index,
)


def _endpoints(source: str):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    return [f for f in engine.analyze(ir, ctx) if f.category == Category.ENDPOINT]


def _by_value(findings):
    return {f.extracted_value: f for f in findings}


def _dormant(f) -> bool:
    return "dormant_endpoint" in f.tags and f.metadata.get("dormant") is True


# --------------------------------------------------------------------------- build_observed_index

def test_index_accepts_strings_and_tuples():
    idx = build_observed_index([
        ("GET", "https://api.x.com/a/1"),
        "https://api.x.com/b",
        ("POST", "/c/2"),
    ])
    assert idx["hosts"] == {"api.x.com"}
    assert "/a/{id}" in idx["rel_paths"]
    assert "/b" in idx["rel_paths"]
    assert ("api.x.com", "/a/{id}") in idx["host_paths"]
    # relative observation has no host
    assert "/c/{id}" in idx["rel_paths"]


def test_index_normalizes_ids_uuid_hex():
    idx = build_observed_index([
        "https://h/u/550e8400-e29b-41d4-a716-446655440000",
        "https://h/o/deadbeefdeadbeefdeadbeef01",
        "https://h/n/12345",
    ])
    assert ("h", "/u/{id}") in idx["host_paths"]
    assert ("h", "/o/{id}") in idx["host_paths"]
    assert ("h", "/n/{id}") in idx["host_paths"]


# --------------------------------------------------------------------------- core dormancy

def test_relative_declared_not_called_is_dormant():
    fs = _endpoints('fetch("/api/v1/users"); fetch("/api/v1/admin/purge");')
    observed = {("GET", "https://app/api/v1/users")}
    n = annotate_dormant_endpoints(fs, observed, Config().rules)
    m = _by_value(fs)
    assert not _dormant(m["/api/v1/users"])           # was called
    assert _dormant(m["/api/v1/admin/purge"])         # never called
    assert n == 1


def test_id_normalized_call_is_not_dormant():
    fs = _endpoints('axios.get("/api/v1/orders/42");')
    observed = {("GET", "https://app/api/v1/orders/99")}  # different id, same route
    annotate_dormant_endpoints(fs, observed, Config().rules)
    assert not _dormant(_by_value(fs)["/api/v1/orders/42"])


def test_absolute_endpoint_on_observed_host():
    fs = _endpoints('fetch("https://api.acme.com/reports"); fetch("https://api.acme.com/health");')
    observed = {("GET", "https://api.acme.com/health")}
    annotate_dormant_endpoints(fs, observed, Config().rules)
    m = _by_value(fs)
    assert _dormant(m["https://api.acme.com/reports"])       # host contacted, path not
    assert not _dormant(m["https://api.acme.com/health"])    # exercised


def test_absolute_endpoint_on_uncontacted_host_is_not_flagged():
    # No baseline for third-party.example -> must NOT be flagged as hidden.
    fs = _endpoints('fetch("https://third-party.example/internal/secret"); fetch("/api/x");')
    observed = {("GET", "https://app.local/api/x")}
    annotate_dormant_endpoints(fs, observed, Config().rules)
    assert not _dormant(_by_value(fs)["https://third-party.example/internal/secret"])


def test_no_baseline_is_noop():
    fs = _endpoints('fetch("/api/v1/admin/purge");')
    assert annotate_dormant_endpoints(fs, set(), Config().rules) == 0
    assert not _dormant(_by_value(fs)["/api/v1/admin/purge"])


# --------------------------------------------------------------------------- severity + additivity

def test_sensitive_dormant_bumped_to_medium():
    fs = _endpoints('fetch("/internal/admin/console"); fetch("/api/loaded");')
    observed = {("GET", "https://app/api/loaded")}
    annotate_dormant_endpoints(fs, observed, Config().rules)
    hidden = _by_value(fs)["/internal/admin/console"]
    assert _dormant(hidden)
    assert hidden.metadata.get("dormant_sensitive") is True
    assert hidden.severity == Severity.MEDIUM


def test_non_sensitive_dormant_keeps_severity_but_tagged():
    fs = _endpoints('fetch("/api/v1/widgets"); fetch("/api/loaded");')
    observed = {("GET", "https://app/api/loaded")}
    before = _by_value(fs)["/api/v1/widgets"].severity
    annotate_dormant_endpoints(fs, observed, Config().rules)
    w = _by_value(fs)["/api/v1/widgets"]
    assert _dormant(w)
    assert w.severity == before             # not sensitive -> severity unchanged
    assert w.metadata.get("dormant_sensitive") is None


def test_severity_never_lowered_for_sensitive_dormant():
    # Simulate an already-HIGH finding (e.g. enh1-gated) that is also dormant+sensitive.
    fs = _endpoints('fetch("/internal/admin/purge");')
    f = _by_value(fs)["/internal/admin/purge"]
    f.severity = Severity.HIGH
    annotate_dormant_endpoints(fs, {("GET", "https://app/internal/admin/other")}, Config().rules)
    assert f.severity == Severity.HIGH      # bump target MEDIUM must not lower HIGH


def test_idempotent_no_double_tag():
    fs = _endpoints('fetch("/api/v1/admin/purge");')
    obs = {("GET", "https://app/api/other")}
    annotate_dormant_endpoints(fs, obs, Config().rules)
    annotate_dormant_endpoints(fs, obs, Config().rules)
    f = _by_value(fs)["/api/v1/admin/purge"]
    assert f.tags.count("dormant_endpoint") == 1


def test_config_disable_is_noop():
    cfg = Config()
    cfg.rules.dormant_endpoint_detection_enabled = False
    fs = _endpoints('fetch("/api/v1/admin/purge");')
    assert annotate_dormant_endpoints(fs, {("GET", "https://app/api/x")}, cfg.rules) == 0
    assert not _dormant(_by_value(fs)["/api/v1/admin/purge"])


def test_additive_never_drops_findings():
    fs = _endpoints('fetch("/api/a"); fetch("/api/b"); fetch("/api/c");')
    before = {f.extracted_value for f in fs}
    annotate_dormant_endpoints(fs, {("GET", "https://app/api/a")}, Config().rules)
    after = {f.extracted_value for f in fs}
    assert before == after
