"""Regression tests for the five upgrades (recursion guard, runtime surfacing,
Chrome cookie decryption, local-pipeline unification, --fail-on gate).

Any token-like literals here are fake sample values, not real secrets.
"""

from __future__ import annotations

import sqlite3
import sys
from types import SimpleNamespace

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category


def _endpoints(src):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
    return [f for f in eng.analyze(ir, ctx) if f.category == Category.ENDPOINT]


# ------------------------------------------------------------------ Item 1: recursion budget

def test_deep_concat_does_not_zero_the_file():
    concat = "+".join(['"x"'] * 2000)
    src = f'fetch("/api/normal");fetch({concat});fetch("/api/second");'
    vals = {f.extracted_value for f in _endpoints(src)}
    assert "/api/normal" in vals and "/api/second" in vals  # no RecursionError, others kept


def test_deep_nested_object_does_not_crash():
    obj = "null"
    for _ in range(3000):
        obj = "{a:" + obj + "}"
    vals = {f.extracted_value for f in _endpoints(f'fetch("/api/obj");const z={obj};')}
    assert "/api/obj" in vals


def test_deep_nested_ast_walker_is_iterative():
    arr = "0"
    for _ in range(5000):
        arr = "[" + arr + "]"
    vals = {f.extracted_value for f in _endpoints(f'fetch("/api/arr");const z={arr};')}
    assert "/api/arr" in vals


def test_deep_logical_chain_in_nonhttp_pass_does_not_wipe_endpoints():
    # Adversarial-review gap: a deep left-nested ||/ternary/unary chain in a WebSocket/
    # GraphQL/URL context must not RecursionError-abort match() and wipe the file's plain
    # endpoints. The scalar/bool spine (_resolve_static_value) is depth-guarded AND every
    # match() pass is wrapped in try/except RecursionError.
    for expr in [
        "||".join(f'"s{i}"' for i in range(600)),
        "0" + "".join(f"?{i}:{i}" for i in range(400)),
        "!" * 600 + "x",
    ]:
        vals = {f.extracted_value
                for f in _endpoints(f'new WebSocket({expr});fetch("/api/plain-endpoint");')}
        assert "/api/plain-endpoint" in vals


def test_iter_nodes_order_matches_recursive_reference():
    # The iterative walker must yield the exact pre-order DFS of the recursive version.
    from bundleInspector.rules.detectors.endpoints import EndpointDetector

    def recursive(node):
        if not isinstance(node, dict):
            return
        yield id(node)
        for v in node.values():
            if isinstance(v, dict):
                yield from recursive(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        yield from recursive(it)

    ast = parse_js('const a={b:[1,{c:2}],d:fetch("/x")};function f(){return g("/y");}').ast
    det = EndpointDetector()
    assert [id(n) for n in det._iter_nodes_uncached(ast)] == list(recursive(ast))


# ------------------------------------------------------------------ Item 2: runtime surfacing

def test_runtime_surface_first_party_http_and_ws():
    from bundleInspector.correlator.runtime_surface import surface_runtime_endpoints

    findings = _endpoints('fetch("/api/known");')
    observed = {
        ("GET", "https://app.example.com/api/known"),         # dup of static -> skip
        ("POST", "https://app.example.com/api/dynamic/secret"),  # net-new first-party
        ("GET", "https://cdn.thirdparty.com/analytics/x"),    # third-party -> skip
    }
    ws = {"wss://app.example.com/socket/live"}
    n = surface_runtime_endpoints(findings, observed, ws, Config().rules,
                                  primary_hosts={"app.example.com"})
    assert n == 2
    runtime = {f.extracted_value for f in findings if "runtime-observed" in f.tags}
    assert "https://app.example.com/api/dynamic/secret" in runtime
    assert "wss://app.example.com/socket/live" in runtime
    assert not any("thirdparty" in v for v in runtime)
    assert not any("api/known" in v for v in runtime)


def test_runtime_surface_noop_without_observations():
    from bundleInspector.correlator.runtime_surface import surface_runtime_endpoints

    findings = _endpoints('fetch("/api/known");')
    before = len(findings)
    assert surface_runtime_endpoints(findings, set(), set(), Config().rules, primary_hosts=set()) == 0
    assert len(findings) == before


def test_headless_websocket_capture():
    from bundleInspector.collector.headless import HeadlessCollector
    from bundleInspector.config import CrawlerConfig

    c = HeadlessCollector(CrawlerConfig())
    c._on_websocket(SimpleNamespace(url="wss://app.example.com/live"))
    c._on_websocket(SimpleNamespace(url=""))            # ignored
    c._on_websocket(SimpleNamespace(url=None))          # ignored
    assert c.observed_websockets == {"wss://app.example.com/live"}


# ------------------------------------------------------------------ Item 3: Chrome cookie decrypt

def test_chromium_v10_decrypt_roundtrip():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from bundleInspector.core.cookie_import import _decrypt_chromium_value

    key = bytes(range(32))
    nonce = b"noncenonce12"
    value = "session=abc123"
    blob = b"v10" + nonce + AESGCM(key).encrypt(nonce, value.encode(), None)
    assert _decrypt_chromium_value(blob, key) == value


def test_chromium_decrypt_graceful_fallbacks():
    from bundleInspector.core.cookie_import import _decrypt_chromium_value

    assert _decrypt_chromium_value(b"", bytes(32)) is None
    assert _decrypt_chromium_value(b"v10" + b"x" * 30, None) is None          # no key
    assert _decrypt_chromium_value(b"v20" + b"x" * 30, bytes(32)) is None     # app-bound unsupported


def test_chromium_reader_still_reads_unencrypted(tmp_path):
    from bundleInspector.core.cookie_import import _read_chromium_cookies

    db = tmp_path / "Cookies"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE cookies (name TEXT, value TEXT, encrypted_value BLOB, host_key TEXT)")
    conn.execute("INSERT INTO cookies VALUES ('plain','plainval', NULL, 'app.example.com')")
    conn.commit()
    conn.close()
    assert _read_chromium_cookies(db).get("plain") == "plainval"


# ------------------------------------------------------------------ Item 5: unified local pipeline

def test_analyze_prebuilt_ir_delegation():
    from bundleInspector.core.asset_analysis import _build_analyzer

    analyzer = _build_analyzer(Config())
    src = 'import {x} from "./m"; fetch("/api/z");'
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
    findings = analyzer.analyze_prebuilt_ir(ir, ctx)
    assert findings
    ep = [f for f in findings if f.category == Category.ENDPOINT]
    assert ep
    # unified enrichment: import_bindings carry the richer scan-path fields
    ib = ep[0].metadata.get("import_bindings", [])
    assert any("scope" in b and "is_dynamic" in b for b in ib)


def test_analyze_prebuilt_ir_enrichment_failure_preserves_findings(monkeypatch):
    from bundleInspector.core.asset_analysis import _build_analyzer

    analyzer = _build_analyzer(Config())
    monkeypatch.setattr(analyzer, "_apply_mappings",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    ir = build_ir(parse_js('fetch("/api/x");').ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content='fetch("/api/x");')
    assert analyzer.analyze_prebuilt_ir(ir, ctx)  # not dropped despite enrichment failure


# ------------------------------------------------------------------ Item 6: --fail-on gate

def _report(*severities):
    return SimpleNamespace(
        findings=[SimpleNamespace(severity=SimpleNamespace(value=s)) for s in severities]
    )


def test_fail_on_gate_trips_at_or_above_threshold():
    from bundleInspector.cli import _apply_fail_on_gate

    with pytest.raises(SystemExit) as exc:
        _apply_fail_on_gate(_report("high", "low"), "high")
    assert exc.value.code == 2


def test_fail_on_gate_passes_below_threshold():
    from bundleInspector.cli import _apply_fail_on_gate

    _apply_fail_on_gate(_report("high", "low"), "critical")  # no critical -> no exit
    _apply_fail_on_gate(_report("low", "info"), "medium")    # nothing >= medium


def test_fail_on_gate_noop_when_unset():
    from bundleInspector.cli import _apply_fail_on_gate

    _apply_fail_on_gate(_report("critical"), None)  # unset -> never exits
