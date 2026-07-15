"""Regression tests for the full-codebase re-audit fixes (BOM tolerance, recursion guards
on the other AST spines, ast_hash resume alignment, serial-analyze hardening).

Any token-like literals are fake sample values, not real secrets.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine

BOM = "﻿"


def _endpoints(src):
    r = parse_js(src)
    assert r.success
    ir = build_ir(r.ast, "f.js", "h")
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
    return sorted(f.extracted_value for f in eng.analyze(ir, ctx) if f.category.value == "endpoint")


# ------------------------------------------------------------------ BOM tolerance

def test_config_from_file_tolerates_bom(tmp_path):
    cf = tmp_path / "c.json"
    cf.write_text(BOM + json.dumps({"crawler": {"max_depth": 2}}), encoding="utf-8")
    assert Config.from_file(cf).crawler.max_depth == 2  # no crash


def test_cookie_file_tolerates_bom(tmp_path):
    from bundleInspector.core.cookie_import import import_cookies_from_file

    ck = tmp_path / "ck.json"
    ck.write_text(BOM + json.dumps([{"name": "sid", "value": "abc", "domain": "x"}]), encoding="utf-8")
    assert import_cookies_from_file(ck).get("sid") == "abc"


def test_custom_rule_file_tolerates_bom(tmp_path):
    from bundleInspector.rules.custom import _load_rule_data

    rf = tmp_path / "r.json"
    rf.write_text(BOM + json.dumps({"rules": []}), encoding="utf-8")
    assert _load_rule_data(rf) == {"rules": []}


# ------------------------------------------------------------------ recursion guards (other spines)

def test_endpoints_deep_boolean_chain_keeps_endpoints():
    # _resolve_bool_expr previously bypassed the depth guard; a deep &&/||/! chain in a
    # request-contract context would RecursionError and drop the whole endpoint finding.
    chain = "&&".join(f"a{i}" for i in range(800))
    vals = _endpoints(f'fetch("/api/orders",{{headers:{{x:{chain}}}}});fetch("/api/plain");')
    assert "/api/plain" in vals


def test_ir_builder_deep_ast_degrades_not_crashes():
    arr = "0"
    for _ in range(5000):
        arr = "[" + arr + "]"
    assert "/api/arr" in _endpoints(f'fetch("/api/arr");const z={arr};')


def test_route_detector_deep_ast_does_not_wipe_file():
    src = 'const r=createBrowserRouter([' + ('{path:"/a",children:[' * 400) + \
          '{path:"/admin"}' + (']}' * 400) + ']);fetch("/api/route-normal");'
    assert "/api/route-normal" in _endpoints(src)


def test_iter_nodes_iterative_matches_recursive_order():
    # routes._iter_nodes and custom._iter_nodes were converted to iterative; order must match.
    from bundleInspector.rules.detectors.routes import RouteDetector

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
    det = RouteDetector()
    assert [id(n) for n in det._iter_nodes(ast)] == list(recursive(ast))


# ------------------------------------------------------------------ ast_hash resume alignment

def test_local_ast_hash_matches_artifact_store_key():
    ast = parse_js('fetch("/x");const a={b:1};').ast
    canonical = json.dumps(ast, separators=(",", ":"), sort_keys=True)
    expected = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    # ArtifactStore.store_ast keys files by exactly this; the local parse stage must match.
    import inspect

    from bundleInspector.storage.artifact_store import ArtifactStore
    src = inspect.getsource(ArtifactStore.store_ast)
    assert 'json.dumps(ast, separators=(",", ":"), sort_keys=True)' in src
    # str(ast) hash must NOT equal it (the old, broken form).
    assert hashlib.sha256(str(ast).encode()).hexdigest()[:16] != expected


# ------------------------------------------------------------------ max_concurrent clamp

def test_download_semaphore_clamped_to_at_least_one():
    import inspect

    from bundleInspector.core.orchestrator import Orchestrator
    src = inspect.getsource(Orchestrator._stage_download)
    assert "max(1, self.config.crawler.max_concurrent)" in src


# ------------------------------------------------------------------ serial analyze hardening

@pytest.mark.asyncio
async def test_serial_analyze_survives_enrichment_failure(monkeypatch, tmp_path):
    """A per-asset enrichment failure in the DEFAULT serial analyze path must neither drop
    that asset's findings nor abort the scan."""
    from bundleInspector.core.orchestrator import Orchestrator
    from bundleInspector.parser.js_parser import JSParser
    from bundleInspector.storage.models import JSAsset

    cfg = Config()
    cfg.cache_dir = tmp_path
    insp = Orchestrator(cfg)

    a1 = JSAsset(url="https://x/a.js", content=b'fetch("/api/one");')
    a1.compute_hash()
    a2 = JSAsset(url="https://x/b.js", content=b'fetch("/api/two");')
    a2.compute_hash()
    for a in (a1, a2):
        insp._parse_results[a.content_hash] = JSParser(tolerant=True).parse(a.content.decode())
        a.parse_success = True

    # Enrichment blows up for EVERY asset -> findings must still be preserved + scan continues.
    monkeypatch.setattr(insp, "_annotate_finding_metadata",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(insp, "_store_checkpoint", _noop_async)

    findings = await insp._stage_analyze([a1, a2])
    vals = {f.extracted_value for f in findings}
    assert "/api/one" in vals and "/api/two" in vals  # both survived despite enrichment failure


async def _noop_async(*args, **kwargs):
    return None
