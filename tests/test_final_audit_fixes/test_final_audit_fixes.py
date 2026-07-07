"""Regression tests for the focused final-audit fixes: rate-limiter crash-safety,
scoring determinism, export_scopes deep-AST degradation, snippet-size cap (OOM),
and chunk_analyzer memory bound.
"""

from __future__ import annotations

import inspect

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import JSAsset


# ---------------------------------------------------------------- rate limiter

def test_rate_limiter_get_domain_survives_malformed_url():
    from bundleInspector.core.rate_limiter import AdaptiveRateLimiter, RateLimiter
    for cls in (AdaptiveRateLimiter, RateLimiter):
        rl = cls()
        for bad in ("https://cdn.example.com:99999/app.js",   # out-of-range port
                    "https://[${host}]/bundle.js",             # unbalanced bracket
                    "http://[::1"):
            rl._get_domain(bad)  # must not raise ValueError


def test_rate_limiter_negative_max_concurrent_no_crash():
    from bundleInspector.core.rate_limiter import RateLimiter
    RateLimiter(max_concurrent=-5)  # Semaphore(max(1,...)) -> no ValueError at construction


# ---------------------------------------------------------------- scoring determinism

def test_correlation_edges_iterate_sorted():
    # Edge selection under the max_edges cap must iterate SORTED sets so correlation counts
    # (and thus risk scores/tiers) are deterministic, not PYTHONHASHSEED-dependent.
    from bundleInspector.correlator import graph as graph_mod
    src = inspect.getsource(graph_mod)
    assert "for import_source in sorted(imports)" in src
    assert "for import_source in sorted(dynamic_imports)" in src


# ---------------------------------------------------------------- snippet cap (OOM)

def test_get_snippet_caps_long_lines():
    ctx = AnalysisContext(file_url="f.js", file_hash="h",
                          source_content="x" * 200000)  # one huge single line
    snippet, _ = ctx.get_snippet(1)
    assert len(snippet) < 1000  # not the whole 200KB line


def test_chunk_analyzer_large_minified_bounded_memory():
    # Many findings on a large single-line minified file must not each carry a multi-MB
    # snippet (the OOM). Every finding's snippet is bounded.
    src = "var x=" + ";".join(f'import("./chunk{i}")' for i in range(3000)) + ";"
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules); eng.register_defaults()
    findings = eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src))
    assert findings
    assert all(len(f.evidence.snippet) <= 520 for f in findings)


# ---------------------------------------------------------------- export_scopes deep-AST degradation

def test_deep_ast_annotation_degrades_not_crashes():
    from bundleInspector.core.asset_analysis import _build_analyzer
    chain = "0" + "".join(f"?a{i}:b{i}" for i in range(1200))  # very deep ternary chain
    src = f'const m=require("./x");const z={chain};fetch("/api/deep-annotate");'
    asset = JSAsset(url="https://x/a.js", content=src.encode()); asset.compute_hash()
    findings = _build_analyzer(Config()).analyze_asset_standalone(asset, None, None)
    vals = {f.extracted_value for f in findings if f.category.value == "endpoint"}
    assert "/api/deep-annotate" in vals  # no RecursionError crash; finding preserved


def test_normal_ast_annotation_metadata_intact():
    from bundleInspector.core.asset_analysis import _build_analyzer
    src = 'const m=require("./client");import {x} from "./m";fetch("/api/z");'
    asset = JSAsset(url="https://x/a.js", content=src.encode()); asset.compute_hash()
    findings = _build_analyzer(Config()).analyze_asset_standalone(asset, None, None)
    ep = [f for f in findings if f.category.value == "endpoint"][0]
    assert ep.metadata.get("imports")           # the try/except wrap didn't regress normal metadata
    assert ep.metadata.get("import_bindings")
