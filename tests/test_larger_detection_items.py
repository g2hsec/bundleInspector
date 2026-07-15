"""Regression locks for the larger detection-quality items (P13/G01/G02/G03/H01/H02/H03/H04).
Secret-like/URL values are fake samples used to verify behavior, not live data."""

from __future__ import annotations

from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)


def _ep(url, method, value_type="api_endpoint"):
    f = Finding(rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.LOW,
                confidence=Confidence.LOW, title="e", description="d", extracted_value=url,
                value_type=value_type, evidence=Evidence(file_url="f.js", file_hash="h", line=1))
    f.metadata["method"] = method
    return f


# ---------------------------------------------------------------- DQ-H01 dormant method-aware

def test_dqh01_declared_delete_not_exercised_by_observed_get():
    from bundleInspector.correlator.dormant import _HTTP_VALUE_TYPES, annotate_dormant_endpoints
    vt = sorted(_HTTP_VALUE_TYPES)[0]
    dele = _ep("/api/users/5", "DELETE", vt)
    gett = _ep("/api/users/5", "GET", vt)
    annotate_dormant_endpoints([dele, gett], [("GET", "/api/users/5")], primary_hosts=None)
    assert "dormant_endpoint" in dele.tags          # DELETE not exercised by a GET
    assert "dormant_endpoint" not in gett.tags      # GET exercised
    # a verbless observation (unknown method) credits any verb
    d2 = _ep("/api/users/5", "DELETE", vt)
    annotate_dormant_endpoints([d2], ["/api/users/5"], primary_hosts=None)
    assert "dormant_endpoint" not in d2.tags


# ---------------------------------------------------------------- DQ-H02 runtime surface method-aware

def test_dqh02_static_get_does_not_suppress_runtime_delete():
    from bundleInspector.correlator.runtime_surface import surface_runtime_endpoints
    findings = [_ep("/api/users/5", "GET")]
    added = surface_runtime_endpoints(findings, [("DELETE", "/api/users/5")], primary_hosts=None)
    assert added >= 1                               # distinct verb -> surfaced
    findings2 = [_ep("/api/users/5", "GET")]
    assert surface_runtime_endpoints(findings2, [("GET", "/api/users/5")], primary_hosts=None) == 0


# ---------------------------------------------------------------- DQ-H03/H04 scoring not neighbor-inflated

def test_dqh03_likelihood_is_neighbor_independent():
    from bundleInspector.classifier.scoring import ScoreCalculator
    sc = ScoreCalculator()
    f = Finding(rule_id="taint", category=Category.SINK, severity=Severity.HIGH,
                confidence=Confidence.HIGH, title="XSS", description="d", extracted_value=".innerHTML",
                evidence=Evidence(file_url="f.js", file_hash="h", line=1))
    vals = {sc.calculate_likelihood(f, cc) for cc in (0, 2, 6, 20)}
    assert len(vals) == 1                           # unrelated neighbors do not inflate likelihood


# ---------------------------------------------------------------- DQ-G01 import resolution

def test_dqg01_multi_segment_import_requires_path_tail():
    from bundleInspector.correlator.graph import Correlator
    c = Correlator()

    def matches(imp, target):
        return c._import_matches(c._normalize_import_source(imp), c._build_file_aliases(target))

    assert not matches("./admin/api", "https://x/public/api.js")   # FP fixed: basename-only link gone
    assert matches("./admin/api", "https://x/src/admin/api.js")    # genuine path-tail link kept
    # single-segment behavior unchanged
    assert matches("./api", "https://x/api.js")
    assert matches("api", "https://x/src/api.js")
    assert not matches("./auth", "https://x/oauth.js")             # boundary still enforced


# ---------------------------------------------------------------- DQ-G02 deterministic correlation

def test_dqg02_correlation_is_order_independent():
    from bundleInspector.correlator.graph import Correlator

    def mk(i):
        return Finding(rule_id=f"r{i % 3}", category=Category.ENDPOINT, severity=Severity.LOW,
                       confidence=Confidence.LOW, title=f"t{i}", description="d",
                       extracted_value=f"/api/x{i}",
                       evidence=Evidence(file_url="same.js", file_hash="h", line=i, column=0))

    fs = [mk(i) for i in range(60)]                 # 60 same-file findings -> hits the per-pass cap

    def edgeset(order):
        g = Correlator().correlate(list(order))
        return frozenset((e.source_id, e.target_id, e.edge_type.value) for e in g.edges)

    assert edgeset(fs) == edgeset(list(reversed(fs)))   # input order does not change the output
    assert edgeset(fs) == edgeset(fs)                   # deterministic across runs


# ---------------------------------------------------------------- DQ-G03 light-taint hint narrowing

def test_dqg03_taint_source_root_anchored_not_substring():
    from bundleInspector.correlator.graph import Correlator
    from bundleInspector.storage.models import EdgeType

    hints = set(Correlator._TAINT_SOURCE_HINTS)
    roots = set(Correlator._TAINT_SOURCE_ROOTS)
    assert not ({"url", "src", "path", "content"} & (hints | roots))   # generic property tokens excluded
    assert {"image", "img", "file", "upload"} <= hints                 # media tokens (substring)
    assert {"response", "data", "result"} <= roots                     # response roots (anchored)

    def edge(sink_source):
        src = _ep("/api/images/gallery", "GET")
        src.evidence.file_url = "same.js"
        sink = Finding(rule_id="dom-sink", category=Category.SINK, severity=Severity.HIGH,
                       confidence=Confidence.HIGH, title="s", description="d", extracted_value=".src",
                       value_type="dom_attr_sink", evidence=Evidence(file_url="same.js", file_hash="h", line=2))
        sink.metadata.update({"sink_attr": "src", "sink_source": sink_source})
        g = Correlator().correlate([src, sink])
        return sum(1 for e in g.edges if e.edge_type == EdgeType.TAINT)

    # canonical upload-response roots create the chain edge
    assert edge("${response.url}") and edge("${data.url}") and edge("${res.data}")
    # a benign identifier that merely CONTAINS a root token as a substring does not (root-anchored)
    assert not edge("${chartData}") and not edge("${searchResult}") and not edge("${dataset.value}")
    assert not edge("${cfg.cdnUrl}")


# ---------------------------------------------------------------- DQ-P13 parser/IR config flags wired

def test_dqp13_ir_extraction_flags_honored():
    from bundleInspector.config import ParserConfig
    from bundleInspector.parser.ir_builder import IRBuilder, build_ir
    from bundleInspector.parser.js_parser import parse_js

    src = 'import m from "./mod"; function outer(){ inner(); } function inner(){return 1;} const s="hi"; fetch("/api/x");'
    ast = parse_js(src).ast

    full = build_ir(ast, "f.js", "h")
    assert full.string_literals and full.function_calls and full.imports and full.call_graph

    assert build_ir(ast, "f.js", "h", extract_strings=False).string_literals == []
    assert build_ir(ast, "f.js", "h", extract_calls=False).function_calls == []
    assert build_ir(ast, "f.js", "h", extract_imports=False).imports == []
    assert not build_ir(ast, "f.js", "h", build_call_graph=False).call_graph

    # ParserConfig default is now honest (build_call_graph True) and from_parser_config threads it
    assert ParserConfig().build_call_graph is True
    ir = IRBuilder.from_parser_config(ParserConfig(extract_calls=False)).build(ast, "f.js", "h")
    assert ir.function_calls == [] and ir.string_literals


def test_dqp13_partial_on_error_flag_honored():
    from bundleInspector.parser.js_parser import parse_js
    broken = "function( {{{ not valid js"
    assert parse_js(broken, partial_on_error=True).partial          # best-effort partial (default)
    pr = parse_js(broken, partial_on_error=False)
    assert not pr.partial                                            # no partial fallback when off


# ================================================================ batch-5 adversarial-fix locks

def test_dqh01_defaulted_get_not_marked_dormant():
    # EndpointDetector defaults an unresolvable verb to GET; such an endpoint hit with POST at runtime
    # must NOT be marked dormant (a declared GET is matched path-only). A confident DELETE still is.
    from bundleInspector.correlator.dormant import _HTTP_VALUE_TYPES, annotate_dormant_endpoints
    vt = sorted(_HTTP_VALUE_TYPES)[0]
    g = _ep("/api/admin/purge", "GET", vt)          # verb was defaulted
    annotate_dormant_endpoints([g], [("POST", "/api/admin/purge")], primary_hosts=None)
    assert "dormant_endpoint" not in g.tags          # live endpoint, not a false dormant
    d = _ep("/api/users/5", "DELETE", vt)            # confident verb
    annotate_dormant_endpoints([d], [("GET", "/api/users/5")], primary_hosts=None)
    assert "dormant_endpoint" in d.tags              # DELETE not exercised by a GET (benefit kept)


def test_dqg01_directory_index_and_path_alias_recovered():
    from bundleInspector.correlator.graph import Correlator
    c = Correlator()

    def matches(imp, target):
        return c._import_matches(c._normalize_import_source(imp), c._build_file_aliases(target))

    assert matches("./x/y", "https://x/x/y/index.js")              # implicit directory-index
    assert matches("@/components/Button", "https://x/src/components/Button.js")  # path alias
    assert matches("~/utils/api", "https://x/src/utils/api.js")
    # the FP the fix targets stays fixed, and genuine/boundary cases unchanged
    assert not matches("./admin/api", "https://x/public/api.js")
    assert matches("./a/b/c", "https://x/a/b/c.js")
    assert not matches("./auth", "https://x/oauth.js")
