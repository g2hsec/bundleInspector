"""Light-taint correlation: a file-upload surface (or upload/file endpoint) auto-connected to a
DOM src/href sink fed a file/image/upload-looking value, within the same asset -- the
`upload -> <img src>` stored/DOM-XSS chain surfaced as a TAINT correlation edge.
"""

from __future__ import annotations

from bundleInspector.config import Config
from bundleInspector.correlator.graph import Correlator
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine


def _correlate(src: str):
    ir = build_ir(parse_js(src).ast, "https://x/a.js", "h")
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    findings = eng.analyze(
        ir, AnalysisContext(file_url="https://x/a.js", file_hash="h", source_content=src)
    )
    graph = Correlator().correlate(findings)
    return findings, graph


def _taint_edges(graph):
    return [e for e in graph.edges if e.edge_type.value == "taint"]


UPLOAD_AND_SINK = """
var uploader = { allowedExt: ["jpg", "png"], maxSize: 1000 };
function render(item){ box.html(`<img src="${item.image_url}">`); }
"""


def test_taint_chain_links_upload_surface_to_img_src_sink():
    findings, graph = _correlate(UPLOAD_AND_SINK)
    taint = _taint_edges(graph)
    assert taint, "expected a taint correlation linking the upload surface to the img-src sink"
    fid = {f.id: f for f in findings}
    e = taint[0]
    src, tgt = fid[e.source_id], fid[e.target_id]
    assert src.category.value == "upload"
    assert tgt.category.value == "sink" and tgt.value_type in (
        "dom_attr_injection",
        "dom_attr_sink",
    )
    assert e.metadata.get("sink_source") == "item.image_url"
    assert "stored/DOM-XSS chain" in e.reasoning


def test_no_taint_without_an_upload_source():
    # Same sink, but no upload surface in the asset -> no chain to assemble.
    _, graph = _correlate('function render(item){ box.html(`<img src="${item.image_url}">`); }')
    assert _taint_edges(graph) == []


def test_no_taint_when_sink_value_is_not_media_like():
    # Upload surface present, but the dynamic attribute value is not file/image/response-like.
    src = 'var u = { allowedExt: ["jpg"] }; function f(cfg){ box.html(`<a href="${cfg.section}">x</a>`); }'
    _, graph = _correlate(src)
    assert _taint_edges(graph) == []


def test_taint_correlation_is_deterministic():
    findings, graph = _correlate(UPLOAD_AND_SINK)

    def sig(g, fs):
        return sorted(
            (e.source_id in {f.id for f in fs}, e.metadata.get("sink_source"))
            for e in _taint_edges(g)
        )

    graph2 = Correlator().correlate(findings)
    assert sig(graph, findings) == sig(graph2, findings)
