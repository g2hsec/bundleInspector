"""DebugDetector must not flag ordinary user-facing routes ("/profile") or framework build assets
("/_next/...") as debug/hidden endpoints -- both were common MEDIUM false positives."""

from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.detectors.debug import DebugDetector


def _debug_findings(src):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
    return list(DebugDetector().match(ir, ctx))


def test_profile_route_not_flagged_as_profiler_endpoint():
    assert _debug_findings('var r = "/profile"; var s = "/user/profile";') == []
    # a genuine profiler/profiling route is STILL flagged
    assert any("profil" in f.extracted_value for f in _debug_findings('var r = "/profiler";'))


def test_framework_static_assets_not_flagged_hidden_endpoint():
    assert (
        _debug_findings('var a = "/_next/static/chunks/main.js"; var b = "/_nuxt/entry.js";') == []
    )
    # a genuine underscore-prefixed internal path is STILL flagged
    assert _debug_findings('var a = "/_internal/config";')
