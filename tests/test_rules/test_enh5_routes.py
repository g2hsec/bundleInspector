"""enh5: framework client route-map extraction. Reconstructs hidden pages from router config;
FP-guarded against SVG/asset/bare arrays; additive ENDPOINT findings."""

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.rules.context_filter import ContextFilter
from bundleInspector.storage.models import Category, Severity


def _routes(source: str):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    return [f for f in engine.analyze(ir, ctx) if f.value_type == "client_route"]


def _vals(source):
    return {f.extracted_value for f in _routes(source)}


def test_react_createbrowserrouter_nested_join():
    fs = _routes('const r=createBrowserRouter([{path:"/admin",element:A,children:['
                 '{path:"users",element:U},{path:"secret",lazy:()=>import("./AdminSecret")}]}]);')
    vals = {f.extracted_value for f in fs}
    assert {"/admin", "/admin/users", "/admin/secret"} <= vals
    secret = [f for f in fs if f.extracted_value == "/admin/secret"][0]
    assert secret.metadata["chunk"] == "./AdminSecret"


def test_react_router_sensitive_severity():
    fs = _routes('createBrowserRouter([{path:"/admin",element:A},{path:"/login",element:L}]);')
    admin = [f for f in fs if f.extracted_value == "/admin"][0]
    login = [f for f in fs if f.extracted_value == "/login"][0]
    assert admin.severity == Severity.MEDIUM and "hidden-candidate" in admin.tags
    assert login.severity == Severity.INFO


def test_compiled_jsx_route_and_svg_reject():
    assert "/x" in _vals('jsx(Route,{path:"/x",element:E});')
    assert _routes("jsx('path',{d:'M0 0L10 10'});") == []


def test_vue_createrouter_unwrap_and_framework():
    fs = _routes('createRouter({routes:[{path:"/dashboard",component:D,children:[{path:"settings",component:S}]}]});')
    vals = {f.extracted_value for f in fs}
    assert {"/dashboard", "/dashboard/settings"} <= vals
    assert all(f.metadata["framework"] == "vue" for f in fs)


def test_angular_forroot_relative_join_and_chunk():
    fs = _routes('RouterModule.forRoot([{path:"admin",loadChildren:()=>import("./admin/admin.module")}]);')
    admin = [f for f in fs if f.extracted_value == "/admin"][0]
    assert admin.metadata["chunk"] == "./admin/admin.module"


def test_generic_array_safetynet():
    assert "/hidden-report" in _vals('const R=[{path:"/hidden-report",element:X},{path:"/pub",element:Y}];fn(R);')


def test_generic_requires_strong_key():
    assert _routes('const cfg=[{path:"/x"},{path:"/y"}];') == []


def test_svg_and_asset_arrays_no_fp():
    assert _routes('const s=[{path:"M10 10L20 20"}];render(s);') == []
    assert _routes('const f=[{path:"/img/a.png",size:1},{path:"/js/app.js"}];') == []


def test_template_literal_path_placeholder():
    assert "/user/${...}" in _vals('createBrowserRouter([{path:`/user/${id}`,element:E}]);')


def test_partial_ast_noop():
    from bundleInspector.rules.detectors.routes import RouteDetector
    from bundleInspector.storage.models import IntermediateRepresentation
    ir = IntermediateRepresentation(file_url="f", file_hash="h", raw_ast=None)
    ctx = AnalysisContext(file_url="f", file_hash="h", source_content="")
    assert list(RouteDetector().match(ir, ctx)) == []


def test_registration_and_category():
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    route_rules = [r for r in engine.rules if r.id == "route-detector"]
    assert route_rules and route_rules[0].category == Category.ENDPOINT


def test_contextfilter_passthrough():
    fs = _routes('createBrowserRouter([{path:"/admin",element:A}]);')
    kept = ContextFilter().filter_findings(fs, None, "createBrowserRouter([{path:'/admin'}]);", "f")
    assert any(f.value_type == "client_route" for f in kept)
