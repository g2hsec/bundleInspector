"""enh4: method-preserving dedup + IDOR/enumeration hints + method-flip candidates.
Additive: preserves every endpoint (hidden verbs surface as extra rows, never dropped)."""

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.classifier.scoring import ScoreCalculator
from bundleInspector.storage.models import Category, Severity, Confidence, Finding, Evidence


def _eps(source: str):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    return [f for f in engine.analyze(ir, ctx) if f.category == Category.ENDPOINT]


def test_method_split_preserves_all_verbs():
    eps = _eps("fetch('/api/item/1'); var x=new XMLHttpRequest(); x.open('DELETE','/api/item/1'); axios.post('/api/item/1',{});")
    methods = {f.metadata.get("method") for f in eps if f.extracted_value == "/api/item/1"}
    assert methods == {"GET", "DELETE", "POST"}   # url-only dedup used to collapse to one


def test_dedup_same_method_same_url_still_collapses():
    eps = _eps("fetch('/api/x'); fetch('/api/x');")
    assert len([f for f in eps if f.extracted_value == "/api/x"]) == 1


def test_literal_suppressed_by_http_same_path():
    eps = _eps("fetch('/api/x'); const p='/api/x';")
    assert len([f for f in eps if f.extracted_value == "/api/x"]) == 1


def test_idor_numeric_segment_tagged():
    f = [f for f in _eps("fetch('/api/users/123');") if f.extracted_value == "/api/users/123"][0]
    assert "idor_candidate" in f.tags
    assert f.metadata["idor_params"][0] == {"position": 3, "segment": "123", "type": "numeric", "value_type": "numeric"}
    assert f.severity == Severity.LOW


def test_idor_uuid_segment_tagged():
    f = [f for f in _eps("fetch('/api/orgs/550e8400-e29b-41d4-a716-446655440000/x');") if "orgs" in f.extracted_value][0]
    assert f.metadata["idor_inferred_type"] == "uuid"


def test_idor_template_param():
    # the endpoint resolver renders the expression as a ${...} placeholder, so the param name
    # is not recoverable -> type 'template', value_type inferred 'dynamic'.
    f = [f for f in _eps("const id=user.id; fetch(`/api/accounts/${id}/balance`);") if "accounts" in f.extracted_value][0]
    p = [p for p in f.metadata["idor_params"] if p["type"] == "template"][0]
    assert p["type"] == "template"


def test_idor_express_param():
    f = [f for f in _eps("axios.get('/api/:userId/x');") if ":userId" in f.extracted_value][0]
    assert f.metadata["idor_params"][0]["type"] == "named"


def test_idor_email_param():
    f = [f for f in _eps("axios.get('/api/lookup/john.doe@example.com');") if "lookup" in f.extracted_value][0]
    assert f.metadata["idor_inferred_type"] == "email"


def test_non_idor_endpoint_no_tag_stays_info():
    f = [f for f in _eps("fetch('/api/health');") if f.extracted_value == "/api/health"][0]
    assert "idor_candidate" not in f.tags and f.severity == Severity.INFO


def test_query_string_id_not_flagged():
    f = [f for f in _eps("fetch('/api/users?id=123');") if "users" in f.extracted_value][0]
    assert "idor_candidate" not in f.tags


def test_method_flip_excludes_observed():
    eps = _eps("fetch('/api/x'); axios.post('/api/x',{});")
    for f in eps:
        if f.extracted_value == "/api/x":
            assert set(f.metadata["method_flip"]) == {"PUT", "PATCH", "DELETE"}


def test_method_flip_full_set_when_only_get():
    f = [f for f in _eps("fetch('/api/only');") if f.extracted_value == "/api/only"][0]
    assert f.metadata["method_flip"] == ["POST", "PUT", "PATCH", "DELETE"]


def test_websocket_gets_idor_no_method_flip():
    f = [f for f in _eps("new WebSocket('wss://h/socket/7');") if "socket/7" in f.extracted_value][0]
    assert "idor_candidate" in f.tags and "method_flip" not in f.metadata


def test_multi_param_positions():
    # /api/... so it is detected; :org fails plain path-url validation only outside /api/.
    f = [f for f in _eps("axios.get('/api/orgs/:org/users/42');") if "orgs" in f.extracted_value][0]
    positions = {p["position"] for p in f.metadata["idor_params"]}
    assert positions == {3, 5}


def test_scoring_idor_likelihood_bump():
    ev = Evidence(file_url="f", file_hash="h", line=1, column=0)
    base = Finding(rule_id="e", category=Category.ENDPOINT, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                   title="t", description="d", evidence=ev, extracted_value="/api/x/1", value_type="api_endpoint")
    idor = base.model_copy(deep=True)
    idor.tags = ["idor_candidate"]
    sc = ScoreCalculator()
    assert sc.calculate_likelihood(idor) > sc.calculate_likelihood(base)
