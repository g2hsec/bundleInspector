"""enh3: per-endpoint request contract + replayable PoC. Additive (endpoints unchanged),
secrets redacted by default."""

from bundleInspector.config import Config
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.reporter.poc import build_curl, build_fetch
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine


def _contracts(source: str):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    return [
        f
        for f in engine.analyze(ir, ctx)
        if f.value_type == "api_endpoint" and "request_contract" in f.metadata
    ]


def test_contract_fetch_bearer_json():
    c = _contracts(
        'const t=getToken(); fetch("https://api.acme.io/v1/users",{method:"POST",'
        'headers:{"Authorization":`Bearer ${t}`,"Content-Type":"application/json"},'
        'body:JSON.stringify({name:"x",age:30,active:true})});'
    )[0].metadata["request_contract"]
    assert c["method"] == "POST"
    assert c["auth"] == {"scheme": "bearer", "in": "header", "header": "Authorization"}
    assert c["body"]["kind"] == "json"
    assert c["body"]["shape"] == {"name": "string", "age": "number", "active": "boolean"}
    assert c["content_type"] == "application/json"


def test_contract_axios_create_default_header_merge():
    c = _contracts(
        'const api=axios.create({baseURL:"https://api.acme.io",headers:{"x-api-key":"KEY"}}); '
        'api.get("/orders",{params:{page:1,q:"a"}});'
    )[0].metadata["request_contract"]
    assert c["auth"]["scheme"] == "apikey"
    assert "x-api-key" in c["headers"]
    assert set(c["query_params"]) == {"page", "q"}


def test_contract_axios_post_arg_positions():
    c = _contracts(
        'axios.post("https://api.acme.io/v2/items",{sku:"S1",qty:2},'
        '{headers:{"X-Auth-Token":"T"},params:{dryRun:true}});'
    )[0].metadata["request_contract"]
    assert c["body"]["shape"] == {"sku": "string", "qty": "number"}
    assert c["auth"]["scheme"] == "apikey"
    assert c["query_params"] == {"dryRun": "boolean"}


def test_contract_urlencoded_body():
    c = _contracts(
        'fetch("/api/login",{method:"POST",'
        'headers:{"Content-Type":"application/x-www-form-urlencoded"},'
        'body:"user=admin&pass=secret"});'
    )[0].metadata["request_contract"]
    assert c["body"]["kind"] == "urlencoded"
    assert set(c["body"]["shape"]) == {"user", "pass"}


def test_contract_secret_redaction_default():
    c = _contracts(
        'fetch("https://api.acme.io/admin",{headers:{"Authorization":"Bearer AKIAIOSFODNN7EXAMPLE"}});'
    )[0].metadata["request_contract"]
    assert c["headers"]["Authorization"].startswith("<REDACTED")
    assert "AKIA" not in c["headers"]["Authorization"]  # raw secret never stored
    assert c["auth"] is not None  # presence signal kept


def test_no_contract_on_non_call_endpoints():
    result = parse_js('const p="/api/v1/orders"; new WebSocket("wss://h/socket");')
    ir = build_ir(result.ast, "f", "h")
    ctx = AnalysisContext(
        file_url="f",
        file_hash="h",
        source_content='const p="/api/v1/orders"; new WebSocket("wss://h/socket");',
    )
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    for f in engine.analyze(ir, ctx):
        if f.value_type in ("api_path", "websocket_url"):
            assert "request_contract" not in f.metadata


def test_poc_build_curl_and_fetch():
    c = _contracts(
        'fetch("https://api.acme.io/v1/users",{method:"POST",'
        'headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"x"})});'
    )[0].metadata["request_contract"]
    curl = build_curl(c)
    assert curl.startswith("curl -X POST")
    assert "Content-Type: application/json" in curl and '"name": "<string>"' in curl
    fetch = build_fetch(c)
    assert 'method: "POST"' in fetch and "JSON.stringify" in fetch


def test_poc_get_omits_method_and_body():
    c = _contracts('fetch("https://api.acme.io/v1/ping");')[0].metadata["request_contract"]
    assert build_fetch(c) == 'fetch("https://api.acme.io/v1/ping")'
    assert build_curl(c).startswith("curl '")  # no -X for GET
