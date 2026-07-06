"""enh6: GraphQL operation + WebSocket message surface extraction. Additive (existing
endpoints unchanged); FP-guarded (res.send / JSON blobs produce nothing)."""

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine


def _find(source: str, value_type=None):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    out = list(engine.analyze(ir, ctx))
    return [f for f in out if value_type is None or f.value_type == value_type]


def test_graphql_gql_tag_named_operation():
    f = _find("const Q = gql`query GetUser($id: ID!) { user(id: $id) { id name } }`;", "graphql_operation")[0]
    assert f.metadata["operation_type"] == "query"
    assert f.metadata["operation_name"] == "GetUser"
    assert "user" in f.metadata["fields"]


def test_graphql_mutation():
    f = _find("const M = gql`mutation DeleteAccount { deleteAccount { ok } }`;", "graphql_operation")[0]
    assert f.metadata["operation_type"] == "mutation" and f.extracted_value == "mutation DeleteAccount"


def test_graphql_anonymous_shorthand():
    f = _find("const Q = gql`{ me { id } settings { theme } }`;", "graphql_operation")[0]
    assert f.metadata["operation_name"] == "" and f.metadata["fields"] == ["me", "settings"]


def test_graphql_fetch_body_coexists_with_endpoint():
    out = _find("fetch('/graphql',{method:'POST',body:JSON.stringify({query:'query Ping { ping }'})});")
    assert any(f.value_type == "api_endpoint" and f.extracted_value == "/graphql" for f in out)  # not suppressed
    assert any(f.value_type == "graphql_operation" and f.extracted_value == "query Ping" for f in out)


def test_graphql_alias_and_fragment_ignored():
    ops = _find("const Q = gql`query { a: user { id } admin { id } } fragment F on User { id }`;", "graphql_operation")
    assert len(ops) == 1
    assert ops[0].metadata["fields"] == ["user", "admin"]   # alias 'a' -> 'user'; fragment not emitted


def test_graphql_apollo_query_prop_plain():
    f = _find("client.query({ query: 'query Feed { feed { id } }' });", "graphql_operation")[0]
    assert f.extracted_value == "query Feed" and "feed" in f.metadata["fields"]


def test_graphql_rejects_json_and_urls():
    assert _find("const j = JSON.stringify({query:{a:1}}); const u = {query:'/api/search?q=1'};", "graphql_operation") == []


def test_ws_send_json_stringify_type():
    f = _find("const ws=new WebSocket('wss://h/s'); ws.send(JSON.stringify({type:'subscribe'}));", "ws_message")[0]
    assert f.extracted_value == "subscribe"
    assert f.metadata["message_key"] == "type" and f.metadata["transport"] == "websocket"


def test_ws_socketio_emit_event():
    msgs = _find("const socket=io('https://h'); socket.emit('chat:message',p); socket.emit('admin:impersonate',id);", "ws_message")
    names = {f.extracted_value for f in msgs}
    assert names == {"chat:message", "admin:impersonate"}
    assert all(f.metadata["transport"] == "socketio" for f in msgs)


def test_ws_enum_type_resolved():
    f = _find("const MT={PING:'ping'}; const ws=new WebSocket('wss://h/s'); ws.send(JSON.stringify({type:MT.PING}));", "ws_message")[0]
    assert f.extracted_value == "ping"


def test_ws_receiver_fp_guard():
    assert _find("res.send('ok'); response.send(html); bus.emit('internal-metric', 1);", "ws_message") == []


def test_ws_raw_string_send_confirmed_client():
    f = _find("const ws=new WebSocket('wss://h/s'); ws.send('ping');", "ws_message")
    assert f and f[0].metadata["message_key"] == "raw"
