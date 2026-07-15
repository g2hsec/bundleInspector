"""Regression locks for the contained High/Medium DQ backlog fixes (post P0-2).

Each test reproduces one audit item and asserts the fixed behavior. Secret-like values are fake
samples used to verify detection/masking and are not live credentials.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bundleInspector.config import Config, RuleConfig
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.custom import load_custom_rules
from bundleInspector.rules.detectors.debug import DebugDetector
from bundleInspector.rules.detectors.endpoints import EndpointDetector
from bundleInspector.rules.detectors.secrets import SecretDetector
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category, Confidence, Evidence, Finding, Report, Severity


def _ir_ctx(src: str):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    return ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src)


# ---------------------------------------------------------------- DQ-O06 enabled_categories

@pytest.mark.parametrize("cats", [[" Endpoint "], ["ENDPOINT"], ["endpoint"]])
def test_dqo06_enabled_categories_normalized(cats):
    """A stray space/capitalization must not silently disable a whole detection category."""
    eng = RuleEngine(RuleConfig(enabled_categories=cats))
    eng.register_defaults()
    ir, ctx = _ir_ctx('fetch("/api/users");')
    findings = eng.analyze(ir, ctx)
    assert any(f.category == Category.ENDPOINT for f in findings)


# ---------------------------------------------------------------- DQ-P12 dynamic import canonical

def test_dqp12_esprima_import_call_recorded_as_dynamic_import():
    """Esprima models `import(x)` as CallExpression(callee.type=='Import'); it must be recorded."""
    ir, _ = _ir_ctx('const m = import("./chunk-admin.js");')
    assert any(i.source == "./chunk-admin.js" and i.is_dynamic for i in ir.imports)


# ---------------------------------------------------------------- DQ-S03 webhook secret in path

def _secret_values(src: str):
    ir, ctx = _ir_ctx(src)
    return [f.extracted_value for f in SecretDetector().match(ir, ctx)]


def test_dqs03_slack_webhook_detected_plain_url_excluded():
    hook = "https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24
    assert any("hooks.slack.com" in v for v in _secret_values(f'const u="{hook}";'))
    # a plain scheme-URL without a path secret stays excluded (re-reported by domain/endpoint)
    assert _secret_values('const u="https://api.example.com/v1/users";') == []


# ---------------------------------------------------------------- DQ-S05 date/version anchor

def test_dqs05_version_or_date_prefixed_secret_not_excluded():
    # a secret that merely STARTS with a version/date must still be detected (entropy path)
    assert _secret_values('const k="1.2.3abcdefghijklmnopqrstuvwxyz0123456789";')
    assert _secret_values('const k="2024-01-15abcdefghijklmnopqrstuvwxyz0123";')
    # a legit version / date literal stays excluded
    assert _secret_values('const v="1.2.3"; const w="v2.10.4-beta"; const d="2024-01-15";') == []


@pytest.mark.parametrize("ver", [
    "15.0.0-canary.abc123def456789012345",   # Next.js canary
    "1.2.3+sha.5114f85abcdef0123456789",     # SemVer build metadata
    "1.0.0-next.20240115094523771",          # timestamped prerelease
    "18.3.0-canary-a1b2c3d4e5f6-20240607",   # React canary
])
def test_dqs05_multi_segment_version_still_excluded(ver):
    """The end-anchor must still allow REPEATED pre-release/build segments so real multi-segment
    SemVer is not reported as a secret (adversarial regression)."""
    assert _secret_values(f'const v="{ver}";') == []


# ---------------------------------------------------------------- DQ-E05 new Request method

def test_dqe05_new_request_method_recovered():
    ir, ctx = _ir_ctx('fetch(new Request("/api/users", {method:"DELETE"}));')
    methods = [(f.extracted_value, (f.metadata or {}).get("method")) for f in EndpointDetector().match(ir, ctx)]
    assert ("/api/users", "DELETE") in methods


# ---------------------------------------------------------------- DQ-E07 GraphQL truncation

def test_dqe07_graphql_flat_siblings_and_op_cap():
    det = EndpointDetector()
    ops = det._parse_graphql_document("query Me { id name email role createdAt }")
    assert ops and ops[0]["fields"] == ["id", "name", "email", "role", "createdAt"]
    many = " ".join(f"query Q{i} {{ f{i} }}" for i in range(20))
    assert len(det._parse_graphql_document(many)) == 20  # was capped at 16
    # field-level directives must NOT be captured as sibling fields (adversarial regression)
    ops2 = det._parse_graphql_document("query D { user @include(if:true) name @skip(if:false) email }")
    assert ops2[0]["fields"] == ["user", "name", "email"]


# ---------------------------------------------------------------- DQ-D04 debugger FP

def _has_debugger(src: str) -> bool:
    ir, ctx = _ir_ctx(src)
    return any(f.value_type == "debugger_statement" for f in DebugDetector().match(ir, ctx))


def test_dqd04_debugger_precision():
    assert _has_debugger("function f(){ debugger; }")          # real statement
    assert not _has_debugger("var x=1; // debugger")            # trailing line comment
    assert not _has_debugger("var re = /debugger/;")           # regex literal
    assert not _has_debugger("var x; /* debugger */ var y;")   # block comment
    # a real debugger right after a CLOSED block comment `*/` must NOT be swallowed by the
    # regex-literal guard (adversarial regression)
    assert _has_debugger("x=1;/**/debugger;")


# ---------------------------------------------------------------- DQ-P09 line-mapping column

def test_dqp09_line_mapper_is_column_aware():
    from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping
    m = LineMapper()
    # two callsites on the same normalized line 1, different columns -> different original lines
    m.add_mapping(LineMapping(original_line=10, original_column=0, normalized_line=1, normalized_column=0))
    m.add_mapping(LineMapping(original_line=20, original_column=0, normalized_line=1, normalized_column=40))
    assert m.get_original(1, 5)[0] == 10     # near column 0 -> first mapping
    assert m.get_original(1, 50)[0] == 20    # past column 40 -> second mapping
    assert m.get_original(1, 0)[0] == 10     # column 0 preserves leftmost (backward compatible)


def test_dqp09_sourcemap_url_picks_last_pragma():
    from bundleInspector.normalizer.sourcemap import SourceMapResolver
    js = "//# sourceMappingURL=stale.js.map\ncode();\n//# sourceMappingURL=real.js.map\n"
    assert SourceMapResolver().find_sourcemap_url(js) == "real.js.map"


# ---------------------------------------------------------------- DQ-O15 reporter non-mutation

def _secret_report() -> Report:
    secret = "sk_live_" + "a" * 32
    return Report(findings=[Finding(
        rule_id="secret-detector", category=Category.SECRET, severity=Severity.HIGH,
        confidence=Confidence.HIGH, title="Secret",
        evidence=Evidence(file_url="f", file_hash="h", line=1, snippet=f'k="{secret}"'),
        extracted_value=secret, value_type="stripe_secret_key",
    )])


def test_dqo15_html_reporter_does_not_mutate_shared_report():
    from bundleInspector.reporter.html_reporter import HTMLReporter
    report = _secret_report()
    raw = report.findings[0].extracted_value
    HTMLReporter().generate(report)
    assert report.findings[0].extracted_value == raw  # caller's Report untouched


def test_dqo15_sarif_reporter_does_not_mutate_shared_report():
    from bundleInspector.reporter.sarif_reporter import SARIFReporter
    report = _secret_report()
    raw = report.findings[0].extracted_value
    SARIFReporter().generate(report)
    assert report.findings[0].extracted_value == raw


# ---------------------------------------------------------------- DQ-R04 one bad rule keeps the pack

def test_dqr04_one_invalid_custom_rule_does_not_abort_pack(tmp_path: Path):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps({"rules": [
        {"id": "bad-regex", "title": "bad", "category": "endpoint", "severity": "low",
         "confidence": "low", "matcher": {"type": "regex", "pattern": "("}},  # uncompilable regex
        {"id": "good-rule", "title": "good", "category": "endpoint", "severity": "low",
         "confidence": "low", "matcher": {"type": "regex", "pattern": "/api/good"}},
    ]}), encoding="utf-8")
    rules = load_custom_rules(rules_file)
    ids = {getattr(r, "id", getattr(getattr(r, "spec", None), "id", None)) for r in rules}
    assert "good-rule" in ids   # the valid rule survives the invalid one


# ---------------------------------------------------------------- DQ-O19 shipped default.yml loads

def test_dqo19_shipped_default_config_loads():
    path = Path(__file__).resolve().parents[1] / "examples" / "yaml-configs" / "default.yml"
    cfg = Config.from_file(path)
    assert cfg.crawler.max_depth >= 0
    assert cfg.rules.enabled_categories  # non-empty


# ---------------------------------------------------------------- DQ-D03 domain staging FP

def test_dqd03_staging_prefix_not_matched_on_filename():
    from bundleInspector.rules.detectors.domains import DomainDetector

    def _domains(src):
        ir, ctx = _ir_ctx(src)
        return [f.extracted_value for f in DomainDetector().match(ir, ctx)]

    assert _domains('const f="test-data.csv";') == []              # filename, not a staging host
    assert _domains('const f="dev-config.json";') == []            # filename
    assert "staging.example.com" in _domains('const u="https://staging.example.com/x";')  # real host still flagged
    # a real internal/staging HOST whose PATH ends in an asset extension must STILL be flagged
    # (the extension check applies to the host, not the URL path) -- adversarial regression
    assert "staging.example.com" in _domains('const u="https://staging.example.com/main.js";')
    assert "dev.internal.corp" in _domains('const u="https://dev.internal.corp/app.css";')
    assert "dev.internal" in _domains('const h="dev.internal";')   # bare internal host still flagged


# ---------------------------------------------------------------- DQ-E03 non-HTTP receiver

def test_dqe03_cache_get_not_high_http_endpoint():
    def _eps(src):
        ir, ctx = _ir_ctx(src)
        return [(f.confidence.value, f.value_type) for f in EndpointDetector().match(ir, ctx)
                if "/api/users" in (f.extracted_value or "")]

    # cache.get is NOT an HTTP call -> not reported as a HIGH api_endpoint (method call)
    assert all(vt != "api_endpoint" for _, vt in _eps('cache.get("/api/users");'))
    # a real HTTP client IS still HIGH
    assert ("high", "api_endpoint") in _eps('axios.get("/api/users");')


# ---------------------------------------------------------------- DQ-E08 socket provenance

def test_dqe08_requires_socket_client_provenance():
    def _ws(src):
        ir, ctx = _ir_ctx(src)
        return [f.confidence.value for f in EndpointDetector().match(ir, ctx) if f.value_type == "ws_message"]

    assert _ws('channel.emit("userUpdate", data);') == []                               # EventEmitter-like only
    assert "high" in _ws('const ws=new WebSocket("wss://x"); ws.emit("userUpdate", data);')  # verified client -> HIGH


# ---------------------------------------------------------------- DQ-O07 config validation fails closed

def test_dqo07_config_rejects_out_of_range_values():
    from pydantic import ValidationError

    from bundleInspector.config import CrawlerConfig, OutputConfig, RuleConfig

    Config()  # defaults still valid
    for bad in (
        lambda: CrawlerConfig(max_depth=-5),
        lambda: CrawlerConfig(max_concurrent=0),
        lambda: CrawlerConfig(rate_limit=-3.0),
        lambda: RuleConfig(entropy_threshold=float("nan")),
        lambda: RuleConfig(entropy_threshold=float("inf")),
        lambda: OutputConfig(min_severity="banana"),
        lambda: OutputConfig(min_risk_tier="P99"),
    ):
        with pytest.raises(ValidationError):
            bad()
    # valid edge values still accepted (and normalized)
    assert CrawlerConfig(max_depth=0).max_depth == 0
    assert OutputConfig(min_severity="HIGH").min_severity == "high"
    assert OutputConfig(min_risk_tier="p0").min_risk_tier == "P0"


# ---------------------------------------------------------------- DQ-O13 config secret redaction

def test_dqo13_config_secrets_redacted():
    from bundleInspector.config import AuthConfig, redact_config_secrets
    d = Config(auth=AuthConfig(
        bearer_token="SECRETTOKEN123", cookies={"session": "SECRETCOOKIE"},
        headers={"Authorization": "Bearer XYZ", "X-Custom": "ok"},
    )).to_dict()
    red = redact_config_secrets(d)
    blob = json.dumps(red)
    assert "SECRETTOKEN123" not in blob and "SECRETCOOKIE" not in blob and "Bearer XYZ" not in blob
    assert red["auth"]["headers"]["X-Custom"] == "ok"       # non-sensitive header preserved
    assert "SECRETTOKEN123" in json.dumps(d)                # the raw dict is untouched (resume sig stable)


# ---------------------------------------------------------------- DQ-O14 non-UTF8 asset serialization

def test_dqo14_non_utf8_asset_does_not_crash_reporters():
    from bundleInspector.reporter.html_reporter import HTMLReporter
    from bundleInspector.reporter.json_reporter import JSONReporter
    from bundleInspector.storage.models import JSAsset
    report = Report(assets=[JSAsset(url="f", content_hash="h", content=b"\xff\xfe not utf8")])
    JSONReporter().generate(report)   # must not raise UnicodeDecodeError
    HTMLReporter().generate(report)


# ---------------------------------------------------------------- DQ-O16 SARIF execution + fingerprint

def test_dqo16_sarif_execution_and_stable_fingerprint():
    from bundleInspector.reporter.sarif_reporter import SARIFReporter

    def _finding():
        return Finding(rule_id="taint", category=Category.SINK, severity=Severity.HIGH,
                       confidence=Confidence.HIGH, title="t",
                       evidence=Evidence(file_url="x/app.js", file_hash="h", line=10),
                       extracted_value=".html()")

    sar_err = json.loads(SARIFReporter().generate(Report(findings=[_finding()], errors=["crawl failed"])))
    inv = sar_err["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False                  # errors -> not successful
    assert inv["toolExecutionNotifications"]                     # surfaced, not empty
    # fingerprint is deterministic across runs (was a per-run uuid)
    fp1 = json.loads(SARIFReporter().generate(Report(findings=[_finding()])))["runs"][0]["results"][0]["fingerprints"]["primaryLocationLineHash"]
    fp2 = json.loads(SARIFReporter().generate(Report(findings=[_finding()])))["runs"][0]["results"][0]["fingerprints"]["primaryLocationLineHash"]
    assert fp1 == fp2


# ---------------------------------------------------------------- DQ-R05 shipped debug rule pack

def test_dqr05_shipped_debug_rule_matches_slash_paths():
    path = Path(__file__).resolve().parents[1] / "examples" / "yaml-configs" / "rulesets" / "meta.yml"
    eng = RuleEngine(RuleConfig(custom_rules_file=path))
    eng.register_defaults()
    ir, ctx = _ir_ctx('fetch("/admin"); go("/health");')
    findings = eng.analyze(ir, ctx)
    assert any((f.metadata or {}).get("debug_path") in ("/admin", "/health")
               or "/admin" in (f.extracted_value or "") or "/health" in (f.extracted_value or "")
               for f in findings)


# ---------------------------------------------------------------- DQ-R01 custom-rule regex match cap

def test_dqr01_bounded_matches_caps_and_yields_all_under_cap():
    """A pathological zero-width/backtracking pattern must not emit unbounded results; a normal
    match count under the cap must pass through unchanged."""
    from bundleInspector.rules import custom as C

    orig = C._MAX_MATCHES_PER_RULE
    try:
        C._MAX_MATCHES_PER_RULE = 3
        capped = list(C._bounded_matches(iter(range(100)), "rule-x"))
        assert capped == [0, 1, 2]                       # truncated at the cap
    finally:
        C._MAX_MATCHES_PER_RULE = orig
    assert list(C._bounded_matches(iter(range(5)), "rule-x")) == [0, 1, 2, 3, 4]  # under cap: all


def test_dqr01_custom_rule_finditer_is_bounded():
    """The custom regex rule's source scan is wrapped by the cap (guards a runaway pattern)."""
    import inspect

    from bundleInspector.rules import custom as C

    src = inspect.getsource(C)
    # every finditer over source/literals is routed through the bounded wrapper
    assert "_bounded_matches(self._pattern.finditer(literal.value)" in src
    assert "_bounded_matches(self._pattern.finditer(source)" in src


# ---------------------------------------------------------------- DQ-R02 constant-table fixpoint depth

def test_dqr02_constant_table_resolves_deep_alias_chain():
    """A linear alias chain deeper than the old fixed 5 passes must still fully resolve."""
    from bundleInspector.rules.custom import _build_constant_table

    chain = "const a=b;const b=c;const c=d;const d=e;const e=f;const f=g;const g='DEEP';"
    table = _build_constant_table(parse_js(chain).ast)
    assert table.get("a") == "DEEP"


def test_dqr02_constant_table_pass_count_is_bounded():
    """Pass count is capped so a huge/adversarial file cannot spin, but never below the prior bound."""
    from bundleInspector.rules.custom import _MAX_CONSTANT_TABLE_PASSES, _build_constant_table

    # empty program: no declarators -> converges immediately, no crash
    assert _build_constant_table(parse_js("var x = 1;").ast) is not None
    assert _MAX_CONSTANT_TABLE_PASSES >= 5           # never regress below the previous fixed bound


def test_dqr02_no_regression_on_low_declarator_shadow_chain():
    """Adversarial: an object member-path shadow-chain needs more passes than the declarator count.
    A pass bound keyed off declarator count under-resolved it vs the old fixed 5 passes; the cap must
    key off passes alone so this fully resolves (zero regression)."""
    from bundleInspector.rules.custom import _build_constant_table

    # single declarator (count=1), 3-hop chain through sibling member paths
    t1 = _build_constant_table(parse_js('var A = { a1: A.a0, a2: A.a1, a0: "SECRET" };').ast)
    assert t1.get("A.a2") == "SECRET"
    # 4-hop with a cross-declarator alias
    t2 = _build_constant_table(
        parse_js('var A = { a1: A.a0, a2: A.a1, a3: A.a2, a0: "S" }; var b = a3ref; var a3ref = A.a3;').ast
    )
    assert t2.get("b") == "S"


def test_dqr02_destructuring_fixpoint_converges_early(monkeypatch):
    """Adversarial: the destructuring bind helpers report `changed` even when they re-bind an
    already-known value; convergence must key off the accumulator so `const {a}=...` does not burn
    all _MAX_CONSTANT_TABLE_PASSES passes on every bundle that uses destructuring."""
    from bundleInspector.rules import custom as C

    passes = {"n": 0}
    real_iter = C._iter_nodes

    def counting_iter(ast):
        passes["n"] += 1
        return real_iter(ast)

    monkeypatch.setattr(C, "_iter_nodes", counting_iter)
    for src in ('const {a}={a:"x"};', 'const [a]=["x"];', 'const {a,b,c}={a:"1",b:"2",c:"3"};',
                'const {a:{b}}={a:{b:"x"}};'):
        passes["n"] = 0
        table = C._build_constant_table(parse_js(src).ast)
        assert passes["n"] < C._MAX_CONSTANT_TABLE_PASSES     # converged, not stuck at the cap
        assert passes["n"] <= 3                               # in fact settles in ~2 passes
        assert table is not None
    # values still resolve correctly after the convergence fix
    vals = C._build_constant_table(parse_js('const {a,b}={a:"1",b:"2"};').ast)
    assert vals.get("a") == "1" and vals.get("b") == "2"


# ---------------------------------------------------------------- DQ-D08 chunk-analyzer comment/route FP

def _chunk_findings(src: str):
    from bundleInspector.parser.chunk_analyzer import ChunkAnalyzer
    ir, ctx = _ir_ctx(src)
    return list(ChunkAnalyzer().match(ir, ctx))


def test_dqd08_commented_route_not_reported():
    """A commented-out route config (line and block) must not surface as a live route."""
    line_c = _chunk_findings('const x=1;\n// { path: "/admin-secret" }\nconst y=2;')
    assert not any("admin-secret" in (f.extracted_value or "") for f in line_c)
    block_c = _chunk_findings('const x=1; /* path: "/hidden-panel" */ const y=2;')
    assert not any("hidden-panel" in (f.extracted_value or "") for f in block_c)


def test_dqd08_live_route_still_reported_and_url_in_string_preserved():
    """A real route is still found; a URL inside a sibling string is not mis-parsed as a comment."""
    src = 'const r=[{ path: "/admin", url: "https://api.example.com" },{ path: "/dashboard" }];'
    found = _chunk_findings(src)
    routes = {f.extracted_value for f in found if f.value_type == "route_path"}
    assert "/admin" in routes and "/dashboard" in routes


def test_dqd08_file_path_config_rejected_as_route():
    """A generic `path:` value that is actually a file path must not be reported as a route."""
    found = _chunk_findings('const c={ path: "src/index.js" };')
    assert not any(f.value_type == "route_path" for f in found)


def test_dqd08_route_path_confidence_is_medium():
    """A bare `path:` match is weaker evidence than an explicit import target -> MEDIUM."""
    found = _chunk_findings('const c={ path: "/settings" };')
    rp = [f for f in found if f.value_type == "route_path"]
    assert rp and all(f.confidence == Confidence.MEDIUM for f in rp)


def test_dqd08_webpack_magic_comment_preserved():
    """The dynamic-import scan keeps block comments so webpack magic names still parse."""
    found = _chunk_findings('import(/* webpackChunkName: "adminChunk" */ "./AdminPage");')
    assert any(f.value_type == "webpack_named_chunk" for f in found)


def test_dqd08_regex_literal_not_masked_as_comment():
    """Adversarial: a regex literal with an escaped slash (/\\/\\//g, common in URL-normalization)
    forms an apparent `//` that must NOT be read as a line comment -- otherwise it blanks the rest of
    a minified single-line bundle and drops every following route (INV-01 false negative)."""
    src = 'var u=s.replace(/\\/\\//g,"/");var routes=[{path:"/admin"},{path:"/dashboard"},{path:"/settings"}];'
    routes = {f.extracted_value for f in _chunk_findings(src) if f.value_type == "route_path"}
    assert {"/admin", "/dashboard", "/settings"} <= routes
    # keyword-position regex (return /.../) and char-class regex /[/]/ must also not swallow routes
    r_kw = {f.extracted_value for f in _chunk_findings(
        'function f(){ return /x\\/\\//.test(y); } const c={ path:"/kw" };') if f.value_type == "route_path"}
    assert "/kw" in r_kw
    r_cls = {f.extracted_value for f in _chunk_findings(
        'const re=/[/]/; const c={ path:"/panel" };') if f.value_type == "route_path"}
    assert "/panel" in r_cls


def test_dqd08_division_and_comment_still_masked():
    """A `/` after an operand is division (not a regex), so a following `//` comment is still a
    comment and its commented-out route is still suppressed."""
    src = 'var a=b/c; // path:"/nope"\n var d={ path:"/yes" };'
    routes = {f.extracted_value for f in _chunk_findings(src) if f.value_type == "route_path"}
    assert routes == {"/yes"}


def test_dqd08_nested_template_literal_not_desynced():
    """Adversarial: a nested template literal inside `${ ... }` whose inner text contains `//`
    (protocol-relative URL / doubled slash) must not desync the masker into treating the inner
    backtick as the outer terminator -- otherwise the `//` reads as a comment and blanks the rest
    of a minified line, dropping every following route (INV-01 false negative)."""
    bt = "`"
    src = ('const link = ' + bt + '<a href="${' + bt + '//${host}/api' + bt + '}">x</a>' + bt +
           '; const routes=[{path:"/admin/users"},{path:"/settings"}];')
    routes = {f.extracted_value for f in _chunk_findings(src) if f.value_type == "route_path"}
    assert routes == {"/admin/users", "/settings"}
    # an object literal inside the interpolation keeps its braces balanced; a route follows
    src2 = 'const s = ' + bt + 'x${ {a:1} }y' + bt + '; const c={ path:"/panel" };'
    assert {f.extracted_value for f in _chunk_findings(src2) if f.value_type == "route_path"} == {"/panel"}
    # a comment INSIDE the interpolation is still masked (FP suppression), route after survives
    src3 = 'const s = ' + bt + 'x${ 1 /* path:"/nope" */ }y' + bt + '; const c={ path:"/yes" };'
    assert {f.extracted_value for f in _chunk_findings(src3) if f.value_type == "route_path"} == {"/yes"}


def test_dqd08_block_comment_preserves_prev_token_for_division():
    """Adversarial: an inline block comment between an operand and `/` is whitespace-equivalent, so
    `a /* c */ / b` stays division. The masker must keep the preceding token across the comment;
    otherwise the `/` is mis-parsed as a regex that swallows a later `//` comment's slash, leaving
    a commented-out route/import/webpack token reported as live (false positive)."""
    assert {f.extracted_value for f in _chunk_findings(
        'const ar = w /* width */ / h; // legacy path:"/admin/legacy"') if f.value_type == "route_path"} == set()
    assert {f.extracted_value for f in _chunk_findings(
        'var r = a /* x */ / b; // import("./AdminPanel")') if f.value_type == "dynamic_import"} == set()
    # a genuine regex after a block comment + operator is still skipped (route after survives)
    kept = {f.extracted_value for f in _chunk_findings(
        'var re = /* c */ /a\\/\\//g; const q={ path:"/ok" };') if f.value_type == "route_path"}
    assert kept == {"/ok"}


def test_dqd08_postfix_increment_before_comment_is_division_not_regex():
    """Adversarial: a postfix ++/-- completes an operand, so `a++/2` is division -- the masker must
    not treat it as a regex start (which would eat the following comment's leading slash and
    re-expose the commented-out route as a false positive). Binary/unary +/- stay regex-openers."""
    assert {f.extracted_value for f in _chunk_findings('var n=a++/2; // path:"/secret-admin"')
            if f.value_type == "route_path"} == set()
    assert {f.extracted_value for f in _chunk_findings('var n=a--/2; /* path:"/hidden" */ z=1;')
            if f.value_type == "route_path"} == set()
    # a binary + followed by a regex is still a regex (route after the comment stays suppressed,
    # and the standalone route is found)
    kept = {f.extracted_value for f in _chunk_findings('var n=a + /x\\/\\//.test(y); const c={ path:"/kw" };')
            if f.value_type == "route_path"}
    assert kept == {"/kw"}


def test_dqd08_chunk_analyzer_source_ascii_clean():
    """DQ-D08 edits must not introduce non-ASCII bytes (a separate test also enforces this)."""
    from bundleInspector.parser import chunk_analyzer
    raw = open(chunk_analyzer.__file__, "rb").read()
    assert all(b <= 127 for b in raw)


# ---------------------------------------------------------------- DQ-G04 directed edge dedup + correlation_ids

def _mk_finding(fid: str, file_url: str, line: int) -> Finding:
    return Finding(id=fid, rule_id="r", category=Category.ENDPOINT, severity=Severity.LOW,
                   confidence=Confidence.LOW, title=fid, description="d", extracted_value="v",
                   evidence=Evidence(file_url=file_url, file_hash="h", line=line))


def test_dqg04_directed_reverse_edge_preserved():
    """A->B and B->A of a directed type (import) are distinct and both retained."""
    from bundleInspector.correlator.edges import create_import_edge
    from bundleInspector.correlator.graph import CorrelationGraph

    g = CorrelationGraph()
    g.add_edge(create_import_edge("A", "B", "./mod"))
    g.add_edge(create_import_edge("B", "A", "./mod"))
    assert len([e for e in g.edges if e.edge_type.value == "import"]) == 2


def test_dqg04_symmetric_edge_still_deduped():
    """A-B and B-A of a symmetric type (same_file) still collapse to one edge."""
    from bundleInspector.correlator.edges import create_same_file_edge
    from bundleInspector.correlator.graph import CorrelationGraph

    g = CorrelationGraph()
    g.add_edge(create_same_file_edge("A", "B", "f.js"))
    g.add_edge(create_same_file_edge("B", "A", "f.js"))
    assert len([e for e in g.edges if e.edge_type.value == "same_file"]) == 1


def test_dqg04_correlation_ids_populated_by_correlate():
    """correlate() fills Finding.correlation_ids (declared but previously never populated)."""
    from bundleInspector.correlator.graph import Correlator

    fa = _mk_finding("X", "same.js", 1)
    fb = _mk_finding("Y", "same.js", 2)
    Correlator().correlate([fa, fb])
    assert fa.correlation_ids == ["Y"]
    assert fb.correlation_ids == ["X"]
