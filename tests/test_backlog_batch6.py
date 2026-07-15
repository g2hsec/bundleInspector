"""Regression locks for batch-6 collection/parser contained fixes + 2 deferred bugs.

Items: DQ-I01/I04/I05/I06/I07/I09 (collection), DQ-P04/P05/P06/P08 (parser/analysis),
FU-JSON (non-UTF8 raw serialize), FU-T02SEED (destructured event-param taint seeding).

Secret-like / URL / key values are FAKE samples used to verify behavior, not live data.
"""

from __future__ import annotations

import base64
import inspect
import json

from bs4 import BeautifulSoup

from bundleInspector.collector.headless import HeadlessCollector, HeadlessMultiPageCollector
from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.static import StaticCollector, _is_inline_js_type
from bundleInspector.config import Config, CrawlerConfig, ScopeConfig
from bundleInspector.core.orchestrator import Orchestrator
from bundleInspector.normalizer.sourcemap import SourceMapInfo
from bundleInspector.parser.js_parser import JSParser
from bundleInspector.reporter.json_reporter import JSONReporter
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    JSAsset,
    JSReference,
    LoadMethod,
    Report,
    Severity,
)


def _static_scope() -> ScopePolicy:
    c = ScopeConfig()
    c.add_seed_domain("https://ex.com/index.html")
    return ScopePolicy(c)


def _orch_with_rules() -> Orchestrator:
    orch = Orchestrator(Config())
    orch.rule_engine.register_defaults()
    return orch


# ------------------------------------------------------------ DQ-I01 inline <script> as asset

async def test_dqi01_inline_script_captured_as_analyzable_asset():
    coll = StaticCollector(CrawlerConfig())
    html = (
        "<html><head>"
        '<script src="/app.js"></script>'
        '<script>const K="AIzaSyA1234567890abcdefghijklmnopqrstuv"; fetch("/api/admin/secret");</script>'
        '<script type="application/json">{"api":"/not-a-real-endpoint"}</script>'
        "</head></html>"
    )
    soup = BeautifulSoup(html, "lxml")
    refs = [r async for r in coll._collect_script_tags(soup, "https://ex.com/page", _static_scope())]

    inline = [r for r in refs if r.inline_content is not None]
    external = [r for r in refs if r.inline_content is None]
    assert len(external) == 1 and external[0].url == "https://ex.com/app.js"     # external still yielded
    assert len(inline) == 1                                                       # JSON script excluded
    assert inline[0].method == LoadMethod.INLINE
    assert "fetch" in inline[0].inline_content
    assert len({r.url for r in refs}) == len(refs)                                # unique URLs (no #frag collapse)
    assert "#" not in inline[0].url                                               # query-marker, not a fragment

    # the inline body becomes an analyzable asset producing real findings (was entirely missed)
    orch = _orch_with_rules()
    asset = orch._build_inline_asset(inline[0])
    assert asset.content_hash and asset.is_first_party
    findings = orch._analyzer.analyze_asset_standalone(asset, None, None)
    cats = {f.category for f in findings}
    assert Category.ENDPOINT in cats and Category.SECRET in cats


def test_dqi01_inline_reference_round_trips_through_resume_state():
    from bundleInspector.collector.static import _deserialize_reference, _serialize_reference
    ref = JSReference(url="https://ex.com/p?__bi_inline=1", method=LoadMethod.INLINE,
                      inline_content="fetch('/api/x');", initiator="https://ex.com/p")
    restored = _deserialize_reference(_serialize_reference(ref))
    assert restored is not None
    assert restored.inline_content == "fetch('/api/x');"
    assert restored.method == LoadMethod.INLINE
    # a plain external ref keeps inline_content None (back-compat)
    ext = _deserialize_reference(_serialize_reference(JSReference(url="https://ex.com/a.js")))
    assert ext.inline_content is None


def test_dqi01_inline_js_type_gate():
    assert _is_inline_js_type(None) and _is_inline_js_type("") and _is_inline_js_type("module")
    assert _is_inline_js_type("text/javascript") and _is_inline_js_type("application/javascript")
    assert not _is_inline_js_type("application/json")
    assert not _is_inline_js_type("importmap")
    assert not _is_inline_js_type("application/ld+json")
    assert not _is_inline_js_type("text/template")


# ------------------------------------------------------------ DQ-I04 extensionless script by resource_type

def test_dqi04_extensionless_script_resource_type_honored():
    from tests.test_collector.test_headless import _FakeResponse, _scope
    collector = HeadlessCollector(CrawlerConfig())
    scope = _scope()
    # extensionless URL, generic content-type, but the browser fetched it AS a script
    collector._on_response(
        _FakeResponse("https://example.com/bundle", content_type="text/plain",
                      method="GET", resource_type="script"),
        "https://example.com", scope,
    )
    urls = [r.url for r in collector._discovered_refs]
    assert any(u.rstrip("/") == "https://example.com/bundle" for u in urls)
    # a non-script generic resource is still NOT captured as JS
    collector2 = HeadlessCollector(CrawlerConfig())
    collector2._on_response(
        _FakeResponse("https://example.com/data", content_type="text/plain",
                      method="GET", resource_type="fetch"),
        "https://example.com", _scope(),
    )
    assert collector2._discovered_refs == []


# ------------------------------------------------------------ DQ-I05 HTML-as-JS body guard

def test_dqi05_html_document_url_attrs_stripped_content_kept():
    login = (
        b'<!DOCTYPE html><html><head><title>Login</title></head><body>'
        b'<a href="/api/logout">Logout</a><form action="/api/login"></form>'
        b'<script>window.__CFG={t:"abc"};</script></body></html>'
    )
    out = Orchestrator._sanitize_html_document_for_analysis(login, "text/html")
    assert b"/api/logout" not in out and b"/api/login" not in out   # URL attrs (href/action) stripped
    assert b"__CFG" in out                                          # inline JS kept (INV-01)
    assert b"Logout" in out                                         # non-URL text kept

    # real JS mislabeled text/html must NOT be touched (body sniff, not header)
    real = b'!function(){var u="/api/real";fetch(u)}();'
    assert Orchestrator._sanitize_html_document_for_analysis(real, "text/html") == real
    # HTML with only a URL attr and no secret -> attr stripped, rest kept (not emptied)
    barebones = b"<!DOCTYPE html><html><body><a href='/api/x'>x</a></body></html>"
    stripped = Orchestrator._sanitize_html_document_for_analysis(barebones, "text/html")
    assert b"/api/x" not in stripped and b"x" in stripped


def test_dqi05_secret_outside_script_survives_sanitization():
    # INV-02: a known-provider secret in a __NEXT_DATA__ application/json island (or a meta/data
    # attribute) must NOT be dropped -- only URL attributes are stripped (round-3 adversarial finding).
    aws = b"AKIAIOSFODNN7EXAMPLE"
    page = (
        b'<!DOCTYPE html><html><head>'
        b'<meta name="cfg" content="' + aws + b'">'
        b'<script id="__NEXT_DATA__" type="application/json">{"props":{"key":"' + aws + b'"}}</script>'
        b'</head><body><a href="/api/logout">x</a></body></html>'
    )
    out = Orchestrator._sanitize_html_document_for_analysis(page, "text/html")
    assert out.count(aws) >= 2          # both the meta attr and the JSON island secret survive
    assert b"/api/logout" not in out    # the endpoint-FP href is still stripped

    # and it is actually detectable end-to-end
    orch = _orch_with_rules()
    asset = JSAsset(url="https://ex.com/app.js", content=out, is_first_party=True)
    asset.compute_hash()
    findings = orch._analyzer.analyze_asset_standalone(asset, None, None)
    assert any(f.category == Category.SECRET for f in findings)


def test_dqi05_secret_bearing_url_attribute_is_not_stripped():
    # CRITICAL round-4 finding: a known-provider secret can live IN a URL attribute value -- a Google
    # key in <script src="...?key=AIza...">, a Slack/Discord webhook in href/action/src. Stripping
    # those would hard-drop the secret (INV-02). Secret-bearing URL attrs must be KEPT; benign nav
    # URLs still stripped.
    gkey = "AIzaSyD1234567890abcdefghijklmnopqrst_-"
    slack = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    page = (
        '<!DOCTYPE html><html><head>'
        '<script src="https://maps.googleapis.com/maps/api/js?key=' + gkey + '&callback=init"></script>'
        '</head><body>'
        '<form action="' + slack + '"></form>'
        '<a href="/api/logout">x</a>'
        '</body></html>'
    ).encode()
    out = Orchestrator._sanitize_html_document_for_analysis(page, "text/html")
    assert gkey.encode() in out          # google key in <script src> kept (INV-02)
    assert slack.encode() in out         # slack webhook in <form action> kept (INV-02)
    assert b"/api/logout" not in out     # benign nav href still stripped (FP fix preserved)

    orch = _orch_with_rules()
    asset = JSAsset(url="https://ex.com/app.js", content=out, is_first_party=True)
    asset.compute_hash()
    sec_types = {f.value_type for f in orch._analyzer.analyze_asset_standalone(asset, None, None)
                 if f.category == Category.SECRET}
    assert "google_api_key" in sec_types and "slack_webhook" in sec_types


def test_dqi05_url_secret_guard_is_not_redos():
    # round-5 finding: the secret guard reused anchorless provider patterns (firebase/auth0) that
    # backtrack O(n^2) on a long crafted attribute value. The required-literal prefilter + length gate
    # must keep it near-linear (a 200KB attr previously took ~55s).
    import time
    blob = "aB3_-x" * (200000 // 6)
    page = ('<!doctype html><html><body><a href="' + blob + '">x</a></body></html>').encode()
    t = time.perf_counter()
    out = Orchestrator._sanitize_html_document_for_analysis(page, "text/html")
    assert time.perf_counter() - t < 2.0            # was ~55s pre-fix
    assert blob.encode() not in out                 # benign long blob still stripped
    # a genuinely short firebase/auth0 domain (anchorless pattern) is still recognized as a secret
    assert Orchestrator._url_value_bears_secret("https://myproj.firebaseio.com")
    # the formerly-unbounded firebase/auth0/telegram/google-oauth patterns are now upper-bounded at
    # the source, so even a 200KB value ending in the anchor scans linearly (no ReDoS, no gate)
    t = time.perf_counter()
    Orchestrator._url_value_bears_secret("a" * 200000 + ".firebaseio.com")
    assert time.perf_counter() - t < 1.0


def test_dqi05_long_amqp_secret_url_is_not_dropped():
    # round-6 finding: database_url `(?:mongodb|...|amqp|rabbitmq)://...{1,512}` is anchorless but
    # LENGTH-BOUNDED (linear) and the ONLY matcher for amqp/rabbitmq; a >512-char amqp connection URL
    # in an href must be KEPT (a blanket len>512 gate wrongly dropped this CRITICAL secret, INV-02).
    amqp = "amqp://admin:S3cretBrok3rPass@rabbitmq-broker-primary.internal.corp.example.com:5672/" + "v" * 480
    assert len(amqp) > 512
    assert Orchestrator._url_value_bears_secret(amqp)          # guard keeps it (secret survives)
    page = ('<!doctype html><html><body><a href="' + amqp + '">broker</a></body></html>').encode()
    out = Orchestrator._sanitize_html_document_for_analysis(page, "text/html")
    assert amqp.encode() in out                                # not stripped
    orch = _orch_with_rules()
    asset = JSAsset(url="https://ex.com/app.js", content=out, is_first_party=True)
    asset.compute_hash()
    assert any(f.value_type == "database_url" for f in orch._analyzer.analyze_asset_standalone(asset, None, None))


def test_secret_detector_not_redos_on_long_literal():
    # root-cause lock: SecretDetector.match() must not be O(n^2) on a long dotless string literal
    # (the 5 formerly-unbounded provider patterns were bounded at the source).
    import time

    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.parser.js_parser import parse_js
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.rules.detectors.secrets import SecretDetector
    blob = ("aB3xZ9kQ7wR2tY6mN1pL4sD8fG5hJ0cV" * 2600)[:80000]     # 80KB dotless [A-Za-z0-9_-]
    src = f'var payload="{blob}";'
    ir = build_ir(parse_js(src).ast, "https://x/app.js", "h")
    ctx = AnalysisContext(file_url="https://x/app.js", file_hash="h", source_content=src)
    t = time.perf_counter()
    list(SecretDetector().match(ir, ctx))
    assert time.perf_counter() - t < 2.0                          # was ~9s pre-fix (O(n^2))


def test_no_secret_pattern_is_super_linear():
    # comprehensive lock: EVERY provider + generic pattern must scan near-linearly on adversarial
    # inputs (repeated required literal + long class runs) -- guards against any future unbounded
    # quantifier reintroducing ReDoS (jwt_token / connection-string / firebase / auth0 all bounded).
    import time

    from bundleInspector.rules.detectors.secrets import SecretDetector

    def leading_literal(pat: str) -> str:
        s, i = "", 0
        while i < len(pat):
            c = pat[i]
            if c == "\\" and i + 1 < len(pat):
                s += pat[i + 1]
                i += 2
                continue
            if c in "[](){}.*+?^$|":
                break
            s += c
            i += 1
        return s

    def poisons(pat: str, n: int) -> list[str]:
        lit = leading_literal(pat)
        out = ["a" * n, "1" * n, ("eyJ" * (n // 3 + 1))[:n], ("aB3_" * (n // 4 + 1))[:n]]
        if lit:
            out.append((lit * (n // max(len(lit), 1) + 1))[:n])   # repeated required literal
        return out

    compiled = ([cp for cp, *_ in SecretDetector._COMPILED_SECRET_PATTERNS]
                + [cp for cp, *_ in SecretDetector._COMPILED_GENERIC_PATTERNS])
    for cp in compiled:
        for base in poisons(cp.pattern, 120000):
            small, big = base[:30000], base[:120000]
            a = time.perf_counter()
            cp.search(small)
            t_s = time.perf_counter() - a
            a = time.perf_counter()
            cp.search(big)
            t_b = time.perf_counter() - a
            # 4x the input must scale ~linearly (~4x), NOT ~16x (O(n^2)). Compare the 4x-input time to
            # a generous multiple of the 1x-input time so the check is robust to CPU load / warmup
            # (an absolute wall-clock threshold flaked); a real quadratic exceeds this by orders.
            limit = max(0.6, t_s * 8)
            assert t_b < limit, (
                f"pattern super-linear (ReDoS?): {cp.pattern[:50]} "
                f"(30k={t_s * 1000:.0f}ms 120k={t_b * 1000:.0f}ms)"
            )


def test_detector_regexes_bounded_not_redos():
    # lock the round-8 detector ReDoS bounds (domains/routes/endpoints): each regex, applied via
    # re.search/finditer/re.sub to attacker-controlled string literals, must be linear on a 200KB
    # adversarial poison. (secrets EXCLUDE_PATTERNS are re.match-anchored on bounded candidates and
    # intentionally excluded here.)
    import re as _re
    import time

    from bundleInspector.rules.detectors.domains import DomainDetector
    from bundleInspector.rules.detectors.endpoints import EndpointDetector

    # the bounded live patterns
    azure = next(p for p, t in DomainDetector.CLOUD_STORAGE_PATTERNS if "blob" in p)
    checks = [
        (azure, "1" * 200000),
        (r"(?:https?://)?([a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63})", "dev-a." + "1" * 200000),
        (r"\[([^\]]{1,256})\]", "[" * 200000),
        (EndpointDetector._RE_TEMPLATE.pattern, "${" * 100000),
        (EndpointDetector._SECRET_LIKE.pattern, ("eyJ" * 66667)[:200000]),
    ]
    for pat, poison in checks:
        cp = _re.compile(pat)
        t = time.perf_counter()
        list(cp.finditer(poison))
        assert time.perf_counter() - t < 1.0, f"detector regex ReDoS: {pat[:50]}"
    # parity spot-checks: real values still extract/match
    assert _re.search(azure, "https://myacct.blob.core.windows.net")
    assert EndpointDetector._RE_TEMPLATE.search("/api/${userId}/x")
    assert EndpointDetector._SECRET_LIKE.search("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0")


def test_dom_sink_danger_attr_regex_not_redos():
    # round-9 finding: sinks._DANGER_ATTR_RE had an unbounded [^"'<>\x00]* before the \x00 sentinel,
    # O(n^2) on an attacker-controlled template literal reached via DomSinkDetector.match(). Bounded
    # to {0,2048}; must be linear end-to-end and still detect real dangerous-attribute injections.
    import time

    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.parser.js_parser import parse_js
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.rules.detectors.sinks import _DANGER_ATTR_RE, _SENTINEL, DomSinkDetector

    for poison in ("<>" + "src=" * 32000, "<>" + "on" * 64000, "<>" + "onx=" * 16000):
        src = f"const h = `{poison}`;"
        ir = build_ir(parse_js(src).ast, "u", "h")
        ctx = AnalysisContext(file_url="u", file_hash="h", source_content=src)
        t = time.perf_counter()
        list(DomSinkDetector().match(ir, ctx))
        assert time.perf_counter() - t < 1.5                  # was O(n^2) via [^..]* AND on\w+
    # real dangerous-attribute value injections still match (both event handlers and src/href)
    assert _DANGER_ATTR_RE.search('<img src="' + _SENTINEL + '">')
    assert _DANGER_ATTR_RE.search('onerror="' + _SENTINEL + '"')
    assert _DANGER_ATTR_RE.search('onmouseover="' + _SENTINEL + '"')
    assert _DANGER_ATTR_RE.search("formaction=" + _SENTINEL)


def test_analysis_is_linear_on_single_line_bundle():
    # round-12 findings: per-finding recompute of split("\n") + doc-context mask (endpoints +
    # context_filter) and BaseRule.get_snippet's split made engine.analyze O(findings x line_len) ->
    # quadratic on a single-line minified bundle (the primary real-world input). Now memoized -> linear.
    import time

    from bundleInspector.config import Config
    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.parser.js_parser import parse_js
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.rules.engine import RuleEngine

    def bundle(c):
        return "".join(f'a.href="https://h{i}.example.com/api/v1/u";' for i in range(c))

    def analyze_time(src):
        ir = build_ir(parse_js(src).ast, "u", "h")
        ctx = AnalysisContext(file_url="u", file_hash="h", source_content=src)
        eng = RuleEngine(Config().rules)
        eng.register_defaults()
        t = time.perf_counter()
        eng.analyze(ir, ctx)
        return time.perf_counter() - t

    t2 = analyze_time(bundle(2000))
    t8 = analyze_time(bundle(8000))
    # 4x the findings on one line must be well under 16x the time (quadratic); linear is ~4x. This
    # covers the memoized doc-context (endpoints + context_filter), the SECRET-path _check_line_context,
    # and BaseRule.get_snippet -- all formerly per-finding whole-source rescans.
    assert t8 < t2 * 10, f"analysis super-linear on a single-line bundle (t2={t2:.2f} t8={t8:.2f})"


def test_secret_context_filter_is_linear_on_single_line_bundle():
    # round-13 finding: ContextFilter._check_line_context (SECRET path) recomputed split + full-line
    # re.search + block-comment split PER finding -> O(findings x line_len). Now memoized per line.
    import time

    from bundleInspector.config import RuleConfig
    from bundleInspector.parser.ir_builder import IRBuilder
    from bundleInspector.parser.js_parser import JSParser
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.rules.engine import RuleEngine

    def secbundle(m):
        return "".join(f'apikey:"AABBCCDDEEFF001122334455{i:08d}",' for i in range(m))

    def analyze_time(src):
        ir = IRBuilder().build(JSParser().parse(src).ast, "u", "h")
        eng = RuleEngine(RuleConfig())
        eng.register_defaults()
        ctx = AnalysisContext(file_url="u", file_hash="h", source_content=src)
        t = time.perf_counter()
        eng.analyze(ir, ctx)
        return time.perf_counter() - t

    t2 = analyze_time(secbundle(2000))
    t8 = analyze_time(secbundle(8000))
    assert t8 < t2 * 10                                       # was O(n^2): 84KB=3.1s, 168KB=17.4s

    # context signals still correct (parity)
    from bundleInspector.rules.context_filter import ContextFilter
    cf = ContextFilter()

    def sig_name(src, line):
        f = Finding(rule_id="secret-detector", category=Category.SECRET, severity=Severity.HIGH,
                    confidence=Confidence.HIGH, title="t", description="d", extracted_value="x",
                    evidence=Evidence(file_url="u", file_hash="h", line=line))
        s = cf._check_line_context(f, src)
        return s.name if s else None

    assert sig_name("// example: a\nreal=1;", 1) == "comment"
    assert sig_name("/* secret\nhere */\nx", 2) == "block_comment"
    assert sig_name('const k = sample: "x";', 1) == "example_line"
    assert sig_name('const k="realsecret";', 1) is None
    # no staleness across two interleaved sources on one instance
    assert sig_name("// example: a\nreal=1;", 1) == "comment"
    assert sig_name("code=1;\n// example: b", 1) is None


def test_require_ensure_scanner_not_redos():
    # round-12 finding: static require.ensure pattern's unbounded [\s\S]*? was O(n^2) on many
    # `require.ensure(...){` prefixes with no inner require(). Bounded to {0,4096}.
    import asyncio
    import time

    from bundleInspector.collector.scope import ScopePolicy
    from bundleInspector.config import ScopeConfig
    col = StaticCollector(CrawlerConfig())
    scope = ScopePolicy(ScopeConfig(allowed_domains=["evil.test"]))

    async def scan(content):
        t = time.perf_counter()
        async for _ in col._extract_dynamic_imports(content, "https://evil.test/a.js", scope):
            pass
        return time.perf_counter() - t

    async def run():
        t = await scan("require.ensure(0,function(){}" * 8000)
        assert t < 2.0                                       # was ~7s at 8k (O(n^2))
        # a real require.ensure inner chunk is still discovered
        refs = [r.url async for r in col._extract_dynamic_imports(
            'require.ensure([], function(){ require("./chunk.js"); })', "https://evil.test/a.js", scope)]
        assert any("chunk" in u for u in refs)

    asyncio.run(run())


def test_regex_fallback_string_scan_is_linear_and_exact():
    # round-14 finding: _parse_regex_fallback used re.finditer(r'"([^"\\]|\\.)*"') which re-scanned to
    # EOF from every quote anchor -> O(n^2) on an unterminated/escaped-quote run (default-reachable
    # when esprima fails first). Replaced with a linear _scan_quoted_literals that yields the SAME
    # extraction set; _get_loc replaced by an O(log n) bisect. Verify exact-match + linear.
    import re as _re
    import time

    def ref(src, q):
        return [(m.start(), m.end()) for m in _re.finditer(q + r"([^" + _re.escape(q) + r"\\]|\\.)*" + q, src)]

    for src in ('a="x";b=\'y\';c=`z`;', '"a\\"b"', '\'{"url":"/api/x"}\'', '"unterminated', '"a"b"c"',
                '"line\ncont"', "'esc\\n'", '`t${x}`', '"a\\\nb"'):
        for q in ('"', "'", "`"):
            assert [(s, e) for s, e in JSParser._scan_quoted_literals(src, q)] == ref(src, q), (src, q)

    p = JSParser()
    poison = 'const x=a?.b??c;const s="' + '\\"' * (128 * 512)   # 128KB unterminated escaped-quote run
    t = time.perf_counter()
    p._parse_regex_fallback(poison)
    assert time.perf_counter() - t < 1.0                     # was ~59s at 128KB (O(n^2))
    # a JSON-in-single-quote endpoint literal is still extracted (INV-01: same set as the regex)
    r = p._parse_regex_fallback('const j = \'{"u":"/api/x"}\'; bad?.syntax;')
    assert any(n["expression"]["value"] == "/api/x" for n in r.ast["body"])


def test_partial_parse_line_offset_is_linear():
    # round-11 finding: _partial_parse_esprima recomputed line_offset per chunk via
    # re.findall(source[:char_offset]) -> O(n^2) over many blank-line chunks (default parse path).
    # Now incremental (O(n)); offsets must stay correct on LF/CRLF/CR.
    import time

    p = JSParser()
    times = {}
    for m in (2000, 8000):
        poison = "@\n\n" + "var x=1;\n\n" * m
        t = time.perf_counter()
        p.parse(poison)
        times[m] = time.perf_counter() - t
    # 4x the chunks must be ~4x time (linear), not ~16x (quadratic)
    assert times[8000] < times[2000] * 8
    # offsets stay correct: a var decl in the 3rd line recovers at absolute line 3 for every ending
    for nl in ("\n", "\r\n", "\r"):
        src = "function( {{{ bad" + nl + nl + 'const AWS = "AKIAX";'
        vd = [n for n in (p.parse(src).ast or {}).get("body", []) if n.get("type") == "VariableDeclaration"]
        assert vd and vd[0]["loc"]["start"]["line"] == 3


def test_string_literal_masks_not_exponential():
    # round-11 finding: the string-literal masks `(["'`])(?:\\.|(?!\1).)*\1` (context_filter +
    # endpoints doc-context) and the gql tokenizer `"(?:\\.|[^"])*"` had OVERLAPPING alt branches
    # (the "any char" branch included backslash), giving EXPONENTIAL backtracking on an unterminated
    # quote + backslash run (<100 bytes -> hours). Now disjoint (`[^\\]`) -> linear.
    import re as _re
    import time

    from bundleInspector.rules import context_filter as _cf
    from bundleInspector.rules.detectors import endpoints as _ep
    # the live compiled masks must use the disjoint form (no bare `.` overlapping `\\.`)
    for compiled in (_cf._DOC_MASK_RE, _ep._DOC_MASK_RE):
        assert r"(?!\1)[^\\]" in compiled.pattern
        assert r"(?!\1)." not in compiled.pattern.replace(r"(?!\1)[^\\]", "")
    # behavior: exponential poison (unterminated quote + backslash run) stays fast
    mask = _re.compile(r'''(["\'`])(?:\\.|(?!\1)[^\\])*\1''')
    gql = _re.compile(r'"(?:\\.|[^"\\])*"')
    for cp in (mask, gql):
        t = time.perf_counter()
        cp.search('"' + "\\" * 100000)
        assert time.perf_counter() - t < 1.0                  # was exponential (~hours at n=54)
    # parity: well-formed strings mask identically
    for s in ('"api.example.com"', r'"C:\\path"', r'"esc\n"', "'single'"):
        assert mask.sub("Q", s) == _re.compile(r'''(["\'`])(?:\\.|(?!\1).)*\1''').sub("Q", s)


def test_chunk_analyzer_nextjs_route_not_redos():
    # round-10 finding: ChunkAnalyzer nextjs_page `pages?[/\\]([^"']+?)(?:\.tsx?|...)` had a lazy
    # unbounded group before a required extension suffix -> O(n^2) on a `page/`-repeated literal on
    # the DEFAULT pipeline. Bounded to {1,200}; must be linear and still match real page paths.
    import re as _re
    import time

    from bundleInspector.parser.chunk_analyzer import ChunkAnalyzer
    pat = _re.compile(next(p for p, t in ChunkAnalyzer.ROUTE_PATTERNS if t == "nextjs_page"))
    t = time.perf_counter()
    list(pat.finditer("page/" * 160000))
    assert time.perf_counter() - t < 1.0                    # was ~4s at 80k (O(n^2))
    for real in ("pages/Home.tsx", "src/pages/user/Profile.jsx", "pages/blog/post.vue"):
        assert pat.search(real)


def test_context_filter_block_comment_not_redos():
    # round-9(+) finding: _is_line_in_block_comment used re.finditer(r"/\*[\s\S]*?\*/", source) which
    # is O(n^2) on a source with many unterminated `/*` (e.g. "/*a" repeated), reached per-finding on
    # attacker-controlled source. Rewritten with str.find pairing (linear); same match semantics.
    import time

    from bundleInspector.rules.context_filter import ContextFilter
    cf = ContextFilter.__new__(ContextFilter)

    # semantics preserved: a line inside a /* */ block is detected; outside is not
    src = "line0\n/* c1\n c2 */\nline4"
    assert cf._is_line_in_block_comment(src, 2) is True    # " c2 */" line is inside the comment
    assert cf._is_line_in_block_comment(src, 0) is False   # "line0" is not
    assert cf._is_line_in_block_comment(src, 3) is False    # "line4" is after the comment

    poison = ("/*a" * 100000) + "\nX"
    t = time.perf_counter()
    cf._is_line_in_block_comment(poison, poison.count("\n"))
    assert time.perf_counter() - t < 1.0                    # was ~10s (O(n^2))


def test_dqi05_reducer_is_wired_into_download_path():
    # round-2 adversarial finding: the reducer must be CALLED in _download_js (not dead code), so a
    # JS-ref URL that returns a 200 HTML login page produces an asset with no markup-derived endpoints.
    import asyncio

    login = (b'<!DOCTYPE html><html><body>'
             b'<a href="/api/logout">Logout</a><form action="/api/login"></form>'
             b'<script>window.__CFG={t:"abc"};</script></body></html>')

    class _Stream:
        def __init__(self, content, headers):
            self._c = content
            self.headers = headers
            self.status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def raise_for_status(self):
            return None

        async def aread(self):
            return self._c

    class _Client:
        def __init__(self, content, headers):
            self._c = content
            self._h = headers

        def stream(self, method, url):
            return _Stream(self._c, self._h)

    orch = _orch_with_rules()
    orch._download_client = _Client(login, {"content-type": "text/html"})
    asset = asyncio.run(orch._download_js(JSReference(url="https://ex.com/app.js")))
    assert b"/api/logout" not in asset.content and b"/api/login" not in asset.content
    assert b"__CFG" in asset.content                       # inline JS kept
    findings = orch._analyzer.analyze_asset_standalone(asset, None, None)
    assert [f for f in findings if f.category == Category.ENDPOINT] == []

    # a real JS bundle mislabeled text/html must survive the download unreduced
    orch._download_client = _Client(b'!function(){fetch("/api/real")}();', {"content-type": "text/html"})
    a2 = asyncio.run(orch._download_js(JSReference(url="https://ex.com/b.js")))
    assert a2.content == b'!function(){fetch("/api/real")}();'


def test_dqi05_endpoint_fp_from_login_html_eliminated():
    orch = _orch_with_rules()
    login = (
        b'<!DOCTYPE html><html><body>'
        b'<a href="/api/logout">Logout</a><form action="/api/login"></form>'
        b'</body></html>'
    )
    reduced = Orchestrator._sanitize_html_document_for_analysis(login, "text/html")
    asset = JSAsset(url="https://ex.com/app.js", content=reduced, is_first_party=True)
    asset.compute_hash()
    findings = orch._analyzer.analyze_asset_standalone(asset, None, None)
    endpoints = [f for f in findings if f.category == Category.ENDPOINT]
    assert endpoints == []   # /api/logout, /api/login were markup hrefs -> no longer endpoints


# ------------------------------------------------------------ DQ-I06 / I07 manifest

class _MFResp:
    def __init__(self, text, ctype):
        self.status_code = 200
        self.text = text
        self.headers = {"content-type": ctype}


class _MFClient:
    def __init__(self, resp):
        self._r = resp

    async def get(self, url):
        return self._r

    async def aclose(self):
        return None


def _manifest_scope() -> ScopePolicy:
    c = ScopeConfig()
    c.add_seed_domain("https://host/index.html")
    return ScopePolicy(c)


async def _manifest_refs(content, url, ctype):
    coll = ManifestCollector(CrawlerConfig())
    coll._client = _MFClient(_MFResp(content, ctype))
    return [r.url async for r in coll._parse_manifest(url, "https://host", _manifest_scope())]


async def test_dqi06_vite_manifest_resolves_to_deployment_base():
    vite = json.dumps({
        "index.html": {"file": "assets/index.abc.js", "isEntry": True},
        "src/About.vue": {"file": "assets/About.def.js", "dynamicEntry": True},
    })
    refs = await _manifest_refs(vite, "https://host/.vite/manifest.json", "application/json")
    assert refs, "vite manifest yielded no refs"
    assert all("/.vite/assets/" not in r for r in refs)                    # not the broken /.vite/ base
    assert any(r == "https://host/assets/index.abc.js" for r in refs)      # resolved to deployment base
    assert any(r == "https://host/assets/About.def.js" for r in refs)      # dynamic-entry chunk discovered

    # a non-.vite manifest keeps resolving against the manifest dir (unchanged)
    other = json.dumps({"files": {"main.js": "static/js/main.abc.js"}})
    refs2 = await _manifest_refs(other, "https://host/build/manifest.json", "application/json")
    assert "https://host/build/static/js/main.abc.js" in refs2


async def test_dqi07_json_manifest_shape_fallback_for_ambiguous_content_type():
    wp = json.dumps({"files": {"main.js": "static/js/main.abc.js"}})
    refs = await _manifest_refs(wp, "https://host/asset-manifest.json", "text/plain")
    assert "https://host/static/js/main.abc.js" in refs                    # recovered via shape fallback

    # non-manifest JSON (PWA icons, png only) served as text/plain -> no spurious refs
    pwa = json.dumps({"name": "App", "icons": [{"src": "/icon.png", "sizes": "192x192"}]})
    assert await _manifest_refs(pwa, "https://host/manifest.json", "text/plain") == []
    # a non-.json path with ambiguous type is still ignored (no fallback)
    assert await _manifest_refs(wp, "https://host/whatever.txt", "text/plain") == []


def test_dqi07_looks_like_json_manifest():
    assert ManifestCollector._looks_like_json_manifest('{"a":1}')
    assert ManifestCollector._looks_like_json_manifest('[1,2,3]')
    assert not ManifestCollector._looks_like_json_manifest("<html></html>")
    assert not ManifestCollector._looks_like_json_manifest("not json at all")
    assert not ManifestCollector._looks_like_json_manifest('"just a string"')


# ------------------------------------------------------------ DQ-I09 deterministic link filtering

def test_dqi09_headless_filter_page_links_is_deterministic():
    src = inspect.getsource(HeadlessMultiPageCollector._filter_page_links)
    assert "return list(dict.fromkeys(result))" in src   # document-order dedup
    assert "return list(set(result))" not in src         # not hash-random


# ------------------------------------------------------------ DQ-P04 per-quote-type budget

def test_dqp04_single_quoted_endpoint_survives_double_quote_flood():
    p = JSParser(tolerant=True, partial_on_error=True)
    flood = " ".join(f'"x{i}"' for i in range(10050))
    src = flood + "; var u = '/api/single-quoted-endpoint';"
    result = p._parse_regex_fallback(src)
    values = [n["expression"]["value"] for n in result.ast["body"]]
    assert "/api/single-quoted-endpoint" in values       # was starved out by the shared cap before
    assert values.count("x0") == 1                        # double-quoted still fully extracted


# ------------------------------------------------------------ DQ-P05 CRLF partial parse

def test_dqp05_crlf_partial_parse_recovers_ast():
    p = JSParser(tolerant=True, partial_on_error=True)
    good = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";'
    broken = "function( {{{ not valid js"
    lf = good + "\n\n" + broken
    crlf = lf.replace("\n", "\r\n")

    def has_vardecl(res):
        return bool(res.ast) and any(n.get("type") == "VariableDeclaration" for n in res.ast.get("body", []))

    r_lf, r_crlf = p.parse(lf), p.parse(crlf)
    assert r_lf.parser_used == "esprima" and has_vardecl(r_lf)      # LF unchanged
    assert r_crlf.parser_used == "esprima" and has_vardecl(r_crlf)  # CRLF now recovers via AST too


# ------------------------------------------------------------ DQ-P06 local parse-error detail preserved

def test_dqp06_local_parse_stage_extends_parse_errors():
    from bundleInspector import cli
    src = inspect.getsource(cli)
    # the local Parse success branch preserves the degraded-parse detail like the canonical scan path
    assert "asset.parse_errors.extend(parse_result.errors)" in src


# ------------------------------------------------------------ DQ-P08 sourcesContent virtual sources

def test_dqp08_virtual_sources_recover_source_only_and_dedupe_shared():
    orch = _orch_with_rules()
    an = orch._analyzer
    sm = SourceMapInfo(
        url=None, content=None, is_inline=True, sources=["src/api.js"],
        sources_content=['fetch("/api/shared"); fetch("/api/source-only-devtool");'],
        mappings="",
    )
    # a realistic bundle GET endpoint carries method GET (as the detector emits it)
    shared = Finding(rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.LOW,
                     confidence=Confidence.LOW, title="e", description="d",
                     extracted_value="/api/shared", value_type="api_endpoint",
                     evidence=Evidence(file_url="bundle.js", file_hash="h", line=1))
    shared.metadata["method"] = "GET"
    virt = an._analyze_virtual_sources(sm, True, [shared])
    vals = [f.extracted_value for f in virt]
    assert "/api/source-only-devtool" in vals                   # present only in the original -> recovered
    assert vals.count("/api/shared") == 0                       # same method GET in bundle -> not double-reported
    assert all(f.metadata.get("virtual_source") for f in virt)  # tagged as virtual
    assert all(f.evidence.original_file_url == "src/api.js" for f in virt)


def test_dqp08_dedup_key_discriminates_http_method():
    # a source-only hidden verb (DELETE) on a path that also has a bundle GET must be RECOVERED,
    # not collapsed by the endpoint-string dedup (round-1 adversarial finding).
    orch = _orch_with_rules()
    an = orch._analyzer
    sm = SourceMapInfo(
        url=None, content=None, is_inline=True, sources=["src/api.js"],
        sources_content=['fetch("/api/users", {method: "DELETE"});'],
        mappings="",
    )
    get_finding = Finding(rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.LOW,
                          confidence=Confidence.LOW, title="e", description="d",
                          extracted_value="/api/users", value_type="api_endpoint",
                          evidence=Evidence(file_url="bundle.js", file_hash="h", line=1))
    get_finding.metadata["method"] = "GET"
    virt = an._analyze_virtual_sources(sm, True, [get_finding])
    methods = {f.metadata.get("method") for f in virt if f.extracted_value == "/api/users"}
    assert "DELETE" in methods       # distinct verb recovered instead of collapsed onto the GET


def test_dqp08_no_sourcemap_or_empty_is_noop():
    an = _orch_with_rules()._analyzer
    assert an._analyze_virtual_sources(None, True, []) == []
    empty = SourceMapInfo(url=None, content=None, is_inline=True, sources=[], sources_content=[], mappings="")
    assert an._analyze_virtual_sources(empty, True, []) == []


# ------------------------------------------------------------ FU-JSON non-UTF8 raw serialize

def test_fujson_include_raw_non_utf8_content_serializes_base64():
    raw = bytes([0xff, 0xfe, 0x00, 0x80, 0x81])
    report = Report(assets=[JSAsset(url="u", content=raw)])
    out = JSONReporter(include_raw=True).generate(report)        # previously raised UnicodeDecodeError
    data = json.loads(out)
    assert base64.b64decode(data["assets"][0]["content"]) == raw
    # sourcemap_content None must not crash the serializer
    report2 = Report(assets=[JSAsset(url="u", content=b"ok", sourcemap_content=None)])
    json.loads(JSONReporter(include_raw=True).generate(report2))


def test_fujson_str_content_still_validates():
    # construction/validation is untouched: a str assigned to the bytes field still coerces
    a = JSAsset(url="u", content="var s = 'x';")
    assert isinstance(a.content, bytes)


# ================================================================ round-1 adversarial-fix locks

def test_dqp05_cr_only_line_terminators_get_correct_absolute_lines():
    # \r\r (old-Mac CR-only) is a delimiter the split recovers; line offset must count lone \r as a
    # line terminator (esprima does), else recovered nodes in later chunks get chunk-local lines.
    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.parser.js_parser import parse_js
    src = "function bad(){ return ;;; @@@\r\rfetch('/api/leaked');\r\rfetch('/api/token');"
    ir = build_ir(parse_js(src).ast, "app.js", "h")
    assert sorted(c.line for c in ir.function_calls) == [3, 5]   # true original lines, not [1, 1]


def test_dqi01_sibling_trailing_slash_pages_do_not_collapse_in_dedup():
    from bundleInspector.core.dedup import DedupCache
    a = StaticCollector._inline_asset_url("https://ex.com/a", 0, 'var harmless=1;')
    a_slash = StaticCollector._inline_asset_url("https://ex.com/a/", 0, 'const K="SECRET"; fetch("/x");')
    d = DedupCache()
    assert d.add_url(a) and d.add_url(a_slash)                   # distinct bodies -> both survive (INV-02)
    # identical bodies whose paths normalize together STILL collapse (content dedup preserved)
    d2 = DedupCache()
    s1 = StaticCollector._inline_asset_url("https://ex.com/a", 0, 'var same=1;')
    s2 = StaticCollector._inline_asset_url("https://ex.com/a/", 0, 'var same=1;')
    assert d2.add_url(s1) and not d2.add_url(s2)


def test_fujson_stored_report_round_trips_content_without_corruption():
    import asyncio
    import tempfile
    from pathlib import Path

    from bundleInspector.storage.finding_store import FindingStore
    orig = b"const API='/api/users';\nfetch(API);\n"

    async def rt(tmp):
        store = FindingStore(Path(tmp))
        a = JSAsset(url="https://ex.com/app.js", content=orig)
        a.compute_hash()
        rep = Report(assets=[a])
        rep.compute_summary()
        await store.store_report(rep)
        resumed = await store.get_latest_report()
        return resumed.assets[0].content

    with tempfile.TemporaryDirectory() as tmp:
        got = asyncio.run(rt(tmp))
    # content is excluded from the persisted report (kept in the artifact store), so the resumed
    # report never carries the double-base64-corrupted bytes the serializer would otherwise produce.
    assert got in (b"", orig) and got != base64.b64encode(orig)


def test_dqi04_service_worker_frame_raise_does_not_crash_on_response():
    from tests.test_collector.test_headless import _scope

    class _RaisingReq:
        def __init__(self, rt):
            self._rt = rt
            self.method = "GET"
            self.headers = {}

        @property
        def resource_type(self):
            return self._rt

        @property
        def frame(self):
            raise Exception("Service Worker requests do not have an associated frame.")

    class _Resp:
        def __init__(self, url, ct, rt):
            self.url = url
            self.headers = {"content-type": ct}
            self.request = _RaisingReq(rt)

    collector = HeadlessCollector(CrawlerConfig())
    # resource_type==script + generic content-type + a frame that raises -> must not throw
    collector._on_response(_Resp("https://example.com/swchunk", "text/plain", "script"),
                           "https://example.com", _scope())
    assert any("swchunk" in r.url for r in collector._discovered_refs)


# ------------------------------------------------------------ FU-T02SEED destructured event param

def test_fut02seed_destructured_event_param_is_dom_source():
    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.parser.js_parser import parse_js
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.rules.detectors.taint import TaintFlowDetector

    def count(src):
        ast = parse_js(src).ast
        ir = build_ir(ast, "f.js", "h")
        ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src, is_first_party=True)
        return len(list(TaintFlowDetector().match(ir, ctx)))

    assert count("function h(e){ box.innerHTML = e.target.value; }") == 1          # named event (unchanged)
    assert count("function h({target}){ box.innerHTML = target.value; }") >= 1     # destructured (was 0)
    assert count("const h = ({target: t}) => { box.innerHTML = t.value; };") >= 1  # renamed
    assert count("function h({currentTarget}){ box.innerHTML = currentTarget.value; }") >= 1
    # DQ-T02 false-positive locks stay 0
    assert count("const target = getConfig(); box.innerHTML = target.value;") == 0
    assert count("box.innerHTML = model.target.value;") == 0
    assert count("box.innerHTML = config.settings.target.value;") == 0
