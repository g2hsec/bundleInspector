"""Intra-file dataflow taint engine: confirms a source->sink chain only when a real def-use
chain exists. Precision is the priority -- the FALSE-POSITIVE table below (must all yield 0
findings) is the contract; the TRUE-POSITIVE table must all catch. Token-like literals are fake.
"""

from __future__ import annotations

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.detectors.taint import TaintFlowDetector
from bundleInspector.rules.engine import RuleEngine


def _taint_flows(src: str):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    return list(
        TaintFlowDetector().match(
            ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
        )
    )


# ---------------------------------------------------------------- FALSE POSITIVES (must be 0)


@pytest.mark.parametrize(
    "label,src",
    [
        (
            "config .url is not a source",
            'var ctx={context:"/api"}; el.html(`<a href="${ctx.context}">x</a>`);',
        ),
        (
            "scope collision",
            'function a(){var d=location.hash; use(d);}\nfunction b(){var d="safe"; el.html(d);}',
        ),
        ("reassign to clean kills taint", 'var v=location.hash; v="0"; el.html(v);'),
        ("reassign to sanitized kills", "var v=location.hash; v=String(Number(v)); el.html(v);"),
        (".text() is not an html sink", "var u=location.hash; el.text(u);"),
        ("encodeURIComponent sanitizes", "var u=location.hash; el.html(encodeURIComponent(u));"),
        (
            "constant-array iterator param clean",
            'var C=["a","b"]; C.forEach(function(x){el.html(`<i>${x}</i>`);});',
        ),
        ("property key is not a variable", "var o={src: safeVal}; el.html(`<b>${o.name}</b>`);"),
        (
            "unknown cross-object return abstains",
            'var it=$.ns.obj.fetch(x); el.html(`<img src="${it.image_url}">`);',
        ),
        (
            "bare parameter is not a source",
            'function show(o){ $("body").append(`<p>${o.message}</p>`); }',
        ),
        ("document.write of a param abstains", "function ws(id){ document.write(id.innerHTML); }"),
        ("static innerHTML is not dynamic", 'chip.innerHTML = "";'),
        (
            "ajax data:/url: is request-direction, not a sink",
            '$.ajax({url:"/a", data: JSON.stringify(location.hash)});',
        ),
        (
            "context-insensitive FP guard: f(clean) not flagged",
            'function r(x){ return `<img src="${x}">`; }\nvar bad=location.hash;\nel.html(r(bad));\nel.html(r("safe"));',
        ),
    ],
)
def test_no_false_positive(label, src):
    flows = _taint_flows(src)
    # the context-sensitive case legitimately has ONE flow (r(bad)); assert the CLEAN call line
    # (the last) is never among the reported sink lines.
    if "f(clean)" in label:
        assert all(f.line != 4 for f in flows), f"clean-arg call flagged: {label}"
    else:
        assert flows == [], f"unexpected taint flow: {label}"


# ---------------------------------------------------------------- TRUE POSITIVES (must catch)


@pytest.mark.parametrize(
    "label,src,expect_source",
    [
        ("location -> innerHTML", "var u=location.hash; el.innerHTML=u;", "location"),
        (
            "ajax .done(res) -> .html",
            '$.ajax({url:"/a"}).done(function(r){ el.html(r.body); });',
            "ajax_response",
        ),
        (
            "await ajax -> template append",
            'async function f(){ var r=await $.ajax({url:"/a"}); box.append(`<img src="${r.img}">`); }',
            "ajax_response",
        ),
        (
            "FileReader -> attr src",
            'var rd=new FileReader(); rd.onload=function(e){ $img.attr("src", e.target.result); };',
            "filereader",
        ),
        (".val() -> .html", 'var v=$("#x").val(); el.html(`<b>${v}</b>`);', "dom_input"),
        (
            "context-sensitive taint call flagged",
            "function r(x){ return `<i>${x}</i>`; } el.html(r(location.hash));",
            "location",
        ),
        (
            "ajax response destructure -> iterator -> img src",
            'var res=$.ajax({async:false});\nvar list=res.responseJSON;\nlist.forEach(function(it){ box.append(`<img src="${it.url}">`); });',
            "ajax_response",
        ),
    ],
)
def test_true_positive(label, src, expect_source):
    flows = _taint_flows(src)
    assert flows, f"missed real flow: {label}"
    assert any(f.metadata["source_kind"] == expect_source for f in flows), (
        f"{label}: expected source {expect_source}, got {[f.metadata['source_kind'] for f in flows]}"
    )


# ---------------------------------------------------------------- confirmed metadata + robustness


def test_confirmed_flow_has_path_and_metadata():
    f = _taint_flows("var u=location.hash; el.innerHTML=u;")[0]
    assert f.metadata["confirmed"] is True
    assert f.value_type == "taint_flow"
    assert f.metadata["flow_path"] and "source:" in f.metadata["flow_path"][0]
    assert "sink" in f.metadata["flow_path"][-1]


def test_degraded_parse_never_yields_confirmed_flow():
    """A degraded parse breaks taint's soundness precondition (complete def-use visibility): the
    esprima chunk-fallback silently DROPS statements that fail to parse -- a dropped `v = "safe"`
    kill turns a neutralized flow into a FALSE confirmed source->sink, which fp_annotate never
    demotes and the report badges as proven. So on a partial/regex-fallback parse the detector must
    ABSTAIN rather than assert an unsound 'confirmed'."""
    # chunk 2 (the kill) has a hard syntax error -> dropped by _partial_parse_esprima, leaving
    # location.hash live to document.write. The same code fully parsed yields NO flow (kill wins).
    degraded = 'var v = location.hash;\n\nv = "safe" @@@ bad;\n\ndocument.write(v);'
    ir = build_ir(parse_js(degraded).ast, "f.js", "h")
    assert ir.partial is True  # sanity: this really is a degraded parse
    flows = list(
        TaintFlowDetector().match(
            ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=degraded)
        )
    )
    assert flows == []  # no FALSE confirmed on a degraded parse

    # guard against over-abstention: a genuine flow on a CLEAN parse still confirms.
    live = _taint_flows("var u=location.hash; el.innerHTML=u;")
    assert len(live) == 1 and live[0].metadata["confirmed"] is True


@pytest.mark.parametrize(
    "label,src",
    [
        (
            "non-numeric .replace() preserves taint",
            "var u=location.hash; el.html(u.replace(/x/g,'<br>'));",
        ),
        (
            "innerHTML += appends tainted HTML",
            "var u=location.hash; document.getElementById('o').innerHTML += u;",
        ),
        (
            "JSON.stringify into .html is XSS (not HTML-escaped)",
            "var u=location.hash; $('#o').html(JSON.stringify(u));",
        ),
    ],
)
def test_previously_missed_xss_now_confirmed(label, src):
    """Regression for real DOM-XSS flows that were silently MISSED: a non-numeric `.replace()`
    laundered taint (missing from _TRANSFORMS), `innerHTML +=` was gated to `=` only, and
    JSON.stringify was wrongly treated as an HTML sanitizer."""
    flows = _taint_flows(src)
    assert flows and flows[0].metadata["confirmed"] is True, f"missed real XSS: {label}"


def test_numeric_strip_replace_still_sanitizes():
    """A numeric-strip `.replace(/[^0-9]/g,'')` still KILLS taint -- only non-numeric replaces
    preserve it (guards against the _TRANSFORMS 'replace' addition over-tainting)."""
    assert _taint_flows("var u=location.hash; el.html(u.replace(/[^0-9]/g,''));") == []


@pytest.mark.parametrize(
    "src",
    [
        "",
        "// just a comment",
        "var x = 1;",
        "a" + ("." + "b") * 500 + ";",  # deep member chain
        "function f(){ return f(); } el.html(f());",  # self-recursive call
        "var o = {}; el.html(o?.a?.b);",  # optional chaining, clean
    ],
)
def test_no_crash_on_edge_inputs(src):
    _taint_flows(src)  # must not raise / hang


def test_deterministic_across_runs():
    src = (
        "var res=$.ajax({async:false}); var l=res.responseJSON;"
        ' l.forEach(function(it){ box.append(`<img src="${it.url}">`); });'
    )

    def sig():
        return [(f.line, f.metadata["source_kind"], f.metadata["sink"]) for f in _taint_flows(src)]

    assert sig() == sig()


@pytest.mark.parametrize(
    "src",
    [
        "if(false){ el.innerHTML=location.hash; }",
        "false && el.html(location.hash);",
        "true || el.html(location.hash);",
        'var x="safe"; switch(1){case 1: break; case 2: x=location.hash;} el.innerHTML=x;',
    ],
)
def test_constant_control_flow_does_not_execute_unreachable_sinks(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src",
    [
        "var o={}; var alias=o; alias.value=location.hash; el.innerHTML=o.value;",
        "var o={value:location.hash}; el.innerHTML=o.value;",
        "var values=[location.hash]; el.innerHTML=values[0];",
    ],
)
def test_heap_alias_and_container_flows_are_tracked(src):
    flows = _taint_flows(src)
    assert flows and flows[0].metadata["confirmed"] is True


def test_named_promise_callback_and_fetch_body_transform_preserve_response_taint():
    src = (
        'function render(value){ el.innerHTML=value; } fetch("/x").then(r=>r.text()).then(render);'
    )
    flows = _taint_flows(src)
    assert flows and flows[0].metadata["source_kind"] == "ajax_response"


@pytest.mark.parametrize(
    "src,source_kind",
    [
        (
            'addEventListener("message", function(event){ el.innerHTML=event.data; });',
            "postmessage",
        ),
        ('el.innerHTML=localStorage.getItem("preview");', "browser_storage"),
    ],
)
def test_browser_event_and_storage_sources(src, source_kind):
    flows = _taint_flows(src)
    assert flows and flows[0].metadata["source_kind"] == source_kind


def test_only_verified_html_sanitizers_kill_taint():
    assert _taint_flows("el.innerHTML=DOMPurify.sanitize(location.hash);") == []
    unverified = _taint_flows("el.innerHTML=custom.sanitize(location.hash);")
    assert unverified and unverified[0].metadata["confirmed"] is False


@pytest.mark.parametrize(
    "label,src",
    [
        # Regressions for the 6 bugs the adversarial verification surfaced (all must be 0 findings):
        (
            "flow-insensitive: source after sink",
            'function f(){ var v="safe"; document.write(v); v=location.hash; }',
        ),
        (
            "placeholder then reused",
            'function s(){ var m="loading"; $("#x").html(m); m=location.hash; }',
        ),
        (
            "cross-object mis-resolution",
            'function helper(p){ $("#x").html(p); }\nsomeObject.helper(location.hash);',
        ),
        (
            "cross-object return",
            'var c={build:function(x){return document.cookie;}};\nfunction d(w){ var h=w.build("s"); w.el.innerHTML=h; }',
        ),
        (
            "block-scope sibling collapse",
            'function h(){ { let x="safe"; document.write(x); } { let x=location.hash; use(x); } }',
        ),
        (
            "FileReader name across scopes",
            "function a(){ var reader=new FileReader(); reader.readAsText(f); }\n"
            'function b(){ var reader=getSock(); reader.onload=function(e){ $("#o").html(e.target.result); }; }',
        ),
        (
            "jQuery .load is not an ajax source",
            "function f(){ var r=$(window).load(function(){}); el.innerHTML=r; }",
        ),
    ],
)
def test_verification_bug_regressions(label, src):
    assert _taint_flows(src) == [], f"regressed: {label}"


@pytest.mark.parametrize(
    "label,src",
    [
        # Branch-merge: taint in one branch must not leak into a mutually-exclusive branch's sink.
        (
            "if/else default-or-render",
            'function d(m){ var x="Welcome"; if(m==="e"){ x=location.hash; } else { document.write(x); } }',
        ),
        (
            "switch case-break",
            'function f(k){ var x="safe"; switch(k){ case 1: x=location.hash; break; case 2: $("#a").html(x); break; } }',
        ),
        (
            "try then catch",
            'function f(){ var x="safe"; try{ x=location.hash; } catch(e){ $("#a").html(x); } }',
        ),
    ],
)
def test_branch_merge_no_leak(label, src):
    assert _taint_flows(src) == [], f"branch leak: {label}"


# ---------------------------------------------------------------- open-redirect / navigation sinks


def _sinks(src):
    return [(f.metadata["sink"], f.metadata["source_kind"]) for f in _taint_flows(src)]


@pytest.mark.parametrize(
    "label,src,sink,source",
    [
        (
            "location.hash -> location.href",
            "var q=location.hash; location.href=q;",
            "location.href=",
            "location",
        ),
        (
            "window.location.hash -> location.assign",
            "location.assign(window.location.hash);",
            "location.assign()",
            "location",
        ),
        (
            "location.search -> location.replace",
            "location.replace(location.search);",
            "location.replace()",
            "location",
        ),
        (
            "location.hash -> window.open",
            "window.open(location.hash);",
            "window.open()",
            "location",
        ),
        ("window.location = tainted", "window.location = location.hash;", "location=", "location"),
        (
            "dom input -> location.href",
            'var v=$("#x").val(); location.href=v;',
            "location.href=",
            "dom_input",
        ),
        (
            "ajax response -> location.href",
            '$.ajax({url:"/a"}).done(function(r){ location.href=r.next; });',
            "location.href=",
            "ajax_response",
        ),
    ],
)
def test_open_redirect_true_positives(label, src, sink, source):
    got = _sinks(src)
    assert (sink, source) in got, f"{label}: expected ({sink},{source}), got {got}"


@pytest.mark.parametrize(
    "label,src",
    [
        # same-origin location components are not attacker-controllable -> not an open redirect
        ("pathname redirect", "location.href = location.pathname;"),
        ("origin redirect", "location.href = location.origin + '/dashboard';"),
        ("host redirect", "location.assign(location.host);"),
        # object-root guards: str.replace / Object.assign / xhr.open are not navigation
        ("str.replace not nav", 'var u=location.hash; el.textContent=u.replace("a","b");'),
        ("Object.assign not nav", "var o=Object.assign({}, location.hash);"),
        ("xhr.open not nav", 'xhr.open("GET", location.hash);'),
        ("bare open() not nav", "var f=open; f(location.hash);"),
        # static / clean values are not flows
        ("static redirect literal", 'location.href="/home";'),
        (
            "bare location= is ambiguous (react-router)",
            "var location=useLocation(); location = next;",
        ),
        # app object .location is not the URL global
        ("store.location is not a URL", "location.href = store.location.name;"),
    ],
)
def test_open_redirect_false_positives(label, src):
    assert _sinks(src) == [], f"nav FP: {label}"


# ---------------------------------------------------------------- window.location source recognition


@pytest.mark.parametrize(
    "src",
    [
        "el.innerHTML = window.location.hash;",
        "el.html(document.location.href);",
        "el.innerHTML = self.location.search;",
        "var l = window.location; el.innerHTML = l.hash;",  # aliased
    ],
)
def test_window_location_is_a_url_source(src):
    assert any(f.metadata["source_kind"] == "location" for f in _taint_flows(src)), src


@pytest.mark.parametrize(
    "src",
    [
        "el.innerHTML = store.location.name;",
        "el.html(router.location.pathname);",
        "el.innerHTML = marker.location.lat;",
    ],
)
def test_app_object_location_is_not_a_source(src):
    assert _taint_flows(src) == [], src


# ---------------------------------------------------------------- jQuery $(builtHtml) DOM-XSS sink


@pytest.mark.parametrize(
    "label,src,source",
    [
        ("$('<div>'+tainted)", 'var u=location.hash; $("<div>"+u+"</div>");', "location"),
        ("$(`<a href=${u}>`)", "var u=location.hash; $(`<a href='${u}'>x</a>`);", "location"),
        ("jQuery(built html)", "var u=location.hash; jQuery(`<b>${u}</b>`);", "location"),
        (
            "$() ajax html",
            '$.ajax({url:"/a"}).done(function(r){ $("<li>"+r.name+"</li>"); });',
            "ajax_response",
        ),
    ],
)
def test_jquery_html_construction_is_a_sink(label, src, source):
    got = _sinks(src)
    assert ("$() html", source) in got, f"{label}: got {got}"


@pytest.mark.parametrize(
    "src",
    [
        'var id=$("#x").val(); $("#"+id);',  # selector construction, not HTML
        "var c=location.hash; $(`#${c}`);",  # template selector
        "var u=location.hash; $(u);",  # bare tainted arg (selector-vs-html ambiguous)
        '$("<div>static</div>");',  # clean literal
    ],
)
def test_jquery_selector_is_not_a_sink(src):
    assert not any(f.metadata["sink"] == "$() html" for f in _taint_flows(src)), src


@pytest.mark.parametrize(
    "src,sink",
    [
        ('$("<div>"+location.hash+"</div>").appendTo("#log");', ".appendto()"),
        ('$("<li>"+location.hash).prependTo(list);', ".prependto()"),
        ('$("<b>"+location.hash+"</b>").insertAfter(el);', ".insertafter()"),
    ],
)
def test_jquery_reverse_insertion_is_a_sink(src, sink):
    # $('<div>'+tainted).appendTo(t) -- built HTML is the receiver, not the arg
    assert (sink, "location") in _sinks(src), src


@pytest.mark.parametrize(
    "src",
    [
        '$("#existing").appendTo("#target");',  # selector receiver, no HTML built
        'var el=$("#x"); el.appendTo("#y");',  # non-jQuery-factory receiver
        '$("<div>"+"static").appendTo("#t");',  # clean concat
    ],
)
def test_jquery_reverse_insertion_no_false_positive(src):
    assert _sinks(src) == [], src


@pytest.mark.parametrize(
    "label,src",
    [
        (
            "taint then sink inside if",
            "function f(c){ if(c){ var x=location.hash; document.write(x); } }",
        ),
        (
            "taint in if, sink after join",
            'function f(c){ var x="s"; if(c){ x=location.hash; } document.write(x); }',
        ),
        (
            "source before, sink in a branch",
            "function f(c){ var x=location.hash; if(c){ el.innerHTML=x; } }",
        ),
        (
            "try/finally is a real flow",
            "function f(){ var x=location.hash; try{ risky(); } finally { el.innerHTML=x; } }",
        ),
    ],
)
def test_branch_true_positives_preserved(label, src):
    assert _taint_flows(src), f"missed real branch flow: {label}"


def test_context_sensitive_only_tainted_call_flags():
    # pt(location.hash) flags; pt("safe") does not -- even through a local intermediary var.
    src = 'function pt(x){ var t=x; return t; }\nel.html(pt(location.hash));\n$("#o").html(pt("safe"));'
    flows = _taint_flows(src)
    assert [f.line for f in flows] == [2]


def test_engine_registered_and_runs_in_pipeline():
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    assert any(r.id == "taint-flow-detector" for r in eng.rules)
    src = "var u=location.hash; el.innerHTML=u;"
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    fs = eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src))
    assert any(f.value_type == "taint_flow" for f in fs)


# ---------------------------------------------------------------- DQ-C03: `confirmed` must be SOUND


@pytest.mark.parametrize(
    "label,src",
    [
        ("unreachable after return", "function f(){let x=location.hash;return;el.innerHTML=x}"),
        (
            "unreachable after throw",
            "function f(){let x=location.hash;throw new Error();el.innerHTML=x}",
        ),
        ("unreachable after break", "for(;;){break;el.innerHTML=location.hash;}"),
        (
            "loop first-iteration is safe",
            "for(let x='safe';true;x=location.hash){el.innerHTML=x;break}",
        ),
        ("mutually-exclusive conditions", "let x; if(c){x=location.hash;} if(!c){el.innerHTML=x;}"),
        (
            "loop-escaped taint (loop may run 0x)",
            "var x; for(var i=0;i<n;i++){ x=location.hash; } el.innerHTML=x;",
        ),
        ("for-of-escaped taint", "var x; for(const k of arr){ x=location.hash; } el.innerHTML=x;"),
        (
            "sink after both-branches-return",
            "function f(c){var x=location.hash; if(c){return;}else{return;} el.innerHTML=x;}",
        ),
        (
            "sink after try-throw-catch-return",
            "function f(){var x=location.hash; try{throw e;}catch(e){return;} el.innerHTML=x;}",
        ),
        (
            "sink after switch all-cases-return+default",
            "var u=location.hash; switch(x){case 1: return; default: return;} el.innerHTML=u;",
        ),
        (
            "sink after switch empty-fallthrough+default",
            "var u=location.hash; switch(x){case 1: default: return;} el.innerHTML=u;",
        ),
    ],
)
def test_no_unsound_confirmed_flow(label, src):
    """INV-05 / DQ-C03: a flow through a construct the intra-file evaluator only APPROXIMATES
    (post-terminator dead code, loop body, cross-branch merge) must NEVER be badged `confirmed`.
    It is either dropped (unreachable statements are not analyzed) or demoted to `probable` -- never
    a false proven vulnerability. These are all clean FULL parses, so the degraded-parse abstention
    does not apply; only the CFG-soundness containment does."""
    for f in _taint_flows(src):
        assert f.metadata.get("confirmed") is not True, f"unsound confirmed: {label}"
        assert f.metadata.get("evidence") == "probable"


def test_straight_line_flow_stays_confirmed():
    """The containment must NOT demote a genuinely sound straight-line def-use chain."""
    flows = _taint_flows("var u=location.hash; el.innerHTML=u;")
    assert len(flows) == 1
    assert flows[0].metadata.get("confirmed") is True
    assert flows[0].metadata.get("evidence") == "confirmed"


def test_unreachable_after_terminator_yields_no_flow():
    """The unreachable-sink cases are dropped entirely (0 findings), not merely demoted."""
    assert _taint_flows("function f(){let x=location.hash;return;el.innerHTML=x}") == []
    assert _taint_flows("for(;;){break;el.innerHTML=location.hash;}") == []
    assert (
        _taint_flows(
            "function f(c){var x=location.hash; if(c){return;}else{return;} el.innerHTML=x;}"
        )
        == []
    )


@pytest.mark.parametrize(
    "label,src",
    [
        ("straight-line", "var u=location.hash; el.innerHTML=u;"),
        ("sink before return", "function f(){var x=location.hash; el.innerHTML=x; return;}"),
        (
            "one-armed if then sink (reachable when !c)",
            "function f(c){var x=location.hash; if(c){return;} el.innerHTML=x;}",
        ),
        (
            "sink in finally",
            "function f(){var x=location.hash; try{ risky(); } finally { el.innerHTML=x; }}",
        ),
        # taint assigned BEFORE the loop (not inside the body) must NOT be demoted by the loop-escape rule
        (
            "taint before loop, used after",
            "var x=location.hash; for(var i=0;i<3;i++){ log(x); } el.innerHTML=x;",
        ),
        # a switch that CAN complete normally (break / no default / non-diverging default) is reachable
        (
            "switch with break is reachable",
            "var u=location.hash; switch(x){case 1: doX(); break; default: return;} el.innerHTML=u;",
        ),
        (
            "switch without default is reachable",
            "var u=location.hash; switch(x){case 1: return; case 2: return;} el.innerHTML=u;",
        ),
    ],
)
def test_sound_flow_stays_confirmed(label, src):
    """The unreachable/loop-escape containment must NOT over-demote a genuinely sound reachable flow.
    In particular, taint established BEFORE a loop and used after it stays confirmed."""
    flows = _taint_flows(src)
    assert flows, f"lost a real flow: {label}"
    assert any(f.metadata.get("confirmed") is True for f in flows), f"over-demoted: {label}"


@pytest.mark.parametrize(
    "src",
    [
        'fetch("/x").then(r => "safe").then(x => { el.innerHTML=x; });',
        (
            'function clean(r){return "safe"} function render(x){el.innerHTML=x} '
            'fetch("/x").then(clean).then(render);'
        ),
        (
            'fetch("/x").then(r => DOMPurify.sanitize(r.text()))'
            '.then(x => { el.innerHTML=x; });'
        ),
        'Promise.resolve("safe").then(x => { el.innerHTML=x; });',
        'let x="safe"; true ?? (x=location.hash); el.innerHTML=x;',
        'let x="safe"; "present" ?? (x=location.hash); el.innerHTML=x;',
        'let x;c&&(x=location.hash);!c&&(el.innerHTML=x);',
        'let x="safe";c?(x=location.hash):0;!c?(el.innerHTML=x):0;',
        'function f(c){let x="safe";if(c){x=location.hash;return;}el.innerHTML=x;}',
        (
            'function f(k){let x="safe";switch(k){case 1:x=location.hash;return;'
            'default:x="safe";}el.innerHTML=x;}'
        ),
        'var x="safe";try{x=location.hash;throw e;}catch(e){x="safe";}el.innerHTML=x;',
        'function f(){let x=location.hash;while(true){}el.innerHTML=x;}',
        'function f(){let x="safe";for(;;){x=location.hash;return;}el.innerHTML=x;}',
        (
            'function f(c){let x="safe";while(true){if(c){break;}x=location.hash;}'
            'el.innerHTML=x;}'
        ),
        'fetch("/x").then(r=>Promise.resolve("safe")).then(x=>el.innerHTML=x);',
        'let x="safe";fetch("/x").then(()=>{x=location.hash});el.innerHTML=x;',
        'function clean(o){o.value="safe"}var o={value:location.hash};'
        'clean(o);el.innerHTML=o.value;',
        'var o={value:location.hash,clean:function(){this.value="safe"}};'
        'o.clean();el.innerHTML=o.value;',
        'let x=location.hash;function clean(){x="safe"}clean();el.innerHTML=x;',
        'var o={render:function(x){el.innerHTML=x},render:function(x){use(x)}};'
        'o.render(location.hash);',
    ],
)
def test_cfg_promise_and_receiver_false_positive_regressions(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src,source_kind",
    [
        ('fetch("/x").then(r=>r.text()).then(x=>{el.innerHTML=x;});', "ajax_response"),
        ('Promise.resolve(location.hash).then(x=>{el.innerHTML=x;});', "location"),
        ('var o={};var a;a=o;a.value=location.hash;el.innerHTML=o.value;', "location"),
        ('var a=[];var b;b=a;b[0]=location.hash;el.innerHTML=a[0];', "location"),
        ('var o={value:location.hash};var {value}=o;el.innerHTML=value;', "location"),
        ('var {value}={value:location.hash};el.innerHTML=value;', "location"),
        ('var o={};var k="value";o[k]=location.hash;el.innerHTML=o.value;', "location"),
        (
            'let current="safe",next="safe";for(let i=0;i<n;i++)'
            '{current=next;next=location.hash;}el.innerHTML=current;',
            "location",
        ),
        (
            'let current="safe",next="safe";do{current=next;next=location.hash;}'
            'while(c);el.innerHTML=current;',
            "location",
        ),
        ('let x;c&&(x=location.hash);c&&(el.innerHTML=x);', "location"),
        (
            'function f(c){let x="safe";if(c){c=false;x=location.hash;}'
            'if(!c){el.innerHTML=x;}}',
            "location",
        ),
        ('function render(x){el.innerHTML=x}setTimeout(render,0,location.hash);', "location"),
        ('var o={render:function(x){el.innerHTML=x}};o.render(location.hash);', "location"),
        ('class O{render(x){el.innerHTML=x}}var o=new O();o.render(location.hash);', "location"),
        (
            'function render(o){el.innerHTML=o.value}var o={value:location.hash};render(o);',
            "location",
        ),
        (
            'var o={value:location.hash,render:function(){el.innerHTML=this.value}};o.render();',
            "location",
        ),
        (
            'function set(o){o.value=location.hash}var o={};set(o);el.innerHTML=o.value;',
            "location",
        ),
        (
            'var o={set:function(){this.value=location.hash}};o.set();el.innerHTML=o.value;',
            "location",
        ),
        ('let x="safe";function set(){x=location.hash}set();el.innerHTML=x;', "location"),
        (
            'fetch("/x").then(r=>Promise.resolve(r.text()))'
            '.then(x=>el.innerHTML=x);',
            "ajax_response",
        ),
        (
            'let x="safe";fetch("/x").then(()=>{x=location.hash})'
            '.then(()=>{el.innerHTML=x});',
            "location",
        ),
        ('var x="safe";try{x=location.hash;throw e;}catch(e){}el.innerHTML=x;', "location"),
    ],
)
def test_cfg_promise_heap_and_receiver_recall_regressions(src, source_kind):
    flows = _taint_flows(src)
    assert flows
    assert any(flow.metadata["source_kind"] == source_kind for flow in flows)


def test_possible_exception_state_is_probable_and_clean_catch_kills_taint():
    possible = _taint_flows(
        'var x="safe";try{x=location.hash;mightThrow();x="safe";}catch(e){}el.innerHTML=x;'
    )
    assert possible and possible[0].metadata["evidence"] == "probable"
    assert (
        _taint_flows(
            'var x="safe";try{x=location.hash;mightThrow();x="safe";}'
            'catch(e){x="safe";}el.innerHTML=x;'
        )
        == []
    )


@pytest.mark.parametrize(
    "src",
    [
        'let x="safe";if(mode==="a"){x=location.hash}if(mode!=="a"){el.innerHTML=x}',
        'let x="safe";if(mode==="a"){x=location.hash}if(mode==="b"){el.innerHTML=x}',
        (
            'let x="safe";if(typeof mode==="string"){x=location.hash}'
            'if(typeof mode!=="string"){el.innerHTML=x}'
        ),
        'let x=location.hash;const f=()=>{el.innerHTML=x};',
        'let x=location.hash;const f=function(){el.innerHTML=x};',
        'let x=location.hash;const o={m:function(){el.innerHTML=x}};',
        'let f=x=>x;f=x=>"safe";el.innerHTML=f(location.hash)',
        'var o={m:function(x){return x}};o.m=x=>"safe";el.innerHTML=o.m(location.hash)',
        '[location.hash,"safe"].forEach((x,i)=>{if(i===1)el.innerHTML=x})',
        'let s=location.hash;s.forEach(x=>el.innerHTML=x)',
        'let x="safe",o;o?.m(x=location.hash);el.innerHTML=x',
        'let x="safe",f;f?.(x=location.hash);el.innerHTML=x',
        'let x="present";x ||= location.hash;el.innerHTML=x',
        'let x="present";x ??= location.hash;el.innerHTML=x',
        'let x="";x &&= location.hash;el.innerHTML=x',
    ],
)
def test_execution_timing_and_path_correlation_false_positive_regressions(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src,evidence",
    [
        (
            'let x="safe";if(mode==="a"){x=location.hash;mode="b"}'
            'if(mode==="b"){el.innerHTML=x}',
            "probable",
        ),
        ('(function(x){el.innerHTML=x})(location.hash)', "confirmed"),
        ('(x=>{el.innerHTML=x})(location.hash)', "confirmed"),
        ('let f;f=x=>x;el.innerHTML=f(location.hash)', "confirmed"),
        ('function f(x){return x}let g=f;el.innerHTML=g(location.hash)', "confirmed"),
        ('let f=x=>"safe";f=x=>x;el.innerHTML=f(location.hash)', "confirmed"),
        (
            'function outer(){let y=location.hash;return ()=>y}'
            'let f=outer();el.innerHTML=f()',
            "confirmed",
        ),
        ('var o={m:x=>"safe"};o.m=x=>x;el.innerHTML=o.m(location.hash)', "confirmed"),
        ('let x=location.hash;[1].forEach(()=>el.innerHTML=x)', "confirmed"),
        ('["safe",location.hash].forEach((x,i)=>{if(i===1)el.innerHTML=x})', "confirmed"),
        ('let x=location.hash;button.addEventListener("click",()=>el.innerHTML=x)', "probable"),
        ('let x=location.hash;queueMicrotask(()=>el.innerHTML=x)', "probable"),
        ('let x="safe";[1].forEach(()=>x=location.hash);el.innerHTML=x', "confirmed"),
    ],
)
def test_exact_callable_and_callback_recall_regressions(src, evidence):
    flows = _taint_flows(src)
    assert flows
    assert any(flow.metadata["source_kind"] == "location" for flow in flows)
    assert all(flow.metadata["evidence"] == evidence for flow in flows)


def test_same_named_classes_resolve_by_lexical_binding():
    clean = (
        'function a(){class O{m(x){el.innerHTML=x}}}'
        'function b(){class O{m(x){use(x)}}let o=new O();o.m(location.hash)}b()'
    )
    tainted = (
        'function a(){class O{m(x){use(x)}}}'
        'function b(){class O{m(x){el.innerHTML=x}}let o=new O();o.m(location.hash)}b()'
    )
    assert _taint_flows(clean) == []
    assert _taint_flows(tainted)


@pytest.mark.parametrize(
    "src",
    [
        'let o={x:"safe"};let a=o;o={x:location.hash};el.innerHTML=a.x',
        'let o={x:location.hash};let b={...o,x:"safe"};el.innerHTML=b.x',
        'let a=["safe",location.hash];let b=[...a];el.innerHTML=b[0]',
        'let k="x";let o={[k]:location.hash};el.innerHTML=o.k',
        'let t={x:location.hash};Object.assign(t,{x:"safe"});el.innerHTML=t.x',
        'let a=[];a.push("safe");el.innerHTML=a[0]',
        'let a=[location.hash];a.length=0;el.innerHTML=a[0]',
        'let o={x:location.hash};o.x="safe";let b={x:location.hash,...o};el.innerHTML=b.x',
        'let x=location.hash;[].forEach(()=>el.innerHTML=x)',
        'let o={};let {x="safe"}=o;el.innerHTML=x',
        'let o={x:location.hash};let {x,...r}=o;el.innerHTML=r.x',
        'function f(x=location.hash){el.innerHTML=x}f("safe")',
    ],
)
def test_allocation_heap_and_destructure_false_positive_regressions(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src",
    [
        'let o={x:location.hash};let a=o;o={x:"safe"};el.innerHTML=a.x',
        'let o={x:"safe"};let b={...o,x:location.hash};el.innerHTML=b.x',
        'let a=["safe",location.hash];let b=[...a];el.innerHTML=b[1]',
        'let k="x";let o={[k]:location.hash};el.innerHTML=o.x',
        'function f(o){el.innerHTML=o.x}f({x:location.hash})',
        'let t={x:"safe"};Object.assign(t,{x:location.hash});el.innerHTML=t.x',
        'let t=Object.assign({}, {x:location.hash});el.innerHTML=t.x',
        'let a=[];a.push(location.hash);el.innerHTML=a[0]',
        'let a=[location.hash];el.innerHTML=a.pop()',
        'let a=["safe"];a.unshift(location.hash);el.innerHTML=a[0]',
        'let x="safe",o={};o[(x=location.hash,"k")];el.innerHTML=x',
        'let x="safe";let o={[(x=location.hash,"k")]:"safe"};el.innerHTML=x',
        'let o={x:location.hash};let {x="safe"}=o;el.innerHTML=x',
        'let o={a:"safe",x:location.hash};let {a,...r}=o;el.innerHTML=r.x',
        'let a=["safe",location.hash];let [first,...r]=a;el.innerHTML=r[0]',
        'function f({x}){el.innerHTML=x}f({x:location.hash})',
        'function f(x=location.hash){el.innerHTML=x}f()',
        'function f(...xs){el.innerHTML=xs[1]}f("safe",location.hash)',
        'function add(a){a.push(location.hash)}let a=[];add(a);el.innerHTML=a[0]',
    ],
)
def test_allocation_heap_and_destructure_recall_regressions(src):
    flows = _taint_flows(src)
    assert flows
    assert any(flow.metadata["source_kind"] == "location" for flow in flows)


@pytest.mark.parametrize(
    "src",
    [
        'function f(){try{return location.hash}finally{return "safe"}}el.innerHTML=f()',
        'function f(){try{return location.hash}finally{throw 1}}el.innerHTML=f()',
        (
            'function f(){try{throw 1}catch(e){return location.hash}'
            'finally{return "safe"}}el.innerHTML=f()'
        ),
        (
            'function f(c){try{return location.hash}finally{if(c)return "safe"}}'
            'el.innerHTML=f(true)'
        ),
        'for(let i=0;i<1;el.innerHTML=location.hash){return}',
        'new Promise(r=>{r("safe");r(location.hash)}).then(x=>el.innerHTML=x)',
        'new Promise((r,j)=>{j("safe");r(location.hash)}).then(x=>el.innerHTML=x)',
        'Promise.resolve("safe").then(x=>el.innerHTML=x)',
        'Promise.reject("safe").catch(x=>el.innerHTML=x)',
        'let promise={resolve:x=>x};promise.resolve(location.hash).then(x=>el.innerHTML=x)',
        (
            'Promise.all([Promise.resolve("safe"),Promise.resolve(location.hash)])'
            '.then(xs=>el.innerHTML=xs[0])'
        ),
        'async function f(){return "safe"}f().then(x=>el.innerHTML=x)',
    ],
)
def test_try_promise_and_loop_false_positive_regressions(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src",
    [
        'function f(){try{return location.hash}finally{log(1)}}el.innerHTML=f()',
        'function f(){try{return "safe"}finally{return location.hash}}el.innerHTML=f()',
        'function f(){try{throw 1}catch(e){return location.hash}}el.innerHTML=f()',
        (
            'function f(){try{try{return location.hash}finally{log(1)}}'
            'finally{log(2)}}el.innerHTML=f()'
        ),
        'Promise.reject(location.hash).catch(x=>el.innerHTML=x)',
        (
            'Promise.resolve("safe").then(()=>Promise.reject(location.hash))'
            '.catch(x=>el.innerHTML=x)'
        ),
        'new Promise((resolve,reject)=>resolve(location.hash)).then(x=>el.innerHTML=x)',
        'new Promise((resolve,reject)=>reject(location.hash)).catch(x=>el.innerHTML=x)',
        'Promise.resolve({x:location.hash}).then(o=>el.innerHTML=o.x)',
        'let p=Promise.resolve(location.hash);p.then(x=>el.innerHTML=x)',
        'let p=new Promise(r=>r(location.hash));p.then(x=>el.innerHTML=x)',
        'async function f(){let x=await Promise.resolve(location.hash);el.innerHTML=x}f()',
        'async function f(){return location.hash}f().then(x=>el.innerHTML=x)',
        (
            'Promise.all([Promise.resolve("safe"),Promise.resolve(location.hash)])'
            '.then(xs=>el.innerHTML=xs[1])'
        ),
        'Promise.all([Promise.reject(location.hash)]).catch(x=>el.innerHTML=x)',
        'let x=location.hash;Promise.all([]).then(()=>el.innerHTML=x)',
    ],
)
def test_try_promise_and_loop_recall_regressions(src):
    flows = _taint_flows(src)
    assert flows
    assert any(flow.metadata["source_kind"] == "location" for flow in flows)


@pytest.mark.parametrize(
    "src",
    [
        "el.innerHTML=DOMPurify.sanitize(location.hash)",
        "const dp=DOMPurify;el.innerHTML=dp.sanitize(location.hash)",
        "el.innerHTML=encodeURI(location.hash)",
        'a.setAttribute("href",encodeURIComponent(location.hash))',
        "eval(Number(location.hash))",
        "el.innerHTML=parseInt(location.hash)",
    ],
)
def test_verified_context_compatible_sanitizers_suppress_taint(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src",
    [
        "function sanitize(x){return x}el.innerHTML=sanitize(location.hash)",
        "function Number(x){return x}eval(Number(location.hash))",
        "let o={getTime(){return location.hash}};eval(o.getTime())",
        "let o={toFixed(){return location.hash}};el.innerHTML=o.toFixed()",
        "eval(DOMPurify.sanitize(location.hash))",
        (
            "let DOMPurify={sanitize(x){return x}};"
            "el.innerHTML=DOMPurify.sanitize(location.hash)"
        ),
        'a.setAttribute("href",encodeURI(location.hash))',
        "eval(encodeURI(location.hash))",
    ],
)
def test_sanitizer_shadowing_and_context_mismatch_preserve_taint(src):
    flows = _taint_flows(src)
    assert flows
    assert any(flow.metadata["source_kind"] == "location" for flow in flows)
    assert all(flow.metadata["evidence"] == "confirmed" for flow in flows)


def test_unverified_sanitizer_like_method_preserves_probable_taint():
    flows = _taint_flows("el.innerHTML=obj.sanitize(location.hash)")
    assert flows
    assert all(flow.metadata["evidence"] == "probable" for flow in flows)
    assert all(flow.metadata["confirmed"] is False for flow in flows)


@pytest.mark.parametrize(
    "src",
    [
        'for(const x of ["safe"]){el.innerHTML=x}',
        "let x=location.hash;for(const y of []){el.innerHTML=x}",
        'let x;for(x of [location.hash,"safe"]){}el.innerHTML=x',
        'let a=[location.hash];let b=a.map(x=>"safe");el.innerHTML=b[0]',
        (
            'let a=[location.hash];a.map=callback=>["safe"];'
            "let b=a.map(x=>x);el.innerHTML=b[0]"
        ),
        "let a=[location.hash];let b=a.filter(()=>false);el.innerHTML=b[0]",
        "let a=[location.hash];let x=a.find(()=>false);el.innerHTML=x",
        'let a=[location.hash,"safe"];a.reverse();el.innerHTML=a[0]',
        'let a=[location.hash,"safe"];let b=a.slice(1);el.innerHTML=b[0]',
        (
            'let a=[location.hash];let b=["safe"].concat(a);'
            "el.innerHTML=b[0]"
        ),
        'let a=[location.hash,"safe"];el.innerHTML=a.at(1)',
        (
            'let a=[location.hash,"safe"];a.splice(0,1);'
            "el.innerHTML=a[0]"
        ),
        'let a=[location.hash];a.fill("safe");el.innerHTML=a[0]',
        (
            'let a=[location.hash,"safe"];a.copyWithin(0,1);'
            "el.innerHTML=a[0]"
        ),
        (
            'Promise.resolve(location.hash).then(()=>{throw "safe"})'
            ".catch(x=>el.innerHTML=x)"
        ),
        (
            'Promise.resolve(location.hash).finally(()=>{throw "safe"})'
            ".catch(x=>el.innerHTML=x)"
        ),
        'function* g(){yield "safe"}el.innerHTML=g().next().value',
        'let o={get x(){return "safe"}};el.innerHTML=o.x',
        'class O{static f(x){el.innerHTML=x}}let o=new O();o.f(location.hash)',
        (
            'class O{constructor(x){this.value="safe"}}'
            "let o=new O(location.hash);el.innerHTML=o.value"
        ),
        'function eval(x){return "safe"}eval(location.hash)',
        (
            "function fetch(x){return location.hash}"
            'fetch("/x").then(x=>el.innerHTML=x)'
        ),
        (
            "let o={x:location.hash};let {[\"x\"]:x,...r}=o;"
            "el.innerHTML=r.x"
        ),
        'let o=false?{x:location.hash}:{x:"safe"};el.innerHTML=o.x',
        'let o={x:"safe"}??{x:location.hash};el.innerHTML=o.x',
        'let o={x:"safe"}||{x:location.hash};el.innerHTML=o.x',
        (
            "let o=c?{x:location.hash}:{x:\"safe\"};"
            "if(!c)el.innerHTML=o.x"
        ),
        (
            'function f(x){el.innerHTML=x}let g=f.bind(null,"safe");'
            "g()"
        ),
        'try{throw "safe"}catch(e){el.innerHTML=e}',
        (
            'let a=[location.hash];let b=a.flatMap(()=>["safe"]);'
            "el.innerHTML=b[0]"
        ),
        (
            'let a=Array.from([location.hash],()=>"safe");'
            "el.innerHTML=a[0]"
        ),
        "let a=Object.keys({x:location.hash});el.innerHTML=a[0]",
        (
            "class A{m(x){el.innerHTML=x}}"
            "class B extends A{m(x){use(x)}}"
            "let b=new B();b.m(location.hash)"
        ),
        (
            "function O(){}O.prototype.m=function(x){el.innerHTML=x};"
            "O.prototype.m=function(x){use(x)};"
            "let o=new O();o.m(location.hash)"
        ),
        (
            "class A{constructor(x){this.v=x}}"
            'class B extends A{constructor(x){super("safe")}}'
            "let b=new B(location.hash);el.innerHTML=b.v"
        ),
        (
            "class A{m(x){el.innerHTML=x}}"
            'class B extends A{m(x){super.m("safe")}}'
            "new B().m(location.hash)"
        ),
        (
            'class A{get x(){return "safe"}}'
            "class B extends A{get y(){return super.x}}"
            "let unrelated=location.hash;el.innerHTML=new B().y"
        ),
        (
            "function* g(){yield location.hash;return \"safe\"}"
            "let i=g();i.next();el.innerHTML=i.next().value"
        ),
        (
            "function* g(){return location.hash}"
            "let i=g();i.next();el.innerHTML=i.next().value"
        ),
        (
            'Promise.race([Promise.resolve("safe"),'
            "Promise.resolve(location.hash)]).then(x=>el.innerHTML=x)"
        ),
        (
            'Promise.any([Promise.resolve("safe"),'
            "Promise.resolve(location.hash)]).then(x=>el.innerHTML=x)"
        ),
        (
            'Promise.race([Promise.reject("safe"),'
            "Promise.resolve(location.hash)]).catch(x=>el.innerHTML=x)"
        ),
        'class B{get x(){return "safe"}}el.innerHTML=new B().x',
    ],
)
def test_iterator_promise_generator_and_accessor_false_positive_regressions(src):
    assert _taint_flows(src) == []


@pytest.mark.parametrize(
    "src",
    [
        "for(const x of [location.hash]){el.innerHTML=x}",
        'let x;for(x of ["safe",location.hash]){}el.innerHTML=x',
        (
            'let a=["safe",location.hash];for(const x of a)'
            "{if(x)el.innerHTML=x}"
        ),
        'let a=[location.hash];let b=a.map(x=>x);el.innerHTML=b[0]',
        (
            "let a=[{x:location.hash}];let b=a.map(x=>x);"
            "el.innerHTML=b[0].x"
        ),
        "let a=[{x:location.hash}];let b=a.shift();el.innerHTML=b.x",
        "let a=[{x:location.hash}];let b=a.pop();el.innerHTML=b.x",
        "let a=[location.hash];let b=a.filter(()=>true);el.innerHTML=b[0]",
        "let a=[location.hash];let x=a.find(()=>true);el.innerHTML=x",
        'let a=["safe",location.hash];a.reverse();el.innerHTML=a[0]',
        'let a=["safe",location.hash];let b=a.slice(1);el.innerHTML=b[0]',
        (
            'let a=[location.hash];let b=["safe"].concat(a);'
            "el.innerHTML=b[1]"
        ),
        'let a=["safe",location.hash];el.innerHTML=a.at(1)',
        (
            'let a=[location.hash,"safe"];let b=a.splice(0,1);'
            "el.innerHTML=b[0]"
        ),
        (
            'let a=[location.hash];let x=a.reduce((previous,value)=>value,"safe");'
            "el.innerHTML=x"
        ),
        (
            'Promise.resolve("safe").then(()=>{throw location.hash})'
            ".catch(x=>el.innerHTML=x)"
        ),
        "Promise.race([Promise.resolve(location.hash)]).then(x=>el.innerHTML=x)",
        "Promise.any([Promise.resolve(location.hash)]).then(x=>el.innerHTML=x)",
        (
            "Promise.allSettled([Promise.resolve(location.hash)])"
            ".then(xs=>el.innerHTML=xs[0].value)"
        ),
        (
            'Promise.resolve("safe").finally(()=>{throw location.hash})'
            ".catch(x=>el.innerHTML=x)"
        ),
        "function* g(){yield location.hash}el.innerHTML=g().next().value",
        "let o={get x(){return location.hash}};el.innerHTML=o.x",
        (
            'let o={get x(){return location.hash}};o.x="safe";'
            "el.innerHTML=o.x"
        ),
        "let o={set x(v){el.innerHTML=v}};o.x=location.hash",
        "class O{static f(x){return x}}el.innerHTML=O.f(location.hash)",
        (
            "class O{constructor(x){this.value=x}}"
            "let o=new O(location.hash);el.innerHTML=o.value"
        ),
        "class O{constructor(x){el.innerHTML=x}}new O(location.hash)",
        (
            "class O{constructor(){return {x:location.hash}}}"
            "let o=new O();el.innerHTML=o.x"
        ),
        "class O{m(x){return x}}el.innerHTML=new O().m(location.hash)",
        (
            "class O{constructor(x){this.x=x}m(){return this}}"
            "let o=new O(location.hash);el.innerHTML=o.m().x"
        ),
        "class O{static get x(){return location.hash}}el.innerHTML=O.x",
        "class O{static set x(v){el.innerHTML=v}}O.x=location.hash",
        "let o={get x(){return {v:location.hash}}};el.innerHTML=o.x.v",
        'let o=true?{x:location.hash}:{x:"safe"};el.innerHTML=o.x',
        "let o=null??{x:location.hash};el.innerHTML=o.x",
        "let o=true&&{x:location.hash};el.innerHTML=o.x",
        "let o=(0,{x:location.hash});el.innerHTML=o.x",
        "let o;el.innerHTML=(o={x:location.hash}).x",
        (
            "let o=c?{x:location.hash}:{x:location.hash};"
            "el.innerHTML=o.x"
        ),
        "function f(x){el.innerHTML=x}f.call(null,location.hash)",
        "function f(x){el.innerHTML=x}f.apply(null,[location.hash])",
        (
            "let o={v:location.hash,m(){el.innerHTML=this.v}};"
            "o.m.call(o)"
        ),
        (
            "function f(x){el.innerHTML=x}"
            "let g=f.bind(null,location.hash);g()"
        ),
        (
            "class O{static f(x){return x}}let f=O.f;"
            "el.innerHTML=f(location.hash)"
        ),
        (
            "function O(x){this.value=x}let o=new O(location.hash);"
            "el.innerHTML=o.value"
        ),
        (
            'let a=["safe",location.hash];a.copyWithin(0,1);'
            "el.innerHTML=a[0]"
        ),
        (
            'let a=["safe",location.hash];let b=a.slice(-1);'
            "el.innerHTML=b[0]"
        ),
        'let a=[location.hash,"safe"];el.innerHTML=a.at(-2)',
        "try{throw location.hash}catch(e){el.innerHTML=e}",
        "try{throw {x:location.hash}}catch(e){el.innerHTML=e.x}",
        "try{throw {x:location.hash}}catch({x}){el.innerHTML=x}",
        (
            "try{throw location.hash}catch(e){try{throw e}"
            "catch(x){el.innerHTML=x}}"
        ),
        (
            "try{try{}finally{throw location.hash}}"
            "catch(e){el.innerHTML=e}"
        ),
        (
            "async function f(){try{await Promise.reject(location.hash)}"
            "catch(e){el.innerHTML=e}}f()"
        ),
        (
            'let a=["safe"];let b=a.flatMap(()=>[location.hash]);'
            "el.innerHTML=b[0]"
        ),
        "let a=Array.from([location.hash]);el.innerHTML=a[0]",
        (
            'let a=Array.from(["safe"],()=>location.hash);'
            "el.innerHTML=a[0]"
        ),
        (
            'let a=Array.of("safe",location.hash);'
            "el.innerHTML=a[1]"
        ),
        "let a=Object.values({x:location.hash});el.innerHTML=a[0]",
        "let a=Object.entries({x:location.hash});el.innerHTML=a[0][1]",
        "for(const x of location.hash){el.innerHTML=x}",
        (
            'let xs=location.hash.split("");'
            "for(const x of xs){el.innerHTML=x}"
        ),
        (
            "async function f(){for await(const x of "
            "[Promise.resolve(location.hash)]){el.innerHTML=x}}f()"
        ),
        (
            "class A{m(x){el.innerHTML=x}}class B extends A{}"
            "let b=new B();b.m(location.hash)"
        ),
        (
            "let O=class{m(x){el.innerHTML=x}};"
            "let o=new O();o.m(location.hash)"
        ),
        (
            "function O(){}O.prototype.m=function(x){el.innerHTML=x};"
            "let o=new O();o.m(location.hash)"
        ),
        (
            "function f(x){el.innerHTML=x}"
            "Reflect.apply(f,null,[location.hash])"
        ),
        (
            "async function f(){let o=await Promise.resolve({x:location.hash});"
            "el.innerHTML=o.x}f()"
        ),
        "async function f(){throw location.hash}f().catch(x=>el.innerHTML=x)",
        "function f(){return {x:location.hash}}el.innerHTML=f().x",
        "let f=()=>({x:location.hash});el.innerHTML=f().x",
        (
            "function f(){return {a:{x:location.hash}}}let a=f().a;"
            "el.innerHTML=a.x"
        ),
        (
            'function f(a,b){el.innerHTML=b}let xs=["safe",location.hash];'
            "f(...xs)"
        ),
        (
            "class A{constructor(x){this.v=x}}"
            "class B extends A{constructor(x){super(x)}}"
            "let b=new B(location.hash);el.innerHTML=b.v"
        ),
        (
            "class A{m(x){el.innerHTML=x}}"
            "class B extends A{m(x){super.m(x)}}"
            "new B().m(location.hash)"
        ),
        (
            "class A{get x(){return location.hash}}"
            "class B extends A{get y(){return super.x}}"
            "el.innerHTML=new B().y"
        ),
        (
            "class A{set x(v){el.innerHTML=v}}"
            "class B extends A{m(v){super.x=v}}"
            "new B().m(location.hash)"
        ),
        (
            "class A{static m(x){el.innerHTML=x}}"
            "class B extends A{static n(x){super.m(x)}}"
            "B.n(location.hash)"
        ),
        (
            "class A{static get x(){return location.hash}}"
            "class B extends A{static get y(){return super.x}}"
            "el.innerHTML=B.y"
        ),
        (
            "class A{static set x(v){el.innerHTML=v}}"
            "class B extends A{static m(v){super.x=v}}"
            "B.m(location.hash)"
        ),
        (
            'Promise.race([Promise.resolve(location.hash),'
            'Promise.resolve("safe")]).then(x=>el.innerHTML=x)'
        ),
        (
            'Promise.any([Promise.resolve(location.hash),'
            'Promise.resolve("safe")]).then(x=>el.innerHTML=x)'
        ),
        (
            "Promise.race([Promise.reject(location.hash),"
            'Promise.resolve("safe")]).catch(x=>el.innerHTML=x)'
        ),
        "function* g(){return location.hash}el.innerHTML=g().next().value",
        (
            'function* g(){yield "safe";return location.hash}'
            "let i=g();i.next();el.innerHTML=i.next().value"
        ),
        (
            "class A{constructor(x){this.v=x}}class B extends A{}"
            "let b=new B(location.hash);el.innerHTML=b.v"
        ),
        (
            "class A{static m(x){el.innerHTML=x}}class B extends A{}"
            "B.m(location.hash)"
        ),
    ],
)
def test_iterator_promise_generator_and_accessor_recall_regressions(src):
    flows = _taint_flows(src)
    assert flows
    assert any(flow.metadata["source_kind"] == "location" for flow in flows)


def test_taint_budget_exhaustion_is_structured_incompleteness(monkeypatch):
    import bundleInspector.rules.detectors.taint as taint_module

    monkeypatch.setattr(taint_module, "_MAX_WORK", 5)
    source = ";".join(f"var x{i}=location.hash" for i in range(20))
    parsed = parse_js(source)
    ir = build_ir(parsed.ast, "budget.js", "h")
    context = AnalysisContext(file_url="budget.js", file_hash="h", source_content=source)
    list(TaintFlowDetector().match(ir, context))

    events = context.metadata.get("analysis_incomplete", [])
    assert any(
        event.get("component") == "taint_detector"
        and event.get("reason") == "taint_analysis_budget_exhausted"
        and event.get("partial_results") is True
        for event in events
    )


def test_budget_exhaustion_downgrades_findings_emitted_before_the_cap(monkeypatch):
    import bundleInspector.rules.detectors.taint as taint_module

    monkeypatch.setattr(taint_module, "_MAX_WORK", 15)
    source = "let x=location.hash;el.innerHTML=x;" + ";".join(
        f"var clean{i}='safe'" for i in range(50)
    )
    parsed = parse_js(source)
    ir = build_ir(parsed.ast, "budget-finding.js", "h")
    context = AnalysisContext(
        file_url="budget-finding.js", file_hash="h", source_content=source
    )
    flows = list(TaintFlowDetector().match(ir, context))

    assert flows
    assert all(flow.metadata["confirmed"] is False for flow in flows)
    assert all(flow.metadata["evidence"] == "probable" for flow in flows)
    assert all(flow.metadata["analysis_incomplete"] is True for flow in flows)
    assert all(flow.description.startswith("PROBABLE") for flow in flows)
    assert any(
        event.get("reason") == "taint_analysis_budget_exhausted"
        for event in context.metadata.get("analysis_incomplete", [])
    )


def test_recursion_limit_downgrades_findings_emitted_before_the_limit():
    source = "el.innerHTML=location.hash;function f(){f()}f()"
    parsed = parse_js(source)
    ir = build_ir(parsed.ast, "recursion-finding.js", "h")
    context = AnalysisContext(
        file_url="recursion-finding.js", file_hash="h", source_content=source
    )
    flows = list(TaintFlowDetector().match(ir, context))

    assert flows
    assert all(flow.metadata["confirmed"] is False for flow in flows)
    assert all(flow.metadata["evidence"] == "probable" for flow in flows)
    assert all(flow.metadata["analysis_incomplete"] is True for flow in flows)
    assert any(
        event.get("reason") == "taint_recursive_summary_incomplete"
        for event in context.metadata.get("analysis_incomplete", [])
    )
