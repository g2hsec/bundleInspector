"""Intra-file dataflow taint engine: confirms a source->sink chain only when a real def-use
chain exists. Precision is the priority -- the FALSE-POSITIVE table below (must all yield 0
findings) is the contract; the TRUE-POSITIVE table must all catch. Token-like literals are fake.
"""

from __future__ import annotations

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.rules.detectors.taint import TaintFlowDetector


def _taint_flows(src: str):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    return list(TaintFlowDetector().match(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src)))


# ---------------------------------------------------------------- FALSE POSITIVES (must be 0)

@pytest.mark.parametrize("label,src", [
    ("config .url is not a source", 'var ctx={context:"/api"}; el.html(`<a href="${ctx.context}">x</a>`);'),
    ("scope collision", 'function a(){var d=location.hash; use(d);}\nfunction b(){var d="safe"; el.html(d);}'),
    ("reassign to clean kills taint", 'var v=location.hash; v="0"; el.html(v);'),
    ("reassign to sanitized kills", 'var v=location.hash; v=String(Number(v)); el.html(v);'),
    (".text() is not an html sink", 'var u=location.hash; el.text(u);'),
    ("JSON.stringify sanitizes", 'var u=location.hash; el.html(JSON.stringify(u));'),
    ("encodeURIComponent sanitizes", 'var u=location.hash; el.html(encodeURIComponent(u));'),
    ("constant-array iterator param clean", 'var C=["a","b"]; C.forEach(function(x){el.html(`<i>${x}</i>`);});'),
    ("property key is not a variable", 'var o={src: safeVal}; el.html(`<b>${o.name}</b>`);'),
    ("unknown cross-object return abstains", 'var it=$.ns.obj.fetch(x); el.html(`<img src="${it.image_url}">`);'),
    ("bare parameter is not a source", 'function show(o){ $("body").append(`<p>${o.message}</p>`); }'),
    ("document.write of a param abstains", 'function ws(id){ document.write(id.innerHTML); }'),
    ("static innerHTML is not dynamic", 'chip.innerHTML = "";'),
    ("ajax data:/url: is request-direction, not a sink", '$.ajax({url:"/a", data: JSON.stringify(location.hash)});'),
    ("context-insensitive FP guard: f(clean) not flagged",
     'function r(x){ return `<img src="${x}">`; }\nvar bad=location.hash;\nel.html(r(bad));\nel.html(r("safe"));'),
])
def test_no_false_positive(label, src):
    flows = _taint_flows(src)
    # the context-sensitive case legitimately has ONE flow (r(bad)); assert the CLEAN call line
    # (the last) is never among the reported sink lines.
    if "f(clean)" in label:
        assert all(f.line != 4 for f in flows), f"clean-arg call flagged: {label}"
    else:
        assert flows == [], f"unexpected taint flow: {label}"


# ---------------------------------------------------------------- TRUE POSITIVES (must catch)

@pytest.mark.parametrize("label,src,expect_source", [
    ("location -> innerHTML", 'var u=location.hash; el.innerHTML=u;', "location"),
    ("ajax .done(res) -> .html", '$.ajax({url:"/a"}).done(function(r){ el.html(r.body); });', "ajax_response"),
    ("await ajax -> template append",
     'async function f(){ var r=await $.ajax({url:"/a"}); box.append(`<img src="${r.img}">`); }', "ajax_response"),
    ("FileReader -> attr src",
     'var rd=new FileReader(); rd.onload=function(e){ $img.attr("src", e.target.result); };', "filereader"),
    (".val() -> .html", 'var v=$("#x").val(); el.html(`<b>${v}</b>`);', "dom_input"),
    ("context-sensitive taint call flagged",
     'function r(x){ return `<i>${x}</i>`; } el.html(r(location.hash));', "location"),
    ("ajax response destructure -> iterator -> img src",
     'var res=$.ajax({async:false});\nvar list=res.responseJSON;\nlist.forEach(function(it){ box.append(`<img src="${it.url}">`); });',
     "ajax_response"),
])
def test_true_positive(label, src, expect_source):
    flows = _taint_flows(src)
    assert flows, f"missed real flow: {label}"
    assert any(f.metadata["source_kind"] == expect_source for f in flows), \
        f"{label}: expected source {expect_source}, got {[f.metadata['source_kind'] for f in flows]}"


# ---------------------------------------------------------------- confirmed metadata + robustness

def test_confirmed_flow_has_path_and_metadata():
    f = _taint_flows('var u=location.hash; el.innerHTML=u;')[0]
    assert f.metadata["confirmed"] is True
    assert f.value_type == "taint_flow"
    assert f.metadata["flow_path"] and "source:" in f.metadata["flow_path"][0]
    assert "sink" in f.metadata["flow_path"][-1]


@pytest.mark.parametrize("src", [
    "", "// just a comment", "var x = 1;",
    "a" + ("." + "b") * 500 + ";",                       # deep member chain
    "function f(){ return f(); } el.html(f());",          # self-recursive call
    "var o = {}; el.html(o?.a?.b);",                      # optional chaining, clean
])
def test_no_crash_on_edge_inputs(src):
    _taint_flows(src)  # must not raise / hang


def test_deterministic_across_runs():
    src = ('var res=$.ajax({async:false}); var l=res.responseJSON;'
           ' l.forEach(function(it){ box.append(`<img src="${it.url}">`); });')
    sig = lambda: [(f.line, f.metadata["source_kind"], f.metadata["sink"]) for f in _taint_flows(src)]
    assert sig() == sig()


@pytest.mark.parametrize("label,src", [
    # Regressions for the 6 bugs the adversarial verification surfaced (all must be 0 findings):
    ("flow-insensitive: source after sink", 'function f(){ var v="safe"; document.write(v); v=location.hash; }'),
    ("placeholder then reused", 'function s(){ var m="loading"; $("#x").html(m); m=location.hash; }'),
    ("cross-object mis-resolution", 'function helper(p){ $("#x").html(p); }\nsomeObject.helper(location.hash);'),
    ("cross-object return", 'var c={build:function(x){return document.cookie;}};\nfunction d(w){ var h=w.build("s"); w.el.innerHTML=h; }'),
    ("block-scope sibling collapse", 'function h(){ { let x="safe"; document.write(x); } { let x=location.hash; use(x); } }'),
    ("FileReader name across scopes",
     'function a(){ var reader=new FileReader(); reader.readAsText(f); }\n'
     'function b(){ var reader=getSock(); reader.onload=function(e){ $("#o").html(e.target.result); }; }'),
    ("jQuery .load is not an ajax source", 'function f(){ var r=$(window).load(function(){}); el.innerHTML=r; }'),
])
def test_verification_bug_regressions(label, src):
    assert _taint_flows(src) == [], f"regressed: {label}"


@pytest.mark.parametrize("label,src", [
    # Branch-merge: taint in one branch must not leak into a mutually-exclusive branch's sink.
    ("if/else default-or-render",
     'function d(m){ var x="Welcome"; if(m==="e"){ x=location.hash; } else { document.write(x); } }'),
    ("switch case-break",
     'function f(k){ var x="safe"; switch(k){ case 1: x=location.hash; break; case 2: $("#a").html(x); break; } }'),
    ("try then catch",
     'function f(){ var x="safe"; try{ x=location.hash; } catch(e){ $("#a").html(x); } }'),
])
def test_branch_merge_no_leak(label, src):
    assert _taint_flows(src) == [], f"branch leak: {label}"


@pytest.mark.parametrize("label,src", [
    ("taint then sink inside if", 'function f(c){ if(c){ var x=location.hash; document.write(x); } }'),
    ("taint in if, sink after join", 'function f(c){ var x="s"; if(c){ x=location.hash; } document.write(x); }'),
    ("source before, sink in a branch", 'function f(c){ var x=location.hash; if(c){ el.innerHTML=x; } }'),
    ("try/finally is a real flow", 'function f(){ var x=location.hash; try{ risky(); } finally { el.innerHTML=x; } }'),
])
def test_branch_true_positives_preserved(label, src):
    assert _taint_flows(src), f"missed real branch flow: {label}"


def test_context_sensitive_only_tainted_call_flags():
    # pt(location.hash) flags; pt("safe") does not -- even through a local intermediary var.
    src = 'function pt(x){ var t=x; return t; }\nel.html(pt(location.hash));\n$("#o").html(pt("safe"));'
    flows = _taint_flows(src)
    assert [f.line for f in flows] == [2]


def test_engine_registered_and_runs_in_pipeline():
    eng = RuleEngine(Config().rules); eng.register_defaults()
    assert any(r.id == "taint-flow-detector" for r in eng.rules)
    src = 'var u=location.hash; el.innerHTML=u;'
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    fs = eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src))
    assert any(f.value_type == "taint_flow" for f in fs)
