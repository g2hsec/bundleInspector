"""Tests for the DOM-XSS / code-injection sink detector and the file-upload surface detector.

Only DYNAMIC arguments (variables / concatenation / template-with-expression) are flagged;
static string literals must NOT be, to keep false positives low.
"""

from __future__ import annotations

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine


def _findings(src: str):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules); eng.register_defaults()
    return eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src))


def _sink_values(src: str) -> set[str]:
    return {f.extracted_value for f in _findings(src) if f.category.value == "sink"}


def _upload_types(src: str) -> set[str]:
    return {f.value_type for f in _findings(src) if f.category.value == "upload"}


# ---------------------------------------------------------------- DOM-XSS / code sinks (dynamic)

@pytest.mark.parametrize("src,expect", [
    ("el.innerHTML = userInput;",                         "innerHTML="),
    ("el.outerHTML = a + b;",                             "outerHTML="),
    ("document.write(location.hash);",                    "document.write()"),
    ("node.insertAdjacentHTML('beforeend', data);",       "insertAdjacentHTML()"),
    ("$('#x').html(rendered);",                           ".html()"),
    ("eval(payload);",                                    "eval()"),
    ("var f = new Function(body);",                       "new Function()"),
    ("el.setAttribute('src', userUrl);",                  "setAttribute(src)"),
    ("$box.append('<img src=' + u + '>');",               ".append()"),
])
def test_dynamic_sinks_are_flagged(src, expect):
    assert expect in _sink_values(src), f"{expect} not flagged for: {src}"


@pytest.mark.parametrize("src", [
    'el.innerHTML = "<b>static</b>";',            # static literal -> not a sink
    '$("#x").html("<div>static</div>");',         # static literal
    'document.write("<p>hi</p>");',               # static literal
    'el.setAttribute("class", dynamicVal);',      # non-dangerous attribute
    'setTimeout(function(){ go(); }, 100);',      # function ref, not a string
    '$("#x").html();',                            # getter, no argument
])
def test_static_or_safe_calls_not_flagged(src):
    assert _sink_values(src) == set(), f"unexpected sink for: {src}"


def test_eval_high_severity():
    fs = [f for f in _findings("eval(x + y);") if f.category.value == "sink"]
    assert fs and fs[0].severity.value == "high"


# ---------------------------------------------------------------- file upload

def test_formdata_is_upload_surface():
    assert "file_upload" in _upload_types("var fd = new FormData(); fd.append('f', file);")


def test_client_side_validation_flagged():
    src = "var opt = { allowedExt: ['jpg','png'], maxSize: 1000 };"
    assert "client_side_file_validation" in _upload_types(src)


def test_file_input_markup_flagged():
    assert "file_input" in _upload_types('var h = \'<input type="file" name="upload">\';')


# ---------------------------------------------------------------- category wiring

def test_sink_and_upload_categories_enabled_by_default():
    assert "sink" in Config().rules.enabled_categories
    assert "upload" in Config().rules.enabled_categories
