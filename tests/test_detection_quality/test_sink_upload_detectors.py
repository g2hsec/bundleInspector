"""Tests for the DOM-XSS / code-injection sink detector and the file-upload surface detector.

Only DYNAMIC arguments (variables / concatenation / template-with-expression) are flagged;
static string literals must NOT be, to keep false positives low.
"""

from __future__ import annotations

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine


def _findings(src: str):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    return eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src))


def _sink_values(src: str) -> set[str]:
    return {f.extracted_value for f in _findings(src) if f.category.value == "sink"}


def _upload_types(src: str) -> set[str]:
    return {f.value_type for f in _findings(src) if f.category.value == "upload"}


# ---------------------------------------------------------------- DOM-XSS / code sinks (dynamic)


@pytest.mark.parametrize(
    "src,expect",
    [
        ("el.innerHTML = userInput;", "innerHTML="),
        ("el.outerHTML = a + b;", "outerHTML="),
        ("document.write(location.hash);", "document.write()"),
        ("node.insertAdjacentHTML('beforeend', data);", "insertAdjacentHTML()"),
        ("$('#x').html(rendered);", ".html()"),
        ("eval(payload);", "eval()"),
        ("var f = new Function(body);", "new Function()"),
        ("el.setAttribute('src', userUrl);", "setAttribute(src)"),
        ("$box.append('<img src=' + u + '>');", ".append()"),
    ],
)
def test_dynamic_sinks_are_flagged(src, expect):
    assert expect in _sink_values(src), f"{expect} not flagged for: {src}"


@pytest.mark.parametrize(
    "src",
    [
        'el.innerHTML = "<b>static</b>";',  # static literal -> not a sink
        '$("#x").html("<div>static</div>");',  # static literal
        'document.write("<p>hi</p>");',  # static literal
        'el.setAttribute("class", dynamicVal);',  # non-dangerous attribute
        "setTimeout(function(){ go(); }, 100);",  # function ref, not a string
        '$("#x").html();',  # getter, no argument
    ],
)
def test_static_or_safe_calls_not_flagged(src):
    assert _sink_values(src) == set(), f"unexpected sink for: {src}"


def test_generic_append_and_timer_callback_identifier_are_not_code_or_html_sinks():
    assert _sink_values("customList.append(payload); setTimeout(handler, 10);") == set()


def test_modern_html_sinks_are_detected():
    assert "setHTMLUnsafe()" in _sink_values("element.setHTMLUnsafe(payload);")
    assert "srcdoc=" in _sink_values("frame.srcdoc = payload;")


def test_eval_high_severity():
    fs = [f for f in _findings("eval(x + y);") if f.category.value == "sink"]
    assert fs and fs[0].severity.value == "high"


# ------------------------------------------------ HTML attribute injection (stored/DOM XSS)


def _sink_by_type(src: str, value_type: str):
    return [f for f in _findings(src) if f.category.value == "sink" and f.value_type == value_type]


@pytest.mark.parametrize(
    "src,attr,source",
    [
        ('var h = `<img src="${item.image_url}">`; $("#x").html(h);', "src", "item.image_url"),
        ('var h = `<a href="${u}">`; $("#x").html(h);', "href", "u"),
        ('var h = `<b onerror="${x}">`; $("#x").html(h);', "onerror", "x"),
        ("var h = '<img src=\"' + data.path + '\">'; $('#x').html(h);", "src", "data.path"),
    ],
)
def test_dangerous_attribute_injection_flagged(src, attr, source):
    fs = _sink_by_type(src, "dom_attr_injection")
    assert fs, f"no dom_attr_injection for: {src}"
    f = fs[0]
    assert f.severity.value == "high"
    assert source in f.description  # the source expression is surfaced for the reviewer


@pytest.mark.parametrize(
    "src",
    [
        'var h = `<div class="${cls}">x</div>`;',  # non-dangerous attribute
        "var h = `<p>${text}</p>`;",  # content position, not an attribute value
        'var h = `<img src="/static/logo.png">`;',  # fully static
    ],
)
def test_safe_html_not_attribute_injection(src):
    assert _sink_by_type(src, "dom_attr_injection") == []


def test_unconsumed_html_template_and_arbitrary_react_named_property_are_not_sinks():
    src = (
        'const preview = `<img src="${userUrl}">`; const data={dangerouslySetInnerHTML:{__html:x}};'
    )
    assert _sink_by_type(src, "dom_attr_injection") == []
    assert "dangerouslySetInnerHTML" not in _sink_values(src)


def test_compiled_react_dangerous_html_property_is_a_sink():
    src = 'jsx("div", {dangerouslySetInnerHTML:{__html:payload}});'
    assert "dangerouslySetInnerHTML" in _sink_values(src)


def test_jquery_attr_src_sink_names_source():
    # the $img.attr("src", uploaded.path) upload -> <img src> pattern
    fs = _sink_by_type('$img.attr("src", uploaded.path);', "dom_attr_sink")
    assert fs and "uploaded.path" in fs[0].description


def test_jquery_attr_safe_attribute_not_flagged():
    assert _sink_by_type('$el.attr("class", dyn);', "dom_attr_sink") == []


def test_attr_injection_snippet_anchored_on_the_interpolation():
    # The ${x} interpolation sits several lines below the template-literal start. The code SNIPPET
    # must show the interpolation (so the reported DANGEROUS VALUE is actually visible), while the
    # finding `line` stays at the construct start (detection-gate stable, snippet is not in the gate).
    src = (
        "function render(item) {\n"  # 1
        "  var html = `\n"  # 2  <- template start
        "    <section>\n"  # 3
        "      <h2>title</h2>\n"  # 4
        "      <p>body copy here</p>\n"  # 5
        '      <div class="thumb">\n'  # 6
        '        <img src="${item.image_url}" alt="x">\n'  # 7  <- interpolation (5 lines below)
        "      </div>\n"  # 8
        "    </section>`;\n"  # 9
        "  $('#c').append(html);\n"  # 10
        "}\n"
    )
    fs = _sink_by_type(src, "dom_attr_injection")
    assert fs, "no dom_attr_injection finding"
    f = fs[0]
    assert f.metadata.get("sink_source") == "item.image_url"
    # the fix: the interpolation (hence the dangerous value) is inside the snippet
    assert "item.image_url" in f.evidence.snippet
    # ...and the finding line still anchors at/above the construct, not the interpolation line
    assert f.evidence.line <= 7


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
