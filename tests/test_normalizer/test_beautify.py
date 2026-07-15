"""Tests for beautify light deobfuscation safety."""

from bundleInspector.normalizer.beautify import (
    Beautifier,
    NormalizationLevel,
    _static_literal_multiset,
)
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.detectors.endpoints import EndpointDetector


def test_beautify_does_not_corrupt_tsx_source():
    """DQ-C02: jsbeautifier has no TS/JSX support -- it injects whitespace INTO string literals
    (`fetch("/api/admin")` -> `fetch("/api / admin ")`), silently dropping the endpoint. Beautify
    must detect TS/JSX and keep the RAW source unchanged so the analysis input is not corrupted."""
    tsx = (
        'interface U {q:string}; const q:string=location.hash; '
        'const C=()=> <div dangerouslySetInnerHTML={{__html:q}}/>; '
        'document.body.innerHTML=q; fetch("/api/admin");'
    )
    res = Beautifier().beautify(tsx)
    assert res.success is True
    assert res.level == NormalizationLevel.NONE      # skipped, not beautified
    assert "/api/admin" in res.content               # raw preserved
    assert "/api / admin" not in res.content          # not corrupted
    assert res.content == tsx                          # immutable raw analysis input


def test_beautify_preserves_endpoint_in_tsx_through_detector():
    """The end-to-end consequence of DQ-C02: the endpoint must survive normalization for the
    EndpointDetector to find it."""
    tsx = (
        'interface U {q:string}; const q:string=location.hash; '
        'const C=()=> <div dangerouslySetInnerHTML={{__html:q}}/>; '
        'document.body.innerHTML=q; fetch("/api/admin");'
    )
    normalized = Beautifier().beautify(tsx).content
    ir = build_ir(parse_js(normalized).ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=normalized)
    values = {f.extracted_value for f in EndpointDetector().match(ir, ctx)}
    assert "/api/admin" in values


def test_beautify_preserves_array_position_jsx_reproduction():
    source = 'const xs=[<div></div>]; fetch("/api/admin");'

    result = Beautifier().beautify(source)

    assert result.level == NormalizationLevel.NONE
    assert result.content == source
    assert "/api / admin" not in result.content
    parsed = parse_js(result.content)
    ir = build_ir(parsed.ast, "array.tsx", "array")
    context = AnalysisContext(
        file_url="array.tsx",
        file_hash="array",
        source_content=result.content,
    )
    assert "/api/admin" in {
        finding.extracted_value for finding in EndpointDetector().match(ir, context)
    }


def test_beautify_preserves_endpoint_after_jsx_fragment():
    source = 'const xs=[<><span/></>]; fetch("/api/fragment");'

    result = Beautifier().beautify(source)
    parsed = parse_js(result.content)
    ir = build_ir(parsed.ast, "fragment.tsx", "fragment")
    context = AnalysisContext(
        file_url="fragment.tsx",
        file_hash="fragment",
        source_content=result.content,
    )

    assert result.content == source
    assert "/api/fragment" in {
        finding.extracted_value for finding in EndpointDetector().match(ir, context)
    }


def test_beautify_preserves_bare_top_level_jsx_at_source_start():
    source = '<App/>; const u=location.hash; el.innerHTML=u;'

    result = Beautifier().beautify(source)

    assert result.level == NormalizationLevel.NONE
    assert result.content == source
    parsed = parse_js(result.content, language_hint="tsx")
    assert parsed.partial is False
    assert parsed.ast is not None


def test_beautify_rejects_any_output_that_loses_a_raw_literal(monkeypatch):
    import bundleInspector.normalizer.beautify as beautify_module

    source = 'fetch("/api/admin"); const token = "secret-value";'
    monkeypatch.setattr(
        beautify_module.jsbeautifier,
        "beautify",
        lambda *_args, **_kwargs: 'fetch("/api / admin"); const token = "secret-value";',
    )

    result = Beautifier().beautify(source)

    assert result.content == source
    assert result.level == NormalizationLevel.NONE
    assert result.errors == [
        "Beautification rejected: normalized output did not preserve raw literals"
    ]


def test_beautify_still_reflows_plain_minified_js():
    """The TS/JSX skip must NOT disable beautification of ordinary minified JS."""
    plain = "var a=1;var b=2;function f(){return a+b;}"
    res = Beautifier().beautify(plain)
    assert res.level == NormalizationLevel.BEAUTIFY
    assert res.content.count("\n") > 1  # reflowed onto multiple lines


def test_literal_invariant_ignores_control_block_regex_and_preserves_division_literal():
    source = (
        'if(ok) {}\n/"inert-regex"/.test(value); '
        'function declared() {}\n/"inert-function"/.test(value); '
        'class Declared {}\n/"inert-class"/.test(value); '
        '// "inert-comment"\u2028'
        'const ratio={} / "live-division" / divisor; '
        'const fn=function(){} / "live-function-division" / divisor; '
        'const cls=class{} / "live-class-division" / divisor; const real="real";'
    )

    assert _static_literal_multiset(source) == {
        '"live-division"': 1,
        '"live-function-division"': 1,
        '"live-class-division"': 1,
        '"real"': 1,
    }


def test_light_deobfuscate_preserves_structural_hex_escapes():
    """Quote-like hex escapes should stay escaped to avoid invalid JS output."""
    beautifier = Beautifier(level=NormalizationLevel.LIGHT)

    result = beautifier.beautify(r'var s = "\x22hello\x22";')

    assert result.success is True
    assert '""hello""' not in result.content
    assert r'"\x22hello\x22"' in result.content


def test_light_deobfuscate_decodes_only_active_hex_escapes():
    """Escaped backslashes should preserve literal `\\xNN` sequences."""
    beautifier = Beautifier(level=NormalizationLevel.LIGHT)

    active = beautifier.beautify(r'var active = "\x41";')
    escaped = beautifier.beautify(r'var escaped = "\\x41";')
    mixed = beautifier.beautify(r'var mixed = "\\\x41";')

    assert 'var active = "A";' in active.content
    assert r'var escaped = "\\x41";' in escaped.content
    assert r'var mixed = "\\A";' in mixed.content


def test_light_deobfuscation_line_mapping_not_drifted():
    """LIGHT deobfuscation (hex decode / string folding) changes NON-whitespace content, so the line
    mapping must be built BEFORE it -- otherwise the non-whitespace alignment drifts and a token on a
    later line maps back to the wrong original line."""
    src = 'var a = "\\x41";\n\nvar token123 = "sk_marker";'  # token is on original line 3
    res = Beautifier(level=NormalizationLevel.LIGHT).beautify(src)
    blines = res.content.split("\n")
    token_line = next(i for i, bl in enumerate(blines, 1) if "token123" in bl)
    orig_line, _ = res.line_mapper.get_original(token_line)
    assert orig_line == 3
