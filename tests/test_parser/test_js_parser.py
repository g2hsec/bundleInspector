"""Tests for JS parser."""

import json
from pathlib import Path

from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import JSParser, parse_js


class TestJSParser:
    """Tests for JSParser."""

    def test_parse_simple(self):
        """Test parsing simple JS."""
        source = 'const x = "hello";'
        parser = JSParser()
        result = parser.parse(source)

        assert result.success
        assert result.ast is not None
        assert not result.partial

    def test_parse_with_fetch(self):
        """Test parsing JS with fetch call."""
        source = '''
        fetch("/api/users")
            .then(r => r.json())
            .then(data => console.log(data));
        '''
        result = parse_js(source)

        assert result.success
        assert result.ast is not None

    def test_parse_tolerant(self):
        """Test tolerant parsing of broken JS."""
        source = '''
        const valid = "string";
        const broken = {
        // incomplete
        '''
        parser = JSParser(tolerant=True)
        result = parser.parse(source)

        # Should still extract what it can
        assert result.ast is not None or result.partial

    def test_parse_template_literal(self):
        """Test parsing template literals."""
        source = '''
        const url = `https://api.example.com/${endpoint}`;
        '''
        result = parse_js(source)

        assert result.success

    def test_parse_arrow_function(self):
        """Test parsing arrow functions."""
        source = '''
        const fn = (x) => x * 2;
        const asyncFn = async () => {
            const data = await fetch("/api");
            return data;
        };
        '''
        result = parse_js(source)

        assert result.success

    def test_parse_nullish_coalescing_with_default_param(self):
        """Parser should recover practical helper ASTs containing default params and `??`."""
        source = '''
        function route(path = null) {
            return path ?? "/api/users";
        }
        fetch(route());
        '''
        result = parse_js(source)

        assert result.success
        assert result.ast is not None
        assert any(
            node.get("type") == "FunctionDeclaration"
            for node in result.ast.get("body", [])
        )

    def test_parse_nested_template_literal_keeps_following_nullish_normalization(self):
        """Nested template expressions should not prevent later `??` normalization."""
        source = '''
        const x = `a${`b${c ?? d}` + e}`;
        const y = f ?? g;
        '''
        parser = JSParser()

        normalized = parser._normalize_modern_syntax_for_esprima(source)
        result = parser.parse(source)

        assert "??" not in normalized
        assert "c || d" in normalized
        assert "f || g" in normalized
        assert result.success
        assert result.ast is not None

    def test_parse_regex_literal_does_not_block_following_nullish_normalization(self):
        """Regex literals containing quotes should not trap the normalizer in string state."""
        source = r'''
        const re = /['"]/g;
        const value = left ?? right;
        '''
        parser = JSParser()

        normalized = parser._normalize_modern_syntax_for_esprima(source)
        result = parser.parse(source)

        assert "/['\"]/g" in normalized
        assert "left || right" in normalized
        assert result.success
        assert result.ast is not None

    def test_parse_regex_literal_ast_is_json_serializable(self):
        """Regex literal ASTs should not retain Python Pattern objects."""
        result = parse_js("const re = /abc/i;")

        assert result.success
        assert result.ast is not None
        json.dumps(result.ast)

        literal = result.ast["body"][0]["declarations"][0]["init"]
        assert literal["regex"] == {"pattern": "abc", "flags": "i"}
        assert literal["value"] is None

    def test_parse_nullish_assignment_normalizes_to_plain_assignment(self):
        """`??=` should normalize to a parser-compatible plain assignment."""
        source = "value ??= fallback;"
        parser = JSParser()

        normalized = parser._normalize_modern_syntax_for_esprima(source)
        result = parser.parse(source)

        assert "??=" not in normalized
        assert "||=" not in normalized
        assert "value  =  fallback;" in normalized
        assert result.success
        assert result.ast is not None

    def test_logical_assignment_operators_normalize_and_recover(self):
        """`||=` / `&&=` (ES2021) are unparseable by esprima; without a width-preserving downgrade a
        minified bundle using them collapses to the string-only regex fallback, zeroing every AST
        detector (endpoints/sinks/taint/flags/debug)."""
        from bundleInspector.parser.ir_builder import build_ir
        parser = JSParser()

        normalized = parser._normalize_modern_syntax_for_esprima("a ||= b; c &&= d;")
        assert "||=" not in normalized and "&&=" not in normalized
        assert normalized == "a  =  b; c  =  d;"
        assert len(normalized) == len("a ||= b; c &&= d;")   # width-preserved (enh1 offset invariant)

        # bitwise `|=` / `&=` and plain `||` / `&&` must be left intact for esprima.
        untouched = parser._normalize_modern_syntax_for_esprima("x |= 1; y &= 2; z = a || b && c;")
        assert "|=" in untouched and "&=" in untouched and "||" in untouched and "&&" in untouched

        # end-to-end: the function-call AST is recovered instead of regex-zeroed.
        result = parse_js('u ||= location.hash; fetch("/api/x");')
        assert result.parser_used == "tree-sitter-javascript"
        assert result.partial is False
        assert result.completeness == "complete"
        ir = build_ir(result.ast, "f.js", "h")
        assert "fetch" in {c.name for c in ir.function_calls}

    def test_partial_parse_preserves_absolute_line_numbers(self):
        """A partial parse (an unparseable region + a blank-line-separated valid statement) must
        report ABSOLUTE source line numbers for recovered statements -- not chunk-relative ones --
        so secrets/endpoints/domains evidence points at the true source line."""
        from bundleInspector.parser.ir_builder import build_ir
        # line 1 is unparseable -> forces the partial path; line 3 is valid and recoverable.
        src = 'var x = @@@ bad syntax;\n\nfetch("/api/secret");'
        result = parse_js(src)
        assert result.partial is True
        ir = build_ir(result.ast, "f.js", "h")
        lit = next(literal for literal in ir.string_literals if literal.value == "/api/secret")
        assert lit.line == 3   # absolute source line, not chunk-relative 1

    def test_partial_parse_populates_absolute_range(self):
        """Partial parsing now requests char ranges and rebases them to absolute source offsets."""
        src = 'var x = @@@ bad syntax;\n\nfetch("/api/secret");'
        result = parse_js(src)
        assert result.partial is True
        stmt = result.ast["body"][0]
        assert stmt["range"][0] == src.index("fetch")   # absolute char offset, not 0

    def test_partial_parse_first_chunk_is_noop(self):
        """The first chunk starts at offset 0 / line 1, so its positions must be left untouched
        (no spurious offset added)."""
        from bundleInspector.parser.ir_builder import build_ir
        src = 'fetch("/api/first");\n\nvar y = @@@ bad;'
        result = parse_js(src)
        assert result.partial is True
        ir = build_ir(result.ast, "f.js", "h")
        lit = next(literal for literal in ir.string_literals if literal.value == "/api/first")
        assert lit.line == 1
        assert result.ast["body"][0]["range"][0] == 0

    def test_offset_ast_positions_handles_deep_ast_without_recursion(self):
        """The offsetter is iterative -- a pathologically deep partial AST must not RecursionError."""
        leaf = {"type": "Leaf", "loc": {"start": {"line": 1}, "end": {"line": 1}}, "range": [0, 1]}
        node = leaf
        for _ in range(3000):
            node = {"type": "Wrap", "child": node}
        JSParser()._offset_ast_positions(node, 5, 10)
        assert leaf["loc"]["start"]["line"] == 6   # 1 + line_offset
        assert leaf["range"][0] == 10              # 0 + char_offset

    def test_optional_chaining_member_normalizes_and_recovers(self):
        """`?.` (ES2020) is unparseable by esprima; without recovery a minified `?.` bundle
        collapses to the string-only regex fallback, zeroing every AST detector."""
        source = 'var u = a?.b?.c; fn(u);'
        parser = JSParser()
        normalized = parser._normalize_modern_syntax_for_esprima(source)
        result = parser.parse(source)
        assert "?." not in normalized
        assert len(normalized) == len(source)   # width-preserved (enh1 offset invariant)
        assert result.success and result.ast is not None

    def test_optional_chaining_call_and_computed_recover(self):
        source = 'cb?.(1, 2); arr?.[i]?.name;'
        parser = JSParser()
        normalized = parser._normalize_modern_syntax_for_esprima(source)
        assert "?." not in normalized
        assert len(normalized) == len(source)
        assert parser.parse(source).success

    def test_optional_chaining_digit_guard_preserves_ternary(self):
        """`a?.5:b` is the conditional operator with a fractional literal, NOT optional chaining --
        esprima parses it natively, so it must be left intact."""
        source = 'var t = cond ?.5 : other; var u = x?.y;'
        parser = JSParser()
        normalized = parser._normalize_modern_syntax_for_esprima(source)
        assert "?.5" in normalized          # ternary preserved
        assert "x?.y" not in normalized     # real optional chain still normalized
        assert parser.parse(source).success

    def test_optional_chaining_restores_ast_detection(self):
        """End-to-end: a `?.` bundle recovers its function-call AST (endpoints/sinks/taint depend
        on ir.function_calls, which the regex fallback never populates)."""
        from bundleInspector.parser.ir_builder import build_ir
        source = 'function f(a){ var u = a?.b?.c; eval(u); fetch("/api/secret"); }'
        result = parse_js(source)
        assert result.parser_used == "tree-sitter-javascript"
        assert result.partial is False
        assert result.completeness == "complete"
        assert result.capability_gaps == ()
        assert "partial" not in result.ast
        ir = build_ir(result.ast, "f.js", "h")
        names = {c.name for c in ir.function_calls}
        assert "eval" in names and "fetch" in names

    def test_parse_es_modules(self):
        """Test parsing ES modules."""
        source = '''
        import { useState } from 'react';
        export const Component = () => null;
        export default function App() {}
        '''
        result = parse_js(source)

        assert result.success


def test_lexical_fallback_excludes_comment_and_regex_literals_and_preserves_source_order():
    parser = JSParser()
    parser._parser = "regex"
    source = (
        '/* "/api/comment-double" */ // \'/api/comment-single\'\n'
        'const re = /["\']/; const first = \'/api/first\'; '
        'const second = "/api/second"; const third = `/api/third`;'
    )

    result = parser._parse_regex_fallback(source)
    values = [node["expression"]["value"] for node in result.ast["body"]]

    assert values == ["/api/first", "/api/second", "/api/third"]
    assert result.partial is True
    assert result.completeness == "partial"
    assert "structural_ast_unavailable" in result.capability_gaps


def test_partial_chunk_recovery_never_executes_multiline_comment_text():
    parser = JSParser()
    source = '/* comment\n\nfetch("/api/fake");\n\n*/\n@'

    direct = parser._partial_parse_esprima(source, "forced syntax failure")
    selected = parser.parse(source)

    for result in (direct, selected):
        assert result.ast is not None
        ir = build_ir(result.ast, "f.js", "h")
        assert "/api/fake" not in {literal.value for literal in ir.string_literals}
        assert result.partial is True


def test_lexical_fallback_scans_nested_template_code_but_not_template_raw_text():
    parser = JSParser()
    parser._parser = "regex"
    source = (
        'const value=`outer ${`/api/real`} '
        '${`import("/api/inert-template")`}`;'
    )

    result = parser._parse_regex_fallback(source)
    values = [node["expression"]["value"] for node in result.ast["body"]]

    assert values == ["/api/real", 'import("/api/inert-template")']
    assert "outer ${" not in values


def test_lexical_fallback_masks_regex_after_control_header():
    parser = JSParser()
    parser._parser = "regex"
    source = (
        'if (\n// misleading )\nok\n) '
        r'/import\(".\/fake.js"\)/.test(value); '
        'const real="/api/real";'
    )

    result = parser._parse_regex_fallback(source)
    values = [node["expression"]["value"] for node in result.ast["body"]]

    assert values == ["/api/real"]


def test_lexical_fallback_masks_regex_after_control_block_without_hiding_division():
    parser = JSParser()
    parser._parser = "regex"
    source = (
        'if (ok) {}\n/import("fake")/.test(value); '
        'function declared() {}\n/import("function-fake")/.test(value); '
        'class Declared {}\n/import("class-fake")/.test(value); '
        '{}\n/import("bare-fake")/.test(value); '
        'const ratio={} / "live-division" / divisor; '
        'const fn=function(){} / "live-function-division" / divisor; '
        'const cls=class{} / "live-class-division" / divisor; '
        'const real="/api/real";'
    )

    result = parser._parse_regex_fallback(source)
    values = [node["expression"]["value"] for node in result.ast["body"]]

    assert values == [
        "live-division",
        "live-function-division",
        "live-class-division",
        "/api/real",
    ]
    modern_regex = 'try {} finally {}\u2028/foo??"inert"/.test(value);'
    assert parser._normalize_modern_syntax_for_esprima(modern_regex) == modern_regex


def test_lexical_fallback_line_comments_end_at_every_javascript_line_terminator():
    parser = JSParser()
    parser._parser = "regex"
    for separator in ("\r", "\n", "\r\n", "\u2028", "\u2029"):
        source = f'// "fake"{separator}const real="/api/real";'
        result = parser._parse_regex_fallback(source)
        values = [node["expression"]["value"] for node in result.ast["body"]]
        assert values == ["/api/real"]
        assert result.ast["body"][0]["expression"]["loc"]["start"]["line"] == 2

        unterminated_regex = (
            f'if(ok) /unterminated\\{separator}'
            'const recovered="/api/recovered";'
        )
        recovered = parser._parse_regex_fallback(unterminated_regex)
        recovered_values = [
            node["expression"]["value"] for node in recovered.ast["body"]
        ]
        assert recovered_values == ["/api/recovered"]


def test_lexical_fallback_reports_each_detection_relevant_cap(monkeypatch):
    parser = JSParser()
    monkeypatch.setattr(parser, "MAX_STRINGS_EXTRACTED", 1)
    monkeypatch.setattr(parser, "MAX_STRING_LENGTH", 4)

    result = parser._parse_regex_fallback('"first-long"; "second"; \'third\';')

    assert result.truncation_reasons
    assert any("count cap 1" in reason for reason in result.truncation_reasons)
    assert any("length cap 4" in reason for reason in result.truncation_reasons)
    assert result.ast["parse_completeness"]["truncation_reasons"] == list(
        result.truncation_reasons
    )


def test_native_acorn_availability_requires_module_resolution(monkeypatch):
    from types import SimpleNamespace

    from bundleInspector.parser import native_acorn

    monkeypatch.setenv("BUNDLEINSPECTOR_NATIVE_PARSER", "1")
    monkeypatch.setattr(native_acorn, "_available", None)
    monkeypatch.setattr(native_acorn, "_availability_reason", "not_probed")
    monkeypatch.setattr(native_acorn.shutil, "which", lambda _name: "node")
    monkeypatch.setattr(
        native_acorn.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="missing"),
    )

    assert native_acorn.native_parser_available() is False
    assert native_acorn.native_parser_availability_reason() == "acorn_unavailable"


def test_native_acorn_uses_configured_temp_directory(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from bundleInspector.parser import native_acorn

    temp_dir = tmp_path / "configured-native-temp"
    observed: dict[str, str] = {}

    def run(args, **_kwargs):
        source_path = args[-1]
        observed["path"] = source_path
        observed["source"] = Path(source_path).read_text(encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout='{"type":"Program","body":[]}', stderr="")

    monkeypatch.setattr(native_acorn, "native_parser_available", lambda: True)
    monkeypatch.setattr(native_acorn, "_node_executable", "node")
    monkeypatch.setattr(native_acorn.subprocess, "run", run)

    result = JSParser(temp_dir=temp_dir).parse("const configured = true;")

    assert result.success and result.parser_used == "acorn"
    assert observed["source"] == "const configured = true;"
    assert temp_dir in Path(observed["path"]).parents
    assert list(temp_dir.iterdir()) == []
