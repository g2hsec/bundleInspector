"""Tests for JS parser."""

import json

import pytest

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
        assert result.parser_used == "esprima-normalized"
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

