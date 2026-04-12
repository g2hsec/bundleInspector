"""Tests for JS parser."""

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

    def test_parse_es_modules(self):
        """Test parsing ES modules."""
        source = '''
        import { useState } from 'react';
        export const Component = () => null;
        export default function App() {}
        '''
        result = parse_js(source)

        assert result.success

