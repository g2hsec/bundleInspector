"""
JavaScript AST parser.

Parses JavaScript into AST with error tolerance.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Optional

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False

try:
    import pyjsparser
    PYJSPARSER_AVAILABLE = True
except ImportError:
    PYJSPARSER_AVAILABLE = False


@dataclass
class ParseResult:
    """Result of parsing JavaScript."""
    success: bool
    ast: Optional[dict[str, Any]]
    errors: list[str]
    partial: bool  # True if only partial parsing succeeded
    parser_used: str


class JSParser:
    """
    JavaScript AST parser with error tolerance.

    Supports multiple parser backends and falls back gracefully.
    """

    def __init__(self, tolerant: bool = True):
        """
        Initialize parser.

        Args:
            tolerant: Whether to use error-tolerant parsing
        """
        self.tolerant = tolerant
        self._parser = self._select_parser()

    def _select_parser(self) -> str:
        """Select available parser."""
        if ESPRIMA_AVAILABLE:
            return "esprima"
        elif PYJSPARSER_AVAILABLE:
            return "pyjsparser"
        else:
            return "regex"  # Fallback to regex-based extraction

    def parse(self, source: str) -> ParseResult:
        """
        Parse JavaScript source code.

        Args:
            source: JavaScript source code

        Returns:
            ParseResult with AST and metadata
        """
        if self._parser == "esprima":
            return self._parse_esprima(source)
        elif self._parser == "pyjsparser":
            return self._parse_pyjsparser(source)
        else:
            return self._parse_regex_fallback(source)

    def _parse_esprima(self, source: str) -> ParseResult:
        """Parse using esprima."""
        try:
            options = {
                "tolerant": self.tolerant,
                "loc": True,
                "range": True,
                "tokens": False,
                "comment": False,
            }

            # Try as script first
            try:
                ast = esprima.parseScript(source, options)
                ast_dict = self._esprima_to_dict(ast)
                return ParseResult(
                    success=True,
                    ast=ast_dict,
                    errors=[],
                    partial=False,
                    parser_used="esprima",
                )
            except esprima.Error:
                # Try as module
                try:
                    ast = esprima.parseModule(source, options)
                    ast_dict = self._esprima_to_dict(ast)
                    return ParseResult(
                        success=True,
                        ast=ast_dict,
                        errors=[],
                        partial=False,
                        parser_used="esprima",
                    )
                except esprima.Error:
                    raise

        except Exception as e:
            normalized = self._normalize_modern_syntax_for_esprima(source)
            if normalized != source:
                normalized_result = self._try_parse_esprima_source(
                    normalized,
                    parser_used="esprima-normalized",
                )
                if normalized_result is not None:
                    return normalized_result
            if self.tolerant:
                return self._partial_parse_esprima(source, str(e))
            return ParseResult(
                success=False,
                ast=None,
                errors=[str(e)],
                partial=False,
                parser_used="esprima",
            )

    def _try_parse_esprima_source(
        self,
        source: str,
        parser_used: str,
    ) -> Optional[ParseResult]:
        """Try parsing a source string as script/module with esprima."""
        options = {
            "tolerant": self.tolerant,
            "loc": True,
            "range": True,
            "tokens": False,
            "comment": False,
        }
        for parser_fn in (esprima.parseScript, esprima.parseModule):
            try:
                ast = parser_fn(source, options)
                ast_dict = self._esprima_to_dict(ast)
                return ParseResult(
                    success=True,
                    ast=ast_dict,
                    errors=[],
                    partial=False,
                    parser_used=parser_used,
                )
            except esprima.Error:
                continue
        return None

    def _normalize_modern_syntax_for_esprima(self, source: str) -> str:
        """Best-effort syntax normalization for parser-unsupported operators."""
        result: list[str] = []
        state = "code"
        string_quote = ""
        template_expr_stack: list[int] = []
        regex_in_char_class = False
        i = 0

        while i < len(source):
            char = source[i]
            next_char = source[i + 1] if i + 1 < len(source) else ""

            if state == "code":
                if char == "/" and next_char == "/":
                    result.append("//")
                    state = "line_comment"
                    i += 2
                    continue
                if char == "/" and next_char == "*":
                    result.append("/*")
                    state = "block_comment"
                    i += 2
                    continue
                if char == "/" and self._can_start_regex_literal(source, i):
                    result.append(char)
                    state = "regex"
                    regex_in_char_class = False
                    i += 1
                    continue
                if char in {"'", '"', "`"}:
                    string_quote = char
                    result.append(char)
                    state = "string"
                    i += 1
                    continue
                if char == "?" and next_char == "?" and i + 2 < len(source) and source[i + 2] == "=":
                    result.append(" = ")
                    i += 3
                    continue
                if char == "?" and next_char == "?":
                    # Preserve width while downgrading to an older logical operator
                    # so esprima can still recover a usable AST for helper analysis.
                    result.append("||")
                    i += 2
                    continue
                if template_expr_stack:
                    if char == "{":
                        template_expr_stack[-1] += 1
                    elif char == "}":
                        template_expr_stack[-1] -= 1
                        if template_expr_stack[-1] == 0:
                            template_expr_stack.pop()
                            result.append(char)
                            state = "string"
                            string_quote = "`"
                            i += 1
                            continue
                result.append(char)
                i += 1
                continue

            if state == "string":
                if string_quote == "`" and char == "$" and next_char == "{":
                    result.append("${")
                    template_expr_stack.append(1)
                    state = "code"
                    i += 2
                    continue
                result.append(char)
                if char == "\\" and i + 1 < len(source):
                    result.append(source[i + 1])
                    i += 2
                    continue
                if char == string_quote:
                    state = "code"
                i += 1
                continue

            if state == "regex":
                result.append(char)
                if char == "\\" and i + 1 < len(source):
                    result.append(source[i + 1])
                    i += 2
                    continue
                if char == "[":
                    regex_in_char_class = True
                    i += 1
                    continue
                if char == "]" and regex_in_char_class:
                    regex_in_char_class = False
                    i += 1
                    continue
                if char == "/" and not regex_in_char_class:
                    state = "code"
                i += 1
                continue

            if state == "line_comment":
                result.append(char)
                if char == "\n":
                    state = "code"
                i += 1
                continue

            if state == "block_comment":
                result.append(char)
                if char == "*" and next_char == "/":
                    result.append("/")
                    state = "code"
                    i += 2
                    continue
                i += 1
                continue

        return "".join(result)

    def _can_start_regex_literal(self, source: str, index: int) -> bool:
        """Heuristically detect regex literal openings in code context."""
        prev = index - 1
        while prev >= 0 and source[prev].isspace():
            prev -= 1
        if prev < 0:
            return True

        prev_char = source[prev]
        if prev_char in "([{:;,=!?&|^~+-*%<>":
            return True

        if prev_char.isalnum() or prev_char in {"_", "$"}:
            end = prev
            while prev >= 0 and (source[prev].isalnum() or source[prev] in {"_", "$"}):
                prev -= 1
            token = source[prev + 1:end + 1]
            return token in {
                "return",
                "throw",
                "case",
                "delete",
                "void",
                "typeof",
                "instanceof",
                "in",
                "new",
                "yield",
                "await",
                "else",
                "do",
            }

        return False

    def _partial_parse_esprima(
        self,
        source: str,
        error: str,
    ) -> ParseResult:
        """Attempt partial parsing when full parsing fails."""
        # Split into chunks and parse what we can
        chunks = source.split("\n\n")
        body = []
        errors = [error]

        for chunk in chunks:
            try:
                chunk_ast = esprima.parseScript(
                    chunk,
                    {"tolerant": True, "loc": True}
                )
                chunk_dict = self._esprima_to_dict(chunk_ast)
                body.extend(chunk_dict.get("body", []))
            except Exception:
                pass

        if body:
            return ParseResult(
                success=True,
                ast={"type": "Program", "body": body, "partial": True},
                errors=errors,
                partial=True,
                parser_used="esprima",
            )

        # Last resort: regex fallback
        return self._parse_regex_fallback(source)

    def _esprima_to_dict(self, node: Any, _seen: set | None = None) -> dict[str, Any]:
        """Convert esprima node to dictionary."""
        if node is None:
            return None
        if isinstance(node, (int, float, bool, str)):
            return node

        if _seen is None:
            _seen = set()

        node_id = id(node)
        if node_id in _seen:
            return {}
        _seen.add(node_id)

        if hasattr(node, "toDict"):
            return self._sanitize_esprima_data(node.toDict())

        if isinstance(node, dict):
            return self._sanitize_esprima_data(node)

        # Manual conversion for esprima nodes
        result = {}
        for key in dir(node):
            if key.startswith("_"):
                continue

            value = getattr(node, key)

            if callable(value):
                continue

            if hasattr(value, "__iter__") and not isinstance(value, (str, dict)):
                result[key] = [self._esprima_to_dict(item, _seen) for item in value]
            elif hasattr(value, "toDict") or hasattr(value, "type"):
                result[key] = self._esprima_to_dict(value, _seen)
            else:
                result[key] = value

        return self._sanitize_esprima_data(result)

    def _sanitize_esprima_data(self, value: Any) -> Any:
        """Convert parser output into JSON-safe AST data."""
        if value is None or isinstance(value, (int, float, bool, str)):
            return value
        if isinstance(value, re.Pattern):
            # Regex literals are already represented by sibling `raw` and
            # `regex` fields. Keeping the compiled Python object breaks AST
            # persistence and checkpoint serialization.
            return None
        if isinstance(value, dict):
            return {
                key: self._sanitize_esprima_data(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self._sanitize_esprima_data(item) for item in value]
        if isinstance(value, set):
            return [self._sanitize_esprima_data(item) for item in sorted(value, key=repr)]
        return None

    def _parse_pyjsparser(self, source: str) -> ParseResult:
        """Parse using pyjsparser."""
        try:
            parser = pyjsparser.PyJsParser()
            ast = parser.parse(source)

            return ParseResult(
                success=True,
                ast=ast,
                errors=[],
                partial=False,
                parser_used="pyjsparser",
            )

        except Exception as e:
            if self.tolerant:
                return self._parse_regex_fallback(source)

            return ParseResult(
                success=False,
                ast=None,
                errors=[str(e)],
                partial=False,
                parser_used="pyjsparser",
            )

    # Security limits for regex fallback
    MAX_STRINGS_EXTRACTED = 10000
    MAX_STRING_LENGTH = 10000

    def _parse_regex_fallback(self, source: str) -> ParseResult:
        """
        Fallback parser using regex for string extraction.

        This doesn't produce a real AST but extracts useful data.
        Security: Limited to prevent memory exhaustion attacks.
        """
        import re

        # Extract string literals with limits
        strings = []

        def add_string(match, string_type: str) -> bool:
            """Add string if within limits. Returns False if limit reached."""
            if len(strings) >= self.MAX_STRINGS_EXTRACTED:
                return False

            value = match.group(0)[1:-1]
            # Truncate very long strings
            if len(value) > self.MAX_STRING_LENGTH:
                value = value[:self.MAX_STRING_LENGTH] + "..."

            strings.append({
                "type": string_type,
                "value": value,
                "raw": match.group(0)[:self.MAX_STRING_LENGTH],
                "loc": self._get_loc(source, match.start()),
            })
            return True

        # Double-quoted strings
        for match in re.finditer(r'"([^"\\]|\\.)*"', source):
            if not add_string(match, "Literal"):
                break

        # Single-quoted strings (only if limit not reached)
        if len(strings) < self.MAX_STRINGS_EXTRACTED:
            for match in re.finditer(r"'([^'\\]|\\.)*'", source):
                if not add_string(match, "Literal"):
                    break

        # Template literals (simplified, only if limit not reached)
        if len(strings) < self.MAX_STRINGS_EXTRACTED:
            for match in re.finditer(r'`([^`\\]|\\.)*`', source):
                if not add_string(match, "Literal"):
                    break

        # Create a pseudo-AST with extracted strings
        body = [
            {"type": "ExpressionStatement", "expression": s}
            for s in strings
        ]

        errors = ["Used regex fallback - no parser available"]
        if len(strings) >= self.MAX_STRINGS_EXTRACTED:
            errors.append(f"String extraction limited to {self.MAX_STRINGS_EXTRACTED}")

        return ParseResult(
            success=True,
            ast={"type": "Program", "body": body, "partial": True, "regex_fallback": True},
            errors=errors,
            partial=True,
            parser_used="regex",
        )

    def _get_loc(self, source: str, offset: int) -> dict:
        """Get line/column location from character offset."""
        lines = source[:offset].split("\n")
        line = len(lines)
        column = len(lines[-1]) if lines else 0

        return {
            "start": {"line": line, "column": column},
            "end": {"line": line, "column": column},
        }


def parse_js(source: str, tolerant: bool = True) -> ParseResult:
    """
    Convenience function to parse JavaScript.

    Args:
        source: JavaScript source code
        tolerant: Whether to use error-tolerant parsing

    Returns:
        ParseResult with AST
    """
    parser = JSParser(tolerant=tolerant)
    return parser.parse(source)
