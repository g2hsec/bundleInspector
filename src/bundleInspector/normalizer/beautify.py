"""
JavaScript beautifier and normalizer.

Transforms minified/obfuscated JS into readable format while
maintaining line mapping for evidence.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum

import jsbeautifier

from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping
from bundleInspector.parser.lexical_context import (
    LexicalGoal,
    is_line_terminator,
    line_comment_end,
)

# Markers that indicate TypeScript or JSX/TSX source. jsbeautifier is a plain JS/HTML/CSS
# beautifier with NO TS/JSX support: on such input it mis-tokenizes JSX element syntax and injects
# whitespace INTO the following string literal (e.g. `fetch("/api/admin")` -> `fetch("/api / admin ")`),
# corrupting the analysis input and silently dropping endpoints/secrets/sinks (DQ-C02). When any of
# these markers is present we skip beautification entirely and keep the RAW source as the (immutable)
# analysis input. Trade-off is deliberately safe: missing a case only forgoes cosmetic reflow, and a
# false match only skips beautify -- both harmless -- whereas beautifying TS/JSX is a correctness loss.
_TS_JSX_MARKERS = re.compile(
    r"""
      \binterface\s+[A-Za-z_$]                              # TS: interface Foo
    | \bnamespace\s+[A-Za-z_$]                              # TS: namespace X
    | \benum\s+[A-Za-z_$]                                   # TS: enum E
    | \bdeclare\s+[A-Za-z_$]                                # TS: declare ...
    | \bimplements\s+[A-Za-z_$]                             # TS: class C implements I
    | \babstract\s+class\b                                  # TS: abstract class
    | \btype\s+[A-Za-z_$][\w$]*\s*(?:<[^=;{}()]*>)?\s*=     # TS: type Alias = ...
    | :\s*(?:string|number|boolean|void|unknown|never|any|object|symbol|bigint)\b  # TS primitive annotation
    | =>\s*<[A-Za-z]                                        # JSX: () => <Tag ...
    | \breturn\s*<[A-Za-z]                                  # JSX: return <Tag ...
    | (?:\A|[;\r\n])[\t ]*<(?:[A-Za-z][\w.:-]*(?:[\t />]|$)|>)  # bare JSX stmt
    | [\[=(,?:]\s*<[A-Za-z]                                 # JSX in expression position / array item
    | (?:&&|\|\|)\s*<[A-Za-z]                               # JSX: cond && <Tag
    | <[A-Za-z][\w.]*\s+[^<>]*?/>                           # JSX self-closing element with attributes
    | (?:=>|\breturn|[=(,?:]|&&|\|\|)\s*<>                  # JSX fragment in expression position: => <>
    | </>                                                  # JSX closing fragment
    """,
    re.VERBOSE,
)


def _static_literal_multiset(source: str) -> Counter[str]:
    """Collect lexical quoted/static-template tokens for the normalization safety invariant."""
    literals: Counter[str] = Counter()
    cursor = 0
    length = len(source)
    lexical_goal = LexicalGoal()
    while cursor < length:
        if source.startswith("//", cursor):
            cursor = line_comment_end(source, cursor + 2)
            continue
        if source.startswith("/*", cursor):
            close = source.find("*/", cursor + 2)
            cursor = length if close < 0 else close + 2
            continue
        char = source[cursor]
        if char == "/" and lexical_goal.can_start_regex(source, cursor):
            cursor += 1
            in_class = False
            while cursor < length:
                current = source[cursor]
                if (
                    current == "\\"
                    and cursor + 1 < length
                    and not is_line_terminator(source[cursor + 1])
                ):
                    cursor += 2
                    continue
                if is_line_terminator(current):
                    lexical_goal.note_operand()
                    break
                if current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "/" and not in_class:
                    cursor += 1
                    while cursor < length and source[cursor].isalpha():
                        cursor += 1
                    lexical_goal.note_operand()
                    break
                cursor += 1
            continue
        if char not in "'\"`":
            lexical_goal.observe_code_char(source, cursor)
            cursor += 1
            continue
        quote = char
        start = cursor
        cursor += 1
        dynamic_template = False
        while cursor < length:
            current = source[cursor]
            if current == "\\" and cursor + 1 < length:
                cursor += 2
                continue
            if quote == "`" and current == "$" and cursor + 1 < length and source[cursor + 1] == "{":
                dynamic_template = True
            if current == quote:
                cursor += 1
                if quote != "`" or not dynamic_template:
                    literals[source[start:cursor]] += 1
                lexical_goal.note_operand()
                break
            cursor += 1
    return literals


class NormalizationLevel(Enum):
    """Normalization levels."""
    NONE = 0       # Original (no changes)
    BEAUTIFY = 1   # Beautify only (formatting)
    LIGHT = 2      # Light deobfuscation (safe transforms)


@dataclass
class NormalizationResult:
    """Result of normalization."""
    content: str
    original_content: str
    level: NormalizationLevel
    line_mapper: LineMapper
    success: bool
    errors: list[str]


class Beautifier:
    """
    JavaScript beautifier with line mapping.

    Transforms minified JS while tracking original positions.
    """

    def __init__(self, level: NormalizationLevel = NormalizationLevel.BEAUTIFY):
        self.level = level

        # jsbeautifier options
        self.options = jsbeautifier.default_options()
        self.options.indent_size = 2
        self.options.indent_char = " "
        self.options.max_preserve_newlines = 2
        self.options.preserve_newlines = True
        self.options.keep_array_indentation = False
        self.options.break_chained_methods = True
        self.options.indent_scripts = "normal"
        self.options.brace_style = "collapse"
        self.options.space_before_conditional = True
        self.options.unescape_strings = False
        self.options.jslint_happy = False
        self.options.end_with_newline = True
        self.options.wrap_line_length = 0
        self.options.e4x = False
        self.options.comma_first = False
        self.options.operator_position = "before-newline"

    def beautify(
        self,
        content: str,
        level: NormalizationLevel | None = None,
    ) -> NormalizationResult:
        """
        Beautify JavaScript content.

        Args:
            content: Raw JS content
            level: Normalization level (optional, uses instance default)

        Returns:
            NormalizationResult with beautified content and line mapping
        """
        level = level if level is not None else self.level
        errors: list[str] = []

        if level == NormalizationLevel.NONE:
            return NormalizationResult(
                content=content,
                original_content=content,
                level=level,
                line_mapper=LineMapper.identity(content),
                success=True,
                errors=[],
            )

        # DQ-C02 containment: jsbeautifier corrupts TS/JSX (injects whitespace into string literals),
        # so skip it for such input and analyze the RAW source unchanged. Identity mapping keeps
        # evidence lines 1:1 with the raw source.
        if _TS_JSX_MARKERS.search(content):
            return NormalizationResult(
                content=content,
                original_content=content,
                level=NormalizationLevel.NONE,
                line_mapper=LineMapper.identity(content),
                success=True,
                errors=[],
            )

        try:
            # Beautify
            beautified = jsbeautifier.beautify(content, self.options)

            # Raw-vs-normalized monotonicity: formatting is allowed to move tokens, never to alter or
            # drop literal evidence. jsbeautifier has corrupted unsupported JSX shapes even when a
            # syntax marker was missed. Reject that output and preserve the raw analysis input.
            missing_literals = _static_literal_multiset(content) - _static_literal_multiset(beautified)
            if missing_literals:
                return NormalizationResult(
                    content=content,
                    original_content=content,
                    level=NormalizationLevel.NONE,
                    line_mapper=LineMapper.identity(content),
                    success=True,
                    errors=[
                        "Beautification rejected: normalized output did not preserve raw literals"
                    ],
                )

            # Build the line mapping against the beautified text BEFORE any content-changing
            # deobfuscation: _create_line_mapping aligns NON-whitespace characters and assumes
            # beautify only reflowed WHITESPACE. LIGHT deobfuscation changes non-whitespace
            # (e.g. `\x41` -> `A`, folded string concats), which would drift the alignment -- so map
            # first (correct line mapping), then deobfuscate the returned content.
            line_mapper = self._create_line_mapping(content, beautified)

            if level == NormalizationLevel.LIGHT:
                beautified, extra_errors = self._light_deobfuscate(beautified)
                errors.extend(extra_errors)

            return NormalizationResult(
                content=beautified,
                original_content=content,
                level=level,
                line_mapper=line_mapper,
                success=True,
                errors=errors,
            )

        except Exception as e:
            # Fallback - return original
            return NormalizationResult(
                content=content,
                original_content=content,
                level=NormalizationLevel.NONE,
                line_mapper=LineMapper.identity(content),
                success=False,
                errors=[str(e)],
            )

    # Characters treated as intra-line whitespace (newlines handled separately).
    _INLINE_WHITESPACE = " \t\r\f\v"
    _ANY_WHITESPACE = " \t\r\f\v\n"

    def _create_line_mapping(
        self,
        original: str,
        beautified: str,
    ) -> LineMapper:
        """
        Create a line mapping between original and beautified content.

        Beautification only inserts/removes whitespace and newlines while
        preserving the order of non-whitespace tokens. We exploit that to align
        the two texts in a single O(n) pass over their characters: for each
        beautified line we record the original position of that line's first
        non-whitespace character.

        This replaces a fuzzy per-line difflib similarity search that was
        O(beautified_lines * len(original)^2) - pathologically slow (tens of
        seconds on a single ~50KB minified line, the dominant pipeline cost)
        and near-useless on minified input (it mapped every line to line 1,
        column 0). The offset alignment is both linear and more accurate.
        """
        mapper = LineMapper()

        inline_ws = self._INLINE_WHITESPACE
        any_ws = self._ANY_WHITESPACE
        olen = len(original)
        oi = 0
        original_line = 1
        original_column = 0

        beautified_line = 1
        beautified_column = 0
        at_line_start = True

        for ch in beautified:
            if ch == "\n":
                beautified_line += 1
                beautified_column = 0
                at_line_start = True
                continue
            if ch in inline_ws:
                beautified_column += 1     # DQ-P07: count leading whitespace so the mapping records
                continue                    # the first token's real (indented) normalized column.

            # Non-whitespace token char: advance original past any whitespace to
            # reach the corresponding token character.
            while oi < olen and original[oi] in any_ws:
                if original[oi] == "\n":
                    original_line += 1
                    original_column = 0
                else:
                    original_column += 1
                oi += 1

            if at_line_start:
                mapper.add_mapping(LineMapping(
                    original_line=original_line,
                    original_column=original_column,
                    normalized_line=beautified_line,
                    # DQ-P07: the beautified column of the line's first token (its indentation), NOT a
                    # 0 sentinel -- so LineMapper.get_original subtracts the beautify indentation when
                    # reconstructing the generated column instead of folding it in.
                    normalized_column=beautified_column,
                ))
                at_line_start = False

            # Consume the matching original character.
            if oi < olen:
                original_column += 1
                oi += 1

        return mapper

    def _light_deobfuscate(self, content: str) -> tuple[str, list[str]]:
        """
        Apply light deobfuscation.

        Safe transforms only - no code execution or complex analysis.
        """
        errors: list[str] = []

        # Simple string concatenation folding
        # "a" + "b" -> "ab"
        import re

        def fold_string_concat(match: re.Match[str]) -> str:
            parts = str(match.group(0))
            # Extract strings and concatenate (handle escaped quotes)
            strings = re.findall(r""""((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'""", parts)
            if strings:
                pieces = []
                for s1, s2 in strings:
                    if s1:
                        # From double-quoted source ??already properly escaped
                        pieces.append(s1)
                    else:
                        # From single-quoted source ??escape unescaped double quotes
                        pieces.append(s2.replace('"', '\\"'))
                return f'"{("").join(pieces)}"'
            return str(match.group(0))

        try:
            # Pattern for simple string concatenation (handle escaped quotes)
            pattern = r'''(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')'''
            for _ in range(10):
                new_content = re.sub(pattern, fold_string_concat, content)
                if new_content == content:
                    break
                content = new_content
        except Exception as e:
            errors.append(f"String folding error: {e}")

        # Decode simple hex/unicode escapes in strings
        try:
            def decode_escapes(match: re.Match[str]) -> str:
                s = str(match.group(1))
                try:
                    return f'"{self._decode_hex_escapes(s)}"'
                except Exception:
                    return str(match.group(0))

            # Hex escapes: \x41 (handle escaped quotes and skip \\x sequences)
            content = re.sub(
                r'"((?:[^"\\]|\\.)*\\x[0-9a-fA-F]{2}(?:[^"\\]|\\.)*)"',
                decode_escapes,
                content
            )

            def decode_escapes_single(match: re.Match[str]) -> str:
                s = str(match.group(1))
                try:
                    return f"'{self._decode_hex_escapes(s)}'"
                except Exception:
                    return str(match.group(0))

            content = re.sub(
                r"'((?:[^'\\]|\\.)*\\x[0-9a-fA-F]{2}(?:[^'\\]|\\.)*)'",
                decode_escapes_single,
                content
            )
        except Exception as e:
            errors.append(f"Escape decoding error: {e}")

        return content, errors

    def _decode_hex_escapes(self, value: str) -> str:
        """Decode practical `\\xNN` escapes without changing string structure."""
        result: list[str] = []
        index = 0

        while index < len(value):
            char = value[index]
            if char != "\\":
                result.append(char)
                index += 1
                continue

            if index + 1 >= len(value):
                result.append("\\")
                break

            next_char = value[index + 1]
            if next_char == "\\":
                # Keep escaped backslashes intact so later characters are
                # interpreted with the same escape parity as the original JS.
                result.append("\\\\")
                index += 2
                continue

            if (
                next_char == "x"
                and index + 3 < len(value)
                and all(ch in "0123456789abcdefABCDEF" for ch in value[index + 2:index + 4])
            ):
                decoded = chr(int(value[index + 2:index + 4], 16))
                if self._is_safe_decoded_char(decoded):
                    result.append(decoded)
                else:
                    result.append(value[index:index + 4])
                index += 4
                continue

            result.append(char)
            result.append(next_char)
            index += 2

        return "".join(result)

    def _is_safe_decoded_char(self, char: str) -> bool:
        """Keep structural escapes intact to avoid producing invalid JS."""
        if char in {'"', "'", "\\", "\n", "\r", "\t", "\0"}:
            return False
        if ord(char) < 0x20:
            return False
        return True


def beautify_js(content: str) -> str:
    """
    Convenience function to beautify JS.

    Args:
        content: Raw JS content

    Returns:
        Beautified JS content
    """
    beautifier = Beautifier()
    result = beautifier.beautify(content)
    return result.content
