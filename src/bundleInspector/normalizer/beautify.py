"""
JavaScript beautifier and normalizer.

Transforms minified/obfuscated JS into readable format while
maintaining line mapping for evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

import jsbeautifier

from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping


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
        level: Optional[NormalizationLevel] = None,
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

        try:
            # Beautify
            beautified = jsbeautifier.beautify(content, self.options)

            # Apply light deobfuscation if requested (before creating line mapping)
            if level == NormalizationLevel.LIGHT:
                beautified, extra_errors = self._light_deobfuscate(beautified)
                errors.extend(extra_errors)

            # Create line mapping after all content transforms are done
            line_mapper = self._create_line_mapping(content, beautified)

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

    def _create_line_mapping(
        self,
        original: str,
        beautified: str,
    ) -> LineMapper:
        """
        Create line mapping between original and beautified.

        This is an approximation - exact mapping would require
        token-level analysis.
        """
        mapper = LineMapper()

        original_lines = original.split("\n")
        beautified_lines = beautified.split("\n")

        # Simple heuristic: map based on content similarity
        # For more accuracy, we'd need to track tokens through beautification

        original_line = 0
        for beautified_line, beautified_content in enumerate(beautified_lines, 1):
            # Find best matching original line
            best_match = self._find_best_match(
                beautified_content,
                original_lines,
                start_from=original_line,
            )

            if best_match is not None:
                original_line = best_match
                mapper.add_mapping(LineMapping(
                    original_line=original_line + 1,
                    original_column=0,
                    normalized_line=beautified_line,
                    normalized_column=0,
                ))
            else:
                original_line = min(original_line + 1, len(original_lines) - 1)

        return mapper

    def _find_best_match(
        self,
        content: str,
        original_lines: list[str],
        start_from: int,
    ) -> Optional[int]:
        """Find best matching original line."""
        content = content.strip()
        if not content:
            return None

        # Look in a window around start_from
        window = 50
        half_window = window // 2
        start = max(0, start_from - half_window)
        end = min(len(original_lines), start_from + half_window)

        best_match = None
        best_score = 0

        for i in range(start, end):
            original = original_lines[i].strip()
            if not original:
                continue

            # Simple similarity: common substring length
            score = self._similarity_score(content, original)
            if score > best_score:
                best_score = score
                best_match = i

        return best_match if best_score > 0.3 else None

    def _similarity_score(self, a: str, b: str) -> float:
        """Calculate similarity score between two strings (0.0 to 1.0)."""
        if not a or not b:
            return 0.0

        from difflib import SequenceMatcher
        return SequenceMatcher(None, a, b).ratio()

    def _light_deobfuscate(self, content: str) -> tuple[str, list[str]]:
        """
        Apply light deobfuscation.

        Safe transforms only - no code execution or complex analysis.
        """
        errors: list[str] = []

        # Simple string concatenation folding
        # "a" + "b" -> "ab"
        import re

        def fold_string_concat(match: re.Match) -> str:
            parts = match.group(0)
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
            return match.group(0)

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
            def decode_escapes(match: re.Match) -> str:
                s = match.group(1)
                try:
                    return f'"{re.sub(r"(?<!\\)\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)}"'
                except Exception:
                    return match.group(0)

            # Hex escapes: \x41 (handle escaped quotes and skip \\x sequences)
            content = re.sub(
                r'"((?:[^"\\]|\\.)*\\x[0-9a-fA-F]{2}(?:[^"\\]|\\.)*)"',
                decode_escapes,
                content
            )

            def decode_escapes_single(match: re.Match) -> str:
                s = match.group(1)
                try:
                    return f"'{re.sub(r'(?<!\\)\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)}'"
                except Exception:
                    return match.group(0)

            content = re.sub(
                r"'((?:[^'\\]|\\.)*\\x[0-9a-fA-F]{2}(?:[^'\\]|\\.)*)'",
                decode_escapes_single,
                content
            )
        except Exception as e:
            errors.append(f"Escape decoding error: {e}")

        return content, errors


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

