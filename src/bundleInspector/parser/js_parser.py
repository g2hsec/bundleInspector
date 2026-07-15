"""
JavaScript AST parser.

Parses JavaScript into AST with error tolerance.
"""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

from bundleInspector.parser import native_acorn, tree_sitter_backend
from bundleInspector.parser.lexical_context import (
    LexicalGoal,
    is_line_terminator,
    line_comment_end,
)
from bundleInspector.parser.tree_sitter_backend import LanguageHint


@dataclass
class ParseResult:
    """Result of parsing JavaScript."""
    success: bool
    ast: dict[str, Any] | None
    errors: list[str]
    partial: bool  # True if only partial parsing succeeded
    parser_used: str
    completeness: str = "complete"  # complete | partial | failed
    capability_gaps: tuple[str, ...] = ()
    truncation_reasons: tuple[str, ...] = ()


class JSParser:
    """
    JavaScript AST parser with error tolerance.

    Supports multiple parser backends and falls back gracefully.
    """

    def __init__(
        self,
        tolerant: bool = True,
        partial_on_error: bool = True,
        temp_dir: Path | None = None,
    ):
        """
        Initialize parser.

        Args:
            tolerant: Whether to use error-tolerant parsing
            partial_on_error: When a full parse fails, fall back to a best-effort PARTIAL/regex parse
                (DQ-P13). Default True preserves prior behavior; False returns a failed ParseResult
                instead of a partial one.
        """
        self.tolerant = tolerant
        self.partial_on_error = partial_on_error
        self.temp_dir = temp_dir
        self._parser = self._select_parser()

    @classmethod
    def from_parser_config(
        cls,
        parser_config: Any,
        *,
        temp_dir: Path | None = None,
    ) -> JSParser:
        """DQ-P13: build a JSParser honoring a ParserConfig (duck-typed)."""
        return cls(
            tolerant=getattr(parser_config, "tolerant", True),
            partial_on_error=getattr(parser_config, "partial_on_error", True),
            temp_dir=temp_dir,
        )

    def _select_parser(self) -> str:
        """Select available parser."""
        if ESPRIMA_AVAILABLE:
            return "esprima"
        elif PYJSPARSER_AVAILABLE:
            return "pyjsparser"
        else:
            return "regex"  # Fallback to regex-based extraction

    def parse(
        self,
        source: str,
        *,
        language_hint: LanguageHint | None = None,
    ) -> ParseResult:
        """
        Parse JavaScript source code.

        Args:
            source: JavaScript source code
            language_hint: Optional explicit JavaScript/JSX/TypeScript/TSX grammar. Existing
                callers remain source-compatible because the hint is keyword-only.

        Returns:
            ParseResult with AST and metadata
        """
        if language_hint is not None:
            structural = tree_sitter_backend.parse_tree_sitter(
                source,
                language_hint=language_hint,
            )
            if structural is not None and structural.success:
                return self._tree_sitter_result(structural)

        # Optional native (acorn) fast path -- opt-in via BUNDLEINSPECTOR_NATIVE_PARSER.
        # Returns an ESTree AST equivalent to esprima's on parseable input (and a more
        # complete one on modern syntax). Any failure yields None -> esprima fallback,
        # so detection can never degrade relative to the default parser.
        native_ast = native_acorn.parse_source(source, temp_dir=self.temp_dir)
        if native_ast is not None:
            return ParseResult(
                success=True,
                ast=native_ast,
                errors=[],
                partial=False,
                parser_used="acorn",
                completeness="complete",
            )

        if self._parser == "esprima":
            legacy_result = self._parse_esprima(source)
        elif self._parser == "pyjsparser":
            legacy_result = self._parse_pyjsparser(source)
        else:
            legacy_result = self._parse_regex_fallback(source)

        # A complete legacy ESTree remains the least disruptive result for unhinted plain JS. When
        # it had to lower syntax, recover fragments, or fall back lexically, prefer the structural
        # backend: this is the production path that restores modern JS/JSX/TS/TSX semantics.
        if language_hint is None and legacy_result.completeness == "complete":
            return legacy_result

        structural = tree_sitter_backend.parse_tree_sitter(
            source,
            language_hint=language_hint,
        )
        if (
            structural is not None
            and structural.success
            and (
                not structural.partial
                or legacy_result.parser_used == "regex"
                or not legacy_result.success
            )
        ):
            return self._tree_sitter_result(structural)

        if language_hint is not None:
            reason = tree_sitter_backend.tree_sitter_availability_reason()
            errors = list(legacy_result.errors)
            errors.append(f"Requested {language_hint} structural backend unavailable: {reason}")
            gaps = tuple(dict.fromkeys((*legacy_result.capability_gaps, reason)))
            return ParseResult(
                success=legacy_result.success,
                ast=legacy_result.ast,
                errors=errors,
                partial=legacy_result.partial,
                parser_used=legacy_result.parser_used,
                completeness=legacy_result.completeness,
                capability_gaps=gaps,
                truncation_reasons=legacy_result.truncation_reasons,
            )
        return legacy_result

    def _tree_sitter_result(
        self,
        result: tree_sitter_backend.TreeSitterParseResult,
    ) -> ParseResult:
        """Adapt the standalone backend result without coupling it back to this module."""

        if result.partial and not self.partial_on_error:
            return ParseResult(
                success=False,
                ast=None,
                errors=list(result.errors),
                partial=False,
                parser_used=result.parser_used,
                completeness="failed",
                capability_gaps=result.capability_gaps,
                truncation_reasons=result.truncation_reasons,
            )
        return ParseResult(
            success=result.success,
            ast=result.ast,
            errors=list(result.errors),
            partial=result.partial,
            parser_used=result.parser_used,
            completeness="partial" if result.partial else "complete",
            capability_gaps=result.capability_gaps,
            truncation_reasons=result.truncation_reasons,
        )

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
            if self.tolerant and self.partial_on_error:
                return self._partial_parse_esprima(source, str(e))
            return ParseResult(
                success=False,
                ast=None,
                errors=[str(e)],
                partial=False,
                parser_used="esprima",
                completeness="failed",
            )

    def _try_parse_esprima_source(
        self,
        source: str,
        parser_used: str,
    ) -> ParseResult | None:
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
                syntax_lowered = parser_used == "esprima-normalized"
                if syntax_lowered:
                    ast_dict["partial"] = True
                    ast_dict["parser_capability"] = "syntax_lowered"
                return ParseResult(
                    success=True,
                    ast=ast_dict,
                    errors=(
                        ["Parser syntax lowering applied; semantics may be incomplete"]
                        if syntax_lowered
                        else []
                    ),
                    partial=syntax_lowered,
                    parser_used=parser_used,
                    completeness="partial" if syntax_lowered else "complete",
                    capability_gaps=("modern_syntax_lowered",) if syntax_lowered else (),
                )
            except esprima.Error:
                continue
            except Exception:
                # RecursionError (deep AST -> _esprima_to_dict) or any other unexpected
                # failure must fall through to the next parser / the regex fallback, never
                # abort the parse stage and the whole scan.
                continue
        return None

    def _normalize_modern_syntax_for_esprima(self, source: str) -> str:
        """Best-effort syntax normalization for parser-unsupported operators."""
        result: list[str] = []
        state = "code"
        string_quote = ""
        template_expr_stack: list[int] = []
        regex_in_char_class = False
        lexical_goal = LexicalGoal()
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
                if char == "/" and lexical_goal.can_start_regex(source, i):
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
                is_template_boundary = bool(
                    template_expr_stack
                    and char == "}"
                    and template_expr_stack[-1] == 1
                )
                if not is_template_boundary:
                    lexical_goal.observe_code_char(source, i)
                if char == "?" and next_char == "?" and i + 2 < len(source) and source[i + 2] == "=":
                    result.append(" = ")
                    i += 3
                    continue
                # Logical-assignment operators `||=` / `&&=` (ES2021) are unparseable by esprima.
                # Width-preserving downgrade to a plain assignment (mirrors `??=` above): `a ||= b`
                # -> `a  =  b` keeps the assignment SHAPE so kill/gen taint tracking and helper
                # analysis survive, instead of the whole (often single-line minified) bundle
                # collapsing to the string-only regex fallback that ZEROES every AST detector.
                # `|=`/`&=` (bitwise, 2 chars) and plain `||`/`&&` are left for esprima -- the
                # `next_char == char and source[i + 2] == "="` guard matches only the 3-char forms.
                if char in ("|", "&") and next_char == char and i + 2 < len(source) and source[i + 2] == "=":
                    result.append(" = ")
                    i += 3
                    continue
                if char == "?" and next_char == "?":
                    # Preserve width while downgrading to an older logical operator
                    # so esprima can still recover a usable AST for helper analysis.
                    result.append("||")
                    i += 2
                    continue
                # Optional chaining `?.` (ES2020) -- esprima cannot parse it, so a single-line
                # minified bundle that uses it fails the full parse and collapses to the string-only
                # regex fallback, ZEROING every AST detector (endpoints/sinks/taint/flags/debug).
                # Downgrade `?.` to plain member access, width-preserving (absolute char offsets are
                # relied on by enh1 access-control gating). GUARD: `a?.5:b` is the ternary operator
                # with a fractional literal, NOT optional chaining -- leave it for esprima.
                if char == "?" and next_char == ".":
                    after = source[i + 2] if i + 2 < len(source) else ""
                    if after.isdigit():
                        result.append(char)          # ternary `?.5` -> leave `?` intact
                        i += 1
                        continue
                    if after in ("(", "["):          # `?.(` optional call / `?.[` computed
                        result.append("  ")          # 2 spaces ('.' before ( / [ is illegal)
                        i += 2
                        continue
                    result.append(" ")               # `?.id` -> ` .id`
                    i += 1
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
                            lexical_goal.note_operand()
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
                    lexical_goal.enter_template_expression()
                    i += 2
                    continue
                result.append(char)
                if char == "\\" and i + 1 < len(source):
                    result.append(source[i + 1])
                    i += 2
                    continue
                if char == string_quote:
                    state = "code"
                    lexical_goal.note_operand()
                i += 1
                continue

            if state == "regex":
                result.append(char)
                if is_line_terminator(char):
                    state = "code"
                    lexical_goal.note_operand()
                    i += 1
                    continue
                if (
                    char == "\\"
                    and i + 1 < len(source)
                    and not is_line_terminator(source[i + 1])
                ):
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
                    lexical_goal.note_operand()
                i += 1
                continue

            if state == "line_comment":
                result.append(char)
                if is_line_terminator(char):
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

    def _partial_parse_esprima(
        self,
        source: str,
        error: str,
    ) -> ParseResult:
        """Attempt partial parsing when full parsing fails."""
        # Split into blank-line-separated chunks and parse what we can. A capturing split keeps the
        # delimiters so CRLF sources (\r\n\r\n) recover too -- plain source.split("\n\n") finds no
        # delimiter in CRLF and returns the whole (already-failing) source as one chunk, recovering
        # nothing. Even parts are chunks, odd parts are the matched blank-line delimiters (DQ-P05).
        parts = re.split(r"(\r\n\r\n|\n\n|\r\r)", source)
        body = []
        errors = [error]
        chunk_starts: set[int] = set()
        running_offset = 0
        for part_index, part in enumerate(parts):
            if part_index % 2 == 0:
                chunk_starts.add(running_offset)
            running_offset += len(part)
        code_chunk_starts = self._code_context_offsets(source, chunk_starts)

        # Track char_offset AND line_offset INCREMENTALLY as we walk parts in order. Recomputing
        # line_offset per chunk via re.findall(source[:char_offset]) re-scans a growing prefix ->
        # O(n^2) over many blank-line chunks (a reachable ReDoS on the default partial-parse path).
        # Accumulating each part's terminators once keeps the whole loop O(n) with identical offsets.
        _term_re = re.compile(r"\r\n|\r|\n")
        char_offset = 0
        line_offset = 0
        for i, part in enumerate(parts):
            if i % 2 == 1:
                # Captured blank-line delimiter (2 chars for \n\n/\r\r, 4 for \r\n\r\n): advance the
                # absolute offset and line count by its real width so loc.line/range stays exact.
                char_offset += len(part)
                line_offset += len(_term_re.findall(part))
                continue
            chunk = part
            # Each chunk is parsed INDEPENDENTLY, so esprima's loc.line and range start at the chunk,
            # not the original source. Translate them back to ABSOLUTE positions using the running
            # line_offset (line terminators before char_offset, counting \r\n as one and lone \r / \n
            # each as one, the way esprima does) -- else a CR-only / \r\r-delimited source would
            # mislabel every recovered node's line (DQ-P05).
            if char_offset not in code_chunk_starts:
                char_offset += len(chunk)
                line_offset += len(_term_re.findall(chunk))
                continue
            try:
                chunk_ast = esprima.parseScript(
                    chunk,
                    {"tolerant": True, "loc": True, "range": True}
                )
                chunk_dict = self._esprima_to_dict(chunk_ast)
                self._offset_ast_positions(chunk_dict, line_offset, char_offset)
                body.extend(chunk_dict.get("body", []))
            except Exception:
                pass
            char_offset += len(chunk)
            line_offset += len(_term_re.findall(chunk))

        if body:
            return ParseResult(
                success=True,
                ast={"type": "Program", "body": body, "partial": True},
                errors=errors,
                partial=True,
                parser_used="esprima",
                completeness="partial",
                capability_gaps=("unparsed_source_regions",),
            )

        # Last resort: regex fallback
        return self._parse_regex_fallback(source)

    def _code_context_offsets(self, source: str, offsets: set[int]) -> set[int]:
        """Return requested offsets that begin in executable lexical code.

        Partial chunks are never parsed when their first byte is inside a comment, string,
        template raw segment, or regex literal. This prevents independent chunk parsing from
        turning inert source text into executable AST nodes.
        """
        code_offsets: set[int] = set()
        state = "code"
        interpolation_depths: list[int] = []
        lexical_goal = LexicalGoal()
        index = 0
        length = len(source)
        while index <= length:
            if index in offsets and state == "code":
                code_offsets.add(index)
            if index == length:
                break
            char = source[index]
            next_char = source[index + 1] if index + 1 < length else ""

            if state in {"single", "double"}:
                if char == "\\" and index + 1 < length:
                    index += 2
                    continue
                if char == ("'" if state == "single" else '"'):
                    state = "code"
                    lexical_goal.note_operand()
                index += 1
                continue
            if state == "template":
                if char == "\\" and index + 1 < length:
                    index += 2
                    continue
                if char == "`":
                    state = "code"
                    lexical_goal.note_operand()
                    index += 1
                    continue
                if char == "$" and next_char == "{":
                    interpolation_depths.append(0)
                    state = "code"
                    lexical_goal.enter_template_expression()
                    index += 2
                    continue
                index += 1
                continue
            if state == "line_comment":
                if is_line_terminator(char):
                    state = "code"
                index += 1
                continue
            if state == "block_comment":
                if char == "*" and next_char == "/":
                    state = "code"
                    index += 2
                else:
                    index += 1
                continue

            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
                index += 2
                continue
            if char == "'":
                state = "single"
                index += 1
                continue
            if char == '"':
                state = "double"
                index += 1
                continue
            if char == "`":
                state = "template"
                index += 1
                continue
            if char == "/" and lexical_goal.can_start_regex(source, index):
                index += 1
                in_class = False
                while index < length:
                    current = source[index]
                    if (
                        current == "\\"
                        and index + 1 < length
                        and not is_line_terminator(source[index + 1])
                    ):
                        index += 2
                        continue
                    if is_line_terminator(current):
                        lexical_goal.note_operand()
                        break
                    if current == "[":
                        in_class = True
                    elif current == "]":
                        in_class = False
                    elif current == "/" and not in_class:
                        index += 1
                        while index < length and source[index].isalpha():
                            index += 1
                        lexical_goal.note_operand()
                        break
                    index += 1
                continue
            if interpolation_depths:
                if char == "{":
                    interpolation_depths[-1] += 1
                elif char == "}":
                    if interpolation_depths[-1] == 0:
                        interpolation_depths.pop()
                        state = "template"
                        lexical_goal.note_operand()
                        index += 1
                        continue
                    interpolation_depths[-1] -= 1
            lexical_goal.observe_code_char(source, index)
            index += 1
        return code_offsets

    def _offset_ast_positions(self, node: Any, line_offset: int, char_offset: int) -> None:
        """Translate a chunk-local AST's loc.line and range offsets to ABSOLUTE positions in the
        original source. Used by partial parsing, which parses each blank-line-separated chunk
        independently. Iterative (explicit stack) to avoid RecursionError on deep/obfuscated ASTs;
        an id()-guarded `seen` set offsets each node exactly once (and neutralizes the cycle-
        collapsed `{}` sentinels _esprima_to_dict emits)."""
        if line_offset == 0 and char_offset == 0:
            return
        stack: list = [node]
        seen: set[int] = set()
        while stack:
            cur = stack.pop()
            if isinstance(cur, list):
                stack.extend(cur)
                continue
            if not isinstance(cur, dict):
                continue
            nid = id(cur)
            if nid in seen:
                continue
            seen.add(nid)
            loc = cur.get("loc")
            if isinstance(loc, dict):
                for k in ("start", "end"):
                    p = loc.get(k)
                    if isinstance(p, dict) and isinstance(p.get("line"), int):
                        p["line"] += line_offset
            rng = cur.get("range")
            if isinstance(rng, list) and len(rng) >= 2:
                try:
                    rng[0] = int(rng[0]) + char_offset
                    rng[1] = int(rng[1]) + char_offset
                except (TypeError, ValueError):
                    pass
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)

    def _esprima_to_dict(self, node: Any, _seen: set[int] | None = None) -> Any:
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
        result: dict[str, Any] = {}
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
                completeness="complete",
            )

        except Exception as e:
            if self.tolerant and self.partial_on_error:
                return self._parse_regex_fallback(source)

            return ParseResult(
                success=False,
                ast=None,
                errors=[str(e)],
                partial=False,
                parser_used="pyjsparser",
                completeness="failed",
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
        # Extract string literals with limits
        strings = []

        # Precompute newline offsets ONCE so a literal's line/column is an O(log lines) bisect rather
        # than self._get_loc's per-literal source[:offset].split("\n") (O(offset)) -> which, called
        # per extracted string on a single-line minified bundle, is O(n^2).
        line_end_positions = [
            match.end() - 1
            for match in re.finditer(r"\r\n|\r|\n|\u2028|\u2029", source)
        ]

        def loc_for(offset: int) -> dict:
            line = bisect.bisect_right(line_end_positions, offset - 1) + 1
            column = offset - (line_end_positions[line - 2] + 1) if line > 1 else offset
            return {"start": {"line": line, "column": column},
                    "end": {"line": line, "column": column}}

        # Scan once in lexical source order, excluding comments and regex bodies. Keep independent
        # per-quote budgets so a flood of one quote type cannot starve another, while retained nodes
        # still preserve source order (DQ-P03/P04).
        counts = {'"': 0, "'": 0, "`": 0}
        truncation_reasons: set[str] = set()
        for start, end, quote in self._scan_js_literals(source):
            if counts[quote] >= self.MAX_STRINGS_EXTRACTED:
                truncation_reasons.add(f"{quote}-literal count cap {self.MAX_STRINGS_EXTRACTED}")
                continue
            raw = source[start:end]
            raw_value = raw[1:-1]
            value = raw_value
            if len(value) > self.MAX_STRING_LENGTH:
                value = value[:self.MAX_STRING_LENGTH] + "..."
                truncation_reasons.add(f"literal length cap {self.MAX_STRING_LENGTH}")
            strings.append({
                "type": "Literal",
                "value": value,
                "raw": raw[:self.MAX_STRING_LENGTH],
                "loc": loc_for(start),
                "range": [start, end],
            })
            counts[quote] += 1

            # Preserve the established JSON-in-a-JS-string recovery without returning to
            # context-free quote matching. Only syntactically valid JSON is expanded, so examples
            # in comments/ordinary prose remain excluded while serialized endpoint values survive.
            if quote != '"' and len(raw_value) <= self.MAX_STRING_LENGTH:
                for nested_value in self._json_string_values(raw_value):
                    if counts['"'] >= self.MAX_STRINGS_EXTRACTED:
                        truncation_reasons.add(
                            f'"-literal count cap {self.MAX_STRINGS_EXTRACTED}'
                        )
                        break
                    nested = nested_value
                    if len(nested) > self.MAX_STRING_LENGTH:
                        nested = nested[:self.MAX_STRING_LENGTH] + "..."
                        truncation_reasons.add(f"literal length cap {self.MAX_STRING_LENGTH}")
                    strings.append({
                        "type": "Literal",
                        "value": nested,
                        "raw": json.dumps(nested_value)[:self.MAX_STRING_LENGTH],
                        "loc": loc_for(start),
                        "range": [start, end],
                    })
                    counts['"'] += 1

        # Create a pseudo-AST with extracted strings
        body = [
            {"type": "ExpressionStatement", "expression": s}
            for s in strings
        ]

        errors = ["Used lexical fallback - structural AST unavailable"]
        for reason in sorted(truncation_reasons):
            errors.append(f"String extraction truncated: {reason}")

        capability_gaps = ["structural_ast_unavailable", "control_flow_unavailable"]
        if not native_acorn.native_parser_available():
            capability_gaps.append(
                f"native_acorn_{native_acorn.native_parser_availability_reason()}"
            )
        completeness = {
            "state": "partial",
            "capability_gaps": capability_gaps,
            "truncation_reasons": sorted(truncation_reasons),
        }

        return ParseResult(
            success=True,
            ast={
                "type": "Program",
                "body": body,
                "partial": True,
                "regex_fallback": True,
                "parse_completeness": completeness,
            },
            errors=errors,
            partial=True,
            parser_used="regex",
            completeness="partial",
            capability_gaps=tuple(capability_gaps),
            truncation_reasons=tuple(sorted(truncation_reasons)),
        )

    def _scan_js_literals(self, source: str) -> Iterator[tuple[int, int, str]]:
        """Yield exact lexical literals while scanning template interpolations as code.

        Dynamic template raw text is not an exact runtime string and is therefore not emitted as a
        literal. Its `${...}` regions are still scanned, including nested static templates.
        """
        length = len(source)
        cursor = 0
        state = "code"
        template_frames: list[dict[str, int | bool]] = []
        interpolation_depths: list[int] = []
        lexical_goal = LexicalGoal()
        while cursor < length:
            if state == "template":
                char = source[cursor]
                next_char = source[cursor + 1] if cursor + 1 < length else ""
                if char == "\\" and cursor + 1 < length:
                    cursor += 2
                    continue
                if char == "$" and next_char == "{":
                    template_frames[-1]["dynamic"] = True
                    interpolation_depths.append(0)
                    state = "code"
                    lexical_goal.enter_template_expression()
                    cursor += 2
                    continue
                if char == "`":
                    cursor += 1
                    frame = template_frames.pop()
                    if not frame["dynamic"]:
                        yield int(frame["start"]), cursor, "`"
                    state = "code"
                    lexical_goal.note_operand()
                    continue
                cursor += 1
                continue

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

            if interpolation_depths:
                if char == "{":
                    interpolation_depths[-1] += 1
                    lexical_goal.observe_code_char(source, cursor)
                    cursor += 1
                    continue
                if char == "}":
                    if interpolation_depths[-1] == 0:
                        interpolation_depths.pop()
                        state = "template"
                        lexical_goal.note_operand()
                        cursor += 1
                        continue
                    interpolation_depths[-1] -= 1
                    lexical_goal.observe_code_char(source, cursor)
                    cursor += 1
                    continue

            if char == "`":
                template_frames.append({"start": cursor, "dynamic": False})
                state = "template"
                cursor += 1
                continue
            if char not in {'"', "'"}:
                lexical_goal.observe_code_char(source, cursor)
                cursor += 1
                continue
            quote = char
            start = cursor
            cursor += 1
            while cursor < length:
                current = source[cursor]
                if current == "\\" and cursor + 1 < length and source[cursor + 1] != "\n":
                    cursor += 2
                    continue
                if current == quote:
                    cursor += 1
                    lexical_goal.note_operand()
                    yield start, cursor, quote
                    break
                cursor += 1

    @staticmethod
    def _json_string_values(value: str) -> Iterator[str]:
        """Yield JSON object keys and string leaves in deterministic document order."""
        stripped = value.strip()
        if not stripped or stripped[0] not in "[{":
            return
        try:
            decoded = json.loads(stripped)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return
        stack = [decoded]
        while stack:
            current = stack.pop()
            if isinstance(current, str):
                yield current
            elif isinstance(current, list):
                stack.extend(reversed(current))
            elif isinstance(current, dict):
                ordered: list[Any] = []
                for key, item in current.items():
                    ordered.extend((key, item))
                stack.extend(reversed(ordered))

    @staticmethod
    def _scan_quoted_literals(source: str, quote: str) -> Iterator[tuple[int, int]]:
        """Yield (start, end_exclusive) for each `quote...quote` literal, context-free per quote type
        -- the SAME extraction set as the old re.finditer(r'Q([^Q\\]|\\.)*Q') but in a single LINEAR
        pass. The regex re-scanned to EOF from EVERY quote anchor, so an unterminated / escaped-quote
        run (reachable on the default regex-fallback path when esprima fails first) was O(n^2). Body
        rules mirror the regex: an ordinary char (incl. a RAW newline) is body; `\\` + a NON-newline
        is an escape pair (the regex's `\\.` -- `.` is non-DOTALL, so it never spans a newline); `\\`
        at EOF or before a newline is a BARRIER the regex body cannot consume, and no quote precedes
        it (else that quote would have closed the string), so no literal of this type starts before
        the barrier -- skip past it in O(1). i only advances, so the whole scan is O(n)."""
        n = len(source)
        i = 0
        while i < n:
            if source[i] != quote:
                i += 1
                continue
            j = i + 1
            barrier = -1
            while j < n:
                c = source[j]
                if c == "\\":
                    if j + 1 < n and source[j + 1] != "\n":
                        j += 2          # `\\.` escape pair (non-newline follower)
                        continue
                    barrier = j         # `\\` at EOF or before a newline -> regex body stops here
                    break
                if c == quote:
                    break               # closing quote
                j += 1
            if j < n and source[j] == quote:
                yield i, j + 1
                i = j + 1
            elif barrier >= 0:
                i = barrier + 1         # no literal starts in (i, barrier]; resume past the barrier
            else:
                return                  # unterminated to EOF: no closing quote of this type remains

    def _get_loc(self, source: str, offset: int) -> dict:
        """Get line/column location from character offset."""
        lines = source[:offset].split("\n")
        line = len(lines)
        column = len(lines[-1]) if lines else 0

        return {
            "start": {"line": line, "column": column},
            "end": {"line": line, "column": column},
        }


def parse_js(
    source: str,
    tolerant: bool = True,
    partial_on_error: bool = True,
    *,
    language_hint: LanguageHint | None = None,
) -> ParseResult:
    """
    Convenience function to parse JavaScript.

    Args:
        source: JavaScript source code
        tolerant: Whether to use error-tolerant parsing
        partial_on_error: On a full-parse failure, fall back to a partial/regex parse (DQ-P13)
        language_hint: Optional explicit JavaScript/JSX/TypeScript/TSX grammar

    Returns:
        ParseResult with AST
    """
    parser = JSParser(tolerant=tolerant, partial_on_error=partial_on_error)
    return parser.parse(source, language_hint=language_hint)
