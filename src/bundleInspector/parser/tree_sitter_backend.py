"""Tree-sitter JS/JSX/TypeScript/TSX backend with an ESTree-compatible projection."""

from __future__ import annotations

import bisect
import importlib
import re
from array import array
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, cast

from bundleInspector.parser.lexical_context import LexicalGoal, is_line_terminator

LanguageHint = Literal["javascript", "jsx", "typescript", "tsx"]

SUPPORTED_LANGUAGE_HINTS: tuple[LanguageHint, ...] = (
    "javascript",
    "jsx",
    "typescript",
    "tsx",
)

MAX_CST_SCAN_NODES = 1_000_000
MAX_CONVERTED_NODES = 500_000
MAX_CONVERSION_DEPTH = 240
MAX_DIAGNOSTICS = 100

try:
    _tree_sitter: Any = importlib.import_module("tree_sitter")
    _javascript_grammar: Any = importlib.import_module("tree_sitter_javascript")
    _typescript_grammar: Any = importlib.import_module("tree_sitter_typescript")
except (ImportError, OSError):
    _tree_sitter = None
    _javascript_grammar = None
    _typescript_grammar = None


@dataclass(frozen=True)
class TreeSitterParseResult:
    """Backend result independent of ``js_parser.ParseResult`` to avoid an import cycle."""

    success: bool
    ast: dict[str, Any] | None
    errors: tuple[str, ...]
    partial: bool
    parser_used: str
    capability_gaps: tuple[str, ...] = ()
    truncation_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _SyntaxScan:
    errors: tuple[str, ...]
    error_count: int
    missing_count: int
    scanned_nodes: int
    truncated: bool


@dataclass(frozen=True)
class _Candidate:
    language: LanguageHint
    root: Any
    scan: _SyntaxScan
    priority: int

    @property
    def score(self) -> tuple[int, int, int, int]:
        return (
            int(self.scan.truncated),
            self.scan.error_count + self.scan.missing_count,
            self.scan.error_count,
            self.priority,
        )


def tree_sitter_available() -> bool:
    """Return true only when the binding and all required official grammars can load."""

    if _tree_sitter is None or _javascript_grammar is None or _typescript_grammar is None:
        return False
    try:
        _get_language("javascript")
        _get_language("typescript")
        _get_language("tsx")
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return False
    return True


def tree_sitter_availability_reason() -> str:
    """Return a stable, non-sensitive availability diagnostic."""

    if _tree_sitter is None:
        return "tree_sitter_binding_unavailable"
    if _javascript_grammar is None:
        return "tree_sitter_javascript_grammar_unavailable"
    if _typescript_grammar is None:
        return "tree_sitter_typescript_grammar_unavailable"
    try:
        _get_language("javascript")
        _get_language("typescript")
        _get_language("tsx")
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return "tree_sitter_grammar_incompatible"
    return "available"


@lru_cache(maxsize=3)
def _get_language(language: Literal["javascript", "typescript", "tsx"]) -> Any:
    if _tree_sitter is None:
        raise RuntimeError("Tree-sitter binding is unavailable")
    if language == "javascript":
        if _javascript_grammar is None:
            raise RuntimeError("JavaScript grammar is unavailable")
        capsule = _javascript_grammar.language()
    elif language == "typescript":
        if _typescript_grammar is None:
            raise RuntimeError("TypeScript grammar is unavailable")
        capsule = _typescript_grammar.language_typescript()
    else:
        if _typescript_grammar is None:
            raise RuntimeError("TSX grammar is unavailable")
        capsule = _typescript_grammar.language_tsx()
    return _tree_sitter.Language(capsule)


def _grammar_for_hint(hint: LanguageHint) -> Literal["javascript", "typescript", "tsx"]:
    if hint in {"javascript", "jsx"}:
        return "javascript"
    if hint == "typescript":
        return "typescript"
    return "tsx"


def _candidate_hints(language_hint: LanguageHint | None) -> tuple[LanguageHint, ...]:
    if language_hint is not None:
        return (language_hint,)
    return ("javascript", "typescript", "tsx")


def _normalize_import_assertions(source: str) -> str:
    """Lower deprecated ``assert {}`` module attributes to width-preserving ``with  {}``.

    The current official grammar implements the standardized ``with`` spelling. The scanner only
    rewrites a code-context keyword inside a static import/export declaration; strings, templates,
    regex-like text, and comments are left byte-for-byte unchanged so every CST offset still maps to
    the original source.
    """

    if "assert" not in source:
        return source

    chars = list(source)
    state = "code"
    quote = ""
    module_declaration = ""
    module_clause_brace_depth = 0
    expect_module_source = False
    string_is_module_source = False
    assertion_eligible = False
    block_comment_has_line_terminator = False
    regex_in_character_class = False
    interpolation_depths: list[int] = []
    lexical_goal = LexicalGoal()
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char.isspace():
                if assertion_eligible and is_line_terminator(char):
                    # A line terminator after the module source is an ASI boundary. Rewriting a
                    # following identifier statement would change valid JavaScript semantics.
                    assertion_eligible = False
                    module_declaration = ""
                    module_clause_brace_depth = 0
                index += 1
                continue
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
                block_comment_has_line_terminator = False
                index += 2
                continue
            if char == "/" and lexical_goal.can_start_regex(source, index):
                state = "regex"
                regex_in_character_class = False
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
            if char == "`":
                state = "template"
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                string_is_module_source = bool(module_declaration and expect_module_source)
                state = "string"
                index += 1
                continue
            if char == ";":
                module_declaration = ""
                module_clause_brace_depth = 0
                expect_module_source = False
                assertion_eligible = False
                lexical_goal.observe_code_char(source, index)
                index += 1
                continue
            if char.isalpha() or char in {"_", "$"}:
                end = index + 1
                while end < len(source) and (source[end].isalnum() or source[end] in {"_", "$"}):
                    end += 1
                token = source[index:end]
                direct_import_source_pending = bool(
                    module_declaration == "import" and expect_module_source
                )
                if direct_import_source_pending:
                    expect_module_source = False
                if token == "assert" and assertion_eligible:
                    lookahead = end
                    while lookahead < len(source) and source[lookahead].isspace():
                        lookahead += 1
                    if lookahead < len(source) and source[lookahead] == "{":
                        chars[index:end] = list("with  ")
                    assertion_eligible = False
                elif assertion_eligible:
                    assertion_eligible = False
                    module_declaration = ""
                    module_clause_brace_depth = 0

                if token == "import":
                    module_declaration = "import"
                    module_clause_brace_depth = 0
                    expect_module_source = True
                elif token == "export":
                    module_declaration = "export"
                    module_clause_brace_depth = 0
                    expect_module_source = False
                elif (
                    token == "from"
                    and module_declaration
                    and module_clause_brace_depth == 0
                    and not direct_import_source_pending
                ):
                    expect_module_source = True
                lexical_goal.observe_code_char(source, index)
                index = end
                continue
            if assertion_eligible:
                assertion_eligible = False
                module_declaration = ""
                module_clause_brace_depth = 0
            if module_declaration == "import" and expect_module_source:
                expect_module_source = False
            if module_declaration == "import" and char in {"(", "."}:
                module_declaration = ""
                module_clause_brace_depth = 0
                expect_module_source = False
            if module_declaration:
                if char == "{":
                    module_clause_brace_depth += 1
                elif char == "}" and module_clause_brace_depth:
                    module_clause_brace_depth -= 1
            lexical_goal.observe_code_char(source, index)
            index += 1
            continue
        if state == "string":
            if char == "\\" and index + 1 < len(source):
                index += 2
                continue
            if char == quote:
                state = "code"
                if string_is_module_source:
                    assertion_eligible = True
                    expect_module_source = False
                string_is_module_source = False
                lexical_goal.note_operand()
            index += 1
            continue
        if state == "line_comment":
            if is_line_terminator(char):
                state = "code"
                if assertion_eligible:
                    assertion_eligible = False
                    module_declaration = ""
                    module_clause_brace_depth = 0
            index += 1
            continue
        if state == "template":
            if char == "\\" and index + 1 < len(source):
                index += 2
                continue
            if char == "$" and next_char == "{":
                interpolation_depths.append(0)
                state = "code"
                lexical_goal.enter_template_expression()
                index += 2
                continue
            if char == "`":
                state = "code"
                lexical_goal.note_operand()
            index += 1
            continue
        if state == "regex":
            if is_line_terminator(char):
                state = "code"
                lexical_goal.note_operand()
                index += 1
                continue
            if (
                char == "\\"
                and index + 1 < len(source)
                and not is_line_terminator(source[index + 1])
            ):
                index += 2
                continue
            if char == "[":
                regex_in_character_class = True
            elif char == "]":
                regex_in_character_class = False
            elif char == "/" and not regex_in_character_class:
                state = "code"
                lexical_goal.note_operand()
                index += 1
                while index < len(source) and source[index] in "dgimsuvy":
                    index += 1
                continue
            index += 1
            continue
        if is_line_terminator(char):
            block_comment_has_line_terminator = True
        if char == "*" and next_char == "/":
            state = "code"
            if assertion_eligible and block_comment_has_line_terminator:
                assertion_eligible = False
                module_declaration = ""
                module_clause_brace_depth = 0
            index += 2
        else:
            index += 1
    return "".join(chars)


def _scan_syntax(root: Any, source: str) -> _SyntaxScan:
    scanned_nodes = int(root.descendant_count)
    if not root.has_error:
        if scanned_nodes > MAX_CST_SCAN_NODES:
            return _SyntaxScan(
                errors=(),
                error_count=0,
                missing_count=0,
                scanned_nodes=MAX_CST_SCAN_NODES,
                truncated=True,
            )
        return _SyntaxScan(
            errors=(),
            error_count=0,
            missing_count=0,
            scanned_nodes=scanned_nodes,
            truncated=False,
        )

    source_bytes = source.encode("utf-8")
    line_start_bytes = array("I", [0])
    for match in re.finditer(rb"\r\n|\r|\n|\xe2\x80\xa8|\xe2\x80\xa9", source_bytes):
        line_start_bytes.append(match.end())

    def diagnostic_position(byte_offset: int) -> tuple[int, int]:
        row = max(0, bisect.bisect_right(line_start_bytes, byte_offset) - 1)
        line_start = line_start_bytes[row]
        return row + 1, len(source_bytes[line_start:byte_offset].decode("utf-8", "replace"))

    errors: list[str] = []
    error_count = 0
    missing_count = 0
    scanned = 0
    stack = [root]
    while stack:
        node = stack.pop()
        scanned += 1
        if scanned > MAX_CST_SCAN_NODES:
            return _SyntaxScan(
                errors=tuple(errors),
                error_count=error_count,
                missing_count=missing_count,
                scanned_nodes=MAX_CST_SCAN_NODES,
                truncated=True,
            )
        if node.is_error:
            error_count += 1
            if len(errors) < MAX_DIAGNOSTICS:
                line, column = diagnostic_position(node.start_byte)
                errors.append(
                    f"Tree-sitter ERROR at {line}:{column} near "
                    f"{source_bytes[node.start_byte:node.end_byte][:80]!r}"
                )
        if node.is_missing:
            missing_count += 1
            if len(errors) < MAX_DIAGNOSTICS:
                line, column = diagnostic_position(node.start_byte)
                errors.append(f"Tree-sitter missing {node.type!r} at {line}:{column}")
        stack.extend(reversed(node.children))
    return _SyntaxScan(
        errors=tuple(errors),
        error_count=error_count,
        missing_count=missing_count,
        scanned_nodes=scanned,
        truncated=False,
    )


def parse_tree_sitter(
    source: str,
    *,
    language_hint: LanguageHint | None = None,
) -> TreeSitterParseResult | None:
    """Parse source with the official grammars and project the CST into the ESTree contract."""

    if language_hint is not None and language_hint not in SUPPORTED_LANGUAGE_HINTS:
        raise ValueError(f"Unsupported JavaScript language hint: {language_hint!r}")
    if not tree_sitter_available():
        return None

    source_bytes = _normalize_import_assertions(source).encode("utf-8")
    candidates: list[_Candidate] = []
    attempt_errors: list[str] = []
    for priority, hint in enumerate(_candidate_hints(language_hint)):
        try:
            parser = _tree_sitter.Parser(_get_language(_grammar_for_hint(hint)))
            tree = parser.parse(source_bytes)
            scan = _scan_syntax(tree.root_node, source)
            candidates.append(_Candidate(hint, tree.root_node, scan, priority))
            if language_hint is None and hint == "javascript" and not (
                scan.error_count or scan.missing_count or scan.truncated
            ):
                break
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            attempt_errors.append(f"Tree-sitter {hint} parse failed: {type(exc).__name__}: {exc}")

    if not candidates:
        return TreeSitterParseResult(
            success=False,
            ast=None,
            errors=tuple(attempt_errors or ["Tree-sitter did not produce a syntax tree"]),
            partial=False,
            parser_used="tree-sitter",
            capability_gaps=("tree_sitter_parse_failed",),
        )

    candidate = min(candidates, key=lambda item: item.score)
    converter = _ESTreeConverter(source)
    try:
        ast = converter.convert_root(candidate.root)
    except (MemoryError, RecursionError) as exc:
        return TreeSitterParseResult(
            success=False,
            ast=None,
            errors=(f"Tree-sitter ESTree conversion failed: {type(exc).__name__}",),
            partial=False,
            parser_used=f"tree-sitter-{candidate.language}",
            capability_gaps=("tree_sitter_conversion_failed",),
        )

    syntax_partial = bool(
        candidate.scan.error_count or candidate.scan.missing_count or candidate.scan.truncated
    )
    partial = syntax_partial or converter.partial
    capability_gaps: list[str] = []
    if candidate.scan.error_count:
        capability_gaps.append("syntax_error_nodes")
    if candidate.scan.missing_count:
        capability_gaps.append("syntax_missing_nodes")
    if converter.unsupported_types:
        capability_gaps.append("unsupported_runtime_cst_nodes")
    if candidate.scan.truncated:
        capability_gaps.append("cst_scan_truncated")
    capability_gaps.extend(converter.capability_gaps)

    truncation_reasons = list(converter.truncation_reasons)
    if candidate.scan.truncated:
        truncation_reasons.insert(
            0,
            f"Tree-sitter CST scan node cap ({MAX_CST_SCAN_NODES}) reached",
        )

    errors = list(candidate.scan.errors)
    errors.extend(converter.errors)
    errors.extend(attempt_errors)
    if len(errors) > MAX_DIAGNOSTICS:
        errors = errors[:MAX_DIAGNOSTICS]
        errors.append("Tree-sitter diagnostics truncated")

    if partial:
        ast["partial"] = True
    ast["parser_capability"] = "tree_sitter_structural"
    ast["source_language"] = candidate.language
    ast["parse_completeness"] = {
        "status": "partial" if partial else "complete",
        "error_nodes": candidate.scan.error_count,
        "missing_nodes": candidate.scan.missing_count,
        "unsupported_runtime_nodes": sorted(converter.unsupported_types),
        "capability_gaps": list(dict.fromkeys(capability_gaps)),
        "truncation_reasons": truncation_reasons,
        "converted_nodes": converter.converted_nodes,
        "scanned_nodes": candidate.scan.scanned_nodes,
    }

    return TreeSitterParseResult(
        success=True,
        ast=ast,
        errors=tuple(errors),
        partial=partial,
        parser_used=f"tree-sitter-{candidate.language}",
        capability_gaps=tuple(dict.fromkeys(capability_gaps)),
        truncation_reasons=tuple(truncation_reasons),
    )


_TYPE_ONLY_ROOTS = {
    "abstract_method_signature",
    "ambient_declaration",
    "call_signature",
    "construct_signature",
    "constructor_signature",
    "function_signature",
    "index_signature",
    "interface_declaration",
    "method_signature",
    "property_signature",
    "type_alias_declaration",
}

_TYPE_ONLY_EXACT = {
    "accessibility_modifier",
    "asserts_annotation",
    "constraint",
    "default_type",
    "extends_clause",
    "implements_clause",
    "infer_type",
    "interface_body",
    "keyof_type",
    "lookup_type",
    "mapped_type_clause",
    "nested_type_identifier",
    "object_type",
    "omitting_type_annotation",
    "optional_type",
    "override_modifier",
    "predefined_type",
    "readonly_type",
    "required_parameter",
    "rest_type",
    "template_literal_type",
    "this_type",
    "tuple_type",
    "type_annotation",
    "type_arguments",
    "type_parameter",
    "type_parameters",
    "type_predicate",
    "type_predicate_annotation",
    "union_type",
    "intersection_type",
}

_DANGEROUS_JSX_ATTRIBUTES = {
    "action",
    "background",
    "data",
    "formaction",
    "href",
    "onerror",
    "onload",
    "onclick",
    "poster",
    "src",
    "srcdoc",
    "xlink:href",
}


class _ESTreeConverter:
    """Convert detection-relevant Tree-sitter CST nodes into the existing ESTree shape."""

    def __init__(self, source: str):
        self.source = source
        self.source_bytes = source.encode("utf-8")
        self._char_byte_offsets: array[int] | None = None
        if len(self.source_bytes) != len(source):
            self._char_byte_offsets = array("I", [0])
            byte_offset = 0
            for char in source:
                byte_offset += len(char.encode("utf-8"))
                self._char_byte_offsets.append(byte_offset)
        self._line_start_bytes = array("I", [0])
        for match in re.finditer(rb"\r\n|\r|\n|\xe2\x80\xa8|\xe2\x80\xa9", self.source_bytes):
            self._line_start_bytes.append(match.end())
        self.converted_nodes = 0
        self.partial = False
        self.unsupported_types: set[str] = set()
        self.capability_gaps: list[str] = []
        self.truncation_reasons: list[str] = []
        self.errors: list[str] = []

    def _char_offset(self, byte_offset: int) -> int:
        if self._char_byte_offsets is None:
            return byte_offset
        return bisect.bisect_left(self._char_byte_offsets, byte_offset)

    def _position(self, node: Any, which: Literal["start", "end"]) -> dict[str, int]:
        byte_offset = node.start_byte if which == "start" else node.end_byte
        return self._position_at_byte(byte_offset)

    def _position_at_byte(self, byte_offset: int) -> dict[str, int]:
        char_offset = self._char_offset(byte_offset)
        row = max(0, bisect.bisect_right(self._line_start_bytes, byte_offset) - 1)
        line_start_byte = self._line_start_bytes[row]
        return {
            "line": row + 1,
            "column": char_offset - self._char_offset(line_start_byte),
        }

    def _base(self, node: Any, node_type: str, **fields: Any) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": node_type,
            "range": [self._char_offset(node.start_byte), self._char_offset(node.end_byte)],
            "loc": {
                "start": self._position(node, "start"),
                "end": self._position(node, "end"),
            },
        }
        result.update(fields)
        return result

    def _base_span(
        self,
        start_byte: int,
        end_byte: int,
        node_type: str,
        **fields: Any,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": node_type,
            "range": [self._char_offset(start_byte), self._char_offset(end_byte)],
            "loc": {
                "start": self._position_at_byte(start_byte),
                "end": self._position_at_byte(end_byte),
            },
        }
        result.update(fields)
        return result

    def _text(self, node: Any) -> str:
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8", "replace")

    @staticmethod
    def _named(node: Any) -> list[Any]:
        return [
            child for child in node.named_children
            if child.type not in {"comment", "html_comment"}
        ]

    @staticmethod
    def _field(node: Any, name: str) -> Any | None:
        return node.child_by_field_name(name)

    def _convert_field(self, node: Any, name: str, depth: int) -> dict[str, Any] | None:
        child = self._field(node, name)
        return self.convert(child, depth + 1) if child is not None else None

    def _token(self, node: Any, choices: set[str], default: str = "") -> str:
        for child in node.children:
            if child.is_named:
                continue
            text = self._text(child).strip()
            if text in choices:
                return text
        return default

    def _mark_partial(self, reason: str, *, capability: str | None = None) -> None:
        self.partial = True
        if reason not in self.errors and len(self.errors) < MAX_DIAGNOSTICS:
            self.errors.append(reason)
        if capability and capability not in self.capability_gaps:
            self.capability_gaps.append(capability)

    def _mark_truncated(self, reason: str) -> None:
        self.partial = True
        if reason not in self.truncation_reasons:
            self.truncation_reasons.append(reason)

    def convert_root(self, root: Any) -> dict[str, Any]:
        converted = self.convert(root, 0)
        if not isinstance(converted, dict) or converted.get("type") != "Program":
            self._mark_partial(
                "Tree-sitter root did not convert to Program",
                capability="invalid_estree_projection",
            )
            return self._base(root, "Program", body=[])
        return converted

    def convert(self, node: Any | None, depth: int = 0) -> dict[str, Any] | None:
        if node is None or node.type in {"comment", "html_comment"}:
            return None
        if depth > MAX_CONVERSION_DEPTH:
            self._mark_truncated(
                f"Tree-sitter conversion depth cap ({MAX_CONVERSION_DEPTH}) reached"
            )
            return self._base(node, "TreeSitterTruncatedNode", originalType=node.type)
        self.converted_nodes += 1
        if self.converted_nodes > MAX_CONVERTED_NODES:
            self._mark_truncated(
                f"Tree-sitter converted-node cap ({MAX_CONVERTED_NODES}) reached"
            )
            return self._base(node, "TreeSitterTruncatedNode", originalType=node.type)

        if node.is_error or node.type == "ERROR":
            self._mark_partial("Tree-sitter recovery ERROR node retained", capability="syntax_error_nodes")
            return self._unknown(node, depth, mark_unsupported=False)
        if node.is_missing:
            self._mark_partial(
                f"Tree-sitter missing node retained: {node.type}",
                capability="syntax_missing_nodes",
            )
            return self._base(node, "TreeSitterMissingNode", expectedType=node.type)

        handler: Any = getattr(self, f"_convert_{node.type}", None)
        if handler is not None:
            return cast(dict[str, Any] | None, handler(node, depth))
        if self._is_type_only(node.type):
            return self._convert_type_only(node, depth)
        return self._unknown(node, depth, mark_unsupported=True)

    @staticmethod
    def _is_type_only(node_type: str) -> bool:
        return (
            node_type in _TYPE_ONLY_ROOTS
            or node_type in _TYPE_ONLY_EXACT
            or node_type.endswith("_type")
            or node_type.startswith("type_")
        )

    def _convert_type_only(self, node: Any, depth: int) -> dict[str, Any]:
        children = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "TSTypeMetadata",
            tsType=node.type,
            raw=self._text(node),
            children=children,
        )

    def _unknown(self, node: Any, depth: int, *, mark_unsupported: bool) -> dict[str, Any]:
        if mark_unsupported:
            self.unsupported_types.add(node.type)
            self._mark_partial(
                f"Unsupported Tree-sitter runtime node retained: {node.type}",
                capability="unsupported_runtime_cst_nodes",
            )
        children = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "TreeSitterUnknownNode",
            originalType=node.type,
            raw=self._text(node),
            children=children,
        )

    # Program and statements

    def _convert_program(self, node: Any, depth: int) -> dict[str, Any]:
        body = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(node, "Program", body=body, sourceType="module")

    def _convert_hash_bang_line(self, node: Any, depth: int) -> None:
        # ESTree parsers expose a hashbang separately from Program.body. Detection consumers do
        # not read that optional field, so omitting it is lossless for the existing IR contract.
        return None

    def _convert_expression_statement(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        expression = self.convert(children[0], depth + 1) if children else None
        return self._base(node, "ExpressionStatement", expression=expression)

    def _convert_empty_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "EmptyStatement")

    def _convert_debugger_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "DebuggerStatement")

    def _convert_statement_block(self, node: Any, depth: int) -> dict[str, Any]:
        body = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(node, "BlockStatement", body=body)

    def _convert_return_statement(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        argument = self.convert(children[0], depth + 1) if children else None
        return self._base(node, "ReturnStatement", argument=argument)

    def _convert_throw_statement(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        argument = self.convert(children[0], depth + 1) if children else None
        return self._base(node, "ThrowStatement", argument=argument)

    def _convert_break_statement(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        label = self.convert(children[0], depth + 1) if children else None
        return self._base(node, "BreakStatement", label=label)

    def _convert_continue_statement(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        label = self.convert(children[0], depth + 1) if children else None
        return self._base(node, "ContinueStatement", label=label)

    def _convert_labeled_statement(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        label = self.convert(children[0], depth + 1) if children else None
        body = self.convert(children[1], depth + 1) if len(children) > 1 else None
        return self._base(node, "LabeledStatement", label=label, body=body)

    def _convert_with_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "WithStatement",
            object=self._convert_field(node, "object", depth),
            body=self._convert_field(node, "body", depth),
        )

    def _convert_if_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "IfStatement",
            test=self._convert_field(node, "condition", depth),
            consequent=self._convert_field(node, "consequence", depth),
            alternate=self._convert_field(node, "alternative", depth),
        )

    def _convert_while_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "WhileStatement",
            test=self._convert_field(node, "condition", depth),
            body=self._convert_field(node, "body", depth),
        )

    def _convert_do_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "DoWhileStatement",
            body=self._convert_field(node, "body", depth),
            test=self._convert_field(node, "condition", depth),
        )

    def _convert_for_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "ForStatement",
            init=self._convert_field(node, "initializer", depth),
            test=self._convert_field(node, "condition", depth),
            update=self._convert_field(node, "increment", depth),
            body=self._convert_field(node, "body", depth),
        )

    def _convert_for_in_statement(self, node: Any, depth: int) -> dict[str, Any]:
        operator = self._token(node, {"in", "of"}, "in")
        left = self._convert_field(node, "left", depth)
        kind = self._token(node, {"const", "let", "var", "using"})
        if kind and left is not None and left.get("type") != "VariableDeclaration":
            left = self._base(node, "VariableDeclaration", declarations=[
                self._base(node, "VariableDeclarator", id=left, init=None)
            ], kind=kind)
        fields: dict[str, Any] = {
            "left": left,
            "right": self._convert_field(node, "right", depth),
            "body": self._convert_field(node, "body", depth),
        }
        if operator == "of":
            fields["await"] = self._token(node, {"await"}) == "await"
        return self._base(
            node,
            "ForOfStatement" if operator == "of" else "ForInStatement",
            **fields,
        )

    def _convert_switch_statement(self, node: Any, depth: int) -> dict[str, Any]:
        body = self._field(node, "body")
        cases = [
            converted
            for child in self._named(body) if body is not None
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "SwitchStatement",
            discriminant=self._convert_field(node, "value", depth),
            cases=cases,
        )

    def _convert_switch_case(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        test_node = self._field(node, "value")
        if test_node is None and self._text(node).lstrip().startswith("case") and children:
            test_node = children[0]
        consequent_nodes = children[1:] if test_node is not None and children else children
        consequent = [
            converted
            for child in consequent_nodes
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "SwitchCase",
            test=self.convert(test_node, depth + 1) if test_node is not None else None,
            consequent=consequent,
        )

    _convert_switch_default = _convert_switch_case

    def _convert_try_statement(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "TryStatement",
            block=self._convert_field(node, "body", depth),
            handler=self._convert_field(node, "handler", depth),
            finalizer=self._convert_field(node, "finalizer", depth),
        )

    def _convert_catch_clause(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "CatchClause",
            param=self._convert_field(node, "parameter", depth),
            body=self._convert_field(node, "body", depth),
        )

    def _convert_finally_clause(self, node: Any, depth: int) -> dict[str, Any] | None:
        children = self._named(node)
        return self.convert(children[0], depth + 1) if children else None

    # Declarations, functions, and classes

    def _convert_lexical_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        return self._convert_variable_declaration(node, depth)

    def _convert_variable_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        declarations = [
            converted
            for child in self._named(node)
            if child.type == "variable_declarator"
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        kind = self._token(node, {"const", "let", "var", "using"}, "var")
        return self._base(node, "VariableDeclaration", declarations=declarations, kind=kind)

    def _convert_variable_declarator(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "VariableDeclarator",
            id=self._convert_field(node, "name", depth),
            init=self._convert_field(node, "value", depth),
        )

    def _parameters(self, node: Any, depth: int) -> list[dict[str, Any]]:
        params_node = self._field(node, "parameters")
        parameter = self._field(node, "parameter")
        if params_node is not None:
            nodes = self._named(params_node)
        elif parameter is not None:
            nodes = [parameter]
        else:
            nodes = []
        return [
            converted
            for child in nodes
            if (converted := self.convert(child, depth + 1)) is not None
        ]

    def _function(self, node: Any, depth: int, node_type: str) -> dict[str, Any]:
        body = self._convert_field(node, "body", depth)
        fields: dict[str, Any] = {
            "id": self._convert_field(node, "name", depth),
            "params": self._parameters(node, depth),
            "body": body,
            "generator": "generator" in node.type or self._token(node, {"*"}) == "*",
            "async": self._token(node, {"async"}) == "async",
            "expression": node_type == "ArrowFunctionExpression" and (
                body is not None and body.get("type") != "BlockStatement"
            ),
        }
        return self._base(
            node,
            node_type,
            **fields,
        )

    def _convert_function_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        return self._function(node, depth, "FunctionDeclaration")

    def _convert_generator_function_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        return self._function(node, depth, "FunctionDeclaration")

    def _convert_function_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._function(node, depth, "FunctionExpression")

    def _convert_generator_function(self, node: Any, depth: int) -> dict[str, Any]:
        return self._function(node, depth, "FunctionExpression")

    def _convert_arrow_function(self, node: Any, depth: int) -> dict[str, Any]:
        return self._function(node, depth, "ArrowFunctionExpression")

    def _convert_class_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        return self._class(node, depth, "ClassDeclaration")

    def _convert_abstract_class_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        result = self._class(node, depth, "ClassDeclaration")
        result["abstract"] = True
        return result

    def _convert_class(self, node: Any, depth: int) -> dict[str, Any]:
        return self._class(node, depth, "ClassExpression")

    def _class(self, node: Any, depth: int, node_type: str) -> dict[str, Any]:
        heritage = next(
            (child for child in self._named(node) if child.type == "class_heritage"),
            None,
        )
        super_class = None
        if heritage is not None:
            extends = next(
                (child for child in self._named(heritage) if child.type == "extends_clause"),
                None,
            )
            if extends is not None:
                value = self._field(extends, "value")
                if value is None:
                    value = next(iter(self._named(extends)), None)
                super_class = self.convert(value, depth + 1)
        decorators = [
            converted
            for child in node.children_by_field_name("decorator")
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            node_type,
            id=self._convert_field(node, "name", depth),
            superClass=super_class,
            body=self._convert_field(node, "body", depth),
            decorators=decorators,
        )

    def _convert_class_body(self, node: Any, depth: int) -> dict[str, Any]:
        body = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(node, "ClassBody", body=body)

    def _convert_method_definition(self, node: Any, depth: int) -> dict[str, Any]:
        name_node = self._field(node, "name")
        key = self.convert(name_node, depth + 1)
        value = self._function(node, depth, "FunctionExpression")
        kind = "constructor" if isinstance(key, dict) and key.get("name") == "constructor" else "method"
        accessor = self._token(node, {"get", "set"})
        if accessor:
            kind = accessor
        decorators = [
            converted
            for child in node.children_by_field_name("decorator")
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        if node.parent is not None and node.parent.type == "object":
            return self._base(
                node,
                "Property",
                key=key,
                value=value,
                kind=kind,
                method=True,
                shorthand=False,
                computed=name_node is not None and name_node.type == "computed_property_name",
                decorators=decorators,
            )
        return self._base(
            node,
            "MethodDefinition",
            key=key,
            value=value,
            kind=kind,
            computed=name_node is not None and name_node.type == "computed_property_name",
            static=self._token(node, {"static"}) == "static",
            decorators=decorators,
        )

    def _convert_field_definition(self, node: Any, depth: int) -> dict[str, Any]:
        return self._field_definition(node, depth)

    def _convert_public_field_definition(self, node: Any, depth: int) -> dict[str, Any]:
        return self._field_definition(node, depth)

    def _field_definition(self, node: Any, depth: int) -> dict[str, Any]:
        name_node = self._field(node, "property") or self._field(node, "name")
        decorators = [
            converted
            for child in node.children_by_field_name("decorator")
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "PropertyDefinition",
            key=self.convert(name_node, depth + 1),
            value=self._convert_field(node, "value", depth),
            computed=name_node is not None and name_node.type == "computed_property_name",
            static=self._token(node, {"static"}) == "static",
            decorators=decorators,
        )

    def _convert_class_static_block(self, node: Any, depth: int) -> dict[str, Any]:
        block = self._convert_field(node, "body", depth)
        return self._base(
            node,
            "StaticBlock",
            body=(block or {}).get("body", []),
        )

    def _convert_decorator(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        expression = self.convert(children[0], depth + 1) if children else None
        return self._base(node, "Decorator", expression=expression)

    # Imports, exports, and TypeScript runtime declarations

    def _convert_import_statement(self, node: Any, depth: int) -> dict[str, Any]:
        source_node = self._field(node, "source")
        source = self.convert(source_node, depth + 1)
        clause = next(
            (child for child in self._named(node) if child.type == "import_clause"),
            None,
        )
        specifiers: list[dict[str, Any]] = []
        if clause is not None:
            for child in self._named(clause):
                if child.type in {"identifier", "type_identifier"}:
                    local = self.convert(child, depth + 1)
                    specifiers.append(self._base(child, "ImportDefaultSpecifier", local=local))
                elif child.type == "namespace_import":
                    identifiers = self._named(child)
                    local = self.convert(identifiers[-1], depth + 1) if identifiers else None
                    specifiers.append(self._base(child, "ImportNamespaceSpecifier", local=local))
                elif child.type == "named_imports":
                    specifiers.extend(
                        converted
                        for spec in self._named(child)
                        if (converted := self.convert(spec, depth + 1)) is not None
                    )
        attributes = self._import_attributes(node, depth)
        return self._base(
            node,
            "ImportDeclaration",
            specifiers=specifiers,
            source=source,
            attributes=attributes,
            assertions=[],
            importKind="type" if self._token(node, {"type"}) == "type" else "value",
        )

    def _convert_import_specifier(self, node: Any, depth: int) -> dict[str, Any]:
        imported_node = self._field(node, "name")
        local_node = self._field(node, "alias") or imported_node
        return self._base(
            node,
            "ImportSpecifier",
            imported=self.convert(imported_node, depth + 1),
            local=self.convert(local_node, depth + 1),
            importKind="type" if self._token(node, {"type"}) == "type" else "value",
        )

    def _import_attributes(self, node: Any, depth: int) -> list[dict[str, Any]]:
        attributes: list[dict[str, Any]] = []
        for attribute in self._named(node):
            if attribute.type != "import_attribute":
                continue
            object_node = next(
                (child for child in self._named(attribute) if child.type == "object"),
                None,
            )
            if object_node is None:
                continue
            for pair in self._named(object_node):
                if pair.type != "pair":
                    continue
                attributes.append(self._base(
                    pair,
                    "ImportAttribute",
                    key=self._convert_field(pair, "key", depth),
                    value=self._convert_field(pair, "value", depth),
                ))
        return attributes

    def _convert_export_statement(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node).lstrip()
        declaration_node = self._field(node, "declaration")
        value_node = self._field(node, "value")
        source = self._convert_field(node, "source", depth)
        decorators = [
            converted
            for child in node.children_by_field_name("decorator")
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        if raw.startswith("export default"):
            declaration = self.convert(declaration_node or value_node, depth + 1)
            if declaration is None:
                candidates = [
                    child for child in self._named(node)
                    if child.type not in {"decorator", "export_clause"}
                ]
                declaration = self.convert(candidates[0], depth + 1) if candidates else None
            if isinstance(declaration, dict) and decorators:
                declaration["decorators"] = [
                    *decorators,
                    *(declaration.get("decorators") or []),
                ]
            return self._base(
                node,
                "ExportDefaultDeclaration",
                declaration=declaration,
                exportKind="type" if self._token(node, {"type"}) == "type" else "value",
            )
        if re.match(r"export\s*\*", raw):
            namespace = next(
                (child for child in self._named(node) if child.type == "namespace_export"),
                None,
            )
            exported = None
            if namespace is not None:
                names = self._named(namespace)
                exported = self.convert(names[-1], depth + 1) if names else None
            return self._base(
                node,
                "ExportAllDeclaration",
                source=source,
                exported=exported,
                exportKind="type" if self._token(node, {"type"}) == "type" else "value",
            )

        declaration = self.convert(declaration_node, depth + 1)
        if isinstance(declaration, dict) and decorators:
            declaration["decorators"] = [
                *decorators,
                *(declaration.get("decorators") or []),
            ]
        clause = next(
            (child for child in self._named(node) if child.type == "export_clause"),
            None,
        )
        specifiers = [] if clause is None else [
            converted
            for child in self._named(clause)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "ExportNamedDeclaration",
            declaration=declaration,
            specifiers=specifiers,
            source=source,
            attributes=self._import_attributes(node, depth),
            exportKind="type" if self._token(node, {"type"}) == "type" else "value",
        )

    def _convert_export_specifier(self, node: Any, depth: int) -> dict[str, Any]:
        local_node = self._field(node, "name")
        exported_node = self._field(node, "alias") or local_node
        return self._base(
            node,
            "ExportSpecifier",
            local=self.convert(local_node, depth + 1),
            exported=self.convert(exported_node, depth + 1),
            exportKind="type" if self._token(node, {"type"}) == "type" else "value",
        )

    def _convert_enum_declaration(self, node: Any, depth: int) -> dict[str, Any]:
        body_node = self._field(node, "body")
        members = [] if body_node is None else [
            converted
            for child in self._named(body_node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(
            node,
            "TSEnumDeclaration",
            id=self._convert_field(node, "name", depth),
            members=members,
        )

    def _convert_enum_assignment(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "TSEnumMember",
            id=self._convert_field(node, "name", depth),
            initializer=self._convert_field(node, "value", depth),
        )

    def _convert_internal_module(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "TSModuleDeclaration",
            id=self._convert_field(node, "name", depth),
            body=self._convert_field(node, "body", depth),
        )

    # Expressions and patterns

    def _convert_identifier(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Identifier", name=self._text(node))

    _convert_property_identifier = _convert_identifier
    _convert_type_identifier = _convert_identifier

    def _convert_private_property_identifier(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "PrivateIdentifier", name=self._text(node).lstrip("#"))

    def _convert_this(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "ThisExpression")

    def _convert_super(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Super")

    def _convert_import(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Import")

    def _convert_undefined(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Identifier", name="undefined")

    def _decode_string(self, raw: str) -> str:
        if len(raw) < 2:
            return raw
        body = raw[1:-1]
        escapes = {
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "v": "\v",
            "0": "\0",
        }
        result: list[str] = []
        index = 0
        while index < len(body):
            char = body[index]
            if char != "\\" or index + 1 >= len(body):
                result.append(char)
                index += 1
                continue
            escaped = body[index + 1]
            if escaped in "\r\n":
                index += 2
                if escaped == "\r" and index < len(body) and body[index] == "\n":
                    index += 1
                continue
            if escaped in "01234567":
                # Annex-B legacy octal escapes remain valid in classic/sloppy scripts. The
                # leading digit determines whether two or three octal digits may be consumed.
                max_digits = 3 if escaped in "0123" else 2
                end = index + 1
                while (
                    end < len(body)
                    and end < index + 1 + max_digits
                    and body[end] in "01234567"
                ):
                    end += 1
                result.append(chr(int(body[index + 1:end], 8)))
                index = end
                continue
            if escaped in escapes:
                result.append(escapes[escaped])
                index += 2
                continue
            if escaped == "x" and re.match(r"[0-9A-Fa-f]{2}", body[index + 2:index + 4]):
                result.append(chr(int(body[index + 2:index + 4], 16)))
                index += 4
                continue
            if escaped == "u":
                braced = re.match(r"\{([0-9A-Fa-f]{1,6})\}", body[index + 2:])
                if braced:
                    codepoint = int(braced.group(1), 16)
                    if codepoint <= 0x10FFFF and not 0xD800 <= codepoint <= 0xDFFF:
                        result.append(chr(codepoint))
                        index += 2 + len(braced.group(0))
                        continue
                digits = body[index + 2:index + 6]
                if re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                    codepoint = int(digits, 16)
                    if 0xD800 <= codepoint <= 0xDBFF:
                        following = body[index + 6:index + 12]
                        if re.fullmatch(r"\\u[0-9A-Fa-f]{4}", following):
                            low = int(following[2:], 16)
                            if 0xDC00 <= low <= 0xDFFF:
                                combined = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                                result.append(chr(combined))
                                index += 12
                                continue
                    if not 0xD800 <= codepoint <= 0xDFFF:
                        result.append(chr(codepoint))
                        index += 6
                        continue
                    result.append(body[index:index + 6])
                    index += 6
                    continue
            result.append(escaped)
            index += 2
        return "".join(result)

    def _convert_string(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        return self._base(node, "Literal", value=self._decode_string(raw), raw=raw)

    def _convert_number(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        normalized = raw.replace("_", "")
        is_bigint = normalized.endswith("n")
        if is_bigint:
            normalized = normalized[:-1]
        try:
            if normalized.lower().startswith(("0x", "0o", "0b")):
                value: int | float = int(normalized, 0)
            elif not is_bigint and re.fullmatch(r"0[0-7]+", normalized):
                value = int(normalized, 8)
            elif any(char in normalized.lower() for char in (".", "e")):
                value = float(normalized)
            else:
                value = int(normalized, 10)
        except ValueError:
            value = 0
            self._mark_partial(
                f"Tree-sitter numeric literal could not be decoded: {raw[:80]!r}",
                capability="literal_decode_error",
            )
        result = self._base(node, "Literal", value=value, raw=raw)
        if is_bigint:
            result["bigint"] = normalized
        return result

    def _convert_true(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Literal", value=True, raw="true")

    def _convert_false(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Literal", value=False, raw="false")

    def _convert_null(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(node, "Literal", value=None, raw="null")

    def _convert_regex(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        slash = raw.rfind("/")
        pattern = raw[1:slash] if slash > 0 else raw
        flags = raw[slash + 1:] if slash > 0 else ""
        return self._base(
            node,
            "Literal",
            value=None,
            raw=raw,
            regex={"pattern": pattern, "flags": flags},
        )

    def _convert_template_string(self, node: Any, depth: int) -> dict[str, Any]:
        quasis: list[dict[str, Any]] = []
        expressions: list[dict[str, Any]] = []
        part_start = node.start_byte + 1
        quasi_start = node.start_byte
        substitutions = [child for child in self._named(node) if child.type == "template_substitution"]
        for substitution in substitutions:
            raw = self.source_bytes[part_start:substitution.start_byte].decode("utf-8", "replace")
            quasi = self._base_span(
                quasi_start,
                min(substitution.end_byte, substitution.start_byte + 2),
                "TemplateElement",
                value={"raw": raw, "cooked": self._decode_string(f"`{raw}`")},
                tail=False,
            )
            quasis.append(quasi)
            children = self._named(substitution)
            if children:
                expression = self.convert(children[0], depth + 1)
                if expression is not None:
                    expressions.append(expression)
            part_start = substitution.end_byte
            quasi_start = max(substitution.start_byte, substitution.end_byte - 1)
        final_raw = self.source_bytes[part_start:max(part_start, node.end_byte - 1)].decode(
            "utf-8", "replace"
        )
        quasis.append(self._base_span(
            quasi_start,
            node.end_byte,
            "TemplateElement",
            value={"raw": final_raw, "cooked": self._decode_string(f"`{final_raw}`")},
            tail=True,
        ))
        return self._base(node, "TemplateLiteral", quasis=quasis, expressions=expressions)

    def _convert_parenthesized_expression(self, node: Any, depth: int) -> dict[str, Any] | None:
        children = self._named(node)
        return self.convert(children[0], depth + 1) if children else None

    def _convert_as_expression(self, node: Any, depth: int) -> dict[str, Any] | None:
        return self._unwrap_runtime_expression(node, depth, "as")

    def _convert_satisfies_expression(self, node: Any, depth: int) -> dict[str, Any] | None:
        return self._unwrap_runtime_expression(node, depth, "satisfies")

    def _convert_non_null_expression(self, node: Any, depth: int) -> dict[str, Any] | None:
        return self._unwrap_runtime_expression(node, depth, "non-null")

    def _convert_type_assertion(self, node: Any, depth: int) -> dict[str, Any] | None:
        return self._unwrap_runtime_expression(node, depth, "assertion")

    def _convert_instantiation_expression(self, node: Any, depth: int) -> dict[str, Any] | None:
        return self._unwrap_runtime_expression(node, depth, "instantiation")

    def _unwrap_runtime_expression(
        self, node: Any, depth: int, syntax: str
    ) -> dict[str, Any] | None:
        for child in self._named(node):
            if self._is_type_only(child.type) or child.type == "type_identifier":
                continue
            converted = self.convert(child, depth + 1)
            if converted is not None:
                converted.setdefault("tsSyntax", []).append(syntax)
                return converted
        self._mark_partial(
            f"Tree-sitter TypeScript {syntax} wrapper had no runtime expression",
            capability="invalid_estree_projection",
        )
        return None

    def _convert_member_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "MemberExpression",
            object=self._convert_field(node, "object", depth),
            property=self._convert_field(node, "property", depth),
            computed=False,
            optional=self._field(node, "optional_chain") is not None,
        )

    def _convert_subscript_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "MemberExpression",
            object=self._convert_field(node, "object", depth),
            property=self._convert_field(node, "index", depth),
            computed=True,
            optional=self._field(node, "optional_chain") is not None,
        )

    def _arguments(self, node: Any, depth: int) -> list[dict[str, Any]]:
        arguments = self._field(node, "arguments")
        if arguments is None:
            return []
        if arguments.type == "template_string":
            converted = self.convert(arguments, depth + 1)
            return [converted] if converted is not None else []
        return [
            converted
            for child in self._named(arguments)
            if not self._is_type_only(child.type)
            if (converted := self.convert(child, depth + 1)) is not None
        ]

    def _convert_call_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "CallExpression",
            callee=self._convert_field(node, "function", depth),
            arguments=self._arguments(node, depth),
            optional=self._field(node, "optional_chain") is not None,
        )

    def _convert_new_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "NewExpression",
            callee=self._convert_field(node, "constructor", depth),
            arguments=self._arguments(node, depth),
        )

    def _convert_await_expression(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        return self._base(
            node,
            "AwaitExpression",
            argument=self.convert(children[0], depth + 1) if children else None,
        )

    def _convert_yield_expression(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        return self._base(
            node,
            "YieldExpression",
            argument=self.convert(children[0], depth + 1) if children else None,
            delegate=self._token(node, {"*"}) == "*",
        )

    def _convert_assignment_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._assignment(node, depth, "=")

    def _convert_augmented_assignment_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._assignment(
            node,
            depth,
            self._token(
                node,
                {"+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "^=", "|=", "&&=", "||=", "??="},
                "=",
            ),
        )

    def _assignment(self, node: Any, depth: int, operator: str) -> dict[str, Any]:
        return self._base(
            node,
            "AssignmentExpression",
            operator=operator,
            left=self._convert_field(node, "left", depth),
            right=self._convert_field(node, "right", depth),
        )

    def _convert_binary_expression(self, node: Any, depth: int) -> dict[str, Any]:
        operator = self._token(
            node,
            {
                "==", "!=", "===", "!==", "<", "<=", ">", ">=", "<<", ">>", ">>>",
                "+", "-", "*", "/", "%", "**", "|", "^", "&", "in", "instanceof",
                "&&", "||", "??",
            },
        )
        node_type = "LogicalExpression" if operator in {"&&", "||", "??"} else "BinaryExpression"
        return self._base(
            node,
            node_type,
            operator=operator,
            left=self._convert_field(node, "left", depth),
            right=self._convert_field(node, "right", depth),
        )

    def _convert_unary_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "UnaryExpression",
            operator=self._token(node, {"!", "~", "+", "-", "typeof", "void", "delete"}),
            prefix=True,
            argument=self._convert_field(node, "argument", depth),
        )

    def _convert_update_expression(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        operator = "++" if "++" in raw else "--"
        children = self._named(node)
        return self._base(
            node,
            "UpdateExpression",
            operator=operator,
            prefix=raw.lstrip().startswith(operator),
            argument=self.convert(children[0], depth + 1) if children else None,
        )

    def _convert_ternary_expression(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "ConditionalExpression",
            test=self._convert_field(node, "condition", depth),
            consequent=self._convert_field(node, "consequence", depth),
            alternate=self._convert_field(node, "alternative", depth),
        )

    def _convert_sequence_expression(self, node: Any, depth: int) -> dict[str, Any]:
        expressions = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(node, "SequenceExpression", expressions=expressions)

    def _convert_object(self, node: Any, depth: int) -> dict[str, Any]:
        properties = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(node, "ObjectExpression", properties=properties)

    def _convert_pair(self, node: Any, depth: int) -> dict[str, Any]:
        key_node = self._field(node, "key")
        return self._base(
            node,
            "Property",
            key=self.convert(key_node, depth + 1),
            value=self._convert_field(node, "value", depth),
            kind="init",
            method=False,
            shorthand=False,
            computed=key_node is not None and key_node.type == "computed_property_name",
        )

    def _convert_pair_pattern(self, node: Any, depth: int) -> dict[str, Any]:
        key_node = self._field(node, "key")
        return self._base(
            node,
            "Property",
            key=self.convert(key_node, depth + 1),
            value=self._convert_field(node, "value", depth),
            kind="init",
            method=False,
            shorthand=False,
            computed=key_node is not None and key_node.type == "computed_property_name",
        )

    def _convert_shorthand_property_identifier(self, node: Any, depth: int) -> dict[str, Any]:
        key = self._convert_identifier(node, depth)
        value = self._convert_identifier(node, depth)
        return self._base(
            node,
            "Property",
            key=key,
            value=value,
            kind="init",
            method=False,
            shorthand=True,
            computed=False,
        )

    def _convert_shorthand_property_identifier_pattern(
        self, node: Any, depth: int
    ) -> dict[str, Any]:
        key = self._convert_identifier(node, depth)
        value = self._convert_identifier(node, depth)
        return self._base(
            node,
            "Property",
            key=key,
            value=value,
            kind="init",
            method=False,
            shorthand=True,
            computed=False,
        )

    def _convert_spread_element(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        return self._base(
            node,
            "SpreadElement",
            argument=self.convert(children[0], depth + 1) if children else None,
        )

    def _array_elements(self, node: Any, depth: int) -> list[dict[str, Any] | None]:
        elements: list[dict[str, Any] | None] = []
        expecting_element = True
        for child in node.children:
            if not child.is_named:
                if self._text(child) == ",":
                    if expecting_element:
                        elements.append(None)
                    expecting_element = True
                continue
            if child.type in {"comment", "html_comment"}:
                continue
            converted = self.convert(child, depth + 1)
            if converted is not None:
                elements.append(converted)
                expecting_element = False
        return elements

    def _convert_array(self, node: Any, depth: int) -> dict[str, Any]:
        elements = self._array_elements(node, depth)
        return self._base(node, "ArrayExpression", elements=elements)

    def _convert_object_pattern(self, node: Any, depth: int) -> dict[str, Any]:
        properties = [
            converted
            for child in self._named(node)
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        return self._base(node, "ObjectPattern", properties=properties)

    def _convert_array_pattern(self, node: Any, depth: int) -> dict[str, Any]:
        elements = self._array_elements(node, depth)
        return self._base(node, "ArrayPattern", elements=elements)

    def _convert_rest_pattern(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        return self._base(
            node,
            "RestElement",
            argument=self.convert(children[0], depth + 1) if children else None,
        )

    _convert_rest_parameter = _convert_rest_pattern

    def _convert_assignment_pattern(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "AssignmentPattern",
            left=self._convert_field(node, "left", depth),
            right=self._convert_field(node, "right", depth),
        )

    def _convert_required_parameter(self, node: Any, depth: int) -> dict[str, Any] | None:
        pattern = self._field(node, "pattern")
        return self.convert(pattern, depth + 1) if pattern is not None else None

    def _convert_optional_parameter(self, node: Any, depth: int) -> dict[str, Any] | None:
        pattern = self._field(node, "pattern")
        converted = self.convert(pattern, depth + 1) if pattern is not None else None
        if converted is not None:
            converted["optional"] = True
        return converted

    def _convert_computed_property_name(self, node: Any, depth: int) -> dict[str, Any] | None:
        children = self._named(node)
        return self.convert(children[0], depth + 1) if children else None

    def _convert_new_target(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "MetaProperty",
            meta=self._base(node, "Identifier", name="new"),
            property=self._base(node, "Identifier", name="target"),
        )

    def _convert_meta_property(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        meta, _, prop = raw.partition(".")
        return self._base(
            node,
            "MetaProperty",
            meta=self._base(node, "Identifier", name=meta),
            property=self._base(node, "Identifier", name=prop),
        )

    def _convert_tagged_template(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "TaggedTemplateExpression",
            tag=self._convert_field(node, "tag", depth),
            quasi=self._convert_field(node, "template", depth),
        )

    # JSX/TSX

    def _jsx_name(self, node: Any | None, depth: int) -> dict[str, Any] | None:
        if node is None:
            return None
        if node.type in {"identifier", "property_identifier", "type_identifier"}:
            return self._base(node, "JSXIdentifier", name=self._text(node))
        if node.type == "member_expression":
            return self._base(
                node,
                "JSXMemberExpression",
                object=self._jsx_name(self._field(node, "object"), depth + 1),
                property=self._jsx_name(self._field(node, "property"), depth + 1),
            )
        if node.type == "jsx_namespace_name":
            children = self._named(node)
            return self._base(
                node,
                "JSXNamespacedName",
                namespace=self._jsx_name(children[0], depth + 1) if children else None,
                name=self._jsx_name(children[1], depth + 1) if len(children) > 1 else None,
            )
        converted = self.convert(node, depth + 1)
        if converted is not None:
            converted["type"] = "JSXIdentifier"
        return converted

    def _jsx_attributes(self, node: Any, depth: int) -> list[dict[str, Any]]:
        attributes: list[dict[str, Any]] = []
        for child in self._named(node):
            if child.type == "jsx_attribute":
                converted = self.convert(child, depth + 1)
                if converted is not None:
                    attributes.append(converted)
            elif child.type == "jsx_expression":
                named = self._named(child)
                if named and named[0].type == "spread_element":
                    spread_children = self._named(named[0])
                    argument = self.convert(spread_children[0], depth + 2) if spread_children else None
                    attributes.append(self._base(child, "JSXSpreadAttribute", argument=argument))
        return attributes

    def _convert_jsx_attribute(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        name_node = children[0] if children else None
        value_node = children[1] if len(children) > 1 else None
        return self._base(
            node,
            "JSXAttribute",
            name=self._jsx_name(name_node, depth + 1),
            value=self.convert(value_node, depth + 1) if value_node is not None else None,
        )

    def _convert_jsx_expression(self, node: Any, depth: int) -> dict[str, Any]:
        children = self._named(node)
        expression = self.convert(children[0], depth + 1) if children else self._base(
            node, "JSXEmptyExpression"
        )
        return self._base(node, "JSXExpressionContainer", expression=expression)

    def _convert_jsx_text(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        return self._base(node, "JSXText", value=raw, raw=raw)

    def _convert_html_character_reference(self, node: Any, depth: int) -> dict[str, Any]:
        raw = self._text(node)
        return self._base(node, "JSXText", value=raw, raw=raw)

    def _convert_jsx_opening_element(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "JSXOpeningElement",
            name=self._jsx_name(self._field(node, "name"), depth + 1),
            attributes=self._jsx_attributes(node, depth),
            selfClosing=False,
        )

    def _convert_jsx_closing_element(self, node: Any, depth: int) -> dict[str, Any]:
        return self._base(
            node,
            "JSXClosingElement",
            name=self._jsx_name(self._field(node, "name"), depth + 1),
        )

    def _convert_jsx_self_closing_element(self, node: Any, depth: int) -> dict[str, Any]:
        opening = self._base(
            node,
            "JSXOpeningElement",
            name=self._jsx_name(self._field(node, "name"), depth + 1),
            attributes=self._jsx_attributes(node, depth),
            selfClosing=True,
        )
        return self._base(
            node,
            "JSXElement",
            openingElement=opening,
            closingElement=None,
            children=[],
            securityProjections=self._jsx_security_projections(opening, node),
        )

    def _convert_jsx_element(self, node: Any, depth: int) -> dict[str, Any]:
        open_node = self._field(node, "open_tag")
        close_node = self._field(node, "close_tag")
        children_nodes = [
            child for child in self._named(node)
            if child is not open_node and child is not close_node
        ]
        children = [
            converted
            for child in children_nodes
            if (converted := self.convert(child, depth + 1)) is not None
        ]
        if open_node is not None and self._text(open_node).strip() == "<>":
            return self._base(
                node,
                "JSXFragment",
                openingFragment=self._base(open_node, "JSXOpeningFragment"),
                closingFragment=self._base(close_node or node, "JSXClosingFragment"),
                children=children,
            )
        opening = self.convert(open_node, depth + 1)
        closing = self.convert(close_node, depth + 1)
        return self._base(
            node,
            "JSXElement",
            openingElement=opening,
            closingElement=closing,
            children=children,
            securityProjections=self._jsx_security_projections(opening, node),
        )

    def _jsx_security_projections(
        self,
        opening: dict[str, Any] | None,
        owner_node: Any,
    ) -> list[dict[str, Any]]:
        if not isinstance(opening, dict):
            return []
        if not self._is_intrinsic_jsx_name(opening.get("name")):
            return []
        projections: list[dict[str, Any]] = []
        for attribute in opening.get("attributes", []):
            if not isinstance(attribute, dict) or attribute.get("type") != "JSXAttribute":
                continue
            name_node = attribute.get("name") or {}
            name = name_node.get("name", "") if isinstance(name_node, dict) else ""
            value = attribute.get("value")
            expression = value.get("expression") if isinstance(value, dict) and value.get(
                "type"
            ) == "JSXExpressionContainer" else value
            if name == "dangerouslySetInnerHTML" and isinstance(expression, dict):
                html_value: Any = expression
                if expression.get("type") == "ObjectExpression":
                    html_value = None
                    for prop in expression.get("properties", []):
                        if not isinstance(prop, dict):
                            continue
                        key = prop.get("key") or {}
                        if key.get("name") == "__html" or key.get("value") == "__html":
                            html_value = prop.get("value")
                            break
                if isinstance(html_value, dict):
                    projections.append(self._synthetic_assignment(
                        owner_node, "innerHTML", html_value
                    ))
                continue
            if name.lower() not in _DANGEROUS_JSX_ATTRIBUTES or not isinstance(expression, dict):
                continue
            if expression.get("type") == "Literal":
                continue
            projections.append(self._synthetic_set_attribute(owner_node, name, expression))
        return projections

    @staticmethod
    def _is_intrinsic_jsx_name(name_node: Any) -> bool:
        if not isinstance(name_node, dict) or name_node.get("type") != "JSXIdentifier":
            return False
        name = str(name_node.get("name") or "")
        return bool(name) and (name[0].islower() or "-" in name)

    def _synthetic_identifier(self, node: Any, name: str) -> dict[str, Any]:
        result = self._base(node, "Identifier", name=name)
        result["synthetic"] = True
        return result

    def _synthetic_assignment(
        self, node: Any, property_name: str, value: dict[str, Any]
    ) -> dict[str, Any]:
        member = self._base(
            node,
            "MemberExpression",
            object=self._synthetic_identifier(node, "__bundleinspector_jsx_element__"),
            property=self._synthetic_identifier(node, property_name),
            computed=False,
            optional=False,
            synthetic=True,
        )
        return self._base(
            node,
            "AssignmentExpression",
            operator="=",
            left=member,
            right=value,
            synthetic=True,
            projectionKind="jsx_security_semantics",
        )

    def _synthetic_set_attribute(
        self, node: Any, attribute_name: str, value: dict[str, Any]
    ) -> dict[str, Any]:
        member = self._base(
            node,
            "MemberExpression",
            object=self._synthetic_identifier(node, "__bundleinspector_jsx_element__"),
            property=self._synthetic_identifier(node, "setAttribute"),
            computed=False,
            optional=False,
            synthetic=True,
        )
        literal = self._base(node, "Literal", value=attribute_name, raw=repr(attribute_name))
        return self._base(
            node,
            "CallExpression",
            callee=member,
            arguments=[literal, value],
            optional=False,
            synthetic=True,
            projectionKind="jsx_security_semantics",
        )
