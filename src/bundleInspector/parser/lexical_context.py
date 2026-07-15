"""Small shared lexical-goal tracker for parser fallback and source masking."""

from __future__ import annotations

from dataclasses import dataclass, field

LINE_TERMINATORS = frozenset({"\r", "\n", "\u2028", "\u2029"})

_CONTROL_HEADERS = frozenset({"if", "while", "for", "with", "switch", "catch"})
_STATEMENT_BLOCK_PREFIXES = frozenset({
    "",
    ";",
    "{",
    "control_close",
    "do",
    "else",
    "finally",
    "function_decl_close",
    "statement_close",
    "try",
})
_REGEX_PREFIX_WORDS = frozenset({
    "await",
    "case",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "new",
    "return",
    "throw",
    "typeof",
    "void",
    "yield",
})
_REGEX_PREFIX_TOKENS = frozenset({
    "",
    "(",
    "[",
    "{",
    ",",
    ";",
    ":",
    "=",
    "?",
    "!",
    "&",
    "|",
    "^",
    "~",
    "+",
    "-",
    "*",
    "/",
    "%",
    "<",
    ">",
    "control_close",
    "statement_close",
    "expression_start",
    *_REGEX_PREFIX_WORDS,
})
_SIGNIFICANT_WORDS = (
    _CONTROL_HEADERS
    | _STATEMENT_BLOCK_PREFIXES
    | _REGEX_PREFIX_WORDS
    | {"async", "class", "default", "export", "function"}
)
_DECLARATION_PREFIXES = frozenset({"", ";", "{", "default", "export", "statement_close"})


def is_line_terminator(char: str) -> bool:
    """Return whether one code point terminates ECMAScript line comments/regex literals."""
    return char in LINE_TERMINATORS


def line_comment_end(source: str, start: int) -> int:
    """Return the first ECMAScript line-terminator offset, or ``len(source)``."""
    cursor = start
    while cursor < len(source) and not is_line_terminator(source[cursor]):
        cursor += 1
    return cursor


@dataclass
class LexicalGoal:
    """Track enough forward token context to distinguish regex literals from division.

    Callers remain responsible for skipping strings, templates, comments and regex bodies. They feed
    only executable code characters through :meth:`observe_code_char` and mark skipped literals as
    operands. The tracker is linear: every call performs O(1) work except the first character of an
    identifier, whose forward scan is skipped by subsequent calls through ``_identifier_end``.
    """

    last_token: str = ""
    _paren_kinds: list[str] = field(default_factory=list)
    _brace_kinds: list[str] = field(default_factory=list)
    _identifier_end: int = 0
    _async_context: str | None = None
    _pending_classes: list[tuple[str, int]] = field(default_factory=list)

    def can_start_regex(self, source: str, index: int) -> bool:
        """Return whether `/` at ``index`` begins a regex in the current lexical goal."""
        if (
            index > 0
            and source[index - 1] == "<"
            and index + 1 < len(source)
            and (source[index + 1].isalpha() or source[index + 1] in "_$>")
        ):
            return False
        return self.last_token in _REGEX_PREFIX_TOKENS

    def note_operand(self) -> None:
        """Record a skipped literal/template/regex as one completed expression operand."""
        self.last_token = "operand"

    def enter_template_expression(self) -> None:
        """Enter `${...}` code without adding its delimiter to ordinary brace balance."""
        self.last_token = "expression_start"

    def observe_code_char(self, source: str, index: int) -> None:
        """Consume one ordinary executable-code character at ``index``."""
        char = source[index]
        if char.isspace():
            return

        is_identifier_char = char.isalnum() or char in "_$"
        if is_identifier_char:
            if index < self._identifier_end:
                return
            if char.isdigit():
                self.last_token = "operand"
                return
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in "_$"):
                end += 1
            token = source[index:end]
            self._identifier_end = end
            if token == "async":
                self._async_context = self.last_token
                self.last_token = "async"
                return
            if token == "function":
                context = self._async_context if self.last_token == "async" else self.last_token
                kind = "function_decl" if context in _DECLARATION_PREFIXES else "function_expr"
                self.last_token = kind
                self._async_context = None
                return
            self._async_context = None
            if token == "class":
                kind = "statement" if self.last_token in _DECLARATION_PREFIXES else "expression"
                self._pending_classes.append((kind, len(self._paren_kinds)))
                self.last_token = "class"
                return
            if self.last_token in {"function_decl", "function_expr"}:
                return
            if self.last_token == ".":
                self.last_token = "operand"
            else:
                self.last_token = token if token in _SIGNIFICANT_WORDS else "operand"
            return

        if char == "(":
            if self.last_token in {"function_decl", "function_expr"}:
                kind = self.last_token
            else:
                kind = "control" if self.last_token in _CONTROL_HEADERS else "ordinary"
            self._paren_kinds.append(kind)
            self.last_token = "("
            return
        if char == ")":
            kind = self._paren_kinds.pop() if self._paren_kinds else "ordinary"
            if kind == "control":
                self.last_token = "control_close"
            elif kind == "function_decl":
                self.last_token = "function_decl_close"
            elif kind == "function_expr":
                self.last_token = "function_expr_close"
            else:
                self.last_token = "operand"
            return
        if char == "{":
            if self._pending_classes and self._pending_classes[-1][1] == len(self._paren_kinds):
                kind, _ = self._pending_classes.pop()
            else:
                kind = "statement" if self.last_token in _STATEMENT_BLOCK_PREFIXES else "expression"
            self._brace_kinds.append(kind)
            self.last_token = "{"
            return
        if char == "}":
            kind = self._brace_kinds.pop() if self._brace_kinds else "expression"
            self.last_token = "statement_close" if kind == "statement" else "operand"
            return
        if char in "]":
            self.last_token = "operand"
            return
        if char in "+-" and index > 0 and source[index - 1] == char:
            self.last_token = "operand"
            return
        if char == ".":
            self.last_token = "."
            return
        if char == "*" and self.last_token in {"function_decl", "function_expr"}:
            return
        if char in "[,:;=?!&|^~+-*/%<>":
            self.last_token = char
            return
        self.last_token = "operand"
