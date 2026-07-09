"""
DOM-XSS / code-injection sink detector.

Flags dangerous JavaScript sinks -- HTML-injection (innerHTML, document.write, jQuery
.html()/.append(), insertAdjacentHTML), attribute-injection (setAttribute src/href/on*),
and code-execution (eval, new Function, string setTimeout/setInterval) -- when the injected
argument is DYNAMIC (a variable / concatenation / template-with-expression rather than a
static string literal). A dynamic argument reaching one of these sinks is the client-side
half of a DOM-based or stored XSS / code-injection vulnerability.

This is a client-side INDICATOR: it does not prove the source is attacker-controlled (that
needs taint tracking / DAST), but it precisely points a reviewer at every injectable sink.
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

# AST node types that represent a runtime (non-static) value.
_DYNAMIC_NODE_TYPES = frozenset({
    "Identifier", "MemberExpression", "CallExpression", "BinaryExpression",
    "ConditionalExpression", "LogicalExpression", "NewExpression", "AwaitExpression",
    "TaggedTemplateExpression", "SequenceExpression", "ChainExpression",
})

# Attribute names that execute or navigate when their value is attacker-controlled.
_DANGEROUS_ATTRS = frozenset({
    "src", "href", "xlink:href", "onerror", "onload", "onclick", "formaction",
    "action", "data", "srcdoc", "background", "poster", "codebase",
})


def _is_dynamic(node: Any) -> bool:
    """True if an argument/RHS node is a runtime value, not a static literal."""
    if not isinstance(node, dict):
        return False
    node_type = node.get("type")
    if node_type == "Literal":
        return False
    if node_type == "TemplateLiteral":
        # `foo` is static; `foo${x}` is dynamic.
        return bool(node.get("expressions"))
    return node_type in _DYNAMIC_NODE_TYPES


def _literal_str(node: Any) -> str:
    """Return a string-literal value, else ''."""
    if isinstance(node, dict) and node.get("type") == "Literal":
        value = node.get("value")
        if isinstance(value, str):
            return value
    return ""


def _expr_source(node: Any, _depth: int = 0) -> str:
    """Best-effort source text of a (member/identifier/call) expression, e.g. `item.image_url`,
    `e.target.result`, `data.filePath` -- shown so a reviewer sees WHAT flows into the sink."""
    if not isinstance(node, dict) or _depth > 8:
        return "<expr>"
    t = node.get("type")
    if t == "Identifier":
        return node.get("name") or "<id>"
    if t == "ThisExpression":
        return "this"
    if t == "Literal":
        return repr(node.get("value"))
    if t == "MemberExpression":
        obj = _expr_source(node.get("object"), _depth + 1)
        prop = node.get("property", {})
        key = prop.get("name") or (prop.get("value") if isinstance(prop.get("value"), str) else None)
        return f"{obj}.{key}" if key else f"{obj}[…]"
    if t == "CallExpression":
        return f"{_expr_source(node.get('callee'), _depth + 1)}(…)"
    return "<expr>"


_SENTINEL = "\x00"
# A sentinel (interpolated expression) sitting as the VALUE of a dangerous HTML attribute:
#   <img src="${x}">  ->  ... src="␀ ;  <a href='${u}'  ;  onerror="${x}"
_DANGER_ATTR_RE = re.compile(
    r"""(?ix)
    (?P<attr>on\w+|src|href|xlink:href|srcdoc|formaction|action|poster|background)
    \s*=\s*["']?[^"'<>\x00]*\x00
    """,
)
# Event handlers / srcdoc / style / formaction execute directly -> higher severity than a
# src/href value-injection (which needs an attribute break-out first).
_EXEC_ATTRS = ("on", "srcdoc", "style", "formaction")


def _flatten_concat(node: Any, out: list) -> None:
    """Flatten a string `+` concatenation into ordered operands (left-to-right)."""
    if isinstance(node, dict) and node.get("type") == "BinaryExpression" and node.get("operator") == "+":
        _flatten_concat(node.get("left"), out)
        _flatten_concat(node.get("right"), out)
    else:
        out.append(node)


class DomSinkDetector(BaseRule):
    """Detect DOM-XSS and code-injection sinks fed a dynamic argument."""

    id = "sink-detector"
    name = "DOM-XSS / Code-Injection Sink Detector"
    description = "Detects HTML-injection, attribute-injection and code-execution sinks"
    category = Category.SINK
    severity = Severity.MEDIUM

    # jQuery / DOM HTML-injection methods (method name -> arg index carrying the HTML).
    _HTML_CALL_SINKS = {
        "html": 0, "append": 0, "prepend": 0, "after": 0, "before": 0,
        "replaceWith": 0, "wrap": 0, "appendTo": 0, "prependTo": 0,
    }
    # code-execution call sinks.
    _EVAL_NAMES = {"eval"}
    _TIMER_NAMES = {"setTimeout", "setInterval", "setImmediate", "execScript"}

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        yield from self._match_calls(ir)
        yield from self._match_ast(ir.raw_ast or {})

    # ---------------------------------------------------------------- call-based sinks

    def _match_calls(self, ir: IntermediateRepresentation) -> Iterator[RuleResult]:
        for call in ir.function_calls:
            name = call.name
            full = call.full_name or name
            args = call.arguments or []

            # document.write / document.writeln -> HTML injection
            if name in ("write", "writeln") and full.lower().startswith("document."):
                if args and _is_dynamic(args[0]):
                    yield self._result(f"document.{name}()", "dom_html_sink", Severity.HIGH,
                                       Confidence.MEDIUM, call.line, call.column,
                                       f"document.{name}() with a dynamic argument (HTML injection / DOM-XSS sink)")
                continue

            # insertAdjacentHTML(position, html) -> arg 1 is the HTML
            if name == "insertAdjacentHTML":
                if len(args) >= 2 and _is_dynamic(args[1]):
                    yield self._result("insertAdjacentHTML()", "dom_html_sink", Severity.HIGH,
                                       Confidence.MEDIUM, call.line, call.column,
                                       "insertAdjacentHTML() with a dynamic argument (HTML injection / DOM-XSS sink)")
                continue

            # jQuery / DOM HTML-injection methods
            if name in self._HTML_CALL_SINKS:
                idx = self._HTML_CALL_SINKS[name]
                if len(args) > idx and _is_dynamic(args[idx]):
                    # .html()/.replaceWith() overwrite content (clearer HTML sink); the insertion
                    # methods (.append/.prepend/...) are lower-severity + lower-confidence (the
                    # argument is more often a built node than raw HTML).
                    strong = name in ("html", "replaceWith")
                    sev = Severity.MEDIUM if strong else Severity.LOW
                    conf = Confidence.MEDIUM if strong else Confidence.LOW
                    yield self._result(f".{name}()", "dom_html_sink", sev, conf,
                                       call.line, call.column,
                                       f"jQuery/DOM .{name}() with a dynamic argument (possible HTML injection / DOM-XSS sink)")
                continue

            # eval(code) -> code execution
            if name in self._EVAL_NAMES and (full == name or full.endswith(f".{name}")):
                if args and _is_dynamic(args[0]):
                    yield self._result("eval()", "code_eval_sink", Severity.HIGH,
                                       Confidence.MEDIUM, call.line, call.column,
                                       "eval() with a dynamic argument (code-injection sink)")
                continue

            # setTimeout/setInterval("code string", ...) -> code execution
            if name in self._TIMER_NAMES:
                if args and (_is_dynamic(args[0]) or _literal_str(args[0])):
                    # Only a STRING (or dynamic) first arg is a code sink; a function ref is safe.
                    first = args[0]
                    if isinstance(first, dict) and first.get("type") in (
                        "FunctionExpression", "ArrowFunctionExpression", "Identifier",
                    ) and not _literal_str(first):
                        # bare function reference -> not a string-eval sink
                        if first.get("type") == "Identifier":
                            pass  # identifier could be a string var; keep, low confidence
                        else:
                            continue
                    yield self._result(f"{name}(string)", "code_eval_sink", Severity.MEDIUM,
                                       Confidence.LOW, call.line, call.column,
                                       f"{name}() with a string/dynamic first argument (code-injection sink)")
                continue

            # setAttribute(name, value) with a dangerous attribute + dynamic value
            if name == "setAttribute" and len(args) >= 2:
                attr = _literal_str(args[0]).lower()
                if attr in _DANGEROUS_ATTRS and _is_dynamic(args[1]):
                    src = _expr_source(args[1])
                    yield self._result(f"setAttribute({attr})", "dom_attr_sink", Severity.MEDIUM,
                                       Confidence.LOW, call.line, call.column,
                                       f"setAttribute('{attr}', {src}) -- attribute-injection sink",
                                       metadata={"sink_source": src, "sink_attr": attr})
                continue

            # jQuery .attr('src'|..., value) / .prop(...) with a dangerous attribute + dynamic value.
            # This is the `$img.attr("src", uploaded.path)` upload -> <img src> stored-XSS pattern.
            if name in ("attr", "prop") and len(args) >= 2:
                attr = _literal_str(args[0]).lower()
                if attr in _DANGEROUS_ATTRS and _is_dynamic(args[1]):
                    src = _expr_source(args[1])
                    yield self._result(f".{name}({attr})", "dom_attr_sink", Severity.MEDIUM,
                                       Confidence.MEDIUM, call.line, call.column,
                                       f"jQuery .{name}('{attr}', {src}) -- attribute-injection "
                                       f"sink (a dynamic value in a '{attr}' attribute)",
                                       metadata={"sink_source": src, "sink_attr": attr})
                continue

    # ---------------------------------------------------------------- assignment sinks

    def _match_ast(self, raw_ast: dict) -> Iterator[RuleResult]:
        """Iterative walk for `x.innerHTML = <dynamic>` / `x.outerHTML = ...`, `new Function(...)`,
        and HTML strings (template literals / concatenation) that interpolate a dynamic value into
        a dangerous HTML attribute (`<img src="${x}">`, `onerror="${x}"` -- DOM/stored-XSS)."""
        if not isinstance(raw_ast, dict):
            return
        stack = [raw_ast]
        MAX_NODES = 300000  # backstop against a pathological tree; nodes, not recursion depth
        seen = 0
        seen_attr: set = set()
        while stack:
            node = stack.pop()
            seen += 1
            if seen > MAX_NODES or not isinstance(node, dict):
                continue
            node_type = node.get("type")

            if node_type == "AssignmentExpression" and node.get("operator") == "=":
                left = node.get("left")
                if isinstance(left, dict) and left.get("type") == "MemberExpression":
                    prop = left.get("property", {})
                    prop_name = prop.get("name") or (
                        prop.get("value") if isinstance(prop.get("value"), str) else ""
                    )
                    if isinstance(prop_name, str) and prop_name in ("innerHTML", "outerHTML"):
                        if _is_dynamic(node.get("right")):
                            loc = (node.get("loc") or {}).get("start", {})
                            yield self._result(
                                f"{prop_name}=", "dom_html_sink", Severity.HIGH, Confidence.MEDIUM,
                                loc.get("line", 0), loc.get("column", 0),
                                f"element.{prop_name} = <dynamic> (HTML injection / DOM-XSS sink)")

            elif node_type == "NewExpression":
                callee = node.get("callee", {})
                if isinstance(callee, dict) and callee.get("name") == "Function":
                    args = node.get("arguments") or []
                    if args and _is_dynamic(args[-1]):
                        loc = (node.get("loc") or {}).get("start", {})
                        yield self._result(
                            "new Function()", "code_eval_sink", Severity.HIGH, Confidence.MEDIUM,
                            loc.get("line", 0), loc.get("column", 0),
                            "new Function(<dynamic>) (code-injection sink)")

            elif node_type == "TemplateLiteral":
                quasis = node.get("quasis") or []
                if any("<" in ((q.get("value") or {}).get("raw") or "") for q in quasis):
                    yield from self._html_attr_injections(
                        self._template_text(node), node.get("expressions") or [], node, seen_attr)

            elif node_type == "BinaryExpression" and node.get("operator") == "+":
                parts: list = []
                _flatten_concat(node, parts)
                if any("<" in _literal_str(p) for p in parts):
                    text = "".join(_literal_str(p) if _literal_str(p) else _SENTINEL for p in parts)
                    exprs = [p for p in parts if not _literal_str(p)]
                    yield from self._html_attr_injections(text, exprs, node, seen_attr)

            # push children
            for key, value in node.items():
                if key in ("loc", "range", "raw"):
                    continue
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            stack.append(item)

    # ---------------------------------------------------------------- HTML attribute injection

    def _template_text(self, node: dict) -> str:
        """Reconstruct a template literal's raw text with one _SENTINEL per ${expression}."""
        quasis = node.get("quasis") or []
        parts: list[str] = []
        for i, q in enumerate(quasis):
            parts.append((q.get("value") or {}).get("raw") or "")
            if i < len(quasis) - 1:
                parts.append(_SENTINEL)
        return "".join(parts)

    def _html_attr_injections(self, text: str, exprs: list, node: dict, seen: set) -> Iterator[RuleResult]:
        """Emit a finding for each dynamic expression interpolated as the value of a dangerous
        HTML attribute inside an HTML string being built (`<img src="${item.image_url}">`)."""
        loc = (node.get("loc") or {}).get("start", {})
        line, col = loc.get("line", 0), loc.get("column", 0)
        for m in _DANGER_ATTR_RE.finditer(text):
            sent_idx = text[:m.end()].count(_SENTINEL) - 1
            if not (0 <= sent_idx < len(exprs)):
                continue
            attr = m.group("attr").lower()
            source = _expr_source(exprs[sent_idx])
            key = (line, attr, source)
            if key in seen:
                continue
            seen.add(key)
            # The `${source}` interpolation usually sits many lines below the template's start line;
            # anchor the SNIPPET there so it actually shows the vulnerable value (the finding `line`
            # stays at the construct start for the detection gate).
            snippet_line = (line + text[:m.start()].count("\n")) if line else None
            yield self._result(
                f"html {attr}= injection", "dom_attr_injection", Severity.HIGH, Confidence.MEDIUM,
                line, col,
                f"Dynamic value `{source}` interpolated into a '{attr}' HTML attribute "
                f"(e.g. <tag {attr}=\"${{{source}}}\">) built for a DOM sink -- DOM/stored-XSS if "
                f"`{source}` is user- or upload-controlled",
                metadata={"sink_source": source, "sink_attr": attr},
                snippet_line=snippet_line)

    # ---------------------------------------------------------------- helper

    def _result(self, sink: str, value_type: str, severity: Severity, confidence: Confidence,
                line: int, column: int, description: str,
                metadata: Optional[dict] = None,
                snippet_line: Optional[int] = None) -> RuleResult:
        return RuleResult(
            rule_id=self.id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            title=f"DOM Sink: {sink}",
            description=description,
            extracted_value=sink,
            value_type=value_type,
            line=line,
            column=column,
            ast_node_type="",
            tags=["dom_sink", value_type],
            metadata=metadata or {},
            snippet_line=snippet_line,
        )
