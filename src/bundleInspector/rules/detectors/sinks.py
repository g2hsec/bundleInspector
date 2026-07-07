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

from typing import Any, Iterator

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
        yield from self._match_assignments(ir.raw_ast or {})

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
                    yield self._result(f"setAttribute({attr})", "dom_attr_sink", Severity.MEDIUM,
                                       Confidence.LOW, call.line, call.column,
                                       f"setAttribute('{attr}', <dynamic>) -- attribute-injection sink")
                continue

    # ---------------------------------------------------------------- assignment sinks

    def _match_assignments(self, raw_ast: dict) -> Iterator[RuleResult]:
        """Iterative walk for `x.innerHTML = <dynamic>` / `x.outerHTML = ...` and
        `new Function(<dynamic>)` (not captured as plain function calls)."""
        if not isinstance(raw_ast, dict):
            return
        stack = [raw_ast]
        MAX_DEPTH = 100000  # backstop against a pathological tree; nodes, not recursion depth
        seen = 0
        while stack:
            node = stack.pop()
            seen += 1
            if seen > MAX_DEPTH or not isinstance(node, dict):
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

    # ---------------------------------------------------------------- helper

    def _result(self, sink: str, value_type: str, severity: Severity, confidence: Confidence,
                line: int, column: int, description: str) -> RuleResult:
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
        )
