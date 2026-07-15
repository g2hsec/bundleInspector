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
from collections.abc import Iterator
from typing import Any

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

# AST node types that represent a runtime (non-static) value.
_DYNAMIC_NODE_TYPES = frozenset(
    {
        "Identifier",
        "MemberExpression",
        "CallExpression",
        "BinaryExpression",
        "ConditionalExpression",
        "LogicalExpression",
        "NewExpression",
        "AwaitExpression",
        "TaggedTemplateExpression",
        "SequenceExpression",
        "ChainExpression",
    }
)

# Attribute names that execute or navigate when their value is attacker-controlled.
_DANGEROUS_ATTRS = frozenset(
    {
        "src",
        "href",
        "xlink:href",
        "onerror",
        "onload",
        "onclick",
        "formaction",
        "action",
        "data",
        "srcdoc",
        "background",
        "poster",
        "codebase",
    }
)


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
        key = prop.get("name") or (
            prop.get("value") if isinstance(prop.get("value"), str) else None
        )
        return f"{obj}.{key}" if key else f"{obj}[…]"
    if t == "CallExpression":
        return f"{_expr_source(node.get('callee'), _depth + 1)}(…)"
    return "<expr>"


_SENTINEL = "\x00"
# A sentinel (interpolated expression) sitting as the VALUE of a dangerous HTML attribute:
#   <img src="${x}">  ->  ... src="␀ ;  <a href='${u}'  ;  onerror="${x}"
_DANGER_ATTR_RE = re.compile(
    # Bounded ({0,2048}): the unbounded `[^"'<>\x00]*` before the required `\x00` sentinel
    # backtracked O(n^2) on a long attacker-controlled template literal (e.g. `<`+`src=` repeated),
    # scanning to the sentinel at every attr-start. A real attribute-value prefix before a `${...}`
    # interpolation is short, so the match set is unchanged.
    r"""(?ix)
    (?P<attr>on\w{1,64}|src|href|xlink:href|srcdoc|formaction|action|poster|background)
    \s*=\s*["']?[^"'<>\x00]{0,2048}\x00
    """,
)
# Event handlers / srcdoc / style / formaction execute directly -> higher severity than a
# src/href value-injection (which needs an attribute break-out first).
_EXEC_ATTRS = ("on", "srcdoc", "style", "formaction")


def _flatten_concat(node: Any, out: list) -> None:
    """Flatten a string `+` concatenation into ordered operands (left-to-right)."""
    if (
        isinstance(node, dict)
        and node.get("type") == "BinaryExpression"
        and node.get("operator") == "+"
    ):
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
        "html": 0,
        "append": 0,
        "prepend": 0,
        "after": 0,
        "before": 0,
        "replaceWith": 0,
        "wrap": 0,
        "appendTo": 0,
        "prependTo": 0,
    }
    _JQUERY_EXCLUSIVE_HTML_METHODS = {"html", "wrap", "appendTo", "prependTo"}
    # code-execution call sinks.
    _EVAL_NAMES = {"eval"}
    _TIMER_NAMES = {"setTimeout", "setInterval", "setImmediate", "execScript"}
    _REACT_ELEMENT_CALLS = {
        "createElement",
        "jsx",
        "jsxs",
        "jsxDEV",
        "_jsx",
        "_jsxs",
        "_jsxDEV",
    }

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        raw_ast = ir.raw_ast or {}
        jquery_sites = self._jquery_html_call_sites(raw_ast)
        yield from self._match_calls(ir, jquery_sites)
        yield from self._match_ast(raw_ast, jquery_sites, context)

    @staticmethod
    def _iter_nodes(raw_ast: dict) -> Iterator[dict]:
        if not isinstance(raw_ast, dict):
            return
        stack = [raw_ast]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            yield node
            for value in node.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(item for item in value if isinstance(item, dict))

    @staticmethod
    def _property_name(node: Any) -> str:
        if not isinstance(node, dict):
            return ""
        value = node.get("name")
        if isinstance(value, str):
            return value
        value = node.get("value")
        return value if isinstance(value, str) else ""

    @classmethod
    def _callee_name(cls, callee: Any) -> str:
        if not isinstance(callee, dict):
            return ""
        if callee.get("type") == "Identifier":
            return cls._property_name(callee)
        if callee.get("type") == "MemberExpression":
            return cls._property_name(callee.get("property"))
        return ""

    @classmethod
    def _is_jquery_expr(cls, node: Any, bindings: set[str], depth: int = 0) -> bool:
        if not isinstance(node, dict) or depth > 12:
            return False
        node_type = node.get("type")
        if node_type == "Identifier":
            name = cls._property_name(node)
            return name in {"$", "jQuery"} or name.startswith("$") or name in bindings
        if node_type == "CallExpression":
            return cls._is_jquery_expr(node.get("callee"), bindings, depth + 1)
        if node_type == "MemberExpression":
            return cls._is_jquery_expr(node.get("object"), bindings, depth + 1)
        return False

    @classmethod
    def _jquery_html_call_sites(cls, raw_ast: dict) -> set[tuple[int, int]]:
        nodes = list(cls._iter_nodes(raw_ast))
        bindings: set[str] = set()
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node.get("type") != "VariableDeclarator":
                    continue
                ident = node.get("id") or {}
                name = cls._property_name(ident)
                if (
                    name
                    and name not in bindings
                    and cls._is_jquery_expr(node.get("init"), bindings)
                ):
                    bindings.add(name)
                    changed = True
        sites: set[tuple[int, int]] = set()
        for node in nodes:
            if node.get("type") != "CallExpression":
                continue
            callee = node.get("callee") or {}
            if not isinstance(callee, dict) or callee.get("type") != "MemberExpression":
                continue
            name = cls._property_name(callee.get("property"))
            if name not in cls._HTML_CALL_SINKS:
                continue
            if name not in cls._JQUERY_EXCLUSIVE_HTML_METHODS and not cls._is_jquery_expr(
                callee.get("object"), bindings
            ):
                continue
            loc = (node.get("loc") or {}).get("start", {})
            sites.add((loc.get("line", 0), loc.get("column", 0)))
        return sites

    # ---------------------------------------------------------------- call-based sinks

    def _match_calls(
        self,
        ir: IntermediateRepresentation,
        jquery_sites: set[tuple[int, int]],
    ) -> Iterator[RuleResult]:
        for call in ir.function_calls:
            name = call.name
            full = call.full_name or name
            args = call.arguments or []

            # document.write / document.writeln -> HTML injection
            if name in ("write", "writeln") and full.lower().startswith("document."):
                if args and _is_dynamic(args[0]):
                    yield self._result(
                        f"document.{name}()",
                        "dom_html_sink",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        call.line,
                        call.column,
                        f"document.{name}() with a dynamic argument (HTML injection / DOM-XSS sink)",
                    )
                continue

            # insertAdjacentHTML(position, html) -> arg 1 is the HTML
            if name == "insertAdjacentHTML":
                if len(args) >= 2 and _is_dynamic(args[1]):
                    yield self._result(
                        "insertAdjacentHTML()",
                        "dom_html_sink",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        call.line,
                        call.column,
                        "insertAdjacentHTML() with a dynamic argument (HTML injection / DOM-XSS sink)",
                    )
                continue

            # DQ-D06: Range.createContextualFragment(html) -- a modern HTML-injection sink (rare
            # method name -> low FP; arg 0 is parsed as HTML incl. active content when inserted).
            if name == "createContextualFragment":
                if args and _is_dynamic(args[0]):
                    yield self._result(
                        "createContextualFragment()",
                        "dom_html_sink",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        call.line,
                        call.column,
                        "Range.createContextualFragment() with a dynamic argument (HTML injection sink)",
                    )
                continue

            if name == "setHTMLUnsafe":
                if args and _is_dynamic(args[0]):
                    yield self._result(
                        "setHTMLUnsafe()",
                        "dom_html_sink",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        call.line,
                        call.column,
                        "Element.setHTMLUnsafe() with a dynamic argument (HTML injection sink)",
                    )
                continue

            # jQuery / DOM HTML-injection methods
            if name in self._HTML_CALL_SINKS:
                if (call.line, call.column) not in jquery_sites:
                    continue
                idx = self._HTML_CALL_SINKS[name]
                if len(args) > idx and _is_dynamic(args[idx]):
                    # .html()/.replaceWith() overwrite content (clearer HTML sink); the insertion
                    # methods (.append/.prepend/...) are lower-severity + lower-confidence (the
                    # argument is more often a built node than raw HTML).
                    strong = name in ("html", "replaceWith")
                    sev = Severity.MEDIUM if strong else Severity.LOW
                    conf = Confidence.MEDIUM if strong else Confidence.LOW
                    yield self._result(
                        f".{name}()",
                        "dom_html_sink",
                        sev,
                        conf,
                        call.line,
                        call.column,
                        f"jQuery/DOM .{name}() with a dynamic argument (possible HTML injection / DOM-XSS sink)",
                    )
                continue

            # eval(code) -> code execution
            if name in self._EVAL_NAMES and (full == name or full.endswith(f".{name}")):
                if args and _is_dynamic(args[0]):
                    yield self._result(
                        "eval()",
                        "code_eval_sink",
                        Severity.HIGH,
                        Confidence.MEDIUM,
                        call.line,
                        call.column,
                        "eval() with a dynamic argument (code-injection sink)",
                    )
                continue

            # setTimeout/setInterval("code string", ...) -> code execution
            if name in self._TIMER_NAMES:
                if args and (_is_dynamic(args[0]) or _literal_str(args[0])):
                    # Only a STRING (or dynamic) first arg is a code sink; a function ref is safe.
                    first = args[0]
                    if (
                        isinstance(first, dict)
                        and first.get("type")
                        in (
                            "FunctionExpression",
                            "ArrowFunctionExpression",
                            "Identifier",
                        )
                        and not _literal_str(first)
                    ):
                        continue
                    yield self._result(
                        f"{name}(string)",
                        "code_eval_sink",
                        Severity.MEDIUM,
                        Confidence.LOW,
                        call.line,
                        call.column,
                        f"{name}() with a string/dynamic first argument (code-injection sink)",
                    )
                continue

            # setAttribute(name, value) with a dangerous attribute + dynamic value
            if name == "setAttribute" and len(args) >= 2:
                attr = _literal_str(args[0]).lower()
                if attr in _DANGEROUS_ATTRS and _is_dynamic(args[1]):
                    src = _expr_source(args[1])
                    yield self._result(
                        f"setAttribute({attr})",
                        "dom_attr_sink",
                        Severity.MEDIUM,
                        Confidence.LOW,
                        call.line,
                        call.column,
                        f"setAttribute('{attr}', {src}) -- attribute-injection sink",
                        metadata={"sink_source": src, "sink_attr": attr},
                    )
                continue

            # jQuery .attr('src'|..., value) / .prop(...) with a dangerous attribute + dynamic value.
            # This is the `$img.attr("src", uploaded.path)` upload -> <img src> stored-XSS pattern.
            if name in ("attr", "prop") and len(args) >= 2:
                attr = _literal_str(args[0]).lower()
                if attr in _DANGEROUS_ATTRS and _is_dynamic(args[1]):
                    src = _expr_source(args[1])
                    yield self._result(
                        f".{name}({attr})",
                        "dom_attr_sink",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        call.line,
                        call.column,
                        f"jQuery .{name}('{attr}', {src}) -- attribute-injection "
                        f"sink (a dynamic value in a '{attr}' attribute)",
                        metadata={"sink_source": src, "sink_attr": attr},
                    )
                continue

    # ---------------------------------------------------------------- assignment sinks

    @classmethod
    def _ast_sink_context(
        cls,
        raw_ast: dict,
        jquery_sites: set[tuple[int, int]],
    ) -> tuple[set[int], set[int]]:
        """Return HTML expressions consumed by a sink and React-owned dangerous prop nodes."""
        nodes = list(cls._iter_nodes(raw_ast))
        bindings: dict[str, dict] = {}
        ambiguous: set[str] = set()
        for node in nodes:
            if node.get("type") != "VariableDeclarator":
                continue
            ident = node.get("id") or {}
            init = node.get("init")
            name = cls._property_name(ident)
            if not name or not isinstance(init, dict):
                continue
            if name in bindings:
                ambiguous.add(name)
            else:
                bindings[name] = init
        for name in ambiguous:
            bindings.pop(name, None)

        def resolve(node: Any, resolving: set[str] | None = None) -> Any:
            if not isinstance(node, dict) or node.get("type") != "Identifier":
                return node
            name = cls._property_name(node)
            if name not in bindings:
                return node
            resolving = set() if resolving is None else set(resolving)
            if name in resolving:
                return node
            resolving.add(name)
            return resolve(bindings[name], resolving)

        def object_property(obj: Any, name: str) -> Any:
            obj = resolve(obj)
            if not isinstance(obj, dict) or obj.get("type") != "ObjectExpression":
                return None
            for prop in reversed(obj.get("properties") or []):
                if not isinstance(prop, dict):
                    continue
                if prop.get("type") == "SpreadElement":
                    inherited = object_property(prop.get("argument"), name)
                    if inherited is not None:
                        return inherited
                elif cls._property_name(prop.get("key")) == name:
                    return prop.get("value")
            return None

        consumed: set[int] = set()
        react_props: set[int] = set()
        for node in nodes:
            node_type = node.get("type")
            if node_type == "AssignmentExpression":
                left = node.get("left") or {}
                if isinstance(left, dict) and left.get("type") == "MemberExpression":
                    prop_name = cls._property_name(left.get("property"))
                    if prop_name in {"innerHTML", "outerHTML", "srcdoc"}:
                        right = resolve(node.get("right"))
                        if isinstance(right, dict):
                            consumed.add(id(right))
                continue
            if node_type != "CallExpression":
                continue
            callee = node.get("callee") or {}
            name = cls._callee_name(callee)
            args = node.get("arguments") or []
            loc = (node.get("loc") or {}).get("start", {})
            arg_index: int | None = None
            if (
                name in cls._HTML_CALL_SINKS
                and (loc.get("line", 0), loc.get("column", 0)) in jquery_sites
            ):
                arg_index = cls._HTML_CALL_SINKS[name]
            elif name in {"write", "writeln"}:
                obj = callee.get("object") if isinstance(callee, dict) else None
                if cls._property_name(obj) == "document":
                    arg_index = 0
            elif name in {"createContextualFragment", "setHTMLUnsafe"}:
                arg_index = 0
            elif name == "insertAdjacentHTML":
                arg_index = 1
            if arg_index is not None and len(args) > arg_index:
                value = resolve(args[arg_index])
                if isinstance(value, dict):
                    consumed.add(id(value))

            if name not in cls._REACT_ELEMENT_CALLS or len(args) < 2:
                continue
            props = resolve(args[1])
            if not isinstance(props, dict) or props.get("type") != "ObjectExpression":
                continue
            for prop in props.get("properties") or []:
                if (
                    isinstance(prop, dict)
                    and prop.get("type") == "Property"
                    and cls._property_name(prop.get("key")) == "dangerouslySetInnerHTML"
                ):
                    react_props.add(id(prop))
                    html_node = object_property(prop.get("value"), "__html")
                    html_node = resolve(html_node)
                    if isinstance(html_node, dict):
                        consumed.add(id(html_node))
        return consumed, react_props

    def _match_ast(
        self,
        raw_ast: dict,
        jquery_sites: set[tuple[int, int]],
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Iterative walk for `x.innerHTML = <dynamic>` / `x.outerHTML = ...`, `new Function(...)`,
        and HTML strings (template literals / concatenation) that interpolate a dynamic value into
        a dangerous HTML attribute (`<img src="${x}">`, `onerror="${x}"` -- DOM/stored-XSS)."""
        if not isinstance(raw_ast, dict):
            return
        consumed_html, react_props = self._ast_sink_context(raw_ast, jquery_sites)
        stack = [raw_ast]
        MAX_NODES = 300000  # backstop against a pathological tree; nodes, not recursion depth
        seen = 0
        seen_attr: set = set()
        while stack:
            node = stack.pop()
            seen += 1
            if seen > MAX_NODES:
                context.metadata.setdefault("analysis_incomplete", []).append(
                    {
                        "component": self.id,
                        "reason": "ast_node_cap",
                        "processed": MAX_NODES,
                        "limit": MAX_NODES,
                    }
                )
                break
            if not isinstance(node, dict):
                continue
            node_type = node.get("type")

            if node_type == "AssignmentExpression" and node.get("operator") in ("=", "+="):
                # `=` sets and `+=` APPENDS raw HTML into the element -- both are DOM-XSS sinks.
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
                                f"{prop_name}=",
                                "dom_html_sink",
                                Severity.HIGH,
                                Confidence.MEDIUM,
                                loc.get("line", 0),
                                loc.get("column", 0),
                                f"element.{prop_name} = <dynamic> (HTML injection / DOM-XSS sink)",
                            )
                    elif prop_name == "srcdoc" and _is_dynamic(node.get("right")):
                        loc = (node.get("loc") or {}).get("start", {})
                        yield self._result(
                            "srcdoc=",
                            "dom_attr_sink",
                            Severity.HIGH,
                            Confidence.MEDIUM,
                            loc.get("line", 0),
                            loc.get("column", 0),
                            "iframe.srcdoc = <dynamic> (HTML injection / DOM-XSS sink)",
                            metadata={"sink_attr": "srcdoc"},
                        )

            elif node_type == "NewExpression":
                callee = node.get("callee", {})
                if isinstance(callee, dict) and callee.get("name") == "Function":
                    args = node.get("arguments") or []
                    if args and _is_dynamic(args[-1]):
                        loc = (node.get("loc") or {}).get("start", {})
                        yield self._result(
                            "new Function()",
                            "code_eval_sink",
                            Severity.HIGH,
                            Confidence.MEDIUM,
                            loc.get("line", 0),
                            loc.get("column", 0),
                            "new Function(<dynamic>) (code-injection sink)",
                        )

            elif node_type == "Property":
                # DQ-D06: React `dangerouslySetInnerHTML={{__html: <dynamic>}}` -- a modern DOM-XSS sink.
                key = node.get("key", {})
                key_name = key.get("name") or (
                    key.get("value") if isinstance(key.get("value"), str) else ""
                )
                if key_name == "dangerouslySetInnerHTML" and id(node) in react_props:
                    val = node.get("value", {})
                    html_node = val
                    if isinstance(val, dict) and val.get("type") == "ObjectExpression":
                        html_node = None
                        for p in val.get("properties", []) or []:
                            pk = p.get("key") or {}
                            pkn = pk.get("name") or (
                                pk.get("value") if isinstance(pk.get("value"), str) else ""
                            )
                            if pkn == "__html":
                                html_node = p.get("value")
                                break
                    if _is_dynamic(html_node):
                        loc = (node.get("loc") or {}).get("start", {})
                        yield self._result(
                            "dangerouslySetInnerHTML",
                            "dom_html_sink",
                            Severity.HIGH,
                            Confidence.MEDIUM,
                            loc.get("line", 0),
                            loc.get("column", 0),
                            "React dangerouslySetInnerHTML={{__html: <dynamic>}} (HTML injection / DOM-XSS sink)",
                        )

            elif node_type == "TemplateLiteral" and id(node) in consumed_html:
                quasis = node.get("quasis") or []
                if any("<" in ((q.get("value") or {}).get("raw") or "") for q in quasis):
                    yield from self._html_attr_injections(
                        self._template_text(node), node.get("expressions") or [], node, seen_attr
                    )

            elif (
                node_type == "BinaryExpression"
                and node.get("operator") == "+"
                and id(node) in consumed_html
            ):
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

    def _html_attr_injections(
        self, text: str, exprs: list, node: dict, seen: set
    ) -> Iterator[RuleResult]:
        """Emit a finding for each dynamic expression interpolated as the value of a dangerous
        HTML attribute inside an HTML string being built (`<img src="${item.image_url}">`)."""
        loc = (node.get("loc") or {}).get("start", {})
        line, col = loc.get("line", 0), loc.get("column", 0)
        for m in _DANGER_ATTR_RE.finditer(text):
            sent_idx = text[: m.end()].count(_SENTINEL) - 1
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
            # stays at the construct start for the detection gate). Prefer the matched expression's
            # OWN source line -- counting sentinel-collapsed newlines undercounts when an earlier
            # `${...}` spanned multiple source lines.
            target_expr = exprs[sent_idx]
            expr_start = (
                (target_expr.get("loc") or {}).get("start") or {}
                if isinstance(target_expr, dict)
                else {}
            )
            snippet_line = expr_start.get("line") or (
                (line + text[: m.start()].count("\n")) if line else None
            )
            yield self._result(
                f"html {attr}= injection",
                "dom_attr_injection",
                Severity.HIGH,
                Confidence.MEDIUM,
                line,
                col,
                f"Dynamic value `{source}` interpolated into a '{attr}' HTML attribute "
                f'(e.g. <tag {attr}="${{{source}}}">) built for a DOM sink -- DOM/stored-XSS if '
                f"`{source}` is user- or upload-controlled",
                metadata={"sink_source": source, "sink_attr": attr},
                snippet_line=snippet_line,
            )

    # ---------------------------------------------------------------- helper

    def _result(
        self,
        sink: str,
        value_type: str,
        severity: Severity,
        confidence: Confidence,
        line: int,
        column: int,
        description: str,
        metadata: dict | None = None,
        snippet_line: int | None = None,
    ) -> RuleResult:
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
