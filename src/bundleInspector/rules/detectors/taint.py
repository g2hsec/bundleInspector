"""
Intra-file dataflow taint engine (flow-sensitive, context-sensitive, closure-aware).

Emits a CONFIRMED source->sink finding only when a real def-use chain connects an ENUMERATED
source (FileReader result, an AJAX/fetch response, a DOM input) to a DOM/HTML/code SINK -- the
client half of a DOM/stored XSS -- with the reconstructed source->...->sink path attached.

Precision is the whole point. The analysis is:
- FLOW-SENSITIVE: statements are processed in source order over a per-function environment;
  `x = source; x = "safe"; sink(x)` does NOT flag (a clean reassignment kills prior taint, and
  a sink only sees taint that reached it *before* it, in order) -- no impossible backward flows.
- CONTEXT-SENSITIVE: a called local function is re-analyzed with THIS call site's argument taints,
  so f(userInput) is tainted while f("safe") is clean.
- CLOSURE-AWARE: a nested callback inherits the enclosing environment (outer tainted vars visible).
- BINDING-KEYED: state is keyed by resolved (scope, name); sibling same-name vars never alias.
- A value is tainted ONLY if its chain reaches an enumerated source; a name that merely looks like
  data is never a source. A bare parameter is not a source. Sanitizers and `.text()` stop taint.
  A call on an arbitrary object (not this/self, not a unique free function) is not resolved -> abstain.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.rules.detectors.sinks import (
    _DANGEROUS_ATTRS,
    _expr_source,
    _flatten_concat,
    _literal_str,
)
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

# ---------------------------------------------------------------- source / sink / sanitizer tables

_AJAX_METHODS = {"ajax", "get", "post", "getjson"}  # on $/jQuery/axios ('load' excluded: it
_AJAX_ROOTS = {"$", "jquery", "axios"}  # injects into an element / event-binds)
_FETCH_NAMES = {"fetch"}
_RESPONSE_MEMBERS = {"responsejson", "responsetext", "responsexml"}
_RESP_CALLBACK_METHODS = {"done", "then", "success", "complete"}
_PROMISE_CALLBACK_METHODS = {"then", "catch", "finally"}
_ITERATOR_METHODS = {"map", "foreach", "filter", "some", "every", "find", "flatmap", "each"}
_DOM_GETTER_0 = {"val"}  # 0-arg jQuery getter -> form input (user-controlled)
# 1-arg getter -> DOM input. `.attr(k)`/`.prop(k)` are excluded: reading an element's own
# attribute (esp. src/href in lazy-load `attr('src') -> attr('src')` patterns) is app/server-set,
# not user input, and produced only low-value self-referential noise. `.data()` is kept (data-*
# attributes commonly carry dynamic/user content).
_DOM_GETTER_1 = {"data"}
_SANITIZERS = {
    "encodeuricomponent",
    "encodeuri",
    "escape",
    "sanitize",
    "purify",
    "number",
    "parseint",
    "parsefloat",
    "formatnumberwithcommas",
    "tofixed",
    "gettime",
    "btoa",
}
# NB: JSON.stringify is intentionally NOT here -- it does not HTML-escape (`<`/`>`/`&` survive), so
# stringifying a tainted value into an HTML sink is still XSS; it is handled as taint-preserving.
_THIS_ALIASES = {"this", "self", "_self", "that", "_this", "me", "_me"}
# DQ-T02: `<x>.target.value|files` is DOM input only when <x> roots at an event object; the common
# handler-parameter spellings. Without this guard, `model.target.value` etc. were treated as sources.
_EVENT_NAMES = {"e", "ev", "evt", "event", "$event", "nativeevent", "domevent"}
# DQ-T02: jQuery-cache property names (this.$el.val()), a DOM-element convention -- distinct from
# framework-service $-properties ($q/$http/$scope/$store/$route/$refs/$timeout) which are NOT jQuery.
_JQUERY_CACHE_PROPS = {
    "$el",
    "$ele",
    "$elem",
    "$element",
    "$node",
    "$dom",
    "$container",
    "$wrapper",
    "$wrap",
    "$input",
    "$form",
    "$field",
    "$btn",
    "$button",
    "$target",
    "$modal",
    "$dialog",
    "$list",
    "$body",
    "$content",
    "$header",
    "$footer",
    "$link",
    "$img",
    "$icon",
    "$menu",
    "$nav",
    "$panel",
    "$box",
    "$table",
    "$row",
    "$cell",
    "$item",
    "$tab",
    "$this",
    "$root",
    "$view",
}
_TRANSFORMS = {
    "map",
    "filter",
    "slice",
    "concat",
    "find",
    "join",
    "trim",
    "tolowercase",
    "touppercase",
    "substring",
    "substr",
    "split",
    "pop",
    "reverse",
    "flat",
    "flatmap",
    "replace",  # non-numeric .replace() preserves taint (numeric-strip is caught as a sanitizer)
}
_HTML_CALL_SINKS = {"html", "append", "prepend", "after", "before", "replacewith", "wrap"}
_ATTR_SINK_CALLS = {"attr", "prop", "setattribute"}
# jQuery reverse-insertion: the built HTML is the RECEIVER, the target is the arg
# (`$('<div>'+x).appendTo(t)`) -- the mirror of _HTML_CALL_SINKS.
_REVERSE_INSERT_METHODS = {"appendto", "prependto", "insertafter", "insertbefore", "replaceall"}

_SOURCE_SEVERITY = {
    "ajax_response": (Severity.HIGH, Confidence.HIGH, "server response"),
    "dom_input": (Severity.HIGH, Confidence.MEDIUM, "DOM input"),
    "location": (Severity.HIGH, Confidence.MEDIUM, "URL/location"),
    "filereader": (Severity.MEDIUM, Confidence.MEDIUM, "uploaded file (FileReader)"),
    "postmessage": (Severity.HIGH, Confidence.HIGH, "cross-origin message"),
    "browser_storage": (Severity.MEDIUM, Confidence.MEDIUM, "browser storage"),
}

_READER_OBJ = "__filereader_object__"  # env marker: a var bound to new FileReader()
_JQUERY_OBJ = "__jquery_object__"  # DQ-T02: env marker: a var bound to $(...) / jQuery(...)
_OBJECT_REF = "__object_reference__"  # env marker: object/array identity for heap-member state
_FUNCTION_REF = "__function_reference__"  # env marker: exact callable + captured lexical state
_CONST_VALUE = "__constant_value__"  # env marker: proven literal for a computed member key
_CLEAN_VALUE = "__clean_value__"  # env marker: explicit clean overwrite/member presence
_PROMISE_REF = "__promise_reference__"  # env marker: fulfilled/rejected abstract state
_PROMISE_RESOLVE_FN = "__promise_resolve_function__"
_PROMISE_REJECT_FN = "__promise_reject_function__"
_SANITIZER_REF = "__sanitizer_reference__"
_GENERATOR_REF = "__generator_reference__"
_ITERATOR_RESULT_REF = "__iterator_result_reference__"
_PATH_CONDITION = "__path_condition__"  # env marker: predicate required to reach this state
_PATH_INVALIDATED = "__path_invalidated__"  # assigned predicate no longer constrains the path
_EXCEPTION_VALUE_KEY = ("control", "exception-value")
_MAX_WORK = 400000
_MAX_DEPTH = 60
_MAX_EXCEPTION_STATES = 1024
_MAX_LOOP_ITERATIONS = 16

_STATE_LABELS = {
    _READER_OBJ,
    _JQUERY_OBJ,
    _OBJECT_REF,
    _FUNCTION_REF,
    _CONST_VALUE,
    _CLEAN_VALUE,
    _PROMISE_REF,
    _PROMISE_RESOLVE_FN,
    _PROMISE_REJECT_FN,
    _SANITIZER_REF,
    _GENERATOR_REF,
    _ITERATOR_RESULT_REF,
    _PATH_CONDITION,
    _PATH_INVALIDATED,
}

_PathAtom = tuple[Any, ...]
_AbruptState = tuple[str, dict, dict | None]


def _prop_name(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    prop = node.get("property", node)
    if isinstance(prop, dict):
        return (
            prop.get("name")
            or (prop.get("value") if isinstance(prop.get("value"), str) else "")
            or ""
        ).lower()
    return ""


def _member_root_name(node: Any) -> str:
    cur = node
    for _ in range(16):
        if not isinstance(cur, dict):
            return ""
        t = cur.get("type")
        if t == "Identifier":
            return (cur.get("name") or "").lower()
        if t == "ThisExpression":
            return "this"
        cur = (
            cur.get("object")
            if t == "MemberExpression"
            else (cur.get("callee") if t == "CallExpression" else None)
        )
    return ""


# `.location` is a URL source only off a window-family global -- NOT off an app object
# (store.location, router.location, marker.location) which would false-positive.
_LOCATION_HOSTS = {"window", "self", "top", "parent", "globalthis", "document"}
# location components that carry ONLY same-origin data (not attacker-controllable) -- a redirect to
# location.pathname / .origin is safe, so the navigation sink must ignore them.
_SAFE_LOC_PROPS = {"origin", "protocol", "host", "hostname", "port", "pathname"}


def _is_location_expr(node: Any) -> bool:
    """True for `location`, `window.location`, `document.location`, `self.location`, ... (the object
    whose .href/.assign/.replace is a navigation sink)."""
    if not isinstance(node, dict):
        return False
    if node.get("type") == "Identifier":
        return (node.get("name") or "").lower() == "location"
    if node.get("type") == "MemberExpression" and _prop_name(node) == "location":
        return _member_root_name(node.get("object")) in _LOCATION_HOSTS
    return False


def _nav_fp_safe(info: Any) -> bool:
    """A location source reading a same-origin component (pathname/origin/...) is not attacker-
    controllable -- navigating to it is not an open redirect."""
    return (
        isinstance(info, dict)
        and info.get("label") == "location"
        and info.get("loc_prop") in _SAFE_LOC_PROPS
    )


def _is_built_html(arg: Any) -> bool:
    """True if the arg is an HTML string being CONSTRUCTED (template/concat whose literal part
    contains `<`) -- distinguishes `$('<div>'+u)` (HTML sink) from `$('#'+id)` (selector, safe)."""
    if not isinstance(arg, dict):
        return False
    if arg.get("type") == "TemplateLiteral":
        return any(
            "<" in ((q.get("value") or {}).get("raw") or "") for q in arg.get("quasis") or []
        )
    if arg.get("type") == "BinaryExpression" and arg.get("operator") == "+":
        parts: list = []
        _flatten_concat(arg, parts)
        return any("<" in _literal_str(p) for p in parts)
    return False


def _callee_last_name(callee: Any) -> str:
    if not isinstance(callee, dict):
        return ""
    if callee.get("type") == "Identifier":
        return (callee.get("name") or "").lower()
    if callee.get("type") == "MemberExpression":
        return _prop_name(callee)
    return ""


def _line_of(node: Any) -> int:
    if isinstance(node, dict):
        line = ((node.get("loc") or {}).get("start") or {}).get("line", 0)
        return line if isinstance(line, int) else 0
    return 0


class _Scope:
    __slots__ = ("id", "parent", "names")

    def __init__(self, sid: int, parent: _Scope | None):
        self.id = sid
        self.parent = parent
        self.names: set[str] = set()

    def resolve(self, name: str) -> int | None:
        s: _Scope | None = self
        while s is not None:
            if name in s.names:
                return s.id
            s = s.parent
        return None


class TaintFlowDetector(BaseRule):
    """Confirmed source->sink dataflow (DOM/stored XSS) via flow-sensitive intra-file taint."""

    id = "taint-flow-detector"
    name = "Dataflow Taint (DOM/stored-XSS chain) Detector"
    description = "Confirms a source->sink dataflow reaching a DOM/HTML/code sink"
    category = Category.SINK
    severity = Severity.HIGH

    def match(
        self, ir: IntermediateRepresentation, context: AnalysisContext
    ) -> Iterator[RuleResult]:
        ast = ir.raw_ast or {}
        if not isinstance(ast, dict) or not ast:
            return
        # A "confirmed" verdict asserts a COMPLETE def-use chain -- every sanitizer/kill on the
        # path was seen in source order. A degraded parse breaks that precondition and can turn a
        # neutralized flow into a FALSE source->sink: the esprima chunk-fallback
        # (_partial_parse_esprima) silently DROPS statements that fail to parse (a dropped
        # `x = "safe"` kill leaves earlier taint live to the sink), and the regex fallback has no
        # real AST at all; both also carry chunk-relative (wrong) line numbers. A false "confirmed"
        # is the worst outcome here -- fp_annotate never demotes it and the report badges it as a
        # proven vulnerability. Precision is the whole point of this detector, so ABSTAIN on a
        # degraded parse (consistent with the RecursionError abstention below) rather than assert
        # an unsound confirmation. The DOM-sink INDICATOR (DomSinkDetector) still surfaces the
        # sink, unconfirmed, so the sink surface is not lost.
        #
        # Abstain ONLY on a degraded PARSE (regex/chunk fallback), i.e. when the raw AST -- this
        # detector's own input (`ir.raw_ast`, walked below) -- is incomplete/unsound. Do NOT abstain
        # merely because `ir.partial` was set by an IR-BUILD cap (DQ-C04 `_note_truncation`): that
        # truncates the IR's DERIVED node lists (identifiers/function_calls) while `ir.raw_ast` stays
        # complete, so abstaining there would suppress every SOUND confirmation in the whole file over
        # one unrelated deep construct. `ir.partial` from a real degraded parse is set (ir_builder)
        # only when these same ast flags are present, so this remains equivalent for that case.
        if ast.get("partial") or ast.get("regex_fallback"):
            return
        try:
            self._scopes: list[_Scope] = []
            self._func_scope: dict[int, int] = {}
            self._node_scope: dict[int, int] = {}
            self._function_scope_ids: set[int] = {0}
            self._func_by_name: dict[str, list[dict]] = {}
            self._func_by_binding: dict[tuple[int, str], list[dict]] = {}
            self._all_funcs: list[dict] = []
            self._class_methods: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._class_getters: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._class_setters: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._class_constructors: dict[tuple[int, str], list[dict]] = {}
            self._static_class_methods: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._static_class_getters: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._static_class_setters: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._prototype_methods: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._function_class_owner: dict[
                int, tuple[tuple[int, str], bool]
            ] = {}
            self._class_owner_by_scope: dict[
                int, tuple[tuple[int, str], bool]
            ] = {}
            self._class_supers: dict[tuple[int, str], tuple[int, str]] = {}
            self._instance_methods: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._instance_getters: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._instance_setters: dict[tuple[int, str], dict[str, list[dict]]] = {}
            self._work_cap_hit = False
            self._depth_cap_hit = False
            self._exception_cap_hit = False
            self._loop_cap_hit = False
            self._recursion_hit = False
            self._allocation_seq = 0
            # Bindings destructured from an event-handler param as `target`/`currentTarget`
            # (`({target}) => target.value`) -> keyed (scope_id, local_name); a DOM-input root.
            self._event_param_bindings: set[tuple[int, str]] = set()
            self._build_scopes(ast)

            self._findings: list[RuleResult] = []
            self._seen: set[tuple] = set()
            self._analyzing: set[int] = set()
            self._exception_frames: list[list[dict]] = []
            self._break_frames: list[list[dict]] = []
            self._abrupt_frames: list[list[_AbruptState] | None] = []
            self._path_conditions: list[dict[_PathAtom, bool]] = []
            self._promise_settlement_frames: list[
                list[tuple[str, dict | None, dict[_PathAtom, bool]]]
            ] = []
            self._yield_frames: list[list[dict | None]] = []
            self._work = 0
            # >0 while executing a construct the intra-file evaluator cannot model soundly (loop
            # body: first-iteration order / backedges / multi-iteration are approximated). A sink
            # recorded while this is set is `probable`, never `confirmed` (DQ-C03 / INV-05).
            self._approx = 0

            # Program top-level (empty env) + every function as an entry point (params untainted),
            # so intra-function source->sink flows are found even for methods/handlers not reached
            # from top-level. Callees are additionally re-analyzed context-sensitively at call sites.
            self._run_function(ast, 0, {}, 0)
            for fnode in self._all_funcs:
                self._run_function(fnode, self._func_scope[id(fnode)], {}, 0)
            budget_incomplete = (
                self._work_cap_hit
                or self._depth_cap_hit
                or self._exception_cap_hit
                or self._loop_cap_hit
            )
            if budget_incomplete:
                self._note_incomplete(
                    context,
                    "taint_analysis_budget_exhausted",
                    work=self._work,
                    max_work=_MAX_WORK,
                    max_depth=_MAX_DEPTH,
                    work_cap_hit=self._work_cap_hit,
                    depth_cap_hit=self._depth_cap_hit,
                    exception_cap_hit=self._exception_cap_hit,
                    max_exception_states=_MAX_EXCEPTION_STATES,
                    loop_cap_hit=self._loop_cap_hit,
                    max_loop_iterations=_MAX_LOOP_ITERATIONS,
                )
            if self._recursion_hit:
                self._note_incomplete(
                    context,
                    "taint_recursive_summary_incomplete",
                    max_call_depth=30,
                )
            if budget_incomplete or self._recursion_hit:
                self._downgrade_incomplete_findings()
            yield from self._findings
        except RecursionError:
            self._note_incomplete(context, "taint_analysis_recursion_error")
            return

    @staticmethod
    def _note_incomplete(context: AnalysisContext, reason: str, **details: Any) -> None:
        event = {
            "component": "taint_detector",
            "reason": reason,
            "partial_results": True,
            **details,
        }
        events = context.metadata.setdefault("analysis_incomplete", [])
        if isinstance(events, list) and event not in events:
            events.append(event)

    def _downgrade_incomplete_findings(self) -> None:
        for finding in self._findings:
            finding.metadata = {
                **finding.metadata,
                "confirmed": False,
                "evidence": "probable",
                "analysis_incomplete": True,
            }
            finding.description = finding.description.replace(
                "CONFIRMED dataflow:", "PROBABLE dataflow:", 1
            )
            if finding.confidence == Confidence.HIGH:
                finding.confidence = Confidence.MEDIUM

    # ------------------------------------------------------------ scope pre-pass

    def _register_class_members(
        self, node: dict, binding: tuple[int, str]
    ) -> None:
        tables: dict[str, dict[str, list[dict]]] = {
            "method": {},
            "get": {},
            "set": {},
            "static-method": {},
            "static-get": {},
            "static-set": {},
        }
        constructors: list[dict] = []
        for method in (node.get("body") or {}).get("body", []) or []:
            if not isinstance(method, dict) or method.get("computed"):
                continue
            key = method.get("key") or {}
            name = key.get("name") or key.get("value")
            value = method.get("value")
            if not isinstance(name, str) or not isinstance(value, dict):
                continue
            self._function_class_owner.setdefault(
                id(value), (binding, bool(method.get("static")))
            )
            kind = method.get("kind") or "method"
            if not method.get("static") and kind == "constructor":
                constructors.append(value)
                continue
            table_name = f"static-{kind}" if method.get("static") else kind
            table = tables.get(table_name)
            if table is not None:
                table.setdefault(name.lower(), []).append(value)
        destinations = (
            (tables["method"], self._class_methods),
            (tables["get"], self._class_getters),
            (tables["set"], self._class_setters),
            (tables["static-method"], self._static_class_methods),
            (tables["static-get"], self._static_class_getters),
            (tables["static-set"], self._static_class_setters),
        )
        for table, destination in destinations:
            if table:
                destination[binding] = table
        if constructors:
            self._class_constructors[binding] = constructors

    def _build_scopes(self, ast: dict) -> None:
        self._scopes.append(_Scope(0, None))
        stack = [(ast, self._scopes[0])]
        class_supers: list[tuple[tuple[int, str], int, str]] = []
        n = 0
        while stack:
            node, scope = stack.pop()
            n += 1
            if n > _MAX_WORK:
                self._work_cap_hit = True
                break
            if not isinstance(node, dict):
                continue
            t = node.get("type")
            child = scope
            if t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
                child = _Scope(len(self._scopes), scope)
                self._scopes.append(child)
                self._function_scope_ids.add(child.id)
                self._func_scope[id(node)] = child.id
                self._all_funcs.append(node)
                for p in node.get("params", []) or []:
                    for nm in self._pattern_names(p):
                        child.names.add(nm)
                    for nm in self._event_target_bindings(p):
                        self._event_param_bindings.add((child.id, nm))
                if t != "ArrowFunctionExpression":
                    child.names.add("this")
                fid = node.get("id")
                if isinstance(fid, dict) and fid.get("name"):
                    scope.names.add(fid["name"])
                    self._func_by_name.setdefault(fid["name"].lower(), []).append(node)
                    self._func_by_binding.setdefault((scope.id, fid["name"]), []).append(node)
            elif t in (
                "BlockStatement",
                "CatchClause",
                "SwitchStatement",
                "ForStatement",
                "ForInStatement",
                "ForOfStatement",
            ):
                child = _Scope(len(self._scopes), scope)
                self._scopes.append(child)
                if t == "CatchClause":
                    for nm in self._pattern_names(node.get("param")):
                        child.names.add(nm)

            self._node_scope[id(node)] = child.id

            if t == "VariableDeclaration":
                target = (
                    child
                    if node.get("kind") in ("let", "const")
                    else self._nearest_function_scope(child)
                )
                for decl in node.get("declarations", []) or []:
                    for nm in self._pattern_names(decl.get("id")):
                        target.names.add(nm)
            elif t == "VariableDeclarator":
                init = node.get("init")
                if isinstance(init, dict) and init.get("type") in (
                    "FunctionExpression",
                    "ArrowFunctionExpression",
                ):
                    idn = node.get("id")
                    if isinstance(idn, dict) and idn.get("name"):
                        self._func_by_name.setdefault(idn["name"].lower(), []).append(init)
                        binding_scope = scope.resolve(idn["name"])
                        self._func_by_binding.setdefault(
                            (binding_scope if binding_scope is not None else scope.id, idn["name"]),
                            [],
                        ).append(init)
                elif isinstance(init, dict) and init.get("type") == "ClassExpression":
                    idn = node.get("id") or {}
                    class_name = idn.get("name")
                    if isinstance(class_name, str) and class_name:
                        binding_scope = scope.resolve(class_name)
                        binding = (
                            binding_scope if binding_scope is not None else scope.id,
                            class_name,
                        )
                        self._register_class_members(init, binding)
                        super_class = init.get("superClass") or {}
                        if super_class.get("type") == "Identifier" and super_class.get("name"):
                            class_supers.append(
                                (binding, scope.id, super_class["name"])
                            )
            elif t == "Property":
                val = node.get("value")
                key = node.get("key") or {}
                kn = key.get("name") or (
                    key.get("value") if isinstance(key.get("value"), str) else None
                )
                if (
                    kn
                    and isinstance(val, dict)
                    and val.get("type") in ("FunctionExpression", "ArrowFunctionExpression")
                ):
                    self._func_by_name.setdefault(kn.lower(), []).append(val)
            elif t in ("ClassDeclaration", "ClassExpression"):
                class_id = node.get("id") or {}
                class_name = class_id.get("name")
                if isinstance(class_name, str) and class_name:
                    scope.names.add(class_name)
                    binding = (scope.id, class_name)
                    self._register_class_members(node, binding)
                    super_class = node.get("superClass") or {}
                    if super_class.get("type") == "Identifier" and super_class.get("name"):
                        class_supers.append((binding, scope.id, super_class["name"]))
            for key, value in node.items():
                if key in ("loc", "range", "raw"):
                    continue
                if isinstance(value, dict):
                    stack.append((value, child))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            stack.append((item, child))

        self._class_owner_by_scope = {
            scope_id: owner
            for node_id, owner in self._function_class_owner.items()
            if (scope_id := self._func_scope.get(node_id)) is not None
        }
        for binding, scope_id, super_name in class_supers:
            super_scope = self._scopes[scope_id].resolve(super_name)
            self._class_supers[binding] = (
                super_scope if super_scope is not None else 0,
                super_name,
            )

        for _ in range(len(class_supers) + 1):
            changed = False
            for binding, _, _ in class_supers:
                super_binding = self._class_supers[binding]
                for destination in (
                    self._class_methods,
                    self._class_getters,
                    self._class_setters,
                    self._static_class_methods,
                    self._static_class_getters,
                    self._static_class_setters,
                ):
                    inherited = destination.get(super_binding)
                    if not inherited:
                        continue
                    current = destination.setdefault(binding, {})
                    merged = {**inherited, **current}
                    if merged != current:
                        destination[binding] = merged
                        changed = True
                if binding not in self._class_constructors:
                    inherited_constructors = self._class_constructors.get(super_binding)
                    if inherited_constructors:
                        self._class_constructors[binding] = inherited_constructors
                        changed = True
            if not changed:
                break

    def _nearest_function_scope(self, scope: _Scope) -> _Scope:
        cur = scope
        while cur.parent is not None and cur.id not in self._function_scope_ids:
            cur = cur.parent
        return cur

    def _current_class_owner(
        self, scope: _Scope
    ) -> tuple[tuple[int, str], bool] | None:
        current: _Scope | None = scope
        while current is not None:
            owner = self._class_owner_by_scope.get(current.id)
            if owner is not None:
                return owner
            current = current.parent
        return None

    def _current_this_root(
        self, scope: _Scope, env: dict
    ) -> tuple[int, str] | None:
        marker = env.get(self._binding("this", scope))
        if not isinstance(marker, dict) or marker.get("label") != _OBJECT_REF:
            return None
        root = marker.get("root")
        return root if isinstance(root, tuple) and len(root) == 2 else None

    def _scope_for_node(self, node: Any, fallback: _Scope) -> _Scope:
        sid = self._node_scope.get(id(node)) if isinstance(node, dict) else None
        return self._scopes[sid] if sid is not None else fallback

    def _event_target_bindings(self, pat: Any) -> list[str]:
        """Local names a destructured handler param binds to an event's `target`/`currentTarget`,
        e.g. `({target}) => target.value` binds "target"; `({currentTarget: ct}) => ct.value` binds
        "ct". These are DOM-input roots (DQ-T02 seeding) -- the same naming-convention class as
        `_EVENT_NAMES`, but strictly narrower (requires the exact DOM Event property name as the
        destructure key). Only Identifier values are seeded; nested patterns are left to the
        deferred sound-taint work."""
        out: list[str] = []
        p = pat
        while isinstance(p, dict) and p.get("type") == "AssignmentPattern":
            p = p.get("left")  # unwrap a default value: `({target} = {}) => ...`
        if not (isinstance(p, dict) and p.get("type") == "ObjectPattern"):
            return out
        for prop in p.get("properties", []) or []:
            if prop.get("type") != "Property":
                continue
            key = prop.get("key") or {}
            kn = key.get("name") or (
                key.get("value") if isinstance(key.get("value"), str) else None
            )
            if not kn or kn.lower() not in ("target", "currenttarget"):
                continue
            val = prop.get("value") or {}
            if val.get("type") == "Identifier" and val.get("name"):
                out.append(val["name"])
        return out

    def _pattern_names(self, pat: Any) -> list[str]:
        out: list[str] = []
        stack = [pat]
        d = 0
        while stack and d < 4000:
            d += 1
            p = stack.pop()
            if not isinstance(p, dict):
                continue
            t = p.get("type")
            if t == "Identifier":
                if p.get("name"):
                    out.append(p["name"])
            elif t == "ObjectPattern":
                for prop in p.get("properties", []) or []:
                    stack.append(
                        prop.get("value")
                        if prop.get("type") == "Property"
                        else prop.get("argument")
                    )
            elif t == "ArrayPattern":
                for el in p.get("elements", []) or []:
                    stack.append(el)
            elif t in ("RestElement", "AssignmentPattern"):
                stack.append(p.get("argument") or p.get("left"))
        if stack:
            self._depth_cap_hit = True
        return out

    def _binding(self, name: str, scope: _Scope) -> tuple[int, str]:
        sid = scope.resolve(name)
        return (sid if sid is not None else 0, name)

    def _const_value(
        self, node: Any, scope: _Scope | None = None, env: dict | None = None
    ) -> tuple[bool, Any]:
        """Return a side-effect-free literal value when it can be proven statically."""
        if not isinstance(node, dict):
            return False, None
        t = node.get("type")
        if t == "Literal" and "value" in node:
            return True, node.get("value")
        if t == "Identifier" and scope is not None and env is not None:
            name = node.get("name", "")
            binding = self._binding(name, scope)
            marker = env.get(binding)
            if isinstance(marker, dict) and marker.get("label") == _CONST_VALUE:
                return True, marker.get("value")
            if name == "undefined" and scope.resolve(name) is None:
                return True, None
        if t == "UnaryExpression" and node.get("operator") == "!":
            known, value = self._const_value(node.get("argument"), scope, env)
            return (True, not bool(value)) if known else (False, None)
        if t == "UnaryExpression" and node.get("operator") == "void":
            return True, None
        if t == "UnaryExpression" and node.get("operator") in {"+", "-"}:
            known, value = self._const_value(node.get("argument"), scope, env)
            if known and isinstance(value, (int, float)) and not isinstance(value, bool):
                return True, value if node.get("operator") == "+" else -value
        if t == "BinaryExpression" and node.get("operator") in {"===", "!=="}:
            left_known, left = self._const_value(node.get("left"), scope, env)
            right_known, right = self._const_value(node.get("right"), scope, env)
            if left_known and right_known:
                same = self._strict_literal_key(left) == self._strict_literal_key(right)
                return True, same if node.get("operator") == "===" else not same
        return False, None

    def _const_truth(
        self, node: Any, scope: _Scope | None = None, env: dict | None = None
    ) -> bool | None:
        known, value = self._const_value(node, scope, env)
        return bool(value) if known else None

    # ------------------------------------------------------------ function analysis (flow-sensitive)

    def _run_function(
        self,
        fnode: dict,
        fsid: int,
        seed_env: dict,
        depth: int,
        effect_env: dict | None = None,
        abrupt_target: list[_AbruptState] | None = None,
        yield_target: list[dict | None] | None = None,
    ) -> dict | None:
        """Analyze a function body with `seed_env` (inherited closure env + seeded params), in
        source order (flow-sensitive). Returns the function's return taint. Re-entrancy guard."""
        if depth > 30:
            self._depth_cap_hit = True
            return None
        if self._work > _MAX_WORK:
            self._work_cap_hit = True
            return None
        if fsid in self._analyzing:
            self._recursion_hit = True
            return None
        scope = self._scopes[fsid]
        env = dict(seed_env)
        body = fnode if fnode.get("type") == "Program" else fnode.get("body")
        self._analyzing.add(fsid)
        self._abrupt_frames.append(abrupt_target)
        if yield_target is not None:
            self._yield_frames.append(yield_target)
        try:
            # arrow with expression body -> the body IS the return expression
            if isinstance(body, dict) and body.get("type") not in ("BlockStatement", "Program"):
                return self._expression_value(body, scope, env, depth)
            return self._exec(body, scope, env, depth)
        finally:
            if yield_target is not None:
                self._yield_frames.pop()
            self._abrupt_frames.pop()
            self._analyzing.discard(fsid)
            if effect_env is not None:
                effect_env.clear()
                effect_env.update(env)

    def _exec(self, node: Any, scope: _Scope, env: dict, depth: int) -> dict | None:
        """Execute a statement/block in order, mutating env; returns any return taint."""
        if not isinstance(node, dict):
            return None
        if depth > _MAX_DEPTH:
            self._depth_cap_hit = True
            return None
        self._work += 1
        if self._work > _MAX_WORK:
            self._work_cap_hit = True
            return None
        t = node.get("type")
        scope = self._scope_for_node(node, scope)

        if t in ("Program", "BlockStatement"):
            ret = None
            for s in node.get("body", []) or []:
                r = self._exec(s, scope, env, depth)
                if r is not None:
                    ret = r
                # DQ-C03: statements after a statement that ALWAYS diverges are UNREACHABLE, so an
                # unreachable sink (e.g. `return; el.innerHTML=x`, or a sink after an if whose BOTH
                # branches return, or after a try whose paths all diverge) must not be analyzed as a
                # reachable -- and thus falsely "confirmed" -- flow. `_always_diverges` is conservative
                # (only stops when every path provably diverges), so it never drops a reachable sink.
                if self._always_diverges(s):
                    break
            return ret
        if t == "VariableDeclaration":
            for d in node.get("declarations", []) or []:
                self._exec_declarator(d, scope, env, depth)
            return None
        if t == "ExpressionStatement":
            self._eval(node.get("expression"), scope, env, depth)
            return None
        if t == "ReturnStatement":
            arg = node.get("argument")
            result = (
                self._expression_value(arg, scope, env, depth)
                if isinstance(arg, dict)
                else None
            )
            self._capture_abrupt_state(
                "return",
                env,
                result or {"label": _CLEAN_VALUE, "line": _line_of(node)},
            )
            return result
        if t == "IfStatement":
            # Fork the env per branch and UNION at the join -- mutually-exclusive branches must
            # not share taint (else the if-branch's taint leaks into the else-branch's sink).
            self._eval(node.get("test"), scope, env, depth)
            truth = self._const_truth(node.get("test"), scope, env)
            if truth is True:
                return self._exec(node.get("consequent"), scope, env, depth)
            if truth is False:
                return self._exec(node.get("alternate"), scope, env, depth)
            then_condition = self._branch_condition(node.get("test"), scope, True)
            else_condition = self._branch_condition(node.get("test"), scope, False)
            then_feasible = self._condition_is_feasible(then_condition, env)
            else_feasible = self._condition_is_feasible(else_condition, env)
            env_then = self._env_for_condition(env, then_condition)
            env_else = self._env_for_condition(env, else_condition)
            r1 = r2 = None
            self._approx += 1
            try:
                if then_feasible:
                    if then_condition is not None:
                        self._path_conditions.append({then_condition[0]: then_condition[1]})
                    try:
                        r1 = self._tag_current_conditions(
                            self._exec(node.get("consequent"), scope, env_then, depth), env_then
                        )
                    finally:
                        if then_condition is not None:
                            self._path_conditions.pop()
                if else_feasible:
                    if else_condition is not None:
                        self._path_conditions.append({else_condition[0]: else_condition[1]})
                    try:
                        r2 = self._tag_current_conditions(
                            self._exec(node.get("alternate"), scope, env_else, depth), env_else
                        )
                    finally:
                        if else_condition is not None:
                            self._path_conditions.pop()
            finally:
                self._approx -= 1
            join_envs = []
            if then_feasible and not self._always_diverges(node.get("consequent")):
                join_envs.append(env_then)
            alternate = node.get("alternate")
            if else_feasible and (
                not isinstance(alternate, dict) or not self._always_diverges(alternate)
            ):
                join_envs.append(env_else)
            if join_envs:
                self._merge_env(env, *join_envs)
            else:
                env.clear()
            return r1 or r2
        if t in (
            "ForStatement",
            "ForInStatement",
            "ForOfStatement",
            "WhileStatement",
            "DoWhileStatement",
        ):
            exact_forof_values: list[dict | None] | None = None
            iterable_value: dict | None = None
            if t == "ForStatement":
                init = node.get("init")
                if isinstance(init, dict):
                    (self._exec if init.get("type") == "VariableDeclaration" else self._eval)(
                        init, scope, env, depth
                    )
                test = node.get("test")
                if isinstance(test, dict):
                    self._eval(test, scope, env, depth)
                    if self._const_truth(test, scope, env) is False:
                        return None
            elif t in ("ForInStatement", "ForOfStatement"):
                right = node.get("right")
                if isinstance(right, dict):
                    if t == "ForOfStatement":
                        exact_forof_values = self._exact_iterable_values(
                            right, scope, env, depth
                        )
                    if exact_forof_values is None:
                        iterable_value = self._eval(right, scope, env, depth)
                left = node.get("left")
                if isinstance(left, dict):
                    if exact_forof_values is not None:
                        if not exact_forof_values:
                            return None
                    else:
                        (
                            self._exec
                            if left.get("type") == "VariableDeclaration"
                            else self._eval
                        )(left, scope, env, depth)
                        if (
                            t == "ForOfStatement"
                            and isinstance(iterable_value, dict)
                            and iterable_value.get("label") not in _STATE_LABELS
                        ):
                            self._assign_loop_target(
                                left,
                                {
                                    **iterable_value,
                                    "step": "iterable element",
                                    "approx": True,
                                },
                                scope,
                                env,
                                depth,
                            )
            elif t == "WhileStatement":
                test = node.get("test")
                if isinstance(test, dict):
                    self._eval(test, scope, env, depth)
                    if self._const_truth(test, scope, env) is False:
                        return None
            if exact_forof_values is not None:
                left = node.get("left") or {}
                body = node.get("body") or {}
                if node.get("await"):
                    awaited_values: list[dict | None] = []
                    for exact_value in exact_forof_values:
                        if (
                            isinstance(exact_value, dict)
                            and exact_value.get("label") == _PROMISE_REF
                        ):
                            if exact_value.get("rejected"):
                                rejected_value = exact_value.get("rejected_value")
                                self._capture_exception_state(
                                    env,
                                    approximate=bool(exact_value.get("fulfilled")),
                                    value=(
                                        rejected_value
                                        if isinstance(rejected_value, dict)
                                        else None
                                    ),
                                )
                            fulfilled_value = exact_value.get("fulfilled_value")
                            awaited_values.append(
                                fulfilled_value
                                if exact_value.get("fulfilled")
                                and isinstance(fulfilled_value, dict)
                                else {
                                    "label": _CLEAN_VALUE,
                                    "line": _line_of(node),
                                }
                            )
                        else:
                            awaited_values.append(exact_value)
                    exact_forof_values = awaited_values
                if self._control_outcomes(body) == {"normal"}:
                    for element in exact_forof_values:
                        self._assign_loop_target(left, element, scope, env, depth)
                        self._exec(body, scope, env, depth)
                    return None
                self._assign_loop_target(
                    left,
                    self._merge_promise_values(exact_forof_values),
                    scope,
                    env,
                    depth,
                )
            # Compute a bounded reaching-definition fixed point over the loop backedge. Findings
            # inside a loop remain probable because exact iteration predicates are not modeled, but
            # a flow that first appears on iteration 2+ must not be lost.
            pre_body = dict(env)
            entry_env = dict(env)
            exit_states: list[dict] = []
            converged = False
            test = node.get("test")
            condition_can_exit = t in ("ForInStatement", "ForOfStatement")
            if t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
                condition_can_exit = (
                    isinstance(test, dict) and self._const_truth(test, scope, env) is not True
                )
            for _ in range(_MAX_LOOP_ITERATIONS):
                body_env = dict(entry_env)
                break_envs: list[dict] = []
                self._break_frames.append(break_envs)
                self._approx += 1
                try:
                    self._exec(node.get("body"), scope, body_env, depth)
                    if (
                        t == "ForStatement"
                        and isinstance(node.get("update"), dict)
                        and not self._always_diverges(node.get("body"))
                    ):
                        self._eval(node.get("update"), scope, body_env, depth)
                    if t == "DoWhileStatement" and isinstance(node.get("test"), dict):
                        self._eval(node.get("test"), scope, body_env, depth)
                finally:
                    self._approx -= 1
                    self._break_frames.pop()
                exit_states.extend(break_envs)
                if condition_can_exit:
                    exit_states.append(body_env)
                if self._always_diverges(node.get("body")):
                    converged = True
                    break
                next_entry: dict = {}
                self._merge_env(next_entry, entry_env, body_env)
                if next_entry == entry_env:
                    converged = True
                    break
                entry_env = next_entry
            if not converged:
                self._loop_cap_hit = True
            zero_iteration = (
                t != "DoWhileStatement"
                and condition_can_exit
                and exact_forof_values is None
            )
            possible_exits = ([pre_body] if zero_iteration else []) + exit_states
            if possible_exits:
                self._merge_env(env, *possible_exits)
            else:
                env.clear()
            for k, v in list(env.items()):
                if (
                    isinstance(v, dict)
                    and v.get("label")
                    not in {
                        _OBJECT_REF,
                        _CONST_VALUE,
                        _READER_OBJ,
                        _JQUERY_OBJ,
                        _PATH_CONDITION,
                        _PATH_INVALIDATED,
                    }
                    and pre_body.get(k) != v
                    and not v.get("approx")
                ):
                    env[k] = {**v, "approx": True}
            return None
        if t == "TryStatement":
            pre = dict(env)
            normal_env = dict(pre)
            exception_envs: list[dict] = []
            block_abrupt: list[_AbruptState] = []
            block_breaks: list[dict] = []
            self._exception_frames.append(exception_envs)
            self._abrupt_frames.append(block_abrupt)
            self._break_frames.append(block_breaks)
            try:
                self._exec(node.get("block"), scope, normal_env, depth)
            finally:
                self._break_frames.pop()
                self._abrupt_frames.pop()
                self._exception_frames.pop()
            h = node.get("handler")
            outcomes: list[dict] = []
            handler_abrupt: list[_AbruptState] = []
            if not self._always_diverges(node.get("block")):
                outcomes.append(normal_env)
            if isinstance(h, dict):
                for exception_env in exception_envs:
                    env_catch = dict(exception_env)
                    caught_value = env_catch.pop(_EXCEPTION_VALUE_KEY, None)
                    catch_scope = self._scope_for_node(h, scope)
                    catch_param = h.get("param") or {}
                    if isinstance(catch_param, dict):
                        if catch_param.get("type") in {
                            "ObjectPattern",
                            "ArrayPattern",
                            "AssignmentPattern",
                        }:
                            self._assign_destructure(
                                catch_param,
                                caught_value,
                                catch_scope,
                                env_catch,
                                depth + 1,
                            )
                        else:
                            self._assign_pattern(
                                catch_param,
                                caught_value
                                if isinstance(caught_value, dict)
                                else {
                                    "label": _CLEAN_VALUE,
                                    "line": _line_of(catch_param),
                                },
                                catch_scope,
                                env_catch,
                            )
                    caught_exceptions: list[dict] = []
                    caught_breaks: list[dict] = []
                    current_abrupt: list[_AbruptState] = []
                    self._exception_frames.append(caught_exceptions)
                    self._abrupt_frames.append(current_abrupt)
                    self._break_frames.append(caught_breaks)
                    try:
                        self._exec(h.get("body"), scope, env_catch, depth)
                    finally:
                        self._break_frames.pop()
                        self._abrupt_frames.pop()
                        self._exception_frames.pop()
                    handler_abrupt.extend(current_abrupt)
                    for escaped in caught_exceptions:
                        escaped_env = dict(escaped)
                        escaped_value = escaped_env.pop(_EXCEPTION_VALUE_KEY, None)
                        item: _AbruptState = (
                            "throw",
                            escaped_env,
                            escaped_value if isinstance(escaped_value, dict) else None,
                        )
                        if item not in handler_abrupt:
                            handler_abrupt.append(item)
                    if not self._always_diverges(h.get("body")):
                        outcomes.append(env_catch)
            abrupt = [
                item
                for item in block_abrupt
                if not (isinstance(h, dict) and item[0] == "throw")
            ]
            abrupt.extend(handler_abrupt)
            if not isinstance(h, dict):
                for escaped in exception_envs:
                    escaped_env = dict(escaped)
                    escaped_value = escaped_env.pop(_EXCEPTION_VALUE_KEY, None)
                    item = (
                        "throw",
                        escaped_env,
                        escaped_value if isinstance(escaped_value, dict) else None,
                    )
                    if item not in abrupt:
                        abrupt.append(item)
            finalizer = node.get("finalizer")
            final_outcomes: list[dict] = []
            resulting_abrupt: list[_AbruptState] = []
            if isinstance(finalizer, dict):
                def apply_finalizer(start_env: dict) -> tuple[dict, list[_AbruptState], bool]:
                    final_env = dict(start_env)
                    final_abrupt: list[_AbruptState] = []
                    final_exceptions: list[dict] = []
                    final_breaks: list[dict] = []
                    self._exception_frames.append(final_exceptions)
                    self._abrupt_frames.append(final_abrupt)
                    self._break_frames.append(final_breaks)
                    try:
                        self._exec(finalizer, scope, final_env, depth)
                    finally:
                        self._break_frames.pop()
                        self._abrupt_frames.pop()
                        self._exception_frames.pop()
                    for escaped in final_exceptions:
                        escaped_env = dict(escaped)
                        escaped_value = escaped_env.pop(_EXCEPTION_VALUE_KEY, None)
                        item: _AbruptState = (
                            "throw",
                            escaped_env,
                            escaped_value if isinstance(escaped_value, dict) else None,
                        )
                        if item not in final_abrupt:
                            final_abrupt.append(item)
                    return final_env, final_abrupt, not self._always_diverges_in_env(
                        finalizer, scope, start_env
                    )

                for outcome in outcomes:
                    final_env, final_abrupt, completes = apply_finalizer(outcome)
                    resulting_abrupt.extend(
                        item for item in final_abrupt if item not in resulting_abrupt
                    )
                    if completes:
                        final_outcomes.append(final_env)
                for kind, abrupt_env, value in abrupt:
                    final_env, final_abrupt, completes = apply_finalizer(abrupt_env)
                    resulting_abrupt.extend(
                        item for item in final_abrupt if item not in resulting_abrupt
                    )
                    if completes:
                        item = (kind, final_env, value)
                        if item not in resulting_abrupt:
                            resulting_abrupt.append(item)
            else:
                final_outcomes = outcomes
                resulting_abrupt = abrupt
            for kind, abrupt_env, value in resulting_abrupt:
                self._capture_abrupt_state(kind, abrupt_env, value)
                if kind == "break" and self._break_frames:
                    if abrupt_env not in self._break_frames[-1]:
                        self._break_frames[-1].append(abrupt_env)
                elif kind == "throw":
                    self._capture_exception_state(
                        abrupt_env, approximate=False, value=value
                    )
            if final_outcomes:
                self._merge_env(env, *final_outcomes)
            else:
                env.clear()
            return_values: list[dict[str, Any] | None] = [
                dict(value)
                for kind, _, value in resulting_abrupt
                if kind == "return"
                and isinstance(value, dict)
                and value.get("label") not in {_CLEAN_VALUE, _CONST_VALUE}
            ]
            taint_return = self._combine_concat_taint(return_values)
            return taint_return or (return_values[0] if return_values else None)
        if t == "SwitchStatement":
            # Analyze every possible case-entry path, respecting fallthrough and stopping at an
            # unlabeled break/return/throw. Unknown dispatch is conditional evidence, never a
            # confirmed path.
            self._eval(node.get("discriminant"), scope, env, depth)
            case_envs = []
            cases = [c for c in (node.get("cases") or []) if isinstance(c, dict)]
            known_disc, disc_value = self._const_value(node.get("discriminant"), scope, env)
            starts: list[int] = []
            if known_disc:
                default_idx = None
                for idx, case in enumerate(cases):
                    if case.get("test") is None:
                        default_idx = idx
                        continue
                    known_case, case_value = self._const_value(case.get("test"), scope, env)
                    if known_case and case_value == disc_value:
                        starts = [idx]
                        break
                if not starts and default_idx is not None:
                    starts = [default_idx]
            else:
                starts = list(range(len(cases)))
            for start in starts:
                ce = dict(env)
                switch_break_envs: list[dict] = []
                self._break_frames.append(switch_break_envs)
                if not known_disc:
                    self._approx += 1
                try:
                    stop = False
                    completes = True
                    for case in cases[start:]:
                        for s in case.get("consequent", []) or []:
                            if s.get("type") == "BreakStatement" and not s.get("label"):
                                stop = True
                                break
                            self._exec(s, scope, ce, depth)
                            if self._always_diverges(s):
                                stop = True
                                completes = False
                                break
                        if stop:
                            break
                finally:
                    if not known_disc:
                        self._approx -= 1
                    self._break_frames.pop()
                case_envs.extend(switch_break_envs)
                if completes:
                    case_envs.append(ce)
            if not known_disc and not any(c.get("test") is None for c in cases):
                case_envs.append(dict(env))
            if case_envs:
                self._merge_env(env, *case_envs)
            return None
        if t in ("LabeledStatement", "WithStatement"):
            return self._exec(node.get("body"), scope, env, depth)
        if t == "FunctionDeclaration":
            return None  # analyzed as its own entry point / at call sites
        if t == "BreakStatement":
            if self._break_frames:
                snapshot = dict(env)
                if snapshot not in self._break_frames[-1]:
                    self._break_frames[-1].append(snapshot)
            self._capture_abrupt_state("break", env)
            return None
        if t == "ContinueStatement":
            self._capture_abrupt_state("continue", env)
            return None
        # ThrowStatement / others: evaluate embedded expression to catch nested sinks
        if t == "ThrowStatement":
            thrown = self._expression_value(node.get("argument"), scope, env, depth)
            self._capture_exception_state(env, approximate=False, value=thrown)
            self._capture_abrupt_state("throw", env, thrown)
        return None

    def _capture_abrupt_state(
        self, kind: str, env: dict, value: dict | None = None
    ) -> None:
        if not self._abrupt_frames or self._abrupt_frames[-1] is None:
            return
        frame = self._abrupt_frames[-1]
        if frame is not None:
            item = (kind, dict(env), value)
            if item not in frame:
                frame.append(item)

    def _capture_exception_state(
        self,
        env: dict,
        *,
        approximate: bool = True,
        value: dict | None = None,
    ) -> None:
        if not self._exception_frames:
            return
        frame = self._exception_frames[-1]
        if len(frame) >= _MAX_EXCEPTION_STATES:
            self._exception_cap_hit = True
            return
        marker_labels = {
            _OBJECT_REF,
            _CONST_VALUE,
            _READER_OBJ,
            _JQUERY_OBJ,
            _PATH_CONDITION,
            _PATH_INVALIDATED,
        }
        snapshot = {
            key: (
                {**value, "approx": True}
                if approximate
                and isinstance(value, dict)
                and value.get("label") not in marker_labels
                and not value.get("approx")
                else value
            )
            for key, value in env.items()
        }
        if value is not None:
            snapshot[_EXCEPTION_VALUE_KEY] = (
                {**value, "approx": True}
                if approximate
                and value.get("label") not in marker_labels
                and not value.get("approx")
                else value
            )
        if snapshot not in frame:
            frame.append(snapshot)

    def _always_diverges(self, node: Any, depth: int = 0) -> bool:
        """Conservative 'this statement never completes normally' (every path returns/throws/breaks/
        continues). Used to stop analyzing statements AFTER it in a block as unreachable (DQ-C03).
        Returns True only when SURE, so a reachable sink is never dropped."""
        if depth > 50:
            self._depth_cap_hit = True
            return False
        if not isinstance(node, dict):
            return False
        t = node.get("type")
        if t in ("ReturnStatement", "ThrowStatement", "BreakStatement", "ContinueStatement"):
            return True
        if t in ("BlockStatement", "Program"):
            return any(self._always_diverges(s, depth + 1) for s in node.get("body", []) or [])
        if t == "IfStatement":
            alt = node.get("alternate")
            truth = self._const_truth(node.get("test"))
            if truth is True:
                return self._always_diverges(node.get("consequent"), depth + 1)
            if truth is False:
                return self._always_diverges(alt, depth + 1)
            # unreachable-after only when BOTH branches provably diverge (a one-armed / one-diverging
            # if can fall through, so the following sink stays reachable).
            return (
                isinstance(alt, dict)
                and self._always_diverges(node.get("consequent"), depth + 1)
                and self._always_diverges(alt, depth + 1)
            )
        if t == "TryStatement":
            fin = node.get("finalizer")
            if isinstance(fin, dict) and self._always_diverges(fin, depth + 1):
                return True  # finally runs on every path and diverges
            h = node.get("handler")
            handler_div = (not isinstance(h, dict)) or self._always_diverges(
                h.get("body"), depth + 1
            )
            return self._always_diverges(node.get("block"), depth + 1) and handler_div
        if t == "SwitchStatement":
            return "normal" not in self._control_outcomes(node, depth + 1)
        if t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
            test = node.get("test")
            always_true = t == "ForStatement" and not isinstance(test, dict)
            if isinstance(test, dict):
                always_true = self._const_truth(test) is True
            return always_true and not self._has_own_loop_break(node.get("body"), depth + 1)
        if t in ("LabeledStatement", "WithStatement"):
            return self._always_diverges(node.get("body"), depth + 1)
        return False

    def _always_diverges_in_env(
        self, node: Any, scope: _Scope, env: dict, depth: int = 0
    ) -> bool:
        if depth > 50:
            self._depth_cap_hit = True
            return False
        if not isinstance(node, dict):
            return False
        scope = self._scope_for_node(node, scope)
        t = node.get("type")
        if t in ("BlockStatement", "Program"):
            return any(
                self._always_diverges_in_env(statement, scope, env, depth + 1)
                for statement in node.get("body", []) or []
            )
        if t == "IfStatement":
            truth = self._const_truth(node.get("test"), scope, env)
            if truth is True:
                return self._always_diverges_in_env(
                    node.get("consequent"), scope, env, depth + 1
                )
            if truth is False:
                return self._always_diverges_in_env(node.get("alternate"), scope, env, depth + 1)
        return self._always_diverges(node, depth)

    def _has_own_loop_break(self, node: Any, depth: int = 0) -> bool:
        if depth > 50:
            self._depth_cap_hit = True
            return False
        if not isinstance(node, dict):
            return False
        t = node.get("type")
        if t == "BreakStatement":
            return True
        if t in (
            "ForStatement",
            "ForInStatement",
            "ForOfStatement",
            "WhileStatement",
            "DoWhileStatement",
            "SwitchStatement",
            "FunctionDeclaration",
            "FunctionExpression",
            "ArrowFunctionExpression",
        ):
            return False
        for key, value in node.items():
            if key in ("loc", "range", "raw"):
                continue
            if isinstance(value, dict) and self._has_own_loop_break(value, depth + 1):
                return True
            if isinstance(value, list) and any(
                self._has_own_loop_break(item, depth + 1)
                for item in value
                if isinstance(item, dict)
            ):
                return True
        return False

    def _control_outcomes(self, node: Any, depth: int = 0) -> set[str]:
        """Bounded statement completion kinds used to keep divergent states out of joins."""
        if depth > 50:
            self._depth_cap_hit = True
            return {"normal"}
        if not isinstance(node, dict):
            return {"normal"}
        t = node.get("type")
        terminal = {
            "ReturnStatement": "return",
            "ThrowStatement": "throw",
            "BreakStatement": "break",
            "ContinueStatement": "continue",
        }
        if t in terminal:
            return {terminal[t]}
        if t in ("Program", "BlockStatement"):
            outcomes = {"normal"}
            for statement in node.get("body", []) or []:
                next_outcomes = outcomes - {"normal"}
                if "normal" in outcomes:
                    next_outcomes.update(self._control_outcomes(statement, depth + 1))
                outcomes = next_outcomes
            return outcomes
        if t == "IfStatement":
            truth = self._const_truth(node.get("test"))
            if truth is True:
                return self._control_outcomes(node.get("consequent"), depth + 1)
            if truth is False:
                return self._control_outcomes(node.get("alternate"), depth + 1)
            consequent = self._control_outcomes(node.get("consequent"), depth + 1)
            alternate = (
                self._control_outcomes(node.get("alternate"), depth + 1)
                if isinstance(node.get("alternate"), dict)
                else {"normal"}
            )
            return consequent | alternate
        if t == "SwitchStatement":
            cases = [case for case in (node.get("cases") or []) if isinstance(case, dict)]
            known, discriminant = self._const_value(node.get("discriminant"))
            starts: list[int] = []
            default_index = next(
                (index for index, case in enumerate(cases) if case.get("test") is None), None
            )
            if known:
                for index, case in enumerate(cases):
                    if case.get("test") is None:
                        continue
                    case_known, case_value = self._const_value(case.get("test"))
                    if case_known and case_value == discriminant:
                        starts = [index]
                        break
                if not starts and default_index is not None:
                    starts = [default_index]
            else:
                starts = list(range(len(cases)))
            switch_outcomes: set[str] = set()
            for start in starts:
                path = {"normal"}
                for case in cases[start:]:
                    for statement in case.get("consequent", []) or []:
                        next_path = path - {"normal"}
                        if "normal" in path:
                            next_path.update(self._control_outcomes(statement, depth + 1))
                        path = next_path
                switch_outcomes.update("normal" if item == "break" else item for item in path)
            if (not known and default_index is None) or (known and not starts):
                switch_outcomes.add("normal")
            return switch_outcomes or {"normal"}
        if t == "TryStatement":
            outcomes = self._control_outcomes(node.get("block"), depth + 1)
            handler = node.get("handler")
            if isinstance(handler, dict) and "throw" in outcomes:
                outcomes = (outcomes - {"throw"}) | self._control_outcomes(
                    handler.get("body"), depth + 1
                )
            finalizer = node.get("finalizer")
            if isinstance(finalizer, dict):
                final_outcomes = self._control_outcomes(finalizer, depth + 1)
                if final_outcomes != {"normal"}:
                    outcomes = (outcomes if "normal" in final_outcomes else set()) | (
                        final_outcomes - {"normal"}
                    )
            return outcomes
        if t in ("LabeledStatement", "WithStatement"):
            return self._control_outcomes(node.get("body"), depth + 1)
        return {"normal"}

    def _has_own_switch_break(self, node: Any, depth: int = 0) -> bool:
        """True if `node` contains an unlabeled `break` that would exit the ENCLOSING switch -- i.e.
        one NOT captured by a nested loop/switch/function. Used to tell whether a switch can complete
        normally (a break resumes control after the switch)."""
        if depth > 50:
            self._depth_cap_hit = True
            return False
        if not isinstance(node, dict):
            return False
        t = node.get("type")
        if t == "BreakStatement" and not node.get("label"):
            return True
        if t in (
            "ForStatement",
            "ForInStatement",
            "ForOfStatement",
            "WhileStatement",
            "DoWhileStatement",
            "SwitchStatement",
            "FunctionDeclaration",
            "FunctionExpression",
            "ArrowFunctionExpression",
        ):
            return False  # a break here targets THIS nested construct, not our switch
        for k, v in node.items():
            if k in ("loc", "range", "raw"):
                continue
            if isinstance(v, dict) and self._has_own_switch_break(v, depth + 1):
                return True
            if isinstance(v, list):
                for it in v:
                    if isinstance(it, dict) and self._has_own_switch_break(it, depth + 1):
                        return True
        return False

    def _exec_declarator(self, d: dict, scope: _Scope, env: dict, depth: int) -> None:
        idn = d.get("id")
        init = d.get("init")
        if not isinstance(idn, dict):
            return
        if init is None:
            for nm in self._pattern_names(idn):
                env[self._binding(nm, scope)] = {
                    "label": _CONST_VALUE,
                    "value": None,
                    "line": _line_of(d),
                }
            return
        if (
            idn.get("type") == "Identifier"
            and isinstance(idn.get("name"), str)
            and idn["name"][:1].isupper()
            and isinstance(init, dict)
            and init.get("type") in ("FunctionExpression", "ArrowFunctionExpression")
            and isinstance(init.get("body"), dict)
            and init["body"].get("securityProjections")
        ):
            # JSX component bodies are framework entry points. Analyze their explicit security
            # projections with the declaration-time closure, without executing arbitrary dormant
            # function literals during initializer traversal.
            self._run_callback(init, {}, scope, env, depth)
        if isinstance(init, dict) and init.get("type") in (
            "FunctionExpression",
            "ArrowFunctionExpression",
        ):
            self._assign_pattern(idn, self._function_value(init, env), scope, env)
            return
        if (
            isinstance(init, dict)
            and init.get("type") == "NewExpression"
            and (init.get("callee") or {}).get("type") == "Identifier"
            and (init.get("callee") or {}).get("name") == "Promise"
            and scope.resolve("Promise") is None
        ):
            promise_state = self._promise_state(init, scope, env, depth)
            self._assign_pattern(idn, promise_state, scope, env)
            return
        if idn.get("type") in ("ObjectPattern", "ArrayPattern"):
            if self._assign_destructure(idn, init, scope, env, depth):
                return
        # track `x = new FileReader()`
        if isinstance(init, dict) and init.get("type") == "NewExpression":
            callee = init.get("callee") or {}
            if callee.get("name") == "FileReader" and idn.get("type") == "Identifier":
                env[self._binding(idn["name"], scope)] = {"label": _READER_OBJ, "line": _line_of(d)}
                return
        if (
            idn.get("type") == "Identifier"
            and isinstance(init, dict)
            and init.get("type") == "NewExpression"
        ):
            binding = self._binding(idn["name"], scope)
            marker = self._eval(init, scope, env, depth)
            self._reset_object_binding(binding, env)
            self._assign_pattern(idn, marker, scope, env)
            return
        if (
            idn.get("type") == "Identifier"
            and isinstance(init, dict)
            and init.get("type") in ("ObjectExpression", "ArrayExpression")
        ):
            binding = self._binding(idn["name"], scope)
            root = self._new_heap_root()
            self._reset_object_binding(binding, env)
            env[binding] = {
                "label": _OBJECT_REF,
                "root": root,
                "container": "array" if init.get("type") == "ArrayExpression" else "object",
                "line": _line_of(d),
            }
            self._bind_heap_literal(root, init, scope, env, depth)
            self._register_literal_methods(root, init)
            return
        if (
            idn.get("type") == "Identifier"
            and isinstance(init, dict)
            and init.get("type") == "Identifier"
        ):
            source = env.get(self._binding(init.get("name", ""), scope))
            if source and source.get("label") == _OBJECT_REF:
                env[self._binding(idn["name"], scope)] = dict(source)
                return
        if (
            idn.get("type") == "Identifier"
            and isinstance(init, dict)
            and init.get("type") == "Literal"
            and self._strict_literal_key(init.get("value")) is not None
        ):
            env[self._binding(idn["name"], scope)] = {
                "label": _CONST_VALUE,
                "value": init.get("value"),
                "line": _line_of(d),
            }
            return
        rt = self._eval(init, scope, env, depth)
        # DQ-T02: track `x = $(...)` / `jQuery(...)` (non-tainted selector) so a later x.val()/x.data()
        # is recognized as a jQuery form-input source. A tainted-arg $(...) keeps its taint via rt.
        if (
            rt is None
            and idn.get("type") == "Identifier"
            and isinstance(init, dict)
            and init.get("type") == "CallExpression"
            and _member_root_name(init.get("callee")) in ("$", "jquery")
        ):
            env[self._binding(idn["name"], scope)] = {"label": _JQUERY_OBJ, "line": _line_of(d)}
            return
        self._assign_pattern(idn, rt, scope, env)

    @staticmethod
    def _path_atom_binding(atom: _PathAtom) -> tuple[int, str] | None:
        if (
            len(atom) >= 3
            and atom[0] in {"truthy", "strict_eq", "typeof"}
            and isinstance(atom[1], int)
            and isinstance(atom[2], str)
        ):
            return atom[1], atom[2]
        return None

    @staticmethod
    def _strict_literal_key(value: Any) -> tuple[str, Any] | None:
        if value is None:
            return "null", None
        if isinstance(value, bool):
            return "boolean", value
        if isinstance(value, str):
            return "string", value
        if isinstance(value, (int, float)) and value == value:
            return "number", value
        return None

    @staticmethod
    def _literal_js_type(atom: _PathAtom) -> str | None:
        if len(atom) != 5 or atom[0] != "strict_eq":
            return None
        literal_type = atom[3]
        if isinstance(literal_type, str) and literal_type in {"boolean", "string", "number"}:
            return literal_type
        if literal_type == "null":
            return "object"
        return None

    @classmethod
    def _conditions_conflict(
        cls, left: dict[_PathAtom, bool], right: dict[_PathAtom, bool]
    ) -> bool:
        for atom, required in left.items():
            if atom in right and right[atom] != required:
                return True

        left_true = [atom for atom, required in left.items() if required]
        right_true = [atom for atom, required in right.items() if required]
        for first in left_true:
            first_binding = cls._path_atom_binding(first)
            if first_binding is None:
                continue
            for second in right_true:
                if cls._path_atom_binding(second) != first_binding:
                    continue
                if first[0] == second[0] == "strict_eq" and first[3:] != second[3:]:
                    return True
                if first[0] == second[0] == "typeof" and first[3:] != second[3:]:
                    return True
                strict_atom = first if first[0] == "strict_eq" else second
                typeof_atom = first if first[0] == "typeof" else second
                if strict_atom[0] == "strict_eq" and typeof_atom[0] == "typeof":
                    literal_type = cls._literal_js_type(strict_atom)
                    if literal_type is not None and literal_type != typeof_atom[3]:
                        return True

        combined = {**left, **right}
        for atom, required in combined.items():
            if atom[0] != "strict_eq" or not required:
                continue
            binding = cls._path_atom_binding(atom)
            literal_truth = bool(atom[4])
            truth_atom: _PathAtom = ("truthy", *binding) if binding is not None else ()
            if truth_atom in combined and combined[truth_atom] != literal_truth:
                return True
        return False

    def _current_conditions(self, env: dict | None = None) -> dict[_PathAtom, bool]:
        current: dict[_PathAtom, bool] = {}
        invalidated: set[tuple[int, str]] = set()
        if env is not None:
            markers = [marker for marker in env.values() if isinstance(marker, dict)]
            invalidated.update(
                binding
                for marker in markers
                if marker.get("label") == _PATH_INVALIDATED
                and isinstance((binding := marker.get("binding")), tuple)
                and len(binding) == 2
            )
            for marker in markers:
                atom = marker.get("atom")
                if (
                    marker.get("label") == _PATH_CONDITION
                    and isinstance(atom, tuple)
                    and isinstance(marker.get("value"), bool)
                    and self._path_atom_binding(atom) not in invalidated
                ):
                    current[atom] = marker["value"]
        for layer in self._path_conditions:
            current.update(
                {
                    atom: value
                    for atom, value in layer.items()
                    if self._path_atom_binding(atom) not in invalidated
                }
            )
        return current

    def _branch_condition(
        self, node: Any, scope: _Scope, truth: bool
    ) -> tuple[_PathAtom, bool] | None:
        negate = False
        current = node
        while isinstance(current, dict) and current.get("type") == "UnaryExpression":
            if current.get("operator") != "!":
                return None
            negate = not negate
            current = current.get("argument")
        if not isinstance(current, dict):
            return None
        required = not truth if negate else truth
        if current.get("type") == "Identifier":
            binding = self._binding(current.get("name", ""), scope)
            return ("truthy", *binding), required
        if current.get("type") != "BinaryExpression":
            return None
        operator = current.get("operator")
        if operator not in {"===", "!=="}:
            return None
        if operator == "!==":
            required = not required
        left = current.get("left") or {}
        right = current.get("right") or {}

        typeof_node = None
        type_node = None
        if left.get("type") == "UnaryExpression" and left.get("operator") == "typeof":
            typeof_node, type_node = left.get("argument"), right
        elif right.get("type") == "UnaryExpression" and right.get("operator") == "typeof":
            typeof_node, type_node = right.get("argument"), left
        if isinstance(typeof_node, dict) and typeof_node.get("type") == "Identifier":
            known, type_name = self._const_value(type_node)
            if known and isinstance(type_name, str):
                binding = self._binding(typeof_node.get("name", ""), scope)
                return ("typeof", *binding, type_name), required

        identifier = left if left.get("type") == "Identifier" else right
        literal = right if identifier is left else left
        if not isinstance(identifier, dict) or identifier.get("type") != "Identifier":
            return None
        known, value = self._const_value(literal)
        literal_key = self._strict_literal_key(value) if known else None
        if literal_key is None:
            return None
        binding = self._binding(identifier.get("name", ""), scope)
        return ("strict_eq", *binding, *literal_key), required

    def _condition_is_feasible(
        self, condition: tuple[_PathAtom, bool] | None, env: dict
    ) -> bool:
        if condition is None:
            return True
        atom, value = condition
        current = self._current_conditions(env)
        return not self._conditions_conflict(current, {atom: value})

    @staticmethod
    def _info_conditions(info: Any) -> dict[_PathAtom, bool]:
        conditions = info.get("conditions") if isinstance(info, dict) else None
        return dict(conditions) if isinstance(conditions, dict) else {}

    def _tag_current_conditions(self, info: dict | None, env: dict | None = None) -> dict | None:
        if info is None or info.get("label") in _STATE_LABELS:
            return info
        conditions = self._info_conditions(info)
        conditions.update(self._current_conditions(env))
        return {**info, "conditions": conditions} if conditions else info

    def _invalidate_path_condition(self, binding: tuple[int, str], env: dict) -> None:
        for key, value in list(env.items()):
            if not isinstance(value, dict):
                continue
            conditions = self._info_conditions(value)
            remaining = {
                atom: required
                for atom, required in conditions.items()
                if self._path_atom_binding(atom) != binding
            }
            if remaining == conditions:
                continue
            updated = dict(value)
            if remaining:
                updated["conditions"] = remaining
            else:
                updated.pop("conditions", None)
            env[key] = updated
        active = any(
            isinstance(marker, dict)
            and marker.get("label") == _PATH_CONDITION
            and marker.get("binding") == binding
            for marker in env.values()
        ) or any(
            any(self._path_atom_binding(atom) == binding for atom in layer)
            for layer in self._path_conditions
        )
        if active:
            env[("path-invalidated", *binding)] = {
                "label": _PATH_INVALIDATED,
                "binding": binding,
            }

    def _env_for_condition(
        self, env: dict, condition: tuple[_PathAtom, bool] | None
    ) -> dict:
        if condition is None:
            return dict(env)
        atom, required = condition
        binding = self._path_atom_binding(atom)
        out = dict(env)
        for key, value in list(out.items()):
            conditions = self._info_conditions(value)
            if self._conditions_conflict(conditions, {atom: required}):
                out.pop(key, None)
        out[("path", atom)] = {
            "label": _PATH_CONDITION,
            "atom": atom,
            "binding": binding,
            "value": required,
        }
        return out

    def _merge_env(self, env: dict, *branch_envs: dict) -> None:
        """Join point after mutually-exclusive branches: a binding is possibly-tainted afterwards
        iff it is tainted on ANY branch (union). env stores only tainted bindings, so this is the
        union of the branch maps -- safe (a clean-in-both binding stays clean; a sink INSIDE a
        branch was already checked against that branch's own forked env).

        DQ-C03: a binding tainted on SOME but not ALL branches is CONDITIONALLY tainted. Predicate
        correlation is not modeled (e.g. `if(c){x=hash} if(!c){sink(x)}` are mutually exclusive but
        the union makes x look tainted at the second sink), so a sink fed by conditionally-tainted
        data can only be `probable`, never `confirmed`. Tag such taint `approx` (on a COPY, never
        mutating the shared branch dict) so _emit downgrades it."""
        n = len(branch_envs)
        marker_labels = _STATE_LABELS
        keys = {key for branch in branch_envs for key in branch}
        merged: dict = {}
        for k in keys:
            branch_values = [branch.get(k) for branch in branch_envs]
            taints = [
                value
                for value in branch_values
                if isinstance(value, dict) and value.get("label") not in marker_labels
            ]
            if not taints:
                candidates = [value for value in branch_values if value is not None]
                if len(candidates) == n and candidates and all(value == candidates[0] for value in candidates):
                    merged[k] = candidates[0]
                continue
            v = taints[0]
            common_conditions = self._info_conditions(v)
            for candidate in taints[1:]:
                candidate_conditions = self._info_conditions(candidate)
                common_conditions = {
                    binding: value
                    for binding, value in common_conditions.items()
                    if candidate_conditions.get(binding) == value
                }
            if common_conditions:
                v = {**v, "conditions": common_conditions}
            elif "conditions" in v:
                v = {key: value for key, value in v.items() if key != "conditions"}
            if len(taints) < n and not v.get("approx"):
                v = {**v, "approx": True}  # conditional across branches -> not soundly confirmable
            merged[k] = v
        env.clear()
        env.update(merged)

    @staticmethod
    def _function_value(node: dict, env: dict) -> dict:
        return {
            "label": _FUNCTION_REF,
            "node": node,
            "closure": dict(env),
            "line": _line_of(node),
        }

    def _assign_pattern(self, target: dict, rt: dict | None, scope: _Scope, env: dict) -> None:
        tt = target.get("type")
        if tt == "Identifier":
            key = self._binding(target["name"], scope)
            self._clear_heap_root(env, key)
            tagged = self._tag_current_conditions(rt, env) if rt is not None else None
            self._invalidate_path_condition(key, env)
            if rt is None:
                env.pop(key, None)  # kill
            else:
                env[key] = tagged or rt  # gen
        elif tt in ("ObjectPattern", "ArrayPattern"):
            for nm in self._pattern_names(target):
                key = self._binding(nm, scope)
                if rt is None:
                    env.pop(key, None)
                else:
                    tagged = self._tag_current_conditions(rt, env) or rt
                    env[key] = {
                        **tagged,
                        "step": f"destructure {nm}",
                        "line": rt.get("line", 0),
                    }

    @staticmethod
    def _pattern_property_name(prop: Any) -> str | None:
        if not isinstance(prop, dict) or prop.get("computed"):
            return None
        key = prop.get("key") or {}
        value = key.get("name") or key.get("value")
        return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else None

    def _object_root(self, node: Any, scope: _Scope, env: dict) -> tuple[int, str] | None:
        if not isinstance(node, dict) or node.get("type") != "Identifier":
            return None
        binding = self._binding(node.get("name", ""), scope)
        marker = env.get(binding)
        if not isinstance(marker, dict) or marker.get("label") != _OBJECT_REF:
            return None
        root = marker.get("root")
        return root if isinstance(root, tuple) and len(root) == 2 else binding

    @staticmethod
    def _object_marker_for_root(root: tuple[int, str], env: dict) -> dict | None:
        return next(
            (
                marker
                for marker in env.values()
                if isinstance(marker, dict)
                and marker.get("label") == _OBJECT_REF
                and marker.get("root") == root
            ),
            None,
        )

    @staticmethod
    def _array_length(root: tuple[int, str], env: dict) -> int:
        length = env.get(("heap-meta", root[0], root[1], "length"))
        if isinstance(length, int) and length >= 0:
            return length
        return (
            max(
                (
                    int(key[3])
                    for key in env
                    if isinstance(key, tuple)
                    and len(key) >= 4
                    and key[0] == "heap"
                    and key[1:3] == root
                    and str(key[3]).isdigit()
                ),
                default=-1,
            )
            + 1
        )

    @staticmethod
    def _set_array_length(root: tuple[int, str], env: dict, length: int) -> None:
        for key in list(env):
            if (
                isinstance(key, tuple)
                and len(key) >= 4
                and key[0] == "heap"
                and key[1:3] == root
                and str(key[3]).isdigit()
                and int(key[3]) >= length
            ):
                env.pop(key, None)
        env[("heap-meta", root[0], root[1], "length")] = length

    def _exact_iterable_values(
        self, node: Any, scope: _Scope, env: dict, depth: int
    ) -> list[dict | None] | None:
        """Return ordered values only for an allocation-backed array with a proven length."""
        if not isinstance(node, dict):
            return None
        if node.get("type") == "ArrayExpression":
            values: list[dict | None] = []
            for element in node.get("elements", []) or []:
                if not isinstance(element, dict):
                    values.append(
                        {"label": _CONST_VALUE, "value": None, "line": _line_of(node)}
                    )
                    continue
                if element.get("type") == "SpreadElement":
                    spread = self._exact_iterable_values(
                        element.get("argument"), scope, env, depth + 1
                    )
                    if spread is None:
                        self._eval(element.get("argument"), scope, env, depth + 1)
                        return None
                    values.extend(spread)
                    continue
                value = self._expression_value(element, scope, env, depth + 1)
                values.append(
                    value
                    or {
                        "label": _CLEAN_VALUE,
                        "line": _line_of(element),
                    }
                )
            return values
        if node.get("type") != "Identifier":
            return None
        marker = env.get(self._binding(node.get("name", ""), scope))
        if not (
            isinstance(marker, dict)
            and marker.get("label") == _OBJECT_REF
            and marker.get("container") == "array"
            and isinstance(marker.get("root"), tuple)
        ):
            return None
        root = marker["root"]
        return [
            self._heap_path_value(root, (str(index),), env, _line_of(node))
            for index in range(self._array_length(root, env))
        ]

    def _heap_path_value(
        self, root: tuple[int, str], path: tuple[str, ...], env: dict, line: int
    ) -> dict:
        value = env.get(("heap", *root, *path))
        if isinstance(value, dict):
            return dict(value)
        descendants = [
            (key, info)
            for key, info in list(env.items())
            if isinstance(key, tuple)
            and len(key) > 3 + len(path)
            and key[0] == "heap"
            and key[1:3] == root
            and key[3 : 3 + len(path)] == path
            and isinstance(info, dict)
        ]
        if descendants:
            materialized_root = self._new_heap_root()
            for key, info in descendants:
                env.pop(key, None)
                env[("heap", *materialized_root, *key[3 + len(path) :])] = dict(info)
            marker = {
                "label": _OBJECT_REF,
                "root": materialized_root,
                "container": "object",
                "line": line,
            }
            env[("heap", *root, *path)] = marker
            return dict(marker)
        return {"label": _CONST_VALUE, "value": None, "line": line}

    def _detach_heap_path(
        self, root: tuple[int, str], path: tuple[str, ...], env: dict, line: int
    ) -> dict:
        value = self._heap_path_value(root, path, env, line)
        if value.get("label") != _OBJECT_REF or value.get("root") != root:
            return value
        detached_root = self._new_heap_root()
        copied = False
        for key, info in list(env.items()):
            if (
                isinstance(key, tuple)
                and len(key) > 3 + len(path)
                and key[0] == "heap"
                and key[1:3] == root
                and key[3 : 3 + len(path)] == path
                and isinstance(info, dict)
            ):
                env[("heap", *detached_root, *key[3 + len(path) :])] = dict(info)
                copied = True
        return (
            {
                "label": _OBJECT_REF,
                "root": detached_root,
                "container": "object",
                "line": line,
            }
            if copied
            else value
        )

    def _assign_loop_target(
        self,
        target: dict,
        value: dict | None,
        scope: _Scope,
        env: dict,
        depth: int,
    ) -> None:
        target_scope = self._scope_for_node(target, scope)
        pattern = target
        if target.get("type") == "VariableDeclaration":
            declarations = [
                declaration
                for declaration in target.get("declarations", []) or []
                if isinstance(declaration, dict)
            ]
            if not declarations:
                return
            pattern = declarations[0].get("id") or {}
        if pattern.get("type") in {"ObjectPattern", "ArrayPattern", "AssignmentPattern"}:
            self._assign_destructure(pattern, value, target_scope, env, depth + 1)
        else:
            self._assign_pattern(pattern, value, target_scope, env)

    def _assign_destructure(
        self,
        target: dict,
        source: Any,
        scope: _Scope,
        env: dict,
        depth: int,
        *,
        heap_root: tuple[int, str] | None = None,
        heap_path: tuple[str, ...] = (),
    ) -> bool:
        """Assign a destructuring pattern without collapsing unrelated object fields."""
        tt = target.get("type")
        if tt == "AssignmentPattern":
            left = target.get("left") or {}
            state = (
                env.get(("heap", heap_root[0], heap_root[1], *heap_path))
                if heap_root is not None and heap_path
                else source
            )
            is_undefined = state is None or (
                isinstance(state, dict)
                and state.get("label") == _CONST_VALUE
                and state.get("value") is None
            )
            if is_undefined:
                default = target.get("right")
                info = self._eval(default, scope, env, depth) if isinstance(default, dict) else None
                self._assign_pattern(left, info, scope, env)
                return True
            return self._assign_destructure(
                left,
                source,
                scope,
                env,
                depth,
                heap_root=heap_root,
                heap_path=heap_path,
            )
        if tt == "Identifier":
            if heap_root is not None and heap_path:
                info = env.get(("heap", heap_root[0], heap_root[1], *heap_path))
            elif isinstance(source, dict) and source.get("label"):
                info = source
            else:
                info = self._eval(source, scope, env, depth) if isinstance(source, dict) else None
            self._assign_pattern(target, info if isinstance(info, dict) else None, scope, env)
            return True
        if tt not in ("ObjectPattern", "ArrayPattern"):
            self._assign_pattern(target, None, scope, env)
            return False

        if heap_root is None and isinstance(source, dict) and source.get("label") == _OBJECT_REF:
            candidate = source.get("root")
            heap_root = candidate if isinstance(candidate, tuple) else None
        if heap_root is None and isinstance(source, dict) and source.get("type") in (
            "ObjectExpression",
            "ArrayExpression",
        ):
            marker = self._allocate_literal(source, scope, env, depth + 1)
            candidate = marker.get("root")
            heap_root = candidate if isinstance(candidate, tuple) else None
        if heap_root is None:
            heap_root = self._object_root(source, scope, env)
        if heap_root is None and isinstance(source, dict):
            expected = "ObjectExpression" if tt == "ObjectPattern" else "ArrayExpression"
            if source.get("type") != expected:
                whole = self._eval(source, scope, env, depth)
                if whole is not None:
                    self._assign_pattern(target, whole, scope, env)
                    return True

        if tt == "ObjectPattern":
            literal_values: dict[str, Any] = {}
            if isinstance(source, dict) and source.get("type") == "ObjectExpression":
                for source_prop in source.get("properties", []) or []:
                    name = self._pattern_property_name(source_prop)
                    if name is not None:
                        literal_values[name] = source_prop.get("value")
            excluded: set[str] = set()
            for prop in target.get("properties", []) or []:
                if not isinstance(prop, dict):
                    continue
                if prop.get("type") == "RestElement":
                    if heap_root is None:
                        self._assign_pattern(prop.get("argument") or {}, None, scope, env)
                        continue
                    rest_root = self._new_heap_root()
                    rest_marker = {
                        "label": _OBJECT_REF,
                        "root": rest_root,
                        "container": "object",
                        "line": _line_of(prop),
                    }
                    for key, info in list(env.items()):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == heap_root
                            and str(key[3]) not in excluded
                            and isinstance(info, dict)
                        ):
                            env[("heap", *rest_root, *key[3:])] = dict(info)
                    self._assign_pattern(prop.get("argument") or {}, rest_marker, scope, env)
                    continue
                name = self._pattern_property_name(prop)
                child = prop.get("value") or {}
                if name is None and prop.get("computed"):
                    key_node = prop.get("key") or {}
                    self._eval(key_node, scope, env, depth + 1)
                    known_name, name_value = self._const_value(key_node, scope, env)
                    if (
                        known_name
                        and isinstance(name_value, (str, int))
                        and not isinstance(name_value, bool)
                    ):
                        name = str(name_value)
                if name is None:
                    self._assign_pattern(child, None, scope, env)
                    continue
                excluded.add(name)
                self._assign_destructure(
                    child,
                    literal_values.get(name),
                    scope,
                    env,
                    depth + 1,
                    heap_root=heap_root,
                    heap_path=(*heap_path, name),
                )
            return True

        elements = source.get("elements", []) if isinstance(source, dict) else []
        for index, child in enumerate(target.get("elements", []) or []):
            if not isinstance(child, dict):
                continue
            if child.get("type") == "RestElement":
                if heap_root is None:
                    self._assign_pattern(child.get("argument") or {}, None, scope, env)
                    continue
                rest_root = self._new_heap_root()
                source_length = self._array_length(heap_root, env)
                for source_index in range(index, source_length):
                    for key, info in list(env.items()):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == heap_root
                            and str(key[3]) == str(source_index)
                            and isinstance(info, dict)
                        ):
                            env[("heap", *rest_root, str(source_index - index), *key[4:])] = dict(
                                info
                            )
                env[("heap-meta", *rest_root, "length")] = max(0, source_length - index)
                self._assign_pattern(
                    child.get("argument") or {},
                    {
                        "label": _OBJECT_REF,
                        "root": rest_root,
                        "container": "array",
                        "line": _line_of(child),
                    },
                    scope,
                    env,
                )
                continue
            child_source = elements[index] if index < len(elements) else None
            self._assign_destructure(
                child,
                child_source,
                scope,
                env,
                depth + 1,
                heap_root=heap_root,
                heap_path=(*heap_path, str(index)),
            )
        return True

    @staticmethod
    def _clear_heap_root(env: dict, root: tuple[int, str]) -> None:
        for key in list(env):
            if isinstance(key, tuple) and len(key) >= 4 and key[0] == "heap" and key[1:3] == root:
                env.pop(key, None)

    def _new_heap_root(self) -> tuple[int, str]:
        self._allocation_seq += 1
        return -1, f"allocation:{self._allocation_seq}"

    def _allocate_literal(
        self, node: dict, scope: _Scope, env: dict, depth: int
    ) -> dict[str, Any]:
        root = self._new_heap_root()
        marker: dict[str, Any] = {
            "label": _OBJECT_REF,
            "root": root,
            "container": "array" if node.get("type") == "ArrayExpression" else "object",
            "line": _line_of(node),
        }
        self._bind_heap_literal(root, node, scope, env, depth)
        self._register_literal_methods(root, node)
        return marker

    def _allocate_new_expression(
        self, node: dict, scope: _Scope, env: dict, depth: int
    ) -> dict | None:
        callee = node.get("callee") or {}
        if callee.get("type") != "Identifier":
            for argument in node.get("arguments", []) or []:
                self._eval(argument, scope, env, depth + 1)
            return None
        class_name = callee.get("name") or ""
        argument_values: list[dict | None] = []
        for argument in node.get("arguments", []) or []:
            if isinstance(argument, dict) and argument.get("type") == "SpreadElement":
                spread_values = self._exact_iterable_values(
                    argument.get("argument"), scope, env, depth + 1
                )
                if spread_values is not None:
                    argument_values.extend(spread_values)
                    continue
            argument_values.append(
                self._expression_value(argument, scope, env, depth + 1)
                if isinstance(argument, dict)
                else None
            )
        if class_name == "Function" and scope.resolve("Function") is None:
            for argument, value in zip(
                node.get("arguments", []) or [], argument_values, strict=False
            ):
                if isinstance(argument, dict) and isinstance(value, dict):
                    self._record(node, argument, "", "new Function()", value, scope, env)
            return None
        binding = self._binding(class_name, scope)
        root = self._new_heap_root()
        marker: dict[str, Any] = {
            "label": _OBJECT_REF,
            "root": root,
            "container": "object",
            "class_name": class_name,
            "line": _line_of(node),
        }
        class_methods = self._class_methods.get(binding, {})
        prototype_methods = self._prototype_methods.get(binding, {})
        methods = {**class_methods, **prototype_methods}
        getters = self._class_getters.get(binding)
        setters = self._class_setters.get(binding)
        if methods:
            self._instance_methods[root] = methods
        if getters:
            self._instance_getters[root] = getters
        if setters:
            self._instance_setters[root] = setters
        constructors = list(self._class_constructors.get(binding, []))
        if not constructors:
            constructors = [
                definition
                for definition in self._func_by_binding.get(binding, [])
                if definition.get("type") in {"FunctionDeclaration", "FunctionExpression"}
            ]
        if len(constructors) == 1:
            _, constructor_result = self._run_callback_result(
                constructors[0],
                {
                    index: value
                    for index, value in enumerate(argument_values)
                    if isinstance(value, dict)
                },
                scope,
                env,
                depth + 1,
                effect_target=env,
                this_root=root,
            )
            if (
                isinstance(constructor_result, dict)
                and constructor_result.get("label") == _OBJECT_REF
            ):
                return constructor_result
        return marker

    def _reset_object_binding(self, binding: tuple[int, str], env: dict) -> None:
        # Rebinding a variable must not destroy the allocation still reachable through aliases.
        env.pop(binding, None)

    def _register_literal_methods(self, root: tuple[int, str], node: dict) -> None:
        if node.get("type") != "ObjectExpression":
            return
        methods: dict[str, list[dict]] = {}
        getters: dict[str, list[dict]] = {}
        setters: dict[str, list[dict]] = {}
        for prop in node.get("properties", []) or []:
            if not isinstance(prop, dict) or prop.get("computed"):
                continue
            key = prop.get("key") or {}
            name = key.get("name") or key.get("value")
            value = prop.get("value")
            if (
                isinstance(name, str)
                and isinstance(value, dict)
                and value.get("type")
                in ("FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration")
            ):
                method_name = name.lower()
                kind = prop.get("kind") or "init"
                if kind == "get":
                    getters[method_name] = [value]
                    methods.pop(method_name, None)
                    setters.pop(method_name, None)
                elif kind == "set":
                    setters[method_name] = [value]
                    methods.pop(method_name, None)
                    getters.pop(method_name, None)
                else:
                    methods[method_name] = [value]
                    getters.pop(method_name, None)
                    setters.pop(method_name, None)
            elif isinstance(name, str):
                methods.pop(name.lower(), None)
                getters.pop(name.lower(), None)
                setters.pop(name.lower(), None)
        if methods:
            self._instance_methods[root] = methods
        if getters:
            self._instance_getters[root] = getters
        if setters:
            self._instance_setters[root] = setters

    def _heap_key(self, node: Any, scope: _Scope, env: dict) -> tuple | None:
        parts: list[str] = []
        cur = node
        while isinstance(cur, dict) and cur.get("type") == "MemberExpression":
            prop = cur.get("property") or {}
            if cur.get("computed"):
                value = prop.get("value") if prop.get("type") == "Literal" else None
                if prop.get("type") == "Identifier":
                    marker = env.get(self._binding(prop.get("name", ""), scope))
                    if isinstance(marker, dict) and marker.get("label") == _CONST_VALUE:
                        value = marker.get("value")
                if not isinstance(value, (str, int)) or isinstance(value, bool):
                    return None
                parts.append(str(value))
            else:
                name = prop.get("name")
                if not isinstance(name, str) or not name:
                    return None
                parts.append(name)
            cur = cur.get("object")
        if not isinstance(cur, dict) or cur.get("type") not in ("Identifier", "ThisExpression"):
            return None
        root = self._binding(
            "this" if cur.get("type") == "ThisExpression" else cur.get("name", ""), scope
        )
        marker = env.get(root)
        if marker and marker.get("label") == _OBJECT_REF and isinstance(marker.get("root"), tuple):
            prefix = marker.get("path")
            if isinstance(prefix, tuple):
                parts.extend(str(part) for part in reversed(prefix))
            root = marker["root"]
        return ("heap", root[0], root[1], *reversed(parts))

    def _bind_heap_literal(
        self,
        root: tuple[int, str],
        node: dict,
        scope: _Scope,
        env: dict,
        depth: int,
        prefix: tuple[str, ...] = (),
    ) -> None:
        def store(path: tuple[str, ...], value: Any) -> None:
            if not isinstance(value, dict):
                env[("heap", root[0], root[1], *path)] = {"label": _CLEAN_VALUE}
                return
            if value.get("type") in ("ObjectExpression", "ArrayExpression"):
                self._bind_heap_literal(root, value, scope, env, depth + 1, path)
                return
            info = self._eval(value, scope, env, depth + 1)
            if info is None:
                known, constant = self._const_value(value, scope, env)
                info = (
                    {"label": _CONST_VALUE, "value": constant, "line": _line_of(value)}
                    if known
                    else {"label": _CLEAN_VALUE, "line": _line_of(value)}
                )
            tagged = self._tag_current_conditions(info, env) or info
            env[("heap", root[0], root[1], *path)] = {
                **tagged,
                "step": f"member {'.'.join(path)}",
            }

        def source_root(value: Any) -> tuple[int, str] | None:
            existing = self._object_root(value, scope, env)
            if existing is not None:
                return existing
            if isinstance(value, dict) and value.get("type") in (
                "ObjectExpression",
                "ArrayExpression",
            ):
                marker = self._allocate_literal(value, scope, env, depth + 1)
                candidate = marker.get("root")
                return candidate if isinstance(candidate, tuple) else None
            self._eval(value, scope, env, depth + 1)
            return None

        if node.get("type") == "ObjectExpression":
            for prop in node.get("properties", []) or []:
                if not isinstance(prop, dict):
                    continue
                if prop.get("type") == "SpreadElement":
                    spread_root = source_root(prop.get("argument"))
                    if spread_root is not None:
                        for key, info in list(env.items()):
                            if (
                                isinstance(key, tuple)
                                and len(key) >= 4
                                and key[0] == "heap"
                                and key[1:3] == spread_root
                                and isinstance(info, dict)
                            ):
                                destination = ("heap", root[0], root[1], *prefix, *key[3:])
                                env[destination] = dict(info)
                    continue
                if prop.get("type") != "Property":
                    continue
                key_node = prop.get("key") or {}
                if prop.get("computed"):
                    self._eval(key_node, scope, env, depth + 1)
                    known, name_value = self._const_value(key_node, scope, env)
                else:
                    name_value = key_node.get("name") or key_node.get("value")
                    known = isinstance(name_value, (str, int)) and not isinstance(name_value, bool)
                value = prop.get("value")
                if not known or not isinstance(name_value, (str, int)) or isinstance(name_value, bool):
                    self._eval(value, scope, env, depth + 1)
                    continue
                store((*prefix, str(name_value)), value)
            return

        destination_index = 0
        for element in node.get("elements", []) or []:
            if isinstance(element, dict) and element.get("type") == "SpreadElement":
                spread_root = source_root(element.get("argument"))
                if spread_root is None:
                    continue
                source_items = [
                    (key, info)
                    for key, info in list(env.items())
                    if isinstance(key, tuple)
                    and len(key) >= 4
                    and key[0] == "heap"
                    and key[1:3] == spread_root
                    and str(key[3]).isdigit()
                    and isinstance(info, dict)
                ]
                source_length = max((int(key[3]) for key, _ in source_items), default=-1) + 1
                for key, info in source_items:
                    destination = (
                        "heap",
                        root[0],
                        root[1],
                        *prefix,
                        str(destination_index + int(key[3])),
                        *key[4:],
                    )
                    env[destination] = dict(info)
                destination_index += source_length
                continue
            store((*prefix, str(destination_index)), element)
            destination_index += 1
        if not prefix:
            env[("heap-meta", root[0], root[1], "length")] = destination_index

    # ------------------------------------------------------------ expression evaluation

    @staticmethod
    def _combine_concat_taint(
        taints: list[dict[str, Any] | None],
    ) -> dict[str, Any] | None:
        """Combine the taints of a '+'-concat / template literal's operands into one representative
        taint. Prefer a nav-UNSAFE part (attacker-controllable, e.g. location.hash / dom_input) over
        a same-origin-safe location part, so a navigation sink is not wrongly suppressed just because
        the FIRST operand happens to be safe (DQ-T03: previously only the first taint was kept)."""
        present = [t for t in taints if t is not None and t.get("label") not in _STATE_LABELS]
        if not present:
            return None
        for t in present:
            if not _nav_fp_safe(t):
                return t
        return present[0]

    def _eval(self, node: Any, scope: _Scope, env: dict, depth: int) -> dict | None:
        if not isinstance(node, dict):
            return None
        if depth > _MAX_DEPTH:
            self._depth_cap_hit = True
            return None
        self._work += 1
        if self._work > _MAX_WORK:
            self._work_cap_hit = True
            return None
        t = node.get("type")
        scope = self._scope_for_node(node, scope)

        if t in ("Literal", "TemplateElement"):
            return None
        if t == "ThisExpression":
            return env.get(self._binding("this", scope))
        if t == "Identifier":
            binding = self._binding(node.get("name", ""), scope)
            info = env.get(binding)
            if info is None:
                if node.get("name") == "DOMPurify" and scope.resolve("DOMPurify") is None:
                    return {
                        "label": _SANITIZER_REF,
                        "kind": "dompurify",
                        "line": _line_of(node),
                    }
                declarations = [
                    definition
                    for definition in self._func_by_binding.get(binding, [])
                    if definition.get("type") == "FunctionDeclaration"
                ]
                if len(declarations) == 1:
                    return self._function_value(declarations[0], env)
            if isinstance(info, dict) and info.get("label") == _OBJECT_REF:
                if info.get("container") == "array" and isinstance(info.get("root"), tuple):
                    root = info["root"]
                    heap_values: list[dict[str, Any] | None] = [
                        dict(value)
                        for key, value in env.items()
                        if isinstance(key, tuple)
                        and len(key) >= 4
                        and key[0] in {"heap", "heap-meta"}
                        and key[1:3] == root
                        and isinstance(value, dict)
                    ]
                    aggregate = self._combine_concat_taint(heap_values)
                    return {**aggregate, "step": "array value"} if aggregate else None
                return None
            # a FileReader / jQuery OBJECT binding is not itself tainted -- only its .result /
            # .val()/.data() reads are sources -- so reading the bare identifier yields no taint.
            return (
                None
                if (
                    info
                    and info.get("label") in (
                        _READER_OBJ,
                        _JQUERY_OBJ,
                        _CONST_VALUE,
                        _CLEAN_VALUE,
                    )
                )
                else info
            )
        if t == "AssignmentExpression":
            return self._eval_assign(node, scope, env, depth)
        if t == "MemberExpression":
            return self._eval_member(node, scope, env, depth)
        if t == "AwaitExpression":
            awaited = self._promise_state(
                node.get("argument"),
                scope,
                env,
                depth + 1,
                chain_env=env,
            )
            if awaited is None:
                awaited = self._eval(node.get("argument"), scope, env, depth)
            if isinstance(awaited, dict) and awaited.get("label") == _PROMISE_REF:
                if awaited.get("rejected"):
                    rejected_value = awaited.get("rejected_value")
                    rejected_info = (
                        rejected_value if isinstance(rejected_value, dict) else None
                    )
                    self._capture_exception_state(
                        env,
                        approximate=bool(awaited.get("fulfilled")),
                        value=rejected_info,
                    )
                    self._capture_abrupt_state("throw", env, rejected_info)
                value = awaited.get("fulfilled_value")
                return value if awaited.get("fulfilled") and isinstance(value, dict) else None
            return awaited
        if t == "YieldExpression":
            yielded = self._expression_value(node.get("argument"), scope, env, depth)
            if self._yield_frames:
                self._yield_frames[-1].append(yielded)
            return yielded
        if t == "SpreadElement":
            return self._eval(node.get("argument"), scope, env, depth)
        if t == "TaggedTemplateExpression":
            info = self._eval(node.get("quasi"), scope, env, depth)
            return {**info, "step": "tagged template", "approx": True} if info else None
        if t == "UpdateExpression":
            argument = node.get("argument") or {}
            self._eval(argument, scope, env, depth)
            if argument.get("type") == "Identifier":
                self._assign_pattern(argument, None, scope, env)
            elif argument.get("type") == "MemberExpression":
                key = self._heap_key(argument, scope, env)
                if key is not None:
                    env[key] = {"label": _CLEAN_VALUE, "line": _line_of(argument)}
            return None
        if t == "UnaryExpression":
            argument = node.get("argument") or {}
            self._eval(argument, scope, env, depth)
            if node.get("operator") == "delete" and argument.get("type") == "MemberExpression":
                key = self._heap_key(argument, scope, env)
                if key is not None:
                    env.pop(key, None)
            return None
        if t == "BinaryExpression":
            if node.get("operator") == "+":
                # DQ-T03: evaluate BOTH operands (no short-circuit -- the right side's sinks must
                # still be checked) and keep a nav-unsafe part if present.
                lt = self._eval(node.get("left"), scope, env, depth)
                rt = self._eval(node.get("right"), scope, env, depth)
                return self._combine_concat_taint([lt, rt])
            self._eval(node.get("left"), scope, env, depth)
            self._eval(node.get("right"), scope, env, depth)
            return None
        if t == "TemplateLiteral":
            hits = [self._eval(e, scope, env, depth) for e in (node.get("expressions") or [])]
            return self._combine_concat_taint(hits)
        if t == "ConditionalExpression":
            self._eval(node.get("test"), scope, env, depth)
            truth = self._const_truth(node.get("test"), scope, env)
            if truth is not None:
                return self._expression_value(
                    node.get("consequent" if truth else "alternate"), scope, env, depth
                )
            left_condition = self._branch_condition(node.get("test"), scope, True)
            right_condition = self._branch_condition(node.get("test"), scope, False)
            left_feasible = self._condition_is_feasible(left_condition, env)
            right_feasible = self._condition_is_feasible(right_condition, env)
            env_left = self._env_for_condition(env, left_condition)
            env_right = self._env_for_condition(env, right_condition)
            left = right = None
            self._approx += 1
            try:
                if left_feasible:
                    if left_condition is not None:
                        self._path_conditions.append({left_condition[0]: left_condition[1]})
                    try:
                        left = self._tag_current_conditions(
                            self._expression_value(
                                node.get("consequent"), scope, env_left, depth
                            ),
                            env_left,
                        )
                    finally:
                        if left_condition is not None:
                            self._path_conditions.pop()
                if right_feasible:
                    if right_condition is not None:
                        self._path_conditions.append({right_condition[0]: right_condition[1]})
                    try:
                        right = self._tag_current_conditions(
                            self._expression_value(
                                node.get("alternate"), scope, env_right, depth
                            ),
                            env_right,
                        )
                    finally:
                        if right_condition is not None:
                            self._path_conditions.pop()
            finally:
                self._approx -= 1
            branches = []
            if left_feasible:
                branches.append(env_left)
            if right_feasible:
                branches.append(env_right)
            if branches:
                self._merge_env(env, *branches)
            result = left or right
            return {**result, "approx": True} if result is not None else None
        if t == "LogicalExpression":
            left_node = node.get("left")
            left = self._expression_value(left_node, scope, env, depth)
            op = node.get("operator")
            known, value = self._const_value(left_node, scope, env)
            if not known and isinstance(left, dict) and left.get("label") in {
                _OBJECT_REF,
                _FUNCTION_REF,
                _PROMISE_REF,
                _GENERATOR_REF,
                _SANITIZER_REF,
            }:
                known, value = True, left
            if op == "??":
                if known and value is not None:
                    return left
                if known:
                    return self._expression_value(node.get("right"), scope, env, depth)
                right_env = dict(env)
                self._approx += 1
                try:
                    right = self._eval(node.get("right"), scope, right_env, depth)
                finally:
                    self._approx -= 1
                self._merge_env(env, dict(env), right_env)
                result = left or right
                return {**result, "approx": True} if result is not None else None
            truth = bool(value) if known else None
            if (op == "&&" and truth is False) or (op == "||" and truth is True):
                return left
            if (op == "&&" and truth is True) or (op == "||" and truth is False):
                return self._expression_value(node.get("right"), scope, env, depth)
            execute_truth = op == "&&"
            execute_condition = self._branch_condition(node.get("left"), scope, execute_truth)
            short_condition = self._branch_condition(node.get("left"), scope, not execute_truth)
            execute_feasible = self._condition_is_feasible(execute_condition, env)
            short_feasible = self._condition_is_feasible(short_condition, env)
            if not execute_feasible:
                return left
            right_env = self._env_for_condition(env, execute_condition)
            self._approx += 1
            try:
                if execute_condition is not None:
                    self._path_conditions.append(
                        {execute_condition[0]: execute_condition[1]}
                    )
                try:
                    right = self._tag_current_conditions(
                        self._eval(node.get("right"), scope, right_env, depth), right_env
                    )
                finally:
                    if execute_condition is not None:
                        self._path_conditions.pop()
            finally:
                self._approx -= 1
            states = [right_env]
            if short_feasible:
                states.insert(0, self._env_for_condition(env, short_condition))
            self._merge_env(env, *states)
            result = left or right
            return {**result, "approx": True} if result is not None else None
        if t == "SequenceExpression":
            r = None
            expressions = node.get("expressions", []) or []
            for index, expression in enumerate(expressions):
                r = (
                    self._expression_value(expression, scope, env, depth)
                    if index == len(expressions) - 1
                    else self._eval(expression, scope, env, depth)
                )
            return r
        if t == "CallExpression":
            return self._eval_call(node, scope, env, depth)
        if t == "NewExpression":
            promise_state = self._promise_state(node, scope, env, depth)
            if promise_state is not None:
                return promise_state
            self._capture_exception_state(env)
            return self._allocate_new_expression(node, scope, env, depth + 1)
        if t == "ArrayExpression":
            array_values: list[dict[str, Any] | None] = [
                self._eval(element, scope, env, depth)
                for element in (node.get("elements") or [])
                if isinstance(element, dict)
            ]
            info = self._combine_concat_taint(array_values)
            return {**info, "step": "array element"} if info else None
        if t == "ObjectExpression":
            for k in ("elements", "properties"):
                for el in node.get(k, []) or []:
                    if isinstance(el, dict):
                        self._eval(
                            el.get("value") if el.get("type") == "Property" else el,
                            scope,
                            env,
                            depth,
                        )
            return None
        if t == "Property":
            return self._eval(node.get("value"), scope, env, depth)
        if t in ("FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration"):
            return self._function_value(node, env)
        # generic: descend to catch nested sinks/sources
        for k, v in node.items():
            if k in ("loc", "range", "raw", "type"):
                continue
            if isinstance(v, dict):
                self._eval(v, scope, env, depth)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        self._eval(it, scope, env, depth)
        return None

    def _eval_member(self, node: dict, scope: _Scope, env: dict, depth: int) -> dict | None:
        obj = node.get("object")
        base = (
            None
            if isinstance(obj, dict) and obj.get("type") in ("ObjectExpression", "ArrayExpression")
            else self._eval(obj, scope, env, depth)
        )
        property_node = node.get("property") or {}
        if node.get("computed"):
            self._eval(property_node, scope, env, depth)
        if (
            isinstance(obj, dict)
            and obj.get("type") == "Super"
            and not node.get("computed")
        ):
            owner = self._current_class_owner(scope)
            parent = self._class_supers.get(owner[0]) if owner is not None else None
            if owner is not None and parent is not None:
                getters = (
                    self._static_class_getters if owner[1] else self._class_getters
                ).get(parent, {}).get(_prop_name(node), [])
                if len(getters) == 1:
                    this_root = self._current_this_root(scope, env)
                    if owner[1] or this_root is None:
                        resolved, getter_value = self._run_callback_result(
                            getters[0],
                            {},
                            scope,
                            env,
                            depth + 1,
                            effect_target=env,
                        )
                    else:
                        resolved, getter_value = self._run_callback_result(
                            getters[0],
                            {},
                            scope,
                            env,
                            depth + 1,
                            effect_target=env,
                            this_root=this_root,
                        )
                    if resolved:
                        return getter_value
                methods = (
                    self._static_class_methods if owner[1] else self._class_methods
                ).get(parent, {}).get(_prop_name(node), [])
                if len(methods) == 1:
                    return self._function_value(methods[0], env)
        if (
            isinstance(obj, dict)
            and obj.get("type") == "Identifier"
            and not node.get("computed")
        ):
            static_getters = self._static_class_getters.get(
                self._binding(obj.get("name", ""), scope), {}
            ).get(_prop_name(node), [])
            if len(static_getters) == 1:
                resolved, getter_value = self._run_callback_result(
                    static_getters[0],
                    {},
                    scope,
                    env,
                    depth + 1,
                    effect_target=env,
                )
                if resolved:
                    return getter_value
            static_methods = self._static_class_methods.get(
                self._binding(obj.get("name", ""), scope), {}
            ).get(_prop_name(node), [])
            if len(static_methods) == 1:
                return self._function_value(static_methods[0], env)
        if (
            isinstance(base, dict)
            and base.get("label") == _OBJECT_REF
            and isinstance(base.get("root"), tuple)
        ):
            direct_root = base["root"]
            direct_getters = self._instance_getters.get(direct_root, {}).get(
                _prop_name(node), []
            )
            if len(direct_getters) == 1:
                resolved, getter_value = self._run_callback_result(
                    direct_getters[0],
                    {},
                    scope,
                    env,
                    depth + 1,
                    effect_target=env,
                    this_root=direct_root,
                )
                if resolved:
                    return getter_value
            direct_methods = self._instance_methods.get(direct_root, {}).get(
                _prop_name(node), []
            )
            if len(direct_methods) == 1:
                return self._function_value(direct_methods[0], env)
        heap_key = self._heap_key(node, scope, env)
        if heap_key is not None and len(heap_key) == 4:
            root = (heap_key[1], heap_key[2])
            getters = self._instance_getters.get(root, {}).get(str(heap_key[3]).lower(), [])
            if len(getters) == 1:
                resolved, getter_value = self._run_callback_result(
                    getters[0],
                    {},
                    scope,
                    env,
                    depth + 1,
                    effect_target=env,
                    this_root=root,
                )
                if resolved:
                    return getter_value
        if heap_key is not None and heap_key in env:
            heap_value = env[heap_key]
            return heap_value if isinstance(heap_value, dict) else None
        if not (isinstance(base, dict) and base.get("label") == _OBJECT_REF) and heap_key is not None:
            root = (heap_key[1], heap_key[2])
            root_marker = self._object_marker_for_root(root, env)
            if isinstance(root_marker, dict) and root_marker.get("label") == _OBJECT_REF:
                return self._heap_path_value(
                    root,
                    tuple(str(part) for part in heap_key[3:]),
                    env,
                    _line_of(node),
                )
        if node.get("computed"):
            known_property, property_value = self._const_value(property_node, scope, env)
            if not known_property:
                property_value = None
        else:
            property_value = property_node.get("name")
        if isinstance(obj, dict) and obj.get("type") == "ObjectExpression" and isinstance(
            property_value, (str, int)
        ):
            for candidate in reversed(obj.get("properties", []) or []):
                if not isinstance(candidate, dict):
                    continue
                if candidate.get("type") == "SpreadElement":
                    return None
                name = self._pattern_property_name(candidate)
                if name == str(property_value):
                    return self._eval(candidate.get("value"), scope, env, depth)
        if (
            isinstance(obj, dict)
            and obj.get("type") == "ArrayExpression"
            and isinstance(property_value, int)
            and not isinstance(property_value, bool)
        ):
            elements = obj.get("elements", []) or []
            if 0 <= property_value < len(elements):
                return self._eval(elements[property_value], scope, env, depth)
        if (
            isinstance(base, dict)
            and base.get("label") == _OBJECT_REF
            and isinstance(base.get("root"), tuple)
            and isinstance(property_value, (str, int))
            and not isinstance(property_value, bool)
        ):
            root = base["root"]
            prefix = base.get("path")
            path = (
                tuple(str(part) for part in prefix)
                if isinstance(prefix, tuple)
                else ()
            )
            path = (*path, str(property_value))
            value = env.get(("heap", *root, *path))
            if isinstance(value, dict):
                return value
            if any(
                isinstance(key, tuple)
                and len(key) > 3 + len(path)
                and key[0] == "heap"
                and key[1:3] == root
                and key[3 : 3 + len(path)] == path
                for key in env
            ):
                return {
                    "label": _OBJECT_REF,
                    "root": root,
                    "container": "object",
                    "path": path,
                    "line": _line_of(node),
                }
            return None
        prop = _prop_name(node)
        if base is not None:
            if base.get("label") == _ITERATOR_RESULT_REF:
                value = base.get("value")
                if prop == "value":
                    return value if isinstance(value, dict) else None
                if prop == "done":
                    return {
                        "label": _CONST_VALUE,
                        "value": bool(base.get("done")),
                        "line": _line_of(node),
                    }
                return None
            if base.get("label") == "filereader" and base.get("reader"):
                return (
                    {**base, "step": "FileReader .result"} if prop in ("result", "target") else None
                )
            if prop == "length":
                return None
            # carry which URL component is read (hash/search/href vs pathname/origin) so the
            # navigation sink can suppress same-origin redirects.
            if base.get("label") == "location":
                return {**base, "step": f".{prop}", "loc_prop": prop}
            return {**base, "step": f".{prop}"}
        if prop in _RESPONSE_MEMBERS:
            if base is not None:
                return {**base, "label": "ajax_response", "step": f".{prop}"}
        member_root = _member_root_name(node)
        if member_root == "location":
            return {
                "label": "location",
                "line": _line_of(node),
                "step": "location.*",
                "loc_prop": prop,
            }
        # window.location / document.location / self.location ... -- the dominant real-world spelling
        # that `_member_root_name` (deepest-identifier) otherwise roots at window/document and misses.
        if prop == "location" and member_root in _LOCATION_HOSTS:
            return {
                "label": "location",
                "line": _line_of(node),
                "step": f"{member_root}.location",
            }
        if member_root == "document" and prop in ("cookie", "url", "documenturi", "referrer"):
            return {"label": "location", "line": _line_of(node), "step": "document.*"}
        # e.target.value / e.target.files inside an event handler are DOM input -- but only when the
        # chain roots at an EVENT object (DQ-T02: model.target.value / config.settings.target.value /
        # a plain `const target = getConfig()` are NOT user input, they were false-positive sources).
        if (
            prop in ("value", "files")
            and isinstance(obj, dict)
            and _prop_name(obj) == "target"
            and _member_root_name(obj) in _EVENT_NAMES
        ):
            return {"label": "dom_input", "line": _line_of(node), "step": f"e.target.{prop}"}
        # A destructured handler param -- `({target}) => target.value` -- binds `target` directly to
        # the event's EventTarget; `.value`/`.files` on that binding is DOM input. Scope-resolved via
        # `_binding` so an inner shadow does not leak (FU-T02SEED). Declarator/member `target`s (the
        # DQ-T02 FP locks) are NOT in `_event_param_bindings`, so they stay non-sources.
        if (
            prop in ("value", "files")
            and isinstance(obj, dict)
            and obj.get("type") == "Identifier"
            and self._binding(obj.get("name", ""), scope) in self._event_param_bindings
        ):
            return {"label": "dom_input", "line": _line_of(node), "step": f"target.{prop}"}
        return None

    def _eval_assign(self, node: dict, scope: _Scope, env: dict, depth: int) -> dict | None:
        left = node.get("left") or {}
        right = node.get("right")
        # reader.onload = fn  -> seed the callback's event param as a FileReader source.
        # Look up the reader marker DIRECTLY (the _eval Identifier path filters _READER_OBJ out).
        if left.get("type") == "MemberExpression" and _prop_name(left) in ("onload", "onloadend"):
            obj = left.get("object") or {}
            is_reader = False
            if obj.get("type") == "Identifier":
                b = env.get(self._binding(obj.get("name", ""), scope))
                is_reader = b is not None and b.get("label") == _READER_OBJ
            if is_reader and isinstance(right, dict):
                self._run_callback(
                    right,
                    {
                        0: {
                            "label": "filereader",
                            "reader": True,
                            "line": _line_of(node),
                            "step": "FileReader onload event",
                        }
                    },
                    scope,
                    env,
                    depth,
                )
            return None
        if not isinstance(right, dict):
            return None
        if left.get("type") == "MemberExpression":
            self._eval(left.get("object"), scope, env, depth)
            if left.get("computed"):
                self._eval(left.get("property"), scope, env, depth)
        operator = node.get("operator")
        if operator in ("&&=", "||=", "??="):
            known, current_value = self._const_value(left, scope, env)
            executes = (
                (operator == "&&=" and bool(current_value))
                or (operator == "||=" and not bool(current_value))
                or (operator == "??=" and current_value is None)
            )
            if known and not executes:
                return self._eval(left, scope, env, depth)
        prior = self._eval(left, scope, env, depth) if operator != "=" else None
        rt = self._eval(right, scope, env, depth)
        write_taint = rt
        if operator == "+=":
            write_taint = self._combine_concat_taint([prior, rt])
        elif operator in ("&&=", "||=", "??="):
            combined = self._combine_concat_taint([prior, rt])
            write_taint = {**combined, "approx": True} if combined is not None else None
        elif operator != "=":
            write_taint = None
        if operator == "=" and left.get("type") == "MemberExpression":
            prototype = left.get("object") or {}
            constructor = prototype.get("object") or {}
            if (
                not left.get("computed")
                and prototype.get("type") == "MemberExpression"
                and not prototype.get("computed")
                and _prop_name(prototype) == "prototype"
                and constructor.get("type") == "Identifier"
            ):
                prototype_binding = self._binding(constructor.get("name", ""), scope)
                method_name = _prop_name(left)
                if right.get("type") in {"FunctionExpression", "FunctionDeclaration"}:
                    self._prototype_methods.setdefault(prototype_binding, {})[
                        method_name
                    ] = [right]
                else:
                    self._prototype_methods.get(prototype_binding, {}).pop(
                        method_name, None
                    )
        if operator == "=" and left.get("type") == "MemberExpression":
            static_object = left.get("object") or {}
            if static_object.get("type") == "Super" and not left.get("computed"):
                owner = self._current_class_owner(scope)
                parent = self._class_supers.get(owner[0]) if owner is not None else None
                if owner is not None and parent is not None:
                    setter_table = (
                        self._static_class_setters if owner[1] else self._class_setters
                    )
                    getter_table = (
                        self._static_class_getters if owner[1] else self._class_getters
                    )
                    member_name = _prop_name(left)
                    setters = setter_table.get(parent, {}).get(member_name, [])
                    if len(setters) == 1:
                        parameters = {
                            0: write_taint
                            or {"label": _CLEAN_VALUE, "line": _line_of(right)}
                        }
                        this_root = self._current_this_root(scope, env)
                        if owner[1] or this_root is None:
                            self._run_callback_result(
                                setters[0],
                                parameters,
                                scope,
                                env,
                                depth + 1,
                                effect_target=env,
                            )
                        else:
                            self._run_callback_result(
                                setters[0],
                                parameters,
                                scope,
                                env,
                                depth + 1,
                                effect_target=env,
                                this_root=this_root,
                            )
                        return write_taint
                    if len(getter_table.get(parent, {}).get(member_name, [])) == 1:
                        return write_taint
            if static_object.get("type") == "Identifier" and not left.get("computed"):
                static_binding = self._binding(static_object.get("name", ""), scope)
                static_name = _prop_name(left)
                static_setters = self._static_class_setters.get(static_binding, {}).get(
                    static_name, []
                )
                if len(static_setters) == 1:
                    self._run_callback_result(
                        static_setters[0],
                        {
                            0: write_taint
                            or {"label": _CLEAN_VALUE, "line": _line_of(right)}
                        },
                        scope,
                        env,
                        depth + 1,
                        effect_target=env,
                    )
                    return write_taint
                static_getters = self._static_class_getters.get(static_binding, {}).get(
                    static_name, []
                )
                if len(static_getters) == 1:
                    return write_taint
            setter_key = self._heap_key(left, scope, env)
            if setter_key is not None and len(setter_key) == 4:
                setter_root = (setter_key[1], setter_key[2])
                setters = self._instance_setters.get(setter_root, {}).get(
                    str(setter_key[3]).lower(), []
                )
                if len(setters) == 1:
                    self._run_callback_result(
                        setters[0],
                        {
                            0: write_taint
                            or {"label": _CLEAN_VALUE, "line": _line_of(right)}
                        },
                        scope,
                        env,
                        depth + 1,
                        effect_target=env,
                        this_root=setter_root,
                    )
                    return write_taint
                getters = self._instance_getters.get(setter_root, {}).get(
                    str(setter_key[3]).lower(), []
                )
                if len(getters) == 1:
                    # A getter-only own/class accessor has no writable data slot. Assignment is
                    # ignored in sloppy code and throws in strict code; it never replaces getter.
                    return write_taint
        if (
            operator == "="
            and left.get("type") == "MemberExpression"
            and _prop_name(left) == "length"
        ):
            array_root = self._object_root(left.get("object"), scope, env)
            marker = self._object_marker_for_root(array_root, env) if array_root is not None else None
            known_length, length = self._const_value(right, scope, env)
            if (
                array_root is not None
                and marker is not None
                and marker.get("container") == "array"
                and known_length
                and isinstance(length, int)
                and not isinstance(length, bool)
                and length >= 0
            ):
                self._set_array_length(array_root, env, length)
                return None
        # innerHTML / outerHTML assignment sink
        if left.get("type") == "MemberExpression" and _prop_name(left) in (
            "innerhtml",
            "outerhtml",
        ):
            # `=` sets and `+=` APPENDS raw HTML -- both put the tainted value into the DOM as HTML.
            if write_taint is not None and operator in ("=", "+=", "&&=", "||=", "??="):
                self._record(node, right, "", f"{_prop_name(left)}=", write_taint, scope, env)
            return write_taint
        # navigation / open-redirect assignment sink: location.href = X, window.location = X.
        # Only member forms (a bare `location = x` is a common React-router local var -> ambiguous).
        if operator == "=" and left.get("type") == "MemberExpression":
            lp = _prop_name(left)
            if lp == "href" and _is_location_expr(left.get("object")):
                if rt is not None and not _nav_fp_safe(rt):
                    self._record(node, right, "", "location.href=", rt, scope, env)
                return rt
            if lp == "location" and _member_root_name(left.get("object")) in _LOCATION_HOSTS:
                if rt is not None and not _nav_fp_safe(rt):
                    self._record(node, right, "", "location=", rt, scope, env)
                return rt
        # env update for a simple / destructuring target (flow-sensitive kill/gen)
        if isinstance(operator, str):
            if left.get("type") == "Identifier":
                binding = self._binding(left.get("name", ""), scope)
                self._invalidate_path_condition(binding, env)
                if operator != "=":
                    self._assign_pattern(left, write_taint, scope, env)
                elif right.get("type") in ("ObjectExpression", "ArrayExpression"):
                    self._reset_object_binding(binding, env)
                    root = self._new_heap_root()
                    env[binding] = {
                        "label": _OBJECT_REF,
                        "root": root,
                        "container": (
                            "array" if right.get("type") == "ArrayExpression" else "object"
                        ),
                        "line": _line_of(node),
                    }
                    self._bind_heap_literal(root, right, scope, env, depth)
                    self._register_literal_methods(root, right)
                elif right.get("type") == "Identifier":
                    source = env.get(self._binding(right.get("name", ""), scope))
                    if isinstance(source, dict) and source.get("label") == _OBJECT_REF:
                        env[binding] = dict(source)
                    else:
                        self._assign_pattern(left, rt, scope, env)
                elif isinstance(rt, dict) and rt.get("label") == _PROMISE_REF:
                    self._assign_pattern(left, rt, scope, env)
                elif right.get("type") == "NewExpression":
                    self._reset_object_binding(binding, env)
                    self._assign_pattern(left, rt, scope, env)
                elif (
                    right.get("type") == "Literal"
                    and self._strict_literal_key(right.get("value")) is not None
                ):
                    self._clear_heap_root(env, binding)
                    env[binding] = {
                        "label": _CONST_VALUE,
                        "value": right.get("value"),
                        "line": _line_of(node),
                    }
                else:
                    self._assign_pattern(left, rt, scope, env)
                if operator == "=":
                    assigned_value = env.get(binding)
                    if isinstance(assigned_value, dict):
                        write_taint = assigned_value
            elif left.get("type") in ("ObjectPattern", "ArrayPattern"):
                if operator == "=":
                    self._assign_destructure(left, right, scope, env, depth)
            elif left.get("type") == "MemberExpression":
                key = self._heap_key(left, scope, env)
                if key is not None:
                    if write_taint is None:
                        known, constant = self._const_value(right, scope, env)
                        env[key] = (
                            {
                                "label": _CONST_VALUE,
                                "value": constant,
                                "line": _line_of(right),
                            }
                            if known
                            else {"label": _CLEAN_VALUE, "line": _line_of(right)}
                        )
                    else:
                        tagged = self._tag_current_conditions(write_taint, env) or write_taint
                        env[key] = {**tagged, "step": f"member write {_expr_source(left)}"}
                    if len(key) == 4:
                        root = (key[1], key[2])
                        method_name = str(key[3]).lower()
                        self._instance_getters.get(root, {}).pop(method_name, None)
                        self._instance_setters.get(root, {}).pop(method_name, None)
                        if right.get("type") in (
                            "FunctionExpression",
                            "ArrowFunctionExpression",
                            "FunctionDeclaration",
                        ):
                            self._instance_methods.setdefault(root, {})[method_name] = [right]
                        elif root in self._instance_methods:
                            self._instance_methods[root].pop(method_name, None)
        return write_taint

    def _jquery_receiver(self, obj: Any, scope: _Scope, env: dict) -> bool:
        """DQ-T02: True if `obj` is a jQuery object, so `obj.val()`/`obj.data()` is a form-input
        source. Recognizes a direct `$(...)`/`jQuery(...)` call, a `$`-prefixed or `jquery` identifier
        (the $field convention), a `$`-prefixed IMMEDIATE property (this.$el), and a variable tracked
        as bound to `$(...)`. Deliberately NOT an arbitrary receiver (calculator.val())."""
        if not isinstance(obj, dict):
            return False
        t = obj.get("type")
        if t == "CallExpression":
            return _member_root_name(obj.get("callee")) in ("$", "jquery")
        if t == "Identifier":
            n = (obj.get("name") or "").lower()
            if n == "jquery" or n.startswith("$"):
                return True
            info = env.get(self._binding(obj.get("name", ""), scope))
            return bool(info and info.get("label") == _JQUERY_OBJ)
        if t == "MemberExpression":
            p = _prop_name(obj)  # immediate property, lowercased
            return p == "jquery" or p in _JQUERY_CACHE_PROPS
        return False

    def _eval_call(self, node: dict, scope: _Scope, env: dict, depth: int) -> dict | None:
        callee = node.get("callee") or {}
        args = node.get("arguments") or []
        last = _callee_last_name(callee)
        optional_subject = None
        if node.get("optional"):
            optional_subject = callee
        elif callee.get("type") == "MemberExpression" and callee.get("optional"):
            optional_subject = callee.get("object")
        if isinstance(optional_subject, dict):
            known, value = self._const_value(optional_subject, scope, env)
            if not known and optional_subject.get("type") == "Identifier":
                marker = env.get(self._binding(optional_subject.get("name", ""), scope))
                known = isinstance(marker, dict) and marker.get("label") in {
                    _OBJECT_REF,
                    _FUNCTION_REF,
                    _READER_OBJ,
                    _JQUERY_OBJ,
                }
                value = marker if known else None
            if known and value is None:
                return None
            if not known:
                branch_env = dict(env)
                branch_callee = dict(callee)
                branch_callee["optional"] = False
                branch_node = {**node, "callee": branch_callee, "optional": False}
                self._approx += 1
                try:
                    result = self._eval_call(branch_node, scope, branch_env, depth + 1)
                finally:
                    self._approx -= 1
                self._merge_env(env, dict(env), branch_env)
                return {**result, "approx": True} if result is not None else None
        function_adapter = ""
        adapted_callable = None
        if callee.get("type") == "MemberExpression" and last in {"call", "apply", "bind"}:
            adapted_callable = self._resolve_callable(callee.get("object"), scope, env)
            if adapted_callable is not None:
                function_adapter = last
        resolved_receiver_root: tuple[int, str] | None = None
        super_callable: tuple[dict, dict] | None = None
        owner = self._current_class_owner(scope)
        parent = self._class_supers.get(owner[0]) if owner is not None else None
        if (
            callee.get("type") == "Super"
            and owner is not None
            and parent is not None
            and not owner[1]
        ):
            constructors = self._class_constructors.get(parent, [])
            if len(constructors) == 1:
                super_callable = constructors[0], dict(env)
                resolved_receiver_root = self._current_this_root(scope, env)
        elif (
            callee.get("type") == "MemberExpression"
            and isinstance(callee.get("object"), dict)
            and callee["object"].get("type") == "Super"
            and not callee.get("computed")
            and owner is not None
            and parent is not None
        ):
            methods = (
                self._static_class_methods if owner[1] else self._class_methods
            ).get(parent, {}).get(last, [])
            if len(methods) == 1:
                super_callable = methods[0], dict(env)
                if not owner[1]:
                    resolved_receiver_root = self._current_this_root(scope, env)
        resolved_exact_callable = (
            None
            if adapted_callable is not None
            else super_callable or self._resolve_callable(callee, scope, env)
        )
        if (
            resolved_exact_callable is None
            and callee.get("type") == "MemberExpression"
            and isinstance(callee.get("object"), dict)
            and callee["object"].get("type") in {"CallExpression", "NewExpression"}
        ):
            receiver_value = self._eval(callee.get("object"), scope, env, depth + 1)
            if (
                isinstance(receiver_value, dict)
                and receiver_value.get("label") == _OBJECT_REF
                and isinstance(receiver_value.get("root"), tuple)
            ):
                resolved_receiver_root = receiver_value["root"]
                receiver_methods = self._instance_methods.get(resolved_receiver_root, {})
                definitions = receiver_methods.get(last, [])
                if len(definitions) == 1:
                    resolved_exact_callable = definitions[0], dict(env)
        arg_values: list[dict | None] = []
        arg_taints: list[dict | None] = []
        marker_labels = _STATE_LABELS
        for argument in args:
            if isinstance(argument, dict) and argument.get("type") == "SpreadElement":
                spread_values = self._exact_iterable_values(
                    argument.get("argument"), scope, env, depth + 1
                )
                if spread_values is not None:
                    for spread_value in spread_values:
                        arg_values.append(spread_value)
                        arg_taints.append(
                            None
                            if isinstance(spread_value, dict)
                            and spread_value.get("label") in marker_labels
                            else spread_value
                        )
                    continue
            value = None
            if isinstance(argument, dict) and argument.get("type") in (
                "FunctionExpression",
                "ArrowFunctionExpression",
                "FunctionDeclaration",
            ):
                value = self._function_value(argument, env)
            elif isinstance(argument, dict):
                if argument.get("type") in ("ObjectExpression", "ArrayExpression"):
                    value = self._allocate_literal(argument, scope, env, depth)
                elif argument.get("type") == "Identifier":
                    marker = env.get(self._binding(argument.get("name", ""), scope))
                    if isinstance(marker, dict) and marker.get("label") in marker_labels:
                        value = marker
                if value is None:
                    value = self._eval(argument, scope, env, depth)
                if value is None:
                    known, constant = self._const_value(argument, scope, env)
                    if known:
                        value = {
                            "label": _CONST_VALUE,
                            "value": constant,
                            "line": _line_of(argument),
                        }
            arg_values.append(value)
            arg_taints.append(
                None
                if isinstance(value, dict) and value.get("label") in marker_labels
                else value
            )
        # Any call may synchronously throw after its argument side effects. A surrounding catch
        # therefore observes this exact reaching-definition state, not the pre-try or post-try
        # state. The bounded exception frontier is merged at the owning TryStatement.
        self._capture_exception_state(env)

        # --- SINK checks (value taint against current env) ---
        if resolved_exact_callable is None:
            for value_node, attr, sink_label in self._call_sinks(node, callee, args):
                vt = self._eval(value_node, scope, env, depth)
                # navigation sinks ignore same-origin location components (redirect to
                # location.pathname is not an open redirect); other sinks are unaffected.
                nav = sink_label.startswith("location.") or sink_label == "window.open()"
                if vt is not None and not (nav and _nav_fp_safe(vt)):
                    self._record(node, value_node, attr, sink_label, vt, scope, env)

        if adapted_callable is not None:
            this_root = None
            if arg_values and isinstance(arg_values[0], dict):
                candidate_root = arg_values[0].get("root")
                if (
                    arg_values[0].get("label") == _OBJECT_REF
                    and isinstance(candidate_root, tuple)
                ):
                    this_root = candidate_root
            if function_adapter == "bind":
                function, captured_env = adapted_callable
                closure = dict(captured_env)
                existing_args = closure.get(("call-meta", "bound-args"))
                bound_args = (
                    list(existing_args) if isinstance(existing_args, list) else []
                )
                bound_args.extend(arg_values[1:])
                closure[("call-meta", "bound-args")] = bound_args
                if ("call-meta", "bound-this") not in closure:
                    closure[("call-meta", "bound-this")] = this_root
                return {
                    "label": _FUNCTION_REF,
                    "node": function,
                    "closure": closure,
                    "line": _line_of(node),
                }
            call_values = arg_values[1:]
            if function_adapter == "apply":
                call_values = []
                applied = arg_values[1] if len(arg_values) > 1 else None
                if (
                    isinstance(applied, dict)
                    and applied.get("label") == _OBJECT_REF
                    and applied.get("container") == "array"
                    and isinstance(applied.get("root"), tuple)
                ):
                    applied_root = applied["root"]
                    call_values = [
                        self._heap_path_value(
                            applied_root, (str(index),), env, _line_of(node)
                        )
                        for index in range(self._array_length(applied_root, env))
                    ]
                elif not (
                    isinstance(applied, dict)
                    and applied.get("label") == _CONST_VALUE
                    and applied.get("value") is None
                ):
                    return None
            return self._execute_resolved_call(
                adapted_callable,
                node,
                callee.get("object") or {},
                call_values,
                scope,
                env,
                depth,
                receiver_root=this_root,
            )

        if resolved_exact_callable is not None:
            return self._execute_resolved_call(
                resolved_exact_callable,
                node,
                callee,
                arg_values,
                scope,
                env,
                depth,
                receiver_root=resolved_receiver_root,
            )

        if (
            callee.get("type") == "MemberExpression"
            and last == "apply"
            and _member_root_name(callee) == "reflect"
            and scope.resolve("Reflect") is None
            and args
        ):
            reflected = self._resolve_callable(args[0], scope, env)
            applied = arg_values[2] if len(arg_values) > 2 else None
            if reflected is not None and (
                isinstance(applied, dict)
                and applied.get("label") == _OBJECT_REF
                and applied.get("container") == "array"
                and isinstance(applied.get("root"), tuple)
            ):
                applied_root = applied["root"]
                reflected_values: list[dict | None] = [
                    self._heap_path_value(
                        applied_root, (str(index),), env, _line_of(node)
                    )
                    for index in range(self._array_length(applied_root, env))
                ]
                reflected_this = arg_values[1] if len(arg_values) > 1 else None
                reflected_root = (
                    reflected_this.get("root")
                    if isinstance(reflected_this, dict)
                    and reflected_this.get("label") == _OBJECT_REF
                    and isinstance(reflected_this.get("root"), tuple)
                    else None
                )
                return self._execute_resolved_call(
                    reflected,
                    node,
                    args[0],
                    reflected_values,
                    scope,
                    env,
                    depth,
                    receiver_root=reflected_root,
                )

        if callee.get("type") == "MemberExpression":
            static_object = callee.get("object") or {}
            static_name = static_object.get("name") if static_object.get("type") == "Identifier" else None
            if static_name == "Array" and scope.resolve("Array") is None and last in {
                "from",
                "of",
            }:
                collection_values: list[dict | None]
                if last == "of":
                    collection_values = list(arg_values)
                else:
                    source = arg_values[0] if arg_values else None
                    if not (
                        isinstance(source, dict)
                        and source.get("label") == _OBJECT_REF
                        and source.get("container") == "array"
                        and isinstance(source.get("root"), tuple)
                    ):
                        return None
                    source_root = source["root"]
                    collection_values = [
                        self._heap_path_value(
                            source_root, (str(index),), env, _line_of(node)
                        )
                        for index in range(self._array_length(source_root, env))
                    ]
                    mapper = args[1] if len(args) > 1 else None
                    if isinstance(mapper, dict):
                        mapped_values: list[dict | None] = []
                        for index, value in enumerate(collection_values):
                            resolved, mapped = self._run_callback_result(
                                mapper,
                                {
                                    0: value
                                    or {"label": _CLEAN_VALUE, "line": _line_of(node)},
                                    1: {
                                        "label": _CONST_VALUE,
                                        "value": index,
                                        "line": _line_of(node),
                                    },
                                },
                                scope,
                                env,
                                depth + 1,
                                effect_target=env,
                            )
                            if not resolved:
                                return None
                            mapped_values.append(mapped)
                        collection_values = mapped_values
                result_root = self._new_heap_root()
                for index, value in enumerate(collection_values):
                    env[("heap", *result_root, str(index))] = dict(
                        value
                        or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                    )
                env[("heap-meta", *result_root, "length")] = len(collection_values)
                return {
                    "label": _OBJECT_REF,
                    "root": result_root,
                    "container": "array",
                    "line": _line_of(node),
                }
            if (
                static_name == "Object"
                and scope.resolve("Object") is None
                and last in {"keys", "values", "entries"}
            ):
                source = arg_values[0] if arg_values else None
                if not (
                    isinstance(source, dict)
                    and source.get("label") == _OBJECT_REF
                    and isinstance(source.get("root"), tuple)
                ):
                    return None
                source_root = source["root"]
                property_names = list(
                    dict.fromkeys(
                        str(key[3])
                        for key in env
                        if isinstance(key, tuple)
                        and len(key) >= 4
                        and key[0] == "heap"
                        and key[1:3] == source_root
                    )
                )
                result_values: list[dict | None] = []
                for property_name in property_names:
                    property_value = self._heap_path_value(
                        source_root, (property_name,), env, _line_of(node)
                    )
                    if last == "keys":
                        result_values.append(
                            {
                                "label": _CONST_VALUE,
                                "value": property_name,
                                "line": _line_of(node),
                            }
                        )
                    elif last == "values":
                        result_values.append(property_value)
                    else:
                        entry_root = self._new_heap_root()
                        env[("heap", *entry_root, "0")] = {
                            "label": _CONST_VALUE,
                            "value": property_name,
                            "line": _line_of(node),
                        }
                        env[("heap", *entry_root, "1")] = dict(property_value)
                        env[("heap-meta", *entry_root, "length")] = 2
                        result_values.append(
                            {
                                "label": _OBJECT_REF,
                                "root": entry_root,
                                "container": "array",
                                "line": _line_of(node),
                            }
                        )
                result_root = self._new_heap_root()
                for index, value in enumerate(result_values):
                    env[("heap", *result_root, str(index))] = dict(
                        value
                        or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                    )
                env[("heap-meta", *result_root, "length")] = len(result_values)
                return {
                    "label": _OBJECT_REF,
                    "root": result_root,
                    "container": "array",
                    "line": _line_of(node),
                }

        if callee.get("type") == "MemberExpression" and last == "next":
            generator = self._eval(callee.get("object"), scope, env, depth + 1)
            if isinstance(generator, dict) and generator.get("label") == _GENERATOR_REF:
                yielded_values = generator.get("yielded_values")
                if not isinstance(yielded_values, list):
                    yielded_values = []
                    generator_seed = generator.get("seed")
                    generator_node = generator.get("node")
                    generator_scope = generator.get("scope")
                    if (
                        isinstance(generator_seed, dict)
                        and isinstance(generator_node, dict)
                        and isinstance(generator_scope, int)
                    ):
                        abrupt: list[_AbruptState] = []
                        return_value = self._run_function(
                            generator_node,
                            generator_scope,
                            generator_seed,
                            depth + 1,
                            effect_env=generator_seed,
                            abrupt_target=abrupt,
                            yield_target=yielded_values,
                        )
                        generator["return_value"] = return_value
                        for key, value in generator_seed.items():
                            if (
                                isinstance(key, tuple)
                                and len(key) == 2
                                and isinstance(key[0], int)
                                and not self._scope_descends_from(key[0], generator_scope)
                            ) or (
                                isinstance(key, tuple)
                                and len(key) >= 4
                                and key[0] in {"heap", "heap-meta"}
                            ):
                                env[key] = value
                    generator["yielded_values"] = yielded_values
                    generator["yield_index"] = 0
                yield_index = generator.get("yield_index", 0)
                if not isinstance(yield_index, int) or yield_index < 0:
                    yield_index = 0
                value = (
                    yielded_values[yield_index]
                    if yield_index < len(yielded_values)
                    else generator.get("return_value")
                    if yield_index == len(yielded_values)
                    else None
                )
                generator["yield_index"] = yield_index + 1
                return {
                    "label": _ITERATOR_RESULT_REF,
                    "value": value,
                    "done": yield_index >= len(yielded_values),
                    "line": _line_of(node),
                }

        if (
            callee.get("type") == "MemberExpression"
            and last == "assign"
            and _member_root_name(callee) == "object"
            and scope.resolve("Object") is None
            and arg_values
        ):
            target = arg_values[0]
            target_root = (
                target.get("root")
                if isinstance(target, dict) and target.get("label") == _OBJECT_REF
                else None
            )
            if isinstance(target_root, tuple):
                for source in arg_values[1:]:
                    source_root = (
                        source.get("root")
                        if isinstance(source, dict) and source.get("label") == _OBJECT_REF
                        else None
                    )
                    if not isinstance(source_root, tuple):
                        continue
                    for key, info in list(env.items()):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == source_root
                            and isinstance(info, dict)
                        ):
                            destination = ("heap", target_root[0], target_root[1], *key[3:])
                            env[destination] = dict(info)
                            if len(key) == 4:
                                method_name = str(key[3]).lower()
                                if info.get("label") == _FUNCTION_REF and isinstance(
                                    info.get("node"), dict
                                ):
                                    self._instance_methods.setdefault(target_root, {})[
                                        method_name
                                    ] = [info["node"]]
                                elif target_root in self._instance_methods:
                                    self._instance_methods[target_root].pop(method_name, None)
                return dict(target) if isinstance(target, dict) else None
            return None

        if callee.get("type") == "MemberExpression" and last in {
            "push",
            "pop",
            "shift",
            "unshift",
            "reverse",
            "slice",
            "concat",
            "at",
            "splice",
            "fill",
            "copywithin",
        }:
            receiver_root = self._object_root(callee.get("object"), scope, env)
            receiver_marker = None
            if receiver_root is None and (callee.get("object") or {}).get(
                "type"
            ) == "ArrayExpression":
                receiver_marker = self._allocate_literal(
                    callee["object"], scope, env, depth + 1
                )
                candidate_root = receiver_marker.get("root")
                receiver_root = candidate_root if isinstance(candidate_root, tuple) else None
            receiver_marker = (
                self._object_marker_for_root(receiver_root, env)
                if receiver_root is not None and receiver_marker is None
                else receiver_marker
            )
            if receiver_root is not None and receiver_marker is not None and receiver_marker.get(
                "container"
            ) == "array":
                length = self._array_length(receiver_root, env)

                def constant_index(position: int, default: int) -> int | None:
                    if position >= len(args):
                        return default
                    known, value = self._const_value(args[position], scope, env)
                    if not known or not isinstance(value, int) or isinstance(value, bool):
                        return None
                    return value

                def bounded_index(value: int) -> int:
                    return min(length, max(0, length + value if value < 0 else value))

                def new_array(values: Sequence[dict | None]) -> dict:
                    result_root = self._new_heap_root()
                    for index, value in enumerate(values):
                        env[("heap", *result_root, str(index))] = dict(
                            value
                            or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                        )
                    env[("heap-meta", *result_root, "length")] = len(values)
                    return {
                        "label": _OBJECT_REF,
                        "root": result_root,
                        "container": "array",
                        "line": _line_of(node),
                    }

                if last == "at":
                    raw_index = constant_index(0, 0)
                    if raw_index is None:
                        return None
                    index = raw_index if raw_index >= 0 else length + raw_index
                    if not 0 <= index < length:
                        return {"label": _CLEAN_VALUE, "line": _line_of(node)}
                    return self._heap_path_value(
                        receiver_root, (str(index),), env, _line_of(node)
                    )
                if last == "slice":
                    raw_start = constant_index(0, 0)
                    raw_end = constant_index(1, length)
                    if raw_start is None or raw_end is None:
                        return None
                    start, end = bounded_index(raw_start), bounded_index(raw_end)
                    return new_array(
                        [
                            self._heap_path_value(
                                receiver_root, (str(index),), env, _line_of(node)
                            )
                            for index in range(start, max(start, end))
                        ]
                    )
                if last == "concat":
                    values: list[dict | None] = [
                        self._heap_path_value(
                            receiver_root, (str(index),), env, _line_of(node)
                        )
                        for index in range(length)
                    ]
                    for value in arg_values:
                        if (
                            isinstance(value, dict)
                            and value.get("label") == _OBJECT_REF
                            and value.get("container") == "array"
                            and isinstance(value.get("root"), tuple)
                        ):
                            argument_root = value["root"]
                            values.extend(
                                self._heap_path_value(
                                    argument_root,
                                    (str(index),),
                                    env,
                                    _line_of(node),
                                )
                                for index in range(self._array_length(argument_root, env))
                            )
                        else:
                            values.append(value)
                    return new_array(values)
                if last == "reverse":
                    reverse_moved: dict[tuple, Any] = {}
                    for key, info in list(env.items()):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == receiver_root
                            and str(key[3]).isdigit()
                        ):
                            env.pop(key, None)
                            reverse_moved[
                                (
                                    "heap",
                                    *receiver_root,
                                    str(length - 1 - int(key[3])),
                                    *key[4:],
                                )
                            ] = info
                    env.update(reverse_moved)
                    return dict(receiver_marker)
                if last == "fill":
                    raw_start = constant_index(1, 0)
                    raw_end = constant_index(2, length)
                    if raw_start is None or raw_end is None:
                        return None
                    start, end = bounded_index(raw_start), bounded_index(raw_end)
                    fill_value = arg_values[0] if arg_values else None
                    for key in list(env):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == receiver_root
                            and str(key[3]).isdigit()
                            and start <= int(key[3]) < end
                        ):
                            env.pop(key, None)
                    for index in range(start, end):
                        env[("heap", *receiver_root, str(index))] = dict(
                            fill_value
                            or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                        )
                    return dict(receiver_marker)
                if last == "copywithin":
                    raw_target = constant_index(0, 0)
                    raw_start = constant_index(1, 0)
                    raw_end = constant_index(2, length)
                    if raw_target is None or raw_start is None or raw_end is None:
                        return None
                    copy_target = bounded_index(raw_target)
                    start, end = bounded_index(raw_start), bounded_index(raw_end)
                    count = min(max(0, end - start), max(0, length - copy_target))
                    snapshot = [
                        self._heap_path_value(
                            receiver_root, (str(start + offset),), env, _line_of(node)
                        )
                        for offset in range(count)
                    ]
                    for key in list(env):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == receiver_root
                            and str(key[3]).isdigit()
                            and copy_target <= int(key[3]) < copy_target + count
                        ):
                            env.pop(key, None)
                    for offset, value in enumerate(snapshot):
                        env[("heap", *receiver_root, str(copy_target + offset))] = dict(value)
                    return dict(receiver_marker)
                if last == "splice":
                    raw_start = constant_index(0, 0)
                    raw_delete = constant_index(1, length)
                    if raw_start is None or raw_delete is None:
                        return None
                    start = bounded_index(raw_start)
                    delete_count = min(max(0, raw_delete), length - start)
                    existing = [
                        self._detach_heap_path(
                            receiver_root, (str(index),), env, _line_of(node)
                        )
                        for index in range(length)
                    ]
                    removed = existing[start : start + delete_count]
                    remaining = (
                        existing[:start]
                        + list(arg_values[2:])
                        + existing[start + delete_count :]
                    )
                    for key in list(env):
                        if (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == receiver_root
                            and str(key[3]).isdigit()
                        ):
                            env.pop(key, None)
                    for index, value in enumerate(remaining):
                        env[("heap", *receiver_root, str(index))] = dict(
                            value
                            or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                        )
                    self._set_array_length(receiver_root, env, len(remaining))
                    return new_array(removed)
                if last == "push":
                    for offset, value in enumerate(arg_values):
                        env[("heap", *receiver_root, str(length + offset))] = dict(
                            value or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                        )
                    self._set_array_length(receiver_root, env, length + len(arg_values))
                    return None
                if last == "pop":
                    if length == 0:
                        return None
                    value = self._detach_heap_path(
                        receiver_root,
                        (str(length - 1),),
                        env,
                        _line_of(node),
                    )
                    self._set_array_length(receiver_root, env, length - 1)
                    return value
                if last == "shift":
                    value = self._detach_heap_path(
                        receiver_root, ("0",), env, _line_of(node)
                    )
                    shift_moved: dict[tuple, Any] = {}
                    for key, info in list(env.items()):
                        if not (
                            isinstance(key, tuple)
                            and len(key) >= 4
                            and key[0] == "heap"
                            and key[1:3] == receiver_root
                            and str(key[3]).isdigit()
                        ):
                            continue
                        env.pop(key, None)
                        index = int(key[3])
                        if index > 0:
                            shift_moved[
                                ("heap", *receiver_root, str(index - 1), *key[4:])
                            ] = info
                    env.update(shift_moved)
                    self._set_array_length(receiver_root, env, max(0, length - 1))
                    return value
                shift = len(arg_values)
                unshift_moved: dict[tuple, Any] = {}
                for key, info in list(env.items()):
                    if not (
                        isinstance(key, tuple)
                        and len(key) >= 4
                        and key[0] == "heap"
                        and key[1:3] == receiver_root
                        and str(key[3]).isdigit()
                    ):
                        continue
                    env.pop(key, None)
                    unshift_moved[
                        ("heap", *receiver_root, str(int(key[3]) + shift), *key[4:])
                    ] = info
                env.update(unshift_moved)
                for index, value in enumerate(arg_values):
                    env[("heap", *receiver_root, str(index))] = dict(
                        value or {"label": _CLEAN_VALUE, "line": _line_of(node)}
                    )
                self._set_array_length(receiver_root, env, length + shift)
                return None

        if callee.get("type") == "Identifier" and self._promise_settlement_frames:
            settler = env.get(self._binding(callee.get("name", ""), scope))
            if isinstance(settler, dict) and settler.get("label") in {
                _PROMISE_RESOLVE_FN,
                _PROMISE_REJECT_FN,
            }:
                kind = "resolve" if settler.get("label") == _PROMISE_RESOLVE_FN else "reject"
                conditions = self._current_conditions(env)
                frame = self._promise_settlement_frames[-1]
                if not any(
                    not prior_conditions or prior_conditions == conditions
                    for _, _, prior_conditions in frame
                ):
                    frame.append((kind, arg_values[0] if arg_values else None, conditions))
                return None

        if (
            callee.get("type") == "MemberExpression"
            and self._is_global_promise_member(callee, scope)
            and last in {"resolve", "reject", "all", "race", "any", "allsettled"}
        ):
            return self._promise_state(node, scope, env, depth)

        # --- CALLBACK SEEDING (side effects; must run regardless of this call's return value) ---
        # Promise/AJAX continuations carry the callback's actual return summary into the next
        # continuation. A clean/sanitized return therefore kills taint instead of re-seeding every
        # `.then()` from the original fetch receiver.
        if (
            last in (_PROMISE_CALLBACK_METHODS | _RESP_CALLBACK_METHODS)
            and callee.get("type") == "MemberExpression"
        ):
            promise_state = self._promise_state(node, scope, env, depth)
            if promise_state is not None:
                return promise_state
        # ajax config callbacks: $.ajax({success: fn, done: fn})
        if self._is_direct_ajax_source_expr(node, scope):
            for a in args:
                if isinstance(a, dict) and a.get("type") == "ObjectExpression":
                    for prop in a.get("properties", []) or []:
                        kn = _prop_name({"property": prop.get("key")}) or ""
                        if kn in _RESP_CALLBACK_METHODS and isinstance(prop.get("value"), dict):
                            self._run_callback(
                                prop["value"],
                                {
                                    0: {
                                        "label": "ajax_response",
                                        "line": _line_of(node),
                                        "step": f"AJAX {kn} callback",
                                    }
                                },
                                scope,
                                env,
                                depth,
                            )
        # postMessage source: the callback event's `.data` is attacker-controlled unless the app
        # validates origin/content later. Keep the explicit source kind in the evidence path.
        if last == "addeventlistener" and len(args) >= 2:
            event_name = args[0].get("value") if isinstance(args[0], dict) else None
            if (
                isinstance(event_name, str)
                and event_name.lower() == "message"
                and isinstance(args[1], dict)
            ):
                self._run_callback(
                    args[1],
                    {
                        0: {
                            "label": "postmessage",
                            "line": _line_of(node),
                            "step": "message event data",
                        }
                    },
                    scope,
                    env,
                    depth,
                )
            elif isinstance(event_name, str) and isinstance(args[1], dict):
                self._approx += 1
                try:
                    self._run_callback(args[1], {}, scope, env, depth)
                finally:
                    self._approx -= 1
        if last in ("queuemicrotask", "requestanimationframe") and args:
            callback_root = _member_root_name(callee)
            if callee.get("type") == "Identifier" or callback_root in (
                "window",
                "self",
                "globalthis",
            ):
                callback = args[0]
                if isinstance(callback, dict) and callback.get("type") != "Literal":
                    self._approx += 1
                    try:
                        self._run_callback(callback, {}, scope, env, depth)
                    finally:
                        self._approx -= 1
        if last in ("settimeout", "setinterval") and args:
            timer_root = _member_root_name(callee)
            if callee.get("type") == "Identifier" or timer_root in ("window", "self", "globalthis"):
                callback = args[0]
                if isinstance(callback, dict) and callback.get("type") != "Literal":
                    timer_params = {
                        index: info
                        for index, info in enumerate(arg_values[2:])
                        if info is not None
                    }
                    self._run_callback(callback, timer_params, scope, env, depth)
        # iterator callback binding: recv.map/forEach(cb) / $.each(recv, cb)
        iterator_result = None
        exact_own_callable = self._resolve_callable(callee, scope, env)
        if (
            last in _ITERATOR_METHODS
            and callee.get("type") == "MemberExpression"
            and exact_own_callable is None
        ):
            iterator_result = self._run_iterator(callee, args, scope, env, depth)
        if iterator_result is not None:
            return iterator_result
        if (
            last in {"reduce", "reduceright"}
            and callee.get("type") == "MemberExpression"
            and exact_own_callable is None
        ):
            reduced = self._run_reduce(callee, args, arg_values, scope, env, depth)
            if reduced is not None:
                return reduced

        # --- RETURN taint ---
        # SOURCE: ajax/fetch response (jqXHR / resolved value)
        if self._is_direct_ajax_source_expr(node, scope):
            return {"label": "ajax_response", "line": _line_of(node), "step": "AJAX/fetch response"}

        if (
            callee.get("type") == "MemberExpression"
            and last == "getitem"
            and _member_root_name(callee) in ("localstorage", "sessionstorage")
        ):
            return {
                "label": "browser_storage",
                "line": _line_of(node),
                "step": f"{_member_root_name(callee)}.getItem()",
            }

        # jQuery $(<tainted>) preserves taint
        if callee.get("type") == "Identifier" and (callee.get("name") or "").lower() in (
            "$",
            "jquery",
        ):
            for at in arg_taints:
                if at is not None:
                    return {**at, "step": "$(...)"}
            return None

        # DOM getters -- only on a jQuery receiver (DQ-T02: `calculator.val()` / `obj.data(k)` on an
        # arbitrary receiver are NOT form input).
        if callee.get("type") == "MemberExpression":
            _jq = self._jquery_receiver(callee.get("object"), scope, env)
            if _jq and last in _DOM_GETTER_0 and len(args) == 0:
                return {"label": "dom_input", "line": _line_of(node), "step": f".{last}()"}
            if _jq and last in _DOM_GETTER_1 and len(args) == 1:
                return {"label": "dom_input", "line": _line_of(node), "step": f".{last}()"}

        # A sanitizer remains evidence-bearing until the concrete sink context is known. Exact
        # local callables shadow all global/intrinsic names and are evaluated below instead.
        sanitizer_shadow = self._resolve_callable(callee, scope, env)
        sanitizer_kind = (
            None
            if sanitizer_shadow is not None
            else self._sanitizer_kind(callee, last, scope, env, depth)
        )
        if sanitizer_kind is not None:
            candidates = list(arg_taints)
            if callee.get("type") == "MemberExpression":
                candidates.append(self._eval(callee.get("object"), scope, env, depth))
            for info in candidates:
                if info is not None and info.get("label") not in _STATE_LABELS:
                    sanitizers = set(info.get("sanitizers") or ())
                    sanitizers.add(sanitizer_kind)
                    return {
                        **info,
                        "step": f"verified {last}()",
                        "sanitizers": tuple(sorted(sanitizers)),
                    }
            return None
        if last in _SANITIZERS and sanitizer_shadow is None:
            for info in arg_taints:
                if info is not None:
                    return {**info, "step": f"unverified .{last}()", "approx": True}
            return None
        if last == "replace" and self._is_numeric_strip(args):
            receiver = self._eval(callee.get("object"), scope, env, depth)
            if receiver is not None:
                sanitizers = set(receiver.get("sanitizers") or ())
                sanitizers.add("numeric")
                return {
                    **receiver,
                    "step": "verified numeric replace()",
                    "sanitizers": tuple(sorted(sanitizers)),
                }
            return None
        # JSON.stringify does NOT HTML-escape (`<`/`>`/`&` pass through unchanged), so a tainted
        # value stringified into .html()/innerHTML is still DOM-XSS -- preserve the ARGUMENT taint
        # (it is not a sanitizer). Narrow: only `stringify`, only when an argument is tainted.
        if last == "stringify":
            for at in arg_taints:
                if at is not None:
                    return {**at, "step": "JSON.stringify()"}
            return None

        # string/array transform preserves receiver taint
        if callee.get("type") == "MemberExpression" and last in _TRANSFORMS:
            recv = self._eval(callee.get("object"), scope, env, depth)
            if recv is not None:
                return {**recv, "step": f".{last}()"}
            return None

        # Fetch/Response body decoders preserve server-response taint.
        if callee.get("type") == "MemberExpression" and last in {
            "json",
            "text",
            "blob",
            "arraybuffer",
            "formdata",
        }:
            recv = self._eval(callee.get("object"), scope, env, depth)
            if recv is not None and recv.get("label") == "ajax_response":
                return {**recv, "step": f"Response.{last}()"}

        return None

    def _execute_resolved_call(
        self,
        resolved_callable: tuple[dict, dict],
        node: dict,
        callee: dict,
        arg_values: list[dict | None],
        scope: _Scope,
        env: dict,
        depth: int,
        receiver_root: tuple[int, str] | None = None,
    ) -> dict | None:
        fnode, captured_env = resolved_callable
        fsid = self._func_scope.get(id(fnode))
        if fsid is None:
            return None
        captured_env = dict(captured_env)
        existing_bound_args = captured_env.pop(("call-meta", "bound-args"), None)
        if isinstance(existing_bound_args, list):
            arg_values = [*existing_bound_args, *arg_values]
        bound_this = captured_env.pop(("call-meta", "bound-this"), None)
        if receiver_root is None and isinstance(bound_this, tuple):
            receiver_root = bound_this
        seed = dict(captured_env)
        seed.update(env)
        shared_roots: set[tuple[int, str]] = set()
        for argument in arg_values:
            if isinstance(argument, dict) and argument.get("label") == _OBJECT_REF:
                root = argument.get("root")
                if isinstance(root, tuple) and len(root) == 2:
                    shared_roots.add(root)
        self._seed_parameters(fnode, fsid, arg_values, seed, depth)
        if callee.get("type") == "MemberExpression":
            receiver_root = receiver_root or self._object_root(
                callee.get("object"), scope, env
            )
        if receiver_root is not None:
            shared_roots.add(receiver_root)
            seed[(fsid, "this")] = {
                "label": _OBJECT_REF,
                "root": receiver_root,
                "line": _line_of(node),
            }
        if fnode.get("generator"):
            return {
                "label": _GENERATOR_REF,
                "node": fnode,
                "scope": fsid,
                "seed": seed,
                "line": _line_of(node),
            }
        call_abrupt: list[_AbruptState] | None = [] if fnode.get("async") else None
        result = self._run_function(
            fnode,
            fsid,
            seed,
            depth + 1,
            effect_env=seed,
            abrupt_target=call_abrupt,
        )
        if isinstance(result, dict) and result.get("label") == _OBJECT_REF:
            returned_root = result.get("root")
            if isinstance(returned_root, tuple) and len(returned_root) == 2:
                shared_roots.add(returned_root)
        for root in shared_roots:
            heap_keys = {
                key
                for mapping in (env, seed)
                for key in mapping
                if isinstance(key, tuple)
                and len(key) >= 4
                and key[0] in {"heap", "heap-meta"}
                and key[1:3] == root
            }
            for key in heap_keys:
                if key in seed:
                    env[key] = seed[key]
                else:
                    env.pop(key, None)
        closure_keys = {
            key
            for mapping in (env, seed)
            for key in mapping
            if isinstance(key, tuple)
            and len(key) == 2
            and isinstance(key[0], int)
            and not self._scope_descends_from(key[0], fsid)
        }
        for key in closure_keys:
            if key in seed:
                env[key] = seed[key]
            else:
                env.pop(key, None)
        if fnode.get("async"):
            return self._promise_from_execution(
                fnode,
                result,
                call_abrupt or [],
                _line_of(node),
            )
        last = _callee_last_name(callee)
        return {**result, "step": f"return of {last}()"} if result else None

    def _sanitizer_kind(
        self,
        callee: dict,
        last: str,
        scope: _Scope,
        env: dict,
        depth: int,
    ) -> str | None:
        if callee.get("type") == "Identifier":
            exact_name = callee.get("name") or ""
            if scope.resolve(exact_name) is not None:
                return None
            return {
                "encodeuricomponent": "uri_component",
                "encodeuri": "uri",
                "escape": "uri",
                "number": "numeric",
                "parseint": "numeric",
                "parsefloat": "numeric",
                "btoa": "base64",
            }.get(last)
        if callee.get("type") != "MemberExpression":
            return None
        receiver = callee.get("object") or {}
        if last in {"sanitize", "purify"}:
            if receiver.get("type") == "Identifier":
                name = receiver.get("name") or ""
                marker = env.get(self._binding(name, scope))
                if isinstance(marker, dict) and marker.get("label") == _SANITIZER_REF:
                    return "html"
                if name == "DOMPurify" and scope.resolve(name) is None:
                    return "html"
            return None
        if last == "gettime" and receiver.get("type") == "Identifier":
            marker = env.get(self._binding(receiver.get("name", ""), scope))
            if (
                isinstance(marker, dict)
                and marker.get("label") == _OBJECT_REF
                and marker.get("class_name") == "Date"
                and scope.resolve("Date") is None
            ):
                return "numeric"
            return None
        if last == "tofixed":
            known, value = self._const_value(receiver, scope, env)
            if known and isinstance(value, (int, float)) and not isinstance(value, bool):
                return "numeric"
            receiver_value = self._eval(receiver, scope, env, depth)
            if isinstance(receiver_value, dict) and "numeric" in set(
                receiver_value.get("sanitizers") or ()
            ):
                return "numeric"
        return None

    @staticmethod
    def _promise_marker(
        *,
        fulfilled: bool,
        fulfilled_value: dict | None,
        rejected: bool,
        rejected_value: dict | None,
        line: int,
    ) -> dict:
        return {
            "label": _PROMISE_REF,
            "fulfilled": fulfilled,
            "fulfilled_value": fulfilled_value,
            "rejected": rejected,
            "rejected_value": rejected_value,
            "line": line,
        }

    def _expression_value(
        self, node: Any, scope: _Scope, env: dict, depth: int
    ) -> dict | None:
        if not isinstance(node, dict):
            return None
        if node.get("type") in ("ObjectExpression", "ArrayExpression"):
            return self._allocate_literal(node, scope, env, depth + 1)
        if node.get("type") == "Identifier":
            marker = env.get(self._binding(node.get("name", ""), scope))
            if isinstance(marker, dict) and marker.get("label") in _STATE_LABELS:
                return marker
        value = self._eval(node, scope, env, depth + 1)
        if value is not None:
            return value
        known, constant = self._const_value(node, scope, env)
        return (
            {"label": _CONST_VALUE, "value": constant, "line": _line_of(node)}
            if known
            else None
        )

    def _adopt_promise_value(self, value: dict | None, line: int) -> dict:
        if isinstance(value, dict) and value.get("label") == _PROMISE_REF:
            return dict(value)
        clean_value = (
            None
            if isinstance(value, dict) and value.get("label") in {_CONST_VALUE, _CLEAN_VALUE}
            else value
        )
        return self._promise_marker(
            fulfilled=True,
            fulfilled_value=clean_value,
            rejected=False,
            rejected_value=None,
            line=line,
        )

    def _promise_from_execution(
        self,
        function: dict,
        result: dict | None,
        abrupt: list[_AbruptState],
        line: int,
    ) -> dict:
        outcomes = self._control_outcomes(function.get("body"))
        can_fulfill = bool(outcomes & {"normal", "return"})
        fulfilled_state = (
            self._adopt_promise_value(result, line)
            if can_fulfill
            else self._promise_marker(
                fulfilled=False,
                fulfilled_value=None,
                rejected=False,
                rejected_value=None,
                line=line,
            )
        )
        thrown_values = [
            value if isinstance(value, dict) else None
            for kind, _, value in abrupt
            if kind == "throw"
        ]
        rejected_values = list(thrown_values)
        if fulfilled_state.get("rejected"):
            rejected_value = fulfilled_state.get("rejected_value")
            rejected_values.append(
                rejected_value if isinstance(rejected_value, dict) else None
            )
        return self._promise_marker(
            fulfilled=bool(fulfilled_state.get("fulfilled")),
            fulfilled_value=(
                fulfilled_state.get("fulfilled_value")
                if isinstance(fulfilled_state.get("fulfilled_value"), dict)
                else None
            ),
            rejected=bool(rejected_values),
            rejected_value=self._merge_promise_values(rejected_values),
            line=line,
        )

    def _merge_promise_values(self, values: list[dict | None]) -> dict | None:
        taint_values: list[dict[str, Any] | None] = [
            dict(value)
            for value in values
            if isinstance(value, dict) and value.get("label") not in _STATE_LABELS
        ]
        merged = self._combine_concat_taint(taint_values)
        if merged is not None:
            return {**merged, "approx": True} if len(values) > 1 else merged
        return next(
            (
                value
                for value in values
                if isinstance(value, dict)
                and value.get("label") in {_OBJECT_REF, _FUNCTION_REF, _PROMISE_REF}
            ),
            None,
        )

    def _promise_state(
        self,
        node: Any,
        scope: _Scope,
        env: dict,
        depth: int,
        chain_env: dict | None = None,
    ) -> dict | None:
        """Return a bounded two-channel fulfilled/rejected state for a proven Promise chain."""
        if chain_env is None:
            chain_env = dict(env)
        if not isinstance(node, dict) or depth > _MAX_DEPTH:
            if depth > _MAX_DEPTH:
                self._depth_cap_hit = True
            return None
        if node.get("type") == "AwaitExpression":
            return self._promise_state(node.get("argument"), scope, env, depth + 1, chain_env)
        if node.get("type") == "Identifier":
            marker = chain_env.get(self._binding(node.get("name", ""), scope))
            if isinstance(marker, dict) and marker.get("label") == _PROMISE_REF:
                return dict(marker)
            if isinstance(marker, dict) and marker.get("label") == "ajax_response":
                return self._promise_marker(
                    fulfilled=True,
                    fulfilled_value=marker,
                    rejected=True,
                    rejected_value=None,
                    line=_line_of(node),
                )
            return None
        if node.get("type") == "NewExpression":
            callee = node.get("callee") or {}
            if (
                callee.get("type") != "Identifier"
                or callee.get("name") != "Promise"
                or scope.resolve("Promise") is not None
            ):
                return None
            args = node.get("arguments") or []
            executor = args[0] if args and isinstance(args[0], dict) else None
            if executor is None:
                return None
            settlements: list[tuple[str, dict | None, dict[_PathAtom, bool]]] = []
            executor_abrupt: list[_AbruptState] = []
            self._promise_settlement_frames.append(settlements)
            try:
                self._run_callback_result(
                    executor,
                    {
                        0: {"label": _PROMISE_RESOLVE_FN, "line": _line_of(node)},
                        1: {"label": _PROMISE_REJECT_FN, "line": _line_of(node)},
                    },
                    scope,
                    chain_env,
                    depth + 1,
                    effect_target=chain_env,
                    abrupt_target=executor_abrupt,
                )
            finally:
                self._promise_settlement_frames.pop()
            fulfilled_values: list[dict | None] = []
            executor_rejected_values: list[dict | None] = []
            for kind, value, _ in settlements:
                adopted = self._adopt_promise_value(value, _line_of(node))
                if kind == "resolve":
                    if adopted.get("fulfilled"):
                        fulfilled_values.append(adopted.get("fulfilled_value"))
                    if adopted.get("rejected"):
                        executor_rejected_values.append(adopted.get("rejected_value"))
                else:
                    executor_rejected_values.append(value)
            if not any(not conditions for _, _, conditions in settlements):
                executor_rejected_values.extend(
                    value if isinstance(value, dict) else None
                    for kind, _, value in executor_abrupt
                    if kind == "throw"
                )
            return self._promise_marker(
                fulfilled=bool(fulfilled_values),
                fulfilled_value=self._merge_promise_values(fulfilled_values),
                rejected=bool(executor_rejected_values),
                rejected_value=self._merge_promise_values(executor_rejected_values),
                line=_line_of(node),
            )
        if node.get("type") != "CallExpression":
            return None
        callee = node.get("callee") or {}
        args = node.get("arguments") or []
        last = _callee_last_name(callee)
        if self._is_direct_ajax_source_expr(node, scope):
            return self._promise_marker(
                fulfilled=True,
                fulfilled_value={
                    "label": "ajax_response",
                    "line": _line_of(node),
                    "step": "AJAX/fetch response",
                },
                rejected=True,
                rejected_value=None,
                line=_line_of(node),
            )
        if (
            callee.get("type") == "MemberExpression"
            and self._is_global_promise_member(callee, scope)
            and last in {"all", "race", "any", "allsettled"}
        ):
            collection = args[0] if args and isinstance(args[0], dict) else None
            elements = self._exact_iterable_values(
                collection, scope, chain_env, depth + 1
            )
            if elements is None:
                return None
            states = [
                (
                    dict(element)
                    if isinstance(element, dict) and element.get("label") == _PROMISE_REF
                    else self._adopt_promise_value(element, _line_of(node))
                )
                for element in elements
            ]
            fulfilled_values = [
                state.get("fulfilled_value")
                if isinstance(state.get("fulfilled_value"), dict)
                else None
                for state in states
                if state.get("fulfilled")
            ]
            rejected_values = [
                state.get("rejected_value")
                if isinstance(state.get("rejected_value"), dict)
                else None
                for state in states
                if state.get("rejected")
            ]
            if last in {"race", "any"}:
                raw_elements = (
                    collection.get("elements", [])
                    if isinstance(collection, dict)
                    and collection.get("type") == "ArrayExpression"
                    else []
                )
                direct_settlements = len(raw_elements) == len(states) and all(
                    isinstance(raw, dict)
                    and raw.get("type") == "CallExpression"
                    and isinstance(raw.get("callee"), dict)
                    and self._is_global_promise_member(raw["callee"], scope)
                    and _callee_last_name(raw["callee"]) in {"resolve", "reject"}
                    and bool(state.get("fulfilled")) != bool(state.get("rejected"))
                    for raw, state in zip(raw_elements, states, strict=True)
                )
                if direct_settlements and last == "race" and states:
                    winner = states[0]
                    return self._promise_marker(
                        fulfilled=bool(winner.get("fulfilled")),
                        fulfilled_value=(
                            winner.get("fulfilled_value")
                            if isinstance(winner.get("fulfilled_value"), dict)
                            else None
                        ),
                        rejected=bool(winner.get("rejected")),
                        rejected_value=(
                            winner.get("rejected_value")
                            if isinstance(winner.get("rejected_value"), dict)
                            else None
                        ),
                        line=_line_of(node),
                    )
                if direct_settlements and last == "any":
                    any_winner: dict | None = None
                    for state in states:
                        if state.get("fulfilled"):
                            any_winner = state
                            break
                    if any_winner is not None:
                        fulfilled_value = any_winner.get("fulfilled_value")
                        return self._promise_marker(
                            fulfilled=True,
                            fulfilled_value=(
                                fulfilled_value
                                if isinstance(fulfilled_value, dict)
                                else None
                            ),
                            rejected=False,
                            rejected_value=None,
                            line=_line_of(node),
                        )
                can_fulfill = bool(fulfilled_values)
                can_reject = (
                    bool(rejected_values)
                    if last == "race"
                    else bool(states) and all(state.get("rejected") for state in states)
                )
                return self._promise_marker(
                    fulfilled=can_fulfill,
                    fulfilled_value=self._merge_promise_values(fulfilled_values),
                    rejected=can_reject,
                    rejected_value=(
                        self._merge_promise_values(rejected_values) if can_reject else None
                    ),
                    line=_line_of(node),
                )

            result_root = self._new_heap_root()
            all_fulfilled = all(state.get("fulfilled") for state in states)
            for index, state in enumerate(states):
                fulfilled_value = state.get("fulfilled_value")
                if last == "allsettled":
                    chain_env[("heap", *result_root, str(index), "status")] = {
                        "label": _CONST_VALUE,
                        "value": "fulfilled" if state.get("fulfilled") else "rejected",
                        "line": _line_of(node),
                    }
                    if state.get("fulfilled"):
                        chain_env[("heap", *result_root, str(index), "value")] = dict(
                            fulfilled_value
                            if isinstance(fulfilled_value, dict)
                            else {"label": _CLEAN_VALUE, "line": _line_of(node)}
                        )
                    if state.get("rejected"):
                        rejected_value = state.get("rejected_value")
                        chain_env[("heap", *result_root, str(index), "reason")] = dict(
                            rejected_value
                            if isinstance(rejected_value, dict)
                            else {"label": _CLEAN_VALUE, "line": _line_of(node)}
                        )
                else:
                    chain_env[("heap", *result_root, str(index))] = dict(
                        fulfilled_value
                        if isinstance(fulfilled_value, dict)
                        else {"label": _CLEAN_VALUE, "line": _line_of(node)}
                    )
            chain_env[("heap-meta", *result_root, "length")] = len(elements)
            settled = last == "allsettled"
            return self._promise_marker(
                fulfilled=settled or all_fulfilled,
                fulfilled_value={
                    "label": _OBJECT_REF,
                    "root": result_root,
                    "container": "array",
                    "line": _line_of(node),
                }
                if settled or all_fulfilled
                else None,
                rejected=not settled and bool(rejected_values),
                rejected_value=(
                    self._merge_promise_values(rejected_values)
                    if not settled
                    else None
                ),
                line=_line_of(node),
            )
        if (
            callee.get("type") == "MemberExpression"
            and self._is_global_promise_member(callee, scope)
            and last in {"resolve", "reject"}
        ):
            value = self._expression_value(args[0], scope, chain_env, depth + 1) if args else None
            if last == "resolve":
                return self._adopt_promise_value(value, _line_of(node))
            return self._promise_marker(
                fulfilled=False,
                fulfilled_value=None,
                rejected=True,
                rejected_value=value,
                line=_line_of(node),
            )
        resolved_callable = self._resolve_callable(callee, scope, chain_env)
        if resolved_callable is not None and resolved_callable[0].get("async"):
            evaluated = self._eval(node, scope, chain_env, depth + 1)
            return (
                dict(evaluated)
                if isinstance(evaluated, dict) and evaluated.get("label") == _PROMISE_REF
                else None
            )
        if callee.get("type") != "MemberExpression" or last not in (
            _PROMISE_CALLBACK_METHODS | _RESP_CALLBACK_METHODS
        ):
            return None
        prior = self._promise_state(callee.get("object"), scope, env, depth + 1, chain_env)
        if prior is None:
            return None

        def callback_state(callback: Any, value: Any) -> dict | None:
            if not isinstance(callback, dict) or callback.get("type") == "Literal":
                return None
            seed = {0: value} if isinstance(value, dict) else {}
            callback_abrupt: list[_AbruptState] = []
            resolved, result = self._run_callback_result(
                callback,
                seed,
                scope,
                chain_env,
                depth + 1,
                effect_target=chain_env,
                abrupt_target=callback_abrupt,
            )
            if not resolved:
                return None
            resolved_callback = self._resolve_callable(callback, scope, chain_env)
            function = resolved_callback[0] if resolved_callback is not None else callback
            return self._promise_from_execution(
                function,
                result,
                callback_abrupt,
                _line_of(callback),
            )

        if last in {"done", "success", "complete"}:
            if prior.get("fulfilled") and args:
                callback_state(args[0], prior.get("fulfilled_value"))
            return prior
        if last == "finally":
            if not args or not (prior.get("fulfilled") or prior.get("rejected")):
                return prior
            final_state = callback_state(args[0], None)
            if final_state is None:
                return prior
            callback_fulfills = bool(final_state.get("fulfilled"))
            final_rejected_values: list[dict | None] = []
            if callback_fulfills and prior.get("rejected"):
                original_rejection = prior.get("rejected_value")
                final_rejected_values.append(
                    original_rejection if isinstance(original_rejection, dict) else None
                )
            if final_state.get("rejected"):
                callback_rejection = final_state.get("rejected_value")
                final_rejected_values.append(
                    callback_rejection if isinstance(callback_rejection, dict) else None
                )
            return self._promise_marker(
                fulfilled=callback_fulfills and bool(prior.get("fulfilled")),
                fulfilled_value=(
                    prior.get("fulfilled_value")
                    if callback_fulfills
                    and isinstance(prior.get("fulfilled_value"), dict)
                    else None
                ),
                rejected=bool(final_rejected_values),
                rejected_value=self._merge_promise_values(final_rejected_values),
                line=_line_of(node),
            )

        fulfilled = bool(prior.get("fulfilled"))
        fulfilled_value = prior.get("fulfilled_value")
        rejected = bool(prior.get("rejected"))
        rejected_value = prior.get("rejected_value")
        on_fulfilled = args[0] if last == "then" and args else None
        on_rejected = (
            args[1]
            if last == "then" and len(args) > 1
            else (args[0] if last == "catch" and args else None)
        )
        if fulfilled and on_fulfilled is not None:
            next_state = callback_state(on_fulfilled, fulfilled_value)
            if next_state is not None:
                fulfilled = bool(next_state.get("fulfilled"))
                fulfilled_value = next_state.get("fulfilled_value")
                if next_state.get("rejected"):
                    rejected = True
                    rejected_value = next_state.get("rejected_value")
        if rejected and on_rejected is not None:
            existing_fulfilled = fulfilled
            existing_fulfilled_value = fulfilled_value
            next_state = callback_state(on_rejected, rejected_value)
            if next_state is not None:
                rejected = bool(next_state.get("rejected"))
                rejected_value = next_state.get("rejected_value")
                if next_state.get("fulfilled"):
                    fulfilled = True
                    recovery_value = next_state.get("fulfilled_value")
                    fulfilled_value = (
                        self._merge_promise_values(
                            [
                                existing_fulfilled_value
                                if isinstance(existing_fulfilled_value, dict)
                                else None,
                                recovery_value if isinstance(recovery_value, dict) else None,
                            ]
                        )
                        if existing_fulfilled
                        else recovery_value
                    )
        return self._promise_marker(
            fulfilled=fulfilled,
            fulfilled_value=fulfilled_value if isinstance(fulfilled_value, dict) else None,
            rejected=rejected,
            rejected_value=rejected_value if isinstance(rejected_value, dict) else None,
            line=_line_of(node),
        )

    def _seed_parameters(
        self,
        fn: dict,
        fsid: int,
        values: list[dict | None],
        seed: dict,
        depth: int,
    ) -> None:
        function_scope = self._scopes[fsid]
        for index, param in enumerate(fn.get("params") or []):
            if not isinstance(param, dict):
                continue
            if param.get("type") == "RestElement":
                rest_root = self._new_heap_root()
                rest_values = values[index:]
                for offset, value in enumerate(rest_values):
                    seed[("heap", *rest_root, str(offset))] = dict(
                        value
                        or {
                            "label": _CONST_VALUE,
                            "value": None,
                            "line": _line_of(param),
                        }
                    )
                seed[("heap-meta", *rest_root, "length")] = len(rest_values)
                self._assign_pattern(
                    param.get("argument") or {},
                    {
                        "label": _OBJECT_REF,
                        "root": rest_root,
                        "container": "array",
                        "line": _line_of(param),
                    },
                    function_scope,
                    seed,
                )
                break
            value = values[index] if index < len(values) else None
            if param.get("type") == "Identifier":
                self._assign_pattern(
                    param,
                    value
                    or {
                        "label": _CONST_VALUE,
                        "value": None,
                        "line": _line_of(param),
                    },
                    function_scope,
                    seed,
                )
            else:
                self._assign_destructure(param, value, function_scope, seed, depth + 1)

    def _run_callback_result(
        self,
        fn: dict,
        param_taints: dict[int, dict],
        scope: _Scope,
        env: dict,
        depth: int,
        effect_target: dict | None = None,
        abrupt_target: list[_AbruptState] | None = None,
        this_root: tuple[int, str] | None = None,
    ) -> tuple[bool, dict | None]:
        resolved = self._resolve_callable(fn, scope, env)
        if resolved is None:
            return False, None
        fn, captured_env = resolved
        fsid = self._func_scope.get(id(fn))
        if fsid is None:
            return False, None
        seed = dict(captured_env)
        seed.update(env)
        callback_values = [param_taints.get(index) for index in range(len(fn.get("params") or []))]
        self._seed_parameters(fn, fsid, callback_values, seed, depth)
        if this_root is not None:
            seed[(fsid, "this")] = {
                "label": _OBJECT_REF,
                "root": this_root,
                "container": "object",
                "line": _line_of(fn),
            }
        result = self._run_function(
            fn,
            fsid,
            seed,
            depth + 1,
            effect_env=seed if effect_target is not None else None,
            abrupt_target=abrupt_target,
        )
        if effect_target is not None:
            external_keys = {
                key
                for mapping in (effect_target, seed)
                for key in mapping
                if isinstance(key, tuple)
                and len(key) == 2
                and isinstance(key[0], int)
                and not self._scope_descends_from(key[0], fsid)
            }
            heap_roots = {
                marker.get("root")
                for marker in effect_target.values()
                if isinstance(marker, dict)
                and marker.get("label") == _OBJECT_REF
                and isinstance(marker.get("root"), tuple)
            }
            if this_root is not None:
                heap_roots.add(this_root)
            if isinstance(result, dict) and result.get("label") == _OBJECT_REF:
                returned_root = result.get("root")
                if isinstance(returned_root, tuple):
                    heap_roots.add(returned_root)
            heap_keys = {
                key
                for mapping in (effect_target, seed)
                for key in mapping
                if isinstance(key, tuple)
                and len(key) >= 4
                and key[0] in {"heap", "heap-meta"}
                and key[1:3] in heap_roots
            }
            for key in external_keys | heap_keys:
                if key in seed:
                    effect_target[key] = seed[key]
                else:
                    effect_target.pop(key, None)
        return True, result

    def _run_callback(
        self, fn: dict, param_taints: dict, scope: _Scope, env: dict, depth: int
    ) -> None:
        """Analyze a callback function (lexically nested) with its params seeded + closure env."""
        self._run_callback_result(fn, param_taints, scope, env, depth)

    def _run_iterator(
        self, callee: dict, args: list, scope: _Scope, env: dict, depth: int
    ) -> dict | None:
        last = _callee_last_name(callee)
        if _member_root_name(callee) == "$" and last in ("each", "map") and len(args) >= 2:
            receiver, cb, elem_idx = args[0], args[1], 1
        else:
            receiver, cb, elem_idx = callee.get("object"), (args[0] if args else None), 0
        if not isinstance(receiver, dict) or not isinstance(cb, dict):
            return None

        exact_values = self._exact_iterable_values(receiver, scope, env, depth + 1)
        exact = exact_values is not None
        elements = exact_values or []
        if exact_values is None and receiver.get("type") == "Identifier":
            marker = env.get(self._binding(receiver.get("name", ""), scope))
            if isinstance(marker, dict) and marker.get("label") == "ajax_response":
                elements = [marker]
            elif marker is not None:
                return None
            else:
                elements = [None]
        elif exact_values is None and _member_root_name(callee) == "$":
            elements = [self._eval(receiver, scope, env, depth)]
        elif exact_values is None:
            return None

        callback_results: list[tuple[bool, dict | None]] = []
        for index, element in enumerate(elements):
            seed: dict[int, dict] = {
                elem_idx + 1: {
                    "label": _CONST_VALUE,
                    "value": index,
                    "line": _line_of(receiver),
                }
            }
            if isinstance(element, dict):
                seed[elem_idx] = {**element, "step": "iterator element"}
            if not exact:
                self._approx += 1
            try:
                resolved, result = self._run_callback_result(
                    cb,
                    seed,
                    scope,
                    env,
                    depth,
                    effect_target=env,
                )
                callback_results.append((resolved, result))
            finally:
                if not exact:
                    self._approx -= 1
        if not exact:
            return None
        if last in {"some", "every"} and all(resolved for resolved, _ in callback_results):
            return {"label": _CLEAN_VALUE, "line": _line_of(callee)}
        if last == "find" and all(resolved for resolved, _ in callback_results):
            for element, (_, result) in zip(elements, callback_results, strict=True):
                if not (isinstance(result, dict) and result.get("label") == _CONST_VALUE):
                    return None
                if bool(result.get("value")):
                    return element or {"label": _CLEAN_VALUE, "line": _line_of(callee)}
            return {"label": _CLEAN_VALUE, "line": _line_of(callee)}
        selected = elements
        if last == "filter" and all(resolved for resolved, _ in callback_results):
            selected = []
            for element, (_, result) in zip(elements, callback_results, strict=True):
                if not (isinstance(result, dict) and result.get("label") == _CONST_VALUE):
                    return None
                if bool(result.get("value")):
                    selected.append(element)
        elif last not in {"map", "flatmap"}:
            return None
        result_root = self._new_heap_root()
        if last == "flatmap":
            result_values: list[dict | None] = []
            for _, result in callback_results:
                if (
                    isinstance(result, dict)
                    and result.get("label") == _OBJECT_REF
                    and result.get("container") == "array"
                    and isinstance(result.get("root"), tuple)
                ):
                    nested_root = result["root"]
                    result_values.extend(
                        self._heap_path_value(
                            nested_root, (str(index),), env, _line_of(cb)
                        )
                        for index in range(self._array_length(nested_root, env))
                    )
                else:
                    result_values.append(result)
        else:
            result_values = (
                [result for _, result in callback_results] if last == "map" else selected
            )
        for index, result in enumerate(result_values):
            env[("heap", *result_root, str(index))] = dict(
                result
                if isinstance(result, dict)
                else {"label": _CLEAN_VALUE, "line": _line_of(cb)}
            )
        env[("heap-meta", *result_root, "length")] = len(result_values)
        return {
            "label": _OBJECT_REF,
            "root": result_root,
            "container": "array",
            "line": _line_of(callee),
        }

    def _run_reduce(
        self,
        callee: dict,
        args: list,
        arg_values: list[dict | None],
        scope: _Scope,
        env: dict,
        depth: int,
    ) -> dict | None:
        receiver = callee.get("object") or {}
        callback = args[0] if args and isinstance(args[0], dict) else None
        elements = self._exact_iterable_values(receiver, scope, env, depth + 1)
        if callback is None or elements is None:
            return None
        reverse = _callee_last_name(callee) == "reduceright"
        ordered = list(reversed(elements)) if reverse else list(elements)
        if len(arg_values) > 1:
            accumulator = arg_values[1]
            start = 0
        elif ordered:
            accumulator = ordered[0]
            start = 1
        else:
            return None
        for offset, element in enumerate(ordered[start:], start=start):
            index = len(elements) - 1 - offset if reverse else offset
            resolved, result = self._run_callback_result(
                callback,
                {
                    0: accumulator
                    or {"label": _CLEAN_VALUE, "line": _line_of(callback)},
                    1: element
                    or {"label": _CLEAN_VALUE, "line": _line_of(receiver)},
                    2: {
                        "label": _CONST_VALUE,
                        "value": index,
                        "line": _line_of(receiver),
                    },
                },
                scope,
                env,
                depth + 1,
                effect_target=env,
            )
            if not resolved:
                return None
            accumulator = result
        if isinstance(accumulator, dict) and accumulator.get("label") not in {
            _CLEAN_VALUE,
            _CONST_VALUE,
        }:
            return accumulator
        return None

    def _resolve_callable(
        self, callee: Any, scope: _Scope | None = None, env: dict | None = None
    ) -> tuple[dict, dict] | None:
        """Resolve an exact callable value and its lexical snapshot without name-only dispatch."""
        if not isinstance(callee, dict):
            return None
        if callee.get("type") in (
            "FunctionExpression",
            "ArrowFunctionExpression",
            "FunctionDeclaration",
        ):
            return callee, dict(env or {})
        if callee.get("type") == "Identifier":
            exact_name = callee.get("name") or ""
            if scope is not None:
                binding = self._binding(exact_name, scope)
                marker = env.get(binding) if env is not None else None
                if isinstance(marker, dict) and marker.get("label") == _FUNCTION_REF:
                    node = marker.get("node")
                    closure = marker.get("closure")
                    if isinstance(node, dict):
                        return node, dict(closure) if isinstance(closure, dict) else {}
                if env is not None and binding in env:
                    return None
                definitions = [
                    definition
                    for definition in self._func_by_binding.get(binding, [])
                    if definition.get("type") == "FunctionDeclaration"
                ]
                return (definitions[0], dict(env or {})) if len(definitions) == 1 else None
            name = exact_name.lower()
        elif callee.get("type") == "MemberExpression" and not callee.get("computed"):
            obj = callee.get("object") or {}
            if scope is not None and env is not None:
                if obj.get("type") == "Identifier":
                    static_definitions = self._static_class_methods.get(
                        self._binding(obj.get("name", ""), scope), {}
                    ).get(_prop_name(callee), [])
                    if len(static_definitions) == 1:
                        return static_definitions[0], dict(env)
                heap_key = self._heap_key(callee, scope, env)
                marker = env.get(heap_key) if heap_key is not None else None
                if isinstance(marker, dict) and marker.get("label") == _FUNCTION_REF:
                    node = marker.get("node")
                    closure = marker.get("closure")
                    if isinstance(node, dict):
                        return node, dict(closure) if isinstance(closure, dict) else {}
            if obj.get("type") == "ThisExpression" or (
                obj.get("type") == "Identifier" and (obj.get("name") or "").lower() in _THIS_ALIASES
            ):
                name = _prop_name(callee)
            elif scope is not None and env is not None:
                root = self._object_root(obj, scope, env)
                methods = self._instance_methods.get(root) if root is not None else None
                definitions = methods.get(_prop_name(callee), []) if methods else []
                return (definitions[0], dict(env)) if len(definitions) == 1 else None
            else:
                return None
        else:
            return None
        defs = self._func_by_name.get(name)
        return (defs[0], dict(env or {})) if defs and len(defs) == 1 else None

    def _scope_descends_from(self, scope_id: int, ancestor_id: int) -> bool:
        if not (0 <= scope_id < len(self._scopes)):
            return False
        current: _Scope | None = self._scopes[scope_id]
        while current is not None:
            if current.id == ancestor_id:
                return True
            current = current.parent
        return False

    def _is_numeric_strip(self, args: list) -> bool:
        if len(args) >= 2 and isinstance(args[0], dict) and args[0].get("type") == "Literal":
            rx = args[0].get("regex") or {}
            pat = rx.get("pattern", "") if isinstance(rx, dict) else ""
            return "[^0-9" in pat or "[^\\d" in pat or "\\D" in pat
        return False

    def _is_direct_ajax_source_expr(self, node: Any, scope: _Scope) -> bool:
        if not isinstance(node, dict) or node.get("type") != "CallExpression":
            return False
        callee = node.get("callee") or {}
        last = _callee_last_name(callee)
        if callee.get("type") == "Identifier":
            name = callee.get("name") or ""
            return last in _FETCH_NAMES and scope.resolve(name) is None
        if callee.get("type") != "MemberExpression" or last not in _AJAX_METHODS:
            return False
        root = _member_root_name(callee)
        if root not in _AJAX_ROOTS:
            return False
        root_node = callee.get("object") or {}
        while isinstance(root_node, dict) and root_node.get("type") == "MemberExpression":
            root_node = root_node.get("object") or {}
        exact_root = root_node.get("name") if root_node.get("type") == "Identifier" else None
        return not isinstance(exact_root, str) or scope.resolve(exact_root) is None

    @staticmethod
    def _is_global_promise_member(callee: Any, scope: _Scope) -> bool:
        if not isinstance(callee, dict) or callee.get("type") != "MemberExpression":
            return False
        obj = callee.get("object") or {}
        if obj.get("type") == "Identifier":
            return obj.get("name") == "Promise" and scope.resolve("Promise") is None
        return (
            obj.get("type") == "MemberExpression"
            and _prop_name(obj) == "promise"
            and _member_root_name(obj) in {"globalthis", "window", "self"}
        )

    # ------------------------------------------------------------ sink surface

    def _call_sinks(
        self,
        node: dict[str, Any],
        callee: dict[str, Any],
        args: list[dict[str, Any]],
    ) -> Iterator[tuple[dict[str, Any], str, str]]:
        last = _callee_last_name(callee)
        if last in ("write", "writeln") and _member_root_name(callee) == "document":
            if args:
                yield (args[0], "", "document.write()")
        elif last == "insertadjacenthtml" and len(args) >= 2:
            yield (args[1], "", "insertAdjacentHTML()")
        elif last in _HTML_CALL_SINKS and args:
            yield (args[0], "", f".{last}()")
        elif last == "eval" and args:
            yield (args[0], "", "eval()")
        elif last == "function" and callee.get("type") == "Identifier" and args:
            yield (args[-1], "", "Function()")
        elif last in ("settimeout", "setinterval") and args:
            yield (args[0], "", f"{last}()")
        # navigation / open-redirect sinks -- location.assign/replace(<tainted>), window.open(<tainted>).
        # Object-rooted at location (excludes str.replace / Object.assign) and window/self (excludes
        # xhr.open / a local open()).
        elif last in ("assign", "replace") and _is_location_expr(callee.get("object")) and args:
            yield (args[0], "", f"location.{last}()")
        elif (
            last == "open"
            and callee.get("type") == "MemberExpression"
            and _member_root_name(callee) in ("window", "self")
            and args
        ):
            yield (args[0], "", "window.open()")
        # jQuery factory HTML parsing: $('<div>'+tainted) runs innerHTML on a detached node -> DOM-XSS.
        # Only when the arg is CONSTRUCTED HTML (contains `<`), never a selector like $('#'+id).
        elif (
            callee.get("type") == "Identifier"
            and (callee.get("name") or "").lower() in ("$", "jquery")
            and args
            and _is_built_html(args[0])
        ):
            yield (args[0], "", "$() html")
        # jQuery reverse-insertion: $('<div>'+tainted).appendTo(target) -- the built HTML is the
        # receiver, so the outer call's own name isn't a sink; reach into the $() receiver.
        elif last in _REVERSE_INSERT_METHODS and callee.get("type") == "MemberExpression":
            ob = callee.get("object") or {}
            if (
                isinstance(ob, dict)
                and ob.get("type") == "CallExpression"
                and _callee_last_name(ob.get("callee") or {}) in ("$", "jquery")
            ):
                jargs = ob.get("arguments") or []
                if jargs and _is_built_html(jargs[0]):
                    yield (jargs[0], "", f".{last}()")
        elif last in _ATTR_SINK_CALLS and len(args) >= 2:
            a0 = args[0]
            an = a0.get("value") if isinstance(a0, dict) and a0.get("type") == "Literal" else ""
            if isinstance(an, str) and an.lower() in _DANGEROUS_ATTRS:
                yield (args[1], an.lower(), f".{last}({an.lower()})")
        # jQuery `$(builtHtml)` / `jQuery(builtHtml)`: passing an HTML *string* to the jQuery
        # factory parses it into elements (running `<img onerror>` etc.), so a tainted value
        # concatenated/interpolated into a string that contains a literal `<` is a real DOM-XSS
        # sink. Restricted to built-HTML shape (a `<` in the literal parts) so selector building
        # -- `$("#"+id)`, `$("."+cls)` -- never matches. Bare `$(tainted)` is NOT flagged.
        elif (
            callee.get("type") == "Identifier"
            and last in ("$", "jquery")
            and args
            and self._is_built_html(args[0])
        ):
            yield (args[0], "", "$() html")

    @staticmethod
    def _is_built_html(arg: Any) -> bool:
        """True if `arg` is a string built by concatenation/interpolation whose LITERAL portion
        contains a `<` -- i.e. HTML being constructed, not a jQuery selector. A bare identifier
        or a plain literal returns False (kept out to hold false positives near zero)."""
        if not isinstance(arg, dict):
            return False
        t = arg.get("type")
        if t == "TemplateLiteral":
            return any(
                "<" in ((q.get("value") or {}).get("raw") or "") for q in arg.get("quasis") or []
            )
        if t == "BinaryExpression" and arg.get("operator") == "+":
            parts: list = []
            _flatten_concat(arg, parts)
            return any("<" in _literal_str(p) for p in parts)
        return False

    # ------------------------------------------------------------ finding emission

    @staticmethod
    def _sanitizer_safe_for_sink(info: dict, sink_label: str, attr: str) -> bool:
        sanitizers = set(info.get("sanitizers") or ())
        if not sanitizers:
            return False
        universally_safe = {"numeric", "base64"}
        if sanitizers & universally_safe:
            return True
        code_sink = sink_label in {
            "eval()",
            "Function()",
            "new Function()",
            "settimeout()",
            "setinterval()",
        } or attr.startswith("on")
        if code_sink:
            return False
        navigation_sink = sink_label.startswith("location.") or sink_label in {
            "location=",
            "location.href=",
            "window.open()",
        }
        url_attr = attr in {"href", "src", "action", "formaction", "xlink:href"}
        if navigation_sink or url_attr:
            return "uri_component" in sanitizers
        if attr == "style":
            return False
        return bool(sanitizers & {"html", "uri", "uri_component"})

    def _record(
        self,
        sink_node: dict,
        value_node: dict,
        attr: str,
        sink_label: str,
        info: dict,
        scope: _Scope,
        env: dict,
    ) -> None:
        if info.get("label") in _STATE_LABELS:
            return
        if self._sanitizer_safe_for_sink(info, sink_label, attr):
            return
        current_conditions = self._current_conditions(env)
        if self._conditions_conflict(self._info_conditions(info), current_conditions):
            return
        tainted_src = self._tainted_source_str(value_node, scope, env)
        key = (_line_of(sink_node), sink_label, attr, tainted_src[:48])
        if key in self._seen:
            return
        self._seen.add(key)
        self._findings.append(self._emit(sink_node, attr, sink_label, info, tainted_src))

    def _tainted_source_str(self, node: Any, scope: _Scope, env: dict, depth: int = 0) -> str:
        if not isinstance(node, dict) or depth > 20:
            return _expr_source(node)
        t = node.get("type")
        if t == "TemplateLiteral":
            # DQ-T03: mirror _combine_concat_taint -- show the attacker-controllable (nav-unsafe)
            # operand, not the first tainted one, so an open-redirect finding's displayed value is
            # location.hash (the real source), not a same-origin location.pathname.
            tainted = [
                e
                for e in (node.get("expressions") or [])
                if self._eval(e, scope, env, 0) is not None
            ]
            for e in tainted:
                if not _nav_fp_safe(self._eval(e, scope, env, 0)):
                    return self._tainted_source_str(e, scope, env, depth + 1)
            if tainted:
                return self._tainted_source_str(tainted[0], scope, env, depth + 1)
        elif t == "BinaryExpression" and node.get("operator") == "+":
            parts: list = []
            _flatten_concat(node, parts)
            tainted = [
                p for p in parts if isinstance(p, dict) and self._eval(p, scope, env, 0) is not None
            ]
            for p in tainted:
                if not _nav_fp_safe(self._eval(p, scope, env, 0)):
                    return self._tainted_source_str(p, scope, env, depth + 1)
            if tainted:
                return self._tainted_source_str(tainted[0], scope, env, depth + 1)
        elif t == "CallExpression":
            for a in node.get("arguments", []) or []:
                if self._eval(a, scope, env, 0) is not None:
                    return self._tainted_source_str(a, scope, env, depth + 1)
        return _expr_source(node)

    def _emit(
        self, sink_node: dict, attr: str, sink_label: str, info: dict, sink_source: str
    ) -> RuleResult:
        label = info.get("label", "dom_input")
        sev, conf, human = _SOURCE_SEVERITY.get(
            label, (Severity.MEDIUM, Confidence.MEDIUM, "tainted input")
        )
        src_line = info.get("line", 0)
        sink_line = _line_of(sink_node)
        # DQ-C03 / INV-05: `confirmed` asserts a soundly reachable straight-line def-use chain. If
        # the flow traversed a construct the evaluator only approximates -- a loop body
        # (self._approx) or a conditional cross-branch merge (info["approx"]) -- it is downgraded to
        # `probable`. fp_annotate/reporters/chain_view treat only `confirmed` flows as proven.
        approximate = self._approx > 0 or bool(info.get("approx"))
        confirmed = not approximate
        verdict = "CONFIRMED" if confirmed else "PROBABLE"
        path = [
            f"source: {human} ({info.get('step', 'input')}) @L{src_line}",
            f"tainted value `{sink_source}`",
            f"sink: {sink_label}" + (f" ['{attr}' attribute]" if attr else "") + f" @L{sink_line}",
        ]
        desc = (
            f"{verdict} dataflow: {human} flows into sink {sink_label}"
            + (f" ('{attr}' attribute)" if attr else "")
            + f" via `{sink_source}`. Chain: "
            + " -> ".join(path)
        )
        return RuleResult(
            rule_id=self.id,
            category=self.category,
            severity=sev,
            confidence=conf,
            title=f"Taint flow: {human} -> {sink_label}",
            description=desc,
            extracted_value=f"{human} -> {sink_label}",
            value_type="taint_flow",
            line=sink_line,
            column=((sink_node.get("loc") or {}).get("start") or {}).get("column", 0),
            ast_node_type="",
            tags=["taint_flow", "dataflow_xss", f"source:{label}"],
            metadata={
                "flow_path": path,
                "source_kind": label,
                "source_line": src_line,
                "sink_line": sink_line,
                "sink": sink_label,
                "sink_attr": attr,
                "sink_source": sink_source,
                "confirmed": confirmed,
                "evidence": "confirmed" if confirmed else "probable",
            },
        )
