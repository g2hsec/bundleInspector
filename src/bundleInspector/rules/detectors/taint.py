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

from typing import Any, Iterator, Optional

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)
from bundleInspector.rules.detectors.sinks import (
    _expr_source,
    _flatten_concat,
    _DANGEROUS_ATTRS,
)

# ---------------------------------------------------------------- source / sink / sanitizer tables

_AJAX_METHODS = {"ajax", "get", "post", "getjson"}     # on $/jQuery/axios ('load' excluded: it
_AJAX_ROOTS = {"$", "jquery", "axios"}                 # injects into an element / event-binds)
_FETCH_NAMES = {"fetch"}
_RESPONSE_MEMBERS = {"responsejson", "responsetext", "responsexml"}
_RESP_CALLBACK_METHODS = {"done", "then", "success", "complete"}
_ITERATOR_METHODS = {"map", "foreach", "filter", "some", "every", "find", "flatmap", "each"}
_DOM_GETTER_0 = {"val"}                    # 0-arg jQuery getter -> form input (user-controlled)
# 1-arg getter -> DOM input. `.attr(k)`/`.prop(k)` are excluded: reading an element's own
# attribute (esp. src/href in lazy-load `attr('src') -> attr('src')` patterns) is app/server-set,
# not user input, and produced only low-value self-referential noise. `.data()` is kept (data-*
# attributes commonly carry dynamic/user content).
_DOM_GETTER_1 = {"data"}
_SANITIZERS = {
    "encodeuricomponent", "encodeuri", "escape", "sanitize", "purify",
    "number", "parseint", "parsefloat", "stringify", "formatnumberwithcommas",
    "tofixed", "gettime", "btoa",
}
_THIS_ALIASES = {"this", "self", "_self", "that", "_this", "me", "_me"}
_TRANSFORMS = {
    "map", "filter", "slice", "concat", "find", "join", "trim", "tolowercase",
    "touppercase", "substring", "substr", "split", "pop", "reverse", "flat", "flatmap",
}
_HTML_CALL_SINKS = {"html", "append", "prepend", "after", "before", "replacewith", "wrap"}
_ATTR_SINK_CALLS = {"attr", "prop", "setattribute"}

_SOURCE_SEVERITY = {
    "ajax_response": (Severity.HIGH, Confidence.HIGH, "server response"),
    "dom_input": (Severity.HIGH, Confidence.MEDIUM, "DOM input"),
    "location": (Severity.HIGH, Confidence.MEDIUM, "URL/location"),
    "filereader": (Severity.MEDIUM, Confidence.MEDIUM, "uploaded file (FileReader)"),
}

_READER_OBJ = "__filereader_object__"   # env marker: a var bound to new FileReader()
_MAX_WORK = 400000
_MAX_DEPTH = 60


def _prop_name(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    prop = node.get("property", node)
    if isinstance(prop, dict):
        return (prop.get("name") or (prop.get("value") if isinstance(prop.get("value"), str) else "") or "").lower()
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
        cur = cur.get("object") if t == "MemberExpression" else (cur.get("callee") if t == "CallExpression" else None)
    return ""


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
        return ((node.get("loc") or {}).get("start") or {}).get("line", 0)
    return 0


class _Scope:
    __slots__ = ("id", "parent", "names")

    def __init__(self, sid: int, parent: Optional["_Scope"]):
        self.id = sid
        self.parent = parent
        self.names: set[str] = set()

    def resolve(self, name: str) -> Optional[int]:
        s: Optional[_Scope] = self
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

    def match(self, ir: IntermediateRepresentation, context: AnalysisContext) -> Iterator[RuleResult]:
        ast = ir.raw_ast or {}
        if not isinstance(ast, dict) or not ast:
            return
        try:
            self._scopes: list[_Scope] = []
            self._func_scope: dict[int, int] = {}
            self._func_by_name: dict[str, list[dict]] = {}
            self._all_funcs: list[dict] = []
            self._build_scopes(ast)

            self._findings: list[RuleResult] = []
            self._seen: set[tuple] = set()
            self._analyzing: set[int] = set()
            self._work = 0

            # Program top-level (empty env) + every function as an entry point (params untainted),
            # so intra-function source->sink flows are found even for methods/handlers not reached
            # from top-level. Callees are additionally re-analyzed context-sensitively at call sites.
            self._run_function(ast, 0, {}, 0)
            for fnode in self._all_funcs:
                self._run_function(fnode, self._func_scope[id(fnode)], {}, 0)
            yield from self._findings
        except RecursionError:
            return

    # ------------------------------------------------------------ scope pre-pass

    def _build_scopes(self, ast: dict) -> None:
        self._scopes.append(_Scope(0, None))
        stack = [(ast, self._scopes[0])]
        n = 0
        while stack:
            node, scope = stack.pop()
            n += 1
            if n > _MAX_WORK or not isinstance(node, dict):
                continue
            t = node.get("type")
            child = scope
            if t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
                child = _Scope(len(self._scopes), scope)
                self._scopes.append(child)
                self._func_scope[id(node)] = child.id
                self._all_funcs.append(node)
                for p in node.get("params", []) or []:
                    for nm in self._pattern_names(p):
                        child.names.add(nm)
                fid = node.get("id")
                if isinstance(fid, dict) and fid.get("name"):
                    scope.names.add(fid["name"])
                    self._func_by_name.setdefault(fid["name"].lower(), []).append(node)
            elif t == "VariableDeclarator":
                for nm in self._pattern_names(node.get("id")):
                    scope.names.add(nm)
                init = node.get("init")
                if isinstance(init, dict) and init.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
                    idn = node.get("id")
                    if isinstance(idn, dict) and idn.get("name"):
                        self._func_by_name.setdefault(idn["name"].lower(), []).append(init)
            elif t == "Property":
                val = node.get("value")
                key = node.get("key") or {}
                kn = key.get("name") or (key.get("value") if isinstance(key.get("value"), str) else None)
                if kn and isinstance(val, dict) and val.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
                    self._func_by_name.setdefault(kn.lower(), []).append(val)
            elif t == "CatchClause":
                for nm in self._pattern_names(node.get("param")):
                    scope.names.add(nm)
            for key, value in node.items():
                if key in ("loc", "range", "raw"):
                    continue
                if isinstance(value, dict):
                    stack.append((value, child))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            stack.append((item, child))

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
                    stack.append(prop.get("value") if prop.get("type") == "Property" else prop.get("argument"))
            elif t == "ArrayPattern":
                for el in p.get("elements", []) or []:
                    stack.append(el)
            elif t in ("RestElement", "AssignmentPattern"):
                stack.append(p.get("argument") or p.get("left"))
        return out

    def _binding(self, name: str, scope: _Scope) -> tuple[int, str]:
        sid = scope.resolve(name)
        return (sid if sid is not None else scope.id, name)

    # ------------------------------------------------------------ function analysis (flow-sensitive)

    def _run_function(self, fnode: dict, fsid: int, seed_env: dict, depth: int) -> Optional[dict]:
        """Analyze a function body with `seed_env` (inherited closure env + seeded params), in
        source order (flow-sensitive). Returns the function's return taint. Re-entrancy guard."""
        if depth > 30 or self._work > _MAX_WORK or fsid in self._analyzing:
            return None
        scope = self._scopes[fsid]
        env = dict(seed_env)
        body = fnode if fnode.get("type") == "Program" else fnode.get("body")
        self._analyzing.add(fsid)
        try:
            # arrow with expression body -> the body IS the return expression
            if isinstance(body, dict) and body.get("type") not in ("BlockStatement", "Program"):
                return self._eval(body, scope, env, depth)
            return self._exec(body, scope, env, depth)
        finally:
            self._analyzing.discard(fsid)

    def _exec(self, node: Any, scope: _Scope, env: dict, depth: int) -> Optional[dict]:
        """Execute a statement/block in order, mutating env; returns any return taint."""
        if not isinstance(node, dict) or depth > _MAX_DEPTH:
            return None
        self._work += 1
        if self._work > _MAX_WORK:
            return None
        t = node.get("type")

        if t in ("Program", "BlockStatement"):
            ret = None
            for s in node.get("body", []) or []:
                r = self._exec(s, scope, env, depth)
                if r is not None:
                    ret = r
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
            return self._eval(arg, scope, env, depth) if isinstance(arg, dict) else None
        if t == "IfStatement":
            # Fork the env per branch and UNION at the join -- mutually-exclusive branches must
            # not share taint (else the if-branch's taint leaks into the else-branch's sink).
            self._eval(node.get("test"), scope, env, depth)
            env_then, env_else = dict(env), dict(env)
            r1 = self._exec(node.get("consequent"), scope, env_then, depth)
            r2 = self._exec(node.get("alternate"), scope, env_else, depth)
            self._merge_env(env, env_then, env_else)
            return r1 or r2
        if t in ("ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement"):
            for k in ("init", "left", "right", "test", "update"):
                c = node.get(k)
                if isinstance(c, dict):
                    (self._exec if c.get("type") == "VariableDeclaration" else self._eval)(c, scope, env, depth)
            self._exec(node.get("body"), scope, env, depth)
            return None
        if t == "TryStatement":
            pre = dict(env)
            self._exec(node.get("block"), scope, env, depth)   # try body runs, mutates env
            h = node.get("handler")
            if isinstance(h, dict):
                # the catch handler runs only on an exception -> it cannot see a value assigned by
                # a statement that completed without throwing; analyze it from the pre-try env.
                env_catch = dict(pre)
                self._exec(h.get("body"), scope, env_catch, depth)
                self._merge_env(env, dict(env), env_catch)
            self._exec(node.get("finalizer"), scope, env, depth)  # finally runs on the merged env
            return None
        if t == "SwitchStatement":
            # Each case is (with break) mutually exclusive -> fork from the pre-switch env per case.
            self._eval(node.get("discriminant"), scope, env, depth)
            case_envs = []
            for case in node.get("cases", []) or []:
                ce = dict(env)
                for s in case.get("consequent", []) or []:
                    self._exec(s, scope, ce, depth)
                case_envs.append(ce)
            if case_envs:
                self._merge_env(env, *case_envs)
            return None
        if t in ("LabeledStatement", "WithStatement"):
            return self._exec(node.get("body"), scope, env, depth)
        if t == "FunctionDeclaration":
            return None  # analyzed as its own entry point / at call sites
        # ThrowStatement / others: evaluate embedded expression to catch nested sinks
        if t == "ThrowStatement":
            self._eval(node.get("argument"), scope, env, depth)
        return None

    def _exec_declarator(self, d: dict, scope: _Scope, env: dict, depth: int) -> None:
        idn = d.get("id")
        init = d.get("init")
        if not isinstance(idn, dict):
            return
        if init is None:
            for nm in self._pattern_names(idn):
                env.pop(self._binding(nm, scope), None)
            return
        # track `x = new FileReader()`
        if isinstance(init, dict) and init.get("type") == "NewExpression":
            callee = init.get("callee") or {}
            if callee.get("name") == "FileReader" and idn.get("type") == "Identifier":
                env[self._binding(idn["name"], scope)] = {"label": _READER_OBJ, "line": _line_of(d)}
                return
        rt = self._eval(init, scope, env, depth)
        self._assign_pattern(idn, rt, scope, env)

    def _merge_env(self, env: dict, *branch_envs: dict) -> None:
        """Join point after mutually-exclusive branches: a binding is possibly-tainted afterwards
        iff it is tainted on ANY branch (union). env stores only tainted bindings, so this is the
        union of the branch maps -- safe (a clean-in-both binding stays clean; a sink INSIDE a
        branch was already checked against that branch's own forked env)."""
        merged: dict = {}
        for be in branch_envs:
            for k, v in be.items():
                if v is not None and k not in merged:
                    merged[k] = v
        env.clear()
        env.update(merged)

    def _assign_pattern(self, target: dict, rt: Optional[dict], scope: _Scope, env: dict) -> None:
        tt = target.get("type")
        if tt == "Identifier":
            key = self._binding(target["name"], scope)
            if rt is None:
                env.pop(key, None)          # kill
            else:
                env[key] = rt               # gen
        elif tt in ("ObjectPattern", "ArrayPattern"):
            for nm in self._pattern_names(target):
                key = self._binding(nm, scope)
                if rt is None:
                    env.pop(key, None)
                else:
                    env[key] = {**rt, "step": f"destructure {nm}", "line": rt.get("line", 0)}

    # ------------------------------------------------------------ expression evaluation

    def _eval(self, node: Any, scope: _Scope, env: dict, depth: int) -> Optional[dict]:
        if not isinstance(node, dict) or depth > _MAX_DEPTH:
            return None
        self._work += 1
        if self._work > _MAX_WORK:
            return None
        t = node.get("type")

        if t in ("Literal", "TemplateElement", "ThisExpression"):
            return None
        if t == "Identifier":
            info = env.get(self._binding(node.get("name", ""), scope))
            return None if (info and info.get("label") == _READER_OBJ) else info
        if t == "AssignmentExpression":
            return self._eval_assign(node, scope, env, depth)
        if t == "MemberExpression":
            return self._eval_member(node, scope, env, depth)
        if t == "AwaitExpression":
            return self._eval(node.get("argument"), scope, env, depth)
        if t == "BinaryExpression":
            if node.get("operator") == "+":
                return self._eval(node.get("left"), scope, env, depth) or self._eval(node.get("right"), scope, env, depth)
            self._eval(node.get("left"), scope, env, depth)
            self._eval(node.get("right"), scope, env, depth)
            return None
        if t == "TemplateLiteral":
            hit = None
            for e in node.get("expressions", []) or []:
                r = self._eval(e, scope, env, depth)
                if r is not None and hit is None:
                    hit = r
            return hit
        if t == "ConditionalExpression":
            self._eval(node.get("test"), scope, env, depth)
            return self._eval(node.get("consequent"), scope, env, depth) or self._eval(node.get("alternate"), scope, env, depth)
        if t == "LogicalExpression":
            return self._eval(node.get("left"), scope, env, depth) or self._eval(node.get("right"), scope, env, depth)
        if t == "SequenceExpression":
            r = None
            for e in node.get("expressions", []) or []:
                r = self._eval(e, scope, env, depth)
            return r
        if t == "CallExpression":
            return self._eval_call(node, scope, env, depth)
        if t == "NewExpression":
            for a in node.get("arguments", []) or []:
                self._eval(a, scope, env, depth)
            return None
        if t in ("ArrayExpression", "ObjectExpression"):
            for k in ("elements", "properties"):
                for el in node.get(k, []) or []:
                    if isinstance(el, dict):
                        self._eval(el.get("value") if el.get("type") == "Property" else el, scope, env, depth)
            return None
        if t == "Property":
            return self._eval(node.get("value"), scope, env, depth)
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

    def _eval_member(self, node: dict, scope: _Scope, env: dict, depth: int) -> Optional[dict]:
        obj = node.get("object")
        base = self._eval(obj, scope, env, depth)
        prop = _prop_name(node)
        if base is not None:
            if base.get("label") == "filereader" and base.get("reader"):
                return {**base, "step": "FileReader .result"} if prop in ("result", "target") else None
            if prop == "length":
                return None
            return {**base, "step": f".{prop}"}
        if prop in _RESPONSE_MEMBERS:
            ob = self._eval(obj, scope, env, depth)
            if ob is not None:
                return {**ob, "label": "ajax_response", "step": f".{prop}"}
        root = _member_root_name(node)
        if root == "location":
            return {"label": "location", "line": _line_of(node), "step": "location.*"}
        if root == "document" and prop in ("cookie", "url", "documenturi", "referrer"):
            return {"label": "location", "line": _line_of(node), "step": "document.*"}
        # e.target.value / e.target.files inside an event handler are DOM input
        if prop in ("value", "files") and isinstance(obj, dict) and _prop_name(obj) == "target":
            return {"label": "dom_input", "line": _line_of(node), "step": f"e.target.{prop}"}
        return None

    def _eval_assign(self, node: dict, scope: _Scope, env: dict, depth: int) -> Optional[dict]:
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
                self._run_callback(right, {0: {"label": "filereader", "reader": True,
                                               "line": _line_of(node), "step": "FileReader onload event"}},
                                   scope, env, depth)
            return None
        rt = self._eval(right, scope, env, depth)
        # innerHTML / outerHTML assignment sink
        if left.get("type") == "MemberExpression" and _prop_name(left) in ("innerhtml", "outerhtml"):
            if rt is not None and node.get("operator") == "=":
                self._record(node, right, "", f"{_prop_name(left)}=", rt, scope, env)
            return rt
        # env update for a simple / destructuring target (flow-sensitive kill/gen)
        if node.get("operator") == "=":
            if left.get("type") == "Identifier":
                self._assign_pattern(left, rt, scope, env)
            elif left.get("type") in ("ObjectPattern", "ArrayPattern"):
                self._assign_pattern(left, rt, scope, env)
        return rt

    def _eval_call(self, node: dict, scope: _Scope, env: dict, depth: int) -> Optional[dict]:
        callee = node.get("callee") or {}
        args = node.get("arguments") or []
        last = _callee_last_name(callee)
        arg_taints = [self._eval(a, scope, env, depth) for a in args]

        # --- SINK checks (value taint against current env) ---
        for value_node, attr, sink_label in self._call_sinks(node, callee, args):
            vt = self._eval(value_node, scope, env, depth)
            if vt is not None:
                self._record(node, value_node, attr, sink_label, vt, scope, env)

        # --- CALLBACK SEEDING (side effects; must run regardless of this call's return value) ---
        # response callbacks: recv.done(fn)/.then(fn) where recv is an ajax source
        if last in _RESP_CALLBACK_METHODS and callee.get("type") == "MemberExpression":
            if self._is_ajax_source_expr(callee.get("object")) and args and isinstance(args[0], dict):
                self._run_callback(args[0], {0: {"label": "ajax_response", "line": _line_of(node),
                                                 "step": f"AJAX .{last}() response"}}, scope, env, depth)
        # ajax config callbacks: $.ajax({success: fn, done: fn})
        if self._is_ajax_source_expr(node):
            for a in args:
                if isinstance(a, dict) and a.get("type") == "ObjectExpression":
                    for prop in a.get("properties", []) or []:
                        kn = _prop_name({"property": prop.get("key")}) or ""
                        if kn in _RESP_CALLBACK_METHODS and isinstance(prop.get("value"), dict):
                            self._run_callback(prop["value"], {0: {"label": "ajax_response", "line": _line_of(node),
                                                                   "step": f"AJAX {kn} callback"}}, scope, env, depth)
        # iterator callback binding: recv.map/forEach(cb) / $.each(recv, cb)
        if last in _ITERATOR_METHODS and callee.get("type") == "MemberExpression":
            self._run_iterator(callee, args, arg_taints, scope, env, depth)

        # --- RETURN taint ---
        # SOURCE: ajax/fetch response (jqXHR / resolved value)
        if self._is_ajax_source_expr(node):
            return {"label": "ajax_response", "line": _line_of(node), "step": "AJAX/fetch response"}

        # jQuery $(<tainted>) preserves taint
        if callee.get("type") == "Identifier" and (callee.get("name") or "").lower() in ("$", "jquery"):
            for at in arg_taints:
                if at is not None:
                    return {**at, "step": "$(...)"}
            return None

        # DOM getters
        if callee.get("type") == "MemberExpression":
            if last in _DOM_GETTER_0 and len(args) == 0:
                return {"label": "dom_input", "line": _line_of(node), "step": f".{last}()"}
            if last in _DOM_GETTER_1 and len(args) == 1:
                return {"label": "dom_input", "line": _line_of(node), "step": f".{last}()"}

        # sanitizers -> clean
        if last in _SANITIZERS:
            return None
        if last == "replace" and self._is_numeric_strip(args):
            return None

        # string/array transform preserves receiver taint
        if callee.get("type") == "MemberExpression" and last in _TRANSFORMS:
            recv = self._eval(callee.get("object"), scope, env, depth)
            if recv is not None:
                return {**recv, "step": f".{last}()"}
            return None

        # --- local function call: analyze context-sensitively, return its return taint ---
        fnode = self._resolve_local_function(callee)
        if fnode is not None:
            fsid = self._func_scope.get(id(fnode))
            if fsid is not None:
                seed = dict(env)  # closure: inherit caller env
                params = fnode.get("params") or []
                for i, p in enumerate(params):
                    at = arg_taints[i] if i < len(arg_taints) else None
                    for nm in self._pattern_names(p):
                        key = (fsid, nm)
                        if at is None:
                            seed.pop(key, None)
                        else:
                            seed[key] = at
                r = self._run_function(fnode, fsid, seed, depth + 1)
                return {**r, "step": f"return of {last}()"} if r else None
        return None

    def _run_callback(self, fn: dict, param_taints: dict, scope: _Scope, env: dict, depth: int) -> None:
        """Analyze a callback function (lexically nested) with its params seeded + closure env."""
        if fn.get("type") not in ("FunctionExpression", "ArrowFunctionExpression"):
            return
        fsid = self._func_scope.get(id(fn))
        if fsid is None:
            return
        seed = dict(env)  # closure
        params = fn.get("params") or []
        for idx, info in param_taints.items():
            if idx < len(params) and isinstance(params[idx], dict):
                for nm in self._pattern_names(params[idx]):
                    seed[(fsid, nm)] = info
        self._run_function(fn, fsid, seed, depth + 1)

    def _run_iterator(self, callee: dict, args: list, arg_taints: list, scope: _Scope, env: dict, depth: int) -> None:
        last = _callee_last_name(callee)
        if _member_root_name(callee) == "$" and last in ("each", "map") and len(args) >= 2:
            coll_taint, cb, elem_idx = self._eval(args[0], scope, env, depth), args[1], 1
        else:
            coll_taint, cb, elem_idx = self._eval(callee.get("object"), scope, env, depth), (args[0] if args else None), 0
        if coll_taint is None or not isinstance(cb, dict):
            return  # constant / untainted receiver -> callback element param stays clean
        self._run_callback(cb, {elem_idx: {**coll_taint, "step": "iterator element"}}, scope, env, depth)

    def _resolve_local_function(self, callee: Any) -> Optional[dict]:
        """Resolve a call to a UNIQUE same-file function -- but only for a bare `f()` or a
        `this/self.f()` method, NEVER for an arbitrary `obj.f()` (whose obj we can't identify),
        so a call is never mis-resolved to an unrelated same-name function on another object."""
        if not isinstance(callee, dict):
            return None
        if callee.get("type") == "Identifier":
            name = (callee.get("name") or "").lower()
        elif callee.get("type") == "MemberExpression" and not callee.get("computed"):
            obj = callee.get("object") or {}
            if obj.get("type") == "ThisExpression" or (obj.get("type") == "Identifier" and (obj.get("name") or "").lower() in _THIS_ALIASES):
                name = _prop_name(callee)
            else:
                return None
        else:
            return None
        defs = self._func_by_name.get(name)
        return defs[0] if defs and len(defs) == 1 else None

    def _is_numeric_strip(self, args: list) -> bool:
        if len(args) >= 2 and isinstance(args[0], dict) and args[0].get("type") == "Literal":
            rx = args[0].get("regex") or {}
            pat = rx.get("pattern", "") if isinstance(rx, dict) else ""
            return "[^0-9" in pat or "[^\\d" in pat or "\\D" in pat
        return False

    def _is_ajax_source_expr(self, node: Any) -> bool:
        cur = node
        for _ in range(8):
            if not isinstance(cur, dict):
                return False
            t = cur.get("type")
            if t == "AwaitExpression":
                cur = cur.get("argument"); continue
            if t == "CallExpression":
                callee = cur.get("callee") or {}
                last = _callee_last_name(callee)
                if callee.get("type") == "Identifier" and last in _FETCH_NAMES:
                    return True
                if callee.get("type") == "MemberExpression":
                    if last in _AJAX_METHODS and _member_root_name(callee) in _AJAX_ROOTS:
                        return True
                    if last in _RESP_CALLBACK_METHODS:
                        cur = callee.get("object"); continue
                return False
            return False
        return False

    # ------------------------------------------------------------ sink surface

    def _call_sinks(self, node: dict, callee: dict, args: list):
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
        elif last in _ATTR_SINK_CALLS and len(args) >= 2:
            a0 = args[0]
            an = a0.get("value") if isinstance(a0, dict) and a0.get("type") == "Literal" else ""
            if isinstance(an, str) and an.lower() in _DANGEROUS_ATTRS:
                yield (args[1], an.lower(), f".{last}({an.lower()})")

    # ------------------------------------------------------------ finding emission

    def _record(self, sink_node: dict, value_node: dict, attr: str, sink_label: str,
                info: dict, scope: _Scope, env: dict) -> None:
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
            for e in node.get("expressions", []) or []:
                if self._eval(e, scope, env, 0) is not None:
                    return self._tainted_source_str(e, scope, env, depth + 1)
        elif t == "BinaryExpression" and node.get("operator") == "+":
            parts: list = []
            _flatten_concat(node, parts)
            for p in parts:
                if isinstance(p, dict) and self._eval(p, scope, env, 0) is not None:
                    return self._tainted_source_str(p, scope, env, depth + 1)
        elif t == "CallExpression":
            for a in node.get("arguments", []) or []:
                if self._eval(a, scope, env, 0) is not None:
                    return self._tainted_source_str(a, scope, env, depth + 1)
        return _expr_source(node)

    def _emit(self, sink_node: dict, attr: str, sink_label: str, info: dict, sink_source: str) -> RuleResult:
        label = info.get("label", "dom_input")
        sev, conf, human = _SOURCE_SEVERITY.get(label, (Severity.MEDIUM, Confidence.MEDIUM, "tainted input"))
        src_line = info.get("line", 0)
        sink_line = _line_of(sink_node)
        path = [
            f"source: {human} ({info.get('step', 'input')}) @L{src_line}",
            f"tainted value `{sink_source}`",
            f"sink: {sink_label}" + (f" ['{attr}' attribute]" if attr else "") + f" @L{sink_line}",
        ]
        desc = (f"CONFIRMED dataflow: {human} flows into sink {sink_label}"
                + (f" ('{attr}' attribute)" if attr else "")
                + f" via `{sink_source}`. Chain: " + " -> ".join(path))
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
                "confirmed": True,
            },
        )
