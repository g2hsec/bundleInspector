"""
enh5: Framework client route-map extraction.

Reconstructs the SPA's full client route table from router configuration (React Router,
Vue Router, Angular, compiled JSX) -- including pages that are never linked in visible nav
(admin/internal/feature-flagged), with parent/child path joining and per-route lazy-chunk
association. Additive: emits `client_route` ENDPOINT findings; never suppresses anything.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import Category, Confidence, IntermediateRepresentation, Severity


class RouteDetector(BaseRule):
    id = "route-detector"
    name = "Client Route Detector"
    description = "Reconstructs the client route map (React/Vue/Angular routers, compiled JSX)"
    category = Category.ENDPOINT
    severity = Severity.INFO

    ROUTER_FACTORIES = {"createbrowserrouter", "createhashrouter", "creatememoryrouter",
                        "createroutesfromelements", "useroutes", "createrouter"}
    VUE_CTORS = {"vuerouter", "router"}
    NG_MEMBERS = {"forroot", "forchild"}
    JSX_CALLEES = {"createelement", "jsx", "jsxs", "jsxdev", "_jsx", "_jsxs", "_jsxdev"}
    STRONG_KEYS = {"element", "component", "children", "loadchildren", "loadcomponent", "lazy",
                   "redirectto", "errorelement", "handle", "index", "casesensitive", "outlet", "templateurl"}
    SENSITIVE = {"admin", "internal", "debug", "dashboard", "settings", "config", "manage",
                 "panel", "superuser", "staff", "private", "sudo", "secret", "hidden", "billing", "account"}
    STATIC_ASSET_EXTENSIONS = {".js", ".mjs", ".cjs", ".css", ".png", ".jpg", ".jpeg", ".gif",
                               ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
    _SVG_CMD = re.compile(r"^[MmLlHhVvCcSsQqTtAaZz][\d\s.,\-]")
    _ROUTE_CHARS = re.compile(r"^/?[\w\-.:*/\[\]~()%@${}]+$")

    # ---- AST helpers (self-contained copies) ----
    def _iter_nodes(self, node: Any) -> Iterator[dict]:
        # Iterative pre-order DFS (children pushed reversed so they pop in source order),
        # byte-identical to the old recursive version but immune to RecursionError on a
        # deeply nested AST -- otherwise RouteDetector.match would yield ZERO routes for that
        # file, dropping unlinked admin/internal pages it exists to surface.
        if not isinstance(node, dict):
            return
        stack = [node]
        while stack:
            cur = stack.pop()
            yield cur
            children: list[dict] = []
            for value in cur.values():
                if isinstance(value, dict):
                    children.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            children.append(item)
            stack.extend(reversed(children))

    def _extract_property_name(self, key) -> str:
        if not isinstance(key, dict):
            return ""
        name = key.get("name")
        if isinstance(name, str) and name:
            return name
        val = key.get("value")
        return val if isinstance(val, str) else ""

    def _callee_last_name(self, callee) -> str:
        if not isinstance(callee, dict):
            return ""
        if callee.get("type") == "Identifier":
            return callee.get("name", "") or ""
        if callee.get("type") in ("MemberExpression", "SequenceExpression"):
            if callee.get("type") == "SequenceExpression":
                exprs = callee.get("expressions", [])
                return self._callee_last_name(exprs[-1]) if exprs else ""
            prop = callee.get("property") or {}
            return prop.get("name", "") or ""
        return ""

    def _object_name(self, callee) -> str:
        if isinstance(callee, dict) and callee.get("type") == "MemberExpression":
            obj = callee.get("object") or {}
            return obj.get("name", "") or self._callee_last_name(obj)
        return ""

    def _resolve_static_string(self, node):
        if not isinstance(node, dict):
            return None
        t = node.get("type")
        if t == "Literal":
            v = node.get("value")
            return v if isinstance(v, str) else None
        if t == "TemplateLiteral":
            quasis, exprs = node.get("quasis", []), node.get("expressions", [])
            parts = []
            for i, q in enumerate(quasis):
                parts.append((q.get("value") or {}).get("cooked", "") or "")
                if i < len(exprs):
                    parts.append("${...}")
            return "".join(parts)
        return None

    def _prop_node(self, obj, key):
        if not isinstance(obj, dict) or obj.get("type") != "ObjectExpression":
            return None
        for prop in obj.get("properties", []):
            if prop.get("type") == "SpreadElement":
                continue
            if self._extract_property_name(prop.get("key", {})) == key:
                return prop.get("value")
        return None

    def _string_prop(self, obj, key):
        return self._resolve_static_string(self._prop_node(obj, key))

    def _bool_prop(self, obj, key):
        node = self._prop_node(obj, key)
        if isinstance(node, dict) and node.get("type") == "Literal":
            v = node.get("value")
            if isinstance(v, bool):
                return v
        return None

    def _array_prop(self, obj, key):
        node = self._prop_node(obj, key)
        if isinstance(node, dict) and node.get("type") == "ArrayExpression":
            return node
        return None

    def _object_has_key(self, obj, key):
        return self._prop_node(obj, key) is not None

    def _props_have_strong_key(self, obj):
        if not isinstance(obj, dict):
            return False
        for prop in obj.get("properties", []):
            if prop.get("type") == "SpreadElement":
                continue
            if self._extract_property_name(prop.get("key", {})).lower() in self.STRONG_KEYS:
                return True
        return False

    def _path_looks_route(self, s: str) -> bool:
        if s in ("", "*", "/"):
            return True
        if any(c.isspace() for c in s) or "://" in s or "\\" in s:
            return False
        low = s.lower().split("?", 1)[0]
        if any(low.endswith(ext) for ext in self.STATIC_ASSET_EXTENSIONS):
            return False
        if self._SVG_CMD.match(s):
            return False
        return bool(self._ROUTE_CHARS.match(s))

    def _is_route_object(self, obj):
        path = self._string_prop(obj, "path")
        return path is not None and self._path_looks_route(path) and self._props_have_strong_key(obj)

    def _join(self, parent: str, seg: str, framework: str) -> str:
        seg = (seg or "").strip()
        if seg.startswith("/"):
            full = seg
        elif seg == "":
            full = parent or "/"
        else:
            full = (parent.rstrip("/") + "/" + seg) if parent else "/" + seg
        full = re.sub(r"/{2,}", "/", full)
        if not full.startswith("/"):
            full = "/" + full
        return full

    def _extract_component_chunk(self, obj):
        comp = chunk = None
        for key in ("element", "component", "Component", "lazy", "loadComponent", "loadChildren", "templateUrl"):
            node = self._prop_node(obj, key)
            if node is None:
                continue
            # Angular legacy 'path#Module'
            s = self._resolve_static_string(node)
            if s and "#" in s:
                chunk = s.split("#", 1)[0]
                comp = s.split("#", 1)[1]
                break
            for sub in self._iter_nodes(node):
                st = sub.get("type")
                if st == "ImportExpression":
                    src = self._resolve_static_string(sub.get("source", {}))
                    if src:
                        chunk = src
                        break
                if st == "CallExpression" and (sub.get("callee") or {}).get("type") == "Import":
                    args = sub.get("arguments") or []
                    src = self._resolve_static_string(args[0]) if args else None
                    if src:
                        chunk = src
                        break
                if st == "Identifier" and comp is None:
                    comp = sub.get("name")
            if chunk:
                break
        return comp, chunk

    def _next_route_from_source(self, s):
        if not isinstance(s, str):
            return None
        m = re.search(r"(?:/|^)(?:pages|app)/(.+?)(?:/page)?\.(?:t|j)sx?$", s)
        if not m:
            return None
        route = "/" + m.group(1)
        route = re.sub(r"/index$", "/", route)
        route = re.sub(r"\[([^\]]+)\]", r":\1", route)
        return re.sub(r"/{2,}", "/", route)

    # ---- emitters ----
    def _emit_route_object(self, obj, parent, framework, conf, processed, seen, ctx):
        processed.add(id(obj))
        path_raw = self._string_prop(obj, "path")
        is_index = self._bool_prop(obj, "index") is True
        redirect = self._string_prop(obj, "redirectTo") or self._string_prop(obj, "redirect")
        if path_raw is None and not is_index and redirect is None:
            return
        if path_raw is not None and not self._path_looks_route(path_raw):
            return
        seg = "" if path_raw is None else path_raw
        full = self._join(parent, seg, framework)
        comp, chunk = self._extract_component_chunk(obj)
        loc = (obj.get("loc") or {}).get("start", {})
        line, col = loc.get("line", 0), loc.get("column", 0)
        if (full, line) not in seen:
            seen.add((full, line))
            sev = Severity.MEDIUM if any(k in full.lower() for k in self.SENSITIVE) else Severity.INFO
            tags = ["route", "client-route", framework]
            if sev == Severity.MEDIUM:
                tags.append("hidden-candidate")
            yield RuleResult(
                rule_id=self.id, category=self.category, severity=sev, confidence=conf,
                title=f"Client Route: {full[:60]}",
                description=f"{framework} client route {full}" + (f" -> chunk {chunk}" if chunk else ""),
                extracted_value=full, value_type="client_route", line=line, column=col,
                ast_node_type="ObjectExpression", tags=tags,
                metadata={"framework": framework, "raw_path": seg, "parent_path": parent,
                          "component": comp, "chunk": chunk, "redirect_to": redirect, "kind": "route"},
            )
        children = self._array_prop(obj, "children")
        if children:
            yield from self._emit_collection(children, full, framework, conf, processed, seen, ctx)

    def _emit_collection(self, node, parent, framework, conf, processed, seen, ctx):
        if not isinstance(node, dict):
            return
        if node.get("type") == "ArrayExpression":
            for el in node.get("elements", []):
                if isinstance(el, dict) and el.get("type") == "ObjectExpression":
                    yield from self._emit_route_object(el, parent, framework, conf, processed, seen, ctx)
        elif node.get("type") == "ObjectExpression":
            rv = self._array_prop(node, "routes")
            if rv is not None:
                yield from self._emit_collection(rv, parent, framework, conf, processed, seen, ctx)

    def _emit_jsx_route(self, node, path_raw, parent, processed, seen, ctx):
        processed.add(id(node))
        full = self._join(parent, path_raw or "", "react")
        args = node.get("arguments") or []
        props = args[1] if len(args) > 1 else {}
        loc = (node.get("loc") or {}).get("start", {})
        line = loc.get("line", 0)
        comp, chunk = self._extract_component_chunk(props)
        if (full, line) not in seen:
            seen.add((full, line))
            sev = Severity.MEDIUM if any(k in full.lower() for k in self.SENSITIVE) else Severity.INFO
            tags = ["route", "client-route", "react"] + (["hidden-candidate"] if sev == Severity.MEDIUM else [])
            yield RuleResult(
                rule_id=self.id, category=self.category, severity=sev, confidence=Confidence.HIGH,
                title=f"Client Route: {full[:60]}", description=f"react client route {full}",
                extracted_value=full, value_type="client_route", line=line, column=loc.get("column", 0),
                ast_node_type="CallExpression", tags=tags,
                metadata={"framework": "react", "raw_path": path_raw or "", "parent_path": parent,
                          "component": comp, "chunk": chunk, "redirect_to": None, "kind": "route"},
            )
        # recurse into child <Route> jsx calls (args 2..)
        children = self._prop_node(props, "children")
        child_nodes = []
        if isinstance(children, dict) and children.get("type") == "ArrayExpression":
            child_nodes = children.get("elements", [])
        elif isinstance(children, dict):
            child_nodes = [children]
        for child in child_nodes:
            if isinstance(child, dict) and child.get("type") == "CallExpression" \
                    and self._callee_last_name(child.get("callee", {})).lower() in self.JSX_CALLEES:
                cargs = child.get("arguments") or []
                cprops = cargs[1] if len(cargs) > 1 else {}
                cpath = self._string_prop(cprops, "path")
                if cpath is not None or self._bool_prop(cprops, "index") is True:
                    if self._props_have_strong_key(cprops):
                        yield from self._emit_jsx_route(child, cpath or "", full, processed, seen, ctx)

    def match(self, ir: IntermediateRepresentation, context: AnalysisContext) -> Iterator[RuleResult]:
        ast = ir.raw_ast
        if not isinstance(ast, dict) or not ast:
            return
        processed: set = set()
        seen: set = set()
        nodes = list(self._iter_nodes(ast))

        # PASS 1 - router factory / constructor calls
        for n in nodes:
            t = n.get("type")
            if t == "CallExpression":
                cname = self._callee_last_name(n.get("callee", {})).lower()
                args = n.get("arguments") or []
                if cname in self.ROUTER_FACTORIES and args:
                    framework = "vue" if cname == "createrouter" else "react"
                    yield from self._emit_collection(args[0], "", framework, Confidence.HIGH, processed, seen, context)
                elif cname in self.NG_MEMBERS and self._object_name(n.get("callee", {})).lower().endswith("routermodule") and args:
                    yield from self._emit_collection(args[0], "", "angular", Confidence.HIGH, processed, seen, context)
            elif t == "NewExpression" and self._callee_last_name(n.get("callee", {})).lower() in self.VUE_CTORS and (n.get("arguments") or []):
                yield from self._emit_collection(n["arguments"][0], "", "vue", Confidence.HIGH, processed, seen, context)

        # PASS 2 - compiled JSX <Route>
        for n in nodes:
            if id(n) in processed or n.get("type") != "CallExpression":
                continue
            if self._callee_last_name(n.get("callee", {})).lower() not in self.JSX_CALLEES:
                continue
            args = n.get("arguments") or []
            if len(args) < 2 or not isinstance(args[1], dict) or args[1].get("type") != "ObjectExpression":
                continue
            props = args[1]
            path_raw = self._string_prop(props, "path")
            if path_raw is None and self._bool_prop(props, "index") is not True:
                continue
            if not self._props_have_strong_key(props):
                continue
            yield from self._emit_jsx_route(n, path_raw or "", "", processed, seen, context)

        # PASS 3 - objects carrying a `routes:` array
        for n in nodes:
            if id(n) in processed or n.get("type") != "ObjectExpression":
                continue
            rv = self._array_prop(n, "routes")
            if rv is None:
                continue
            framework = "vue" if (self._object_has_key(n, "history") or self._object_has_key(n, "mode")) else "generic"
            yield from self._emit_collection(rv, "", framework, Confidence.MEDIUM, processed, seen, context)

        # PASS 4 - generic route-shaped arrays (safety net for minified/aliased factories)
        for n in nodes:
            if n.get("type") != "ArrayExpression" or id(n) in processed:
                continue
            objs = [e for e in n.get("elements", []) if isinstance(e, dict) and e.get("type") == "ObjectExpression"]
            route_objs = [e for e in objs if id(e) not in processed and self._is_route_object(e)]
            if not route_objs:
                continue
            conf = Confidence.MEDIUM if (len(route_objs) >= 2 or (objs and len(route_objs) == len(objs))) else Confidence.LOW
            for e in route_objs:
                yield from self._emit_route_object(e, "", "generic", conf, processed, seen, context)

        # PASS 5 - Next.js file-based route hints (LOW)
        sources = [imp.source for imp in ir.imports if getattr(imp, "is_dynamic", False) and imp.source]
        sources += [s.value for s in ir.string_literals if isinstance(getattr(s, "value", None), str)]
        for s in sources:
            route = self._next_route_from_source(s)
            if route and (route, -1) not in seen:
                seen.add((route, -1))
                yield RuleResult(
                    rule_id=self.id, category=self.category, severity=Severity.INFO, confidence=Confidence.LOW,
                    title=f"Client Route (Next): {route[:60]}", description=f"next file route {route} ({s})",
                    extracted_value=route, value_type="client_route", line=0, column=0,
                    ast_node_type="Literal", tags=["route", "client-route", "next"],
                    metadata={"framework": "next", "raw_path": route, "parent_path": "",
                              "component": None, "chunk": s, "redirect_to": None, "kind": "next_file_route"},
                )
