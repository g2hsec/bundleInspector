"""
enh5: Framework client route-map extraction.

Reconstructs the SPA's full client route table from router configuration (React Router,
Vue Router, Angular, compiled JSX) -- including pages that are never linked in visible nav
(admin/internal/feature-flagged), with parent/child path joining and per-route lazy-chunk
association. Additive: emits `client_route` ENDPOINT findings; never suppresses anything.
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


class RouteDetector(BaseRule):
    id = "route-detector"
    name = "Client Route Detector"
    description = "Reconstructs the client route map (React/Vue/Angular routers, compiled JSX)"
    category = Category.ENDPOINT
    severity = Severity.INFO

    ROUTER_FACTORIES = {
        "createbrowserrouter",
        "createhashrouter",
        "creatememoryrouter",
        "createroutesfromelements",
        "useroutes",
        "createrouter",
    }
    VUE_CTORS = {"vuerouter", "router"}
    NG_MEMBERS = {"forroot", "forchild"}
    JSX_CALLEES = {"createelement", "jsx", "jsxs", "jsxdev", "_jsx", "_jsxs", "_jsxdev"}
    STRONG_KEYS = {
        "element",
        "component",
        "children",
        "loadchildren",
        "loadcomponent",
        "lazy",
        "redirectto",
        "errorelement",
        "handle",
        "index",
        "casesensitive",
        "outlet",
        "templateurl",
    }
    SENSITIVE = {
        "admin",
        "internal",
        "debug",
        "dashboard",
        "settings",
        "config",
        "manage",
        "panel",
        "superuser",
        "staff",
        "private",
        "sudo",
        "secret",
        "hidden",
        "billing",
        "account",
    }
    _SENSITIVE_COMPOUNDS = {
        "adminpanel",
        "administrator",
        "debugmode",
        "internalonly",
        "settingspage",
        "superadmin",
        "sysadmin",
    }
    _ROUTE_BINDING = re.compile(
        r"^(?:r|routes?(?:\d+)?|route(?:config|map|table|list|defs?)?(?:\d+)?)$",
        re.IGNORECASE,
    )
    STATIC_ASSET_EXTENSIONS = {
        ".js",
        ".mjs",
        ".cjs",
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
    }
    _SVG_CMD = re.compile(r"^[MmLlHhVvCcSsQqTtAaZz][\d\s.,\-]")
    _ROUTE_CHARS = re.compile(r"^/?[\w\-.:*/\[\]~()%@${}]+$")

    def __init__(self) -> None:
        self._named_nodes: dict[str, dict] = {}

    def _is_sensitive(self, full: str) -> bool:
        """Classify exact path/camel tokens, plus a short allow-list of common glued names."""
        tokens: list[str] = []
        for segment in re.split(r"[^A-Za-z0-9]+", full or ""):
            if not segment:
                continue
            camel = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", segment)
            tokens.extend(part.lower() for part in camel)
            if segment.lower() in self._SENSITIVE_COMPOUNDS:
                return True
        return any(token in self.SENSITIVE for token in tokens)

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

    def _extract_property_name(self, key: Any) -> str:
        if not isinstance(key, dict):
            return ""
        name = key.get("name")
        if isinstance(name, str) and name:
            return name
        val = key.get("value")
        return val if isinstance(val, str) else ""

    def _callee_last_name(self, callee: Any) -> str:
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

    def _object_name(self, callee: Any) -> str:
        if isinstance(callee, dict) and callee.get("type") == "MemberExpression":
            obj = callee.get("object") or {}
            return obj.get("name", "") or self._callee_last_name(obj)
        return ""

    def _resolve_static_string(self, node: Any) -> str | None:
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

    def _prop_node(self, obj: Any, key: str) -> Any | None:
        obj = self._resolve_node(obj)
        if not isinstance(obj, dict) or obj.get("type") != "ObjectExpression":
            return None
        # Object properties are last-write-wins. Walk spreads as well so a named base route such as
        # `{...baseRoute, element: Page}` retains its path and children.
        for prop in reversed(obj.get("properties", [])):
            if prop.get("type") == "SpreadElement":
                inherited = self._prop_node(prop.get("argument"), key)
                if inherited is not None:
                    return inherited
                continue
            if self._extract_property_name(prop.get("key", {})) == key:
                return prop.get("value")
        return None

    def _resolve_node(self, node: Any, resolving: set[str] | None = None) -> Any:
        if not isinstance(node, dict) or node.get("type") != "Identifier":
            return node
        name = node.get("name")
        if not isinstance(name, str) or name not in self._named_nodes:
            return node
        resolving = set() if resolving is None else set(resolving)
        if name in resolving:
            return node
        resolving.add(name)
        return self._resolve_node(self._named_nodes[name], resolving)

    def _string_prop(self, obj: Any, key: str) -> str | None:
        return self._resolve_static_string(self._prop_node(obj, key))

    def _bool_prop(self, obj: Any, key: str) -> bool | None:
        node = self._prop_node(obj, key)
        if isinstance(node, dict) and node.get("type") == "Literal":
            v = node.get("value")
            if isinstance(v, bool):
                return v
        return None

    def _array_prop(self, obj: Any, key: str) -> dict[str, Any] | None:
        node = self._resolve_node(self._prop_node(obj, key))
        if isinstance(node, dict) and node.get("type") == "ArrayExpression":
            return node
        return None

    def _object_has_key(self, obj: Any, key: str) -> bool:
        return self._prop_node(obj, key) is not None

    def _props_have_strong_key(self, obj: Any) -> bool:
        return any(self._prop_node(obj, key) is not None for key in self.STRONG_KEYS)

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

    def _is_route_object(self, obj: Any) -> bool:
        path = self._string_prop(obj, "path")
        return (
            path is not None and self._path_looks_route(path) and self._props_have_strong_key(obj)
        )

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

    def _extract_component_chunk(self, obj: Any) -> tuple[str | None, str | None]:
        comp = chunk = None
        for key in (
            "element",
            "component",
            "Component",
            "lazy",
            "loadComponent",
            "loadChildren",
            "templateUrl",
        ):
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

    def _next_route_from_source(self, s: Any) -> str | None:
        if not isinstance(s, str):
            return None
        m = re.search(r"(?:/|^)(?:pages|app)/(.+?)(?:/page)?\.(?:t|j)sx?$", s)
        if not m:
            return None
        route = "/" + m.group(1)
        route = re.sub(r"/index$", "/", route)
        route = re.sub(r"\[([^\]]{1,256})\]", r":\1", route)  # bounded: unbounded [^\]]+ was O(n^2)
        return re.sub(r"/{2,}", "/", route)

    # ---- emitters ----
    def _emit_route_object(
        self,
        obj: dict[str, Any],
        parent: str,
        framework: str,
        conf: Confidence,
        processed: set[int],
        seen: set[tuple[str, int]],
        ctx: AnalysisContext,
    ) -> Iterator[RuleResult]:
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
            sev = Severity.MEDIUM if self._is_sensitive(full) else Severity.INFO
            tags = ["route", "client-route", framework]
            if sev == Severity.MEDIUM:
                tags.append("hidden-candidate")
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=sev,
                confidence=conf,
                title=f"Client Route: {full[:60]}",
                description=f"{framework} client route {full}"
                + (f" -> chunk {chunk}" if chunk else ""),
                extracted_value=full,
                value_type="client_route",
                line=line,
                column=col,
                ast_node_type="ObjectExpression",
                tags=tags,
                metadata={
                    "framework": framework,
                    "raw_path": seg,
                    "parent_path": parent,
                    "component": comp,
                    "chunk": chunk,
                    "redirect_to": redirect,
                    "kind": "route",
                },
            )
        children = self._array_prop(obj, "children")
        if children:
            yield from self._emit_collection(children, full, framework, conf, processed, seen, ctx)

    def _emit_collection(
        self,
        node: Any,
        parent: str,
        framework: str,
        conf: Confidence,
        processed: set[int],
        seen: set[tuple[str, int]],
        ctx: AnalysisContext,
    ) -> Iterator[RuleResult]:
        node = self._resolve_node(node)
        if not isinstance(node, dict):
            return
        if node.get("type") == "ArrayExpression":
            for el in node.get("elements", []):
                if isinstance(el, dict) and el.get("type") == "SpreadElement":
                    yield from self._emit_collection(
                        el.get("argument"),
                        parent,
                        framework,
                        conf,
                        processed,
                        seen,
                        ctx,
                    )
                    continue
                resolved = self._resolve_node(el)
                if isinstance(resolved, dict) and resolved.get("type") == "ObjectExpression":
                    yield from self._emit_route_object(
                        resolved,
                        parent,
                        framework,
                        conf,
                        processed,
                        seen,
                        ctx,
                    )
        elif node.get("type") == "ObjectExpression":
            rv = self._array_prop(node, "routes")
            if rv is not None:
                yield from self._emit_collection(rv, parent, framework, conf, processed, seen, ctx)

    def _emit_jsx_route(
        self,
        node: dict[str, Any],
        path_raw: str | None,
        parent: str,
        processed: set[int],
        seen: set[tuple[str, int]],
        ctx: AnalysisContext,
    ) -> Iterator[RuleResult]:
        processed.add(id(node))
        full = self._join(parent, path_raw or "", "react")
        args = node.get("arguments") or []
        props = args[1] if len(args) > 1 else {}
        loc = (node.get("loc") or {}).get("start", {})
        line = loc.get("line", 0)
        comp, chunk = self._extract_component_chunk(props)
        if (full, line) not in seen:
            seen.add((full, line))
            sev = Severity.MEDIUM if self._is_sensitive(full) else Severity.INFO
            tags = ["route", "client-route", "react"] + (
                ["hidden-candidate"] if sev == Severity.MEDIUM else []
            )
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=sev,
                confidence=Confidence.HIGH,
                title=f"Client Route: {full[:60]}",
                description=f"react client route {full}",
                extracted_value=full,
                value_type="client_route",
                line=line,
                column=loc.get("column", 0),
                ast_node_type="CallExpression",
                tags=tags,
                metadata={
                    "framework": "react",
                    "raw_path": path_raw or "",
                    "parent_path": parent,
                    "component": comp,
                    "chunk": chunk,
                    "redirect_to": None,
                    "kind": "route",
                },
            )
        # recurse into child <Route> jsx calls (args 2..)
        children = self._prop_node(props, "children")
        child_nodes = []
        if isinstance(children, dict) and children.get("type") == "ArrayExpression":
            child_nodes = children.get("elements", [])
        elif isinstance(children, dict):
            child_nodes = [children]
        for child in child_nodes:
            if (
                isinstance(child, dict)
                and child.get("type") == "CallExpression"
                and self._callee_last_name(child.get("callee", {})).lower() in self.JSX_CALLEES
            ):
                cargs = child.get("arguments") or []
                cprops = cargs[1] if len(cargs) > 1 else {}
                cpath = self._string_prop(cprops, "path")
                if cpath is not None or self._bool_prop(cprops, "index") is True:
                    if self._props_have_strong_key(cprops):
                        yield from self._emit_jsx_route(
                            child, cpath or "", full, processed, seen, ctx
                        )

    def match(
        self, ir: IntermediateRepresentation, context: AnalysisContext
    ) -> Iterator[RuleResult]:
        ast = ir.raw_ast
        if not isinstance(ast, dict) or not ast:
            return
        processed: set = set()
        seen: set = set()
        nodes = list(self._iter_nodes(ast))
        named_nodes: dict[str, dict] = {}
        ambiguous_names: set[str] = set()
        for node in nodes:
            if node.get("type") != "VariableDeclarator":
                continue
            ident = node.get("id") or {}
            init = node.get("init")
            name = ident.get("name") if isinstance(ident, dict) else None
            if not isinstance(name, str) or not isinstance(init, dict):
                continue
            if name in named_nodes:
                ambiguous_names.add(name)
            else:
                named_nodes[name] = init
        self._named_nodes = {
            name: node for name, node in named_nodes.items() if name not in ambiguous_names
        }

        # PASS 1 - router factory / constructor calls
        for n in nodes:
            t = n.get("type")
            if t == "CallExpression":
                cname = self._callee_last_name(n.get("callee", {})).lower()
                args = n.get("arguments") or []
                if cname in self.ROUTER_FACTORIES and args:
                    framework = "vue" if cname == "createrouter" else "react"
                    yield from self._emit_collection(
                        args[0], "", framework, Confidence.HIGH, processed, seen, context
                    )
                elif (
                    cname in self.NG_MEMBERS
                    and self._object_name(n.get("callee", {})).lower().endswith("routermodule")
                    and args
                ):
                    yield from self._emit_collection(
                        args[0], "", "angular", Confidence.HIGH, processed, seen, context
                    )
            elif (
                t == "NewExpression"
                and self._callee_last_name(n.get("callee", {})).lower() in self.VUE_CTORS
                and (n.get("arguments") or [])
            ):
                yield from self._emit_collection(
                    n["arguments"][0], "", "vue", Confidence.HIGH, processed, seen, context
                )

        # PASS 2 - compiled JSX <Route>
        for n in nodes:
            if id(n) in processed or n.get("type") != "CallExpression":
                continue
            if self._callee_last_name(n.get("callee", {})).lower() not in self.JSX_CALLEES:
                continue
            args = n.get("arguments") or []
            if (
                len(args) < 2
                or not isinstance(args[1], dict)
                or args[1].get("type") != "ObjectExpression"
            ):
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
            framework = (
                "vue"
                if (self._object_has_key(n, "history") or self._object_has_key(n, "mode"))
                else "generic"
            )
            yield from self._emit_collection(
                rv, "", framework, Confidence.MEDIUM, processed, seen, context
            )

        # PASS 4 - named route tables. Restrict the safety net to route-provenance binding names;
        # arbitrary application data frequently has `{path, component}` records too.
        for name, bound in sorted(self._named_nodes.items()):
            if not self._ROUTE_BINDING.match(name):
                continue
            n = self._resolve_node(bound)
            if not isinstance(n, dict) or n.get("type") != "ArrayExpression":
                continue
            objs = [
                self._resolve_node(e)
                for e in n.get("elements", [])
                if isinstance(e, dict) and e.get("type") != "SpreadElement"
            ]
            objs = [e for e in objs if isinstance(e, dict) and e.get("type") == "ObjectExpression"]
            route_objs = [e for e in objs if id(e) not in processed and self._is_route_object(e)]
            if not route_objs:
                continue
            conf = (
                Confidence.MEDIUM
                if (len(route_objs) >= 2 or (objs and len(route_objs) == len(objs)))
                else Confidence.LOW
            )
            for e in route_objs:
                yield from self._emit_route_object(e, "", "generic", conf, processed, seen, context)

        # PASS 5 - Next.js file-based route hints (LOW)
        sources = [
            imp.source for imp in ir.imports if getattr(imp, "is_dynamic", False) and imp.source
        ]
        sources += [
            s.value for s in ir.string_literals if isinstance(getattr(s, "value", None), str)
        ]
        for s in sources:
            route = self._next_route_from_source(s)
            if route and (route, -1) not in seen:
                seen.add((route, -1))
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title=f"Client Route (Next): {route[:60]}",
                    description=f"next file route {route} ({s})",
                    extracted_value=route,
                    value_type="client_route",
                    line=0,
                    column=0,
                    ast_node_type="Literal",
                    tags=["route", "client-route", "next"],
                    metadata={
                        "framework": "next",
                        "raw_path": route,
                        "parent_path": "",
                        "component": None,
                        "chunk": s,
                        "redirect_to": None,
                        "kind": "next_file_route",
                    },
                )
