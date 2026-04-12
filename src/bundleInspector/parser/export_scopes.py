"""
Helpers for mapping exported symbols back to likely function scopes.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


_FUNCTION_PREFIX_BY_TYPE = {
    "FunctionDeclaration": "function",
    "FunctionExpression": "function_expr",
    "ArrowFunctionExpression": "arrow",
}


def build_export_scope_map(ir: Any) -> dict[str, list[str]]:
    """Build a practical export symbol -> entry scope map from IR metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return {}

    name_scopes = _build_named_scope_map(ir, raw_ast)
    object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
    class_member_scopes = _collect_class_member_scopes(raw_ast)
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    export_scopes: dict[str, set[str]] = defaultdict(set)

    for node in raw_ast.get("body", []):
        if not isinstance(node, dict):
            continue

        node_type = node.get("type", "")
        if node_type == "ExportDefaultDeclaration":
            declaration = node.get("declaration")
            for scope in _resolve_export_target_scopes(
                declaration,
                name_scopes,
            ):
                export_scopes["default"].add(scope)
            for export_name, scopes in _resolve_export_member_scopes(
                declaration,
                name_scopes,
                member_scopes,
            ).items():
                export_scopes[export_name].update(scopes)
        elif node_type == "ExportNamedDeclaration":
            declaration = node.get("declaration")
            if isinstance(declaration, dict):
                for export_name, scopes in _resolve_named_declaration_scopes(
                    declaration,
                    name_scopes,
                ).items():
                    export_scopes[export_name].update(scopes)
                if declaration.get("type") == "VariableDeclaration":
                    for declarator in declaration.get("declarations", []):
                        if not isinstance(declarator, dict):
                            continue
                        local_name = _identifier_name(declarator.get("id"))
                        if not local_name:
                            continue
                        for export_name, scopes in member_scopes.get(local_name, {}).items():
                            export_scopes[export_name].update(scopes)
                if declaration.get("type") == "ClassDeclaration":
                    local_name = _identifier_name(declaration.get("id"))
                    if local_name:
                        for export_name, scopes in member_scopes.get(local_name, {}).items():
                            export_scopes[export_name].update(scopes)

            for specifier in node.get("specifiers", []):
                if not isinstance(specifier, dict):
                    continue
                exported = _identifier_name(specifier.get("exported"))
                local = _identifier_name(specifier.get("local"))
                if not exported:
                    continue
                export_scopes[exported].add(name_scopes.get(local, "global"))
                for export_name, scopes in _resolve_export_member_scopes(
                    specifier.get("local"),
                    name_scopes,
                    member_scopes,
                ).items():
                    export_scopes[export_name].update(scopes)

    return {
        export_name: sorted(scopes)
        for export_name, scopes in export_scopes.items()
        if scopes
    }


def build_default_object_export_members(ir: Any) -> list[str]:
    """Build a practical list of callable members exposed through an ESM default object export."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return []

    name_scopes = _build_named_scope_map(ir, raw_ast)
    object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
    class_member_scopes = _collect_class_member_scopes(raw_ast)
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: set[str] = set()

    for node in raw_ast.get("body", []):
        if not isinstance(node, dict):
            continue
        if node.get("type") != "ExportDefaultDeclaration":
            continue
        for export_name in _resolve_export_member_scopes(
            node.get("declaration"),
            name_scopes,
            member_scopes,
        ):
            if export_name:
                members.add(export_name)

    return sorted(members)


def build_named_object_export_members(ir: Any) -> dict[str, list[str]]:
    """Build practical callable-member metadata for named object exports."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return {}

    name_scopes = _build_named_scope_map(ir, raw_ast)
    object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
    class_member_scopes = _collect_class_member_scopes(raw_ast)
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: dict[str, set[str]] = defaultdict(set)

    for node in raw_ast.get("body", []):
        if not isinstance(node, dict) or node.get("type") != "ExportNamedDeclaration":
            continue

        declaration = node.get("declaration")
        if isinstance(declaration, dict) and declaration.get("type") == "VariableDeclaration":
            for declarator in declaration.get("declarations", []):
                if not isinstance(declarator, dict):
                    continue
                local_name = _identifier_name(declarator.get("id"))
                if not local_name:
                    continue
                for member_name in member_scopes.get(local_name, {}):
                    if member_name:
                        members[local_name].add(member_name)
        if isinstance(declaration, dict) and declaration.get("type") == "ClassDeclaration":
            local_name = _identifier_name(declaration.get("id"))
            if local_name:
                for member_name in member_scopes.get(local_name, {}):
                    if member_name:
                        members[local_name].add(member_name)

        for specifier in node.get("specifiers", []):
            if not isinstance(specifier, dict):
                continue
            exported = _identifier_name(specifier.get("exported"))
            local = _identifier_name(specifier.get("local"))
            if not exported or not local:
                continue
            for member_name in member_scopes.get(local, {}):
                if member_name:
                    members[exported].add(member_name)

    return {
        export_name: sorted(member_names)
        for export_name, member_names in members.items()
        if member_names
    }


def build_re_export_bindings(ir: Any) -> list[dict[str, object]]:
    """Build practical re-export forwarding bindings from raw AST metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return []

    bindings: list[dict[str, object]] = []
    for node in raw_ast.get("body", []):
        if not isinstance(node, dict):
            continue
        node_type = node.get("type")
        if node_type == "ExportNamedDeclaration":
            source = _literal_source(node.get("source"))
            if not source:
                continue

            for specifier in node.get("specifiers", []):
                if not isinstance(specifier, dict):
                    continue
                exported = _identifier_name(specifier.get("exported"))
                imported = _identifier_name(specifier.get("local"))
                if not exported or not imported:
                    continue
                bindings.append({
                    "source": source,
                    "imported": imported,
                    "local": exported,
                    "kind": "default" if imported == "default" else "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                })
        elif node_type == "ExportAllDeclaration":
            source = _literal_source(node.get("source"))
            if not source:
                continue
            exported = _identifier_name(node.get("exported"))
            bindings.append({
                "source": source,
                "imported": "*",
                "local": exported or "*",
                "kind": "namespace",
                "scope": "global",
                "is_dynamic": False,
                "is_reexport": True,
                "is_reexport_all": True,
            })

    return bindings


def build_commonjs_re_export_bindings(ir: Any) -> list[dict[str, object]]:
    """Build practical CommonJS barrel re-export bindings from raw AST metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return []

    bindings: list[dict[str, object]] = []
    require_aliases = _build_commonjs_require_alias_map(build_commonjs_require_bindings(ir))

    def _visit(node: Any) -> None:
        if not isinstance(node, dict):
            return

        if node.get("type") == "AssignmentExpression" and node.get("operator") == "=":
            target_path = _member_path(node.get("left"))
            if target_path == "module.exports":
                right = node.get("right")
                if isinstance(right, dict) and right.get("type") == "ObjectExpression":
                    for prop in right.get("properties", []):
                        if not isinstance(prop, dict) or prop.get("type") != "Property":
                            continue
                        export_name = _identifier_name(prop.get("key")) or _literal_source(prop.get("key"))
                        forwarded = _extract_commonjs_reexport_target(
                            prop.get("value"),
                            require_aliases,
                        )
                        if not export_name or not forwarded:
                            continue
                        bindings.append({
                            "source": forwarded[0],
                            "imported": forwarded[1],
                            "local": export_name,
                            "kind": "default" if forwarded[1] == "default" else "named",
                            "scope": "global",
                            "is_dynamic": False,
                            "is_reexport": True,
                            "is_commonjs_reexport": True,
                        })
                else:
                    forwarded = _extract_commonjs_reexport_target(right, require_aliases)
                    if forwarded:
                        bindings.append({
                            "source": forwarded[0],
                            "imported": forwarded[1],
                            "local": "default",
                            "kind": "default" if forwarded[1] == "default" else "named",
                            "scope": "global",
                            "is_dynamic": False,
                            "is_reexport": True,
                            "is_commonjs_reexport": True,
                        })
            elif target_path.startswith("module.exports.") or target_path.startswith("exports."):
                export_name = target_path.split(".")[-1]
                forwarded = _extract_commonjs_reexport_target(node.get("right"), require_aliases)
                if export_name and forwarded:
                    bindings.append({
                        "source": forwarded[0],
                        "imported": forwarded[1],
                        "local": export_name,
                        "kind": "default" if forwarded[1] == "default" else "named",
                        "scope": "global",
                        "is_dynamic": False,
                        "is_reexport": True,
                        "is_commonjs_reexport": True,
                    })

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(raw_ast)
    return bindings


def build_commonjs_require_bindings(ir: Any) -> list[dict[str, object]]:
    """Build practical `require()` import bindings from raw AST metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return []

    bindings: list[dict[str, object]] = []

    def _visit(node: Any, scope: str = "global") -> None:
        if not isinstance(node, dict):
            return

        node_type = node.get("type", "")
        if node_type in _FUNCTION_PREFIX_BY_TYPE:
            function_scope = _derive_function_scope(node) or scope
            for param in node.get("params", []):
                _visit(param, function_scope)
            body = node.get("body")
            if body:
                _visit(body, function_scope)
            return

        if node_type == "VariableDeclarator":
            bindings.extend(
                _extract_commonjs_require_binding_targets(
                    node.get("id"),
                    node.get("init"),
                    scope,
                )
            )
        elif node_type == "AssignmentExpression" and node.get("operator") == "=":
            bindings.extend(
                _extract_commonjs_require_binding_targets(
                    node.get("left"),
                    node.get("right"),
                    scope,
                )
            )

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value, scope)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item, scope)

    _visit(raw_ast)
    return bindings


def build_commonjs_export_metadata(ir: Any) -> tuple[list[str], dict[str, list[str]]]:
    """Build practical CommonJS export names and entry scopes from raw AST metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return [], {}

    name_scopes = _build_named_scope_map(ir, raw_ast)
    object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
    class_member_scopes = _collect_class_member_scopes(raw_ast)
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    export_names: set[str] = set()
    export_scopes: dict[str, set[str]] = defaultdict(set)

    def _visit(node: Any) -> None:
        if not isinstance(node, dict):
            return

        if node.get("type") == "AssignmentExpression" and node.get("operator") == "=":
            target_path = _member_path(node.get("left"))
            if target_path == "module.exports":
                right = node.get("right")
                if isinstance(right, dict) and right.get("type") == "ObjectExpression":
                    for export_name, scopes in _resolve_object_export_scopes(right, name_scopes).items():
                        export_names.add(export_name)
                        export_scopes[export_name].update(scopes)
                else:
                    export_names.add("default")
                    export_scopes["default"].update(
                        _resolve_export_target_scopes(right, name_scopes)
                    )
                    for export_name, scopes in _resolve_export_member_scopes(
                        right,
                        name_scopes,
                        member_scopes,
                    ).items():
                        export_scopes[export_name].update(scopes)
            elif target_path.startswith("module.exports.") or target_path.startswith("exports."):
                export_name = target_path.split(".")[-1]
                if export_name:
                    export_names.add(export_name)
                    export_scopes[export_name].update(
                        _resolve_export_target_scopes(node.get("right"), name_scopes)
                    )
                    for member_name, scopes in _resolve_export_member_scopes(
                        node.get("right"),
                        name_scopes,
                        member_scopes,
                    ).items():
                        export_scopes[member_name].update(scopes)

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(raw_ast)
    return sorted(export_names), {
        export_name: sorted(scopes)
        for export_name, scopes in export_scopes.items()
        if scopes
    }


def build_commonjs_default_object_export_members(ir: Any) -> list[str]:
    """Build a practical list of callable members exposed through `module.exports = { ... }`."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return []

    name_scopes = _build_named_scope_map(ir, raw_ast)
    object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
    class_member_scopes = _collect_class_member_scopes(raw_ast)
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: set[str] = set()

    def _visit(node: Any) -> None:
        if not isinstance(node, dict):
            return

        if node.get("type") == "AssignmentExpression" and node.get("operator") == "=":
            target_path = _member_path(node.get("left"))
            if target_path == "module.exports":
                right = node.get("right")
                resolved_members = _resolve_export_member_scopes(
                    right,
                    name_scopes,
                    member_scopes,
                )
                for export_name in resolved_members:
                    if export_name:
                        members.add(export_name)

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(raw_ast)
    return sorted(members)


def build_commonjs_named_object_export_members(ir: Any) -> dict[str, list[str]]:
    """Build callable-member metadata for named CommonJS object exports."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return {}

    name_scopes = _build_named_scope_map(ir, raw_ast)
    object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
    class_member_scopes = _collect_class_member_scopes(raw_ast)
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: dict[str, set[str]] = defaultdict(set)

    def _visit(node: Any) -> None:
        if not isinstance(node, dict):
            return

        if node.get("type") == "AssignmentExpression" and node.get("operator") == "=":
            target_path = _member_path(node.get("left"))
            right = node.get("right")
            if target_path == "module.exports" and isinstance(right, dict) and right.get("type") == "ObjectExpression":
                for prop in right.get("properties", []):
                    if not isinstance(prop, dict) or prop.get("type") != "Property":
                        continue
                    export_name = _identifier_name(prop.get("key")) or _literal_source(prop.get("key"))
                    if not export_name:
                        continue
                    for member_name in _resolve_export_member_scopes(
                        prop.get("value"),
                        name_scopes,
                        member_scopes,
                    ):
                        if member_name:
                            members[export_name].add(member_name)
            elif target_path.startswith("module.exports.") or target_path.startswith("exports."):
                export_name = target_path.split(".")[-1]
                if export_name:
                    for member_name in _resolve_export_member_scopes(
                        right,
                        name_scopes,
                        member_scopes,
                    ):
                        if member_name:
                            members[export_name].add(member_name)

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(raw_ast)
    return {
        export_name: sorted(member_names)
        for export_name, member_names in members.items()
        if member_names
    }


def _build_named_scope_map(ir: Any, raw_ast: dict[str, Any]) -> dict[str, str]:
    """Build a practical local-name -> scope map for exported bindings."""
    name_scopes: dict[str, str] = {}

    for function_def in getattr(ir, "function_defs", []):
        name = (getattr(function_def, "name", "") or "").strip()
        scope = (getattr(function_def, "scope", "") or "").strip()
        if name and scope:
            name_scopes[name] = scope

    for local_name, scope in _collect_variable_function_scopes(raw_ast).items():
        name_scopes.setdefault(local_name, scope)

    return name_scopes


def _extract_commonjs_require_binding_targets(
    target: Any,
    value: Any,
    scope: str,
) -> list[dict[str, object]]:
    """Extract practical CommonJS bindings from `require()` assignment targets."""
    source, member_import = _extract_commonjs_require_source(value)
    if not source or not isinstance(target, dict):
        return []

    if target.get("type") == "Identifier":
        local = _identifier_name(target)
        if not local:
            return []
        imported = member_import or "default"
        return [{
            "source": source,
            "imported": imported,
            "local": local,
            "kind": "default" if imported == "default" else "named",
            "scope": scope,
            "is_dynamic": False,
            "is_commonjs": True,
        }]

    if target.get("type") != "ObjectPattern" or member_import:
        return []

    bindings: list[dict[str, object]] = []
    for prop in target.get("properties", []):
        if not isinstance(prop, dict) or prop.get("type") != "Property":
            continue
        imported = _identifier_name(prop.get("key")) or _literal_source(prop.get("key"))
        local = _pattern_target_name(prop.get("value"))
        if not imported or not local:
            continue
        bindings.append({
            "source": source,
            "imported": imported,
            "local": local,
            "kind": "default" if imported == "default" else "named",
            "scope": scope,
            "is_dynamic": False,
            "is_commonjs": True,
        })
    return bindings


def _extract_commonjs_require_source(node: Any) -> tuple[str, str]:
    """Extract a `require()` source and optional member import from an expression."""
    if not isinstance(node, dict):
        return "", ""

    if _is_require_call(node):
        arguments = node.get("arguments") or []
        if not arguments:
            return "", ""
        return _literal_source(arguments[0]), ""

    if node.get("type") == "MemberExpression":
        source, _ = _extract_commonjs_require_source(node.get("object"))
        if not source:
            return "", ""
        return source, _member_property_name(node)

    return "", ""


def _build_commonjs_require_alias_map(bindings: list[dict[str, object]]) -> dict[str, tuple[str, str]]:
    """Build a practical local-name -> require target map for CommonJS barrel forwarding."""
    aliases: dict[str, tuple[str, str]] = {}
    for binding in bindings:
        local = str(binding.get("local") or "").strip()
        source = str(binding.get("source") or "").strip()
        imported = str(binding.get("imported") or "default").strip() or "default"
        scope = str(binding.get("scope") or "global").strip() or "global"
        if not local or not source or scope != "global":
            continue
        aliases.setdefault(local, (source, imported))
    return aliases


def _extract_commonjs_reexport_target(
    node: Any,
    require_aliases: dict[str, tuple[str, str]] | None = None,
) -> tuple[str, str]:
    """Extract forwarded source/symbol info from CommonJS re-export expressions."""
    source, imported = _extract_commonjs_require_source(node)
    if source:
        return source, imported or "default"

    if not isinstance(node, dict):
        return "", ""

    require_aliases = require_aliases or {}

    if node.get("type") == "Identifier":
        alias = require_aliases.get(_identifier_name(node))
        if alias:
            return alias

    if node.get("type") == "MemberExpression":
        object_node = node.get("object")
        if isinstance(object_node, dict) and object_node.get("type") == "Identifier":
            alias = require_aliases.get(_identifier_name(object_node))
            if alias and alias[1] == "default":
                property_name = _member_property_name(node)
                if property_name:
                    return alias[0], property_name
    return "", ""


def _collect_variable_function_scopes(node: Any) -> dict[str, str]:
    """Collect variable bindings that point at function-like expressions."""
    scopes: dict[str, str] = {}

    def _visit(current: Any) -> None:
        if not isinstance(current, dict):
            return

        if current.get("type") == "VariableDeclarator":
            local_name = _identifier_name(current.get("id"))
            scope = _derive_function_scope(current.get("init"))
            if local_name and scope:
                scopes.setdefault(local_name, scope)

        for key, value in current.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(node)
    return scopes


def _collect_variable_object_member_scopes(
    node: Any,
    name_scopes: dict[str, str],
) -> dict[str, dict[str, set[str]]]:
    """Collect variable bindings that point at object literals with callable members."""
    resolved: dict[str, dict[str, set[str]]] = {}

    def _visit(current: Any) -> None:
        if not isinstance(current, dict):
            return

        if current.get("type") == "VariableDeclarator":
            local_name = _identifier_name(current.get("id"))
            init = current.get("init")
            if local_name and isinstance(init, dict) and init.get("type") == "ObjectExpression":
                member_scopes = _resolve_object_export_scopes(init, name_scopes)
                if member_scopes:
                    resolved[local_name] = member_scopes

        for key, value in current.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(node)
    return resolved


def _collect_class_member_scopes(
    node: Any,
) -> dict[str, dict[str, set[str]]]:
    """Collect class declarations/expressions with callable member scopes."""
    resolved: dict[str, dict[str, set[str]]] = {}

    def _store(local_name: str, member_scopes: dict[str, set[str]]) -> None:
        if not local_name or not member_scopes:
            return
        existing = resolved.setdefault(local_name, {})
        for member_name, scopes in member_scopes.items():
            existing.setdefault(member_name, set()).update(scopes)

    def _visit(current: Any) -> None:
        if not isinstance(current, dict):
            return

        if current.get("type") == "ClassDeclaration":
            local_name = _identifier_name(current.get("id"))
            _store(local_name, _resolve_class_export_scopes(current))
        elif current.get("type") == "VariableDeclarator":
            local_name = _identifier_name(current.get("id"))
            init = current.get("init")
            _store(local_name, _resolve_class_export_scopes(init))

        for key, value in current.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                _visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _visit(item)

    _visit(node)
    return resolved


def _merge_member_scope_maps(
    *member_maps: dict[str, dict[str, set[str]]],
) -> dict[str, dict[str, set[str]]]:
    """Merge object/class member-scope maps without losing sets."""
    merged: dict[str, dict[str, set[str]]] = {}
    for member_map in member_maps:
        for local_name, members in member_map.items():
            if not isinstance(local_name, str) or not isinstance(members, dict):
                continue
            target_members = merged.setdefault(local_name, {})
            for member_name, scopes in members.items():
                if not isinstance(member_name, str):
                    continue
                target_members.setdefault(member_name, set()).update(
                    scope for scope in scopes or []
                    if isinstance(scope, str) and scope
                )
    return merged


def _resolve_object_export_scopes(
    node: dict[str, Any],
    name_scopes: dict[str, str],
) -> dict[str, set[str]]:
    """Resolve `module.exports = { ... }` object members into export scopes."""
    resolved: dict[str, set[str]] = defaultdict(set)
    for prop in node.get("properties", []):
        if not isinstance(prop, dict) or prop.get("type") != "Property":
            continue
        export_name = _identifier_name(prop.get("key")) or _literal_source(prop.get("key"))
        if not export_name:
            continue
        value = prop.get("value")
        if _is_function_like(value):
            scopes = [_derive_named_member_scope(export_name, value)]
        else:
            scopes = _resolve_export_target_scopes(value, name_scopes)
        resolved[export_name].update(scopes)
    return resolved


def _resolve_class_export_scopes(
    node: Any,
) -> dict[str, set[str]]:
    """Resolve callable class members back to named function scopes."""
    if not isinstance(node, dict) or node.get("type") not in {"ClassDeclaration", "ClassExpression"}:
        return {}

    resolved: dict[str, set[str]] = defaultdict(set)
    body = (node.get("body") or {}).get("body") or []
    for member in body:
        if not isinstance(member, dict) or member.get("type") != "MethodDefinition":
            continue
        if member.get("kind") == "constructor":
            continue
        export_name = _identifier_name(member.get("key")) or _literal_source(member.get("key"))
        if not export_name:
            continue
        resolved[export_name].add(
            _derive_named_member_scope(export_name, member.get("value"))
        )
    return resolved


def _resolve_export_member_scopes(
    target: Any,
    name_scopes: dict[str, str],
    member_scopes: dict[str, dict[str, set[str]]],
) -> dict[str, set[str]]:
    """Resolve practical exported object/class members back to callable scopes."""
    if not isinstance(target, dict):
        return {}

    if target.get("type") == "ObjectExpression":
        return _resolve_object_export_scopes(target, name_scopes)

    if target.get("type") in {"ClassDeclaration", "ClassExpression"}:
        return _resolve_class_export_scopes(target)

    if target.get("type") == "Identifier":
        local_name = _identifier_name(target)
        if local_name:
            return member_scopes.get(local_name, {})

    return {}


def _resolve_named_declaration_scopes(
    declaration: dict[str, Any],
    name_scopes: dict[str, str],
) -> dict[str, set[str]]:
    """Resolve export scopes from `export <declaration>` nodes."""
    resolved: dict[str, set[str]] = defaultdict(set)
    declaration_type = declaration.get("type", "")

    if declaration_type == "FunctionDeclaration":
        name = _identifier_name(declaration.get("id"))
        if name:
            resolved[name].add(name_scopes.get(name, _derive_function_scope(declaration) or "global"))
        return resolved

    if declaration_type == "VariableDeclaration":
        for declarator in declaration.get("declarations", []):
            if not isinstance(declarator, dict):
                continue
            local_name = _identifier_name(declarator.get("id"))
            if not local_name:
                continue
            scope = name_scopes.get(local_name)
            if not scope:
                scope = _derive_function_scope(declarator.get("init")) or "global"
            resolved[local_name].add(scope)
        return resolved

    return resolved


def _resolve_export_target_scopes(
    target: Any,
    name_scopes: dict[str, str],
) -> list[str]:
    """Resolve likely entry scopes for an exported target node."""
    if not isinstance(target, dict):
        return ["global"]

    target_type = target.get("type", "")
    if target_type == "Identifier":
        local_name = _identifier_name(target)
        return [name_scopes.get(local_name, "global")]

    derived_scope = _derive_function_scope(target)
    if derived_scope:
        return [derived_scope]

    if target_type == "ClassDeclaration":
        local_name = _identifier_name(target.get("id"))
        return [name_scopes.get(local_name, "global")]

    return ["global"]


def _derive_function_scope(node: Any) -> str:
    """Derive the IR function scope name for a function-like AST node."""
    if not isinstance(node, dict):
        return ""

    node_type = node.get("type", "")
    prefix = _FUNCTION_PREFIX_BY_TYPE.get(node_type)
    if not prefix:
        return ""

    local_name = _identifier_name(node.get("id"))
    if local_name:
        return f"function:{local_name}"

    start = ((node.get("loc") or {}).get("start") or {})
    line = int(start.get("line", 0) or 0)
    if line <= 0:
        return ""
    return f"function:{prefix}@{line}"


def _derive_named_member_scope(member_name: str, value: Any) -> str:
    """Derive the IR scope used for object/class member functions."""
    if isinstance(member_name, str) and member_name:
        return f"function:{member_name}"
    return _derive_function_scope(value)


def _is_function_like(node: Any) -> bool:
    """Check whether an AST node is a function-like expression."""
    return isinstance(node, dict) and node.get("type") in {
        "FunctionDeclaration",
        "FunctionExpression",
        "ArrowFunctionExpression",
    }


def _identifier_name(node: Any) -> str:
    """Extract a plain identifier name from an AST node."""
    if not isinstance(node, dict):
        return ""
    return str(node.get("name") or "").strip()


def _pattern_target_name(node: Any) -> str:
    """Extract a plain local target name from destructuring patterns."""
    if not isinstance(node, dict):
        return ""
    node_type = node.get("type", "")
    if node_type == "Identifier":
        return _identifier_name(node)
    if node_type == "AssignmentPattern":
        return _pattern_target_name(node.get("left"))
    return ""


def _literal_source(node: Any) -> str:
    """Extract a plain source string from an export-from/import-like source node."""
    if not isinstance(node, dict):
        return ""
    value = node.get("value")
    return value.strip() if isinstance(value, str) else ""


def _is_require_call(node: Any) -> bool:
    """Check whether a node is a simple `require("./mod")` call."""
    if not isinstance(node, dict) or node.get("type") != "CallExpression":
        return False
    callee = node.get("callee") or {}
    return callee.get("type") == "Identifier" and callee.get("name") == "require"


def _member_property_name(node: Any) -> str:
    """Extract the final property name from a non-computed member expression."""
    if not isinstance(node, dict) or node.get("type") != "MemberExpression" or node.get("computed"):
        return ""
    property_node = node.get("property")
    return _identifier_name(property_node) or _literal_source(property_node)


def _member_path(node: Any) -> str:
    """Extract a dotted member path from a non-computed member expression."""
    if not isinstance(node, dict):
        return ""
    node_type = node.get("type", "")
    if node_type == "Identifier":
        return _identifier_name(node)
    if node_type != "MemberExpression" or node.get("computed"):
        return ""
    object_path = _member_path(node.get("object"))
    property_name = _member_property_name(node)
    if object_path and property_name:
        return f"{object_path}.{property_name}"
    return property_name
