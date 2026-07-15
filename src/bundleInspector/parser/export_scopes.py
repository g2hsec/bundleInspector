"""
Helpers for mapping exported symbols back to likely function scopes.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from typing import Any

_FUNCTION_PREFIX_BY_TYPE = {
    "FunctionDeclaration": "function",
    "FunctionExpression": "function_expr",
    "ArrowFunctionExpression": "arrow",
}

_MAX_EXPORT_AST_NODES = 500_000
_EXPORT_SCOPE_ERROR_PREFIX = "export scope analysis incomplete"


class _AstTraversalLimit(RuntimeError):
    """Raised internally when a bounded export-scope AST walk exhausts its node budget."""


def _mark_ir_partial(ir: Any, reason: str) -> None:
    """Record one stable export-scope completeness error without leaking AST content."""
    error = f"{_EXPORT_SCOPE_ERROR_PREFIX} ({reason})"
    try:
        ir.partial = True
        errors = getattr(ir, "errors", None)
        if isinstance(errors, list) and error not in errors:
            errors.append(error)
    except (AttributeError, TypeError, ValueError):
        return


def _child_nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
    children: list[dict[str, Any]] = []
    for key, value in node.items():
        if key in {"loc", "range", "raw"}:
            continue
        if isinstance(value, dict):
            children.append(value)
        elif isinstance(value, list):
            children.extend(item for item in value if isinstance(item, dict))
    return children


def _iter_ast_nodes(
    root: Any,
    *,
    max_nodes: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield AST dictionaries in recursive-preorder using bounded explicit stack storage."""
    if not isinstance(root, dict):
        return
    stack: list[tuple[dict[str, Any], bool]] = [(root, False)]
    visited = 0
    active: set[int] = set()
    completed: set[int] = set()
    effective_max = _MAX_EXPORT_AST_NODES if max_nodes is None else max_nodes
    while stack:
        node, exiting = stack.pop()
        node_id = id(node)
        if exiting:
            active.discard(node_id)
            completed.add(node_id)
            continue
        if node_id in active:
            raise _AstTraversalLimit("ast cycle detected")
        if node_id in completed:
            continue
        active.add(node_id)
        visited += 1
        if visited > effective_max:
            raise _AstTraversalLimit(f"ast node cap={effective_max}")
        yield node
        stack.append((node, True))
        stack.extend((child, False) for child in reversed(_child_nodes(node)))


_COMMONJS_SENTINELS = frozenset({"module", "exports", "require"})
_COMMONJS_SCOPE_NODES = frozenset({
    "Program",
    "BlockStatement",
    "StaticBlock",
    "SwitchStatement",
    "CatchClause",
    "ForStatement",
    "ForInStatement",
    "ForOfStatement",
})


def _pattern_bound_names(node: Any, *, max_nodes: int) -> set[str]:
    """Collect identifiers bound by a declaration/parameter pattern."""
    names: set[str] = set()
    if not isinstance(node, dict):
        return names
    stack = [node]
    seen: set[int] = set()
    visited = 0
    while stack:
        current = stack.pop()
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        visited += 1
        if visited > max_nodes:
            raise _AstTraversalLimit(f"ast node cap={max_nodes}")
        node_type = current.get("type", "")
        if node_type == "Identifier":
            name = _identifier_name(current)
            if name:
                names.add(name)
            continue
        if node_type == "Property":
            value = current.get("value")
            if isinstance(value, dict):
                stack.append(value)
            continue
        for key in ("left", "argument", "elements", "properties"):
            value = current.get(key)
            if isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                stack.extend(item for item in value if isinstance(item, dict))
    return names


def _declaration_bound_names(node: Any, *, max_nodes: int) -> set[str]:
    if not isinstance(node, dict):
        return set()
    node_type = node.get("type", "")
    if node_type == "VariableDeclaration":
        names: set[str] = set()
        for declaration in node.get("declarations", []):
            if isinstance(declaration, dict):
                names.update(_pattern_bound_names(declaration.get("id"), max_nodes=max_nodes))
        return names
    if node_type in {"FunctionDeclaration", "ClassDeclaration"}:
        return _pattern_bound_names(node.get("id"), max_nodes=max_nodes)
    if node_type == "ImportDeclaration":
        names = set()
        for specifier in node.get("specifiers", []):
            if isinstance(specifier, dict):
                names.update(_pattern_bound_names(specifier.get("local"), max_nodes=max_nodes))
        return names
    return set()


def _hoisted_var_commonjs_bindings(node: Any, *, max_nodes: int) -> set[str]:
    """Collect function/program `var` bindings without entering nested functions."""
    if not isinstance(node, dict):
        return set()
    names: set[str] = set()
    stack = _child_nodes(node)
    seen: set[int] = set()
    visited = 0
    while stack:
        current = stack.pop()
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        visited += 1
        if visited > max_nodes:
            raise _AstTraversalLimit(f"ast node cap={max_nodes}")
        node_type = current.get("type", "")
        if node_type in _FUNCTION_PREFIX_BY_TYPE:
            continue
        if node_type == "VariableDeclaration" and current.get("kind") == "var":
            names.update(_declaration_bound_names(current, max_nodes=max_nodes))
        stack.extend(_child_nodes(current))
    return names & _COMMONJS_SENTINELS


def _commonjs_scope_bindings(
    node: dict[str, Any],
    *,
    max_nodes: int,
    trusted_parameters: frozenset[str] = frozenset(),
) -> set[str]:
    """Collect CommonJS sentinel names declared by one lexical scope."""
    node_type = node.get("type", "")
    names: set[str] = set()
    if node_type in _FUNCTION_PREFIX_BY_TYPE:
        names.update(_pattern_bound_names(node.get("id"), max_nodes=max_nodes))
        parameter_names: set[str] = set()
        for parameter in node.get("params", []):
            parameter_names.update(_pattern_bound_names(parameter, max_nodes=max_nodes))
        parameter_names.difference_update(trusted_parameters)
        names.update(parameter_names)
        names.update(_hoisted_var_commonjs_bindings(node.get("body"), max_nodes=max_nodes))
    elif node_type in {"Program", "BlockStatement", "StaticBlock"}:
        for statement in node.get("body", []):
            if not isinstance(statement, dict):
                continue
            if (
                node_type in {"BlockStatement", "StaticBlock"}
                and statement.get("type") == "VariableDeclaration"
                and statement.get("kind") == "var"
            ):
                continue
            names.update(_declaration_bound_names(statement, max_nodes=max_nodes))
        if node_type == "Program":
            names.update(_hoisted_var_commonjs_bindings(node, max_nodes=max_nodes))
    elif node_type == "SwitchStatement":
        for case in node.get("cases", []):
            if not isinstance(case, dict):
                continue
            for statement in case.get("consequent", []):
                if not isinstance(statement, dict):
                    continue
                if (
                    statement.get("type") == "VariableDeclaration"
                    and statement.get("kind") == "var"
                ):
                    continue
                names.update(_declaration_bound_names(statement, max_nodes=max_nodes))
    elif node_type == "CatchClause":
        names.update(_pattern_bound_names(node.get("param"), max_nodes=max_nodes))
    elif node_type in {"ForStatement", "ForInStatement", "ForOfStatement"}:
        declaration = node.get("init") if node_type == "ForStatement" else node.get("left")
        if isinstance(declaration, dict) and declaration.get("kind") != "var":
            names.update(_declaration_bound_names(declaration, max_nodes=max_nodes))
    return names & _COMMONJS_SENTINELS


def _trusted_commonjs_iife_parameters(
    node: dict[str, Any],
    visible_shadows: frozenset[str],
) -> frozenset[str]:
    """Return sentinel parameters proven to receive the same visible CommonJS value."""
    if node.get("type") != "CallExpression":
        return frozenset()
    callee = node.get("callee")
    if not isinstance(callee, dict) or callee.get("type") not in {
        "FunctionExpression",
        "ArrowFunctionExpression",
    }:
        return frozenset()

    parameter_evidence: dict[str, bool] = {}
    parameters = callee.get("params") or []
    arguments = node.get("arguments") or []
    for index, parameter in enumerate(parameters):
        if not isinstance(parameter, dict) or parameter.get("type") != "Identifier":
            continue
        parameter_name = _identifier_name(parameter)
        if parameter_name not in _COMMONJS_SENTINELS:
            continue
        argument = arguments[index] if index < len(arguments) else None
        parameter_evidence[parameter_name] = (
            isinstance(argument, dict)
            and argument.get("type") == "Identifier"
            and parameter_name not in visible_shadows
            and _identifier_name(argument) == parameter_name
        )
    return frozenset(
        parameter_name
        for parameter_name, is_trusted in parameter_evidence.items()
        if is_trusted
    )


def _iter_ast_nodes_with_commonjs_scope(
    root: Any,
    *,
    max_nodes: int,
) -> Iterator[tuple[dict[str, Any], str, tuple[int, ...], frozenset[str]]]:
    """Yield nodes with lexical identity and visible CommonJS-sentinel shadowing."""
    if not isinstance(root, dict):
        return
    stack: list[
        tuple[
            dict[str, Any],
            str,
            tuple[int, ...],
            frozenset[str],
            frozenset[str],
            bool,
        ]
    ] = [
        (root, "global", (), frozenset(), frozenset(), False)
    ]
    visited = 0
    active: set[int] = set()
    completed: set[int] = set()
    while stack:
        (
            node,
            scope_name,
            scope_path,
            inherited_shadows,
            trusted_parameters,
            exiting,
        ) = stack.pop()
        node_id = id(node)
        if exiting:
            active.discard(node_id)
            completed.add(node_id)
            continue
        if node_id in active:
            raise _AstTraversalLimit("ast cycle detected")
        if node_id in completed:
            continue
        active.add(node_id)
        visited += 1
        if visited > max_nodes:
            raise _AstTraversalLimit(f"ast node cap={max_nodes}")

        node_type = node.get("type", "")
        opens_scope = node_type in _COMMONJS_SCOPE_NODES or node_type in _FUNCTION_PREFIX_BY_TYPE
        child_scope_name = scope_name
        child_scope_path = scope_path
        child_shadows = inherited_shadows
        if opens_scope:
            child_scope_path = (*scope_path, node_id)
            local_bindings = _commonjs_scope_bindings(
                node,
                max_nodes=max_nodes,
                trusted_parameters=trusted_parameters,
            )
            child_shadows = frozenset((
                *inherited_shadows,
                *local_bindings,
            ))
            if node_type in _FUNCTION_PREFIX_BY_TYPE:
                child_scope_name = _derive_function_scope(node) or scope_name

        yield node, child_scope_name, child_scope_path, child_shadows
        stack.append((
            node,
            scope_name,
            scope_path,
            inherited_shadows,
            trusted_parameters,
            True,
        ))
        trusted_iife_parameters = _trusted_commonjs_iife_parameters(node, child_shadows)
        callee = node.get("callee") if trusted_iife_parameters else None
        stack.extend(
            (
                child,
                child_scope_name,
                child_scope_path,
                child_shadows,
                trusted_iife_parameters if child is callee else frozenset(),
                False,
            )
            for child in reversed(_child_nodes(node))
        )


def build_export_scope_map(ir: Any) -> dict[str, list[str]]:
    """Build a practical export symbol -> entry scope map from IR metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return {}

    try:
        name_scopes = _build_named_scope_map(ir, raw_ast)
        object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
        class_member_scopes = _collect_class_member_scopes(raw_ast)
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
        return {}
    except RecursionError:
        _mark_ir_partial(ir, "metadata recursion limit")
        return {}
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    export_scopes: dict[str, set[str]] = defaultdict(set)

    for node in raw_ast.get("body", []):
        if not isinstance(node, dict):
            continue

        node_type = node.get("type", "")
        if node.get("exportKind") == "type":
            continue
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

            # A re-export-from (`export { X } from './mod'`) names symbols in the OTHER module, so
            # resolving `local` against THIS file's scopes would wrongly bind the export to an
            # unrelated same-named local symbol. Only direct exports are handled here; re-exports are
            # resolved separately by build_re_export_bindings.
            if not node.get("source"):
                for specifier in node.get("specifiers", []):
                    if not isinstance(specifier, dict):
                        continue
                    if specifier.get("exportKind") == "type":
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

    try:
        name_scopes = _build_named_scope_map(ir, raw_ast)
        object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
        class_member_scopes = _collect_class_member_scopes(raw_ast)
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
        return []
    except RecursionError:
        _mark_ir_partial(ir, "metadata recursion limit")
        return []
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: set[str] = set()

    for node in raw_ast.get("body", []):
        if not isinstance(node, dict):
            continue
        if node.get("type") != "ExportDefaultDeclaration" or node.get("exportKind") == "type":
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

    try:
        name_scopes = _build_named_scope_map(ir, raw_ast)
        object_member_scopes = _collect_variable_object_member_scopes(raw_ast, name_scopes)
        class_member_scopes = _collect_class_member_scopes(raw_ast)
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
        return {}
    except RecursionError:
        _mark_ir_partial(ir, "metadata recursion limit")
        return {}
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: dict[str, set[str]] = defaultdict(set)

    for node in raw_ast.get("body", []):
        if (
            not isinstance(node, dict)
            or node.get("type") != "ExportNamedDeclaration"
            or node.get("exportKind") == "type"
        ):
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
            if specifier.get("exportKind") == "type":
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
    body = raw_ast.get("body", [])
    if not isinstance(body, list):
        return bindings
    for node_index, node in enumerate(body):
        if node_index >= _MAX_EXPORT_AST_NODES:
            _mark_ir_partial(ir, f"ast node cap={_MAX_EXPORT_AST_NODES}")
            break
        if not isinstance(node, dict):
            continue
        node_type = node.get("type")
        if node_type == "ExportNamedDeclaration":
            if node.get("exportKind") == "type":
                continue
            source = _literal_source(node.get("source"))
            if not source:
                continue

            for specifier in node.get("specifiers", []):
                if not isinstance(specifier, dict):
                    continue
                if specifier.get("exportKind") == "type":
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
            if node.get("exportKind") == "type":
                continue
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
    seen_bindings: set[tuple[str, str, str]] = set()

    def append_binding(binding: dict[str, object]) -> None:
        key = (
            str(binding.get("source") or ""),
            str(binding.get("imported") or ""),
            str(binding.get("local") or ""),
        )
        if key not in seen_bindings:
            seen_bindings.add(key)
            bindings.append(binding)

    try:
        require_aliases = _build_scoped_commonjs_require_alias_map(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        for node, _, scope_path, shadows in _iter_ast_nodes_with_commonjs_scope(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        ):
            if node.get("type") != "AssignmentExpression" or node.get("operator") != "=":
                continue
            target_path = _member_path(node.get("left"))
            if (
                (target_path.startswith("module.") and "module" in shadows)
                or (target_path.startswith("exports.") and "exports" in shadows)
            ):
                continue
            if target_path == "module.exports":
                right = node.get("right")
                if isinstance(right, dict) and right.get("type") == "ObjectExpression":
                    for prop in right.get("properties", []):
                        if not isinstance(prop, dict) or prop.get("type") != "Property":
                            continue
                        export_name = _export_property_name(prop)
                        forwarded = _extract_commonjs_reexport_target(
                            prop.get("value"),
                            require_aliases,
                            scope_path=scope_path,
                            allow_require="require" not in shadows,
                        )
                        if not export_name or not forwarded[0]:
                            continue
                        append_binding({
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
                    forwarded = _extract_commonjs_reexport_target(
                        right,
                        require_aliases,
                        scope_path=scope_path,
                        allow_require="require" not in shadows,
                    )
                    if forwarded[0]:
                        append_binding({
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
                forwarded = _extract_commonjs_reexport_target(
                    node.get("right"),
                    require_aliases,
                    scope_path=scope_path,
                    allow_require="require" not in shadows,
                )
                if export_name and forwarded[0]:
                    append_binding({
                        "source": forwarded[0],
                        "imported": forwarded[1],
                        "local": export_name,
                        "kind": "default" if forwarded[1] == "default" else "named",
                        "scope": "global",
                        "is_dynamic": False,
                        "is_reexport": True,
                        "is_commonjs_reexport": True,
                    })
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
    except RecursionError:
        _mark_ir_partial(ir, "expression recursion limit")
    return bindings


def build_commonjs_require_bindings(ir: Any) -> list[dict[str, object]]:
    """Build practical `require()` import bindings from raw AST metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return []

    bindings: list[dict[str, object]] = []
    seen_bindings: set[tuple[str, str, str, str]] = set()

    try:
        for node, scope, _, shadows in _iter_ast_nodes_with_commonjs_scope(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        ):
            node_type = node.get("type", "")
            if node_type == "VariableDeclarator":
                candidates = _extract_commonjs_require_binding_targets(
                    node.get("id"),
                    node.get("init"),
                    scope,
                    allow_require="require" not in shadows,
                )
            elif node_type == "AssignmentExpression" and node.get("operator") == "=":
                candidates = _extract_commonjs_require_binding_targets(
                    node.get("left"),
                    node.get("right"),
                    scope,
                    allow_require="require" not in shadows,
                )
            else:
                continue
            for binding in candidates:
                key = (
                    str(binding.get("source") or ""),
                    str(binding.get("imported") or ""),
                    str(binding.get("local") or ""),
                    str(binding.get("scope") or ""),
                )
                if key not in seen_bindings:
                    seen_bindings.add(key)
                    bindings.append(binding)
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
    except RecursionError:
        _mark_ir_partial(ir, "expression recursion limit")
    return bindings


def build_commonjs_export_metadata(ir: Any) -> tuple[list[str], dict[str, list[str]]]:
    """Build practical CommonJS export names and entry scopes from raw AST metadata."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return [], {}

    try:
        name_scopes = _build_named_scope_map(
            ir,
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        object_member_scopes = _collect_variable_object_member_scopes(
            raw_ast,
            name_scopes,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        class_member_scopes = _collect_class_member_scopes(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
        return [], {}
    except RecursionError:
        _mark_ir_partial(ir, "metadata recursion limit")
        return [], {}
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    export_names: set[str] = set()
    export_scopes: dict[str, set[str]] = defaultdict(set)

    try:
        for node, _, _, shadows in _iter_ast_nodes_with_commonjs_scope(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        ):
            if node.get("type") != "AssignmentExpression" or node.get("operator") != "=":
                continue
            target_path = _member_path(node.get("left"))
            if (
                (target_path.startswith("module.") and "module" in shadows)
                or (target_path.startswith("exports.") and "exports" in shadows)
            ):
                continue
            if target_path == "module.exports":
                right = node.get("right")
                if isinstance(right, dict) and right.get("type") == "ObjectExpression":
                    for export_name, scopes in _resolve_object_export_scopes(
                        right,
                        name_scopes,
                    ).items():
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
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
    except RecursionError:
        _mark_ir_partial(ir, "expression recursion limit")
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

    try:
        name_scopes = _build_named_scope_map(
            ir,
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        object_member_scopes = _collect_variable_object_member_scopes(
            raw_ast,
            name_scopes,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        class_member_scopes = _collect_class_member_scopes(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
        return []
    except RecursionError:
        _mark_ir_partial(ir, "metadata recursion limit")
        return []
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: set[str] = set()

    try:
        for node, _, _, shadows in _iter_ast_nodes_with_commonjs_scope(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        ):
            if node.get("type") != "AssignmentExpression" or node.get("operator") != "=":
                continue
            target_path = _member_path(node.get("left"))
            if (
                (target_path.startswith("module.") and "module" in shadows)
                or (target_path.startswith("exports.") and "exports" in shadows)
            ):
                continue
            if target_path != "module.exports":
                continue
            resolved_members = _resolve_export_member_scopes(
                node.get("right"),
                name_scopes,
                member_scopes,
            )
            members.update(export_name for export_name in resolved_members if export_name)
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
    except RecursionError:
        _mark_ir_partial(ir, "expression recursion limit")
    return sorted(members)


def build_commonjs_named_object_export_members(ir: Any) -> dict[str, list[str]]:
    """Build callable-member metadata for named CommonJS object exports."""
    raw_ast = getattr(ir, "raw_ast", None)
    if not isinstance(raw_ast, dict):
        return {}

    try:
        name_scopes = _build_named_scope_map(
            ir,
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        object_member_scopes = _collect_variable_object_member_scopes(
            raw_ast,
            name_scopes,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
        class_member_scopes = _collect_class_member_scopes(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        )
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
        return {}
    except RecursionError:
        _mark_ir_partial(ir, "metadata recursion limit")
        return {}
    member_scopes = _merge_member_scope_maps(object_member_scopes, class_member_scopes)
    members: dict[str, set[str]] = defaultdict(set)

    try:
        for node, _, _, shadows in _iter_ast_nodes_with_commonjs_scope(
            raw_ast,
            max_nodes=_MAX_EXPORT_AST_NODES,
        ):
            if node.get("type") != "AssignmentExpression" or node.get("operator") != "=":
                continue
            target_path = _member_path(node.get("left"))
            if (
                (target_path.startswith("module.") and "module" in shadows)
                or (target_path.startswith("exports.") and "exports" in shadows)
            ):
                continue
            right = node.get("right")
            if (
                target_path == "module.exports"
                and isinstance(right, dict)
                and right.get("type") == "ObjectExpression"
            ):
                for prop in right.get("properties", []):
                    if not isinstance(prop, dict) or prop.get("type") != "Property":
                        continue
                    export_name = _export_property_name(prop)
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
    except _AstTraversalLimit as exc:
        _mark_ir_partial(ir, str(exc))
    except RecursionError:
        _mark_ir_partial(ir, "expression recursion limit")
    return {
        export_name: sorted(member_names)
        for export_name, member_names in members.items()
        if member_names
    }


def _build_named_scope_map(
    ir: Any,
    raw_ast: dict[str, Any],
    *,
    max_nodes: int | None = None,
) -> dict[str, str]:
    """Build a practical local-name -> scope map for exported bindings."""
    name_scopes: dict[str, str] = {}

    for function_def in getattr(ir, "function_defs", []):
        name = (getattr(function_def, "name", "") or "").strip()
        scope = (getattr(function_def, "scope", "") or "").strip()
        if name and scope:
            name_scopes[name] = scope

    for local_name, scope in _collect_variable_function_scopes(
        raw_ast,
        max_nodes=max_nodes,
    ).items():
        name_scopes.setdefault(local_name, scope)

    return name_scopes


def _extract_commonjs_require_binding_targets(
    target: Any,
    value: Any,
    scope: str,
    *,
    allow_require: bool = True,
) -> list[dict[str, object]]:
    """Extract practical CommonJS bindings from `require()` assignment targets."""
    source, member_import = _extract_commonjs_require_source(value, allow_require=allow_require)
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
        imported = _export_property_name(prop)
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


def _extract_commonjs_require_source(
    node: Any,
    *,
    allow_require: bool = True,
) -> tuple[str, str]:
    """Extract a `require()` source and optional member import from an expression."""
    if not isinstance(node, dict):
        return "", ""

    if allow_require and _is_require_call(node):
        arguments = node.get("arguments") or []
        if not arguments:
            return "", ""
        return _literal_source(arguments[0]), ""

    if node.get("type") == "MemberExpression":
        source, _ = _extract_commonjs_require_source(
            node.get("object"),
            allow_require=allow_require,
        )
        if not source:
            return "", ""
        return source, _member_property_name(node)

    return "", ""


_CommonJSAliasMap = dict[tuple[tuple[int, ...], str], tuple[str, str]]


def _build_scoped_commonjs_require_alias_map(
    raw_ast: dict[str, Any],
    *,
    max_nodes: int,
) -> _CommonJSAliasMap:
    aliases: _CommonJSAliasMap = {}
    for node, scope_name, scope_path, shadows in _iter_ast_nodes_with_commonjs_scope(
        raw_ast,
        max_nodes=max_nodes,
    ):
        node_type = node.get("type", "")
        if node_type == "VariableDeclarator":
            target, value = node.get("id"), node.get("init")
        elif node_type == "AssignmentExpression" and node.get("operator") == "=":
            target, value = node.get("left"), node.get("right")
        else:
            continue
        for binding in _extract_commonjs_require_binding_targets(
            target,
            value,
            scope_name,
            allow_require="require" not in shadows,
        ):
            local = str(binding.get("local") or "").strip()
            source = str(binding.get("source") or "").strip()
            imported = str(binding.get("imported") or "default").strip() or "default"
            if local and source:
                aliases.setdefault((scope_path, local), (source, imported))
    return aliases


def _lookup_commonjs_alias(
    aliases: _CommonJSAliasMap,
    scope_path: tuple[int, ...],
    local: str,
) -> tuple[str, str] | None:
    for length in range(len(scope_path), 0, -1):
        alias = aliases.get((scope_path[:length], local))
        if alias is not None:
            return alias
    return None


def _extract_commonjs_reexport_target(
    node: Any,
    require_aliases: _CommonJSAliasMap | None = None,
    *,
    scope_path: tuple[int, ...] = (),
    allow_require: bool = True,
) -> tuple[str, str]:
    """Extract forwarded source/symbol info from CommonJS re-export expressions."""
    source, imported = _extract_commonjs_require_source(node, allow_require=allow_require)
    if source:
        return source, imported or "default"

    if not isinstance(node, dict):
        return "", ""

    require_aliases = require_aliases or {}

    if node.get("type") == "Identifier":
        alias = _lookup_commonjs_alias(require_aliases, scope_path, _identifier_name(node))
        if alias:
            return alias

    if node.get("type") == "MemberExpression":
        object_node = node.get("object")
        if isinstance(object_node, dict) and object_node.get("type") == "Identifier":
            alias = _lookup_commonjs_alias(
                require_aliases,
                scope_path,
                _identifier_name(object_node),
            )
            if alias and alias[1] == "default":
                property_name = _member_property_name(node)
                if property_name:
                    return alias[0], property_name
    return "", ""


def _collect_variable_function_scopes(
    node: Any,
    *,
    max_nodes: int | None = None,
) -> dict[str, str]:
    """Collect variable bindings that point at function-like expressions."""
    scopes: dict[str, str] = {}
    for current in _iter_ast_nodes(node, max_nodes=max_nodes):
        if current.get("type") == "VariableDeclarator":
            local_name = _identifier_name(current.get("id"))
            scope = _derive_function_scope(current.get("init"))
            if local_name and scope:
                scopes.setdefault(local_name, scope)
    return scopes


def _collect_variable_object_member_scopes(
    node: Any,
    name_scopes: dict[str, str],
    *,
    max_nodes: int | None = None,
) -> dict[str, dict[str, set[str]]]:
    """Collect variable bindings that point at object literals with callable members."""
    resolved: dict[str, dict[str, set[str]]] = {}
    for current in _iter_ast_nodes(node, max_nodes=max_nodes):
        if current.get("type") == "VariableDeclarator":
            local_name = _identifier_name(current.get("id"))
            init = current.get("init")
            if local_name and isinstance(init, dict) and init.get("type") == "ObjectExpression":
                member_scopes = _resolve_object_export_scopes(init, name_scopes)
                if member_scopes:
                    resolved[local_name] = member_scopes
    return resolved


def _collect_class_member_scopes(
    node: Any,
    *,
    max_nodes: int | None = None,
) -> dict[str, dict[str, set[str]]]:
    """Collect class declarations/expressions with callable member scopes."""
    resolved: dict[str, dict[str, set[str]]] = {}

    def _store(local_name: str, member_scopes: dict[str, set[str]]) -> None:
        if not local_name or not member_scopes:
            return
        existing = resolved.setdefault(local_name, {})
        for member_name, scopes in member_scopes.items():
            existing.setdefault(member_name, set()).update(scopes)

    for current in _iter_ast_nodes(node, max_nodes=max_nodes):
        if current.get("type") == "ClassDeclaration":
            local_name = _identifier_name(current.get("id"))
            _store(local_name, _resolve_class_export_scopes(current))
        elif current.get("type") == "VariableDeclarator":
            local_name = _identifier_name(current.get("id"))
            init = current.get("init")
            _store(local_name, _resolve_class_export_scopes(init))
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
        export_name = _export_property_name(prop)
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
        if not isinstance(member, dict):
            continue
        member_type = member.get("type")
        value = member.get("value")
        if member_type == "MethodDefinition":
            if member.get("kind") == "constructor":
                continue
        elif member_type == "PropertyDefinition":
            if not _is_function_like(value):
                continue
        else:
            continue
        export_name = _export_property_name(member)
        if not export_name:
            continue
        resolved[export_name].add(
            _derive_named_member_scope(export_name, value)
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


def _export_property_name(owner: Any) -> str:
    """Return a public, statically resolvable object/class property name."""
    if not isinstance(owner, dict):
        return ""
    key = owner.get("key")
    if not isinstance(key, dict) or key.get("type") == "PrivateIdentifier":
        return ""
    if owner.get("computed"):
        if key.get("type") != "Literal":
            return ""
        value = key.get("value")
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return str(value).strip()
        return ""
    return _identifier_name(key) or _literal_source(key)


def _is_require_call(node: Any) -> bool:
    """Check whether a node is a simple `require("./mod")` call."""
    if not isinstance(node, dict) or node.get("type") != "CallExpression":
        return False
    callee = node.get("callee") or {}
    return callee.get("type") == "Identifier" and callee.get("name") == "require"


def _member_property_name(node: Any) -> str:
    """Extract a statically resolvable member-expression property name."""
    if not isinstance(node, dict) or node.get("type") != "MemberExpression":
        return ""
    property_node = node.get("property")
    if node.get("computed"):
        if not isinstance(property_node, dict) or property_node.get("type") != "Literal":
            return ""
        value = property_node.get("value")
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return str(value).strip()
        return ""
    return _identifier_name(property_node) or _literal_source(property_node)


def _member_path(node: Any) -> str:
    """Extract a dotted path whose computed segments are static literals."""
    if not isinstance(node, dict):
        return ""
    node_type = node.get("type", "")
    if node_type == "Identifier":
        return _identifier_name(node)
    if node_type != "MemberExpression":
        return ""
    object_path = _member_path(node.get("object"))
    property_name = _member_property_name(node)
    if object_path and property_name:
        return f"{object_path}.{property_name}"
    return property_name
