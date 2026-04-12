"""
Intermediate Representation (IR) builder.

Transforms AST into analysis-friendly structures.
"""

from __future__ import annotations

from typing import Any, Optional

from bundleInspector.storage.models import (
    IntermediateRepresentation,
    StringLiteral,
    FunctionCall,
    FunctionDef,
    ImportDecl,
    ExportDecl,
    Identifier,
)


class IRBuilder:
    """
    Build Intermediate Representation from AST.

    Extracts strings, function calls, imports, and other
    structures useful for security analysis.
    """

    MAX_UNIQUE_IDENTIFIERS = 10_000
    MAX_OCCURRENCES_PER_IDENTIFIER = 100

    def __init__(self):
        self._current_ir: Optional[IntermediateRepresentation] = None
        self._current_scope: str = "global"

    def build(
        self,
        ast: dict[str, Any],
        file_url: str,
        file_hash: str,
    ) -> IntermediateRepresentation:
        """
        Build IR from AST.

        Args:
            ast: Parsed AST dictionary
            file_url: URL of the source file
            file_hash: Hash of the source file

        Returns:
            IntermediateRepresentation
        """
        self._current_ir = IntermediateRepresentation(
            file_url=file_url,
            file_hash=file_hash,
            raw_ast=ast,
        )

        self._current_scope = "global"

        # Check if this is a partial/fallback parse
        if ast.get("partial") or ast.get("regex_fallback"):
            self._current_ir.partial = True
            self._current_ir.errors.append("Partial parse - some data may be missing")

        # Visit all nodes
        self._visit(ast)
        self._finalize_call_graph()

        return self._current_ir

    def _visit(self, node: Any) -> None:
        """Visit an AST node."""
        if not isinstance(node, dict):
            return

        node_type = node.get("type", "")

        # Dispatch to specific handlers
        # Handlers may return a set of child keys they already visited
        # to prevent the generic loop from double-visiting them.
        handled_keys: set[str] = set()
        handler = getattr(self, f"_visit_{node_type}", None)
        if handler:
            result = handler(node)
            if isinstance(result, set):
                handled_keys = result

        # Visit children (skip keys already handled by the specific visitor)
        for key, value in node.items():
            if key in ("loc", "range", "raw") or key in handled_keys:
                continue

            if isinstance(value, dict):
                self._visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._visit(item)

    def _visit_Literal(self, node: dict) -> None:
        """Handle literal values."""
        value = node.get("value")

        if isinstance(value, str):
            loc = node.get("loc", {})
            start = loc.get("start", {})

            self._current_ir.string_literals.append(StringLiteral(
                value=value,
                raw=node.get("raw"),
                line=start.get("line", 0),
                column=start.get("column", 0),
                context=self._get_parent_context(node),
            ))

    def _visit_TemplateLiteral(self, node: dict) -> None:
        """Handle template literals."""
        # Extract quasis (static parts)
        for quasi in node.get("quasis", []):
            value = quasi.get("value", {})
            cooked = value.get("cooked", "")

            if cooked:
                loc = quasi.get("loc", {})
                start = loc.get("start", {})

                self._current_ir.string_literals.append(StringLiteral(
                    value=cooked,
                    raw=value.get("raw"),
                    line=start.get("line", 0),
                    column=start.get("column", 0),
                    context="TemplateLiteral",
                ))

    def _visit_CallExpression(self, node: dict) -> None:
        """Handle function calls."""
        callee = node.get("callee", {})
        callee_name = self._get_callee_name(callee)

        if callee_name:
            loc = node.get("loc", {})
            start = loc.get("start", {})

            self._current_ir.function_calls.append(FunctionCall(
                name=callee_name.split(".")[-1],  # Last part
                full_name=callee_name,
                arguments=node.get("arguments", []),
                scope=self._current_scope,
                line=start.get("line", 0),
                column=start.get("column", 0),
            ))

    def _visit_ImportDeclaration(self, node: dict) -> set:
        """Handle import declarations."""
        source = node.get("source", {}).get("value", "")
        specifiers = []

        for spec in node.get("specifiers", []):
            spec_type = spec.get("type", "")
            if spec_type == "ImportDefaultSpecifier":
                local = spec.get("local", {}).get("name", "")
                if local:
                    specifiers.append(f"default as {local}")
            elif spec_type == "ImportNamespaceSpecifier":
                local = spec.get("local", {}).get("name", "")
                if local:
                    specifiers.append(f"* as {local}")
            elif spec_type == "ImportSpecifier":
                imported = spec.get("imported", {}).get("name", "")
                local = spec.get("local", {}).get("name", "")
                if imported:
                    if local and local != imported:
                        specifiers.append(f"{imported} as {local}")
                    else:
                        specifiers.append(imported)

        loc = node.get("loc", {})
        start = loc.get("start", {})

        self._current_ir.imports.append(ImportDecl(
            source=source,
            specifiers=specifiers,
            is_dynamic=False,
            line=start.get("line", 0),
        ))

        return {"source"}

    def _visit_ImportExpression(self, node: dict) -> None:
        """Handle dynamic imports."""
        source_node = node.get("source", {})
        source = ""

        if source_node.get("type") == "Literal":
            source = source_node.get("value", "")
        elif source_node.get("type") == "TemplateLiteral":
            # Get static parts
            quasis = source_node.get("quasis", [])
            if quasis:
                source = quasis[0].get("value", {}).get("cooked", "")

        if source:
            loc = node.get("loc", {})
            start = loc.get("start", {})

            self._current_ir.imports.append(ImportDecl(
                source=source,
                specifiers=[],
                is_dynamic=True,
                line=start.get("line", 0),
            ))

    def _visit_ExportDefaultDeclaration(self, node: dict) -> None:
        """Handle default exports."""
        loc = node.get("loc", {})
        start = loc.get("start", {})

        self._current_ir.exports.append(ExportDecl(
            name="default",
            is_default=True,
            line=start.get("line", 0),
        ))

    def _visit_ExportNamedDeclaration(self, node: dict) -> None:
        """Handle named exports."""
        loc = node.get("loc", {})
        start = loc.get("start", {})

        # Export from declaration
        declaration = node.get("declaration")
        if declaration:
            decl_type = declaration.get("type", "")
            if decl_type == "FunctionDeclaration":
                name = declaration.get("id", {}).get("name", "")
                if name:
                    self._current_ir.exports.append(ExportDecl(
                        name=name,
                        is_default=False,
                        line=start.get("line", 0),
                    ))
            elif decl_type == "VariableDeclaration":
                for decl in declaration.get("declarations", []):
                    name = decl.get("id", {}).get("name", "")
                    if name:
                        self._current_ir.exports.append(ExportDecl(
                            name=name,
                            is_default=False,
                            line=start.get("line", 0),
                        ))
            elif decl_type == "ClassDeclaration":
                name = declaration.get("id", {}).get("name", "")
                if name:
                    self._current_ir.exports.append(ExportDecl(
                        name=name,
                        is_default=False,
                        line=start.get("line", 0),
                    ))

        # Export specifiers
        for spec in node.get("specifiers", []):
            exported = spec.get("exported", {}).get("name", "")
            if exported:
                self._current_ir.exports.append(ExportDecl(
                    name=exported,
                    is_default=False,
                    line=start.get("line", 0),
                ))

    def _visit_Identifier(self, node: dict) -> None:
        """Handle identifiers."""
        name = node.get("name", "")
        if not name:
            return

        # Cap unique identifier names to prevent unbounded memory growth
        if (name not in self._current_ir.identifiers
                and len(self._current_ir.identifiers) >= self.MAX_UNIQUE_IDENTIFIERS):
            return

        loc = node.get("loc", {})
        start = loc.get("start", {})

        identifier = Identifier(
            name=name,
            scope=self._current_scope,
            line=start.get("line", 0),
            column=start.get("column", 0),
        )

        if name not in self._current_ir.identifiers:
            self._current_ir.identifiers[name] = []
        if len(self._current_ir.identifiers[name]) < self.MAX_OCCURRENCES_PER_IDENTIFIER:
            self._current_ir.identifiers[name].append(identifier)

    def _visit_FunctionDeclaration(self, node: dict) -> set:
        """Handle function declarations. Returns handled keys to prevent double-visit."""
        old_scope = self._current_scope
        func_name = self._derive_function_name(node, "function")
        self._record_function_def(node, func_name)
        self._current_scope = f"function:{func_name}"

        # Visit params in function scope (F-21 fix)
        for param in node.get("params", []):
            self._visit(param)

        # Visit body in function scope
        body = node.get("body")
        if body:
            self._visit(body)

        self._current_scope = old_scope
        return {"body", "params"}

    def _visit_FunctionExpression(self, node: dict) -> set:
        """Handle function expressions. Returns handled keys to prevent double-visit."""
        old_scope = self._current_scope
        func_name = self._derive_function_name(node, "function_expr")
        self._record_function_def(node, func_name)
        self._current_scope = f"function:{func_name}"

        for param in node.get("params", []):
            self._visit(param)

        body = node.get("body")
        if body:
            self._visit(body)

        self._current_scope = old_scope
        return {"body", "params"}

    def _visit_ArrowFunctionExpression(self, node: dict) -> set:
        """Handle arrow functions. Returns handled keys to prevent double-visit."""
        old_scope = self._current_scope
        func_name = self._derive_function_name(node, "arrow")
        self._record_function_def(node, func_name)
        self._current_scope = f"function:{func_name}"

        for param in node.get("params", []):
            self._visit(param)

        body = node.get("body")
        if body:
            self._visit(body)

        self._current_scope = old_scope
        return {"body", "params"}

    def _visit_Property(self, node: dict) -> set:
        """Handle object-literal methods and function-valued properties."""
        value = node.get("value")
        if not isinstance(value, dict):
            return set()
        if value.get("type") not in {"FunctionExpression", "ArrowFunctionExpression"}:
            return set()

        func_name = self._derive_member_name(node)
        if not func_name:
            return set()

        old_scope = self._current_scope
        self._record_function_def(value, func_name)
        self._current_scope = f"function:{func_name}"

        for param in value.get("params", []):
            self._visit(param)

        body = value.get("body")
        if body:
            self._visit(body)

        self._current_scope = old_scope
        return {"value", "params"}

    def _visit_MethodDefinition(self, node: dict) -> set:
        """Handle class methods with stable method-name scopes."""
        value = node.get("value")
        if not isinstance(value, dict):
            return set()

        func_name = self._derive_member_name(node)
        if not func_name:
            return set()

        old_scope = self._current_scope
        self._record_function_def(value, func_name)
        self._current_scope = f"function:{func_name}"

        for param in value.get("params", []):
            self._visit(param)

        body = value.get("body")
        if body:
            self._visit(body)

        self._current_scope = old_scope
        return {"value", "params"}

    def _get_callee_name(self, callee: dict) -> str:
        """Get full callee name from call expression."""
        callee_type = callee.get("type", "")

        if callee_type == "Identifier":
            return callee.get("name", "")

        elif callee_type == "MemberExpression":
            obj = self._get_callee_name(callee.get("object", {}))
            prop = callee.get("property", {})

            if callee.get("computed"):
                # obj[prop] - can't determine statically
                prop_name = "[computed]"
            else:
                prop_name = prop.get("name", "")

            if obj and prop_name:
                return f"{obj}.{prop_name}"
            return prop_name

        return ""

    def _derive_function_name(self, node: dict, prefix: str) -> str:
        """Derive a stable function name for graph building."""
        identifier = (node.get("id") or {}).get("name")
        if identifier:
            return identifier

        loc = node.get("loc", {})
        start = loc.get("start", {})
        line = start.get("line", 0)
        return f"{prefix}@{line}"

    def _derive_member_name(self, node: dict) -> str:
        """Derive a stable method/property name for object/class members."""
        key = node.get("key")
        if isinstance(key, dict):
            key_type = key.get("type", "")
            if key_type == "Identifier":
                name = key.get("name", "")
                if isinstance(name, str) and name:
                    return name
            if key_type == "Literal":
                value = key.get("value")
                if isinstance(value, str) and value:
                    return value

        value = node.get("value")
        if isinstance(value, dict):
            prefix = "method"
            if value.get("type") == "ArrowFunctionExpression":
                prefix = "arrow"
            return self._derive_function_name(value, prefix)
        return ""

    def _record_function_def(self, node: dict, func_name: str) -> None:
        """Record a function definition for later call-graph use."""
        loc = node.get("loc", {})
        start = loc.get("start", {})
        end = loc.get("end", {})
        self._current_ir.function_defs.append(FunctionDef(
            name=func_name,
            scope=f"function:{func_name}",
            line=start.get("line", 0),
            end_line=end.get("line", start.get("line", 0)),
        ))

    def _finalize_call_graph(self) -> None:
        """Build a simple intra-file call graph between known function scopes."""
        known_names = {func_def.name for func_def in self._current_ir.function_defs}
        call_graph: dict[str, set[str]] = {}

        for call in self._current_ir.function_calls:
            if call.scope == "global":
                continue
            callee = call.name
            if callee not in known_names:
                continue
            call_graph.setdefault(call.scope, set()).add(f"function:{callee}")

        self._current_ir.call_graph = {
            scope: sorted(targets)
            for scope, targets in call_graph.items()
        }

    def _get_parent_context(self, node: dict) -> str:
        """Get parent context for a node."""
        # This would require tracking parent nodes during traversal
        # For now, return empty
        return ""


def build_ir(
    ast: dict[str, Any],
    file_url: str,
    file_hash: str,
) -> IntermediateRepresentation:
    """
    Convenience function to build IR.

    Args:
        ast: Parsed AST dictionary
        file_url: URL of the source file
        file_hash: Hash of the source file

    Returns:
        IntermediateRepresentation
    """
    builder = IRBuilder()
    return builder.build(ast, file_url, file_hash)

