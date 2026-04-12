"""
API Endpoint detector.

Extracts API paths, methods, and parameters from JS.
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional
from urllib.parse import urljoin, urlsplit

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

_BLOCKED_STRING = "__JSFINDER_BLOCKED__"
_NULLISH_STATIC = object()


class EndpointDetector(BaseRule):
    """
    Detect API endpoints in JavaScript.

    Looks for:
    - fetch(), axios, XMLHttpRequest calls
    - URL patterns like /api/*, /v1/*, etc.
    - GraphQL endpoints
    - WebSocket connections
    """

    id = "endpoint-detector"
    name = "API Endpoint Detector"
    description = "Detects API endpoints and HTTP calls"
    category = Category.ENDPOINT
    severity = Severity.INFO

    # HTTP client function names (exact match for short names)
    HTTP_FUNCTIONS_EXACT = {
        "fetch", "axios", "request", "ajax",
    }

    # HTTP method-named functions (only match as obj.method patterns)
    HTTP_METHOD_FUNCTIONS = {
        "get", "post", "put", "patch", "delete", "head", "options",
    }

    # URL patterns
    API_PATTERNS = [
        r"^/api/",
        r"^/v\d+/",
        r"^/graphql",
        r"^/rest/",
        r"^/rpc/",
        r"^/ws/",
        r"^/socket",
        r"/webhook",
    ]

    STATIC_ASSET_EXTENSIONS = {
        ".js", ".mjs", ".cjs", ".css", ".png", ".jpg", ".jpeg",
        ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".eot", ".map",
    }

    DOC_CONTEXT_HINTS = {
        "example", "sample", "demo", "readme", "docs", "documentation",
        "guide", "guides", "tutorial", "snippet", "reference",
    }

    API_HOST_LABELS = {"api", "graphql", "rpc", "rest", "webhook", "socket", "ws"}

    API_QUERY_HINTS = (
        "api_key=", "apikey=", "token=", "access_token=", "auth=", "graphql",
    )

    def _is_placeholder_value(self, value: Any) -> bool:
        """Return True for placeholder strings used only for partial URL assembly."""
        return isinstance(value, str) and value.startswith("${") and value.endswith("}")

    def _is_nullish_static_value(self, value: Any) -> bool:
        """Return True for statically known null/undefined-like sentinel values."""
        return value is _NULLISH_STATIC

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match endpoints in IR."""
        seen_values = set()
        function_returns = self._build_function_return_table(
            ir.raw_ast or {},
            {},
        )
        constants = self._build_constant_table(ir.raw_ast or {}, function_returns)
        bool_constants = self._build_boolean_table(ir.raw_ast or {}, constants)
        client_base_urls = self._build_client_base_urls(
            ir.raw_ast or {},
            constants,
            bool_constants,
            function_returns,
        )
        xhr_clients = self._build_xhr_client_names(ir.raw_ast or {})

        # Check function calls
        for call in ir.function_calls:
            for result in self._check_http_call(
                call,
                ir,
                context,
                constants,
                bool_constants,
                function_returns,
                client_base_urls,
                xhr_clients,
            ):
                if result.extracted_value not in seen_values:
                    seen_values.add(result.extracted_value)
                    yield result

        # Check WebSocket constructors
        for result in self._check_websocket_constructors(
            ir.raw_ast or {},
            context,
            constants,
            bool_constants,
            function_returns,
        ):
            if result.extracted_value not in seen_values:
                seen_values.add(result.extracted_value)
                yield result

        # Check string literals for URL patterns
        for literal in ir.string_literals:
            for result in self._check_url_pattern(literal, context):
                if result.extracted_value not in seen_values:
                    seen_values.add(result.extracted_value)
                    yield result

    def _check_http_call(
        self,
        call,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        client_base_urls: dict[str, str],
        xhr_clients: set[str],
    ) -> Iterator[RuleResult]:
        """Check if function call is an HTTP request."""
        # Check if it's an HTTP function using exact matching
        name_lower = call.name.lower()
        full_name_lower = call.full_name.lower()
        object_name = call.full_name.split(".", 1)[0]

        is_exact_http = name_lower in self.HTTP_FUNCTIONS_EXACT
        is_axios = "axios" in full_name_lower
        # HTTP method names only match when used as obj.method (e.g., axios.get, http.post)
        is_method_call = (
            name_lower in self.HTTP_METHOD_FUNCTIONS
            and "." in call.full_name  # Must be a method call, not standalone
        )
        is_xhr_open = name_lower == "open" and object_name in xhr_clients

        if not (is_exact_http or is_axios or is_method_call or is_xhr_open):
            return

        # Extract URL from arguments
        if not call.arguments:
            return

        resolved_arg_object = None
        if call.arguments:
            resolved_arg_object = self._resolve_object_expr(
                call.arguments[0],
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=True,
            )

        if is_xhr_open:
            if len(call.arguments) < 2:
                return
            method = self._resolve_http_method_expr(
                call.arguments[0],
                constants,
                bool_constants,
                function_returns,
            )
            url, confidence = self._extract_url_from_args(
                call.arguments[1:],
                constants,
                bool_constants,
                function_returns,
            )
        else:
            url, confidence = self._extract_url_from_args(
                call.arguments,
                constants,
                bool_constants,
                function_returns,
            )

        if not url:
            return

        base_url = client_base_urls.get(object_name)
        if base_url and url.startswith("/"):
            url = self._join_url(base_url, url)
            confidence = max(confidence, Confidence.MEDIUM, key=self._confidence_rank)

        # Determine HTTP method
        if not is_xhr_open:
            method = self._extract_method(
                call,
                is_exact_http and name_lower == "fetch",
                is_axios,
                constants,
                bool_constants,
                function_returns,
                resolved_arg_object=resolved_arg_object,
            )

        yield RuleResult(
            rule_id=self.id,
            category=self.category,
            severity=Severity.INFO,
            confidence=confidence,
            title=f"API Endpoint: {method} {url[:50]}",
            description=f"HTTP {method} call to {url}",
            extracted_value=url,
            value_type="api_endpoint",
            line=call.line,
            column=call.column,
            ast_node_type="CallExpression",
            tags=["http", method.lower()],
            metadata={
                "method": method,
                "function": call.full_name,
                "base_url": base_url,
            },
        )

    def _check_websocket_constructors(
        self,
        ast: dict[str, Any],
        context: AnalysisContext,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
    ) -> Iterator[RuleResult]:
        """Check practical `new WebSocket(url)` constructor calls."""
        if not ast:
            return

        for node in self._iter_nodes(ast):
            if node.get("type") != "NewExpression":
                continue
            if not self._is_websocket_constructor(node.get("callee", {})):
                continue

            arguments = node.get("arguments", [])
            if not arguments:
                continue

            url = self._resolve_string_expr(
                arguments[0],
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=True,
            )
            if not url or url == _BLOCKED_STRING or not self._looks_like_url(url):
                continue

            loc = node.get("loc", {})
            start = loc.get("start", {})
            parsed = urlsplit(url if url.startswith(("http://", "https://", "ws://", "wss://")) else f"https://host{url}")
            confidence = Confidence.HIGH if "${" not in url else Confidence.MEDIUM

            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.INFO,
                confidence=confidence,
                title=f"WebSocket Endpoint: {url[:50]}",
                description=f"WebSocket connection to {url}",
                extracted_value=url,
                value_type="websocket_url",
                line=start.get("line", 0),
                column=start.get("column", 0),
                ast_node_type="NewExpression",
                tags=["websocket"],
                metadata={
                    "protocol": parsed.scheme or "relative",
                    "function": "WebSocket",
                },
            )

    def _extract_url_from_args(
        self,
        arguments: list,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
    ) -> tuple[str, Confidence]:
        """Extract URL from function arguments."""
        if not arguments:
            return "", Confidence.LOW

        first_arg = arguments[0]

        resolved_object = self._resolve_object_expr(
            first_arg,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=True,
        )
        if resolved_object:
            return self._extract_url_from_resolved_object(resolved_object)

        if first_arg.get("type") == "ObjectExpression":
            return self._extract_url_from_object(
                first_arg,
                constants,
                bool_constants,
                function_returns,
            )

        # Literal string
        if first_arg.get("type") == "Literal":
            value = first_arg.get("value", "")
            if isinstance(value, str) and self._looks_like_url(value):
                return value, Confidence.HIGH

        # Template literal
        resolved = self._resolve_string_expr(
            first_arg,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=True,
        )
        if resolved and self._looks_like_url(resolved):
            confidence = (
                Confidence.HIGH
                if "${" not in resolved
                else Confidence.MEDIUM
            )
            return resolved, confidence

        if first_arg.get("type") == "Identifier":
            var_name = first_arg.get("name", "")
            object_url, object_confidence = self._extract_url_from_named_object(var_name, constants)
            if object_url:
                return object_url, object_confidence
            if any(kw in var_name.lower() for kw in ["url", "endpoint", "api", "path"]):
                return f"${{{var_name}}}", Confidence.LOW

        return "", Confidence.LOW

    def _extract_url_from_object(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
    ) -> tuple[str, Confidence]:
        """Extract URL from object config patterns like axios({ url, baseURL })."""
        url_value = self._extract_object_property(
            node,
            {"url", "uri", "endpoint", "path"},
            constants,
            bool_constants,
            function_returns,
        )
        base_url = self._extract_object_property(
            node,
            {"baseURL", "baseUrl", "base_uri", "baseUri"},
            constants,
            bool_constants,
            function_returns,
        )

        if url_value and base_url and url_value.startswith("/"):
            return self._join_url(base_url, url_value), Confidence.HIGH
        if url_value and self._looks_like_url(url_value):
            return url_value, Confidence.HIGH
        if base_url and self._looks_like_url(base_url):
            return base_url, Confidence.LOW
        return "", Confidence.LOW

    def _extract_object_property(
        self,
        node: dict[str, Any],
        keys: set[str],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
    ) -> str:
        """Extract a string-ish property from an object expression."""
        for prop in node.get("properties", []):
            key_node = prop.get("key", {})
            key_name = self._extract_property_name(key_node)
            if key_name not in keys:
                continue
            value = self._resolve_string_expr(
                prop.get("value", {}),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=True,
            )
            if value and value != _BLOCKED_STRING:
                return value
        return ""

    def _extract_url_from_named_object(
        self,
        name: str,
        constants: dict[str, str],
    ) -> tuple[str, Confidence]:
        """Extract URL data from an identifier bound to a static object literal."""
        url_value = self._extract_named_object_property(
            name,
            {"url", "uri", "endpoint", "path"},
            constants,
        )
        base_url = self._extract_named_object_property(
            name,
            {"baseURL", "baseUrl", "base_uri", "baseUri"},
            constants,
        )

        if url_value and base_url and url_value.startswith("/"):
            return self._join_url(base_url, url_value), Confidence.HIGH
        if url_value and self._looks_like_url(url_value):
            return url_value, Confidence.HIGH
        if base_url and self._looks_like_url(base_url):
            return base_url, Confidence.LOW
        return "", Confidence.LOW

    def _extract_named_object_property(
        self,
        name: str,
        keys: set[str],
        constants: dict[str, str],
    ) -> str:
        """Resolve a flattened object-literal property captured in the constant table."""
        for key in keys:
            value = constants.get(f"{name}.{key}")
            if value:
                return value
        return ""

    def _extract_url_from_resolved_object(
        self,
        values: dict[str, Any],
    ) -> tuple[str, Confidence]:
        """Extract URL data from a resolved object-like config mapping."""
        url_value = ""
        for key in ("url", "uri", "endpoint", "path"):
            value = values.get(key)
            if isinstance(value, str) and value:
                url_value = value
                break

        base_url = ""
        for key in ("baseURL", "baseUrl", "base_uri", "baseUri"):
            value = values.get(key)
            if isinstance(value, str) and value:
                base_url = value
                break

        if url_value and base_url and url_value.startswith("/"):
            return self._join_url(base_url, url_value), Confidence.HIGH
        if url_value and self._looks_like_url(url_value):
            return url_value, Confidence.HIGH
        if base_url and self._looks_like_url(base_url):
            return base_url, Confidence.LOW
        return "", Confidence.LOW

    def _resolve_object_expr(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Resolve a practical object-literal/config expression."""
        if not isinstance(node, dict):
            return {}

        node_type = node.get("type")
        if node_type == "ObjectExpression":
            return self._resolve_object_literal(
                node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )

        if node_type == "Identifier":
            name = node.get("name", "")
            if not name:
                return {}
            return self._resolve_named_object_values(name, constants, bindings)

        if node_type == "MemberExpression":
            path = self._extract_member_path(node) or self._resolve_member_lookup_path(
                node,
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            if not path:
                return {}
            return self._resolve_named_object_values(path, constants, bindings)

        if node_type == "CallExpression" and node.get("callee", {}).get("type") == "Identifier":
            return self._resolve_function_object_call(
                node.get("callee", {}).get("name", ""),
                node.get("arguments", []),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )

        if node_type == "CallExpression" and node.get("callee", {}).get("type") == "MemberExpression":
            member_name = self._extract_member_path(node.get("callee", {}))
            if member_name:
                return self._resolve_function_object_call(
                    member_name,
                    node.get("arguments", []),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )

        return {}

    def _resolve_object_literal(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Resolve top-level static properties from an object literal."""
        if node.get("type") != "ObjectExpression":
            return {}

        values: dict[str, Any] = {}
        for prop in node.get("properties", []):
            if not isinstance(prop, dict):
                continue
            if prop.get("type") == "SpreadElement":
                spread_values = self._resolve_object_expr(
                    prop.get("argument", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
                for key, value in spread_values.items():
                    if value is None or value == "" or self._is_nullish_static_value(value):
                        continue
                    values[key] = value
                continue
            key_name = self._extract_property_name(prop.get("key"))
            if not key_name:
                continue
            value = self._resolve_static_value(
                prop.get("value", {}),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )
            if value is None or value == "" or self._is_nullish_static_value(value):
                continue
            values[key_name] = value
        return values

    def _resolve_named_object_constants(
        self,
        name: str,
        constants: dict[str, str],
    ) -> dict[str, Any]:
        """Collect top-level flattened constant-table fields for a named object."""
        prefix = f"{name}."
        values: dict[str, Any] = {}
        for key, value in constants.items():
            if not key.startswith(prefix) or not value:
                continue
            remainder = key[len(prefix):]
            if "." in remainder:
                continue
            values[remainder] = value
        return values

    def _resolve_named_object_values(
        self,
        name: str,
        constants: dict[str, str],
        bindings: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Collect flattened object fields from helper-local bindings before constants."""
        values = self._resolve_named_object_constants(name, constants)
        prefix = f"{name}."
        for key, value in (bindings or {}).items():
            if not isinstance(key, str) or not key.startswith(prefix) or value in {None, ""}:
                continue
            remainder = key[len(prefix):]
            if "." in remainder:
                continue
            values[remainder] = value
        return values

    def _resolve_http_method_expr(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
    ) -> str:
        """Resolve a practical HTTP method expression to an uppercase verb."""
        value = self._resolve_string_expr(
            node,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=False,
        )
        if value:
            return value.upper()
        return "GET"

    def _resolve_string_expr(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve simple string expressions without executing code."""
        if not isinstance(node, dict):
            return ""

        node_type = node.get("type")
        if node_type == "Literal" and isinstance(node.get("value"), str):
            return node.get("value", "")

        if node_type == "NewExpression":
            url_value = self._resolve_url_constructor(
                node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )
            if url_value:
                return url_value
            request_value = self._resolve_request_constructor(
                node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )
            if request_value:
                return request_value

        if node_type == "TemplateLiteral":
            parts: list[str] = []
            quasis = node.get("quasis", [])
            expressions = node.get("expressions", [])
            for index, quasi in enumerate(quasis):
                parts.append(quasi.get("value", {}).get("cooked", ""))
                if index < len(expressions):
                    resolved = self._resolve_string_expr(
                        expressions[index],
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=allow_placeholders,
                        seen=seen,
                        bindings=bindings,
                    )
                    if resolved == _BLOCKED_STRING:
                        return _BLOCKED_STRING
                    if resolved:
                        parts.append(resolved)
                    elif allow_placeholders:
                        parts.append("${...}")
                    else:
                        return ""
            return "".join(parts)

        if node_type == "BinaryExpression" and node.get("operator") == "+":
            left = self._resolve_string_expr(
                node.get("left", {}),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )
            right = self._resolve_string_expr(
                node.get("right", {}),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )
            if left == _BLOCKED_STRING or right == _BLOCKED_STRING:
                return _BLOCKED_STRING
            if left and right:
                return f"{left}{right}"
            if allow_placeholders and (left or right):
                return f"{left or '${...}'}{right or '${...}'}"
            return ""

        if node_type == "LogicalExpression":
            operator = node.get("operator")
            left_value = self._resolve_static_value(
                node.get("left", {}),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
                )
            if operator == "&&":
                if left_value is None:
                    return _BLOCKED_STRING
                if not self._is_truthy_static_value(left_value):
                    return ""
                return self._resolve_string_expr(
                    node.get("right", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
            if operator == "??":
                if left_value is None:
                    return _BLOCKED_STRING
                if self._is_nullish_static_value(left_value):
                    return self._resolve_string_expr(
                        node.get("right", {}),
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=allow_placeholders,
                        seen=seen,
                        bindings=bindings,
                    )
                return left_value if isinstance(left_value, str) else self._resolve_string_expr(
                    node.get("left", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
            if operator == "||":
                if left_value is None:
                    return _BLOCKED_STRING
                if self._is_truthy_static_value(left_value):
                    return left_value if isinstance(left_value, str) else self._resolve_string_expr(
                        node.get("left", {}),
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=allow_placeholders,
                        seen=seen,
                        bindings=bindings,
                    )
                return self._resolve_string_expr(
                    node.get("right", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )

        if node_type == "ConditionalExpression":
            decision = self._resolve_bool_expr(
                node.get("test", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            if decision is True:
                return self._resolve_string_expr(
                    node.get("consequent", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
            if decision is False:
                return self._resolve_string_expr(
                    node.get("alternate", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
            return _BLOCKED_STRING

        if node_type == "Identifier":
            name = node.get("name", "")
            if not name:
                return ""
            if bindings and name in bindings:
                value = bindings[name]
                return value if isinstance(value, str) else ""
            if seen is None:
                seen = set()
            if name in seen:
                return ""
            if name in constants:
                seen.add(name)
                value = constants[name]
                return value if isinstance(value, str) else ""
            if allow_placeholders and any(
                keyword in name.lower()
                for keyword in ("url", "api", "path", "endpoint", "base")
            ):
                return f"${{{name}}}"
            return ""

        if node_type == "MemberExpression":
            url_property_value = self._resolve_url_object_property(
                node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            )
            if url_property_value:
                return url_property_value
            path = self._extract_member_path(node)
            if path and bindings and path in bindings:
                value = bindings[path]
                return value if isinstance(value, str) else ""
            if path and path in constants:
                value = constants[path]
                return value if isinstance(value, str) else ""
            lookup_path = self._resolve_member_lookup_path(
                node,
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            if lookup_path and bindings and lookup_path in bindings:
                value = bindings[lookup_path]
                return value if isinstance(value, str) else ""
            if lookup_path and lookup_path in constants:
                value = constants[lookup_path]
                return value if isinstance(value, str) else ""
            return ""

        if node_type == "CallExpression" and not node.get("arguments"):
            callee = node.get("callee", {})
            if callee.get("type") == "MemberExpression":
                member_call_value = self._resolve_url_member_call(
                    callee,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
                if member_call_value:
                    return member_call_value
                member_name = self._extract_member_path(callee)
                if member_name:
                    return self._resolve_function_call(
                        member_name,
                        [],
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=allow_placeholders,
                        seen=seen,
                        bindings=bindings,
                    )
            if callee.get("type") == "Identifier":
                return self._resolve_function_call(
                    callee.get("name", ""),
                    [],
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )

        if node_type == "CallExpression":
            callee = node.get("callee", {})
            if callee.get("type") == "MemberExpression":
                member_call_value = self._resolve_url_member_call(
                    callee,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )
                if member_call_value:
                    return member_call_value
                member_name = self._extract_member_path(callee)
                if member_name:
                    return self._resolve_function_call(
                        member_name,
                        node.get("arguments", []),
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=allow_placeholders,
                        seen=seen,
                        bindings=bindings,
                    )
            if callee.get("type") == "Identifier":
                return self._resolve_function_call(
                    callee.get("name", ""),
                    node.get("arguments", []),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=bindings,
                )

        return ""

    def _resolve_url_constructor(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve practical `new URL(path, base)` expressions into endpoint strings."""
        if node.get("type") != "NewExpression":
            return ""

        callee = node.get("callee", {})
        if callee.get("type") != "Identifier" or callee.get("name") != "URL":
            return ""

        arguments = node.get("arguments", [])
        if not arguments:
            return ""

        resource = self._resolve_string_expr(
            arguments[0],
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=bindings,
        )
        if not resource or resource == _BLOCKED_STRING:
            return ""

        if resource.startswith(("http://", "https://", "ws://", "wss://")):
            return resource

        if len(arguments) < 2:
            return resource if self._looks_like_url(resource) else ""

        base = self._resolve_string_expr(
            arguments[1],
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=bindings,
        )
        if not base or base == _BLOCKED_STRING:
            return ""
        if not base.startswith(("http://", "https://", "ws://", "wss://")):
            return ""

        return urljoin(base, resource)

    def _resolve_request_constructor(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve practical `new Request(url)` expressions into endpoint strings."""
        if node.get("type") != "NewExpression":
            return ""

        callee = node.get("callee", {})
        if callee.get("type") != "Identifier" or callee.get("name") != "Request":
            return ""

        arguments = node.get("arguments", [])
        if not arguments:
            return ""

        resource = self._resolve_string_expr(
            arguments[0],
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=bindings,
        )
        if not resource or resource == _BLOCKED_STRING:
            return ""
        return resource if self._looks_like_url(resource) else ""

    def _resolve_url_object_property(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve URL-object property reads such as `userUrl.href` or `userUrl.pathname`."""
        if node.get("type") != "MemberExpression":
            return ""

        property_name = self._extract_property_name(node.get("property"))
        if not property_name:
            return ""

        object_value = self._resolve_string_expr(
            node.get("object", {}),
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=bindings,
        )
        if not object_value or object_value == _BLOCKED_STRING:
            return ""

        parsed = urlsplit(object_value)
        property_name = property_name.lower()
        if property_name in {"href", "url"}:
            return object_value
        if property_name == "pathname":
            return parsed.path or ""
        if property_name == "origin" and parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        if property_name == "search":
            return f"?{parsed.query}" if parsed.query else ""
        return ""

    def _resolve_url_member_call(
        self,
        callee: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve simple zero-arg URL/Request-object method calls."""
        if callee.get("type") != "MemberExpression":
            return ""

        property_name = self._extract_property_name(callee.get("property")).lower()
        if property_name not in {"tostring", "tojson", "valueof", "clone"}:
            return ""

        object_value = self._resolve_string_expr(
            callee.get("object", {}),
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=bindings,
        )
        if object_value and object_value != _BLOCKED_STRING:
            return object_value
        return ""

    def _resolve_function_call(
        self,
        name: str,
        arguments: list[Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve a simple helper call by substituting static arguments into its return expression."""
        if not name:
            return ""

        function_spec = function_returns.get(name)
        if not function_spec:
            return ""

        if seen is None:
            seen = set()
        if name in seen:
            return ""

        params = list(function_spec.get("params", []))
        local_bindings = dict(bindings or {})

        for index, param_spec in enumerate(params):
            if not self._bind_helper_param_spec(
                param_spec,
                arguments[index] if index < len(arguments) else None,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=set(seen),
                bindings=local_bindings,
            ):
                return ""

        next_seen = set(seen)
        next_seen.add(name)
        body_node = function_spec.get("body", {})
        if isinstance(body_node, dict) and body_node.get("type") == "BlockStatement":
            return self._resolve_block_body(
                body_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=next_seen,
                bindings=local_bindings,
            )
        return self._resolve_string_expr(
            body_node,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=next_seen,
            bindings=local_bindings,
        )

    def _resolve_function_object_call(
        self,
        name: str,
        arguments: list[Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Resolve a helper call that returns a practical object config."""
        if not name:
            return {}

        function_spec = function_returns.get(name)
        if not function_spec:
            return {}

        if seen is None:
            seen = set()
        if name in seen:
            return {}

        params = list(function_spec.get("params", []))
        local_bindings = dict(bindings or {})

        for index, param_spec in enumerate(params):
            if not self._bind_helper_param_spec(
                param_spec,
                arguments[index] if index < len(arguments) else None,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=set(seen),
                bindings=local_bindings,
            ):
                return {}

        next_seen = set(seen)
        next_seen.add(name)
        body_node = function_spec.get("body", {})
        if isinstance(body_node, dict) and body_node.get("type") == "BlockStatement":
            return self._resolve_block_body_object(
                body_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=next_seen,
                bindings=local_bindings,
            )

        return self._resolve_object_expr(
            body_node,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=next_seen,
            bindings=local_bindings,
        )

    def _bind_helper_param_spec(
        self,
        param_spec: Any,
        argument_node: Any,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Bind a supported helper parameter spec into helper-local bindings."""
        local_bindings = bindings if bindings is not None else {}
        if not isinstance(param_spec, dict):
            return True

        pattern_node = param_spec.get("pattern")
        default_node = param_spec.get("default")
        effective_node = argument_node if isinstance(argument_node, dict) else default_node

        if isinstance(pattern_node, dict) and pattern_node.get("type") in {"ObjectPattern", "ArrayPattern"}:
            if not isinstance(effective_node, dict):
                return False
            return self._bind_pattern_alias_value(
                pattern_node,
                effective_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        param_name = str(param_spec.get("name") or "").strip()
        if not param_name:
            return True
        if isinstance(argument_node, dict):
            arg_value = self._resolve_static_value(
                argument_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if arg_value is not None and arg_value != "":
                local_bindings[param_name] = arg_value
                return True
        elif isinstance(default_node, dict):
            default_value = self._resolve_static_value(
                default_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if default_value is not None and default_value != "":
                local_bindings[param_name] = default_value
                return True
        if allow_placeholders:
            local_bindings[param_name] = f"${{{param_name}}}"
            return True
        return False

    def _resolve_block_body(
        self,
        body_node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve a conservative subset of block-bodied helper functions."""
        local_bindings = dict(bindings or {})
        result, did_return = self._process_statements(
            body_node.get("body", []),
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=local_bindings,
        )
        if did_return and result:
            return result
        return _BLOCKED_STRING

    def _resolve_block_body_object(
        self,
        body_node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Resolve a conservative subset of block-bodied object-return helpers."""
        local_bindings = dict(bindings or {})
        result, did_return = self._process_statements_object(
            body_node.get("body", []),
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=local_bindings,
        )
        if did_return and result:
            return result
        return {}

    def _process_statements(
        self,
        statements: list[Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        """Evaluate a small statement subset until a return is reached."""
        local_bindings = bindings if bindings is not None else {}

        for statement in statements:
            if not isinstance(statement, dict):
                continue
            result, did_return = self._process_statement(
                statement,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if did_return:
                return result, True

        return "", False

    def _process_statements_object(
        self,
        statements: list[Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> tuple[dict[str, Any], bool]:
        """Evaluate a small statement subset for object-return helpers."""
        local_bindings = bindings if bindings is not None else {}

        for statement in statements:
            if not isinstance(statement, dict):
                continue
            result, did_return = self._process_statement_object(
                statement,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if did_return:
                return result, True

        return {}, False

    def _process_statement(
        self,
        statement: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        """Evaluate one supported statement and optionally produce a return value."""
        statement_type = statement.get("type")
        local_bindings = bindings if bindings is not None else {}

        if statement_type == "ReturnStatement":
            argument = statement.get("argument")
            if not isinstance(argument, dict):
                return "", True
            return (
                self._resolve_string_expr(
                    argument,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                ),
                True,
            )

        if statement_type == "VariableDeclaration":
            for declarator in statement.get("declarations", []):
                self._bind_local_declarator(
                    declarator,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
            return "", False

        if statement_type == "ExpressionStatement":
            expression = statement.get("expression", {})
            if expression.get("type") == "AssignmentExpression":
                self._apply_local_assignment(
                    expression,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
            return "", False

        if statement_type == "IfStatement":
            decision = self._resolve_bool_expr(
                statement.get("test", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            if decision is None:
                if self._statement_contains_return(statement.get("consequent")) or self._statement_contains_return(statement.get("alternate")):
                    return "", True
                return "", False
            branch = statement.get("consequent" if decision else "alternate")
            if not isinstance(branch, dict):
                return "", False
            branch_statements = (
                branch.get("body", [])
                if branch.get("type") == "BlockStatement"
                else [branch]
            )
            return self._process_statements(
                branch_statements,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        if statement_type == "SwitchStatement":
            discriminant = self._resolve_scalar_expr(
                statement.get("discriminant", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            cases = statement.get("cases", [])
            if discriminant is None:
                if any(self._switch_case_contains_return(case) for case in cases):
                    return "", True
                return "", False

            matched_case = None
            default_case = None
            for case in cases:
                if not isinstance(case, dict):
                    continue
                test = case.get("test")
                if not isinstance(test, dict):
                    default_case = case
                    continue
                test_value = self._resolve_scalar_expr(
                    test,
                    constants,
                    bool_constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
                if test_value is not None and test_value == discriminant:
                    matched_case = case
                    break

            target_case = matched_case or default_case
            if not isinstance(target_case, dict):
                return "", False
            return self._process_switch_case(
                target_case,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        if statement_type == "BlockStatement":
            return self._process_statements(
                statement.get("body", []),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        return "", False

    def _process_statement_object(
        self,
        statement: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> tuple[dict[str, Any], bool]:
        """Evaluate one supported statement for object-return helpers."""
        statement_type = statement.get("type")
        local_bindings = bindings if bindings is not None else {}

        if statement_type == "ReturnStatement":
            argument = statement.get("argument")
            if not isinstance(argument, dict):
                return {}, True
            return (
                self._resolve_object_expr(
                    argument,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                ),
                True,
            )

        if statement_type == "VariableDeclaration":
            for declarator in statement.get("declarations", []):
                self._bind_local_declarator(
                    declarator,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
            return {}, False

        if statement_type == "ExpressionStatement":
            expression = statement.get("expression", {})
            if expression.get("type") == "AssignmentExpression":
                self._apply_local_assignment(
                    expression,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
            return {}, False

        if statement_type == "IfStatement":
            decision = self._resolve_bool_expr(
                statement.get("test", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            if decision is None:
                if self._statement_contains_return(statement.get("consequent")) or self._statement_contains_return(statement.get("alternate")):
                    return {}, True
                return {}, False
            branch = statement.get("consequent" if decision else "alternate")
            if not isinstance(branch, dict):
                return {}, False
            branch_statements = (
                branch.get("body", [])
                if branch.get("type") == "BlockStatement"
                else [branch]
            )
            return self._process_statements_object(
                branch_statements,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        if statement_type == "SwitchStatement":
            discriminant = self._resolve_scalar_expr(
                statement.get("discriminant", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            cases = statement.get("cases", [])
            if discriminant is None:
                if any(self._switch_case_contains_return(case) for case in cases):
                    return {}, True
                return {}, False

            matched_case = None
            default_case = None
            for case in cases:
                if not isinstance(case, dict):
                    continue
                test = case.get("test")
                if not isinstance(test, dict):
                    default_case = case
                    continue
                test_value = self._resolve_scalar_expr(
                    test,
                    constants,
                    bool_constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
                if test_value is not None and test_value == discriminant:
                    matched_case = case
                    break

            target_case = matched_case or default_case
            if not isinstance(target_case, dict):
                return {}, False
            return self._process_switch_case_object(
                target_case,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        if statement_type == "BlockStatement":
            return self._process_statements_object(
                statement.get("body", []),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        return {}, False

    def _process_switch_case(
        self,
        case: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        """Process a matched switch case until break or return."""
        local_bindings = bindings if bindings is not None else {}

        for statement in case.get("consequent", []):
            if not isinstance(statement, dict):
                continue
            if statement.get("type") == "BreakStatement":
                return "", False
            result, did_return = self._process_statement(
                statement,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if did_return:
                return result, True

        return "", False

    def _process_switch_case_object(
        self,
        case: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> tuple[dict[str, Any], bool]:
        """Process a matched switch case for object-return helpers."""
        local_bindings = bindings if bindings is not None else {}

        for statement in case.get("consequent", []):
            if not isinstance(statement, dict):
                continue
            if statement.get("type") == "BreakStatement":
                return {}, False
            result, did_return = self._process_statement_object(
                statement,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if did_return:
                return result, True

        return {}, False

    def _statement_contains_return(self, statement: Any) -> bool:
        """Return True when a statement subtree contains a return statement."""
        if not isinstance(statement, dict):
            return False
        if statement.get("type") == "ReturnStatement":
            return True
        if statement.get("type") == "BlockStatement":
            return any(self._statement_contains_return(item) for item in statement.get("body", []))
        if statement.get("type") == "IfStatement":
            return (
                self._statement_contains_return(statement.get("consequent"))
                or self._statement_contains_return(statement.get("alternate"))
            )
        if statement.get("type") == "SwitchStatement":
            return any(self._switch_case_contains_return(case) for case in statement.get("cases", []))
        return False

    def _switch_case_contains_return(self, case: Any) -> bool:
        """Return True when a switch case subtree contains a return statement."""
        if not isinstance(case, dict):
            return False
        return any(self._statement_contains_return(item) for item in case.get("consequent", []))

    def _bind_local_declarator(
        self,
        declarator: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> None:
        """Bind a supported local variable declaration into the helper scope."""
        local_bindings = bindings if bindings is not None else {}
        identifier = declarator.get("id", {})
        init = declarator.get("init", {})
        if identifier.get("type") in {"ObjectPattern", "ArrayPattern"}:
            self._bind_pattern_alias_value(
                identifier,
                init,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            return
        if identifier.get("type") != "Identifier":
            return
        name = identifier.get("name", "")
        if not name or not isinstance(init, dict):
            return

        if init.get("type") == "ObjectExpression":
            self._bind_local_object(
                name,
                init,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            return
        if init.get("type") == "ArrayExpression":
            self._bind_local_array(
                name,
                init,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            return
        if self._clone_local_object_binding(
            name,
            init,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        ):
            return

        value = self._resolve_static_value(
            init,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=local_bindings,
        )
        if value is not None and value != "":
            local_bindings[name] = value

    def _apply_local_assignment(
        self,
        assignment: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> None:
        """Apply a simple local assignment to the helper scope."""
        local_bindings = bindings if bindings is not None else {}
        left = assignment.get("left", {})
        if left.get("type") not in {"Identifier", "MemberExpression"}:
            return
        target = (
            left.get("name", "")
            if left.get("type") == "Identifier"
            else self._extract_member_path(left)
        )
        if not target:
            return
        if self._clone_local_object_binding(
            target,
            assignment.get("right", {}),
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        ):
            return
        value = self._resolve_static_value(
            assignment.get("right", {}),
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=local_bindings,
        )
        if value is not None and value != "":
            local_bindings[target] = value

    def _bind_object_pattern_aliases(
        self,
        pattern: dict[str, Any],
        init: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Bind object-destructuring aliases into the current scope."""
        local_bindings = bindings if bindings is not None else {}
        if pattern.get("type") != "ObjectPattern" or not isinstance(init, dict):
            return False

        bound_any = False
        if init.get("type") == "ObjectExpression":
            flattened_init_bindings: dict[str, Any] = {}
            self._bind_local_object(
                "__inline__",
                init,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=flattened_init_bindings,
            )
            for prop in pattern.get("properties", []):
                if not isinstance(prop, dict) or prop.get("type") != "Property":
                    continue
                key_name = self._extract_property_name(prop.get("key"))
                if not key_name:
                    continue
                value_node = self._find_object_property_value(init, key_name)
                if self._bind_pattern_alias_value(
                    prop.get("value"),
                    value_node,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                ):
                    bound_any = True
                    continue
                if self._bind_pattern_alias_path(
                    prop.get("value"),
                    f"__inline__.{key_name}",
                    constants,
                    flattened_init_bindings,
                    bool_constants=bool_constants,
                    function_returns=function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                ):
                    bound_any = True
            return bound_any

        source_path = self._extract_member_path(init) or self._resolve_member_lookup_path(
            init,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        if not source_path:
            return False

        for prop in pattern.get("properties", []):
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                continue
            key_name = self._extract_property_name(prop.get("key"))
            if not key_name:
                continue
            property_path = f"{source_path}.{key_name}"
            if self._bind_pattern_alias_path(
                prop.get("value"),
                property_path,
                constants,
                local_bindings,
                bool_constants=bool_constants,
                function_returns=function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
            ):
                bound_any = True

        return bound_any

    def _bind_array_pattern_aliases(
        self,
        pattern: dict[str, Any],
        init: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Bind array-destructuring aliases into the current scope."""
        local_bindings = bindings if bindings is not None else {}
        if pattern.get("type") != "ArrayPattern" or not isinstance(init, dict):
            return False

        bound_any = False
        if init.get("type") == "ArrayExpression":
            for index, element_pattern in enumerate(pattern.get("elements", [])):
                if not isinstance(element_pattern, dict):
                    continue
                if self._bind_pattern_alias_value(
                    element_pattern,
                    init.get("elements", [])[index]
                    if index < len(init.get("elements", []))
                    else None,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                ):
                    bound_any = True
            return bound_any

        source_path = self._extract_member_path(init) or self._resolve_member_lookup_path(
            init,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        if not source_path:
            return False

        for index, element_pattern in enumerate(pattern.get("elements", [])):
            if not isinstance(element_pattern, dict):
                continue
            property_path = f"{source_path}.{index}"
            if self._bind_pattern_alias_path(
                element_pattern,
                property_path,
                constants,
                local_bindings,
                bool_constants=bool_constants,
                function_returns=function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
            ):
                bound_any = True
        return bound_any

    def _normalize_pattern_node(self, node: Any) -> Optional[dict[str, Any]]:
        """Unwrap destructuring-assignment nodes to the effective binding pattern."""
        if not isinstance(node, dict):
            return None
        if node.get("type") == "AssignmentPattern":
            left = node.get("left")
            return left if isinstance(left, dict) else None
        return node

    def _extract_pattern_default_node(self, node: Any) -> Optional[dict[str, Any]]:
        """Extract a destructuring default value when one is present."""
        if not isinstance(node, dict):
            return None
        if node.get("type") != "AssignmentPattern":
            return None
        right = node.get("right")
        return right if isinstance(right, dict) else None

    def _bind_pattern_alias_value(
        self,
        pattern_node: Any,
        value_node: Any,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Bind an identifier or nested object-pattern from a concrete AST value node."""
        local_bindings = bindings if bindings is not None else {}
        default_node = self._extract_pattern_default_node(pattern_node)
        pattern = self._normalize_pattern_node(pattern_node)
        if not isinstance(pattern, dict):
            return False
        effective_value_node = (
            value_node if isinstance(value_node, dict)
            else default_node if isinstance(default_node, dict)
            else None
        )
        if not isinstance(effective_value_node, dict):
            return False

        if pattern.get("type") == "ObjectPattern":
            return self._bind_object_pattern_aliases(
                pattern,
                effective_value_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
        if pattern.get("type") == "ArrayPattern":
            return self._bind_array_pattern_aliases(
                pattern,
                effective_value_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )

        target_name = self._extract_pattern_target_name(pattern)
        if not target_name:
            return False

        if effective_value_node.get("type") == "ObjectExpression":
            self._bind_local_object(
                target_name,
                effective_value_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            return True
        if effective_value_node.get("type") == "ArrayExpression":
            self._bind_local_array(
                target_name,
                effective_value_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            return True
        if self._clone_local_object_binding(
            target_name,
            effective_value_node,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        ):
            return True
        value = self._resolve_static_value(
            effective_value_node,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=local_bindings,
        )
        if value is None or value == "":
            return False
        local_bindings[target_name] = value
        return True

    def _bind_pattern_alias_path(
        self,
        pattern_node: Any,
        source_path: str,
        constants: dict[str, str],
        bindings: dict[str, Any],
        bool_constants: Optional[dict[str, bool]] = None,
        function_returns: Optional[dict[str, dict[str, Any]]] = None,
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
    ) -> bool:
        """Bind an identifier or nested object-pattern from a flattened dotted source path."""
        default_node = self._extract_pattern_default_node(pattern_node)
        pattern = self._normalize_pattern_node(pattern_node)
        if not isinstance(pattern, dict) or not source_path:
            return False

        if pattern.get("type") == "ObjectPattern":
            bound_any = False
            for prop in pattern.get("properties", []):
                if not isinstance(prop, dict) or prop.get("type") != "Property":
                    continue
                key_name = self._extract_property_name(prop.get("key"))
                if not key_name:
                    continue
                property_path = f"{source_path}.{key_name}"
                if self._bind_pattern_alias_path(
                    prop.get("value"),
                    property_path,
                    constants,
                    bindings,
                    bool_constants=bool_constants,
                    function_returns=function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                ):
                    bound_any = True
            return bound_any
        if pattern.get("type") == "ArrayPattern":
            bound_any = False
            for index, element_pattern in enumerate(pattern.get("elements", [])):
                if not isinstance(element_pattern, dict):
                    continue
                property_path = f"{source_path}.{index}"
                if self._bind_pattern_alias_path(
                    element_pattern,
                    property_path,
                    constants,
                    bindings,
                    bool_constants=bool_constants,
                    function_returns=function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                ):
                    bound_any = True
            return bound_any

        target_name = self._extract_pattern_target_name(pattern)
        if not target_name:
            return False
        bound_any = self._clone_flattened_binding_prefix(
            target_name,
            source_path,
            constants,
            bindings,
            bool_constants=bool_constants,
        )
        if source_path in bindings:
            value = bindings[source_path]
        elif bool_constants and source_path in bool_constants:
            value = bool_constants[source_path]
        else:
            value = constants.get(source_path)
        if value is None or value == "":
            if not isinstance(default_node, dict):
                return bound_any
            if self._bind_pattern_alias_value(
                pattern,
                default_node,
                constants,
                bool_constants or {},
                function_returns or {},
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=bindings,
            ):
                return True
            return bound_any
        bindings[target_name] = value
        return True

    def _clone_local_object_binding(
        self,
        target: str,
        value_node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Clone a flattened object binding into a new helper-local alias when possible."""
        if not target or not isinstance(value_node, dict):
            return False

        source_path = self._extract_member_path(value_node) or self._resolve_member_lookup_path(
            value_node,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
        if not source_path:
            return False

        local_bindings = bindings if bindings is not None else {}
        cloned = False
        prefix = f"{source_path}."
        for key, value in {**constants, **local_bindings}.items():
            if not isinstance(key, str) or not key.startswith(prefix) or value in {None, ""}:
                continue
            suffix = key[len(source_path):]
            local_bindings[f"{target}{suffix}"] = value
            cloned = True
        return cloned

    def _clone_flattened_binding_prefix(
        self,
        target: str,
        source_path: str,
        constants: dict[str, str],
        bindings: dict[str, Any],
        bool_constants: Optional[dict[str, bool]] = None,
    ) -> bool:
        """Clone flattened dotted bindings from one prefix to another."""
        if not target or not source_path:
            return False
        merged: dict[str, Any] = dict(constants)
        if bool_constants:
            merged.update(bool_constants)
        merged.update(bindings)
        prefix = f"{source_path}."
        cloned = False
        for key, value in merged.items():
            if not isinstance(key, str) or not key.startswith(prefix) or value in {None, ""}:
                continue
            suffix = key[len(source_path):]
            bindings[f"{target}{suffix}"] = value
            cloned = True
        return cloned

    def _find_object_property_value(
        self,
        node: dict[str, Any],
        key_name: str,
    ) -> Optional[dict[str, Any]]:
        """Find a direct object-literal property value by key name."""
        if node.get("type") != "ObjectExpression":
            return None
        for prop in reversed(node.get("properties", [])):
            if not isinstance(prop, dict):
                continue
            if prop.get("type") == "SpreadElement":
                argument = prop.get("argument", {})
                if isinstance(argument, dict):
                    spread_value = self._find_object_property_value(argument, key_name)
                    if isinstance(spread_value, dict):
                        return spread_value
                continue
            if self._extract_property_name(prop.get("key")) != key_name:
                continue
            value = prop.get("value")
            return value if isinstance(value, dict) else None
        return None

    def _extract_pattern_target_name(self, node: Any) -> str:
        """Extract a simple local target name from a destructuring pattern node."""
        if not isinstance(node, dict):
            return ""
        node_type = node.get("type")
        if node_type == "Identifier":
            return str(node.get("name") or "").strip()
        if node_type == "AssignmentPattern":
            return self._extract_pattern_target_name(node.get("left"))
        return ""

    def _bind_local_object(
        self,
        prefix: str,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> None:
        """Flatten a local object literal into dotted helper-scope bindings."""
        local_bindings = bindings if bindings is not None else {}
        if node.get("type") != "ObjectExpression":
            return

        for prop in node.get("properties", []):
            if not isinstance(prop, dict):
                continue
            if prop.get("type") == "SpreadElement":
                argument = prop.get("argument", {})
                if isinstance(argument, dict) and argument.get("type") == "ObjectExpression":
                    self._bind_local_object(
                        prefix,
                        argument,
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=allow_placeholders,
                        seen=seen,
                        bindings=local_bindings,
                    )
                    continue
                source_path = self._extract_member_path(argument) or self._resolve_member_lookup_path(
                    argument,
                    constants,
                    bool_constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
                if source_path and self._clone_flattened_binding_prefix(
                    prefix,
                    source_path,
                    constants,
                    local_bindings,
                    bool_constants=bool_constants,
                ):
                    continue
                spread_values = self._resolve_object_expr(
                    argument,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
                for spread_key, spread_value in spread_values.items():
                    if spread_value is None or spread_value == "" or self._is_nullish_static_value(spread_value):
                        continue
                    local_bindings[f"{prefix}.{spread_key}"] = spread_value
                continue
            key_name = self._extract_property_name(prop.get("key"))
            if not key_name:
                continue
            path = f"{prefix}.{key_name}"
            value_node = prop.get("value")
            if isinstance(value_node, dict) and value_node.get("type") == "ObjectExpression":
                self._bind_local_object(
                    path,
                    value_node,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
                continue
            if isinstance(value_node, dict) and value_node.get("type") == "ArrayExpression":
                self._bind_local_array(
                    path,
                    value_node,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
                continue
            value = self._resolve_static_value(
                value_node,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if value is not None and value != "":
                local_bindings[path] = value

    def _bind_local_array(
        self,
        prefix: str,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> None:
        """Flatten a local array literal into helper-scope bindings."""
        local_bindings = bindings if bindings is not None else {}
        if node.get("type") != "ArrayExpression":
            return

        for index, element in enumerate(node.get("elements", [])):
            if not isinstance(element, dict):
                continue
            path = f"{prefix}.{index}"
            if element.get("type") == "ObjectExpression":
                self._bind_local_object(
                    path,
                    element,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
                continue
            if element.get("type") == "ArrayExpression":
                self._bind_local_array(
                    path,
                    element,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=allow_placeholders,
                    seen=seen,
                    bindings=local_bindings,
                )
                continue
            value = self._resolve_static_value(
                element,
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=allow_placeholders,
                seen=seen,
                bindings=local_bindings,
            )
            if value is not None and value != "":
                local_bindings[path] = value

    def _resolve_static_value(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        allow_placeholders: bool = False,
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Resolve a small static scalar subset used for helper argument binding."""
        scalar_value = self._resolve_scalar_expr(
            node,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
        if scalar_value is _NULLISH_STATIC:
            return _NULLISH_STATIC
        if isinstance(scalar_value, (str, bool, int)):
            return scalar_value
        bool_value = self._resolve_bool_expr(
            node,
            constants,
            bool_constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
        if bool_value is not None:
            return bool_value
        string_value = self._resolve_string_expr(
            node,
            constants,
            bool_constants,
            function_returns,
            allow_placeholders=allow_placeholders,
            seen=seen,
            bindings=bindings,
        )
        if string_value == _BLOCKED_STRING:
            return None
        return string_value

    def _resolve_bool_expr(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> Optional[bool]:
        """Resolve a conservative boolean subset for branch-aware helper analysis."""
        if not isinstance(node, dict):
            return None

        node_type = node.get("type")
        if node_type == "Literal" and isinstance(node.get("value"), bool):
            return node.get("value")

        if node_type == "Identifier":
            name = node.get("name", "")
            if bindings and isinstance(bindings.get(name), bool):
                return bindings[name]
            value = bool_constants.get(name)
            return value if isinstance(value, bool) else None

        if node_type == "MemberExpression":
            path = self._extract_member_path(node)
            if path and bindings and isinstance(bindings.get(path), bool):
                return bindings[path]
            value = bool_constants.get(path or "")
            return value if isinstance(value, bool) else None

        if node_type == "UnaryExpression" and node.get("operator") == "!":
            value = self._resolve_bool_expr(
                node.get("argument", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            return (not value) if value is not None else None

        if node_type == "LogicalExpression":
            left = self._resolve_bool_expr(
                node.get("left", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            right = self._resolve_bool_expr(
                node.get("right", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            if left is None or right is None:
                return None
            if node.get("operator") == "&&":
                return left and right
            if node.get("operator") == "||":
                return left or right
            return None

        if node_type == "BinaryExpression":
            operator = node.get("operator")
            if operator in {"==", "===", "!=", "!=="}:
                left = self._resolve_scalar_expr(
                    node.get("left", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
                right = self._resolve_scalar_expr(
                    node.get("right", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
                if left is None or right is None:
                    return None
                return (left == right) if operator in {"==", "==="} else (left != right)

        return None

    def _resolve_scalar_expr(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Resolve a scalar literal/binding used by boolean comparisons."""
        if not isinstance(node, dict):
            return None
        if node.get("type") == "Literal":
            value = node.get("value")
            if value is None:
                return _NULLISH_STATIC
            if isinstance(value, (str, bool, int)):
                return value
            return None
        if node.get("type") == "Identifier":
            name = node.get("name", "")
            if bindings and name in bindings:
                value = bindings[name]
                if value is _NULLISH_STATIC:
                    return _NULLISH_STATIC
                if isinstance(value, (str, bool, int)):
                    return None if self._is_placeholder_value(value) else value
            if name in bool_constants:
                return bool_constants[name]
            value = constants.get(name)
            if not isinstance(value, str):
                return None
            return None if self._is_placeholder_value(value) else value
        if node.get("type") == "MemberExpression":
            path = self._extract_member_path(node)
            if not path:
                path = self._resolve_member_lookup_path(
                    node,
                    constants,
                    bool_constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
            if not path:
                return None
            if bindings and path in bindings:
                value = bindings[path]
                if value is _NULLISH_STATIC:
                    return _NULLISH_STATIC
                if isinstance(value, (str, bool, int)):
                    return None if self._is_placeholder_value(value) else value
            if path in bool_constants:
                return bool_constants[path]
            value = constants.get(path)
            if not isinstance(value, str):
                return None
            return None if self._is_placeholder_value(value) else value
        if node.get("type") == "CallExpression" and node.get("callee", {}).get("type") == "Identifier":
            resolved = self._resolve_function_call(
                node.get("callee", {}).get("name", ""),
                node.get("arguments", []),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=False,
                seen=seen,
                bindings=bindings,
            )
            if resolved == _BLOCKED_STRING:
                return None
            return resolved or None
        if node.get("type") == "CallExpression" and node.get("callee", {}).get("type") == "MemberExpression":
            member_name = self._extract_member_path(node.get("callee", {}))
            if not member_name:
                return None
            resolved = self._resolve_function_call(
                member_name,
                node.get("arguments", []),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=False,
                seen=seen,
                bindings=bindings,
            )
            if resolved == _BLOCKED_STRING:
                return None
            return resolved or None
        if node.get("type") == "LogicalExpression":
            operator = node.get("operator")
            left = self._resolve_static_value(
                node.get("left", {}),
                constants,
                bool_constants,
                function_returns,
                allow_placeholders=False,
                seen=seen,
                bindings=bindings,
            )
            if left is None:
                return None
            if operator == "&&":
                if not self._is_truthy_static_value(left):
                    return left
                return self._resolve_static_value(
                    node.get("right", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=False,
                    seen=seen,
                    bindings=bindings,
                )
            if operator == "||":
                if self._is_truthy_static_value(left):
                    return left
                return self._resolve_static_value(
                    node.get("right", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=False,
                    seen=seen,
                    bindings=bindings,
                )
            if operator == "??":
                if self._is_nullish_static_value(left):
                    return self._resolve_static_value(
                        node.get("right", {}),
                        constants,
                        bool_constants,
                        function_returns,
                        allow_placeholders=False,
                        seen=seen,
                        bindings=bindings,
                    )
                return left
            return None
        if node.get("type") == "ConditionalExpression":
            decision = self._resolve_bool_expr(
                node.get("test", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            if decision is True:
                return self._resolve_static_value(
                    node.get("consequent", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=False,
                    seen=seen,
                    bindings=bindings,
                )
            if decision is False:
                return self._resolve_static_value(
                    node.get("alternate", {}),
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=False,
                    seen=seen,
                    bindings=bindings,
                )
            return None
        return None

    def _resolve_member_lookup_path(
        self,
        node: Any,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        seen: Optional[set[str]] = None,
        bindings: Optional[dict[str, Any]] = None,
    ) -> str:
        """Resolve computed member expressions such as ROUTES[kind] into dotted paths."""
        if not isinstance(node, dict) or node.get("type") != "MemberExpression":
            return ""

        object_node = node.get("object", {})
        object_path = ""
        if isinstance(object_node, dict) and object_node.get("type") == "MemberExpression":
            object_path = self._resolve_member_lookup_path(
                object_node,
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            ) or self._extract_member_path(object_node)
        else:
            object_path = self._extract_member_path(object_node)

        if not object_path:
            return ""

        if node.get("computed"):
            property_value = self._resolve_scalar_expr(
                node.get("property", {}),
                constants,
                bool_constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            if isinstance(property_value, int):
                property_name = str(property_value)
            elif isinstance(property_value, str) and not self._is_placeholder_value(property_value):
                property_name = property_value
            else:
                return ""
        else:
            property_name = node.get("property", {}).get("name", "")

        if not property_name:
            return ""
        return f"{object_path}.{property_name}"

    def _is_truthy_static_value(self, value: Any) -> bool:
        """Approximate JS truthiness for statically resolved helper values."""
        if self._is_nullish_static_value(value):
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value != ""
        return bool(value)

    def _build_constant_table(
        self,
        ast: dict[str, Any],
        function_returns: Optional[dict[str, dict[str, Any]]] = None,
    ) -> dict[str, str]:
        """Build a simple constant table for string-valued variables."""
        constants: dict[str, str] = {}
        resolved_functions = function_returns or {}
        if not ast:
            return constants

        for _ in range(5):
            changed = False
            for node in self._iter_nodes(ast):
                if node.get("type") != "VariableDeclarator":
                    continue
                identifier = node.get("id", {})
                init = node.get("init", {})
                if identifier.get("type") in {"ObjectPattern", "ArrayPattern"}:
                    if self._bind_pattern_alias_value(
                        identifier,
                        init,
                        constants,
                        {},
                        resolved_functions,
                        bindings=constants,
                    ):
                        changed = True
                    continue
                name = identifier.get("name")
                if not name:
                    continue
                if isinstance(init, dict) and init.get("type") == "ObjectExpression":
                    object_values = self._extract_object_string_values(
                        name,
                        init,
                        constants,
                        resolved_functions,
                    )
                    for key, value in object_values.items():
                        if value and constants.get(key) != value:
                            constants[key] = value
                            changed = True
                    continue
                if isinstance(init, dict) and init.get("type") == "ArrayExpression":
                    array_values = self._extract_array_string_values(
                        name,
                        init,
                        constants,
                        resolved_functions,
                    )
                    for key, value in array_values.items():
                        if value and constants.get(key) != value:
                            constants[key] = value
                            changed = True
                    continue
                if isinstance(init, dict) and init.get("type") == "Literal" and isinstance(init.get("value"), int):
                    numeric_value = str(init.get("value"))
                    if constants.get(name) != numeric_value:
                        constants[name] = numeric_value
                        changed = True
                    continue
                if isinstance(init, dict):
                    resolved_object = self._resolve_object_expr(
                        init,
                        constants,
                        {},
                        resolved_functions,
                        allow_placeholders=False,
                    )
                    if resolved_object:
                        for key, value in resolved_object.items():
                            if not isinstance(value, str) or not value:
                                continue
                            dotted_key = f"{name}.{key}"
                            if constants.get(dotted_key) != value:
                                constants[dotted_key] = value
                                changed = True
                value = self._resolve_string_expr(
                    init,
                    constants,
                    {},
                    resolved_functions,
                    allow_placeholders=False,
                )
                if value and constants.get(name) != value:
                    constants[name] = value
                    changed = True
            if not changed:
                break

        return constants

    def _build_boolean_table(
        self,
        ast: dict[str, Any],
        constants: dict[str, str],
    ) -> dict[str, bool]:
        """Build a small boolean table for statically decidable branch conditions."""
        bool_constants: dict[str, bool] = {}
        if not ast:
            return bool_constants

        for _ in range(5):
            changed = False
            for node in self._iter_nodes(ast):
                if node.get("type") != "VariableDeclarator":
                    continue
                identifier = node.get("id", {})
                name = identifier.get("name")
                if not name:
                    continue
                init = node.get("init", {})
                if isinstance(init, dict) and init.get("type") == "ObjectExpression":
                    object_values = self._extract_object_boolean_values(
                        name,
                        init,
                        constants,
                        bool_constants,
                    )
                    for key, value in object_values.items():
                        if bool_constants.get(key) != value:
                            bool_constants[key] = value
                            changed = True
                    continue
                value = self._resolve_bool_expr(
                    init,
                    constants,
                    bool_constants,
                    {},
                )
                if value is not None and bool_constants.get(name) != value:
                    bool_constants[name] = value
                    changed = True
            if not changed:
                break

        return bool_constants

    def _build_client_base_urls(
        self,
        ast: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
    ) -> dict[str, str]:
        """Find axios.create-style client instances and their base URLs."""
        clients: dict[str, str] = {}
        if not ast:
            return clients

        for node in self._iter_nodes(ast):
            if node.get("type") != "VariableDeclarator":
                continue
            identifier = node.get("id", {})
            name = identifier.get("name")
            init = node.get("init", {})
            if not name or init.get("type") != "CallExpression":
                continue

            callee = init.get("callee", {})
            if (
                callee.get("type") == "MemberExpression"
                and callee.get("object", {}).get("type") == "Identifier"
                and callee.get("object", {}).get("name") == "axios"
                and callee.get("property", {}).get("name") == "create"
                and init.get("arguments")
            ):
                config_arg = init["arguments"][0]
                if config_arg.get("type") == "ObjectExpression":
                    base_url = self._extract_object_property(
                        config_arg,
                        {"baseURL", "baseUrl", "base_uri", "baseUri"},
                        constants,
                        bool_constants,
                        function_returns,
                    )
                elif config_arg.get("type") == "Identifier":
                    base_url = self._extract_named_object_property(
                        config_arg.get("name", ""),
                        {"baseURL", "baseUrl", "base_uri", "baseUri"},
                        constants,
                    )
                else:
                    base_url = ""
                if base_url:
                    clients[name] = base_url

        return clients

    def _build_xhr_client_names(self, ast: dict[str, Any]) -> set[str]:
        """Collect variables bound to `new XMLHttpRequest()` instances."""
        clients: set[str] = set()
        if not ast:
            return clients

        for node in self._iter_nodes(ast):
            node_type = node.get("type")
            if node_type == "VariableDeclarator":
                identifier = node.get("id", {})
                name = identifier.get("name")
                init = node.get("init", {})
                if (
                    name
                    and isinstance(init, dict)
                    and init.get("type") == "NewExpression"
                    and self._is_xml_http_request_constructor(init.get("callee", {}))
                ):
                    clients.add(name)
            elif node_type == "AssignmentExpression":
                left = node.get("left", {})
                right = node.get("right", {})
                name = left.get("name", "") if left.get("type") == "Identifier" else ""
                if (
                    name
                    and isinstance(right, dict)
                    and right.get("type") == "NewExpression"
                    and self._is_xml_http_request_constructor(right.get("callee", {}))
                ):
                    clients.add(name)

        return clients

    def _is_xml_http_request_constructor(self, callee: Any) -> bool:
        """Return True for `XMLHttpRequest` constructor references."""
        if not isinstance(callee, dict):
            return False
        if callee.get("type") == "Identifier":
            return callee.get("name") == "XMLHttpRequest"
        if callee.get("type") != "MemberExpression" or callee.get("computed"):
            return False
        object_name = callee.get("object", {}).get("name", "")
        property_name = callee.get("property", {}).get("name", "")
        return object_name in {"window", "self", "globalThis"} and property_name == "XMLHttpRequest"

    def _is_websocket_constructor(self, callee: Any) -> bool:
        """Return True for `WebSocket` constructor references."""
        if not isinstance(callee, dict):
            return False
        if callee.get("type") == "Identifier":
            return callee.get("name") == "WebSocket"
        if callee.get("type") != "MemberExpression" or callee.get("computed"):
            return False
        object_name = callee.get("object", {}).get("name", "")
        property_name = callee.get("property", {}).get("name", "")
        return object_name in {"window", "self", "globalThis"} and property_name == "WebSocket"

    def _build_function_return_table(
        self,
        ast: dict[str, Any],
        constants: dict[str, str],
    ) -> dict[str, dict[str, Any]]:
        """Collect simple function signatures that can be resolved statically."""
        function_returns: dict[str, dict[str, Any]] = {}
        if not ast:
            return function_returns

        for node in self._iter_nodes(ast):
            name, params, body_node = self._extract_function_body_node(node)
            if not name or body_node is None:
                if node.get("type") == "VariableDeclarator":
                    object_name = node.get("id", {}).get("name", "")
                    init = node.get("init", {})
                    if object_name and isinstance(init, dict):
                        function_returns.update(
                            self._extract_object_method_bodies(object_name, init)
                        )
                continue
            function_returns[name] = {
                "params": params,
                "body": body_node,
            }

        return function_returns

    def _extract_object_method_bodies(
        self,
        prefix: str,
        node: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Collect static object-literal helper methods under dotted member paths."""
        if node.get("type") != "ObjectExpression" or not prefix:
            return {}

        function_returns: dict[str, dict[str, Any]] = {}
        for prop in node.get("properties", []):
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                continue

            key_name = self._extract_property_name(prop.get("key"))
            if not key_name:
                continue

            value = prop.get("value", {})
            path = f"{prefix}.{key_name}"
            params, body_node = self._extract_callable_body_node(value)
            if body_node is not None:
                function_returns[path] = {
                    "params": params,
                    "body": body_node,
                }
                continue

            if isinstance(value, dict) and value.get("type") == "ObjectExpression":
                function_returns.update(
                    self._extract_object_method_bodies(path, value)
                )

        return function_returns

    def _extract_callable_body_node(
        self,
        node: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
        """Extract params/body from a function expression or arrow function."""
        if not isinstance(node, dict):
            return [], None

        node_type = node.get("type")
        if node_type not in {"ArrowFunctionExpression", "FunctionExpression"}:
            return [], None

        params = self._extract_param_specs(node.get("params", []))
        if params is None:
            return [], None

        body_node = node.get("body", {})
        if node_type == "ArrowFunctionExpression" and body_node.get("type") != "BlockStatement":
            return params, body_node
        return params, body_node

    def _extract_function_body_node(
        self,
        node: dict[str, Any],
    ) -> tuple[str, list[dict[str, Any]], Optional[dict[str, Any]]]:
        """Extract a named function's params and returned expression node."""
        node_type = node.get("type")
        if node_type == "FunctionDeclaration":
            identifier = node.get("id", {})
            name = identifier.get("name", "")
            params = self._extract_param_specs(node.get("params", []))
            if name and params is not None:
                return name, params, node.get("body", {})
            return "", [], None

        if node_type != "VariableDeclarator":
            return "", [], None

        identifier = node.get("id", {})
        name = identifier.get("name", "")
        init = node.get("init", {})
        if not name or not isinstance(init, dict):
            return "", [], None

        init_type = init.get("type")
        if init_type not in {"ArrowFunctionExpression", "FunctionExpression"}:
            return "", [], None
        params = self._extract_param_specs(init.get("params", []))
        if params is None:
            return "", [], None

        if init_type == "ArrowFunctionExpression" and init.get("body", {}).get("type") != "BlockStatement":
            return name, params, init.get("body")
        return name, params, init.get("body", {})

    def _extract_param_specs(self, params: list[Any]) -> Optional[list[dict[str, Any]]]:
        """Extract supported function parameter specs, including simple defaults."""
        specs: list[dict[str, Any]] = []
        for param in params:
            if not isinstance(param, dict):
                return None
            if param.get("type") == "Identifier":
                specs.append({
                    "name": param.get("name", ""),
                    "default": None,
                })
                continue
            if param.get("type") == "ObjectPattern":
                specs.append({
                    "pattern": param,
                    "default": None,
                })
                continue
            if param.get("type") == "ArrayPattern":
                specs.append({
                    "pattern": param,
                    "default": None,
                })
                continue
            if param.get("type") == "AssignmentPattern":
                left = param.get("left", {})
                right = param.get("right")
                if not isinstance(right, dict):
                    return None
                if left.get("type") == "Identifier":
                    specs.append({
                        "name": left.get("name", ""),
                        "default": right,
                    })
                    continue
                if left.get("type") == "ObjectPattern":
                    specs.append({
                        "pattern": left,
                        "default": right,
                    })
                    continue
                if left.get("type") == "ArrayPattern":
                    specs.append({
                        "pattern": left,
                        "default": right,
                    })
                    continue
                return None
                continue
            return None
        return specs

    def _extract_return_expression(
        self,
        body_node: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Extract the first returned expression from a function body."""
        if body_node.get("type") != "BlockStatement":
            return None
        for statement in body_node.get("body", []):
            if statement.get("type") == "ReturnStatement":
                argument = statement.get("argument")
                if isinstance(argument, dict):
                    return argument
        return None

    def _iter_nodes(self, node: Any) -> Iterator[dict[str, Any]]:
        """Iterate all AST nodes depth-first."""
        if not isinstance(node, dict):
            return

        yield node
        for value in node.values():
            if isinstance(value, dict):
                yield from self._iter_nodes(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield from self._iter_nodes(item)

    def _extract_object_string_values(
        self,
        prefix: str,
        node: dict[str, Any],
        constants: dict[str, str],
        function_returns: Optional[dict[str, dict[str, Any]]] = None,
    ) -> dict[str, str]:
        """Flatten object-literal string members into dotted constant-table keys."""
        values: dict[str, str] = {}
        if node.get("type") != "ObjectExpression":
            return values

        for prop in node.get("properties", []):
            if not isinstance(prop, dict):
                continue
            if prop.get("type") == "SpreadElement":
                argument = prop.get("argument", {})
                if isinstance(argument, dict) and argument.get("type") == "ObjectExpression":
                    values.update(self._extract_object_string_values(prefix, argument, constants, function_returns))
                    continue
                source_path = self._extract_member_path(argument) or self._resolve_member_lookup_path(
                    argument,
                    constants,
                    {},
                    function_returns or {},
                )
                if source_path:
                    source_prefix = f"{source_path}."
                    for key, value in constants.items():
                        if not isinstance(key, str) or not key.startswith(source_prefix) or not value:
                            continue
                        remainder = key[len(source_prefix):]
                        path = f"{prefix}.{remainder}" if prefix else remainder
                        values[path] = value
                spread_values = self._resolve_object_expr(
                    argument if isinstance(argument, dict) else {},
                    constants,
                    {},
                    function_returns or {},
                )
                for spread_key, spread_value in spread_values.items():
                    if not isinstance(spread_value, str) or not spread_value or spread_value == _BLOCKED_STRING:
                        continue
                    path = f"{prefix}.{spread_key}" if prefix else spread_key
                    values[path] = spread_value
                continue
            key_name = self._extract_property_name(prop.get("key"))
            if not key_name:
                continue
            path = f"{prefix}.{key_name}"
            value_node = prop.get("value")
            if isinstance(value_node, dict) and value_node.get("type") == "ObjectExpression":
                values.update(self._extract_object_string_values(path, value_node, constants))
                continue
            if isinstance(value_node, dict) and value_node.get("type") == "ArrayExpression":
                values.update(self._extract_array_string_values(path, value_node, constants, function_returns))
                continue
            value = self._resolve_string_expr(
                value_node,
                constants,
                {},
                function_returns or {},
                allow_placeholders=False,
            )
            if value and value != _BLOCKED_STRING:
                values[path] = value
        return values

    def _extract_array_string_values(
        self,
        prefix: str,
        node: dict[str, Any],
        constants: dict[str, str],
        function_returns: Optional[dict[str, dict[str, Any]]] = None,
    ) -> dict[str, str]:
        """Flatten array string members into dotted constant-table keys."""
        values: dict[str, str] = {}
        if node.get("type") != "ArrayExpression":
            return values

        for index, element in enumerate(node.get("elements", [])):
            if not isinstance(element, dict):
                continue
            path = f"{prefix}.{index}"
            if element.get("type") == "ObjectExpression":
                values.update(self._extract_object_string_values(path, element, constants, function_returns))
                continue
            if element.get("type") == "ArrayExpression":
                values.update(self._extract_array_string_values(path, element, constants, function_returns))
                continue
            value = self._resolve_string_expr(
                element,
                constants,
                {},
                function_returns or {},
                allow_placeholders=False,
            )
            if value and value != _BLOCKED_STRING:
                values[path] = value
        return values

    def _extract_object_boolean_values(
        self,
        prefix: str,
        node: dict[str, Any],
        constants: dict[str, str],
        bool_constants: dict[str, bool],
    ) -> dict[str, bool]:
        """Flatten object-literal boolean members into dotted keys."""
        values: dict[str, bool] = {}
        if node.get("type") != "ObjectExpression":
            return values

        for prop in node.get("properties", []):
            if not isinstance(prop, dict):
                continue
            if prop.get("type") == "SpreadElement":
                argument = prop.get("argument", {})
                if isinstance(argument, dict) and argument.get("type") == "ObjectExpression":
                    values.update(
                        self._extract_object_boolean_values(
                            prefix,
                            argument,
                            constants,
                            bool_constants,
                        )
                    )
                    continue
                source_path = self._extract_member_path(argument) or self._resolve_member_lookup_path(
                    argument,
                    constants,
                    bool_constants,
                    {},
                )
                if source_path:
                    source_prefix = f"{source_path}."
                    for key, value in bool_constants.items():
                        if not isinstance(key, str) or not key.startswith(source_prefix):
                            continue
                        remainder = key[len(source_prefix):]
                        path = f"{prefix}.{remainder}" if prefix else remainder
                        values[path] = value
                spread_values = self._resolve_object_expr(
                    argument if isinstance(argument, dict) else {},
                    constants,
                    bool_constants,
                    {},
                )
                for spread_key, spread_value in spread_values.items():
                    if not isinstance(spread_value, bool):
                        continue
                    path = f"{prefix}.{spread_key}" if prefix else spread_key
                    values[path] = spread_value
                continue
            key_name = self._extract_property_name(prop.get("key"))
            if not key_name:
                continue
            path = f"{prefix}.{key_name}"
            value_node = prop.get("value")
            if isinstance(value_node, dict) and value_node.get("type") == "ObjectExpression":
                values.update(
                    self._extract_object_boolean_values(
                        path,
                        value_node,
                        constants,
                        bool_constants,
                    )
                )
                continue
            value = self._resolve_bool_expr(
                value_node,
                constants,
                bool_constants,
                {},
            )
            if value is not None:
                values[path] = value
        return values

    def _extract_property_name(self, node: Any) -> str:
        """Extract a static property name from an object key node."""
        if not isinstance(node, dict):
            return ""
        if node.get("type") == "Identifier":
            return node.get("name", "")
        if node.get("type") == "Literal":
            value = node.get("value")
            if isinstance(value, str):
                return value
            if isinstance(value, int):
                return str(value)
        return ""

    def _extract_member_path(self, node: Any) -> str:
        """Resolve a static dotted member-expression path."""
        if not isinstance(node, dict):
            return ""
        node_type = node.get("type")
        if node_type == "Identifier":
            return node.get("name", "")
        if node_type != "MemberExpression":
            return ""

        object_path = self._extract_member_path(node.get("object"))
        if not object_path:
            return ""
        if node.get("computed"):
            property_node = node.get("property", {})
            if property_node.get("type") == "Literal":
                property_name = self._extract_property_name(property_node)
            else:
                property_name = ""
        else:
            property_name = node.get("property", {}).get("name", "")
        if not property_name:
            return ""
        return f"{object_path}.{property_name}"

    def _looks_like_url(self, value: str) -> bool:
        """Check if value looks like a URL."""
        if not value:
            return False

        if self._is_static_asset_url(value):
            return False

        # Absolute URL
        if value.startswith(("http://", "https://", "ws://", "wss://", "//")):
            return True

        # Relative API path
        for pattern in self.API_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return True

        # Path with extension or query
        if re.match(r"^/[a-zA-Z0-9_/-]+(\.[a-z]+)?(\?.*)?$", value):
            return True

        return False

    def _is_static_asset_url(self, value: str) -> bool:
        """Return True for obvious frontend asset URLs that are not endpoints."""
        parsed = urlsplit(value if value.startswith(("http://", "https://", "ws://", "wss://")) else f"https://host{value}")
        path = parsed.path.lower()
        for extension in self.STATIC_ASSET_EXTENSIONS:
            if path.endswith(extension):
                return True
        return False

    def _join_url(self, base_url: str, path: str) -> str:
        """Join a base URL and relative path."""
        return f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    def _confidence_rank(self, value: Confidence) -> int:
        order = {
            Confidence.LOW: 0,
            Confidence.MEDIUM: 1,
            Confidence.HIGH: 2,
        }
        return order.get(value, 0)

    def _extract_method(
        self,
        call,
        is_fetch: bool,
        is_axios: bool,
        constants: dict[str, str],
        bool_constants: dict[str, bool],
        function_returns: dict[str, dict[str, Any]],
        resolved_arg_object: Optional[dict[str, Any]] = None,
    ) -> str:
        """Extract HTTP method from call."""
        name_lower = call.name.lower()

        # Method in function name (exact match only)
        if name_lower in self.HTTP_METHOD_FUNCTIONS:
            return name_lower.upper()

        if resolved_arg_object:
            method_value = resolved_arg_object.get("method")
            if isinstance(method_value, str) and method_value:
                return method_value.upper()

        # Check options object for method
        if len(call.arguments) > 1:
            options = call.arguments[1]
            if options.get("type") == "ObjectExpression":
                for prop in options.get("properties", []):
                    key = prop.get("key", {}).get("name", "")
                    if key.lower() == "method":
                        value = prop.get("value", {})
                        if value.get("type") == "Literal":
                            return str(value.get("value", "GET")).upper()
            else:
                resolved_options = self._resolve_object_expr(
                    options,
                    constants,
                    bool_constants,
                    function_returns,
                    allow_placeholders=False,
                )
                method_value = resolved_options.get("method")
                if isinstance(method_value, str) and method_value:
                    return method_value.upper()

        return "GET"

    def _check_url_pattern(
        self,
        literal,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Check string literals for URL patterns."""
        value = literal.value

        # Skip already processed (from function calls)
        if not value or len(value) < 3:
            return

        # Check for API patterns
        matched = False
        for pattern in self.API_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                if self._is_static_asset_url(value):
                    return
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    title=f"API Path: {value[:50]}",
                    description=f"Potential API path found: {value}",
                    extracted_value=value,
                    value_type="api_path",
                    line=literal.line,
                    column=literal.column,
                    ast_node_type="Literal",
                    tags=["api_path"],
                )
                matched = True
                break

        if matched:
            return

        # Check for full URLs (path is optional ??bare domain, trailing slash, or query-only is valid)
        url_match = re.match(
            r"^((?:https?|wss?)://[a-zA-Z0-9.-]+(?::\d+)?)((?:/|\?).*)?$",
            value
        )
        if url_match:
            if not self._is_standalone_api_literal(value, literal, context):
                return
            domain = url_match.group(1)
            path = url_match.group(2) or "/"
            if self._is_static_asset_url(value):
                return

            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title=f"Full URL: {value[:50]}",
                description=f"Full URL found: {value}",
                extracted_value=value,
                value_type="full_url",
                line=literal.line,
                column=literal.column,
                ast_node_type="Literal",
                tags=["full_url"],
                metadata={"domain": domain, "path": path},
            )

    def _is_standalone_api_literal(
        self,
        value: str,
        literal,
        context: AnalysisContext,
    ) -> bool:
        """Return True when a standalone full URL literal looks API-like enough to report."""
        if self._has_documentation_literal_context(literal, context):
            return False

        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").lower()
        query = (parsed.query or "").lower()

        if any(label in self.API_HOST_LABELS for label in host.split(".")):
            return True
        if self._path_looks_api_like(path):
            return True
        if any(hint in query for hint in self.API_QUERY_HINTS):
            return True
        return False

    def _path_looks_api_like(self, path: str) -> bool:
        """Return True when a URL path looks API-specific rather than like a docs/site page."""
        if not path:
            return False
        for pattern in self.API_PATTERNS:
            if re.match(pattern, path, re.IGNORECASE):
                return True
        if "/api/" in path:
            return True
        return False

    def _has_documentation_literal_context(
        self,
        literal,
        context: AnalysisContext,
    ) -> bool:
        """Return True when a standalone literal line looks like docs/example content."""
        if not context.source_content or literal.line <= 0:
            return False

        lines = context.source_content.split("\n")
        line_idx = literal.line - 1
        if line_idx < 0 or line_idx >= len(lines):
            return False

        line = re.sub(r'(["\'`])(?:\\.|(?!\1).)*\1', '""', lines[line_idx]).lower()
        return any(hint in line for hint in self.DOC_CONTEXT_HINTS)

