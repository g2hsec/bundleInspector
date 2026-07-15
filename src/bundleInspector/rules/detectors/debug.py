"""
Debug endpoint detector.

Detects debug endpoints, diagnostic routes, and development artifacts.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    FunctionCall,
    IntermediateRepresentation,
    Severity,
    StringLiteral,
)


class DebugDetector(BaseRule):
    """
    Detect debug endpoints and development artifacts.

    Looks for:
    - Debug/admin endpoints
    - Health check and metrics endpoints
    - Logging and diagnostic calls
    - Development-only code
    """

    id = "debug-detector"
    name = "Debug Endpoint Detector"
    description = "Detects debug endpoints and development artifacts"
    category = Category.DEBUG
    severity = Severity.MEDIUM

    # Debug endpoint patterns (path, type, severity)
    # Use word boundary (/dev/ or /dev$) to avoid matching /devices, /developers etc.
    DEBUG_ENDPOINTS = [
        (r"^/debug(?:/|$)", "debug_endpoint", Severity.HIGH),
        (r"^/admin(?:/|$)", "admin_endpoint", Severity.HIGH),
        (r"^/internal(?:/|$)", "internal_endpoint", Severity.HIGH),
        # `/_` marks an underscore-prefixed (often internal) path, but framework BUILD ASSETS
        # (/_next/, /_nuxt/) are public artifacts in every Next.js/Nuxt bundle -- exclude them so a
        # scan of any such app isn't flooded with MEDIUM "hidden endpoint" false positives.
        (r"^/_(?!(?:next|nuxt)[/-])", "hidden_endpoint", Severity.MEDIUM),
        (r"^/test(?:/|$)", "test_endpoint", Severity.MEDIUM),
        (r"^/dev(?:/|$)", "dev_endpoint", Severity.MEDIUM),
        (r"^/health(?:/|$)", "health_endpoint", Severity.LOW),
        (r"^/status(?:/|$)", "status_endpoint", Severity.LOW),
        (r"^/metrics(?:/|$)", "metrics_endpoint", Severity.LOW),
        (r"^/info(?:/|$)", "info_endpoint", Severity.LOW),
        (r"^/actuator(?:/|$)", "actuator_endpoint", Severity.MEDIUM),
        (r"^/swagger(?:/|$)", "swagger_endpoint", Severity.LOW),
        (r"^/api-docs(?:/|$)", "api_docs_endpoint", Severity.LOW),
        (r"^/graphql(?:/|$)", "graphql_endpoint", Severity.INFO),
        (r"^/playground(?:/|$)", "playground_endpoint", Severity.MEDIUM),
        (r"^/console(?:/|$)", "console_endpoint", Severity.HIGH),
        (r"^/shell(?:/|$)", "shell_endpoint", Severity.CRITICAL),
        (r"^/eval(?:/|$)", "eval_endpoint", Severity.CRITICAL),
        (r"^/exec(?:/|$)", "exec_endpoint", Severity.CRITICAL),
        (r"(?:^|(?<=/))phpinfo(?:/|$)", "phpinfo_endpoint", Severity.HIGH),
        (r"(?:^|(?<=/))server-status(?:/|$)", "server_status_endpoint", Severity.MEDIUM),
        (r"(?:^|(?<=/))trace(?:/|$)", "trace_endpoint", Severity.MEDIUM),
        (r"(?:^|(?<=/))dump(?:/|$)", "dump_endpoint", Severity.HIGH),
        # `profiler`/`profiling` only -- the bare `e` alternative matched the ordinary user-facing
        # `/profile` route as a MEDIUM "Profiler Endpoint" false positive.
        (r"(?:^|(?<=/))profil(?:er|ing)(?:/|$)", "profiler_endpoint", Severity.MEDIUM),
    ]

    # Debug function calls
    DEBUG_FUNCTIONS = [
        "console.log",
        "console.debug",
        "console.trace",
        "console.dir",
        "console.table",
        "debugger",
        "alert",
    ]

    # Development-only patterns
    DEV_PATTERNS = [
        # Only match equality checks (=== or ==), not inequality (!== or !=)
        (r"process\.env\.NODE_ENV\s*={2,3}\s*['\"]development['\"]", "dev_check"),
        (r"process\.env\.NODE_ENV\s*={2,3}\s*['\"]test['\"]", "test_check"),
        (r"__DEV__", "dev_flag"),
        (r"__DEBUG__", "debug_flag"),
        (r"\bDEBUG\s*=\s*true", "debug_enabled"),
        (r"\bDEVELOPMENT\s*[=:]\s*true", "dev_enabled"),
    ]

    # `//# sourceMappingURL=...` (or legacy `//@`, or `/* ... */`) points at the source map, which
    # reconstructs the ORIGINAL (pre-minification) source -- comments, dev endpoints, sometimes
    # secrets. Anchored to the start of a (beautified) line so it can't match the directive text
    # embedded inside a bundled tooling string literal.
    SOURCE_MAP_DIRECTIVE = re.compile(
        r"^[ \t]*(?://|/\*)[#@]\s*(sourceMappingURL|sourceURL)\s*=\s*(\S+?)(?:\s*\*/)?[ \t]*\r?$",
        re.IGNORECASE | re.MULTILINE,
    )

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match debug patterns in IR."""
        # Check string literals for debug endpoints
        for literal in ir.string_literals:
            yield from self._check_debug_endpoints(literal)

        # Check function calls for debug functions
        for call in ir.function_calls:
            yield from self._check_debug_calls(call, context)

        # Check source for debugger statements (DebuggerStatement is not a
        # CallExpression, so it won't appear in ir.function_calls)
        yield from self._check_debugger_statements(ir)

        # Check source for development patterns
        yield from self._check_dev_patterns(ir)

        # Check source for source-map disclosure directives
        yield from self._check_source_map(context)

    def _check_debug_endpoints(self, literal: StringLiteral) -> Iterator[RuleResult]:
        """Check for debug endpoints in strings."""
        value = literal.value

        for pattern, endpoint_type, severity in self.DEBUG_ENDPOINTS:
            if re.search(pattern, value, re.IGNORECASE):
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    title=f"Debug Endpoint: {endpoint_type.replace('_', ' ').title()}",
                    description=f"Found debug/admin endpoint: {value}",
                    extracted_value=value,
                    value_type=endpoint_type,
                    line=literal.line,
                    column=literal.column,
                    ast_node_type="Literal",
                    tags=["debug", endpoint_type],
                )
                break

    def _check_debug_calls(
        self,
        call: FunctionCall,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Check for debug function calls."""
        full_name = call.full_name

        # Check console methods with potential sensitive data
        if full_name.startswith("console."):
            # Check what's being logged
            has_sensitive = self._check_logged_data(call.arguments)

            if has_sensitive:
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title=f"Debug Logging: {full_name}",
                    description="Found console logging with potentially sensitive data",
                    extracted_value=full_name,
                    value_type="debug_logging",
                    line=call.line,
                    column=call.column,
                    ast_node_type="CallExpression",
                    tags=["debug", "logging"],
                )

        # Check for alert (often used for debugging)
        if call.name == "alert":
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title="Alert Statement",
                description="Found alert() call, possibly for debugging",
                extracted_value="alert",
                value_type="alert_call",
                line=call.line,
                column=call.column,
                ast_node_type="CallExpression",
                tags=["debug", "alert"],
            )

    def _iter_nodes(self, root: Any) -> Iterator[dict[str, Any]]:
        stack = [root]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            yield node
            for key, value in node.items():
                if key in ("loc", "range", "raw"):
                    continue
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(item for item in reversed(value) if isinstance(item, dict))

    @staticmethod
    def _member_path(node: Any) -> str:
        parts = []
        cur = node
        while isinstance(cur, dict) and cur.get("type") == "MemberExpression":
            prop = cur.get("property") or {}
            parts.append(str(prop.get("name") or prop.get("value") or ""))
            cur = cur.get("object")
        if isinstance(cur, dict) and cur.get("type") == "Identifier":
            parts.append(cur.get("name", ""))
        return ".".join(reversed([part for part in parts if part]))

    def _check_debugger_statements(self, ir: IntermediateRepresentation) -> Iterator[RuleResult]:
        """DebuggerStatement is syntax, so use the AST instead of quote/comment heuristics."""
        for node in self._iter_nodes(ir.raw_ast or {}):
            if node.get("type") != "DebuggerStatement":
                continue
            start = (node.get("loc") or {}).get("start") or {}
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Debugger Statement",
                description="Found debugger statement in code",
                extracted_value="debugger",
                value_type="debugger_statement",
                line=int(start.get("line") or 0),
                column=int(start.get("column") or 0),
                ast_node_type="DebuggerStatement",
                tags=["debug", "debugger"],
            )

    def _check_logged_data(self, arguments: list) -> bool:
        """Check if logged data might be sensitive."""
        sensitive_keywords = [
            "password",
            "token",
            "secret",
            "key",
            "auth",
            "credential",
            "session",
            "cookie",
            "bearer",
        ]

        for arg in arguments:
            # Check literals
            if arg.get("type") == "Literal":
                value = str(arg.get("value", "")).lower()
                if any(kw in value for kw in sensitive_keywords):
                    return True

            # Check identifiers
            if arg.get("type") == "Identifier":
                name = arg.get("name", "").lower()
                if any(kw in name for kw in sensitive_keywords):
                    return True

        return False

    def _check_dev_patterns(self, ir: IntermediateRepresentation) -> Iterator[RuleResult]:
        """Detect development conditions structurally; comments/strings are not AST expressions."""
        seen = set()
        for node in self._iter_nodes(ir.raw_ast or {}):
            pattern_type = None
            extracted = ""
            t = node.get("type")
            if t == "Identifier" and node.get("name") in ("__DEV__", "__DEBUG__"):
                extracted = node["name"]
                pattern_type = "dev_flag" if extracted == "__DEV__" else "debug_flag"
            elif t in ("BinaryExpression", "LogicalExpression") and node.get("operator") in (
                "==",
                "===",
            ):
                left, right = node.get("left") or {}, node.get("right") or {}
                path = self._member_path(left)
                value = right.get("value") if right.get("type") == "Literal" else None
                if path == "process.env.NODE_ENV" and value in ("development", "test"):
                    extracted = f"{path} === {value!r}"
                    pattern_type = "dev_check" if value == "development" else "test_check"
            elif t in ("VariableDeclarator", "AssignmentExpression"):
                target = node.get("id") if t == "VariableDeclarator" else node.get("left")
                value = node.get("init") if t == "VariableDeclarator" else node.get("right")
                name = target.get("name") if isinstance(target, dict) else None
                if (
                    name in ("DEBUG", "DEVELOPMENT")
                    and isinstance(value, dict)
                    and value.get("value") is True
                ):
                    extracted = f"{name}=true"
                    pattern_type = "debug_enabled" if name == "DEBUG" else "dev_enabled"
            if pattern_type is None:
                continue
            start = (node.get("loc") or {}).get("start") or {}
            sig = (pattern_type, int(start.get("line") or 0), int(start.get("column") or 0))
            if sig in seen:
                continue
            seen.add(sig)
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title=f"Development Check: {pattern_type}",
                description=f"Found development/debug conditional: {extracted}",
                extracted_value=extracted,
                value_type=pattern_type,
                line=sig[1],
                column=sig[2],
                ast_node_type="Expression",
                tags=["debug", "development"],
            )

    @staticmethod
    def _mask_strings(source: str) -> str:
        chars = list(source)
        quote = None
        escaped = False
        for i, ch in enumerate(source):
            if quote is not None:
                if ch == "\n" and quote != "`":
                    quote = None
                    escaped = False
                    continue
                if not escaped and ch == quote:
                    chars[i] = " "
                    quote = None
                    continue
                escaped = not escaped and ch == "\\"
                if ch != "\n":
                    chars[i] = " "
                continue
            if ch in ("'", '"', "`"):
                quote = ch
                chars[i] = " "
                escaped = False
        return "".join(chars)

    def _check_source_map(
        self,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Check for `//# sourceMappingURL=` disclosure directives in source."""
        source = context.source_content or ""
        for match in self.SOURCE_MAP_DIRECTIVE.finditer(self._mask_strings(source)):
            line = context.source_content[: match.start()].count("\n") + 1
            directive, target = match.group(1), match.group(2)
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Source Map Disclosure",
                description=(
                    f"{directive} directive exposes the source map ({target}), which "
                    f"reconstructs the original pre-minification source."
                ),
                extracted_value=target,
                value_type="source_map_reference",
                line=line,
                column=0,
                ast_node_type="Line",
                tags=["debug", "source-map", "disclosure"],
            )
