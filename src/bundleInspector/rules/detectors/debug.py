"""
Debug endpoint detector.

Detects debug endpoints, diagnostic routes, and development artifacts.
"""

from __future__ import annotations

import re
from typing import Iterator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
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
        (r"^/_", "hidden_endpoint", Severity.MEDIUM),
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
        (r"(?:^|(?<=/))profil(?:e|er|ing)(?:/|$)", "profiler_endpoint", Severity.MEDIUM),
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
        yield from self._check_debugger_statements(context)

        # Check source for development patterns
        yield from self._check_dev_patterns(context)

    def _check_debug_endpoints(self, literal) -> Iterator[RuleResult]:
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
        call,
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
                    description=f"Found console logging with potentially sensitive data",
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

    def _check_debugger_statements(
        self,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Check for debugger statements via source regex (not in IR function_calls)."""
        for match in re.finditer(r'\bdebugger\b', context.source_content):
            # Get the line containing the match to filter out strings/comments
            line_start = context.source_content.rfind("\n", 0, match.start()) + 1
            line_end = context.source_content.find("\n", match.end())
            if line_end == -1:
                line_end = len(context.source_content)
            line_text = context.source_content[line_start:line_end].strip()

            # Skip matches inside comments
            if line_text.startswith("//") or line_text.startswith("*") or line_text.startswith("/*"):
                continue

            prefix = context.source_content[line_start:match.start()]

            # Skip matches inside inline block comments (e.g., var x; /* debugger */)
            last_comment_open = prefix.rfind('/*')
            if last_comment_open >= 0 and prefix.rfind('*/', last_comment_open) < 0:
                continue

            # Skip matches inside string literals (count unescaped quotes)
            unescaped_dq = len(re.findall(r'(?<!\\)"', prefix))
            unescaped_sq = len(re.findall(r"(?<!\\)'", prefix))
            if unescaped_dq % 2 == 1 or unescaped_sq % 2 == 1:
                continue

            # Skip matches inside template literals (backtick strings)
            if prefix.count('`') % 2 == 1:
                continue

            line = context.source_content[:match.start()].count("\n") + 1

            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Debugger Statement",
                description="Found debugger statement in code",
                extracted_value="debugger",
                value_type="debugger_statement",
                line=line,
                column=0,
                ast_node_type="DebuggerStatement",
                tags=["debug", "debugger"],
            )

    def _check_logged_data(self, arguments: list) -> bool:
        """Check if logged data might be sensitive."""
        sensitive_keywords = [
            "password", "token", "secret", "key", "auth",
            "credential", "session", "cookie", "bearer",
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

    def _check_dev_patterns(
        self,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Check for development-only patterns in source."""
        for pattern, pattern_type in self.DEV_PATTERNS:
            for match in re.finditer(pattern, context.source_content):
                # Get line number
                line = context.source_content[:match.start()].count("\n") + 1

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title=f"Development Check: {pattern_type}",
                    description=f"Found development/debug conditional: {match.group(0)}",
                    extracted_value=match.group(0),
                    value_type=pattern_type,
                    line=line,
                    column=0,
                    ast_node_type="Expression",
                    tags=["debug", "development"],
                )

