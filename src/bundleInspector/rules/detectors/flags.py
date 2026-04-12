"""
Feature flag detector.

Detects feature flags, A/B tests, and hidden functionality.
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


class FlagDetector(BaseRule):
    """
    Detect feature flags and hidden functionality.

    Looks for:
    - Feature flag patterns
    - A/B test configurations
    - Remote config fetches
    - Conditional feature enablement
    """

    id = "flag-detector"
    name = "Feature Flag Detector"
    description = "Detects feature flags and hidden functionality"
    category = Category.FLAG
    severity = Severity.LOW

    # Flag-related keywords in variable/function names
    FLAG_KEYWORDS = [
        "feature_flag",
        "feature-flag",
        "featureflag",
        "feature_toggle",
        "feature-toggle",
        "toggle",
        "experiment",
        "variant",
        "ab_test",
        "abtest",
        "a_b_test",
        "rollout",
        "canary",
        "beta_feature",
        "alpha_feature",
        "preview_feature",
        "hidden_feature",
        "internal_only",
        "admin_only",
        "debug_mode",
        "dev_mode",
        "dev_only",
    ]

    # Common feature flag SDKs
    FLAG_SDKS = [
        "launchdarkly",
        "optimizely",
        "splitio",
        "configcat",
        "unleash",
        "flipper",
        "growthbook",
        "flagsmith",
        "featureflag",
    ]

    # Config endpoint patterns
    CONFIG_ENDPOINTS = [
        r"/(?:api/)?(?:feature[-_]?)?flags?",
        r"/(?:api/)?config(?:uration)?s?",
        r"/(?:api/)?experiments?",
        r"/(?:api/)?settings",
        r"/(?:api/)?toggles?",
        r"/(?:api/)?variants?",
    ]

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match feature flags in IR."""
        # Check string literals
        for literal in ir.string_literals:
            yield from self._check_literal(literal)

        # Check function calls
        for call in ir.function_calls:
            yield from self._check_call(call)

        # Check identifiers
        for name, identifiers in ir.identifiers.items():
            yield from self._check_identifier(name, identifiers)

    def _check_literal(self, literal) -> Iterator[RuleResult]:
        """Check string literals for flag patterns."""
        value = literal.value.lower()

        # Skip short strings
        if len(value) < 3:
            return

        # Check for flag keywords
        matched_keyword = False
        for keyword in self.FLAG_KEYWORDS:
            if keyword in value:
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title=f"Feature Flag: {literal.value[:50]}",
                    description=f"Found potential feature flag reference: {literal.value}",
                    extracted_value=literal.value,
                    value_type="feature_flag",
                    line=literal.line,
                    column=literal.column,
                    ast_node_type="Literal",
                    tags=["flag", keyword],
                )
                matched_keyword = True
                break

        # Check for config endpoints (skip if already matched as keyword)
        if matched_keyword:
            return
        for pattern in self.CONFIG_ENDPOINTS:
            if re.search(pattern, value, re.IGNORECASE):
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title=f"Config Endpoint: {literal.value[:50]}",
                    description=f"Found feature/config endpoint: {literal.value}",
                    extracted_value=literal.value,
                    value_type="config_endpoint",
                    line=literal.line,
                    column=literal.column,
                    ast_node_type="Literal",
                    tags=["flag", "endpoint"],
                )
                break

    def _check_call(self, call) -> Iterator[RuleResult]:
        """Check function calls for flag SDKs."""
        full_name = call.full_name.lower()
        name = call.name.lower()

        # Common function names that contain flag keywords but aren't flags
        EXCLUDE_NAMES = {"invariant", "environment", "development", "navigator"}
        if name in EXCLUDE_NAMES:
            return
        # Exclude calls on browser APIs (e.g., window.navigator.vibrate)
        # Only check the caller object names, not the entire chain, to avoid
        # false exclusions like "config.environment.getFlag()"
        EXCLUDE_OBJECTS = {"navigator"}
        parts = full_name.split(".")
        if any(part in EXCLUDE_OBJECTS for part in parts[:-1]):
            return

        # Check for flag SDK usage
        sdk_matched = False
        for sdk in self.FLAG_SDKS:
            if sdk in full_name:
                # Try to extract flag name
                flag_name = self._extract_flag_from_args(call.arguments)

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Feature Flag SDK: {sdk.title()}",
                    description=f"Found {sdk} SDK usage" + (f" for flag: {flag_name}" if flag_name else ""),
                    extracted_value=flag_name or call.full_name,
                    value_type="flag_sdk",
                    line=call.line,
                    column=call.column,
                    ast_node_type="CallExpression",
                    tags=["flag", "sdk", sdk],
                    metadata={"sdk": sdk, "flag": flag_name},
                )
                sdk_matched = True
                break

        # Skip function pattern check if already matched as SDK call
        if sdk_matched:
            return

        # Check for common flag function patterns
        flag_functions = ["isfeatureenabled", "isflagon", "hasfeature", "getvariant", "getexperiment"]
        if name in flag_functions or any(re.search(rf"(?<![a-z]){f}(?![a-z])", name) for f in ["flag", "feature", "variant"]):
            flag_name = self._extract_flag_from_args(call.arguments)

            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title=f"Feature Flag Check: {call.name}",
                description=f"Found feature flag check" + (f" for: {flag_name}" if flag_name else ""),
                extracted_value=flag_name or call.full_name,
                value_type="flag_check",
                line=call.line,
                column=call.column,
                ast_node_type="CallExpression",
                tags=["flag"],
                metadata={"flag": flag_name},
            )

    def _check_identifier(self, name: str, identifiers: list) -> Iterator[RuleResult]:
        """Check identifier names for flag patterns."""
        name_lower = name.lower()

        # Skip common names
        if len(name) < 5:
            return

        # Check for admin/internal patterns
        admin_patterns = ["isadmin", "adminmode", "adminonly", "internalonly", "devmode", "debugmode"]
        for pattern in admin_patterns:
            if pattern in name_lower:
                first = identifiers[0] if identifiers else None
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title=f"Admin/Debug Flag: {name}",
                    description=f"Found potential admin/debug flag: {name}",
                    extracted_value=name,
                    value_type="admin_flag",
                    line=first.line if first else 0,
                    column=first.column if first else 0,
                    ast_node_type="Identifier",
                    tags=["flag", "admin"],
                )
                break

    def _extract_flag_from_args(self, arguments: list) -> str:
        """Extract flag name from function arguments."""
        if not arguments:
            return ""

        first_arg = arguments[0]

        if first_arg.get("type") == "Literal":
            return str(first_arg.get("value", ""))

        return ""

