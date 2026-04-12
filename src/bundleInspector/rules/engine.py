"""
Rule engine for running detection rules.
"""

from __future__ import annotations

import structlog
from typing import Iterator, Optional

from bundleInspector.config import RuleConfig
from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import Category, Finding, IntermediateRepresentation


logger = structlog.get_logger()


class RuleEngine:
    """
    Engine for running detection rules against parsed JS.
    """

    def __init__(self, config: RuleConfig | None = None):
        self.config = config or RuleConfig()
        self.rules: list[BaseRule] = []
        self._context_filter: Optional["ContextFilter"] = None
        self._defaults_registered: bool = False

    def register(self, rule: BaseRule) -> None:
        """
        Register a rule with the engine.

        Args:
            rule: Rule to register
        """
        self.rules.append(rule)

    def register_defaults(self) -> None:
        """Register default detection rules (idempotent)."""
        if self._defaults_registered:
            return
        self._defaults_registered = True

        from bundleInspector.rules.detectors.endpoints import EndpointDetector
        from bundleInspector.rules.detectors.secrets import SecretDetector
        from bundleInspector.rules.detectors.domains import DomainDetector
        from bundleInspector.rules.detectors.flags import FlagDetector
        from bundleInspector.rules.detectors.debug import DebugDetector
        from bundleInspector.parser.chunk_analyzer import ChunkAnalyzer
        from bundleInspector.rules.context_filter import ContextFilter

        self.register(EndpointDetector())
        self.register(SecretDetector(entropy_threshold=self.config.entropy_threshold))
        self.register(DomainDetector())
        self.register(FlagDetector())
        self.register(DebugDetector())
        self.register(ChunkAnalyzer())

        # Initialize context filter for false positive reduction
        self._context_filter = ContextFilter()

        # Register optional user-provided regex rules
        if self.config.custom_rules_file:
            from bundleInspector.rules.custom import load_custom_rules

            try:
                for rule in load_custom_rules(self.config.custom_rules_file):
                    self.register(rule)
            except Exception as e:
                logger.warning(
                    "custom_rules_load_error",
                    path=str(self.config.custom_rules_file),
                    error=str(e),
                )

    def analyze(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> list[Finding]:
        """
        Run all rules against an IR.

        Args:
            ir: Intermediate representation
            context: Analysis context

        Returns:
            List of findings
        """
        findings = []
        enabled_categories = set()
        for c in self.config.enabled_categories:
            try:
                enabled_categories.add(Category(c))
            except ValueError:
                pass

        for rule in self.rules:
            # Skip disabled rules
            if not rule.enabled:
                continue

            # Skip rules not in enabled categories
            if rule.category not in enabled_categories:
                continue

            try:
                for result in rule.match(ir, context):
                    # Filter by confidence
                    if not self._meets_confidence_threshold(result):
                        continue

                    finding = rule.to_finding(result, context)

                    # Mask secrets if configured
                    if (
                        self.config.mask_secrets and
                        finding.category == Category.SECRET
                    ):
                        finding.mask_value(self.config.secret_visible_chars)

                    findings.append(finding)

            except Exception as e:
                logger.warning(
                    "rule_error",
                    rule_id=rule.id,
                    error=str(e),
                )

        # Apply context-based false positive filtering
        if self._context_filter:
            findings = self._context_filter.filter_findings(
                findings,
                ir=ir,
                source_content=context.source_content,
                file_url=context.file_url,
            )

        return findings

    def _meets_confidence_threshold(self, result: RuleResult) -> bool:
        """Check if result meets minimum confidence threshold."""
        min_conf = self.config.min_confidence.lower()

        confidence_order = ["low", "medium", "high"]

        try:
            result_idx = confidence_order.index(result.confidence.value.lower())
        except ValueError:
            return True

        try:
            min_idx = confidence_order.index(min_conf)
        except ValueError:
            return True

        return result_idx >= min_idx

    def get_rules_by_category(self, category: Category) -> list[BaseRule]:
        """Get all rules for a specific category."""
        return [r for r in self.rules if r.category == category]

    def get_rule(self, rule_id: str) -> BaseRule | None:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

