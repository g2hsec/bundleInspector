"""
Rule engine for running detection rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from bundleInspector.config import RuleConfig
from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import Category, Finding, IntermediateRepresentation

if TYPE_CHECKING:
    from bundleInspector.rules.context_filter import ContextFilter

logger = structlog.get_logger()


class RuleEngine:
    """
    Engine for running detection rules against parsed JS.
    """

    def __init__(self, config: RuleConfig | None = None):
        self.config = config or RuleConfig()
        self.rules: list[BaseRule] = []
        self._context_filter: ContextFilter | None = None
        self._defaults_registered: bool = False
        self._custom_rule_load_events: list[dict[str, object]] = []

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

        from bundleInspector.parser.chunk_analyzer import ChunkAnalyzer
        from bundleInspector.rules.context_filter import ContextFilter
        from bundleInspector.rules.detectors.debug import DebugDetector
        from bundleInspector.rules.detectors.domains import DomainDetector
        from bundleInspector.rules.detectors.endpoints import EndpointDetector
        from bundleInspector.rules.detectors.flags import FlagDetector
        from bundleInspector.rules.detectors.routes import RouteDetector
        from bundleInspector.rules.detectors.secrets import SecretDetector
        from bundleInspector.rules.detectors.sinks import DomSinkDetector
        from bundleInspector.rules.detectors.taint import TaintFlowDetector
        from bundleInspector.rules.detectors.uploads import FileUploadDetector

        self.register(EndpointDetector(self.config))
        self.register(SecretDetector(entropy_threshold=self.config.entropy_threshold))
        self.register(DomainDetector())
        self.register(FlagDetector())
        self.register(DebugDetector())
        self.register(ChunkAnalyzer())
        self.register(RouteDetector())
        self.register(DomSinkDetector())
        self.register(FileUploadDetector())
        self.register(TaintFlowDetector())

        # Initialize context filter for false positive reduction
        self._context_filter = ContextFilter()

        # Register optional user-provided regex rules
        if self.config.custom_rules_file:
            from bundleInspector.rules.custom import CustomRuleLoadDiagnostic, load_custom_rules

            diagnostics: list[CustomRuleLoadDiagnostic] = []
            try:
                for rule in load_custom_rules(
                    self.config.custom_rules_file,
                    diagnostics=diagnostics,
                ):
                    self.register(rule)
            except Exception as e:
                logger.warning(
                    "custom_rules_load_error",
                    path=str(self.config.custom_rules_file),
                    error=str(e),
                )
            self._custom_rule_load_events = [
                diagnostic.as_analysis_incomplete() for diagnostic in diagnostics
            ]

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
        if self._custom_rule_load_events:
            incomplete = context.metadata.setdefault("analysis_incomplete", [])
            if isinstance(incomplete, list):
                for event in self._custom_rule_load_events:
                    if event not in incomplete:
                        incomplete.append(dict(event))
        enabled_categories = set()
        unknown_categories = []
        for c in self.config.enabled_categories:
            try:
                # Normalize case/whitespace so " Endpoint " / "ENDPOINT" resolve instead of
                # silently disabling the whole category (DQ-O06).
                normalized = c.strip().lower() if isinstance(c, str) else c
                enabled_categories.add(Category(normalized))
            except (ValueError, AttributeError):
                unknown_categories.append(c)
        if unknown_categories and not getattr(self, "_warned_unknown_categories", False):
            # A typo here (e.g. "secrets" vs "secret") would otherwise silently
            # disable an entire finding category with zero signal to the user.
            self._warned_unknown_categories = True
            logger.warning(
                "unknown_enabled_categories",
                unknown=unknown_categories,
                valid=[c.value for c in Category],
            )

        for rule in self.rules:
            # Skip disabled rules
            if not rule.enabled:
                continue

            # Skip rules not in enabled categories
            if rule.category not in enabled_categories:
                continue

            # Obtain the result iterator. A failure constructing it (or a
            # generator raising mid-iteration) is contained to THIS rule.
            try:
                matcher = iter(rule.match(ir, context))
            except Exception as e:
                logger.warning("rule_error", rule_id=rule.id, error=str(e))
                self._record_rule_execution_error(
                    context,
                    rule_id=rule.id,
                    phase="matcher_creation",
                    error=e,
                )
                continue

            while True:
                try:
                    result = next(matcher)
                except StopIteration:
                    break
                except Exception as e:
                    # A generator can't be resumed after it raises, so stop this
                    # rule -- but results already collected are preserved.
                    logger.warning("rule_error", rule_id=rule.id, error=str(e))
                    self._record_rule_execution_error(
                        context,
                        rule_id=rule.id,
                        phase="matcher_iteration",
                        error=e,
                    )
                    break

                # A single malformed result must not discard the rule's other
                # findings. Previously one bad AST node zeroed the whole
                # detector for the file (silent detection drop).
                try:
                    finding = rule.to_finding(result, context)

                    # Mask secrets if configured
                    if self.config.mask_secrets and finding.category == Category.SECRET:
                        finding.mask_value(self.config.secret_visible_chars)

                    findings.append(finding)
                except Exception as e:
                    logger.warning("rule_result_error", rule_id=rule.id, error=str(e))
                    self._record_rule_execution_error(
                        context,
                        rule_id=rule.id,
                        phase="result_conversion",
                        error=e,
                    )
                    continue

        findings = self._collapse_overlapping_route_findings(findings)

        # Apply context-based false positive filtering
        if self._context_filter:
            findings = self._context_filter.filter_findings(
                findings,
                ir=ir,
                source_content=context.source_content,
                file_url=context.file_url,
            )

        # Context analysis is allowed to lower confidence (for example a provider credential in
        # documentation/sample code).  Applying the configured threshold before that adjustment
        # leaked post-filter LOW findings through a HIGH-only engine.  Threshold the final evidence
        # level instead, after every context downgrade has been applied.
        findings = [finding for finding in findings if self._meets_confidence_threshold(finding)]

        # enh1: flag endpoints reachable only behind a client-side access-control guard.
        try:
            from bundleInspector.rules.access_control import annotate_client_side_gating

            annotate_client_side_gating(findings, ir, context.source_content, self.config)
        except Exception as e:
            logger.warning("access_control_error", error=str(e))

        return findings

    @staticmethod
    def _record_rule_execution_error(
        context: AnalysisContext,
        *,
        rule_id: str,
        phase: str,
        error: Exception,
    ) -> None:
        """Disclose contained rule failures without exposing exception messages."""
        event: dict[str, object] = {
            "component": "rule_engine",
            "rule_id": rule_id,
            "phase": phase,
            "reason": "rule_execution_error",
            "partial_results": True,
            "error_type": type(error).__name__,
        }
        incomplete = context.metadata.setdefault("analysis_incomplete", [])
        if isinstance(incomplete, list) and event not in incomplete:
            incomplete.append(event)

    @staticmethod
    def _collapse_overlapping_route_findings(findings: list[Finding]) -> list[Finding]:
        """Prefer structural client-route evidence over a generic regex hit at one occurrence."""
        structural_occurrences = {
            (
                finding.evidence.file_url,
                finding.evidence.line,
                finding.extracted_value,
            )
            for finding in findings
            if finding.category == Category.ENDPOINT and finding.value_type == "client_route"
        }
        if not structural_occurrences:
            return findings
        return [
            finding
            for finding in findings
            if not (
                finding.category == Category.ENDPOINT
                and finding.value_type == "route_path"
                and (
                    finding.evidence.file_url,
                    finding.evidence.line,
                    finding.extracted_value,
                )
                in structural_occurrences
            )
        ]

    def _meets_confidence_threshold(self, result: RuleResult | Finding) -> bool:
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
            # A bad min_confidence normally can't reach here (config validation rejects it), but a
            # direct runtime assignment (engine.config.min_confidence = "typo") bypasses pydantic.
            # Warn ONCE and fall back to the permissive 'low' threshold rather than silently
            # disabling filtering -- no finding is dropped, but the misconfig is no longer invisible.
            if not getattr(self, "_warned_bad_min_confidence", False):
                self._warned_bad_min_confidence = True
                logger.warning("invalid_min_confidence", value=min_conf, valid=confidence_order)
            min_idx = 0

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
