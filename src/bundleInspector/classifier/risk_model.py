"""
Risk classification model.
"""

from __future__ import annotations

from dataclasses import dataclass

from bundleInspector.classifier.scoring import ScoreCalculator
from bundleInspector.correlator.graph import CorrelationGraph
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Finding,
    RiskTier,
    Severity,
)


@dataclass
class RiskScore:
    """Risk score result."""
    tier: RiskTier
    score: float
    impact: float
    likelihood: float
    confidence: float
    reasoning: str


class RiskClassifier:
    """
    Classify findings by risk level.

    Uses a model combining:
    - Impact (what's the potential damage)
    - Likelihood (how likely is exploitation)
    - Confidence (how sure are we about the finding)
    """

    def __init__(self):
        self._calculator = ScoreCalculator()

    def classify(
        self,
        finding: Finding,
        graph: CorrelationGraph | None = None,
    ) -> RiskScore:
        """
        Classify a finding's risk level.

        Args:
            finding: Finding to classify
            graph: Optional correlation graph

        Returns:
            RiskScore
        """
        # Count correlations
        correlation_count = 0
        if graph:
            correlation_count = len(graph.get_related(finding.id))

        # Calculate scores
        score = self._calculator.calculate_risk_score(
            finding, correlation_count
        )

        # Determine tier
        tier = self._score_to_tier(score, finding)

        # Build reasoning
        reasoning = self._build_reasoning(
            finding, score, tier, correlation_count
        )

        # Update finding
        finding.risk_score = score
        finding.risk_tier = tier

        return RiskScore(
            tier=tier,
            score=score,
            impact=finding.impact_score,
            likelihood=finding.likelihood_score,
            confidence=self._calculator.calculate_confidence(finding),
            reasoning=reasoning,
        )

    def classify_all(
        self,
        findings: list[Finding],
        graph: CorrelationGraph | None = None,
    ) -> list[RiskScore]:
        """
        Classify all findings.

        Args:
            findings: Findings to classify
            graph: Optional correlation graph

        Returns:
            List of RiskScore
        """
        return [self.classify(f, graph) for f in findings]

    def _score_to_tier(self, score: float, finding: Finding) -> RiskTier:
        """Determine risk tier from score and finding."""
        # P0: Critical secrets with high confidence
        if (
            finding.category == Category.SECRET and
            finding.severity == Severity.CRITICAL and
            finding.confidence == Confidence.HIGH
        ):
            return RiskTier.P0

        # P0: Very high scores
        if score >= 7.0:
            return RiskTier.P0

        # P1: High scores or critical findings
        if score >= 5.0:
            return RiskTier.P1

        if finding.severity == Severity.CRITICAL:
            return RiskTier.P1

        # P2: Medium scores
        if score >= 3.0:
            return RiskTier.P2

        # P3: Low scores
        return RiskTier.P3

    def _build_reasoning(
        self,
        finding: Finding,
        score: float,
        tier: RiskTier,
        correlation_count: int,
    ) -> str:
        """Build human-readable reasoning."""
        parts = []

        # Category
        parts.append(f"Category: {finding.category.value}")

        # Severity
        parts.append(f"Severity: {finding.severity.value}")

        # Confidence
        parts.append(f"Confidence: {finding.confidence.value}")

        # Correlations
        if correlation_count > 0:
            parts.append(f"Correlated with {correlation_count} other findings")

        # Score breakdown
        parts.append(
            f"Score: {score:.1f}/10 "
            f"(Impact: {finding.impact_score:.2f}, "
            f"Likelihood: {finding.likelihood_score:.2f})"
        )

        return ". ".join(parts)


def classify_findings(
    findings: list[Finding],
    graph: CorrelationGraph | None = None,
) -> list[RiskScore]:
    """
    Convenience function to classify findings.

    Args:
        findings: Findings to classify
        graph: Optional correlation graph

    Returns:
        List of RiskScore
    """
    classifier = RiskClassifier()
    return classifier.classify_all(findings, graph)

