"""
Risk scoring utilities.
"""

from __future__ import annotations

from bundleInspector.storage.models import Category, Confidence, Finding, Severity


# Impact weights by category
CATEGORY_IMPACT = {
    Category.SECRET: 1.0,
    Category.DEBUG: 0.8,
    Category.ENDPOINT: 0.5,
    Category.DOMAIN: 0.6,
    Category.FLAG: 0.3,
}

# Severity multipliers
SEVERITY_MULTIPLIER = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.3,
    Severity.INFO: 0.1,
}

# Confidence weights
CONFIDENCE_WEIGHT = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}


class ScoreCalculator:
    """Calculate risk scores for findings."""

    def calculate_impact(self, finding: Finding) -> float:
        """
        Calculate impact score.

        Args:
            finding: Finding to score

        Returns:
            Impact score (0.0 - 1.0)
        """
        base = CATEGORY_IMPACT.get(finding.category, 0.5)
        severity_mult = SEVERITY_MULTIPLIER.get(finding.severity, 0.5)

        return base * severity_mult

    def calculate_likelihood(
        self,
        finding: Finding,
        correlation_count: int = 0,
    ) -> float:
        """
        Calculate likelihood score.

        Args:
            finding: Finding to score
            correlation_count: Number of correlations

        Returns:
            Likelihood score (0.0 - 1.0)
        """
        base = 0.5

        # Increase for first-party findings
        if finding.metadata.get("is_first_party", False):
            base += 0.1

        # Increase for correlated findings
        base += min(0.2, correlation_count * 0.05)

        # Adjust based on value type
        high_likelihood_types = [
            "aws_access_key", "stripe_secret_key", "github_pat",
            "jwt_token", "database_url", "private_key",
        ]
        if finding.value_type in high_likelihood_types:
            base += 0.2

        return min(base, 1.0)

    def calculate_confidence(self, finding: Finding) -> float:
        """
        Calculate confidence score.

        Args:
            finding: Finding to score

        Returns:
            Confidence score (0.0 - 1.0)
        """
        return CONFIDENCE_WEIGHT.get(finding.confidence, 0.5)

    def calculate_risk_score(
        self,
        finding: Finding,
        correlation_count: int = 0,
    ) -> float:
        """
        Calculate overall risk score.

        Args:
            finding: Finding to score
            correlation_count: Number of correlations

        Returns:
            Risk score (0.0 - 10.0)
        """
        impact = self.calculate_impact(finding)
        likelihood = self.calculate_likelihood(finding, correlation_count)
        confidence = self.calculate_confidence(finding)

        # Store component scores
        finding.impact_score = impact
        finding.likelihood_score = likelihood

        # Calculate final score
        score = impact * likelihood * confidence * 10

        return round(score, 2)

