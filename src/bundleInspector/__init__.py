"""
BundleInspector - JavaScript Security Analysis Tool

Extract hidden APIs, domains, secrets, feature flags, and debug endpoints
from JavaScript files through static and dynamic analysis.
"""

__version__ = "0.1.0"
__author__ = "BundleInspector Team"

from bundleInspector.config import Config, ScopeConfig, AuthConfig
from bundleInspector.core.orchestrator import BundleInspector
from bundleInspector.storage.models import (
    JSAsset,
    Finding,
    Evidence,
    Correlation,
    Cluster,
    Report,
    Severity,
    Confidence,
    Category,
    RiskTier,
)

__all__ = [
    # Main
    "BundleInspector",
    "Config",
    "ScopeConfig",
    "AuthConfig",
    # Models
    "JSAsset",
    "Finding",
    "Evidence",
    "Correlation",
    "Cluster",
    "Report",
    # Enums
    "Severity",
    "Confidence",
    "Category",
    "RiskTier",
]

