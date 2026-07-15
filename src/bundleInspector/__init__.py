"""
BundleInspector - JavaScript Security Analysis Tool

Extract hidden APIs, domains, secrets, feature flags, and debug endpoints
from JavaScript files through static and dynamic analysis.
"""

from typing import Any

__version__ = "0.1.0"
__author__ = "BundleInspector Team"

from bundleInspector.config import AuthConfig, Config, ScopeConfig
from bundleInspector.storage.models import (
    Category,
    Cluster,
    Confidence,
    Correlation,
    Evidence,
    Finding,
    JSAsset,
    Report,
    RiskTier,
    Severity,
)


def __getattr__(name: str) -> Any:
    # Lazy re-export: importing `BundleInspector` pulls in the orchestrator (and its
    # playwright/httpx stack). Deferring it keeps `import bundleInspector.<submodule>`
    # light -- critical for spawned parallel analysis workers (asset_analysis), which must
    # not re-import the browser/network stack. `from bundleInspector import BundleInspector`
    # still resolves through this hook.
    if name == "BundleInspector":
        from bundleInspector.core.orchestrator import BundleInspector

        return BundleInspector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

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
