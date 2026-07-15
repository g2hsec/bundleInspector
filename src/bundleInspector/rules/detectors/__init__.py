"""Detection rules for various security findings."""

from bundleInspector.rules.detectors.debug import DebugDetector
from bundleInspector.rules.detectors.domains import DomainDetector
from bundleInspector.rules.detectors.endpoints import EndpointDetector
from bundleInspector.rules.detectors.flags import FlagDetector
from bundleInspector.rules.detectors.secrets import SecretDetector

__all__ = [
    "EndpointDetector",
    "SecretDetector",
    "DomainDetector",
    "FlagDetector",
    "DebugDetector",
]
