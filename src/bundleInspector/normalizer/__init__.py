"""JS normalization module - beautify, sourcemap, line mapping."""

from bundleInspector.normalizer.beautify import Beautifier, NormalizationLevel
from bundleInspector.normalizer.sourcemap import SourceMapResolver
from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping

__all__ = [
    "Beautifier",
    "NormalizationLevel",
    "SourceMapResolver",
    "LineMapper",
    "LineMapping",
]

