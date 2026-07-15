"""JS normalization module - beautify, sourcemap, line mapping."""

from bundleInspector.normalizer.beautify import Beautifier, NormalizationLevel
from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping
from bundleInspector.normalizer.sourcemap import SourceMapResolver

__all__ = [
    "Beautifier",
    "NormalizationLevel",
    "SourceMapResolver",
    "LineMapper",
    "LineMapping",
]

