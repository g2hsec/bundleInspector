"""
Line mapping for tracking positions through normalization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LineMapping:
    """Mapping between original and normalized positions."""
    original_line: int
    original_column: int
    normalized_line: int
    normalized_column: int


@dataclass
class LineMapper:
    """
    Maps between original and normalized line/column positions.

    Used to maintain evidence accuracy after beautification.
    """

    mappings: list[LineMapping] = field(default_factory=list)

    # Quick lookup structures (list per line to preserve all mappings)
    _by_normalized: dict[int, list[LineMapping]] = field(default_factory=dict)
    _by_original: dict[int, list[LineMapping]] = field(default_factory=dict)

    def add_mapping(self, mapping: LineMapping) -> None:
        """Add a line mapping."""
        self.mappings.append(mapping)
        self._by_normalized.setdefault(mapping.normalized_line, []).append(mapping)
        self._by_original.setdefault(mapping.original_line, []).append(mapping)

    def get_original(
        self,
        normalized_line: int,
        normalized_column: int = 0,
    ) -> tuple[int, int]:
        """
        Get original position from normalized position.

        Args:
            normalized_line: Line in normalized content
            normalized_column: Column in normalized content

        Returns:
            (original_line, original_column)
        """
        if normalized_line in self._by_normalized:
            mapping = self._by_normalized[normalized_line][0]
            return mapping.original_line, mapping.original_column

        # Find nearest mapping
        nearest = self._find_nearest_normalized(normalized_line)
        if nearest:
            # Estimate based on offset
            offset = normalized_line - nearest.normalized_line
            return nearest.original_line + offset, 0

        # Fallback: same line
        return normalized_line, normalized_column

    def get_normalized(
        self,
        original_line: int,
        original_column: int = 0,
    ) -> tuple[int, int]:
        """
        Get normalized position from original position.

        Args:
            original_line: Line in original content
            original_column: Column in original content

        Returns:
            (normalized_line, normalized_column)
        """
        if original_line in self._by_original:
            mapping = self._by_original[original_line][0]
            return mapping.normalized_line, mapping.normalized_column

        # Find nearest mapping
        nearest = self._find_nearest_original(original_line)
        if nearest:
            offset = original_line - nearest.original_line
            return nearest.normalized_line + offset, 0

        return original_line, original_column

    def _find_nearest_normalized(
        self,
        line: int,
    ) -> Optional[LineMapping]:
        """Find mapping with nearest normalized line."""
        if not self.mappings:
            return None

        # Binary search would be more efficient for large mappings
        best = None
        best_dist = float("inf")

        for mapping in self.mappings:
            dist = abs(mapping.normalized_line - line)
            if dist < best_dist:
                best_dist = dist
                best = mapping

        return best

    def _find_nearest_original(
        self,
        line: int,
    ) -> Optional[LineMapping]:
        """Find mapping with nearest original line."""
        if not self.mappings:
            return None

        best = None
        best_dist = float("inf")

        for mapping in self.mappings:
            dist = abs(mapping.original_line - line)
            if dist < best_dist:
                best_dist = dist
                best = mapping

        return best

    @classmethod
    def identity(cls, content: str) -> "LineMapper":
        """
        Create identity mapper (1:1 mapping).

        Used when no transformation is applied.
        """
        mapper = cls()
        lines = content.count("\n") + 1

        for i in range(1, lines + 1):
            mapper.add_mapping(LineMapping(
                original_line=i,
                original_column=0,
                normalized_line=i,
                normalized_column=0,
            ))

        return mapper

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "mappings": [
                {
                    "original_line": m.original_line,
                    "original_column": m.original_column,
                    "normalized_line": m.normalized_line,
                    "normalized_column": m.normalized_column,
                }
                for m in self.mappings
            ]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LineMapper":
        """Deserialize from dictionary."""
        mapper = cls()
        for m in data.get("mappings", []):
            mapper.add_mapping(LineMapping(
                original_line=m["original_line"],
                original_column=m["original_column"],
                normalized_line=m["normalized_line"],
                normalized_column=m["normalized_column"],
            ))
        return mapper
