"""
Line mapping for tracking positions through normalization.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
            mappings = self._by_normalized[normalized_line]
            # Column-aware: pick the mapping whose normalized_column is the greatest <= the requested
            # column (best segment), instead of blindly taking the first -- two callsites on one
            # minified line otherwise both map to the leftmost token (DQ-P09). Column 0 still picks
            # the leftmost mapping, preserving prior behavior.
            best = None
            best_col = -1
            for m in mappings:
                mc = getattr(m, "normalized_column", 0) or 0
                if mc <= normalized_column and mc > best_col:
                    best, best_col = m, mc
            mapping = best if best is not None else mappings[0]
            # DQ-P07: preserve the intra-segment column offset. Mappings are stored one-per-line with
            # normalized_column at the segment start, so returning the raw original_column dropped the
            # requested column (an identity mapper always yielded column 0), which then mis-queried a
            # sourcemap on the leftmost token. Add the offset so column 0 stays backward-compatible
            # and a non-zero column resolves to its true original column.
            # Clamp the offset to >= 0: a line-level finding queries column 0 while the segment starts
            # at the indentation, so (0 - indent) would go negative -- an invalid coordinate that also
            # defeats sourcemap resolution. Column 0 then correctly maps to the line's first token
            # (mapping.original_column), and a real token column keeps its intra-segment offset.
            seg_col = getattr(mapping, "normalized_column", 0) or 0
            return mapping.original_line, mapping.original_column + max(0, normalized_column - seg_col)

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
    ) -> LineMapping | None:
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
    ) -> LineMapping | None:
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
    def identity(cls, content: str) -> LineMapper:
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
    def from_dict(cls, data: dict) -> LineMapper:
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
