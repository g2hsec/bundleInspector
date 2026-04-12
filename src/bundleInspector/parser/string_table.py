"""
String table for extracted strings.

Provides utilities for working with extracted string literals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

from bundleInspector.storage.models import StringLiteral


@dataclass
class StringEntry:
    """Entry in string table with metadata."""
    value: str
    literals: list[StringLiteral]
    count: int = 1

    @property
    def first_occurrence(self) -> Optional[StringLiteral]:
        """Get first occurrence of this string."""
        return self.literals[0] if self.literals else None


class StringTable:
    """
    Table of unique strings extracted from JS.

    Provides deduplication and lookup functionality.
    """

    def __init__(self):
        self._entries: dict[str, StringEntry] = {}
        self._by_line: dict[int, list[StringLiteral]] = {}

    def add(self, literal: StringLiteral) -> None:
        """
        Add a string literal to the table.

        Args:
            literal: StringLiteral to add
        """
        value = literal.value

        if value in self._entries:
            self._entries[value].literals.append(literal)
            self._entries[value].count += 1
        else:
            self._entries[value] = StringEntry(
                value=value,
                literals=[literal],
                count=1,
            )

        # Index by line
        line = literal.line
        if line not in self._by_line:
            self._by_line[line] = []
        self._by_line[line].append(literal)

    def get(self, value: str) -> Optional[StringEntry]:
        """Get entry for a string value."""
        return self._entries.get(value)

    def contains(self, value: str) -> bool:
        """Check if string exists in table."""
        return value in self._entries

    def get_at_line(self, line: int) -> list[StringLiteral]:
        """Get all strings at a specific line."""
        return self._by_line.get(line, [])

    def __iter__(self) -> Iterator[StringEntry]:
        """Iterate over all entries."""
        return iter(self._entries.values())

    def __len__(self) -> int:
        """Get number of unique strings."""
        return len(self._entries)

    @property
    def total_occurrences(self) -> int:
        """Get total number of string occurrences."""
        return sum(e.count for e in self._entries.values())

    def filter_by_length(
        self,
        min_length: int = 0,
        max_length: Optional[int] = None,
    ) -> Iterator[StringEntry]:
        """
        Filter strings by length.

        Args:
            min_length: Minimum string length
            max_length: Maximum string length (None for no limit)

        Yields:
            StringEntry objects matching criteria
        """
        for entry in self._entries.values():
            length = len(entry.value)
            if length >= min_length:
                if max_length is None or length <= max_length:
                    yield entry

    def filter_by_pattern(
        self,
        pattern: str,
        case_sensitive: bool = True,
    ) -> Iterator[StringEntry]:
        """
        Filter strings by regex pattern.

        Args:
            pattern: Regex pattern to match
            case_sensitive: Whether matching is case-sensitive

        Yields:
            StringEntry objects matching pattern
        """
        import re

        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = re.compile(pattern, flags)

        for entry in self._entries.values():
            if compiled.search(entry.value):
                yield entry

    def find_urls(self) -> Iterator[StringEntry]:
        """Find strings that look like URLs (deduplicated across patterns)."""
        url_patterns = [
            r'^https?://',
            r'^/api/',
            r'^/v\d+/',
            r'^/graphql',
        ]

        seen: set[str] = set()
        for pattern in url_patterns:
            for entry in self.filter_by_pattern(pattern, case_sensitive=False):
                if entry.value not in seen:
                    seen.add(entry.value)
                    yield entry

    def find_potential_secrets(self) -> Iterator[StringEntry]:
        """Find strings that might be secrets (deduplicated across patterns)."""
        secret_patterns = [
            r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64-like
            r'^[a-f0-9]{32,}$',  # Hex
            r'(api|secret|token|key|password)',  # Keywords
        ]

        seen: set[str] = set()
        for pattern in secret_patterns:
            for entry in self.filter_by_pattern(pattern, case_sensitive=False):
                if entry.value not in seen:
                    seen.add(entry.value)
                    yield entry

    @classmethod
    def from_ir(cls, ir: "IntermediateRepresentation") -> "StringTable":
        """
        Build string table from IR.

        Args:
            ir: IntermediateRepresentation

        Returns:
            StringTable
        """
        table = cls()
        for literal in ir.string_literals:
            table.add(literal)
        return table

