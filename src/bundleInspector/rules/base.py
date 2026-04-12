"""
Base classes for rule engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterator

from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    IntermediateRepresentation,
    Severity,
)


@dataclass
class AnalysisContext:
    """Context for rule analysis."""
    file_url: str
    file_hash: str
    source_content: str
    is_first_party: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_snippet(
        self,
        line: int,
        context_lines: int = 3,
    ) -> tuple[str, tuple[int, int]]:
        """
        Get code snippet around a line.

        Args:
            line: Target line (1-indexed)
            context_lines: Number of context lines before/after

        Returns:
            (snippet, (start_line, end_line))
        """
        lines = self.source_content.split("\n")

        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)

        snippet_lines = lines[start:end]
        snippet = "\n".join(snippet_lines)

        return snippet, (start + 1, end)


@dataclass
class RuleResult:
    """Result from a single rule match."""
    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    extracted_value: str
    value_type: str
    line: int
    column: int
    ast_node_type: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for detection rules."""

    # Rule metadata (override in subclasses)
    id: str = "base"
    name: str = "Base Rule"
    description: str = ""
    category: Category = Category.ENDPOINT
    severity: Severity = Severity.INFO
    enabled: bool = True

    @abstractmethod
    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """
        Match rule against IR.

        Args:
            ir: Intermediate representation of the JS file
            context: Analysis context

        Yields:
            RuleResult for each match
        """
        pass

    def to_finding(
        self,
        result: RuleResult,
        context: AnalysisContext,
    ) -> Finding:
        """
        Convert RuleResult to Finding.

        Args:
            result: Rule match result
            context: Analysis context

        Returns:
            Finding
        """
        snippet, (start, end) = context.get_snippet(result.line)

        evidence = Evidence(
            file_url=context.file_url,
            file_hash=context.file_hash,
            line=result.line,
            column=result.column,
            snippet=snippet,
            snippet_lines=(start, end),
            ast_node_type=result.ast_node_type,
        )

        # Merge is_first_party from context into metadata for scoring
        metadata = dict(result.metadata)
        metadata["is_first_party"] = context.is_first_party

        return Finding(
            rule_id=result.rule_id,
            category=result.category,
            severity=result.severity,
            confidence=result.confidence,
            title=result.title,
            description=result.description,
            evidence=evidence,
            extracted_value=result.extracted_value,
            value_type=result.value_type,
            tags=result.tags,
            metadata=metadata,
        )

