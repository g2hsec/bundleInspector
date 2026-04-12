"""
Context-based false positive filter.

Analyzes surrounding code context to reduce false positives
in secret and other detection rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bundleInspector.storage.models import (
    Category,
    Confidence,
    Finding,
    IntermediateRepresentation,
    Severity,
)

# Severity ordering: higher index = more severe
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CONFIDENCE_ORDER = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


@dataclass
class ContextSignal:
    """A context signal that affects confidence."""
    name: str
    is_false_positive: bool
    confidence_adjustment: float  # -1.0 to +1.0
    reason: str


class ContextFilter:
    """
    Filter findings based on surrounding code context.

    Reduces false positives by analyzing:
    - Variable names (uuid, hash, version ??likely not secrets)
    - Assignment context (is the value assigned to a known non-secret var)
    - File context (test files, mock data, example configs)
    - Structural patterns (arrays of similar values, lookup tables)
    - Duplicate detection (same value across multiple patterns)
    """

    # Variable names that indicate non-secret values
    NON_SECRET_VAR_NAMES = {
        "uuid", "guid", "id", "uid", "objectid",
        "hash", "checksum", "digest", "md5", "sha1", "sha256", "sha512",
        "version", "ver", "revision", "rev",
        "timestamp", "time", "date", "created", "updated", "expires",
        "nonce", "salt", "iv",
        "color", "colour", "hex",
        "regex", "pattern", "regexp",
        "classname", "classnames", "css", "style",
        "mimetype", "contenttype", "encoding", "charset",
        "locale", "lang", "language", "timezone",
        "placeholder", "example", "sample", "demo", "test", "mock",
        "doc", "docs", "readme", "documentation", "guide", "tutorial", "snippet",
        "default", "fallback",
        "name", "label", "title", "description", "text", "message",
        "path", "route", "pathname", "dirname", "filename",
        "type", "kind", "category", "status", "state",
        "format", "template", "layout",
    }

    # File path patterns indicating test/mock context
    TEST_FILE_PATTERNS = [
        r"[/\\]tests?[/\\]",
        r"[/\\]__tests__[/\\]",
        r"[/\\]spec[/\\]",
        r"[/\\]__mocks__[/\\]",
        r"[/\\]fixtures?[/\\]",
        r"[/\\]stubs?[/\\]",
        r"\.test\.",
        r"\.spec\.",
        r"\.mock\.",
        r"\.example\.",
        r"\.sample\.",
    ]

    # String patterns that look like non-secret structured data
    NON_SECRET_VALUE_PATTERNS = [
        # CSS-like hex colors
        r"^#[0-9a-fA-F]{3,8}$",
        # Semantic version strings
        r"^\d+\.\d+\.\d+",
        # ISO date strings
        r"^\d{4}-\d{2}-\d{2}",
        # Email addresses (not secrets themselves)
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        # MIME types
        r"^(application|text|image|audio|video|multipart)/[a-z0-9.+-]+$",
        # File extensions
        r"^\.[a-z]{2,5}$",
        # Simple word-based strings (spaces, natural language)
        r"^[a-zA-Z]+(\s[a-zA-Z]+){2,}$",
        # CSS class names (kebab-case with multiple segments)
        r"^[a-z][a-z0-9]*(-[a-z0-9]+){2,}$",
        # URL paths without credentials or credential-like query params
        r"^https?://[a-zA-Z0-9.-]+(?::\d+)?(/[^?]*)?(\?(?!.*(key=|token=|secret=|password=|auth=|api_key=|apikey=|access_token=))[^@]*)?$",
    ]

    def __init__(self):
        self._compiled_test_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.TEST_FILE_PATTERNS
        ]
        self._compiled_value_patterns = [
            re.compile(p) for p in self.NON_SECRET_VALUE_PATTERNS
        ]

    def filter_findings(
        self,
        findings: list[Finding],
        ir: Optional[IntermediateRepresentation] = None,
        source_content: str = "",
        file_url: str = "",
    ) -> list[Finding]:
        """
        Filter findings to reduce false positives.

        Args:
            findings: List of findings to filter
            ir: Optional IR for context analysis
            source_content: Source code content
            file_url: File URL for test file detection

        Returns:
            Filtered list of findings
        """
        filtered = []
        seen_values: dict[str, Finding] = {}

        # Check if this is a test/mock file
        is_test_file = self._is_test_file(file_url)

        for finding in findings:
            # Only apply context filtering to secrets
            if finding.category != Category.SECRET:
                filtered.append(finding)
                continue

            signals = self._analyze_context(
                finding, ir, source_content, is_test_file
            )

            # Check for strong FP signals
            is_fp = any(s.is_false_positive for s in signals)
            if is_fp:
                continue

            # Deduplicate: keep only highest-severity match per value
            value_key = finding.extracted_value
            if value_key in seen_values:
                existing = seen_values[value_key]
                # Keep the more severe finding (higher order = more severe)
                finding_order = _SEVERITY_ORDER.get(finding.severity, 0)
                existing_order = _SEVERITY_ORDER.get(existing.severity, 0)
                # If same severity, prefer higher confidence
                if finding_order > existing_order or (
                    finding_order == existing_order
                    and _CONFIDENCE_ORDER.get(finding.confidence, 0) > _CONFIDENCE_ORDER.get(existing.confidence, 0)
                ):
                    filtered.remove(existing)
                    self._apply_confidence_adjustment(finding, signals)
                    seen_values[value_key] = finding
                    filtered.append(finding)
                continue

            # Adjust confidence based on signals
            self._apply_confidence_adjustment(finding, signals)

            seen_values[value_key] = finding
            filtered.append(finding)

        return filtered

    def _analyze_context(
        self,
        finding: Finding,
        ir: Optional[IntermediateRepresentation],
        source_content: str,
        is_test_file: bool,
    ) -> list[ContextSignal]:
        """Analyze context around a finding."""
        signals = []

        # Test file ??lower confidence
        if is_test_file:
            signals.append(ContextSignal(
                name="test_file",
                is_false_positive=False,
                confidence_adjustment=-0.5,
                reason="Finding is in a test/mock file",
            ))

        # Check variable name context
        var_signal = self._check_variable_context(
            finding, ir, source_content
        )
        if var_signal:
            signals.append(var_signal)

        # Check value pattern (non-secret structures)
        value_signal = self._check_value_pattern(finding.extracted_value)
        if value_signal:
            signals.append(value_signal)

        # Check surrounding line context
        line_signal = self._check_line_context(finding, source_content)
        if line_signal:
            signals.append(line_signal)

        return signals

    def _check_variable_context(
        self,
        finding: Finding,
        ir: Optional[IntermediateRepresentation],
        source_content: str,
    ) -> Optional[ContextSignal]:
        """Check if the value is assigned to a non-secret variable."""
        if not source_content or not finding.evidence.snippet:
            return None

        snippet = finding.evidence.snippet
        value_lower = finding.extracted_value.lower()

        # Look for assignment patterns: varName = "value" (anchor at closing quote)
        assign_pattern = re.compile(
            r'(?:const|let|var)\s+(\w+)\s*=\s*["\']' + re.escape(value_lower) + r'["\']',
            re.IGNORECASE,
        )
        match = assign_pattern.search(snippet)
        if match:
            var_name = match.group(1)
            # Check against non-secret variable names
            var_parts = set(p.lower() for p in re.split(r'[_\-]|(?<=[a-z])(?=[A-Z])', var_name) if p)
            for ns_name in self.NON_SECRET_VAR_NAMES:
                if ns_name in var_parts:
                    return ContextSignal(
                        name="non_secret_variable",
                        is_false_positive=True,
                        confidence_adjustment=-1.0,
                        reason=f"Assigned to non-secret variable: {var_name}",
                    )

        # Check object key context: { someKey: "value" } (anchor at closing quote)
        key_pattern = re.compile(
            r'(?:^|[{,])\s*["\']?(\w+)["\']?\s*:\s*["\']' + re.escape(value_lower) + r'["\']',
            re.IGNORECASE | re.MULTILINE,
        )
        match = key_pattern.search(snippet)
        if match:
            key_name = match.group(1)
            key_parts = set(p.lower() for p in re.split(r'[_\-]|(?<=[a-z])(?=[A-Z])', key_name) if p)
            for ns_name in self.NON_SECRET_VAR_NAMES:
                if ns_name in key_parts:
                    return ContextSignal(
                        name="non_secret_key",
                        is_false_positive=True,
                        confidence_adjustment=-1.0,
                        reason=f"Object key is non-secret type: {key_name}",
                    )

        return None

    def _check_value_pattern(
        self,
        value: str,
    ) -> Optional[ContextSignal]:
        """Check if the value matches non-secret patterns."""
        for pattern in self._compiled_value_patterns:
            if pattern.match(value):
                return ContextSignal(
                    name="non_secret_pattern",
                    is_false_positive=True,
                    confidence_adjustment=-1.0,
                    reason=f"Value matches non-secret pattern: {pattern.pattern}",
                )
        return None

    def _check_line_context(
        self,
        finding: Finding,
        source_content: str,
    ) -> Optional[ContextSignal]:
        """Check surrounding code for context clues."""
        if not source_content:
            return None

        lines = source_content.split("\n")
        line_idx = finding.evidence.line - 1

        if line_idx < 0 or line_idx >= len(lines):
            return None

        line = lines[line_idx].strip()

        # Check if line is a comment
        if line.startswith("//") or line.startswith("*") or line.startswith("/*"):
            return ContextSignal(
                name="comment",
                is_false_positive=True,
                confidence_adjustment=-1.0,
                reason="Value appears in a comment",
            )
        if self._is_line_in_block_comment(source_content, line_idx):
            return ContextSignal(
                name="block_comment",
                is_false_positive=True,
                confidence_adjustment=-1.0,
                reason="Value appears in a block comment",
            )

        if re.search(r"@example\b|\b(example|sample|demo)\s*:", line, re.IGNORECASE):
            return ContextSignal(
                name="example_line",
                is_false_positive=True,
                confidence_adjustment=-1.0,
                reason="Value appears in example/sample documentation context",
            )

        # Check for console.log/debug context (logged secrets = still a finding,
        # but if it's the FORMAT string, not the secret itself)
        if re.match(r'console\.\w+\s*\(', line):
            # Check if the value IS the log message (not a leaked secret)
            if "example" in line.lower() or "test" in line.lower():
                return ContextSignal(
                    name="debug_example",
                    is_false_positive=True,
                    confidence_adjustment=-1.0,
                    reason="Value is in example/test logging",
                )

        return None

    def _is_line_in_block_comment(self, source_content: str, line_idx: int) -> bool:
        """Return True when the 0-based line index falls inside a block comment."""
        if line_idx < 0:
            return False

        lines = source_content.split("\n")
        if line_idx >= len(lines):
            return False

        line_start_offsets: list[int] = []
        offset = 0
        for line in lines:
            line_start_offsets.append(offset)
            offset += len(line) + 1

        target_start = line_start_offsets[line_idx]
        target_end = target_start + len(lines[line_idx])

        for match in re.finditer(r"/\*[\s\S]*?\*/", source_content):
            if match.start() <= target_start and match.end() >= target_end:
                return True
        return False

    def _apply_confidence_adjustment(
        self,
        finding: Finding,
        signals: list[ContextSignal],
    ) -> None:
        """Adjust finding confidence based on signals."""
        total_adjustment = sum(s.confidence_adjustment for s in signals)

        if total_adjustment < -0.3:
            finding.confidence = Confidence.LOW
        elif total_adjustment > 0.3:
            finding.confidence = Confidence.HIGH

    def _is_test_file(self, file_url: str) -> bool:
        """Check if file is a test/mock file."""
        for pattern in self._compiled_test_patterns:
            if pattern.search(file_url):
                return True
        return False

