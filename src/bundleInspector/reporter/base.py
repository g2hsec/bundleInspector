"""
Base reporter class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from bundleInspector.storage.models import Category, Report


def mask_secret_findings(report: Report, visible_chars: int = 4) -> None:
    """Redact raw secret values from SECRET findings IN PLACE so NO report format leaks the
    secret in clear text: masks extracted_value, the evidence snippet (the source line that
    literally contains the secret), and snippet-bearing metadata. Idempotent."""
    for finding in report.findings:
        if finding.category != Category.SECRET:
            continue
        raw = finding.extracted_value
        if not raw:
            continue
        masked = finding.masked_value or finding.mask_value(visible_chars)
        finding.extracted_value = masked
        finding.masked_value = masked
        if finding.evidence is not None and finding.evidence.snippet:
            finding.evidence.snippet = finding.evidence.snippet.replace(raw, masked)
        # Sweep the whole metadata tree: the raw secret can hide in matched_text, original_snippet,
        # normalized_evidence.snippet, extracted_fields.*, etc. -- redact every string so no report
        # format (incl. the HTML report's embedded JSON) can leak it. Per-field handling missed
        # matched_text.
        _redact_raw_in_tree(finding.metadata, raw, masked)


def _redact_raw_in_tree(obj: object, raw: str, masked: str) -> None:
    """Recursively replace every occurrence of `raw` with `masked` in all strings inside a
    metadata dict/list, in place."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, str):
                if raw in val:
                    obj[key] = val.replace(raw, masked)
            elif isinstance(val, (dict, list)):
                _redact_raw_in_tree(val, raw, masked)
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            if isinstance(val, str):
                if raw in val:
                    obj[i] = val.replace(raw, masked)
            elif isinstance(val, (dict, list)):
                _redact_raw_in_tree(val, raw, masked)


class BaseReporter(ABC):
    """Abstract base class for reporters."""

    name: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def generate(self, report: Report) -> str:
        """
        Generate report content.

        Args:
            report: Report to generate

        Returns:
            Report content as string
        """
        pass

    async def write(
        self,
        report: Report,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Write report to file.

        Args:
            report: Report to write
            output_path: Output file path

        Returns:
            Path to written file
        """
        content = self.generate(report)

        if output_path is None:
            output_path = Path(f"bundleInspector_report_{report.id[:8]}{self.extension}")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

        return output_path

