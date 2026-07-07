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
        metadata = finding.metadata or {}
        snippet = metadata.get("original_snippet")
        if isinstance(snippet, str):
            metadata["original_snippet"] = snippet.replace(raw, masked)
        normalized = metadata.get("normalized_evidence")
        if isinstance(normalized, dict) and isinstance(normalized.get("snippet"), str):
            normalized["snippet"] = normalized["snippet"].replace(raw, masked)


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

