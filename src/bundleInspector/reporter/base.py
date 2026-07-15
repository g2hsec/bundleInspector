"""
Base reporter class.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path

from bundleInspector.storage.atomic import atomic_publish_text
from bundleInspector.storage.identifiers import is_portable_component
from bundleInspector.storage.models import Report


def mask_secret_findings(report: Report, visible_chars: int = 4) -> None:
    """Redact raw secret values from the WHOLE report IN PLACE so NO report format leaks a secret in
    clear text. Two passes: (1) mask each SECRET finding's own value and collect (raw -> masked);
    (2) sweep EVERY finding of ANY category -- extracted_value, evidence snippet, and metadata tree.
    A secret literally appears in a co-located NON-secret finding's snippet (e.g. an ENDPOINT
    `fetch(...Authorization: Bearer <secret>...)`), which a per-SECRET-only pass would leak.
    Idempotent."""
    from bundleInspector.reporter.redaction import sanitize_report_copy

    sanitized = sanitize_report_copy(
        report,
        visible_chars=visible_chars,
        include_raw_assets=True,
        honor_existing_mask=False,
    )
    # Preserve references to existing findings/assets for callers that hold them while still
    # replacing every report-level field with its sanitized value.
    for current_finding, replacement_finding in zip(
        report.findings,
        sanitized.findings,
        strict=True,
    ):
        for field_name in type(current_finding).model_fields:
            setattr(current_finding, field_name, getattr(replacement_finding, field_name))
    sanitized.findings = report.findings
    for current_asset, replacement_asset in zip(report.assets, sanitized.assets, strict=True):
        for field_name in type(current_asset).model_fields:
            setattr(current_asset, field_name, getattr(replacement_asset, field_name))
    sanitized.assets = report.assets
    for field_name in Report.model_fields:
        setattr(report, field_name, getattr(sanitized, field_name))


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
        output_path: Path | None = None,
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
            if is_portable_component(report.id):
                filename_token = report.id
            else:
                filename_token = hashlib.sha256(
                    report.id.encode("utf-8", "surrogatepass")
                ).hexdigest()
            output_path = Path(f"bundleInspector_report_{filename_token}{self.extension}")

        atomic_publish_text(output_path, content)

        return output_path
