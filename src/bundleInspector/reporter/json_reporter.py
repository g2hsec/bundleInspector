"""
JSON report generator.
"""

from __future__ import annotations

import json
from typing import Any

from bundleInspector.reporter.base import BaseReporter
from bundleInspector.storage.models import Report, Category


class JSONReporter(BaseReporter):
    """Generate JSON reports."""

    name = "json"
    extension = ".json"

    def __init__(
        self,
        indent: int = 2,
        include_raw: bool = False,
        mask_secrets: bool = True,
    ):
        self.indent = indent
        self.include_raw = include_raw
        self.mask_secrets = mask_secrets

    def generate(self, report: Report) -> str:
        """Generate JSON report."""
        # Compute summary
        report.compute_summary()

        # Convert to dict
        data = report.model_dump(
            mode="json",
            exclude_none=True,
        )

        # Remove raw asset payloads unless explicitly requested
        if not self.include_raw:
            for asset in data.get("assets", []):
                asset.pop("content", None)
                asset.pop("sourcemap_content", None)

        for finding in data.get("findings", []):
            self._prefer_original_evidence(finding)

        # Security: Mask or remove secret values from findings
        if self.mask_secrets:
            for finding in data.get("findings", []):
                if finding.get("category") == Category.SECRET.value:
                    self._mask_secret_finding(finding)

        return json.dumps(data, indent=self.indent, ensure_ascii=False)

    def _prefer_original_evidence(self, finding: dict[str, Any]) -> None:
        """Replace normalized evidence with source-map-backed original evidence when available."""
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            return

        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            finding["metadata"] = metadata

        original_file_url = evidence.get("original_file_url")
        original_line = evidence.get("original_line")
        original_column = evidence.get("original_column")
        original_snippet = metadata.get("original_snippet")
        original_snippet_lines = metadata.get("original_snippet_lines")

        if not any([original_file_url, original_line, original_snippet]):
            return

        metadata.setdefault(
            "normalized_evidence",
            {
                "file_url": evidence.get("file_url"),
                "line": evidence.get("line"),
                "column": evidence.get("column"),
                "snippet": evidence.get("snippet"),
                "snippet_lines": evidence.get("snippet_lines"),
            },
        )

        if original_file_url:
            evidence["file_url"] = original_file_url
        if original_line:
            evidence["line"] = original_line
        if original_column is not None:
            evidence["column"] = original_column
        if original_snippet:
            evidence["snippet"] = original_snippet
        if original_snippet_lines:
            evidence["snippet_lines"] = original_snippet_lines

    def _mask_secret_finding(self, finding: dict[str, Any]) -> None:
        """Mask secret values in the main finding payload and attached metadata."""
        raw_value = finding.get("extracted_value", "")
        masked_value = finding.get("masked_value") or self._mask_value(raw_value)
        finding["extracted_value"] = masked_value

        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            return

        masked_fields = metadata.get("masked_fields")
        field_overrides = masked_fields if isinstance(masked_fields, dict) else {}
        metadata["extracted_fields"] = self._mask_nested_value(
            metadata.get("extracted_fields"),
            raw_value,
            masked_value,
            field_overrides,
        )
        finding["metadata"] = self._mask_nested_value(
            metadata,
            raw_value,
            masked_value,
            field_overrides,
        )

    def _mask_nested_value(
        self,
        value: Any,
        raw_value: str,
        masked_value: str,
        field_overrides: dict[str, Any],
    ) -> Any:
        """Recursively replace secret-like metadata values with masked values."""
        if isinstance(value, dict):
            masked_dict = {}
            for key, item in value.items():
                if key in field_overrides:
                    masked_dict[key] = field_overrides[key]
                else:
                    masked_dict[key] = self._mask_nested_value(
                        item,
                        raw_value,
                        masked_value,
                        field_overrides,
                    )
            return masked_dict
        if isinstance(value, list):
            return [
                self._mask_nested_value(item, raw_value, masked_value, field_overrides)
                for item in value
            ]
        if isinstance(value, str) and raw_value and value == raw_value:
            return masked_value
        return value

    def _mask_value(self, value: str) -> str:
        """Fallback masking for a secret string."""
        if len(value) > 8:
            return value[:4] + "*" * (len(value) - 8) + value[-4:]
        return "*" * len(value)


class CompactJSONReporter(JSONReporter):
    """Generate compact JSON reports."""

    name = "json_compact"

    def __init__(self):
        super().__init__(indent=None, include_raw=False)

