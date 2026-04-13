"""Tests for API map output."""

from bundleInspector.correlator.api_map import APIMapBuilder
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Report,
    Severity,
)


def _endpoint_finding(url: str, value: str) -> Finding:
    return Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=url,
            file_hash=f"hash-{abs(hash((url, value)))}",
            line=1,
            column=0,
        ),
        extracted_value=value,
    )


def test_api_map_tree_uses_box_drawing_connectors():
    report = Report(
        findings=[
            _endpoint_finding("https://example.com/app.js", "https://api.example.com/api/users"),
            _endpoint_finding("https://example.com/app.js", "https://api.example.com/health"),
        ]
    )

    builder = APIMapBuilder()
    builder.build(report)
    tree = builder.to_tree_string()

    assert "├── " in tree
    assert "└── " in tree
    assert "health" in tree
    assert "users" in tree
    assert "戌" not in tree
    assert "戍" not in tree
