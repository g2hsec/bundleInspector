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


def test_template_and_concrete_id_merge_into_one_route():
    """A template-param route (`/users/${uid}`) and a concrete-id instance (`/users/42`) map to ONE
    canonical `/users/{id}` node, not two siblings that double-count the endpoint."""
    from bundleInspector.correlator.api_map import build_api_map
    from bundleInspector.storage.models import (
        Category,
        Confidence,
        Evidence,
        Finding,
        Report,
        Severity,
    )

    def _ep(v, m):
        return Finding(
            rule_id="r",
            category=Category.ENDPOINT,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            title="t",
            evidence=Evidence(file_url="f", file_hash="h", line=1),
            extracted_value=v,
            value_type="api_path",
            metadata={"method": m},
        )

    res = build_api_map(Report(findings=[_ep("/users/42", "GET"), _ep("/users/${uid}", "POST")]))
    assert sum(dom.total_endpoints for dom in res.domains.values()) == 1
