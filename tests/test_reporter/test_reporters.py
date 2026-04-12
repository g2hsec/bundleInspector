"""Tests for reporter output sanitization and source-map aware locations.

Secret-like values in this module are fake samples used to verify masking and
must not be treated as live credentials.
"""

import json

from bundleInspector.reporter.html_reporter import HTMLReporter
from bundleInspector.reporter.json_reporter import JSONReporter
from bundleInspector.reporter.sarif_reporter import SARIFReporter
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    JSAsset,
    Report,
    Severity,
)


def test_json_reporter_masks_secret_metadata_fields():
    """JSON reports should not leak raw secret values through metadata fields."""
    secret = "Bearer ABCDEFGHIJKLMNOPQRSTUVWX123456"
    finding = Finding(
        rule_id="custom-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="hash-secret",
            line=1,
            column=0,
            snippet='headers.Authorization = "Bearer ..."',
        ),
        extracted_value=secret,
        value_type="secret_value",
        metadata={
            "extracted_fields": {
                "secret_type": "bearer_token",
                "secret_value": secret,
            },
            "masked_fields": {
                "secret_value": "Bearer**************************3456",
            },
        },
    )
    finding.mask_value()
    report = Report(findings=[finding])

    data = json.loads(JSONReporter().generate(report))
    finding_data = data["findings"][0]

    assert finding_data["extracted_value"] == finding.masked_value
    assert finding_data["metadata"]["extracted_fields"]["secret_value"] == "Bearer**************************3456"
    assert secret not in json.dumps(finding_data)


def test_sarif_reporter_prefers_original_source_location():
    """SARIF should emit original source-map-backed locations when available."""
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url="https://example.com/static/app.js",
            file_hash="hash-endpoint",
            line=40,
            column=2,
            snippet='fetch("/api/users")',
            snippet_lines=(39, 41),
            original_file_url="src/app.ts",
            original_line=12,
            original_column=4,
        ),
        extracted_value="/api/users",
        metadata={
            "original_snippet": 'const endpoint = "/api/users";',
            "original_snippet_lines": [11, 13],
        },
    )
    report = Report(findings=[finding])

    sarif = json.loads(SARIFReporter().generate(report))
    result = sarif["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    related = result["relatedLocations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == "src/app.ts"
    assert location["region"]["startLine"] == 12
    assert location["region"]["startColumn"] == 5
    assert location["region"]["snippet"]["text"] == 'const endpoint = "/api/users";'
    assert related["artifactLocation"]["uri"] == "https://example.com/static/app.js"


def test_json_reporter_prefers_original_source_location():
    """JSON should emit original source-map-backed evidence while preserving normalized metadata."""
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url="https://example.com/static/app.js",
            file_hash="hash-endpoint",
            line=40,
            column=2,
            snippet='fetch("/api/users")',
            snippet_lines=(39, 41),
            original_file_url="src/app.ts",
            original_line=12,
            original_column=4,
        ),
        extracted_value="/api/users",
        metadata={
            "original_snippet": 'const endpoint = "/api/users";',
            "original_snippet_lines": [11, 13],
        },
    )
    report = Report(findings=[finding])

    data = json.loads(JSONReporter().generate(report))
    finding_data = data["findings"][0]

    assert finding_data["evidence"]["file_url"] == "src/app.ts"
    assert finding_data["evidence"]["line"] == 12
    assert finding_data["evidence"]["column"] == 4
    assert finding_data["evidence"]["snippet"] == 'const endpoint = "/api/users";'
    assert finding_data["metadata"]["normalized_evidence"]["file_url"] == "https://example.com/static/app.js"


def test_json_reporter_can_include_raw_asset_content():
    """JSON include_raw should preserve stored asset payloads for explicit debugging use."""
    report = Report(
        assets=[
            JSAsset(
                url="file:///bundle.js",
                content_hash="hash-bundle",
                content=b'console.log("x")',
            )
        ]
    )

    data = json.loads(JSONReporter(include_raw=True).generate(report))

    assert data["assets"][0]["content"]


def test_html_reporter_embeds_machine_readable_json_without_raw_asset_content():
    """HTML should embed safe machine-readable JSON without leaking raw asset bytes."""
    report = Report(
        findings=[
            Finding(
                rule_id="endpoint-detector",
                category=Category.ENDPOINT,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Endpoint",
                evidence=Evidence(
                    file_url="https://example.com/static/app.js",
                    file_hash="hash-endpoint",
                    line=12,
                    column=2,
                    snippet='fetch("</script><script>alert(1)</script>")',
                ),
                extracted_value='</script><script>alert(1)</script>',
            )
        ],
        assets=[
            JSAsset(
                url="file:///bundle.js",
                content_hash="hash-bundle",
                content=b'console.log("secret raw content")',
            )
        ],
    )

    html = HTMLReporter().generate(report)
    embedded_json = html.split('<script id="bundleInspector-report-data" type="application/json">', 1)[1].split("</script>", 1)[0]

    assert '<\\/script><script>alert(1)<\\/script>' in embedded_json
    assert "secret raw content" not in embedded_json
    data = json.loads(embedded_json.replace("<\\/script>", "</script>"))
    assert data["findings"][0]["extracted_value"] == '</script><script>alert(1)</script>'
    assert "content" not in data["assets"][0]


def test_html_reporter_shows_original_source_location_and_snippet():
    """HTML should render original source-map-backed location and snippet details."""
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url="https://example.com/static/app.js",
            file_hash="hash-endpoint",
            line=40,
            column=2,
            snippet='fetch("/api/users")',
            snippet_lines=(39, 41),
            original_file_url="src/app.ts",
            original_line=12,
            original_column=4,
        ),
        extracted_value="/api/users",
        metadata={
            "original_snippet": 'const endpoint = "/api/users";',
            "original_snippet_lines": [11, 13],
        },
    )
    report = Report(findings=[finding])

    html = HTMLReporter().generate(report)

    assert "<strong>Location:</strong> https://example.com/static/app.js:40" in html
    assert "<strong>Original:</strong>" in html
    assert "src/app.ts:12" in html
    assert "Original Source Snippet" in html
    assert 'const endpoint = &#34;/api/users&#34;;' in html

