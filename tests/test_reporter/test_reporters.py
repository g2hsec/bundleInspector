"""Tests for reporter output sanitization and source-map aware locations.

Secret-like values in this module are fake samples used to verify masking and
must not be treated as live credentials.
"""

import json

from bundleInspector.reporter.html_reporter import HTMLReporter
from bundleInspector.reporter.json_reporter import JSONReporter
from bundleInspector.reporter.sarif_reporter import SARIFReporter
from bundleInspector.reporter.wordlist_reporter import WordlistReporter
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


def test_sarif_reporter_ignores_non_positive_original_lines():
    """SARIF should fall back to the finding line when original source lines are invalid."""
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
            snippet_lines=(0, 0),
            original_file_url="src/app.ts",
            original_line=-1,
            original_column=4,
        ),
        extracted_value="/api/users",
        metadata={
            "original_snippet": 'const endpoint = "/api/users";',
            "original_snippet_lines": [0, 0],
        },
    )
    report = Report(findings=[finding])

    sarif = json.loads(SARIFReporter().generate(report))
    result = sarif["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]
    flow_location = result["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]

    assert location["region"]["startLine"] == 40
    assert flow_location["region"]["startLine"] == 40


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

    # All "<" escaped to <: no raw </script> or <script> can break out.
    assert "</script>" not in embedded_json
    assert "<script>" not in embedded_json
    assert "\\u003c" in embedded_json
    assert "secret raw content" not in embedded_json
    data = json.loads(embedded_json)  # < is valid JSON, decodes back to "<"
    assert data["findings"][0]["extracted_value"] == '</script><script>alert(1)</script>'
    assert "content" not in data["assets"][0]


def test_html_reporter_escapes_script_end_tag_case_insensitively():
    """Embedded JSON should escape mixed-case script end tags as well."""
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
                    snippet='fetch("</SCRIPT>")',
                ),
                extracted_value='</SCRIPT>',
            )
        ],
    )

    html = HTMLReporter().generate(report)
    embedded_json = html.split('<script id="bundleInspector-report-data" type="application/json">', 1)[1].split("</script>", 1)[0]

    # Every "<" is escaped to its JSON unicode escape, so no </script variant (any case,
    # any following char) can break out of the embedded <script> block.
    assert "</SCRIPT>" not in embedded_json
    assert "<" not in embedded_json
    assert "\\u003c/SCRIPT>" in embedded_json


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

    # both the minified location and the source-mapped original location are shown
    assert "https://example.com/static/app.js:40" in html
    assert "src/app.ts:12" in html
    # the source-mapped original snippet is rendered under its own caption (escaped)
    assert "ORIGINAL SOURCE" in html
    assert 'const endpoint = &#34;/api/users&#34;;' in html


def test_html_reporter_demotes_and_labels_noise_findings():
    """Likely-FP / vendor findings are demoted (sorted last), dimmed, badged, and hideable via the
    noise toggle -- never dropped. A real finding sorts before a noise one."""
    real = Finding(
        rule_id="sink-detector", category=Category.SINK, severity=Severity.HIGH,
        confidence=Confidence.MEDIUM, title="Real sink",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=10),
        extracted_value=".html()", value_type="dom_html_sink",
    )
    noise = Finding(
        rule_id="secret-detector", category=Category.SECRET, severity=Severity.MEDIUM,
        confidence=Confidence.LOW, title="Vendor secret",
        evidence=Evidence(file_url="https://x/jquery.min.js", file_hash="h", line=2),
        extracted_value="regexnoise", value_type="potential_secret",
        metadata={"third_party_file": "jquery", "likely_fp": True,
                  "fp_reason": "third-party library file (jquery)"},
    )
    html = HTMLReporter().generate(Report(findings=[noise, real]))  # noise passed first...
    assert 'data-noise="1"' in html and "LIKELY FP" in html
    assert "toggleNoise" in html and "Hide vendor" in html
    assert "Demoted, not dropped" in html
    # ...but the real finding must render BEFORE the noise finding (noise sinks to the bottom)
    assert html.index("Real sink") < html.index("Vendor secret")


def test_html_reporter_hides_noise_by_default_with_banner():
    """Noise (vendor / likely-FP) is HIDDEN by default so the FP reduction is visible; a banner
    states the counts and the toggle can reveal it (findings stay in the report)."""
    real = Finding(
        rule_id="sink-detector", category=Category.SINK, severity=Severity.HIGH,
        confidence=Confidence.MEDIUM, title="Real sink",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=10),
        extracted_value=".html()", value_type="dom_html_sink",
    )
    noise = Finding(
        rule_id="secret-detector", category=Category.SECRET, severity=Severity.MEDIUM,
        confidence=Confidence.LOW, title="Vendor secret",
        evidence=Evidence(file_url="https://x/jquery.min.js", file_hash="h", line=2),
        extracted_value="regexnoise", value_type="potential_secret",
        metadata={"third_party_file": "jquery", "likely_fp": True, "fp_reason": "vendor"},
    )
    html = HTMLReporter().generate(Report(findings=[real, noise]))
    assert "hideNoise = true" in html          # default view hides noise
    assert "noise-banner" in html and "hidden by default" in html
    assert 'data-noise="1"' in html            # the noise finding is still present (recoverable)


def test_html_reporter_never_demotes_confirmed_flow_even_in_vendor_file():
    """INVARIANT: a CONFIRMED source->sink taint flow must never be treated as noise, even when it
    lives in a vendor-classified file (third_party_file set)."""
    confirmed = Finding(
        rule_id="taint", category=Category.SINK, severity=Severity.HIGH,
        confidence=Confidence.HIGH, title="Confirmed flow in vendor bundle",
        evidence=Evidence(file_url="https://x/assets/jquery.min.js", file_hash="h", line=9),
        extracted_value=".html()", value_type="taint_flow",
        metadata={"confirmed": True, "third_party_file": "jquery",
                  "sink_source": "location.hash", "sink": ".html()"},
    )
    html = HTMLReporter().generate(Report(findings=[confirmed]))
    # rendered as a normal finding, not demoted: data-noise=0 and no LIKELY FP badge
    assert 'data-noise="0"' in html
    assert "LIKELY FP" not in html


def test_html_reporter_surfaces_the_dangerous_field():
    """A sink finding names the actual value that reaches the sink (WHERE it is vulnerable)."""
    finding = Finding(
        rule_id="sink-detector", category=Category.SINK, severity=Severity.HIGH,
        confidence=Confidence.MEDIUM, title="html attr injection",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=1),
        extracted_value="html src= injection", value_type="dom_attr_injection",
        metadata={"sink_source": "item.image_url", "sink_attr": "src"},
    )
    html = HTMLReporter().generate(Report(findings=[finding]))
    assert "DANGEROUS VALUE" in html and "item.image_url" in html


def test_html_reporter_does_not_leak_raw_secret_via_matched_text():
    """The raw secret must not survive anywhere in the HTML -- including metadata.matched_text,
    which is embedded verbatim in the report JSON. mask_secret_findings sweeps the whole tree."""
    secret = "abcdefghijklmnopqrstuvwxyz123456"
    finding = Finding(
        rule_id="secret-detector",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        title="Hardcoded Session Token",
        evidence=Evidence(
            file_url="https://example.com/static/app.js", file_hash="h", line=12,
            snippet=f'const authorization = "Bearer {secret}";',
        ),
        extracted_value=secret,
        metadata={"matched_text": f'authorization = "Bearer {secret}"'},
    )
    html = HTMLReporter().generate(Report(findings=[finding]))
    assert secret not in html


def test_html_reporter_shows_distinct_matched_text_when_value_is_captured():
    """HTML reports should show the original matched text when it differs from the extracted value."""
    finding = Finding(
        rule_id="secret-detector",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        title="Hardcoded Session Token",
        evidence=Evidence(
            file_url="https://example.com/static/app.js",
            file_hash="hash-secret",
            line=12,
            column=4,
            snippet='const authorization = "Bearer abcdefghijklmnopqrstuvwxyz123456";',
        ),
        extracted_value="abcdefghijklmnopqrstuvwxyz123456",
        metadata={
            "matched_text": 'authorization = "Bearer abcdefghijklmnopqrstuvwxyz123456"',
        },
    )
    report = Report(findings=[finding])

    html = HTMLReporter().generate(report)

    # The finding is surfaced by highlighting the matched region inside the code snippet, so the
    # reader sees exactly what in the code triggered it -- and for a secret the value is MASKED
    # (never shown raw) while the surrounding context (the assigned variable) stays visible.
    assert "<mark>authorization = &quot;Bearer abcd" in html   # matched region highlighted
    assert "3456&quot;</mark>" in html                         # ...ending on the masked value


def test_wordlist_reporter_params_only_uses_endpoint_snippets():
    """Parameter wordlists should not harvest names from non-endpoint findings."""
    report = Report(
        findings=[
            Finding(
                rule_id="secret-detector",
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Secret",
                evidence=Evidence(
                    file_url="file:///bundle.js",
                    file_hash="hash-secret",
                    line=1,
                    column=0,
                    snippet="{ userId: 1, accountId: 2 }",
                ),
                extracted_value="Bearer token",
            ),
            Finding(
                rule_id="endpoint-detector",
                category=Category.ENDPOINT,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Endpoint",
                evidence=Evidence(
                    file_url="file:///bundle.js",
                    file_hash="hash-endpoint",
                    line=2,
                    column=0,
                    snippet='fetch("/api/users?teamId=1")',
                ),
                extracted_value="/api/users?teamId=1",
            ),
        ]
    )

    params = WordlistReporter(mode="params").generate(report).splitlines()

    assert "teamId" in params
    assert "userId" not in params
    assert "accountId" not in params

