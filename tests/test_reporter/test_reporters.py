"""Tests for reporter output sanitization and source-map aware locations.

Secret-like values in this module are fake samples used to verify masking and
must not be treated as live credentials.
"""

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from bundleInspector.cli import _build_reporter
from bundleInspector.config import AuthConfig, Config, RuleConfig
from bundleInspector.reporter.html_reporter import HTMLReporter
from bundleInspector.reporter.json_reporter import JSONReporter
from bundleInspector.reporter.redaction import sanitize_report_copy
from bundleInspector.reporter.sarif_reporter import SARIFReporter
from bundleInspector.reporter.wordlist_reporter import WordlistReporter
from bundleInspector.storage.atomic import UnsafePathError
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    JSAsset,
    Report,
    Severity,
)


async def test_default_report_path_hashes_nonportable_ids_without_traversal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report = Report(id="../../escaped-report")
    expected_token = hashlib.sha256(report.id.encode("utf-8")).hexdigest()
    monkeypatch.chdir(tmp_path)

    output_path = await JSONReporter().write(report)

    assert output_path == Path(f"bundleInspector_report_{expected_token}.json")
    assert output_path.resolve().parent == tmp_path.resolve()
    assert output_path.is_file()
    assert not (tmp_path.parent / "escaped-report.json").exists()


async def test_default_report_path_hashes_case_aliases_and_windows_device_names(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    for identifier in ("Mixed-Case", "con", "nul.txt"):
        expected_token = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        assert len(expected_token) == 64
        output_path = await JSONReporter().write(Report(id=identifier))
        assert output_path.name == f"bundleInspector_report_{expected_token}.json"
        assert output_path.resolve().parent == tmp_path.resolve()


async def test_default_report_path_preserves_full_portable_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    output_path = await JSONReporter().write(Report(id="report-123456"))

    assert output_path == Path("bundleInspector_report_report-123456.json")
    assert not list(tmp_path.glob(".bundleinspector-lock-*"))
    assert not list(tmp_path.glob("*.tmp"))


async def test_default_report_paths_do_not_collide_on_a_shared_eight_character_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    first = Report(id="report-123456")
    second = Report(id="report-198765")
    assert first.id[:8] == second.id[:8]

    first_path = await JSONReporter().write(first)
    second_path = await JSONReporter().write(second)

    assert first_path != second_path
    assert json.loads(first_path.read_text(encoding="utf-8"))["id"] == first.id
    assert json.loads(second_path.read_text(encoding="utf-8"))["id"] == second.id


async def test_explicit_report_path_is_unchanged_for_nonportable_report_id(
    tmp_path: Path,
) -> None:
    explicit_path = tmp_path / "chosen" / "report.json"

    output_path = await JSONReporter().write(
        Report(id="../../nonportable"),
        output_path=explicit_path,
    )

    assert output_path == explicit_path
    assert explicit_path.is_file()


async def test_explicit_report_path_rejects_a_symbolic_link_destination(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("outside", encoding="utf-8")
    destination = tmp_path / "report.json"
    try:
        destination.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        await JSONReporter().write(Report(id="safe-report"), output_path=destination)

    assert outside.read_text(encoding="utf-8") == "outside"


async def test_explicit_report_path_rejects_a_hard_link_destination(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("outside", encoding="utf-8")
    destination = tmp_path / "report.json"
    try:
        os.link(outside, destination)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        await JSONReporter().write(Report(id="safe-report"), output_path=destination)

    assert outside.read_text(encoding="utf-8") == "outside"


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


def test_zero_visible_chars_masks_entire_secret_in_all_reporters() -> None:
    secret = "ZERO_VISIBLE_SECRET_0123456789"
    finding = Finding(
        rule_id="zero-visible-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Zero visible secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="hash-zero-visible",
            line=1,
            column=0,
            snippet=f'const token = "{secret}";',
        ),
        extracted_value=secret,
        value_type="secret_value",
    )

    masked_finding = finding.model_copy(deep=True)
    assert masked_finding.mask_value(0) == "*" * len(secret)

    reporters = (
        JSONReporter(secret_visible_chars=0),
        HTMLReporter(secret_visible_chars=0),
        SARIFReporter(secret_visible_chars=0),
    )
    for reporter in reporters:
        report = Report(findings=[finding.model_copy(deep=True)])
        rendered = reporter.generate(report)
        assert secret not in rendered
        assert "*" * len(secret) in rendered


@pytest.mark.parametrize(
    "reporter",
    (
        JSONReporter(secret_visible_chars=2),
        HTMLReporter(secret_visible_chars=2),
        SARIFReporter(secret_visible_chars=2),
    ),
    ids=("json", "html", "sarif"),
)
def test_reporters_override_precomputed_mask_without_mutating_input(reporter) -> None:
    secret = "PREMASKED_REPORTER_SECRET_0123456789"
    finding = Finding(
        rule_id="pre-masked-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Pre-masked secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="hash-pre-masked",
            line=1,
            snippet=f'const token = "{secret}";',
        ),
        extracted_value=secret,
    )
    old_mask = finding.mask_value(4)
    expected = secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    report = Report(findings=[finding])
    before = report.model_dump(mode="python")

    rendered = reporter.generate(report)

    assert secret not in rendered
    assert expected in rendered
    assert old_mask not in rendered
    assert report.model_dump(mode="python") == before


@pytest.mark.parametrize(
    "reporter",
    (
        JSONReporter(mask_secrets=False),
        HTMLReporter(mask_secrets=False),
        SARIFReporter(mask_secrets=False),
    ),
    ids=("json", "html", "sarif"),
)
def test_mask_off_reporters_do_not_mutate_input(reporter) -> None:
    secret = "MASK_OFF_PRIVATE_SECRET_0123456789"
    finding = Finding(
        rule_id="mask-off-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Mask-off secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="h",
            line=1,
            snippet=f'const token = "{secret}";',
        ),
        extracted_value=secret,
    )
    report = Report(findings=[finding])
    before = report.model_dump(mode="python")

    reporter.generate(report)

    assert report.model_dump(mode="python") == before


@pytest.mark.parametrize(
    "reporter",
    (
        JSONReporter(secret_visible_chars=0),
        HTMLReporter(secret_visible_chars=0),
        SARIFReporter(secret_visible_chars=0),
    ),
    ids=("json", "html", "sarif"),
)
def test_zero_visible_chars_fully_masks_custom_rule_metadata(reporter) -> None:
    secret = "LEAKPX_PRIVATE_SECRET_9X7Q"
    explicit_mask = "LEAKPX" + "*" * (len(secret) - 10) + "9X7Q"
    finding = Finding(
        rule_id="metadata-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Metadata secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="h",
            line=1,
            snippet=f'const token = "{secret}";',
        ),
        extracted_value=secret,
        metadata={
            "extracted_fields": {"secret_value": secret},
            "masked_fields": {"secret_value": explicit_mask},
        },
    )
    finding.mask_value(4)

    rendered = reporter.generate(Report(findings=[finding]))

    assert secret not in rendered
    assert explicit_mask not in rendered
    assert "LEAKPX" not in rendered
    assert "9X7Q" not in rendered
    assert "*" * len(secret) in rendered


def test_storage_sanitization_preserves_existing_mask_by_default() -> None:
    secret = "STORAGE_ZERO_VISIBLE_SECRET_012345"
    finding = Finding(
        rule_id="stored-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Stored secret",
        evidence=Evidence(file_url="file:///bundle.js", file_hash="h", line=1),
        extracted_value=secret,
    )
    stored_mask = finding.mask_value(0)

    sanitized = sanitize_report_copy(Report(findings=[finding]))

    assert sanitized.findings[0].extracted_value == stored_mask
    assert sanitized.findings[0].masked_value == stored_mask


def test_json_reporter_honors_non_default_visible_chars() -> None:
    secret = "CONFIGURED_VISIBLE_SECRET_0123456789"
    finding = Finding(
        rule_id="configured-visible-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Configured visible secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="hash-configured-visible",
            line=1,
            column=0,
            snippet=f'const token = "{secret}";',
        ),
        extracted_value=secret,
        value_type="secret_value",
    )

    rendered = json.loads(
        JSONReporter(secret_visible_chars=2).generate(Report(findings=[finding]))
    )

    assert rendered["findings"][0]["extracted_value"] == (
        secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    )
    assert secret not in json.dumps(rendered)


def test_html_reporter_honors_non_default_visible_chars() -> None:
    secret = "HTML_VISIBLE_SECRET_0123456789"
    finding = Finding(
        rule_id="html-visible-secret",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="HTML configured visible secret",
        evidence=Evidence(
            file_url="file:///bundle.js",
            file_hash="hash-html-visible",
            line=1,
            column=0,
            snippet=f'const token = "{secret}";',
        ),
        extracted_value=secret,
        value_type="secret_value",
    )
    expected = secret[:2] + "*" * (len(secret) - 4) + secret[-2:]

    rendered = HTMLReporter(secret_visible_chars=2).generate(
        Report(findings=[finding])
    )

    assert expected in rendered
    assert secret not in rendered


def test_cli_json_reporter_receives_secret_visible_chars() -> None:
    reporter = _build_reporter(Config(rules=RuleConfig(secret_visible_chars=0)))

    assert isinstance(reporter, JSONReporter)
    assert reporter.secret_visible_chars == 0


@pytest.mark.parametrize(
    "cookies",
    (
        {"bad\rname": "value"},
        {"session": "bad\nvalue"},
        {"session": "bad\x00value"},
    ),
)
def test_auth_config_rejects_cookie_control_characters(cookies: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="Invalid characters in cookie"):
        AuthConfig(cookies=cookies)


@pytest.mark.parametrize("cookies", ({"": "value"}, {"   ": "value"}))
def test_auth_config_rejects_empty_cookie_names(cookies: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="Empty cookie name"):
        AuthConfig(cookies=cookies)


def test_auth_config_invalid_assignment_rolls_back_every_auth_field() -> None:
    auth = AuthConfig(
        cookies={"session": "valid"},
        headers={"X-Test": "valid"},
        bearer_token="valid-token",
        basic_auth=("valid-user", "valid-password"),
    )
    invalid_assignments = (
        ("cookies", {"bad\nname": "value"}),
        ("headers", {"X-Test": "bad\rvalue"}),
        ("bearer_token", "bad\x00token"),
        ("basic_auth", ("valid-user", "bad\npassword")),
    )

    for field_name, invalid_value in invalid_assignments:
        before = auth.model_dump(mode="python")
        with pytest.raises(ValueError):
            setattr(auth, field_name, invalid_value)
        assert auth.model_dump(mode="python") == before


def test_auth_config_revalidates_in_place_mapping_mutation_before_transport() -> None:
    cookie_auth = AuthConfig(cookies={"session": "valid"})
    cookie_auth.cookies["bad\nname"] = "value"
    with pytest.raises(ValueError, match="Invalid characters in cookie"):
        cookie_auth.get_auth_headers()

    header_auth = AuthConfig(headers={"X-Test": "valid"})
    header_auth.headers["X-Test"] = "bad\rvalue"
    with pytest.raises(ValueError, match="Invalid characters in header"):
        header_auth.get_auth_headers()

    valid_auth = AuthConfig()
    valid_auth.cookies["session"] = "valid"
    valid_auth.headers["X-Test"] = "valid"
    assert valid_auth.get_auth_headers() == {"X-Test": "valid"}


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


def test_sarif_reporter_defines_every_mapped_rule_id():
    """Every ruleId that _get_rule_id can emit MUST be defined in tool.driver.rules -- otherwise the
    SARIF references an undefined rule and GitHub Code Scanning drops the result. Guards the whole
    category->id map (not just SINK/UPLOAD) so this class of gap cannot be reintroduced."""
    reporter = SARIFReporter()
    defined_ids = {r["id"] for r in reporter._generate_rules()}
    for category in Category:
        stub = Finding(
            rule_id="x", category=category, severity=Severity.HIGH,
            confidence=Confidence.HIGH, title="t",
            evidence=Evidence(file_url="f", file_hash="h", line=1),
            extracted_value="x",
        )
        rid = reporter._get_rule_id(stub)
        assert rid in defined_ids, f"category {category} -> ruleId {rid} has no rule definition"


def test_sarif_reporter_defines_sink_and_upload_rules():
    """SINK (DOM-XSS) and UPLOAD findings -- the highest-value results -- must serialize to VALID
    SARIF: their ruleId resolves to a defined rule with the expected level and CWE tag."""
    sink = Finding(
        rule_id="taint", category=Category.SINK, severity=Severity.HIGH,
        confidence=Confidence.HIGH, title="Confirmed DOM-XSS",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=10),
        extracted_value=".html()", value_type="taint_flow",
    )
    upload = Finding(
        rule_id="upload-detector", category=Category.UPLOAD, severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM, title="Client-side upload validation",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=20),
        extracted_value="allowedExt", value_type="client_side_file_validation",
    )
    sarif = json.loads(SARIFReporter().generate(Report(findings=[sink, upload])))
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    result_ids = {res["ruleId"] for res in sarif["runs"][0]["results"]}

    assert result_ids == {"JSFINDER006", "JSFINDER007"}
    assert result_ids <= set(rules)  # every referenced rule is defined
    assert rules["JSFINDER006"]["defaultConfiguration"]["level"] == "error"
    assert "CWE-79" in rules["JSFINDER006"]["properties"]["tags"]
    assert rules["JSFINDER007"]["defaultConfiguration"]["level"] == "warning"
    assert "CWE-434" in rules["JSFINDER007"]["properties"]["tags"]


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


def test_html_reporter_shows_download_surface_badge_and_risk():
    """A file-download endpoint gets a DOWNLOAD badge, the specific risk, and the dangerous param."""
    from bundleInspector.core.download_surface import annotate_download_surfaces
    ep = Finding(
        rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.LOW,
        confidence=Confidence.MEDIUM, title="API Endpoint: /getFile.do",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=1),
        extracted_value="/getFile.do?fileNm=report.pdf", value_type="api_path", metadata={},
    )
    r = Report(findings=[ep])
    assert annotate_download_surfaces(r) == 1
    html = HTMLReporter().generate(r)
    assert "badge download" in html and "DOWNLOAD: path-traversal" in html
    assert "download-note" in html and "fileNm" in html


def test_html_severity_split_is_consistent_with_the_noise_demotion():
    """The severity distribution must MATCH the (noise-hidden) findings view: a demoted vendor
    CRITICAL must count as demoted, not first-party -- otherwise the summary reports a CRITICAL the
    default view never shows. Columns must sum to first-party / demoted / total."""
    crit_vendor = Finding(
        rule_id="secret-detector", category=Category.SECRET, severity=Severity.CRITICAL,
        confidence=Confidence.HIGH, title="Hardcoded Private Key",
        evidence=Evidence(file_url="https://x/jsencrypt.min.js", file_hash="h", line=1),
        extracted_value="-----BEGIN", value_type="private_key",
        metadata={"third_party_file": "jsencrypt", "likely_fp": True, "fp_reason": "vendor"},
    )
    high_fp = Finding(
        rule_id="sink-detector", category=Category.SINK, severity=Severity.HIGH,
        confidence=Confidence.MEDIUM, title="Real sink",
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=9),
        extracted_value=".html()", value_type="dom_html_sink",
    )
    html = HTMLReporter().generate(Report(findings=[crit_vendor, high_fp]))
    rows = re.findall(
        r'badge (\w+)">\w+</span></td>\s*<td><strong>(\d+)</strong></td>'
        r'\s*<td[^>]*>(\d+)</td>\s*<td>(\d+)</td>', html)
    by = {sv: (int(fp), int(nz), int(tot)) for sv, fp, nz, tot in rows}
    assert by["critical"] == (0, 1, 1)   # vendor CRITICAL: 0 first-party, 1 demoted, 1 total
    assert by["high"] == (1, 0, 1)       # real HIGH: 1 first-party
    # columns are internally consistent
    assert sum(v[0] for v in by.values()) == 1   # first-party total
    assert sum(v[1] for v in by.values()) == 1   # demoted total
    assert sum(v[2] for v in by.values()) == 2   # grand total


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
    assert "noise-banner" in html and "first-party finding" in html and "to review" in html
    # honest framing: the banner must NOT call them real vulnerabilities
    assert "likely-real" not in html
    assert "not all vulnerabilities" in html
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


def test_json_reporter_masks_secret_in_colocated_nonsecret_finding():
    """A secret that appears verbatim in a NON-secret finding's evidence snippet must also be
    redacted -- masking was category-scoped and leaked the secret via co-located endpoint findings."""
    secret = "sk_live_0123456789abcdefghij0123"
    secret_f = Finding(
        rule_id="secret-detector", category=Category.SECRET, severity=Severity.HIGH,
        confidence=Confidence.HIGH, title="Secret",
        evidence=Evidence(file_url="f", file_hash="h", line=1, snippet=f'k = "{secret}"'),
        extracted_value=secret, value_type="secret_value",
    )
    endpoint_f = Finding(
        rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.MEDIUM,
        confidence=Confidence.HIGH, title="Endpoint",
        evidence=Evidence(file_url="f", file_hash="h", line=2,
                          snippet=f'fetch("/api/data", {{headers: {{Authorization: "Bearer {secret}"}}}})'),
        extracted_value="/api/data",
    )
    out = JSONReporter().generate(Report(findings=[secret_f, endpoint_f]))
    assert secret not in out


def test_mask_secret_findings_redacts_colocated_nonsecret_finding():
    """base.mask_secret_findings (used by HTML/SARIF) must redact the secret from a co-located
    non-secret finding's snippet, not only the SECRET finding's own."""
    from bundleInspector.reporter.base import mask_secret_findings
    secret = "sk_live_0123456789abcdefghij0123"
    secret_f = Finding(
        rule_id="s", category=Category.SECRET, severity=Severity.HIGH, confidence=Confidence.HIGH,
        title="Secret", evidence=Evidence(file_url="f", file_hash="h", line=1, snippet=f'k="{secret}"'),
        extracted_value=secret,
    )
    endpoint_f = Finding(
        rule_id="e", category=Category.ENDPOINT, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
        title="Endpoint", evidence=Evidence(file_url="f", file_hash="h", line=2, snippet=f"Bearer {secret}"),
        extracted_value="/api/data",
    )
    mask_secret_findings(Report(findings=[secret_f, endpoint_f]))
    assert secret not in (endpoint_f.evidence.snippet or "")
    assert secret not in (secret_f.evidence.snippet or "")


def test_wordlist_reporter_does_not_leak_url_credentials():
    """A credentialed endpoint URL must not emit its userinfo (user:pass) into the domain wordlist;
    only the host is used (netloc.split(':')[0] previously emitted the username)."""
    ep = Finding(
        rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.MEDIUM,
        confidence=Confidence.HIGH, title="Endpoint",
        evidence=Evidence(file_url="f", file_hash="h", line=1),
        extracted_value="https://admin:s3cr3tTOKEN@api.internal.example.com/v1/users",
    )
    lines = WordlistReporter(mode="domains").generate(Report(findings=[ep])).splitlines()
    assert not any("s3cr3tTOKEN" in ln for ln in lines)
    assert "admin" not in lines
    assert "api.internal.example.com" in lines
