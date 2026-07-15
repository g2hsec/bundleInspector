from __future__ import annotations

import asyncio
import base64
import errno
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.shared.exceptions import McpError
from pydantic import ValidationError

import bundleInspector.mcp_server.server as server_module
import bundleInspector.storage.atomic as atomic_module
from bundleInspector.core.job_queue import JobQueue, JobStatus
from bundleInspector.correlator.graph import Correlator
from bundleInspector.mcp_server.server import create_server
from bundleInspector.mcp_server.service import MCPService, PublicResourceUnavailable
from bundleInspector.reporter.public_view import (
    _PUBLIC_CAPPED_PASS_NAMES,
    CursorError,
    PublicReportProjector,
)
from bundleInspector.reporter.redaction import sanitize_uri
from bundleInspector.storage.atomic import UnsafePathError, atomic_read_text
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.job_repository import JobAccessError, JobRepository
from bundleInspector.storage.models import (
    AnalysisCompleteness,
    Category,
    Cluster,
    CompletenessIssue,
    CompletenessStatus,
    Confidence,
    Correlation,
    EdgeType,
    Evidence,
    Finding,
    JSAsset,
    Report,
    Severity,
)


def _report(count: int = 5) -> Report:
    secret = "sk_live_0123456789abcdefghij0123"
    findings = [
        Finding(
            rule_id="endpoint-detector",
            category=Category.ENDPOINT,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title=f"Endpoint {index}",
            evidence=Evidence(
                file_url=f"https://user:pass@example.com/app.js?token={secret}",
                file_hash="h",
                line=index + 1,
                snippet=f'fetch("/api/{index}", {{Authorization: "Bearer {secret}"}})',
            ),
            extracted_value=f"/api/{index}?token={secret}",
        )
        for index in range(count)
    ]
    findings.append(Finding(
        rule_id="custom-secret-rule",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Secret",
        evidence=Evidence(file_url="https://example.com/a.js", file_hash="h", line=1),
        extracted_value=secret,
    ))
    correlation = Correlation(
        id="correlation-1",
        edge_type=EdgeType.IMPORT,
        source_finding_id=findings[0].id,
        target_finding_id=findings[1].id,
        confidence=Confidence.HIGH,
        reasoning="same module",
    )
    cluster = Cluster(
        id="cluster-1",
        name="API surface",
        finding_ids=[findings[0].id, findings[1].id],
    )
    report = Report(
        id="report-1",
        job_id="job-1",
        seed_urls=[f"https://user:pass@example.com/?token={secret}"],
        findings=findings,
        assets=[JSAsset(
            id="asset-1",
            url=f"https://example.com/a.js?token={secret}",
            content=secret.encode(),
            content_hash="abc",
            size=len(secret),
        )],
        correlations=[correlation],
        clusters=[cluster],
    )
    report.compute_summary()
    return report


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _cursor_payload(cursor: str) -> dict[str, object]:
    packed = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
    payload = json.loads(packed[:-32])
    assert isinstance(payload, dict)
    return payload


def test_public_pages_are_opaque_join_stable_and_revision_bound() -> None:
    report = _report()
    canaries = {
        "CANARY_REPORT_SECRET",
        "CANARY_JOB_SECRET",
        "CANARY_FINDING_A_SECRET",
        "CANARY_FINDING_B_SECRET",
        "CANARY_ASSET_SECRET",
        "CANARY_CORRELATION_SECRET",
        "CANARY_CLUSTER_SECRET",
    }
    report.id, report.job_id = "CANARY_REPORT_SECRET", "CANARY_JOB_SECRET"
    report.findings[0].id = "CANARY_FINDING_A_SECRET"
    report.findings[1].id = "CANARY_FINDING_B_SECRET"
    report.assets[0].id = "CANARY_ASSET_SECRET"
    report.correlations[0].id = "CANARY_CORRELATION_SECRET"
    report.correlations[0].source_finding_id = report.findings[0].id
    report.correlations[0].target_finding_id = report.findings[1].id
    report.clusters[0].id = "CANARY_CLUSTER_SECRET"
    report.clusters[0].finding_ids = [report.findings[0].id, report.findings[1].id]
    report.findings[0].evidence.file_url = "file:///C:/Users/alice/secret/app.js"
    report.findings[1].evidence.file_url = r"\\server\share\alice\secret.js"

    projector = PublicReportProjector(b"k" * 32)
    cursor = None
    public_finding_ids: list[str] = []
    revisions: set[str] = set()
    while True:
        page = projector.project(
            report,
            page_kind="findings",
            limit=2,
            cursor=cursor,
            principal_id="alice",
        )
        public_finding_ids.extend(item.id for item in page.findings)
        revisions.add(page.revision)
        cursor = page.next_cursor
        if cursor is None:
            break

    assert len(public_finding_ids) == len(report.findings)
    assert len(set(public_finding_ids)) == len(public_finding_ids)
    assert not canaries.intersection(public_finding_ids)
    correlation_page = projector.project(report, page_kind="correlations", principal_id="alice")
    cluster_page = projector.project(report, page_kind="clusters", principal_id="alice")
    assert correlation_page.correlations[0].source_finding_id == public_finding_ids[0]
    assert correlation_page.correlations[0].target_finding_id == public_finding_ids[1]
    assert cluster_page.clusters[0].finding_ids == public_finding_ids[:2]
    assert len(revisions) == 1

    payload = json.dumps(page.model_dump(mode="json"))
    payload += json.dumps(correlation_page.model_dump(mode="json"))
    payload += json.dumps(cluster_page.model_dump(mode="json"))
    assert not any(canary in payload for canary in canaries)
    assert "sk_live_" not in payload
    assert "user:pass" not in payload
    assert "?token=" not in payload
    assert "C:/Users/alice" not in payload
    assert r"server\\share\\alice" not in payload
    assert "[local-resource:" in json.dumps(
        projector.project(report, page_kind="findings", limit=100).model_dump(mode="json")
    )

    first = projector.project(report, limit=2, principal_id="alice")
    assert first.next_cursor
    with pytest.raises(CursorError):
        projector.project(report, limit=2, cursor=first.next_cursor, principal_id="bob")
    tampered = first.next_cursor[:-1] + ("A" if first.next_cursor[-1] != "A" else "B")
    with pytest.raises(CursorError):
        projector.project(report, limit=2, cursor=tampered, principal_id="alice")

    report.findings[0].title = "Same ID, changed public title"
    with pytest.raises(CursorError):
        projector.project(report, limit=2, cursor=first.next_cursor, principal_id="alice")


def test_report_cursor_uses_opaque_principal_binding() -> None:
    principal = "TENANT_CANARY_alice@example.com"
    page = PublicReportProjector(b"k" * 32).project(
        _report(),
        limit=1,
        principal_id=principal,
    )

    assert page.next_cursor is not None
    payload = _cursor_payload(page.next_cursor)
    assert principal not in page.next_cursor
    assert principal not in json.dumps(payload)
    assert "principal_id" not in payload
    assert str(payload["principal"]).startswith("principal-")


def test_public_projection_masks_arbitrary_discovered_secret_in_all_text_fields() -> None:
    secret = "ARBITRARY_CANARY_CREDENTIAL_93af750bc1"
    report = _report()
    secret_finding = report.findings[-1]
    secret_finding.extracted_value = secret
    secret_finding.masked_value = "ARBI***0bc1"
    secret_finding.rule_id = f"rule-{secret}"
    secret_finding.title = f"Secret {secret}"
    secret_finding.description = f"Found credential {secret}"
    secret_finding.value_type = f"type-{secret}"
    secret_finding.tags = [f"tag-{secret}"]
    report.findings[0].description = f"Endpoint uses {secret}"
    secret_uri = f"https://{secret}.example.com/private/app.js?token={secret}"
    report.seed_urls = [secret_uri]
    report.assets[0].url = secret_uri
    report.findings[0].evidence.file_url = secret_uri
    report.findings[0].evidence.original_file_url = secret_uri
    report.findings[0].metadata["third_party_file"] = secret_uri
    report.correlations[0].reasoning = f"Shared value {secret}"
    report.clusters[0].name = f"Cluster {secret}"
    report.clusters[0].description = f"Contains {secret}"
    report.completeness = AnalysisCompleteness(
        status=CompletenessStatus.PARTIAL,
        issues=[
            CompletenessIssue(
                code=f"code-{secret}",
                stage=f"stage-{secret}",
                message=f"Message {secret}",
                details={
                    f"key-{secret}": f"value-{secret}",
                    "nested": {f"nested-key-{secret}": f"nested-value-{secret}"},
                },
            )
        ],
    )

    projector = PublicReportProjector(b"k" * 32)
    payload = json.dumps(
        {
            kind: projector.project(report, page_kind=kind, limit=100).model_dump(
                mode="json"
            )
            for kind in ("findings", "assets", "correlations", "clusters")
        }
    )

    assert secret not in payload
    assert secret.lower() not in payload.lower()
    assert "ARBI***0bc1" in payload


def test_public_summary_ignores_stale_internal_cache_and_arbitrary_keys() -> None:
    secret = "ARBITRARY_SUMMARY_SECRET_4ec973"
    report = _report()
    report.findings[-1].extracted_value = secret
    report.findings[-1].masked_value = "SUMM***c973"
    report.summary.total_js_files = 999
    report.summary.total_findings = 999
    report.summary.total_correlations = 999
    report.summary.total_clusters = 999
    report.summary.findings_by_severity = {secret: 999}
    report.summary.findings_by_category = {secret: 999}
    report.summary.findings_by_tier = {secret: 999}

    page = PublicReportProjector(b"k" * 32).project(report, limit=1)
    payload = page.model_dump_json()

    assert secret not in payload
    assert page.summary.total_js_files == len(report.assets)
    assert page.summary.total_findings == len(report.findings)
    assert page.summary.total_correlations == len(report.correlations)
    assert page.summary.total_clusters == len(report.clusters)
    assert page.summary.findings_by_severity[Severity.MEDIUM.value] == 5
    assert page.summary.findings_by_severity[Severity.HIGH.value] == 1
    assert page.summary.findings_by_category[Category.ENDPOINT.value] == 5
    assert page.summary.findings_by_category[Category.SECRET.value] == 1
    assert report.summary.total_findings == 999
    assert report.summary.findings_by_category == {secret: 999}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("duration_seconds", float("inf")),
        ("risk_score", float("nan")),
    ],
)
def test_public_projection_rejects_mutated_nonfinite_numbers(field: str, value: float) -> None:
    report = _report()
    if field == "duration_seconds":
        report.duration_seconds = value
    else:
        report.findings[0].risk_score = value

    with pytest.raises(ValidationError, match="finite number"):
        PublicReportProjector(b"k" * 32).project(report, limit=1)


def test_internal_report_models_reject_nonfinite_numbers() -> None:
    with pytest.raises(ValidationError, match="finite number"):
        Report(duration_seconds=float("inf"))
    finding_payload = _report().findings[0].model_dump()
    finding_payload["risk_score"] = float("nan")
    with pytest.raises(ValidationError, match="finite number"):
        Finding.model_validate(finding_payload)


def test_public_completeness_normalizes_nonfinite_telemetry_scalars() -> None:
    report = _report()
    report.completeness = AnalysisCompleteness(
        status=CompletenessStatus.PARTIAL,
        issues=[CompletenessIssue(
            code="parse_incomplete",
            stage="parse",
            message="invalid numeric sample",
            details={
                "limit": 1.25,
                "status": float("nan"),
                "nested": {"infinite": float("inf"), "count": 2},
            },
        )],
    )

    page = PublicReportProjector(b"k" * 32).project(report, limit=1)
    details = page.completeness.issues[0].details

    assert details == {
        "limit": 1.25,
        "status": None,
    }
    assert "NaN" not in page.model_dump_json()
    assert "Infinity" not in page.model_dump_json()


def test_public_completeness_normalizes_negative_and_oversized_counters() -> None:
    report = _report()
    report.completeness = AnalysisCompleteness(
        status=CompletenessStatus.PARTIAL,
        issues=[CompletenessIssue(
            code="parse_incomplete",
            stage="parse",
            message="invalid counters",
            details={
                "capped_passes": {
                    "_add_import_edges": 2,
                    "_add_taint_chain_edges": -1,
                    "PRIVATE_PASS_CANARY": 9,
                },
                "limit": -1,
                "processed": 1 << 64,
                "timeout_seconds": -0.25,
                "partial_results": True,
            },
        )],
    )

    page = PublicReportProjector(b"k" * 32).project(report, limit=1)

    assert page.completeness.issues[0].details == {
        "capped_passes": {
            "_add_import_edges": 2,
            "_add_taint_chain_edges": None,
        },
        "limit": None,
        "partial_results": True,
        "processed": None,
        "timeout_seconds": None,
    }
    assert "18446744073709551616" not in page.model_dump_json()
    assert "PRIVATE_PASS_CANARY" not in page.model_dump_json()


def test_public_capped_pass_allowlist_tracks_every_correlator_pass() -> None:
    correlator_passes = {
        name
        for name, member in inspect.getmembers(Correlator, predicate=inspect.isfunction)
        if name.startswith("_add_")
    }

    assert _PUBLIC_CAPPED_PASS_NAMES == correlator_passes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("risk_score", -0.1),
        ("end_line", -1),
        ("end_column", -1),
        ("original_line", -1),
        ("original_column", -1),
    ],
)
def test_public_projection_rejects_negative_scores_and_optional_positions(
    field: str,
    value: float | int,
) -> None:
    report = _report()
    if field == "risk_score":
        report.findings[0].risk_score = value
    else:
        setattr(report.findings[0].evidence, field, value)

    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        PublicReportProjector(b"k" * 32).project(report, limit=1)


def test_public_secret_index_is_linear_in_distinct_input_bytes() -> None:
    count = 3_000
    findings = []
    secrets: list[str] = []
    for index in range(count):
        secret = f"UNIQUE_SECRET_{index:05d}_abcdefghijklmnopqrstuvwxyz"
        secrets.append(secret)
        findings.append(Finding(
            rule_id="secret",
            category=Category.SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title=f"Secret {secret}",
            evidence=Evidence(
                file_url="https://example.com/app.js",
                file_hash="h",
                line=index + 1,
            ),
            extracted_value=secret,
            masked_value=f"masked-{index:05d}",
        ))
    report = Report(id="report-many-secrets", job_id="job-1", findings=findings)
    report.compute_summary()
    projector = PublicReportProjector(b"k" * 32)

    replacements = projector._secret_replacements(report)
    assert not isinstance(replacements, tuple)
    indexed_secrets = secrets + [secret.lower() for secret in secrets]
    assert len(replacements._patterns) == len(indexed_secrets)
    assert len(replacements._transitions) <= 1 + sum(map(len, indexed_secrets))
    replaced = replacements.replace(f"{secrets[0]}|{secrets[-1]}")
    assert replaced == "masked-00000|masked-02999"

    payload = projector.project(report, page_kind="findings", limit=1).model_dump_json()
    assert secrets[0] not in payload
    assert secrets[-1] not in payload


def test_public_secret_index_handles_overlap_untrusted_masks_and_reconstruction() -> None:
    def finding(raw: str, masked: str) -> Finding:
        return Finding(
            rule_id="secret",
            category=Category.SECRET,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Secret",
            evidence=Evidence(file_url="https://example.com/app.js", file_hash="h", line=1),
            extracted_value=raw,
            masked_value=masked,
        )

    projector = PublicReportProjector(b"k" * 32)
    overlap = projector._secret_replacements(Report(findings=[
        finding("abcd", "MASK-LONG"),
        finding("bc", "MASK-SHORT"),
        finding("X", "abcd"),
    ]))
    assert not isinstance(overlap, tuple)
    projected = overlap.replace("zabcd X tail")
    assert projected == "zMASK-LONG ***redacted*** tail"
    assert not overlap.contains(projected)

    reconstruction = projector._secret_replacements(Report(findings=[
        finding("ab", "MASK-AB"),
        finding("X", "a"),
    ]))
    assert not isinstance(reconstruction, tuple)
    assert reconstruction.replace("Xb") == ""

    marker_collision = projector._secret_replacements(Report(findings=[
        finding("redacted", "MASK"),
        finding("X", "redacted"),
    ]))
    assert not isinstance(marker_collision, tuple)
    assert marker_collision.replace("X") == ""


def test_public_header_and_nested_collections_are_bounded() -> None:
    count = 10_000
    report = Report(
        seed_urls=[f"file:///C:/Users/alice/project/{index}.js" for index in range(count)],
        completeness=AnalysisCompleteness(
            status=CompletenessStatus.PARTIAL,
            issues=[
                CompletenessIssue(
                    code="cap",
                    stage="analyze",
                    message=f"issue {index}",
                    affected_count=1,
                )
                for index in range(count)
            ],
        ),
        clusters=[Cluster(
            name="large",
            finding_ids=[f"finding-{index}" for index in range(count)],
        )],
    )
    page = PublicReportProjector(b"k" * 32).project(report, page_kind="clusters", limit=1)
    assert page.target_count == count and len(page.targets) == 100 and page.targets_truncated
    assert page.completeness.issue_count == count
    assert len(page.completeness.issues) == 100 and page.completeness.issues_truncated
    assert page.clusters[0].finding_count == count
    assert len(page.clusters[0].finding_ids) == 100
    assert page.clusters[0].finding_ids_truncated
    assert len(page.model_dump_json()) < 150_000


@pytest.mark.parametrize(
    "page_kind",
    ["findings", "assets", "correlations", "clusters"],
)
def test_paginated_page_union_matches_full_public_projection(page_kind: str) -> None:
    report = _report(count=7)
    report.assets = [
        report.assets[0].model_copy(
            deep=True,
            update={"id": f"asset-{index}", "url": f"https://example.com/{index}.js"},
        )
        for index in range(5)
    ]
    report.correlations = [
        report.correlations[0].model_copy(
            deep=True,
            update={"id": f"correlation-{index}"},
        )
        for index in range(5)
    ]
    report.clusters = [
        report.clusters[0].model_copy(
            deep=True,
            update={"id": f"cluster-{index}", "name": f"Cluster {index}"},
        )
        for index in range(5)
    ]
    report.compute_summary()
    projector = PublicReportProjector(b"k" * 32)
    full = projector.project(report, page_kind=page_kind, limit=100, principal_id="alice")
    expected = [item.model_dump(mode="json") for item in getattr(full, page_kind)]
    observed: list[dict[str, object]] = []
    cursor = None
    header_signature = None
    while True:
        page = projector.project(
            report,
            page_kind=page_kind,
            limit=2,
            cursor=cursor,
            principal_id="alice",
        )
        current_header = (
            page.report_id,
            page.job_id,
            page.revision,
            page.summary,
            page.completeness,
        )
        header_signature = header_signature or current_header
        assert current_header == header_signature
        assert page.page_total == len(getattr(report, page_kind))
        assert page.page_offset == len(observed)
        assert page.page_count == len(getattr(page, page_kind))
        assert page.page_truncated is (page.next_cursor is not None)
        observed.extend(item.model_dump(mode="json") for item in getattr(page, page_kind))
        cursor = page.next_cursor
        if cursor is None:
            break

    assert observed == expected


@pytest.mark.parametrize("count", [10_000, 100_000])
def test_limit_one_projection_creates_only_page_models_with_bounded_peak_memory(
    count: int,
    monkeypatch,
) -> None:
    report = _report()
    finding = report.findings[0]
    report.findings = [finding] * count
    projector = PublicReportProjector(b"k" * 32)
    projected_models = 0
    original = projector._finding

    def count_page_model(
        current_report: Report,
        current_finding: Finding,
        replacements=(),
    ):
        nonlocal projected_models
        projected_models += 1
        return original(current_report, current_finding, replacements)

    monkeypatch.setattr(projector, "_finding", count_page_model)
    tracemalloc.start()
    try:
        page = projector.project(report, page_kind="findings", limit=1)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(page.findings) == 1
    assert projected_models == 1
    assert peak < 2_000_000


def test_public_http_paths_are_opaque_for_plain_and_percent_encoded_canaries() -> None:
    secret = "CANARY_TENANT_ALICE_SK_live_1234567890123456"
    encoded = "%43%41%4E%41%52%59%5F%54%45%4E%41%4E%54"
    report = _report()
    report.seed_urls = [f"https://example.com/users/alice/{secret}/index.html"]
    report.assets[0].url = f"https://example.com/users/alice/{encoded}/app.js"
    report.findings[0].evidence.file_url = (
        f"https://example.com/users/alice/{secret}/app.js?token={secret}"
    )
    projector = PublicReportProjector(b"k" * 32)

    payload = json.dumps(
        {
            "finding": projector.project(report, page_kind="findings").model_dump(mode="json"),
            "asset": projector.project(report, page_kind="assets").model_dump(mode="json"),
        }
    )

    assert secret not in payload
    assert encoded not in payload
    assert "/users/alice/" not in payload
    assert "?token=" not in payload
    assert "[resource:" in payload

    shared = f"https://example.com/users/alice/{secret}/shared.js?token={secret}"
    report.seed_urls = [shared]
    report.assets[0].url = shared
    report.findings[0].evidence.file_url = shared
    finding_page = projector.project(report, page_kind="findings")
    asset_page = projector.project(report, page_kind="assets")
    assert finding_page.targets[0] == finding_page.findings[0].evidence.uri
    assert finding_page.targets[0] == asset_page.assets[0].uri


def test_public_uri_redacts_token_hostnames_and_preserves_ipv6_netloc() -> None:
    token = "sk_live_0123456789abcdefghij0123"
    report = Report(seed_urls=[
        f"https://{token}.example.com/private.js",
        "https://[2001:db8::1]:8443/private.js?token=value",
    ])

    page = PublicReportProjector(b"k" * 32).project(report)

    assert token not in page.model_dump_json()
    assert page.targets[0] == "[invalid-uri]"
    assert page.targets[1].startswith("https://[2001:db8::1]:8443/")
    assert "?" not in page.targets[1]


def test_public_uri_rejects_encoded_hosts_and_never_encodes_discarded_surrogate_query() -> None:
    assert sanitize_uri("https://%73ecret.example/path", public=True) == "[invalid-uri]"
    assert sanitize_uri("https://example.com/?\ud800=value", public=True) == "https://example.com/"
    assert sanitize_uri("https://bücher.example/path", public=True).startswith(
        "https://xn--bcher-kva.example/"
    )
    assert "%3F=" in sanitize_uri("https://example.com/?\ud800=value", public=False)


@pytest.mark.parametrize("field", ["title", "description", "rule_id", "value_type"])
def test_public_text_normalizes_unpaired_surrogates_before_json(field: str) -> None:
    report = _report()
    setattr(report.findings[0], field, "before\ud800after")

    payload = PublicReportProjector(b"k" * 32).project(report, limit=1).model_dump_json()

    assert "before?after" in payload
    assert "\\ud800" not in payload.lower()


def test_public_projection_bounds_oversized_scalar_processing() -> None:
    oversized = "OVERSIZED_CANARY_" + "x" * 70_000
    report = _report()
    report.seed_urls = ["https://" + oversized + ".example.com/path"]
    report.findings[0].title = oversized
    report.completeness = AnalysisCompleteness(
        status=CompletenessStatus.PARTIAL,
        issues=[CompletenessIssue(
            code=oversized,
            stage="analyze",
            message=oversized,
            details={oversized: oversized},
        )],
    )

    page = PublicReportProjector(b"k" * 32).project(report, limit=1)

    assert oversized not in page.model_dump_json()
    assert page.targets == ["[oversized-uri]"]
    assert page.findings[0].title == "[oversized-redacted]"
    issue = page.completeness.issues[0]
    assert issue.code == "analysis_incomplete"
    assert issue.stage == "analyze"
    assert issue.message == "Analysis coverage was reduced (analysis_incomplete)"
    assert issue.details == {}


def test_public_completeness_drops_unallowlisted_diagnostic_credentials_and_paths() -> None:
    canaries = {
        "UNLISTED_CODE_PRIVATE_CANARY",
        "UNLISTED_STAGE_PRIVATE_CANARY",
        "opaque-private-authorization-canary",
        "opaque-private-nested-canary",
        "C:/Users/alice/private/project.js",
        "custom-rule-private-id",
    }
    report = _report()
    report.completeness = AnalysisCompleteness(
        status=CompletenessStatus.COMPLETE,
        issues=[CompletenessIssue(
            code="UNLISTED_CODE_PRIVATE_CANARY",
            stage="UNLISTED_STAGE_PRIVATE_CANARY",
            message="Failure at C:/Users/alice/private/project.js",
            affected_count=2,
            details={
                "authorization": "opaque-private-authorization-canary",
                "nested": {"token": "opaque-private-nested-canary"},
                "rule_id": "custom-rule-private-id",
                "limit": 10,
                "partial_results": True,
            },
        )],
    )

    page = PublicReportProjector(b"k" * 32).project(report, limit=1)
    payload = page.model_dump_json()
    issue = page.completeness.issues[0]

    assert not any(canary in payload for canary in canaries)
    assert issue.code == "analysis_incomplete"
    assert issue.stage == "unknown"
    assert issue.message == "Analysis coverage was reduced (analysis_incomplete)"
    assert issue.details == {"limit": 10, "partial_results": True}
    assert page.completeness.status == "partial"
    assert page.completeness.is_complete is False


def test_revision_changes_when_same_asset_id_status_changes() -> None:
    report = _report()
    projector = PublicReportProjector(b"k" * 32)
    first = projector.project(report, page_kind="assets", limit=1)
    report.assets[0].status_code = 503
    second = projector.project(report, page_kind="assets", limit=1)

    assert first.assets[0].id == second.assets[0].id
    assert first.revision != second.revision


def test_public_projector_rejects_oversized_cursor_before_decoding() -> None:
    projector = PublicReportProjector(b"k" * 32)
    with pytest.raises(CursorError, match="malformed"):
        projector.project(_report(), cursor="A" * 4097)


@pytest.mark.parametrize("limit", [True, False, 0, 101, 1.5, "1"])
def test_public_projector_rejects_non_integer_or_out_of_range_limits(limit: object) -> None:
    with pytest.raises(ValueError, match="limit must be"):
        PublicReportProjector(b"k" * 32).project(_report(), limit=limit)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_mcp_in_memory_protocol_is_public_read_only_and_cache_immutable(tmp_path) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session

    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "local")
    report = _report()
    report.completeness = AnalysisCompleteness(
        status=CompletenessStatus.PARTIAL,
        issues=[CompletenessIssue(
            code="SERVICE_PRIVATE_CODE_CANARY",
            stage="SERVICE_PRIVATE_STAGE_CANARY",
            message="SERVICE_PRIVATE_MESSAGE_CANARY",
            details={"diagnostic": "SERVICE_PRIVATE_DETAIL_CANARY", "limit": 7},
        )],
    )
    await FindingStore(tmp_path / "job-1").store_report(report)
    service = MCPService(repository)
    server = create_server(service)
    before = _tree_hash(tmp_path)

    async with create_connected_server_and_client_session(server) as client:
        tools = await client.list_tools()
        tool_names = {tool.name for tool in tools.tools}
        assert tool_names == {"list_jobs", "get_report_page", "get_job_status"}
        listed = await client.call_tool("list_jobs", {"limit": 10})
        listed_payload = json.loads(
            "".join(item.text for item in listed.content if hasattr(item, "text"))
        )
        assert listed_payload["page_total"] == 1
        assert listed_payload["page_offset"] == 0
        assert listed_payload["page_count"] == 1
        assert listed_payload["page_truncated"] is False
        public_job_id = listed_payload["jobs"][0]["job_id"]
        assert public_job_id != "job-1"
        templates = await client.list_resource_templates()
        assert len(templates.resourceTemplates) == 1
        template = templates.resourceTemplates[0]
        assert template.uriTemplate == "bundleinspector://jobs/{job_id}"
        assert template.mimeType == "application/json"
        status = await client.call_tool("get_job_status", {"job_id": public_job_id})
        status_payload = json.loads(
            "".join(item.text for item in status.content if hasattr(item, "text"))
        )
        resource = await client.read_resource(
            f"bundleinspector://jobs/{public_job_id}"
        )
        assert len(resource.contents) == 1
        resource_content = resource.contents[0]
        assert hasattr(resource_content, "text")
        assert resource_content.mimeType == "application/json"
        resource_payload = json.loads(resource_content.text)
        assert resource_payload == status_payload
        assert resource_payload["job_id"] == public_job_id
        encoded_resource = json.dumps(resource_payload, sort_keys=True)
        assert "job-1" not in encoded_resource
        assert "sk_live_" not in encoded_resource
        assert "SERVICE_PRIVATE_" not in encoded_resource
        with pytest.raises(McpError) as raw_error:
            await client.read_resource("bundleinspector://jobs/job-1")
        assert "job-1" not in str(raw_error.value)
        result = await client.call_tool("get_report_page", {
            "job_id": public_job_id,
            "page_kind": "findings",
            "limit": 2,
        })
        assert not result.isError
        text = "".join(item.text for item in result.content if hasattr(item, "text"))
        assert "sk_live_" not in text
        assert "SERVICE_PRIVATE_" not in text
        decoded = json.loads(text)
        assert decoded["page_kind"] == "findings"
        assert decoded["page_total"] == len(report.findings)
        assert decoded["page_offset"] == 0
        assert decoded["page_count"] == 2
        assert decoded["page_truncated"] is True
        assert decoded["completeness"]["issues"][0]["details"] == {"limit": 7}
        assert "config" not in decoded and "errors" not in decoded
        assert "snippet" not in json.dumps(decoded)

    assert _tree_hash(tmp_path) == before


@pytest.mark.asyncio
async def test_public_job_status_omits_queue_name_and_error_canaries(tmp_path) -> None:
    queue = JobQueue(max_concurrent=1)
    job = await queue.add("https://example.com/?token=QUEUE_NAME_CANARY")
    job.status = JobStatus.FAILED
    job.error = "Authorization: Bearer QUEUE_ERROR_CANARY"
    repository = JobRepository(tmp_path)
    repository.register_owner(job.id, "local")
    service = MCPService(repository, queue=queue)
    public_job_id = (await service.list_jobs(limit=1))["jobs"][0]["job_id"]
    payload = await service.get_job_status(str(public_job_id))
    encoded = json.dumps(payload)
    assert "QUEUE_NAME_CANARY" not in encoded
    assert "QUEUE_ERROR_CANARY" not in encoded
    assert "name" not in payload and "error" not in payload
    assert payload["job_id"] != job.id
    assert payload["status_source"] == "queue"
    assert not hasattr(service, "cancel_job")
    assert not hasattr(service, "queue")

    with pytest.raises(PublicResourceUnavailable, match="resource unavailable"):
        await service.get_job_status(job.id)


@pytest.mark.asyncio
async def test_missing_and_unauthorized_mcp_errors_are_indistinguishable(tmp_path) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session

    repository = JobRepository(tmp_path)
    repository.register_owner("unauthorized-canary", "alice")
    server = create_server(MCPService(repository, principal_id="local"))
    async with create_connected_server_and_client_session(server) as client:
        unauthorized = await client.call_tool(
            "get_job_status",
            {"job_id": "UNAUTHORIZED_CANARY"},
        )
        missing = await client.call_tool("get_job_status", {"job_id": "MISSING_CANARY"})
    unauthorized_text = "".join(
        item.text for item in unauthorized.content if hasattr(item, "text")
    )
    missing_text = "".join(item.text for item in missing.content if hasattr(item, "text"))
    assert unauthorized.isError and missing.isError
    assert unauthorized_text == missing_text
    assert "UNAUTHORIZED_CANARY" not in unauthorized_text
    assert "MISSING_CANARY" not in missing_text


@pytest.mark.asyncio
async def test_job_list_cursor_rejects_status_mutation(tmp_path) -> None:
    queue = JobQueue(max_concurrent=1)
    jobs = [await queue.add(f"job-{index}") for index in range(2)]
    repository = JobRepository(tmp_path)
    for job in jobs:
        repository.register_owner(job.id, "local")
    service = MCPService(repository, queue=queue)
    first = await service.list_jobs(limit=1)
    assert first["next_cursor"]
    jobs[0].status = JobStatus.RUNNING
    with pytest.raises(ValueError, match="revision"):
        await service.list_jobs(limit=1, cursor=str(first["next_cursor"]))


@pytest.mark.asyncio
async def test_job_list_cursor_uses_opaque_principal_binding(tmp_path) -> None:
    principal = "TENANT_CANARY_alice_93af"
    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", principal)
    repository.register_owner("job-2", principal)
    service = MCPService(repository, principal_id=principal)

    first = await service.list_jobs(limit=1)

    assert first["next_cursor"] is not None
    cursor = str(first["next_cursor"])
    payload = _cursor_payload(cursor)
    assert principal not in cursor
    assert principal not in json.dumps(payload)
    assert "principal_id" not in payload
    assert str(payload["principal"]).startswith("principal-")
    second = await service.list_jobs(limit=1, cursor=cursor)
    assert len(second["jobs"]) == 1


@pytest.mark.asyncio
async def test_raw_job_and_report_ids_are_never_accepted_by_public_service(tmp_path) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "local")
    await FindingStore(tmp_path / "job-1").store_report(_report())
    service = MCPService(repository)
    listed = await service.list_jobs(limit=1)
    public_job_id = str(listed["jobs"][0]["job_id"])
    public_report_id = str(
        (await service.get_report_page(public_job_id, limit=1))["report_id"]
    )

    with pytest.raises(PublicResourceUnavailable, match="resource unavailable"):
        await service.get_report_page("job-1", limit=1)
    with pytest.raises(PublicResourceUnavailable, match="resource unavailable"):
        await service.get_report_page(public_job_id, report_id="report-1", limit=1)
    assert (
        await service.get_report_page(
            public_job_id,
            report_id=public_report_id,
            limit=1,
        )
    )["report_id"] == public_report_id


@pytest.mark.asyncio
async def test_mcp_rejects_oversized_cursors_and_malformed_ids_before_repository_work(
    tmp_path,
    monkeypatch,
) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "local")
    await FindingStore(tmp_path / "job-1").store_report(_report())
    service = MCPService(repository)
    public_job_id = str((await service.list_jobs(limit=1))["jobs"][0]["job_id"])
    calls = {"jobs": 0, "reports": 0}
    original_list_jobs = repository.list_job_ids

    def list_jobs(principal_id: str):
        calls["jobs"] += 1
        return original_list_jobs(principal_id)

    async def list_reports(_job_id: str, _principal_id: str):
        calls["reports"] += 1
        return ["report-1"]

    monkeypatch.setattr(repository, "list_job_ids", list_jobs)
    monkeypatch.setattr(repository, "list_report_ids", list_reports)

    with pytest.raises(ValueError, match="malformed"):
        await service.list_jobs(cursor="A" * 4097)
    with pytest.raises(ValueError, match="malformed"):
        await service.get_report_page(public_job_id, cursor="A" * 4097)
    with pytest.raises(PublicResourceUnavailable):
        await service.get_job_status("job-" + "A" * 25)
    assert calls == {"jobs": 0, "reports": 0}

    with pytest.raises(PublicResourceUnavailable):
        await service.get_report_page(public_job_id, report_id="report-short")
    assert calls == {"jobs": 1, "reports": 0}


@pytest.mark.asyncio
async def test_repository_status_distinguishes_unknown_partial_and_complete(tmp_path) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("unknown-job", "local")
    repository.register_owner("partial-job", "local")
    repository.register_owner("complete-job", "local")
    partial = _report()
    partial.job_id = "partial-job"
    partial.completeness = AnalysisCompleteness(
        status=CompletenessStatus.PARTIAL,
        issues=[CompletenessIssue(code="partial", stage="parse", message="partial")],
    )
    complete = _report()
    complete.job_id = "complete-job"
    await FindingStore(tmp_path / "partial-job").store_report(partial)
    await FindingStore(tmp_path / "complete-job").store_report(complete)
    service = MCPService(repository)

    listed = await service.list_jobs(limit=10)
    by_raw_order = dict(
        zip(
            repository.list_job_ids("local"),
            listed["jobs"],
            strict=True,
        )
    )
    assert by_raw_order["unknown-job"]["status"] == "unknown"
    assert by_raw_order["unknown-job"]["status_source"] == "repository"
    assert by_raw_order["partial-job"]["status"] == "partial"
    assert by_raw_order["partial-job"]["completeness_status"] == "partial"
    assert by_raw_order["complete-job"]["status"] == "completed"
    assert by_raw_order["complete-job"]["completeness_status"] == "complete"


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [10_000, 100_000])
async def test_job_list_limit_one_keeps_row_memory_bounded(count: int, monkeypatch) -> None:
    class Repository:
        public_signing_key = b"k" * 32

        def __init__(self) -> None:
            self.ids = [f"job-{index}" for index in range(count)]

        def list_job_ids(self, _principal_id: str) -> list[str]:
            return self.ids

    repository = Repository()
    service = MCPService(repository)

    async def status(raw_job_id: str) -> dict[str, object]:
        return {"job_id": raw_job_id, "status": "unknown"}

    monkeypatch.setattr(service, "_job_status", status)
    tracemalloc.start()
    try:
        page = await service.list_jobs(limit=1)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(page["jobs"]) == 1
    assert page["next_cursor"]
    assert peak < 2_000_000


@pytest.mark.asyncio
async def test_stdio_entrypoint_has_clean_framing_and_read_only_cache(tmp_path) -> None:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "local")
    await FindingStore(tmp_path / "job-1").store_report(_report())
    _ = repository.public_signing_key
    before = _tree_hash(tmp_path)
    env = os.environ.copy()
    source_root = str(Path(__file__).resolve().parents[2] / "src")
    env["PYTHONPATH"] = source_root + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "bundleInspector.mcp_server.server",
            "--cache-dir",
            str(tmp_path),
        ],
        env=env,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as streams:
            async with ClientSession(*streams) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "list_jobs", "get_report_page", "get_job_status",
                }
                result = await client.call_tool("list_jobs", {"limit": 10})
                assert not result.isError
                listed_payload = json.loads(
                    "".join(
                        item.text for item in result.content if hasattr(item, "text")
                    )
                )
                public_job_id = listed_payload["jobs"][0]["job_id"]
                templates = await client.list_resource_templates()
                assert len(templates.resourceTemplates) == 1
                template = templates.resourceTemplates[0]
                assert template.uriTemplate == "bundleinspector://jobs/{job_id}"
                assert template.mimeType == "application/json"
                resource = await client.read_resource(
                    f"bundleinspector://jobs/{public_job_id}"
                )
                assert len(resource.contents) == 1
                resource_content = resource.contents[0]
                assert hasattr(resource_content, "text")
                assert resource_content.mimeType == "application/json"
                resource_payload = json.loads(resource_content.text)
                assert resource_payload["job_id"] == public_job_id
                encoded_resource = json.dumps(resource_payload, sort_keys=True)
                assert "job-1" not in encoded_resource
                assert "sk_live_" not in encoded_resource
                with pytest.raises(McpError) as raw_error:
                    await client.read_resource("bundleinspector://jobs/job-1")
                assert "job-1" not in str(raw_error.value)
        errlog.seek(0)
        stderr_output = errlog.read()
    assert _tree_hash(tmp_path) == before
    assert "sk_live_" not in stderr_output


def test_http_transport_is_fail_closed_at_entrypoint(tmp_path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bundleInspector.mcp_server.server",
            "--cache-dir",
            str(tmp_path),
            "--transport",
            "streamable-http",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert "invalid choice" in result.stderr


def test_repository_and_mcp_entrypoint_reject_a_linked_cache_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    cache_link = tmp_path / "cache-link"
    try:
        cache_link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(UnsafePathError, match="symbolic link or junction"):
        JobRepository(cache_link)

    server_started = False

    def unexpected_server_start(service):
        nonlocal server_started
        server_started = True
        raise AssertionError("MCP server must not start with an unsafe cache directory")

    monkeypatch.setattr(server_module, "create_server", unexpected_server_start)
    monkeypatch.setattr(sys, "argv", ["bundleinspector-mcp", "--cache-dir", str(cache_link)])
    with pytest.raises(UnsafePathError, match="symbolic link or junction"):
        server_module.main()
    assert not server_started
    assert list(outside.iterdir()) == []


def test_repository_rejects_cache_directory_reparse_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    original_lstat = atomic_module.os.lstat

    def mark_cache_as_reparse(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if Path(path) == cache_dir:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_file_attributes=0x400,
            )
        return metadata

    monkeypatch.setattr(atomic_module.os, "lstat", mark_cache_as_reparse)

    with pytest.raises(UnsafePathError, match="symbolic link or junction"):
        JobRepository(cache_dir)


@pytest.mark.asyncio
async def test_job_queue_cancellation_waits_for_handler_cleanup() -> None:
    queue = JobQueue(max_concurrent=1)
    job = await queue.add("scan")
    started = asyncio.Event()
    cleaned = asyncio.Event()

    async def handler(_job):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    processing = asyncio.create_task(queue.process(handler))
    await started.wait()
    assert await queue.cancel(job.id)
    await processing
    assert cleaned.is_set()
    assert job.status == JobStatus.CANCELLED


def test_repository_ownership_is_create_once_and_fail_closed(tmp_path) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "alice")
    repository.register_owner("job-1", "alice")
    with pytest.raises(JobAccessError):
        repository.register_owner("job-1", "bob")

    (tmp_path / "legacy").mkdir()
    (tmp_path / "empty-owner").mkdir()
    (tmp_path / "empty-owner" / ".owner").write_text("", encoding="utf-8")
    (tmp_path / "corrupt-owner").mkdir()
    (tmp_path / "corrupt-owner" / ".owner").write_text("bad owner!", encoding="utf-8")
    with pytest.raises(JobAccessError):
        repository.assert_access("legacy", "local")
    with pytest.raises(JobAccessError):
        repository.assert_access("empty-owner", "local")
    with pytest.raises(JobAccessError):
        repository.assert_access("corrupt-owner", "local")


@pytest.mark.parametrize("job_id", ["Uppercase", "con", "job."])
def test_repository_rejects_nonportable_filesystem_job_ids(tmp_path, job_id: str) -> None:
    repository = JobRepository(tmp_path)
    with pytest.raises(ValueError, match="portable"):
        repository.register_owner(job_id, "Alice")
    assert not (tmp_path / job_id).exists()


@pytest.mark.asyncio
async def test_repository_keeps_principals_compatible_but_rejects_device_report_ids(tmp_path) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "Alice")
    assert repository.assert_access("job-1", "Alice") == tmp_path / "job-1"
    (tmp_path / "job-1" / "reports").mkdir()

    with pytest.raises(ValueError, match="portable"):
        await repository.get_report("job-1", "Alice", "con")


def test_repository_never_adopts_preexisting_ownerless_storage(tmp_path) -> None:
    repository = JobRepository(tmp_path)
    empty = tmp_path / "empty-job"
    empty.mkdir()
    legacy = tmp_path / "legacy-job"
    (legacy / "artifacts").mkdir(parents=True)

    with pytest.raises(JobAccessError, match="ownerless"):
        repository.register_owner("empty-job", "local")
    with pytest.raises(JobAccessError, match="ownerless"):
        repository.register_owner("legacy-job", "local")

    job_path, owned = repository.prepare_job(
        "legacy-job",
        "local",
        create=True,
        allow_legacy=True,
    )
    assert job_path == legacy
    assert owned is False
    assert not (empty / ".owner").exists()
    assert not (legacy / ".owner").exists()


def test_repository_rejects_malformed_legacy_markers(tmp_path) -> None:
    repository = JobRepository(tmp_path)
    job_path = tmp_path / "legacy-job"
    job_path.mkdir()
    (job_path / "checkpoint.json").mkdir()

    with pytest.raises(JobAccessError, match="unsafe"):
        repository.prepare_job("legacy-job", "local", create=False, allow_legacy=True)


def test_repository_rejects_linked_legacy_descendants(tmp_path) -> None:
    repository = JobRepository(tmp_path / "cache")
    job_path = repository.base_path / "legacy-job"
    artifacts = job_path / "artifacts"
    artifacts.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (artifacts / "js").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(JobAccessError, match="unsafe"):
        repository.prepare_job("legacy-job", "local", create=False, allow_legacy=True)


@pytest.mark.asyncio
async def test_repository_owner_registration_is_atomic_under_concurrency(tmp_path) -> None:
    repositories = [JobRepository(tmp_path) for _ in range(16)]
    await asyncio.gather(
        *[
            asyncio.to_thread(repository.register_owner, "same-job", "alice")
            for repository in repositories
        ]
    )
    assert (tmp_path / "same-job" / ".owner").read_bytes() == b"alice"

    principals = ["alice", "bob"] * 8

    def attempt(repository: JobRepository, principal: str) -> bool:
        try:
            repository.register_owner("contested-job", principal)
        except JobAccessError:
            return False
        return True

    results = await asyncio.gather(
        *[
            asyncio.to_thread(attempt, repository, principal)
            for repository, principal in zip(repositories, principals, strict=True)
        ]
    )
    winner = (tmp_path / "contested-job" / ".owner").read_text(encoding="utf-8")
    assert winner in {"alice", "bob"}
    assert results == [principal == winner for principal in principals]


def test_repository_owner_publish_failure_leaves_no_empty_final_file(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bundleInspector.storage.atomic as atomic_module

    owner_path = tmp_path / "job-1" / ".owner"
    original_replace = atomic_module._replace_path

    def fail_owner_replace(source, destination) -> None:
        if Path(destination) == owner_path:
            raise OSError("injected owner publish failure")
        original_replace(source, Path(destination))

    monkeypatch.setattr(atomic_module, "_replace_path", fail_owner_replace)
    with pytest.raises(OSError, match="injected owner publish failure"):
        JobRepository(tmp_path).register_owner("job-1", "alice")

    assert not owner_path.exists()
    assert not list(owner_path.parent.glob(".owner.*.tmp"))

    (owner_path.parent / "artifacts").mkdir()
    with pytest.raises(JobAccessError):
        JobRepository(tmp_path).prepare_job(
            "job-1",
            "bob",
            create=True,
            allow_legacy=True,
        )

    monkeypatch.setattr(atomic_module, "_replace_path", original_replace)
    JobRepository(tmp_path).register_owner("job-1", "alice")
    assert owner_path.read_text(encoding="utf-8") == "alice"


@pytest.mark.asyncio
async def test_repository_read_only_sidecars_preserve_locked_report_and_key_reads(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bundleInspector.storage.atomic as atomic_module

    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "local")
    report = _report()
    await FindingStore(tmp_path / "job-1").store_report(report)
    signing_key = repository.public_signing_key
    report_path = tmp_path / "job-1" / "reports" / "report-1.json"
    report_lock = atomic_module._lock_path(report_path)
    key_path = tmp_path / ".public-view-key"
    key_lock = atomic_module._lock_path(key_path)
    guarded_locks = {report_lock, key_lock}
    original_open = atomic_module._open_lock_handle

    def reject_writable(path: Path, *, writable: bool, create: bool):
        if path in guarded_locks and writable:
            raise PermissionError(errno.EACCES, "read-only sidecar", str(path))
        return original_open(path, writable=writable, create=create)

    monkeypatch.setattr(atomic_module, "_open_lock_handle", reject_writable)
    protected_files = (report_path, report_lock, key_path, key_lock)
    protected_dirs = (report_path.parent, tmp_path)
    try:
        for path in protected_files:
            path.chmod(0o444)
        for path in protected_dirs:
            path.chmod(0o555)

        restored = await repository.get_report("job-1", "local", "report-1")
        assert restored is not None and restored.id == "report-1"
        assert JobRepository(tmp_path).public_signing_key == signing_key
    finally:
        for path in reversed(protected_dirs):
            path.chmod(0o755)
        for path in protected_files:
            path.chmod(0o600)

    report_lock.unlink()
    with pytest.raises(FileNotFoundError):
        atomic_read_text(report_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["report_id", "job_id"])
async def test_repository_rejects_report_payload_identity_mismatch(
    tmp_path,
    mismatch: str,
) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("job-1", "local")
    reports = tmp_path / "job-1" / "reports"
    reports.mkdir()
    report = _report()
    report.id = "stored-report"
    report.job_id = "job-1"
    if mismatch == "report_id":
        report.id = "payload-report"
    else:
        report.job_id = "other-job"
    (reports / "stored-report.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="identity"):
        await repository.get_report("job-1", "local", "stored-report")

    repository.register_owner("valid-job", "local")
    valid = _report()
    valid.id = "valid-report"
    valid.job_id = "valid-job"
    await FindingStore(tmp_path / "valid-job").store_report(valid)
    service = MCPService(repository)
    listed = await service.list_jobs(limit=10)
    assert [row["job_id"] for row in listed["jobs"]] == [
        service._public_id("job", "valid-job")
    ]
    public_job_id = service._public_id("job", "job-1")
    assert public_job_id != "job-1"
    with pytest.raises(PublicResourceUnavailable, match="resource unavailable"):
        await service.get_report_page(public_job_id)


@pytest.mark.asyncio
async def test_repository_does_not_list_or_read_hardlinked_reports(tmp_path) -> None:
    repository = JobRepository(tmp_path / "cache")
    repository.register_owner("job-1", "local")
    reports = repository.base_path / "job-1" / "reports"
    reports.mkdir()
    outside_report = tmp_path / "outside-report.json"
    report = _report()
    outside_report.write_text(report.model_dump_json(), encoding="utf-8")
    hardlinked_report = reports / "report-1.json"
    try:
        os.link(outside_report, hardlinked_report)
    except OSError:
        pytest.skip("hardlink creation is unavailable on this platform")

    assert await repository.list_report_ids("job-1", "local") == []
    with pytest.raises(UnsafePathError):
        await repository.get_report("job-1", "local", "report-1")


@pytest.mark.asyncio
async def test_repository_and_service_reject_nonfinite_report_numbers(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = JobRepository(tmp_path)
    repository.register_owner("bad-job", "local")
    reports = tmp_path / "bad-job" / "reports"
    reports.mkdir()
    payload = _report().model_dump(mode="json")
    payload["id"] = "bad-report"
    payload["job_id"] = "bad-job"
    payload["duration_seconds"] = float("inf")
    (reports / "bad-report.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationError, match="finite number"):
        await repository.get_report("bad-job", "local", "bad-report")

    repository.register_owner("valid-job", "local")
    valid = _report()
    valid.id = "valid-report"
    valid.job_id = "valid-job"
    await FindingStore(tmp_path / "valid-job").store_report(valid)
    service = MCPService(repository)
    listed = await service.list_jobs(limit=10)
    assert [row["job_id"] for row in listed["jobs"]] == [
        service._public_id("job", "valid-job")
    ]

    mutated = valid.model_copy(deep=True)
    mutated.findings[0].risk_score = float("nan")

    async def mutated_report(*_args, **_kwargs):
        return mutated

    monkeypatch.setattr(repository, "get_report", mutated_report)
    with pytest.raises(PublicResourceUnavailable, match="resource unavailable"):
        await service.get_report_page(service._public_id("job", "valid-job"), limit=1)


@pytest.mark.asyncio
async def test_repository_rejects_linked_job_owner_and_report_paths(tmp_path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / ".owner").write_text("local", encoding="utf-8")
    linked_job = tmp_path / "linked-job"
    try:
        linked_job.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")

    repository = JobRepository(tmp_path)
    with pytest.raises(ValueError, match="links|escapes"):
        repository.assert_access("linked-job", "local")

    linked_owner_job = tmp_path / "linked-owner"
    linked_owner_job.mkdir()
    (linked_owner_job / ".owner").symlink_to(outside / ".owner")
    with pytest.raises(ValueError, match="links|escapes"):
        repository.assert_access("linked-owner", "local")

    repository.register_owner("job-1", "local")
    reports = tmp_path / "job-1" / "reports"
    reports.mkdir()
    outside_report = outside / "report.json"
    outside_report.write_text(_report().model_dump_json(), encoding="utf-8")
    (reports / "linked-report.json").symlink_to(outside_report)
    assert "linked-report" not in await repository.list_report_ids("job-1", "local")
