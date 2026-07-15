"""Tests for analyze command config integration.

Any token-like literals in this module are fake sample values used for testing.
They are not real secrets.
"""

import base64
import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

import bundleInspector.cli as cli_module
from bundleInspector.cli import _run_local_analysis, main
from bundleInspector.config import Config
from bundleInspector.core.resume_policy import (
    build_local_resume_signature,
    build_stage_state_with_resume_signature,
)
from bundleInspector.mcp_server.service import MCPService
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.atomic import UnsafePathError
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.job_repository import JobAccessError, JobRepository
from bundleInspector.storage.models import (
    AnalysisCompleteness,
    Category,
    CompletenessIssue,
    CompletenessStatus,
    Confidence,
    Evidence,
    Finding,
    JSAsset,
    PipelineCheckpoint,
    Severity,
)
from tests.fixtures.fake_secrets import FAKE_STRIPE_LIVE

TEST_TMP_ROOT = Path(".tmp_test_artifacts")
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _make_test_path(name: str) -> Path:
    """Create a unique path under the workspace-local sandbox."""
    return (TEST_TMP_ROOT / f"{uuid.uuid4().hex}_{name}").resolve()


def _local_resume_stage_state(
    config: Config,
    *,
    recursive: bool = True,
    include_json: bool = False,
    stage_state: dict | None = None,
    input_paths: list[str] | None = None,
) -> dict:
    # input_paths mirrors production: a real checkpoint embeds the content-aware resume signature
    # (DQ-C05), so a checkpoint built for the SAME unchanged input matches the run and is reused.
    return build_stage_state_with_resume_signature(
        stage_state,
        build_local_resume_signature(
            config,
            recursive=recursive,
            include_json=include_json,
            input_paths=input_paths,
        ),
    )


def test_analyze_uses_config_file_and_custom_rules():
    """Analyze should honor config-file output and custom rule settings."""
    js_path = _make_test_path("bundle.js")
    report_path = _make_test_path("report.json")
    cache_dir = _make_test_path("cache")
    rules_path = _make_test_path("rules.json")
    config_path = _make_test_path("config.json")
    cache_dir.mkdir(parents=True, exist_ok=True)

    js_path.write_text(
        'const marker = "INTERNAL_DEBUG_MARKER";',
        encoding="utf-8",
    )
    rules_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-debug-marker",
                        "title": "Internal Debug Marker",
                        "category": "debug",
                        "severity": "medium",
                        "confidence": "high",
                        "value_type": "debug_marker",
                        "pattern": "INTERNAL_DEBUG_MARKER",
                        "scope": "string_literal",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config_path.write_text(
        json.dumps(
            {
                "rules": {
                    "custom_rules_file": str(rules_path),
                },
                "output": {
                    "format": "json",
                    "output_file": str(report_path),
                },
                "cache_dir": str(cache_dir),
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--quiet"],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["job_id"]
    assert report["findings"]
    assert any(f["rule_id"] == "custom-debug-marker" for f in report["findings"])
    stored_report = cache_dir / report["job_id"] / "reports" / f"{report['id']}.json"
    assert stored_report.exists()


def test_analyze_resume_reuses_latest_stored_report():
    """Analyze should recover the latest stored report for the same job id WHEN THE INPUT IS
    UNCHANGED (the resume signature now folds in input content, DQ-C05)."""
    js_path = _make_test_path("bundle.js")
    report_path = _make_test_path("report.json")
    cache_dir = _make_test_path("cache")
    rules_path = _make_test_path("rules.json")
    config_path = _make_test_path("config.json")
    cache_dir.mkdir(parents=True, exist_ok=True)

    js_path.write_text('const marker = "INTERNAL_DEBUG_MARKER";', encoding="utf-8")
    rules_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom-debug-marker",
                        "title": "Internal Debug Marker",
                        "category": "debug",
                        "severity": "medium",
                        "confidence": "high",
                        "value_type": "debug_marker",
                        "pattern": "INTERNAL_DEBUG_MARKER",
                        "scope": "string_literal",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config_path.write_text(
        json.dumps(
            {
                "rules": {
                    "custom_rules_file": str(rules_path),
                },
                "output": {
                    "format": "json",
                    "output_file": str(report_path),
                },
                "cache_dir": str(cache_dir),
            }
        ),
        encoding="utf-8",
    )

    first = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--job-id", "resume-job", "--quiet"],
    )
    assert first.exit_code == 0, first.output
    report_before = json.loads(report_path.read_text(encoding="utf-8"))

    # Input UNCHANGED -> the stored report is reused (same id).
    resumed = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--job-id", "resume-job", "--resume", "--quiet"],
    )
    assert resumed.exit_code == 0, resumed.output
    report_after = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_after["id"] == report_before["id"]
    assert report_after["job_id"] == "resume-job"
    assert any(f["rule_id"] == "custom-debug-marker" for f in report_after["findings"])


def test_analyze_resume_reanalyzes_when_input_file_changed():
    """DQ-C05: overwriting a local input file (same path) must INVALIDATE the stored report on
    --resume and re-analyze the new content -- never return the stale report. The signature folds
    in an input content inventory, so a changed file yields a different signature."""
    js_path = _make_test_path("bundle_changed.js")
    report_path = _make_test_path("report_changed.json")
    cache_dir = _make_test_path("cache_changed")
    config_path = _make_test_path("config_changed.json")
    cache_dir.mkdir(parents=True, exist_ok=True)

    js_path.write_text('fetch("/api/old"); const marker = "INTERNAL_DEBUG_MARKER";', encoding="utf-8")
    config_path.write_text(
        json.dumps({
            "output": {"format": "json", "output_file": str(report_path)},
            "cache_dir": str(cache_dir),
        }),
        encoding="utf-8",
    )

    first = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--job-id", "changed-job", "--quiet"],
    )
    assert first.exit_code == 0, first.output
    report_before = json.loads(report_path.read_text(encoding="utf-8"))
    ghp = "ghp_" + "a" * 36

    # Overwrite the SAME path with new content (new endpoint + a provider secret).
    js_path.write_text(f'fetch("/api/new-admin"); const k = "{ghp}";', encoding="utf-8")

    resumed = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--job-id", "changed-job", "--resume", "--quiet"],
    )
    assert resumed.exit_code == 0, resumed.output
    report_after = json.loads(report_path.read_text(encoding="utf-8"))

    # re-analyzed (fresh report), NOT the stale one
    assert report_after["id"] != report_before["id"]
    values = {f.get("extracted_value", "") for f in report_after["findings"]}
    joined = " ".join(values)
    assert "/api/new-admin" in joined                 # new endpoint found
    assert not any("/api/old" == v for v in values)   # stale endpoint gone
    assert any(f["category"] == "secret" for f in report_after["findings"])  # new secret found


def test_analyze_resume_ignores_stored_report_when_analysis_config_changes():
    """Analyze should not reuse a stored report across parser/rule config changes."""
    js_path = _make_test_path("bundle_resume_mismatch.js")
    report_path = _make_test_path("report_resume_mismatch.json")
    cache_dir = _make_test_path("cache_resume_mismatch")
    config_a = _make_test_path("config_resume_a.json")
    config_b = _make_test_path("config_resume_b.json")
    cache_dir.mkdir(parents=True, exist_ok=True)

    js_path.write_text('const marker = "INTERNAL_DEBUG_MARKER";', encoding="utf-8")
    config_a.write_text(
        json.dumps(
            {
                "output": {"format": "json", "output_file": str(report_path)},
                "cache_dir": str(cache_dir),
                "parser": {"beautify": True},
            }
        ),
        encoding="utf-8",
    )
    config_b.write_text(
        json.dumps(
            {
                "output": {"format": "json", "output_file": str(report_path)},
                "cache_dir": str(cache_dir),
                "parser": {"beautify": False},
            }
        ),
        encoding="utf-8",
    )

    first = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_a), "--job-id", "resume-config-change", "--quiet"],
    )
    assert first.exit_code == 0, first.output
    report_before = json.loads(report_path.read_text(encoding="utf-8"))

    second = CliRunner().invoke(
        main,
        [
            "analyze",
            str(js_path),
            "--config",
            str(config_b),
            "--job-id",
            "resume-config-change",
            "--resume",
            "--quiet",
        ],
    )
    assert second.exit_code == 0, second.output
    report_after = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_after["id"] != report_before["id"]


def test_analyze_honors_output_dir_and_secret_masking_from_config():
    """Analyze should honor output.output_dir and rules.mask_secrets from config files."""
    js_path = _make_test_path("bundle_secret.js")
    output_dir = _make_test_path("report_dir")
    cache_dir = _make_test_path("cache_secret")
    config_path = _make_test_path("config_secret.json")
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    secret = FAKE_STRIPE_LIVE
    js_path.write_text(
        f'const stripeKey = "{secret}";',
        encoding="utf-8",
    )
    config_path.write_text(
        json.dumps(
            {
                "rules": {
                    "mask_secrets": False,
                },
                "output": {
                    "format": "json",
                    "output_dir": str(output_dir),
                },
                "cache_dir": str(cache_dir),
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--quiet"],
    )

    assert result.exit_code == 0, result.output
    report_path = output_dir / "bundleInspector_local_report.json"
    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    secret_findings = [f for f in report["findings"] if f["category"] == "secret"]
    assert secret_findings
    assert any(f["extracted_value"] == secret for f in secret_findings)


@pytest.mark.asyncio
async def test_local_analysis_resumes_from_checkpoint_without_final_report():
    """Local analysis should continue from a stage checkpoint even without a final report."""
    cache_dir = _make_test_path("cache_resume")
    js_path = _make_test_path("resume_bundle.js")
    cache_dir.mkdir(parents=True, exist_ok=True)
    js_path.write_text('const marker = "IGNORED_AFTER_RESUME";', encoding="utf-8")

    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "local-checkpoint-job"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)

    asset = JSAsset(
        url=js_path.as_uri(),
        content=b'const marker = "INTERNAL_DEBUG_MARKER";',
        content_hash="",
        parse_success=True,
    )
    asset.compute_hash()
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)

    finding = Finding(
        rule_id="custom-debug-marker",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Internal Debug Marker",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="INTERNAL_DEBUG_MARKER",
        metadata={"is_first_party": True},
    )
    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=config.job_id,
            seed_urls=[str(js_path)],
            stage="analyze",
            asset_hashes=[asset.content_hash],
            findings=[finding],
            stage_state=_local_resume_stage_state(config, input_paths=[str(js_path)]),
        )
    )

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.job_id == config.job_id
    assert any(f.rule_id == "custom-debug-marker" for f in report.findings)


@pytest.mark.asyncio
async def test_local_analysis_ignores_checkpoint_when_analysis_config_changes():
    """Local analysis should not resume a stale checkpoint from a different config profile."""
    cache_dir = _make_test_path("cache_resume_signature_mismatch")
    js_path = _make_test_path("resume_signature_mismatch_bundle.js")
    cache_dir.mkdir(parents=True, exist_ok=True)
    js_path.write_text('fetch("/api/users");', encoding="utf-8")

    stale_config = Config()
    stale_config.cache_dir = cache_dir
    stale_config.job_id = "local-signature-mismatch-job"
    stale_config.resume = True
    stale_config.parser.beautify = True
    stale_config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / stale_config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / stale_config.job_id)

    stale_asset = JSAsset(
        url=js_path.as_uri(),
        content=b'const marker = "STALE_CHECKPOINT";',
        content_hash="",
        parse_success=True,
    )
    stale_asset.compute_hash()
    await artifact_store.store_js(stale_asset.content, stale_asset.url)
    await artifact_store.store_asset_meta(stale_asset)

    stale_finding = Finding(
        rule_id="stale-checkpoint",
        category=Category.DEBUG,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Stale Finding",
        evidence=Evidence(
            file_url=stale_asset.url,
            file_hash=stale_asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="STALE_CHECKPOINT",
    )
    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=stale_config.job_id,
            seed_urls=[str(js_path)],
            stage="analyze",
            asset_hashes=[stale_asset.content_hash],
            findings=[stale_finding],
            stage_state=_local_resume_stage_state(stale_config),
        )
    )

    fresh_config = Config()
    fresh_config.cache_dir = cache_dir
    fresh_config.job_id = stale_config.job_id
    fresh_config.resume = True
    fresh_config.parser.beautify = False
    fresh_config.ensure_dirs()

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=fresh_config,
    )

    assert report.job_id == fresh_config.job_id
    assert all(f.rule_id != "stale-checkpoint" for f in report.findings)
    assert any(f.category == Category.ENDPOINT for f in report.findings)


@pytest.mark.asyncio
async def test_local_analysis_resumes_partial_analyze_checkpoint():
    """Local analysis should reuse findings already produced inside an unfinished analyze stage."""
    cache_dir = _make_test_path("cache_partial_resume")
    js_path = _make_test_path("partial_resume_bundle.js")
    cache_dir.mkdir(parents=True, exist_ok=True)
    js_path.write_text('const marker = "IGNORED_AFTER_RESUME";', encoding="utf-8")

    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "local-partial-analyze-job"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)

    source = 'const marker = "INTERNAL_DEBUG_MARKER";'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url=js_path.as_uri(),
        content=source.encode("utf-8"),
        content_hash="",
        parse_success=True,
    )
    asset.compute_hash()
    asset.ast_hash = await artifact_store.store_ast(parse_result.ast, asset.content_hash)
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)

    finding = Finding(
        rule_id="custom-debug-marker",
        category=Category.DEBUG,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Internal Debug Marker",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="INTERNAL_DEBUG_MARKER",
    )
    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=config.job_id,
            seed_urls=[str(js_path)],
            stage="parse",
            asset_hashes=[asset.content_hash],
            findings=[finding],
            stage_state=_local_resume_stage_state(
                config,
                stage_state={"analyze_complete_hashes": [asset.content_hash]},
                input_paths=[str(js_path)],
            ),
        )
    )

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.job_id == config.job_id
    assert len(report.findings) == 1
    assert report.findings[0].extracted_value == "INTERNAL_DEBUG_MARKER"


@pytest.mark.asyncio
async def test_local_analysis_includes_outer_scope_import_alias_metadata():
    """Local analyze should surface inner-scope aliases derived from outer-scope import bindings."""
    cache_dir = _make_test_path("cache_local_alias_scope")
    js_path = _make_test_path("alias_scope_bundle.js")
    cache_dir.mkdir(parents=True, exist_ok=True)
    js_path.write_text(
        """
        const stripeKey = "__STRIPE__";
        async function boot() {
          const api = await import("./chunk");
          function inner() {
            const loadUsers = api.loadUsers;
            return loadUsers();
          }
          return inner();
        }
        """.replace("__STRIPE__", FAKE_STRIPE_LIVE),
        encoding="utf-8",
    )

    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "local-alias-scope-job"
    config.ensure_dirs()

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.findings
    finding = next(f for f in report.findings if f.category == Category.SECRET)
    assert {
        "source": "./chunk",
        "imported": "*",
        "local": "api",
        "kind": "namespace",
        "scope": "function:boot",
        "is_dynamic": True,
    } in finding.metadata["import_bindings"]
    assert {
        "source": "./chunk",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "function:inner",
        "is_dynamic": True,
        "is_alias": True,
        "is_member_alias": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_local_analysis_includes_named_object_export_metadata():
    """Local analyze should surface named object export members under exported aliases."""
    cache_dir = _make_test_path("cache_local_named_object_exports")
    js_path = _make_test_path("named_object_exports_bundle.js")
    cache_dir.mkdir(parents=True, exist_ok=True)
    js_path.write_text(
        """
        const stripeKey = "__STRIPE__";
        function loadUsers() {
          return "/api/users";
        }
        const client = { loadUsers };
        export { client as sdk };
        """.replace("__STRIPE__", FAKE_STRIPE_LIVE),
        encoding="utf-8",
    )

    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "local-named-object-exports-job"
    config.ensure_dirs()

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.findings
    finding = next(f for f in report.findings if f.category == Category.SECRET)
    assert finding.metadata["export_scopes"]["loadUsers"] == ["function:loadUsers"]
    assert finding.metadata["named_object_exports"] == {"sdk": ["loadUsers"]}


@pytest.mark.asyncio
async def test_local_analysis_resumes_partial_normalize_checkpoint(monkeypatch):
    """Local analysis should skip already-normalized assets inside an unfinished normalize stage."""
    cache_dir = _make_test_path("cache_partial_normalize")
    js_path = _make_test_path("partial_normalize_bundle.js")
    cache_dir.mkdir(parents=True, exist_ok=True)
    js_path.write_text('fetch("/api/users");', encoding="utf-8")

    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "local-partial-normalize-job"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)

    asset = JSAsset(
        url=js_path.as_uri(),
        content=b'fetch("/api/users");',
        content_hash="",
    )
    asset.compute_hash()
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)

    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=config.job_id,
            seed_urls=[str(js_path)],
            stage="collect",
            asset_hashes=[asset.content_hash],
            stage_state=_local_resume_stage_state(
                config,
                stage_state={"normalize_complete_hashes": [asset.content_hash]},
            ),
        )
    )

    monkeypatch.setattr(
        "bundleInspector.normalizer.beautify.Beautifier.beautify",
        lambda self, content: (_ for _ in ()).throw(AssertionError("beautify should not run")),
    )

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.job_id == config.job_id
    assert any(f.category.value == "endpoint" for f in report.findings)


@pytest.mark.asyncio
async def test_local_semantic_variants_and_completeness_survive_checkpoint_resume(tmp_path):
    source = 'const value: string = location.hash; document.body.innerHTML = value;'
    js_path = tmp_path / "same.js"
    ts_path = tmp_path / "same.ts"
    js_path.write_text(source, encoding="utf-8")
    ts_path.write_text(source, encoding="utf-8")
    paths = [str(js_path), str(ts_path)]
    cache_dir = tmp_path / "cache"

    fresh_config = Config()
    fresh_config.cache_dir = cache_dir
    fresh_config.job_id = "semantic-variant-resume"
    fresh_config.ensure_dirs()
    fresh = await _run_local_analysis(
        paths=paths,
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=fresh_config,
    )

    checkpoint = await FindingStore(cache_dir / fresh_config.job_id).get_checkpoint()
    assert checkpoint is not None
    assert len(checkpoint.stage_state["local_asset_metadata"]) == 2
    assert len({item["id"] for item in checkpoint.stage_state["local_asset_metadata"]}) == 2
    assert len(fresh.assets) == 2
    assert {(asset.language_hint, Path(asset.url).suffix) for asset in fresh.assets} == {
        ("javascript", ".js"),
        ("typescript", ".ts"),
    }
    assert any(
        finding.rule_id == "taint-flow-detector"
        and finding.evidence.file_url == ts_path.as_uri()
        for finding in fresh.findings
    )

    resume_config = fresh_config.model_copy(deep=True)
    resume_config.resume = True
    resumed = await _run_local_analysis(
        paths=paths,
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=resume_config,
    )

    def finding_signature(report):
        return sorted(
            (finding.rule_id, finding.evidence.file_url, finding.extracted_value)
            for finding in report.findings
        )
    assert finding_signature(resumed) == finding_signature(fresh)
    assert sorted(asset.id for asset in resumed.assets) == sorted(asset.id for asset in fresh.assets)
    assert resumed.completeness.model_dump() == fresh.completeness.model_dump()


@pytest.mark.asyncio
async def test_local_checkpoint_rehydrates_stored_completeness_exactly(tmp_path):
    source = tmp_path / "checkpoint.js"
    source.write_text('fetch("/api/checkpoint");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "stored-completeness"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)
    asset = JSAsset(url=source.as_uri(), content=source.read_bytes())
    asset.compute_hash()
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)
    stored_issue = CompletenessIssue(
        code="local_file_unreadable",
        stage="collect",
        message="Local collection coverage degraded (permission_denied)",
        retryable=False,
        affected_count=3,
        details={"bounded": True},
    )
    await finding_store.store_checkpoint(PipelineCheckpoint(
        job_id=config.job_id,
        seed_urls=[str(source)],
        stage="analyze",
        asset_hashes=[asset.content_hash],
        stage_state=_local_resume_stage_state(config, input_paths=[str(source)]),
        completeness=AnalysisCompleteness(
            status=CompletenessStatus.PARTIAL,
            issues=[stored_issue],
        ),
    ))

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.completeness.status == CompletenessStatus.PARTIAL
    assert report.completeness.issues == [stored_issue]


@pytest.mark.asyncio
async def test_resumed_stage_does_not_double_replayed_completeness_issue(monkeypatch, tmp_path):
    source = tmp_path / "replayed.js"
    source.write_text('fetch("/api/replayed");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "replayed-completeness"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)
    asset = JSAsset(url=source.as_uri(), content=source.read_bytes())
    asset.compute_hash()
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)
    message = f"Normalization failed for {asset.url}: rerun failure"
    await finding_store.store_checkpoint(PipelineCheckpoint(
        job_id=config.job_id,
        seed_urls=[str(source)],
        stage="collect",
        asset_hashes=[asset.content_hash],
        stage_state=_local_resume_stage_state(config, input_paths=[str(source)]),
        completeness=AnalysisCompleteness(
            status=CompletenessStatus.PARTIAL,
            issues=[CompletenessIssue(
                code="normalization_exception",
                stage="normalize",
                message=message,
                retryable=True,
                affected_count=1,
            )],
        ),
    ))
    monkeypatch.setattr(
        "bundleInspector.normalizer.beautify.Beautifier.beautify",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("rerun failure")),
    )

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    replayed = [
        issue
        for issue in report.completeness.issues
        if issue.code == "normalization_exception" and issue.message == message
    ]
    assert len(replayed) == 1
    assert replayed[0].affected_count == 1


@pytest.mark.asyncio
async def test_collect_checkpoint_contains_fresh_collector_diagnostics(tmp_path):
    source = tmp_path / "oversized.js"
    source.write_bytes(b"x" * 2)
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "collector-diagnostic-checkpoint"
    config.crawler.max_file_size = 1
    config.ensure_dirs()

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )
    checkpoint = await FindingStore(config.cache_dir / config.job_id).get_checkpoint()

    assert report.completeness.status == CompletenessStatus.PARTIAL
    assert checkpoint is not None
    assert checkpoint.stage == "collect"
    assert checkpoint.completeness.model_dump() == report.completeness.model_dump()
    assert [issue.code for issue in checkpoint.completeness.issues] == ["local_file_oversized"]


@pytest.mark.asyncio
async def test_local_analysis_registers_owner_and_is_visible_through_mcp(tmp_path):
    source = tmp_path / "mcp-visible.js"
    source.write_text('fetch("/api/mcp-visible");', encoding="utf-8")
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "local-mcp-visible"
    config.ensure_dirs()

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )
    repository = JobRepository(config.cache_dir)
    service = MCPService(repository, principal_id="local")
    listed = await service.list_jobs(limit=10)

    assert (config.cache_dir / config.job_id / ".owner").read_text(encoding="utf-8") == "local"
    assert len(listed["jobs"]) == 1
    public_job_id = listed["jobs"][0]["job_id"]
    page = await service.get_report_page(public_job_id, page_kind="findings", limit=50)
    assert page["completeness"]["status"] == report.completeness.status.value
    assert any(
        finding["category"] == "endpoint" and finding["masked_value"] == "/api/mcp-visible"
        for finding in page["findings"]
    )


@pytest.mark.asyncio
async def test_local_analysis_rejects_foreign_owned_resume_and_writes(tmp_path):
    source = tmp_path / "foreign.js"
    source.write_text('fetch("/api/foreign");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    repository = JobRepository(cache_dir)
    repository.register_owner("foreign-job", "alice")
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "foreign-job"
    config.resume = True

    with pytest.raises(JobAccessError):
        await _run_local_analysis(
            paths=[str(source)],
            recursive=True,
            include_json=False,
            verbose=False,
            quiet=True,
            config=config,
        )

    job_root = cache_dir / "foreign-job"
    assert (job_root / ".owner").read_text(encoding="utf-8") == "alice"
    assert not (job_root / "artifacts").exists()
    assert not (job_root / "findings").exists()
    assert not (job_root / "reports").exists()


@pytest.mark.asyncio
async def test_local_analysis_rejects_malformed_ownerless_legacy_storage(tmp_path):
    source = tmp_path / "legacy.js"
    source.write_text('fetch("/api/legacy");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    job_root = cache_dir / "unsafe-legacy"
    job_root.mkdir(parents=True)
    (job_root / "artifacts").write_text("not a directory", encoding="utf-8")
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "unsafe-legacy"

    with pytest.raises(JobAccessError, match="unsafe"):
        await _run_local_analysis(
            paths=[str(source)],
            recursive=True,
            include_json=False,
            verbose=False,
            quiet=True,
            config=config,
        )

    assert not (job_root / ".owner").exists()
    assert (job_root / "artifacts").read_text(encoding="utf-8") == "not a directory"


@pytest.mark.asyncio
async def test_local_analysis_propagates_a_hardlinked_owner_as_unsafe_storage(tmp_path: Path) -> None:
    source = tmp_path / "hardlinked.js"
    source.write_text('fetch("/api/hardlinked");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    job_id = "hardlinked-owner"
    job_root = cache_dir / job_id
    job_root.mkdir(parents=True)
    outside_owner = tmp_path / "outside-owner"
    outside_owner.write_text("local", encoding="utf-8")
    try:
        os.link(outside_owner, job_root / ".owner")
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = job_id

    with pytest.raises(UnsafePathError, match="link count is not one"):
        await _run_local_analysis(
            paths=[str(source)],
            recursive=True,
            include_json=False,
            verbose=False,
            quiet=True,
            config=config,
        )

    assert outside_owner.read_text(encoding="utf-8") == "local"
    assert not (job_root / "artifacts").exists()


@pytest.mark.asyncio
async def test_ownerless_legacy_local_job_remains_private(tmp_path):
    source = tmp_path / "legacy.js"
    source.write_text('fetch("/api/legacy");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    job_id = "ownerless-legacy"
    ArtifactStore(cache_dir / job_id / "artifacts")
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = job_id

    await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert not (cache_dir / job_id / ".owner").exists()
    assert job_id not in JobRepository(cache_dir).list_job_ids("local")


@pytest.mark.asyncio
async def test_missing_checkpoint_artifact_forces_full_local_recollection(tmp_path):
    source = tmp_path / "recollect.js"
    source.write_text('fetch("/api/recollected");', encoding="utf-8")
    cache_dir = tmp_path / "cache"
    job_id = "missing-checkpoint-artifact"
    repository = JobRepository(cache_dir)
    repository.register_owner(job_id, "local")
    artifact_store = ArtifactStore(cache_dir / job_id / "artifacts")
    finding_store = FindingStore(cache_dir / job_id)
    asset = JSAsset(url=source.as_uri(), content=source.read_bytes())
    asset.compute_hash()
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)
    (cache_dir / job_id / "artifacts" / "js" / f"{asset.content_hash}.js").unlink()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = job_id
    config.resume = True
    await finding_store.store_checkpoint(PipelineCheckpoint(
        job_id=job_id,
        seed_urls=[str(source)],
        stage="collect",
        asset_hashes=[asset.content_hash],
        stage_state=_local_resume_stage_state(config, input_paths=[str(source)]),
    ))

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert report.completeness.status == CompletenessStatus.COMPLETE
    assert any(
        finding.category == Category.ENDPOINT
        and finding.extracted_value == "/api/recollected"
        for finding in report.findings
    )


@pytest.mark.asyncio
async def test_local_sourcemap_mapping_budget_is_reported_as_partial(tmp_path):
    source = tmp_path / "mapped.js"
    source.write_text(
        'fetch("/api/mapped");\n//# sourceMappingURL=mapped.js.map\n',
        encoding="utf-8",
    )
    (tmp_path / "mapped.js.map").write_text(
        json.dumps({
            "version": 3,
            "sources": ["mapped.ts"],
            "sourcesContent": ['fetch("/api/original");'],
            "names": [],
            "mappings": "/" * 10_000,
        }),
        encoding="utf-8",
    )
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "local-map-budget"

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    issues = [
        issue
        for issue in report.completeness.issues
        if issue.code == "sourcemap_mapping_truncated"
    ]
    assert len(issues) == 1
    assert issues[0].stage == "normalize"
    assert issues[0].details == {"diagnostics": ["vlq_value_too_long"]}


@pytest.mark.asyncio
async def test_local_analysis_includes_dynamic_default_import_bindings():
    """Local analyze should annotate dynamic-import default destructuring bindings."""
    bundle_dir = _make_test_path("dynamic_default_dir")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    js_path = bundle_dir / "app.js"
    js_path.write_text(
        """
        async function boot() {
          const { default: chunkApi } = await import("./chunk");
          return fetch("/api/users").then(() => chunkApi());
        }
        """,
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    endpoint_findings = [f for f in report.findings if f.category == Category.ENDPOINT]
    assert endpoint_findings
    assert {
        "source": "./chunk",
        "imported": "default",
        "local": "chunkApi",
        "kind": "default",
        "scope": "function:boot",
        "is_dynamic": True,
    } in endpoint_findings[0].metadata["import_bindings"]


@pytest.mark.asyncio
async def test_local_analysis_includes_dynamic_then_default_import_bindings():
    """Local analyze should annotate `.then()` callback default destructuring bindings."""
    bundle_dir = _make_test_path("dynamic_then_default_dir")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    js_path = bundle_dir / "app.js"
    js_path.write_text(
        'import("./chunk").then(({ default: chunkApi }) => fetch("/api/users").then(() => chunkApi()));',
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    endpoint_findings = [f for f in report.findings if f.category == Category.ENDPOINT]
    assert endpoint_findings
    assert any(
        binding.get("source") == "./chunk"
        and binding.get("imported") == "default"
        and binding.get("local") == "chunkApi"
        and binding.get("kind") == "default"
        and binding.get("is_dynamic") is True
        and str(binding.get("scope") or "").startswith("function:arrow@")
        for binding in endpoint_findings[0].metadata["import_bindings"]
    )


@pytest.mark.asyncio
async def test_local_analysis_logs_normalization_warning(monkeypatch):
    """Normalization exceptions should be logged instead of being silently swallowed."""
    js_path = _make_test_path("normalize_warning_bundle.js")
    js_path.write_text('fetch("/api/users");', encoding="utf-8")

    warnings: list[tuple[str, dict]] = []

    def _fake_warning(event: str, **kwargs):
        warnings.append((event, kwargs))

    def _boom(self, content: str):
        raise RuntimeError("synthetic normalization failure")

    monkeypatch.setattr(cli_module.logger, "warning", _fake_warning)
    monkeypatch.setattr("bundleInspector.normalizer.beautify.Beautifier.beautify", _boom)

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    assert report.findings
    assert warnings
    assert warnings[0][0] == "normalization_error"
    assert warnings[0][1]["error"] == "synthetic normalization failure"
    # cli.py logs url=asset.url[:100] for log hygiene (mirrors local_asset_store_error), so the
    # assertion must mirror that [:100] truncation, NOT the full URI -- an absolute
    # .tmp_test_artifacts file URI exceeds 100 chars, which is what made this look flaky.
    assert warnings[0][1]["url"] == js_path.as_uri()[:100]


async def test_normalization_warning_url_truncated_to_100_regardless_of_cwd(monkeypatch):
    """The logged url is capped at 100 chars (hygiene) and stays a prefix of the real URI, no matter
    how deep the checkout path is -- pins the truncation contract that the fix above relies on."""
    js_path = _make_test_path("trunc_contract_bundle.js")
    js_path.write_text('fetch("/api/x");', encoding="utf-8")
    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(cli_module.logger, "warning",
                        lambda event, **kw: warnings.append((event, kw)))

    def _boom(self, content):
        raise RuntimeError("boom")
    monkeypatch.setattr("bundleInspector.normalizer.beautify.Beautifier.beautify", _boom)

    await _run_local_analysis(paths=[str(js_path)], recursive=True, include_json=False,
                              verbose=False, quiet=True, config=Config())
    url = warnings[0][1]["url"]
    assert len(url) <= 100
    assert js_path.as_uri().startswith(url)


async def test_single_file_analysis_ignores_sibling_files(monkeypatch):
    """A single FILE path collects ONLY that file and never globs its parent dir, so a stale sibling
    .js in the same dir is not analyzed (the recursive **/* glob applies to DIRECTORY paths only).
    Guards collect()'s single-file semantics against a refactor that reintroduces dir scanning --
    and disproves the earlier 'stale-file pollution' hypothesis for the flaky warning above."""
    js_path = _make_test_path("solo_bundle.js")
    js_path.write_text('fetch("/api/solo");', encoding="utf-8")
    sibling = js_path.parent / "sibling_should_be_ignored.js"
    sibling.write_text('fetch("/api/sibling");', encoding="utf-8")
    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(cli_module.logger, "warning",
                        lambda event, **kw: warnings.append((event, kw)))

    def _boom(self, content):
        raise RuntimeError("boom")
    monkeypatch.setattr("bundleInspector.normalizer.beautify.Beautifier.beautify", _boom)

    await _run_local_analysis(paths=[str(js_path)], recursive=True, include_json=False,
                              verbose=False, quiet=True, config=Config())
    norm = [w for w in warnings if w[0] == "normalization_error"]
    assert len(norm) == 1                                  # only the single file, not the sibling
    assert norm[0][1]["url"] == js_path.as_uri()[:100]


@pytest.mark.asyncio
async def test_local_analysis_preserves_original_content_hash_when_beautifying():
    """Local normalize should keep the raw asset hash and track beautified bytes separately."""
    js_path = _make_test_path("normalize_hash_bundle.js")
    source = 'const  value=1;\nfetch("/api/users");'
    js_path.write_text(source, encoding="utf-8")

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    assert report.assets
    asset = report.assets[0]
    original_hash = hashlib.sha256(js_path.read_bytes()).hexdigest()

    assert asset.content_hash == original_hash
    assert asset.normalized_hash is not None
    assert asset.normalized_hash != asset.content_hash


@pytest.mark.asyncio
async def test_local_analysis_skips_beautify_for_large_assets():
    """Local analyze should skip beautify when the configured size limit is exceeded."""
    js_path = _make_test_path("normalize_skip_large_bundle.js")
    source = 'const  value=1;\nfetch("/api/users");'
    js_path.write_text(source, encoding="utf-8")

    config = Config()
    config.parser.beautify_max_bytes = 8

    report = await _run_local_analysis(
        paths=[str(js_path)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    asset = report.assets[0]
    original_hash = hashlib.sha256(js_path.read_bytes()).hexdigest()

    assert asset.content_hash == original_hash
    assert asset.normalized_hash == asset.content_hash


@pytest.mark.asyncio
async def test_local_analysis_includes_commonjs_require_and_export_metadata():
    """Local analyze should annotate CommonJS require/import metadata for correlation."""
    bundle_dir = _make_test_path("commonjs_dir")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    js_path = bundle_dir / "app.js"
    js_path.write_text(
        """
        function fetchUsers() {}
        const api = require("./api");
        module.exports = fetchUsers;
        exports.loadUsers = fetchUsers;
        fetch("/api/users").then(() => api());
        """,
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    endpoint_findings = [f for f in report.findings if f.category == Category.ENDPOINT]
    assert endpoint_findings
    assert {
        "source": "./api",
        "imported": "default",
        "local": "api",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_commonjs": True,
    } in endpoint_findings[0].metadata["import_bindings"]
    assert "default" in endpoint_findings[0].metadata["exports"]
    assert "loadUsers" in endpoint_findings[0].metadata["exports"]


@pytest.mark.asyncio
async def test_local_analysis_includes_commonjs_reexport_metadata():
    """Local analyze should annotate CommonJS barrel re-export metadata."""
    bundle_dir = _make_test_path("commonjs_reexport_dir")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    js_path = bundle_dir / "app.js"
    js_path.write_text(
        """
        module.exports = require("./api");
        exports.loadUsers = require("./api").loadUsers;
        fetch("/api/users");
        """,
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    endpoint_findings = [f for f in report.findings if f.category == Category.ENDPOINT]
    assert endpoint_findings
    assert {
        "source": "./api",
        "imported": "default",
        "local": "default",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in endpoint_findings[0].metadata["re_export_bindings"]


@pytest.mark.asyncio
async def test_local_analysis_includes_commonjs_object_barrel_reexport_metadata():
    """Local analyze should annotate object-style CommonJS barrel re-export metadata."""
    bundle_dir = _make_test_path("commonjs_object_reexport_dir")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    js_path = bundle_dir / "app.js"
    js_path.write_text(
        """
        module.exports = { loadUsers: require("./api").loadUsers };
        fetch("/api/users");
        """,
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    endpoint_findings = [f for f in report.findings if f.category == Category.ENDPOINT]
    assert endpoint_findings
    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in endpoint_findings[0].metadata["re_export_bindings"]


@pytest.mark.asyncio
async def test_local_analysis_recovers_mts_cts_and_component_script_endpoints():
    bundle_dir = _make_test_path("local_languages")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "module.mts").write_text(
        'const endpoint: string = "/api/mts"; fetch(endpoint);',
        encoding="utf-8",
    )
    (bundle_dir / "common.cts").write_text(
        'const endpoint: string = "/api/cts"; fetch(endpoint);',
        encoding="utf-8",
    )
    (bundle_dir / "Account.vue").write_text(
        """
        <template><a href="/api/template-decoy">Account</a></template>
        <script setup lang="ts">
        const endpoint: string = "/api/vue";
        fetch(endpoint);
        </script>
        """,
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    endpoints = {finding.extracted_value for finding in report.findings}
    assert {"/api/mts", "/api/cts", "/api/vue"} <= endpoints
    assert "/api/template-decoy" not in endpoints
    assert {asset.language_hint for asset in report.assets} == {"typescript"}
    assert any("#bundleinspector-script-" in asset.url for asset in report.assets)


@pytest.mark.asyncio
async def test_local_analysis_uses_attached_map_as_artifact_and_analyzes_sources_content():
    bundle_dir = _make_test_path("local_sourcemap")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    source = bundle_dir / "bundle.js"
    source.write_text(
        "const generated = true;\n//# sourceMappingURL=bundle.js.map",
        encoding="utf-8",
    )
    map_path = bundle_dir / "bundle.js.map"
    map_path.write_text(
        json.dumps(
            {
                "version": 3,
                "sources": ["src/original.ts"],
                "sourcesContent": ['fetch("/api/source-only");'],
                "names": [],
                "mappings": "AAAA",
            }
        ),
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    assert len(report.assets) == 1
    assert report.assets[0].has_sourcemap is True
    assert report.assets[0].sourcemap_url == map_path.as_uri()
    original = next(
        finding for finding in report.findings if finding.extracted_value == "/api/source-only"
    )
    assert original.evidence.file_url.endswith("src/original.ts")


@pytest.mark.asyncio
async def test_local_analysis_resolves_inline_map_without_network_access():
    source_map = json.dumps(
        {
            "version": 3,
            "sources": ["src/inline.tsx"],
            "sourcesContent": ['fetch("/api/inline-source");'],
            "names": [],
            "mappings": "AAAA",
        },
        separators=(",", ":"),
    )
    encoded = base64.b64encode(source_map.encode()).decode("ascii")
    source = _make_test_path("inline-map.js")
    source.write_text(
        f"const generated = true;\n//# sourceMappingURL=data:application/json;base64,{encoded}",
        encoding="utf-8",
    )

    report = await _run_local_analysis(
        paths=[str(source)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    assert report.assets[0].has_sourcemap is True
    assert any(
        finding.extracted_value == "/api/inline-source" for finding in report.findings
    )


@pytest.mark.asyncio
async def test_local_analysis_reports_malformed_attached_map_as_incomplete():
    bundle_dir = _make_test_path("malformed_local_sourcemap")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    source = bundle_dir / "bundle.js"
    source.write_text(
        'fetch("/api/generated");\n//# sourceMappingURL=bundle.js.map',
        encoding="utf-8",
    )
    (bundle_dir / "bundle.js.map").write_text("{not-json", encoding="utf-8")

    report = await _run_local_analysis(
        paths=[str(bundle_dir)],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=Config(),
    )

    assert report.completeness.status.value == "partial"
    assert any(
        issue.code == "sourcemap_resolution_failed"
        for issue in report.completeness.issues
    )
    assert any(error.startswith("sourcemap:") for error in report.assets[0].parse_errors)


@pytest.mark.asyncio
async def test_local_analysis_promotes_enrichment_event_for_identical_assets(
    monkeypatch,
    tmp_path,
):
    sources = [tmp_path / "enrichment-a.js", tmp_path / "enrichment-b.js"]
    for source in sources:
        source.write_text('fetch("/api/local-enrichment");', encoding="utf-8")
    original_build_analyzer = cli_module._build_analyzer

    def _build_failing_analyzer(config):
        analyzer = original_build_analyzer(config)

        def _fail_enrichment(*_args, **_kwargs):
            raise RuntimeError("sensitive-local-enrichment-detail")

        monkeypatch.setattr(analyzer, "_apply_mappings", _fail_enrichment)
        return analyzer

    monkeypatch.setattr(cli_module, "_build_analyzer", _build_failing_analyzer)
    config = Config(cache_dir=tmp_path / "cache", job_id="local-enrichment-event")

    report = await _run_local_analysis(
        paths=[str(source) for source in sources],
        recursive=True,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert any(
        finding.extracted_value == "/api/local-enrichment"
        for finding in report.findings
    )
    assert {issue.code for issue in report.completeness.issues} == {
        "asset_analysis_incomplete",
        "finding_enrichment_failed",
    }
    enrichment_issue = next(
        issue
        for issue in report.completeness.issues
        if issue.code == "finding_enrichment_failed"
    )
    assert enrichment_issue.details == {
        "component": "asset_enrichment",
        "reason": "failed",
        "partial_results": True,
    }
    expected_error = "asset analysis incomplete (component=asset_enrichment; reason=failed)"
    assert len(report.assets) == 2
    assert {asset.url for asset in report.assets} == {source.as_uri() for source in sources}
    assert all(asset.parse_errors == [expected_error] for asset in report.assets)
    assert "sensitive-local-enrichment-detail" not in json.dumps(
        {
            "details": enrichment_issue.details,
            "parse_errors": [asset.parse_errors for asset in report.assets],
        }
    )


@pytest.mark.asyncio
async def test_local_sourcemap_metadata_and_findings_survive_completed_report_resume(tmp_path):
    source = tmp_path / "bundle.js"
    source.write_text("const generated = true;", encoding="utf-8")
    (tmp_path / "bundle.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "sources": ["src/resumed.ts"],
                "sourcesContent": ['fetch("/api/resumed-source");'],
                "names": [],
                "mappings": "AAAA",
            }
        ),
        encoding="utf-8",
    )
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "local-map-resume"
    config.resume = True
    config.ensure_dirs()

    first = await _run_local_analysis(
        paths=[str(tmp_path)],
        recursive=False,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )
    resumed = await _run_local_analysis(
        paths=[str(tmp_path)],
        recursive=False,
        include_json=False,
        verbose=False,
        quiet=True,
        config=config,
    )

    assert first.assets[0].sourcemap_hash
    assert resumed.assets[0].has_sourcemap is True
    assert resumed.assets[0].sourcemap_hash == first.assets[0].sourcemap_hash
    assert any(
        finding.extracted_value == "/api/resumed-source" for finding in resumed.findings
    )

