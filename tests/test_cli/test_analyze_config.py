"""Tests for analyze command config integration.

Any token-like literals in this module are fake sample values used for testing.
They are not real secrets.
"""

import json
import uuid
from pathlib import Path

from click.testing import CliRunner
import pytest

from tests.fixtures.fake_secrets import FAKE_STRIPE_LIVE
from bundleInspector.cli import _run_local_analysis, main
from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.models import Category, Confidence, Evidence, Finding, PipelineCheckpoint, Severity, JSAsset

TEST_TMP_ROOT = Path(".tmp_test_artifacts")
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _make_test_path(name: str) -> Path:
    """Create a unique path under the workspace-local sandbox."""
    return (TEST_TMP_ROOT / f"{uuid.uuid4().hex}_{name}").resolve()


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
    """Analyze should recover the latest stored report for the same job id."""
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

    # Change the input so a non-resumed run would differ.
    js_path.write_text('const marker = "CHANGED_MARKER";', encoding="utf-8")

    resumed = CliRunner().invoke(
        main,
        ["analyze", str(js_path), "--config", str(config_path), "--job-id", "resume-job", "--resume", "--quiet"],
    )
    assert resumed.exit_code == 0, resumed.output
    report_after = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_after["id"] == report_before["id"]
    assert report_after["job_id"] == "resume-job"
    assert any(f["rule_id"] == "custom-debug-marker" for f in report_after["findings"])


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
            stage_state={"analyze_complete_hashes": [asset.content_hash]},
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
            stage_state={"normalize_complete_hashes": [asset.content_hash]},
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

