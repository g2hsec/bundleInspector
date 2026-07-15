"""Tests for orchestrator behavior."""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from pathlib import Path

import pytest

import bundleInspector.storage.finding_store as finding_store_module
from bundleInspector.config import Config, CrawlerConfig, ThirdPartyPolicy
from bundleInspector.core.orchestrator import BundleInspector, Orchestrator
from bundleInspector.core.progress import PipelineStage
from bundleInspector.core.resume_policy import (
    build_remote_resume_signature,
    build_stage_state_with_resume_signature,
    embed_report_resume_signature,
)
from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping
from bundleInspector.normalizer.sourcemap import SourceMapInfo
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.atomic import UnsafePathError
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.job_repository import JobAccessError, JobRepository
from bundleInspector.storage.models import (
    AnalysisCompleteness,
    AssetProvenance,
    Category,
    CompletenessIssue,
    CompletenessStatus,
    Confidence,
    Evidence,
    Finding,
    JSAsset,
    JSReference,
    LoadMethod,
    PipelineCheckpoint,
    Report,
    Severity,
)
from tests.fixtures.fake_secrets import FAKE_STRIPE_LIVE

TEST_TMP_ROOT = Path(".tmp_test_artifacts")
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _make_test_dir() -> Path:
    """Create a unique workspace-local directory for orchestrator tests."""
    path = TEST_TMP_ROOT / f"{uuid.uuid4().hex}_orchestrator"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _resume_stage_state(config: Config, stage_state: dict | None = None) -> dict:
    return build_stage_state_with_resume_signature(
        stage_state,
        build_remote_resume_signature(config),
    )


class _FakeCollector:
    """Minimal async collector test double."""

    instances: list[str] = []

    def __init__(self, *args, **kwargs):
        type(self).instances.append(type(self).__name__)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

    async def collect(self, url, scope):
        if False:  # pragma: no cover - keeps this an async generator
            yield None


class FakeStaticCollector(_FakeCollector):
    instances: list[str] = []


class FakeMultiPageStaticCollector(_FakeCollector):
    instances: list[str] = []


class FakeHeadlessCollector(_FakeCollector):
    instances: list[str] = []


class FakeHeadlessMultiPageCollector(_FakeCollector):
    instances: list[str] = []


class FakeManifestCollector(_FakeCollector):
    instances: list[str] = []


class IntegrationStaticCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        del scope
        yield JSReference(
            url=f"{url}/static-entry.js",
            initiator=url,
            load_context=url,
        )


class IntegrationHeadlessCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        del scope
        yield JSReference(
            url=f"{url}/dashboard.js",
            initiator=url,
            load_context=f"{url}/dashboard",
        )
        yield JSReference(
            url=f"{url}/static-entry.js",
            initiator=url,
            load_context=f"{url}/dashboard",
        )


class IntegrationManifestCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        del scope
        yield JSReference(
            url=f"{url}/manifest-chunk.js",
            initiator=f"{url}/asset-manifest.json",
            load_context=f"{url}/asset-manifest.json",
            method=LoadMethod.MANIFEST,
        )
        yield JSReference(
            url=f"{url}/static-entry.js",
            initiator=f"{url}/asset-manifest.json",
            load_context=f"{url}/asset-manifest.json",
            method=LoadMethod.MANIFEST,
        )


class PhaseStaticCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        yield JSReference(url=f"{url}/static.js")


class PhaseHeadlessMultiPageCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        yield JSReference(url=f"{url}/headless.js")


class PhaseManifestCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        yield JSReference(url=f"{url}/manifest.js")


class StreamingStaticCollector(_FakeCollector):
    instances: list[str] = []

    async def collect(self, url, scope):
        yield JSReference(url=f"{url}/a.js")
        yield JSReference(url=f"{url}/b.js")


class ResumablePhaseStaticCollector(_FakeCollector):
    instances: list[str] = []
    loaded_states: list[dict] = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.on_page_complete = None

    def load_resume_state(self, state):
        type(self).loaded_states.append(dict(state))

    async def collect(self, url, scope):
        if self.on_page_complete:
            await self.on_page_complete({
                "visited_urls": [url, f"{url}/next"],
                "collected_js_urls": [f"{url}/resumed.js"],
                "pending_pages": [{"url": f"{url}/later", "depth": 1}],
            })
        yield JSReference(url=f"{url}/resumed.js")


class MidPageProgressStaticCollector(_FakeCollector):
    instances: list[str] = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.on_page_complete = None

    async def collect(self, url, scope):
        yield JSReference(url=f"{url}/a.js")
        if self.on_page_complete:
            await self.on_page_complete({
                "visited_urls": [url],
                "collected_js_urls": [f"{url}/a.js"],
                "pending_pages": [{"url": f"{url}/next", "depth": 1}],
                "inflight_page": {"url": url, "depth": 0},
            })
        yield JSReference(url=f"{url}/b.js")


@pytest.mark.asyncio
async def test_crawl_uses_multi_page_collectors_when_depth_enabled(monkeypatch):
    """Main scan path should honor max_depth by selecting recursive collectors."""
    config = Config(crawler=CrawlerConfig(max_depth=2, use_headless=True))
    orchestrator = Orchestrator(config)

    for fake in (
        FakeStaticCollector,
        FakeMultiPageStaticCollector,
        FakeHeadlessCollector,
        FakeHeadlessMultiPageCollector,
        FakeManifestCollector,
    ):
        fake.instances.clear()

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.StaticCollector", FakeStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.MultiPageStaticCollector", FakeMultiPageStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.HeadlessCollector", FakeHeadlessCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.HeadlessMultiPageCollector", FakeHeadlessMultiPageCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", _FakeCollector)

    await orchestrator._crawl_url("https://example.com")

    assert FakeMultiPageStaticCollector.instances
    assert FakeHeadlessMultiPageCollector.instances
    assert not FakeStaticCollector.instances
    assert not FakeHeadlessCollector.instances


@pytest.mark.asyncio
async def test_collectors_and_sourcemap_resolver_share_orchestrator_rate_limiter(
    monkeypatch,
):
    config = Config(crawler=CrawlerConfig(max_depth=0, use_headless=True))
    orchestrator = Orchestrator(config)
    collector_limiters = []
    resolver_limiters = []

    class _CapturingCollector(_FakeCollector):
        def __init__(self, *args, **kwargs):
            collector_limiters.append(kwargs["rate_limiter"])
            super().__init__(*args, **kwargs)

    class _Diagnostic:
        status = "not_found"

    class _CapturingSourceMapResolver:
        last_diagnostic = _Diagnostic()

        def __init__(self, *args, **kwargs):
            resolver_limiters.append(kwargs["rate_limiter"])

        async def setup(self):
            return None

        async def teardown(self):
            return None

        async def resolve(self, source, url):
            return None

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(
        "bundleInspector.core.orchestrator.is_url_safe",
        lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"),
    )
    monkeypatch.setattr(
        "bundleInspector.core.orchestrator.StaticCollector",
        _CapturingCollector,
    )
    monkeypatch.setattr(
        "bundleInspector.core.orchestrator.HeadlessCollector",
        _CapturingCollector,
    )
    monkeypatch.setattr(
        "bundleInspector.core.orchestrator.ManifestCollector",
        _CapturingCollector,
    )
    monkeypatch.setattr(
        "bundleInspector.core.orchestrator.SourceMapResolver",
        _CapturingSourceMapResolver,
    )
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)

    await orchestrator._crawl_url("https://example.com")
    asset = JSAsset(url="https://example.com/app.js", content=b"const value = 1;")
    asset.compute_hash()
    await orchestrator._stage_normalize([asset])

    assert len(collector_limiters) == 3
    assert all(limiter is orchestrator.rate_limiter for limiter in collector_limiters)
    assert resolver_limiters == [orchestrator.rate_limiter]


@pytest.mark.asyncio
async def test_run_integrates_headless_and_manifest_discovery_into_real_pipeline(monkeypatch):
    """A real pipeline run should process headless and manifest discoveries end-to-end with dedupe and metadata preservation."""
    config = Config(crawler=CrawlerConfig(use_headless=True, max_depth=0))
    config.cache_dir = _make_test_dir()
    config.job_id = "integration-headless-manifest"
    config.ensure_dirs()
    orchestrator = Orchestrator(config)

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.StaticCollector", IntegrationStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.HeadlessCollector", IntegrationHeadlessCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", IntegrationManifestCollector)

    async def _fake_download(ref: JSReference):
        content_map = {
            "https://example.com/static-entry.js": b'fetch("/api/static-users");',
            "https://example.com/dashboard.js": f'const stripeKey = "{FAKE_STRIPE_LIVE}";'.encode(),
            "https://example.com/manifest-chunk.js": b'fetch("/api/manifest-users");',
        }
        asset = JSAsset(
            url=ref.url,
            content=content_map[ref.url],
            content_hash="",
            initiator=ref.initiator,
            load_context=ref.load_context,
            load_method=ref.method,
        )
        asset.compute_hash()
        return asset

    monkeypatch.setattr(orchestrator, "_download_js", _fake_download)

    report = await orchestrator.run(["https://example.com"])

    assert report.summary.total_js_files == 3
    assert report.summary.total_findings >= 3
    assert {finding.category for finding in report.findings} >= {Category.ENDPOINT, Category.SECRET}
    assert any(
        finding.evidence.file_url == "https://example.com/dashboard.js"
        and finding.metadata.get("load_context") == "https://example.com/dashboard"
        for finding in report.findings
    )
    assert any(
        finding.evidence.file_url == "https://example.com/manifest-chunk.js"
        and finding.metadata.get("initiator") == "https://example.com/asset-manifest.json"
        and finding.metadata.get("load_context") == "https://example.com/asset-manifest.json"
        for finding in report.findings
    )


@pytest.mark.asyncio
async def test_apply_artifact_mappings_sets_original_positions():
    """Beautify line mappings and sourcemaps should reach finding evidence."""
    orchestrator = Orchestrator(Config())
    asset = JSAsset(
        url="https://example.com/app.js",
        content=b'fetch("/api/users")',
        content_hash="asset-hash",
    )

    # The finding is detected at BEAUTIFIED line 3; the line mapper reconstructs the GENERATED
    # (minified) coordinate -- line 1 -- which the sourcemap (a single "AAAA" segment on generated
    # line 1) resolves to src/app.ts line 1. (DQ-P07: the sourcemap must be queried with the restored
    # generated coord, not the raw beautified finding coord; the previous fixture mapped normalized 1
    # -> generated 5, a line the sourcemap did not cover, and only "passed" because of that bug.)
    mapper = LineMapper()
    mapper.add_mapping(LineMapping(
        original_line=1,
        original_column=0,
        normalized_line=3,
        normalized_column=0,
    ))
    orchestrator._line_mappers[asset.content_hash] = mapper
    orchestrator._sourcemaps[asset.content_hash] = SourceMapInfo(
        url=None,
        content='{"version":3}',
        is_inline=False,
        sources=["src/app.ts"],
        sources_content=['const endpoint = "/api/users";'],
        mappings="AAAA",
    )

    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=3,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._apply_artifact_mappings(asset, [finding])

    assert finding.evidence.original_file_url == "src/app.ts"
    assert finding.evidence.original_line == 1
    assert finding.metadata["original_snippet"] == 'const endpoint = "/api/users";'


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_dynamic_import_bindings():
    """Dynamic import namespace bindings should be surfaced into finding metadata."""
    orchestrator = Orchestrator(Config())
    source = """
    async function boot() {
      const chunkApi = await import("./chunk");
      chunkApi.loadUsers();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-dynamic",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=3,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "*",
        "local": "chunkApi",
        "kind": "namespace",
        "scope": "function:boot",
        "is_dynamic": True,
    } in finding.metadata["import_bindings"]
    assert "chunkApi.loadUsers" in finding.metadata["scoped_calls"]["function:boot"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_import_member_alias_binding():
    """Namespace-import member aliases should be surfaced as local named bindings."""
    orchestrator = Orchestrator(Config())
    source = """
    import * as api from "./chunk";
    function boot() {
      const loadUsers = api.loadUsers;
      return loadUsers();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-import-member-alias",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=4,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "function:boot",
        "is_dynamic": False,
        "is_alias": True,
        "is_member_alias": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_named_import_identifier_alias_binding():
    """Direct aliases of named imports should be surfaced as local named bindings."""
    orchestrator = Orchestrator(Config())
    source = """
    import { loadUsers } from "./chunk";
    function boot() {
      const run = loadUsers;
      return run();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-import-alias",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=4,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "loadUsers",
        "local": "run",
        "kind": "named",
        "scope": "function:boot",
        "is_dynamic": False,
        "is_alias": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_inner_scope_alias_of_outer_import_alias():
    """Nested scopes should surface aliases of outer-scope import aliases."""
    orchestrator = Orchestrator(Config())
    source = """
    import { loadUsers } from "./chunk";
    function boot() {
      const run = loadUsers;
      function inner() {
        const call = run;
        return call();
      }
      return inner();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-nested-import-alias",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=6,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "loadUsers",
        "local": "call",
        "kind": "named",
        "scope": "function:inner",
        "is_dynamic": False,
        "is_alias": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_namespace_alias_then_destructured_binding():
    """Namespace aliases and their destructured members should be surfaced transitively."""
    orchestrator = Orchestrator(Config())
    source = """
    import * as api from "./chunk";
    function boot() {
      const client = api;
      const { loadUsers: run } = client;
      return run();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-import-destructure",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=5,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "*",
        "local": "client",
        "kind": "namespace",
        "scope": "function:boot",
        "is_dynamic": False,
        "is_alias": True,
    } in finding.metadata["import_bindings"]
    assert {
        "source": "./chunk",
        "imported": "loadUsers",
        "local": "run",
        "kind": "named",
        "scope": "function:boot",
        "is_dynamic": False,
        "is_alias": True,
        "is_destructured_alias": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_commonjs_destructured_alias_binding():
    """Destructured aliases from CommonJS default objects should surface as named bindings."""
    orchestrator = Orchestrator(Config())
    source = """
    const api = require("./chunk");
    function boot() {
      const { loadUsers } = api;
      return loadUsers();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-commonjs-destructure",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=4,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "function:boot",
        "is_dynamic": False,
        "is_commonjs": True,
        "is_alias": True,
        "is_destructured_alias": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_dynamic_default_import_bindings():
    """Dynamic import destructuring of `default` should surface as a default binding."""
    orchestrator = Orchestrator(Config())
    source = """
    async function boot() {
      const { default: chunkApi } = await import("./chunk");
      return chunkApi();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-dynamic-default",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=3,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "default",
        "local": "chunkApi",
        "kind": "default",
        "scope": "function:boot",
        "is_dynamic": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_dynamic_then_default_bindings():
    """Dynamic import `.then()` callbacks should surface default destructuring bindings."""
    orchestrator = Orchestrator(Config())
    source = 'import("./chunk").then(({ default: chunkApi }) => chunkApi());'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-dynamic-then-default",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./chunk",
        "imported": "default",
        "local": "chunkApi",
        "kind": "default",
        "scope": "function:arrow@1",
        "is_dynamic": True,
    } in finding.metadata["import_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_scope_parent_map():
    """Nested functions should surface lexical parent scopes for correlation visibility."""
    orchestrator = Orchestrator(Config())
    source = """
    async function boot() {
      const chunkApi = await import("./chunk");
      function inner() {
        return chunkApi.loadUsers();
      }
      return inner();
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-scope-parents",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=5,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert finding.metadata["enclosing_scope"] == "function:inner"
    assert finding.metadata["scope_parents"] == {
        "function:inner": ["function:boot"],
    }


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_export_scope_map():
    """Export scope metadata should preserve aliased and default-export entry scopes."""
    orchestrator = Orchestrator(Config())
    source = """
    function fetchUsers() {
      return getToken();
    }

    function getToken() {
      return "secret";
    }

    export { fetchUsers as loadUsers };
    export default fetchUsers;
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-exports",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=2,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert finding.metadata["export_scopes"]["loadUsers"] == ["function:fetchUsers"]
    assert finding.metadata["export_scopes"]["default"] == ["function:fetchUsers"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_default_object_member_export_scopes():
    """Default-exported object members should surface practical callable member scopes."""
    orchestrator = Orchestrator(Config())
    source = """
    function fetchUsers() {
      return getToken();
    }

    function getToken() {
      return "secret";
    }

    const api = { loadUsers: fetchUsers };
    export default api;
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-default-object-exports",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=2,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert finding.metadata["export_scopes"]["loadUsers"] == ["function:fetchUsers"]
    assert "default" in finding.metadata["export_scopes"]
    assert finding.metadata["default_object_exports"] == ["loadUsers"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_named_object_export_members():
    """Named object exports should surface callable member metadata under exported aliases."""
    orchestrator = Orchestrator(Config())
    source = """
    function fetchUsers() {
      return getToken();
    }

    function getToken() {
      return "secret";
    }

    const client = { loadUsers: fetchUsers };
    export { client as sdk };
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-named-object-exports",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=2,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert finding.metadata["export_scopes"]["loadUsers"] == ["function:fetchUsers"]
    assert finding.metadata["named_object_exports"] == {"sdk": ["loadUsers"]}


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_class_export_member_metadata():
    """Class exports should surface callable member scopes and enclosing method scopes."""
    orchestrator = Orchestrator(Config())
    source = """
    export default class Client {
      loadUsers() {
        return "/api/users";
      }
    }
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-class-exports",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=3,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert finding.metadata["export_scopes"]["loadUsers"] == ["function:loadUsers"]
    assert finding.metadata["default_object_exports"] == ["loadUsers"]
    assert finding.metadata["enclosing_scope"] == "function:loadUsers"


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_reexport_bindings():
    """Export-from specifiers should surface as practical re-export bindings."""
    orchestrator = Orchestrator(Config())
    source = 'export { fetchUsers as loadUsers, default as defaultClient } from "./api";'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-reexport",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="debug-detector",
        category=Category.DEBUG,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Debug",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="debug",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./api",
        "imported": "fetchUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
    } in finding.metadata["re_export_bindings"]
    assert {
        "source": "./api",
        "imported": "default",
        "local": "defaultClient",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
    } in finding.metadata["re_export_bindings"]
    assert "./api" in finding.metadata["imports"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_export_all_reexport_binding():
    """Export-all declarations should surface as practical wildcard re-export bindings."""
    orchestrator = Orchestrator(Config())
    source = 'export * from "./api";'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-reexport-all",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="debug-detector",
        category=Category.DEBUG,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Debug",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="debug",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./api",
        "imported": "*",
        "local": "*",
        "kind": "namespace",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_reexport_all": True,
    } in finding.metadata["re_export_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_commonjs_bindings_and_exports():
    """CommonJS require/module.exports metadata should be surfaced for correlation."""
    orchestrator = Orchestrator(Config())
    source = """
    function fetchUsers() {}
    const api = require("./api");
    module.exports = fetchUsers;
    exports.loadUsers = fetchUsers;
    api();
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-commonjs",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=5,
            column=0,
        ),
        extracted_value="/api/users",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert "./api" in finding.metadata["imports"]
    assert {
        "source": "./api",
        "imported": "default",
        "local": "api",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_commonjs": True,
    } in finding.metadata["import_bindings"]
    assert "default" in finding.metadata["exports"]
    assert "loadUsers" in finding.metadata["exports"]
    assert finding.metadata["export_scopes"]["default"] == ["function:fetchUsers"]
    assert finding.metadata["export_scopes"]["loadUsers"] == ["function:fetchUsers"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_commonjs_reexport_bindings():
    """CommonJS barrel assignments should surface as re-export forwarding metadata."""
    orchestrator = Orchestrator(Config())
    source = """
    module.exports = require("./api");
    exports.loadUsers = require("./api").loadUsers;
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-commonjs-reexport",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="debug-detector",
        category=Category.DEBUG,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Debug",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="debug",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./api",
        "imported": "default",
        "local": "default",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in finding.metadata["re_export_bindings"]
    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in finding.metadata["re_export_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_commonjs_object_barrel_reexports():
    """Object-style CommonJS barrel assignments should surface as forwarding metadata."""
    orchestrator = Orchestrator(Config())
    source = 'module.exports = { loadUsers: require("./api").loadUsers };'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-commonjs-object-reexport",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="debug-detector",
        category=Category.DEBUG,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Debug",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="debug",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in finding.metadata["re_export_bindings"]


@pytest.mark.asyncio
async def test_annotate_finding_metadata_includes_identifier_backed_commonjs_reexports():
    """Identifier-backed require aliases should surface as CommonJS re-export metadata."""
    orchestrator = Orchestrator(Config())
    source = """
    const api = require("./api");
    const pingUsers = require("./api").pingUsers;
    module.exports = api;
    module.exports.loadUsers = api.loadUsers;
    module.exports = { ping: pingUsers };
    """
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="asset-hash-commonjs-identifier-reexport",
    )
    ir = orchestrator.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
    finding = Finding(
        rule_id="debug-detector",
        category=Category.DEBUG,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Debug",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="debug",
    )

    orchestrator._annotate_finding_metadata(asset, ir, [finding])

    assert {
        "source": "./api",
        "imported": "default",
        "local": "default",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in finding.metadata["re_export_bindings"]
    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in finding.metadata["re_export_bindings"]
    assert {
        "source": "./api",
        "imported": "pingUsers",
        "local": "ping",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in finding.metadata["re_export_bindings"]


@pytest.mark.asyncio
async def test_run_resumes_from_analyze_checkpoint(monkeypatch):
    """Resume should skip earlier stages when an analyze checkpoint exists."""
    cache_dir = _make_test_dir()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "resume-analyze"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)

    asset = JSAsset(
        url="https://example.com/app.js",
        content=b'fetch("/api/users")',
        content_hash="",
        parse_success=True,
    )
    asset.compute_hash()
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)

    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="/api/users",
        metadata={"is_first_party": True},
    )
    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=config.job_id,
            seed_urls=["https://example.com"],
            stage="analyze",
            asset_hashes=[asset.content_hash],
            findings=[finding],
            stage_state=_resume_stage_state(config),
        )
    )

    orchestrator = Orchestrator(config)

    for method_name in (
        "_stage_crawl",
        "_stage_download",
        "_stage_normalize",
        "_stage_parse",
        "_stage_analyze",
    ):
        async def _unexpected(*args, _method_name=method_name, **kwargs):  # pragma: no cover - assertion path
            raise AssertionError(f"{_method_name} should not run during resume")

        monkeypatch.setattr(orchestrator, method_name, _unexpected)

    report = await orchestrator.run(["https://example.com"])

    assert report.job_id == config.job_id
    assert report.summary.total_findings == 1
    assert report.findings[0].extracted_value == "/api/users"


@pytest.mark.asyncio
async def test_run_resumes_partial_parse_checkpoint_without_reparsing(monkeypatch):
    """Resume should skip assets already parsed inside an unfinished parse stage."""
    cache_dir = _make_test_dir()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "resume-partial-parse"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)

    source = 'fetch("/api/users");'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="",
        parse_success=True,
    )
    asset.compute_hash()
    asset.ast_hash = await artifact_store.store_ast(parse_result.ast, asset.content_hash)
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)

    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=config.job_id,
            seed_urls=["https://example.com"],
            stage="normalize",
            asset_hashes=[asset.content_hash],
            stage_state=_resume_stage_state(
                config,
                {"parse_complete_hashes": [asset.content_hash]},
            ),
        )
    )

    orchestrator = Orchestrator(config)

    for method_name in ("_stage_crawl", "_stage_download", "_stage_normalize"):
        async def _unexpected(*args, _method_name=method_name, **kwargs):  # pragma: no cover - assertion path
            raise AssertionError(f"{_method_name} should not run during resume")
        monkeypatch.setattr(orchestrator, method_name, _unexpected)

    monkeypatch.setattr(
        orchestrator.parser,
        "parse",
        lambda content: (_ for _ in ()).throw(AssertionError("parser.parse should not run")),
    )

    report = await orchestrator.run(["https://example.com"])

    assert report.job_id == config.job_id
    assert report.summary.total_js_files == 1
    assert any(f.category == Category.ENDPOINT for f in report.findings)


@pytest.mark.asyncio
async def test_stage_parse_persists_ast_with_resume_compatible_hash():
    """Stage parse should persist ASTs under the same hash scheme used by the artifact store."""
    cache_dir = _make_test_dir()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "ast-hash-compat"
    config.ensure_dirs()

    orchestrator = Orchestrator(config)
    asset = JSAsset(
        url="https://example.com/app.js",
        content=b'fetch("/api/users");',
        content_hash="",
    )
    asset.compute_hash()

    await orchestrator._stage_parse([asset])

    assert asset.ast_hash
    assert orchestrator._artifact_store is not None
    stored_ast = await orchestrator._artifact_store.get_ast(asset.content_hash, asset.ast_hash)
    assert stored_ast is not None

    restored = Orchestrator(config)
    restored_asset = JSAsset(
        url=asset.url,
        content=asset.content,
        content_hash="",
        ast_hash=asset.ast_hash,
        parse_success=True,
    )
    restored_asset.compute_hash()

    await restored._restore_parse_results([restored_asset])

    assert restored_asset.content_hash in restored._parse_results
    assert restored._parse_results[restored_asset.content_hash].ast == stored_ast


@pytest.mark.asyncio
async def test_stage_parse_forwards_asset_language_hint(monkeypatch):
    config = Config()
    config.cache_dir = _make_test_dir()
    config.job_id = "parse-language-hint"
    config.ensure_dirs()
    orchestrator = Orchestrator(config)
    original_parse = orchestrator.parser.parse
    calls: list[str | None] = []

    def _recording_parse(source, *, language_hint=None):
        calls.append(language_hint)
        return original_parse(source, language_hint=language_hint)

    monkeypatch.setattr(orchestrator.parser, "parse", _recording_parse)
    asset = JSAsset(
        url="file:///Component.tsx",
        content=b'const Component = () => <div data-api="/api/tsx" />;',
        content_hash="",
        language_hint="tsx",
    )
    asset.compute_hash()

    await orchestrator._stage_parse([asset])

    assert calls == ["tsx"]
    assert asset.parse_success is True


@pytest.mark.asyncio
async def test_run_resumes_partial_analyze_checkpoint_without_reanalyzing(monkeypatch):
    """Resume should reuse findings already produced inside an unfinished analyze stage."""
    cache_dir = _make_test_dir()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "resume-partial-analyze"
    config.resume = True
    config.ensure_dirs()

    artifact_store = ArtifactStore(cache_dir / config.job_id / "artifacts")
    finding_store = FindingStore(cache_dir / config.job_id)

    source = 'fetch("/api/users");'
    parse_result = parse_js(source)
    assert parse_result.success and parse_result.ast is not None

    asset = JSAsset(
        url="https://example.com/app.js",
        content=source.encode("utf-8"),
        content_hash="",
        parse_success=True,
    )
    asset.compute_hash()
    asset.ast_hash = await artifact_store.store_ast(parse_result.ast, asset.content_hash)
    await artifact_store.store_js(asset.content, asset.url)
    await artifact_store.store_asset_meta(asset)

    finding = Finding(
        rule_id="endpoint-detector",
        category=Category.ENDPOINT,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        title="Endpoint",
        evidence=Evidence(
            file_url=asset.url,
            file_hash=asset.content_hash,
            line=1,
            column=0,
        ),
        extracted_value="/api/users",
    )

    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=config.job_id,
            seed_urls=["https://example.com"],
            stage="parse",
            asset_hashes=[asset.content_hash],
            findings=[finding],
            stage_state=_resume_stage_state(
                config,
                {"analyze_complete_hashes": [asset.content_hash]},
            ),
        )
    )

    orchestrator = Orchestrator(config)

    for method_name in ("_stage_crawl", "_stage_download", "_stage_normalize"):
        async def _unexpected(*args, _method_name=method_name, **kwargs):  # pragma: no cover - assertion path
            raise AssertionError(f"{_method_name} should not run during resume")
        monkeypatch.setattr(orchestrator, method_name, _unexpected)

    monkeypatch.setattr(
        orchestrator.rule_engine,
        "analyze",
        lambda ir, context: (_ for _ in ()).throw(AssertionError("rule_engine.analyze should not run")),
    )

    report = await orchestrator.run(["https://example.com"])

    assert report.job_id == config.job_id
    assert report.summary.total_findings == 1
    assert report.findings[0].extracted_value == "/api/users"


@pytest.mark.asyncio
async def test_bundleinspector_scan_does_not_reuse_report_when_profile_changes(monkeypatch):
    """Stored reports should not be resumed across analysis-affecting config changes."""
    cache_dir = _make_test_dir()

    conservative = Config()
    conservative.cache_dir = cache_dir
    conservative.job_id = "profile-mismatch-report"
    conservative.resume = True
    conservative.crawler.use_headless = False
    conservative.crawler.max_depth = 1
    conservative.ensure_dirs()

    finding_store = FindingStore(cache_dir / conservative.job_id)
    stale_report = Report(
        job_id=conservative.job_id,
        seed_urls=["https://example.com"],
        config=embed_report_resume_signature(
            conservative.to_dict(),
            build_remote_resume_signature(conservative),
        ),
    )
    await finding_store.store_report(stale_report)

    deep = Config()
    deep.cache_dir = cache_dir
    deep.job_id = conservative.job_id
    deep.resume = True
    deep.crawler.use_headless = True
    deep.crawler.explore_routes = True
    deep.crawler.max_depth = 3
    deep.ensure_dirs()

    fresh_report = Report(job_id=deep.job_id, seed_urls=["https://example.com"])

    async def _fake_run(self, seed_urls):
        assert seed_urls == ["https://example.com"]
        return fresh_report

    monkeypatch.setattr(Orchestrator, "run", _fake_run)

    report = await BundleInspector(deep).scan(["https://example.com"])

    assert report is fresh_report
    assert report.id != stale_report.id


@pytest.mark.asyncio
@pytest.mark.parametrize("resume", [False, True])
async def test_bundleinspector_rejects_foreign_job_before_storage_access(resume):
    cache_dir = _make_test_dir()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "foreign-python-job"
    config.resume = resume
    repository = JobRepository(cache_dir)
    repository.register_owner(config.job_id, "alice")

    if resume:
        report = Report(
            job_id=config.job_id,
            seed_urls=["https://example.com"],
            config=embed_report_resume_signature(
                config.to_dict(),
                build_remote_resume_signature(config),
            ),
        )
        await FindingStore(cache_dir / config.job_id).store_report(report)

    with pytest.raises(JobAccessError):
        await BundleInspector(config).scan(["https://example.com"])

    job_root = cache_dir / config.job_id
    assert (job_root / ".owner").read_text(encoding="utf-8") == "alice"
    assert not (job_root / "artifacts").exists()


def test_orchestrator_rejects_unsafe_owned_storage_before_pipeline_access(tmp_path):
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "unsafe-python-job"
    repository = JobRepository(config.cache_dir)
    repository.register_owner(config.job_id, "local")
    artifacts_path = config.cache_dir / config.job_id / "artifacts"
    artifacts_path.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="directory"):
        Orchestrator(config)

    assert artifacts_path.read_text(encoding="utf-8") == "not a directory"
    assert not (config.cache_dir / config.job_id / "findings").exists()


def test_orchestrator_propagates_a_hardlinked_owner_as_unsafe_storage(tmp_path: Path) -> None:
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "hardlinked-owner"
    job_root = config.cache_dir / config.job_id
    job_root.mkdir(parents=True)
    outside_owner = tmp_path / "outside-owner"
    outside_owner.write_text("local", encoding="utf-8")
    try:
        os.link(outside_owner, job_root / ".owner")
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(UnsafePathError, match="link count is not one"):
        Orchestrator(config)

    assert outside_owner.read_text(encoding="utf-8") == "local"
    assert not (job_root / "artifacts").exists()


def test_orchestrator_propagates_finding_store_containment_violations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = Config()
    config.cache_dir = tmp_path / "cache"
    config.job_id = "escaped-finding-store"
    outside_findings = tmp_path / "outside" / "findings"
    original_ensure = finding_store_module.ensure_safe_directory

    def escape_findings(path: Path) -> Path:
        if path.name == "findings":
            outside_findings.mkdir(parents=True, exist_ok=True)
            return outside_findings.resolve()
        return original_ensure(path)

    monkeypatch.setattr(finding_store_module, "ensure_safe_directory", escape_findings)

    with pytest.raises(UnsafePathError, match="escaped"):
        Orchestrator(config)


@pytest.mark.asyncio
async def test_bundleinspector_resume_propagates_an_unsafe_cache_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    cache_link = tmp_path / "cache-link"
    try:
        cache_link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")
    config = Config()
    config.cache_dir = cache_link
    config.job_id = "unsafe-resume"
    config.resume = True

    with pytest.raises(UnsafePathError, match="symbolic link or junction"):
        await BundleInspector(config).scan(["https://example.com"])


@pytest.mark.asyncio
async def test_load_checkpoint_rejects_checkpoint_from_different_profile():
    """Stored checkpoints should not resume across analysis-affecting config changes."""
    cache_dir = _make_test_dir()

    conservative = Config()
    conservative.cache_dir = cache_dir
    conservative.job_id = "profile-mismatch-checkpoint"
    conservative.resume = True
    conservative.crawler.use_headless = False
    conservative.crawler.max_depth = 1
    conservative.ensure_dirs()

    finding_store = FindingStore(cache_dir / conservative.job_id)
    await finding_store.store_checkpoint(
        PipelineCheckpoint(
            job_id=conservative.job_id,
            seed_urls=["https://example.com"],
            stage="analyze",
            stage_state=_resume_stage_state(conservative),
        )
    )

    deep = Config()
    deep.cache_dir = cache_dir
    deep.job_id = conservative.job_id
    deep.resume = True
    deep.crawler.use_headless = True
    deep.crawler.explore_routes = True
    deep.crawler.max_depth = 3
    deep.ensure_dirs()

    checkpoint = await Orchestrator(deep)._load_checkpoint(["https://example.com"])

    assert checkpoint is None


@pytest.mark.asyncio
async def test_load_checkpoint_rehydrates_completeness_without_duplicate_growth():
    cache_dir = _make_test_dir()
    config = Config()
    config.cache_dir = cache_dir
    config.job_id = "resume-completeness"
    config.resume = True
    config.ensure_dirs()
    issue = CompletenessIssue(
        code="prior_truncation",
        stage="crawl",
        message="Prior crawl was truncated",
        affected_count=3,
        details={"limit": 10},
    )
    store = FindingStore(cache_dir / config.job_id)
    await store.store_checkpoint(PipelineCheckpoint(
        job_id=config.job_id,
        seed_urls=["https://example.com"],
        stage="crawl",
        stage_state=_resume_stage_state(config),
        completeness=AnalysisCompleteness(
            status=CompletenessStatus.PARTIAL,
            issues=[issue],
        ),
    ))
    orchestrator = Orchestrator(config)

    assert await orchestrator._load_checkpoint(["https://example.com"]) is not None
    assert await orchestrator._load_checkpoint(["https://example.com"]) is not None
    assert orchestrator._completeness_issues == [issue]


@pytest.mark.asyncio
async def test_dependency_frontier_resolves_relative_import_for_every_content_provenance(
    monkeypatch,
):
    config = Config()
    config.scope.allowed_domains = ["example.com"]
    config.scope.third_party_policy = ThirdPartyPolicy.SKIP
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com/a/app.js"]
    asset = JSAsset(
        url="https://example.com/a/app.js",
        content=b'import "./chunk.js";',
        provenance=[
            AssetProvenance(url="https://example.com/a/app.js"),
            AssetProvenance(url="https://example.com/b/app.js"),
        ],
    )
    asset.compute_hash()
    orchestrator._parse_results[asset.content_hash] = parse_js('import "./chunk.js";')
    seen: list[str] = []

    async def download(refs, assets, _completed):
        seen.extend(ref.url for ref in refs if ref.url.endswith("chunk.js"))
        return assets

    async def noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orchestrator, "_stage_download", download)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", noop)
    refs = [JSReference(url=asset.url)]
    await orchestrator._expand_dependency_frontier(refs, [asset])

    assert sorted(set(seen)) == [
        "https://example.com/a/chunk.js",
        "https://example.com/b/chunk.js",
    ]


@pytest.mark.asyncio
async def test_download_scope_rejection_precedes_dns_validation(monkeypatch):
    config = Config()
    config.scope.allowed_domains = ["example.com"]
    config.scope.third_party_policy = ThirdPartyPolicy.SKIP
    orchestrator = Orchestrator(config)
    orchestrator._download_client = object()
    validated: list[str] = []

    def validate(url: str, *_args) -> tuple[bool, str]:
        validated.append(url)
        return True, "OK"

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", validate)
    result = await orchestrator._download_js(JSReference(
        url="https://leaked-value.attacker.test/app.js"
    ))

    assert result is None
    assert validated == []


def test_asset_provenance_merge_preserves_redirect_final_url_as_canonical_base():
    orchestrator = Orchestrator(Config())
    existing = JSAsset(
        url="https://cdn.example.net/a/app.js",
        provenance=[AssetProvenance(url="https://app.example.com/a/app.js")],
    )
    incoming = JSAsset(
        url="https://cdn.example.net/b/app.js",
        provenance=[AssetProvenance(url="https://app.example.com/b/app.js")],
    )

    orchestrator._merge_asset_provenance(existing, incoming)

    assert existing.url == "https://cdn.example.net/a/app.js"
    assert {item.url for item in existing.provenance} == {
        "https://app.example.com/a/app.js",
        "https://app.example.com/b/app.js",
        "https://cdn.example.net/a/app.js",
        "https://cdn.example.net/b/app.js",
    }


@pytest.mark.asyncio
async def test_stage_crawl_skips_completed_seed_urls(monkeypatch):
    """Partial crawl resume should skip seed URLs already completed."""
    orchestrator = Orchestrator(Config())
    orchestrator._seed_urls = ["https://done.example", "https://todo.example"]

    seen: list[str] = []

    async def _fake_crawl(
        url,
        completed_phases=None,
        phase_states=None,
        on_phase_complete=None,
        on_ref_discovered=None,
        on_page_complete=None,
    ):
        del completed_phases, phase_states, on_phase_complete, on_ref_discovered, on_page_complete
        seen.append(url)
        return [JSReference(url=f"{url}/static/app.js")]

    monkeypatch.setattr(orchestrator, "_crawl_url", _fake_crawl)
    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        assert stage == ""
        assert stage_state["crawl_complete_seeds"] == ["https://done.example", "https://todo.example"]
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    existing_refs = [JSReference(url="https://done.example/static/app.js")]
    refs = await orchestrator._stage_crawl(
        ["https://done.example", "https://todo.example"],
        existing_refs=existing_refs,
        completed_seeds={"https://done.example"},
    )

    assert seen == ["https://todo.example"]
    assert sorted(ref.url for ref in refs) == [
        "https://done.example/static/app.js",
        "https://todo.example/static/app.js",
    ]


@pytest.mark.asyncio
async def test_stage_crawl_skips_completed_seed_collector_phases(monkeypatch):
    """Partial crawl resume should skip collector phases already completed inside a seed."""
    config = Config(crawler=CrawlerConfig(max_depth=2, use_headless=True))
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    for fake in (PhaseStaticCollector, PhaseHeadlessMultiPageCollector, PhaseManifestCollector):
        fake.instances.clear()

    checkpoint_states: list[dict] = []

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.MultiPageStaticCollector", PhaseStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.HeadlessMultiPageCollector", PhaseHeadlessMultiPageCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", PhaseManifestCollector)

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        del stage, seed_urls, js_refs, assets, findings
        checkpoint_states.append(stage_state or {})

    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    refs = await orchestrator._stage_crawl(
        ["https://example.com"],
        existing_refs=[JSReference(url="https://example.com/static.js")],
        completed_seed_phases={"https://example.com": {"static"}},
    )

    assert not PhaseStaticCollector.instances
    assert PhaseHeadlessMultiPageCollector.instances
    assert PhaseManifestCollector.instances
    assert sorted(ref.url for ref in refs) == [
        "https://example.com/headless.js",
        "https://example.com/manifest.js",
        "https://example.com/static.js",
    ]
    assert any(
        state.get("crawl_complete_seed_phases", {}).get("https://example.com")
        for state in checkpoint_states
    )


@pytest.mark.asyncio
async def test_stage_crawl_checkpoints_partially_discovered_refs_inside_phase(monkeypatch):
    """Crawl resume checkpoints should retain refs discovered before a collector phase finishes."""
    config = Config(crawler=CrawlerConfig(max_depth=0, use_headless=False))
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    checkpoint_payloads: list[tuple[list[str], dict]] = []

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.StaticCollector", StreamingStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", FakeManifestCollector)

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        del stage, seed_urls, assets, findings
        checkpoint_payloads.append((
            sorted(ref.url for ref in (js_refs or [])),
            dict(stage_state or {}),
        ))

    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    refs = await orchestrator._stage_crawl(["https://example.com"])

    assert sorted(ref.url for ref in refs) == [
        "https://example.com/a.js",
        "https://example.com/b.js",
    ]
    assert any(
        urls == ["https://example.com/a.js"]
        and state.get("crawl_in_progress_seed") == "https://example.com"
        and state.get("crawl_in_progress_phase") == "static"
        and state.get("crawl_in_progress_ref_count") == 1
        for urls, state in checkpoint_payloads
    )


@pytest.mark.asyncio
async def test_stage_crawl_persists_page_level_phase_state_and_restores_it(monkeypatch):
    """Partial crawl resume should restore and persist multipage collector page state."""
    config = Config(crawler=CrawlerConfig(max_depth=2, use_headless=False))
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    checkpoint_states: list[dict] = []
    ResumablePhaseStaticCollector.loaded_states.clear()

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.MultiPageStaticCollector", ResumablePhaseStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", FakeManifestCollector)

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        del stage, seed_urls, js_refs, assets, findings
        checkpoint_states.append(dict(stage_state or {}))

    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    refs = await orchestrator._stage_crawl(
        ["https://example.com"],
        partial_seed_phase_states={
            "https://example.com": {
                "static": {
                    "visited_urls": ["https://example.com"],
                    "pending_pages": [{"url": "https://example.com/next", "depth": 1}],
                }
            }
        },
    )

    assert [ref.url for ref in refs] == ["https://example.com/resumed.js"]
    assert ResumablePhaseStaticCollector.loaded_states == [{
        "visited_urls": ["https://example.com"],
        "pending_pages": [{"url": "https://example.com/next", "depth": 1}],
    }]
    assert any(
        state.get("crawl_seed_phase_states", {})
        .get("https://example.com", {})
        .get("static", {})
        .get("pending_pages")
        == [{"url": "https://example.com/later", "depth": 1}]
        for state in checkpoint_states
    )


@pytest.mark.asyncio
async def test_stage_crawl_checkpoints_partial_refs_with_mid_page_progress_state(monkeypatch):
    """Mid-page progress callbacks should checkpoint discovered refs together with updated page state."""
    config = Config(crawler=CrawlerConfig(max_depth=2, use_headless=False))
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    checkpoint_payloads: list[tuple[list[str], dict]] = []

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe", lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.MultiPageStaticCollector", MidPageProgressStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", FakeManifestCollector)

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        del stage, seed_urls, assets, findings
        checkpoint_payloads.append((
            sorted(ref.url for ref in (js_refs or [])),
            dict(stage_state or {}),
        ))

    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    refs = await orchestrator._stage_crawl(["https://example.com"])

    assert sorted(ref.url for ref in refs) == [
        "https://example.com/a.js",
        "https://example.com/b.js",
    ]
    assert any(
        urls == ["https://example.com/a.js"]
        and state.get("crawl_seed_phase_states", {})
        .get("https://example.com", {})
        .get("static", {})
        .get("collected_js_urls")
        == ["https://example.com/a.js"]
        and state.get("crawl_seed_phase_states", {})
        .get("https://example.com", {})
        .get("static", {})
        .get("pending_pages")
        == [{"url": "https://example.com/next", "depth": 1}]
        and state.get("crawl_seed_phase_states", {})
        .get("https://example.com", {})
        .get("static", {})
        .get("inflight_page")
        == {"url": "https://example.com", "depth": 0}
        for urls, state in checkpoint_payloads
    )


@pytest.mark.asyncio
async def test_stage_download_skips_completed_urls(monkeypatch):
    """Partial download resume should skip URLs already completed."""
    orchestrator = Orchestrator(Config())
    orchestrator._seed_urls = ["https://example.com"]

    existing_asset = JSAsset(
        url="https://example.com/static/a.js",
        content=b'console.log("a")',
        content_hash="",
    )
    existing_asset.compute_hash()

    download_calls: list[str] = []

    async def _fake_download(ref):
        download_calls.append(ref.url)
        asset = JSAsset(url=ref.url, content=b'console.log("b")', content_hash="")
        asset.compute_hash()
        return asset

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        assert stage == PipelineStage.CRAWL
        assert "https://example.com/static/b.js" in stage_state["download_complete_urls"]

    monkeypatch.setattr(orchestrator, "_download_js", _fake_download)
    async def _fake_persist_asset(asset):
        return None
    monkeypatch.setattr(orchestrator, "_persist_asset", _fake_persist_asset)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    refs = [
        JSReference(url="https://example.com/static/a.js"),
        JSReference(url="https://example.com/static/b.js"),
    ]
    assets = await orchestrator._stage_download(
        refs,
        existing_assets=[existing_asset],
        completed_urls={"https://example.com/static/a.js"},
    )

    assert download_calls == ["https://example.com/static/b.js"]
    assert sorted(asset.url for asset in assets) == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]


@pytest.mark.asyncio
async def test_stage_download_does_not_mark_transient_failures_complete(monkeypatch):
    """A transient (5xx/network) download failure must NOT be marked complete, so --resume retries
    it instead of permanently dropping the asset and its findings. Success and permanent skips
    (SSRF/too-large -> None) ARE marked complete."""
    import httpx
    orchestrator = Orchestrator(Config(crawler=CrawlerConfig(max_retries=2, retry_delay=0)))
    orchestrator._seed_urls = ["https://example.com"]

    async def _fake_download(ref):
        if "transient" in ref.url:
            req = httpx.Request("GET", ref.url)
            raise httpx.HTTPStatusError("503", request=req, response=httpx.Response(503, request=req))
        if "permanent" in ref.url:
            return None  # e.g. SSRF-blocked / file-too-large
        asset = JSAsset(url=ref.url, content=b"x", content_hash="")
        asset.compute_hash()
        return asset

    seen_state: dict = {}

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        seen_state.update(stage_state or {})

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(orchestrator, "_download_js", _fake_download)
    monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)
    acquired: list[str] = []

    async def _acquire(url: str) -> None:
        acquired.append(url)

    monkeypatch.setattr(orchestrator.rate_limiter, "acquire", _acquire)

    refs = [
        JSReference(url="https://example.com/ok.js"),
        JSReference(url="https://example.com/transient.js"),
        JSReference(url="https://example.com/permanent.js"),
    ]
    await orchestrator._stage_download(refs, existing_assets=[], completed_urls=set())

    completed = set(seen_state.get("download_complete_urls", []))
    assert "https://example.com/ok.js" in completed                # success -> done
    assert "https://example.com/permanent.js" in completed         # permanent skip -> done
    assert "https://example.com/transient.js" not in completed     # transient -> RETRY on resume
    assert acquired.count("https://example.com/transient.js") == 3


@pytest.mark.asyncio
async def test_stage_normalize_skips_completed_assets(monkeypatch):
    """Partial normalize resume should skip assets already normalized."""
    config = Config()
    config.parser.resolve_sourcemaps = False
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    first = JSAsset(url="https://example.com/a.js", content=b'const a=1;', content_hash="")
    first.compute_hash()
    second = JSAsset(url="https://example.com/b.js", content=b'const b=1;', content_hash="")
    second.compute_hash()
    first_hash = first.content_hash

    beautify_calls: list[str] = []
    original_beautify = orchestrator.beautifier.beautify

    def _tracked_beautify(content):
        beautify_calls.append(content)
        return original_beautify(content)

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        assert stage == PipelineStage.DOWNLOAD
        assert second.content_hash in stage_state["normalize_complete_hashes"]

    monkeypatch.setattr(orchestrator.beautifier, "beautify", _tracked_beautify)
    async def _fake_persist_asset(asset):
        return None
    monkeypatch.setattr(orchestrator, "_persist_asset", _fake_persist_asset)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    await orchestrator._stage_normalize([first, second], processed_hashes={first_hash})

    assert beautify_calls == ['const b=1;']


@pytest.mark.asyncio
async def test_stage_normalize_preserves_original_content_hash_and_tracks_normalized_hash(monkeypatch):
    """Normalize should keep the raw asset hash stable while recording beautified bytes separately."""
    config = Config()
    config.parser.resolve_sourcemaps = False
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    source = b'const  value=1;\nfetch("/api/users");'
    asset = JSAsset(url="https://example.com/a.js", content=source, content_hash="")
    asset.compute_hash()
    original_hash = asset.content_hash

    async def _fake_persist_asset(asset):
        return None

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        return None

    monkeypatch.setattr(orchestrator, "_persist_asset", _fake_persist_asset)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    await orchestrator._stage_normalize([asset])

    assert asset.content_hash == original_hash
    assert asset.normalized_hash == hashlib.sha256(asset.content).hexdigest()
    assert asset.normalized_hash != original_hash
    assert original_hash in orchestrator._line_mappers


@pytest.mark.asyncio
async def test_stage_normalize_emits_asset_and_sourcemap_detail_updates(monkeypatch):
    """Normalize should publish current asset and sourcemap status as stage detail updates."""
    config = Config()
    config.parser.resolve_sourcemaps = True
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    asset = JSAsset(url="https://example.com/static/app.js", content=b'const value=1;', content_hash="")
    asset.compute_hash()
    details: list[str] = []
    orchestrator.progress.on_stage_detail = lambda stage, detail: details.append(detail)

    async def _fake_persist_asset(asset):
        return None

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        return None

    async def _fake_setup(self):
        return None

    async def _fake_teardown(self):
        return None

    async def _fake_resolve(self, content, url):
        return None

    monkeypatch.setattr(orchestrator, "_persist_asset", _fake_persist_asset)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)
    monkeypatch.setattr("bundleInspector.core.orchestrator.SourceMapResolver.setup", _fake_setup)
    monkeypatch.setattr("bundleInspector.core.orchestrator.SourceMapResolver.teardown", _fake_teardown)
    monkeypatch.setattr("bundleInspector.core.orchestrator.SourceMapResolver.resolve", _fake_resolve)

    await orchestrator._stage_normalize([asset])

    assert any("example.com/static/app.js" in detail and "beautify" in detail for detail in details)
    assert any("sourcemap check" in detail for detail in details)
    assert any("no sourcemap" in detail for detail in details)


@pytest.mark.asyncio
async def test_stage_normalize_emits_heartbeat_for_slow_beautify(monkeypatch):
    """Long-running normalize work should emit heartbeat detail updates instead of looking stuck."""
    config = Config()
    config.parser.resolve_sourcemaps = False
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]
    orchestrator._normalize_heartbeat_seconds = 0.1

    asset = JSAsset(url="https://example.com/static/slow.js", content=b'const value=1;', content_hash="")
    asset.compute_hash()
    details: list[str] = []
    orchestrator.progress.on_stage_detail = lambda stage, detail: details.append(detail)

    original_beautify = orchestrator.beautifier.beautify

    def _slow_beautify(content):
        time.sleep(0.25)
        return original_beautify(content)

    async def _fake_persist_asset(asset):
        return None

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        return None

    monkeypatch.setattr(orchestrator.beautifier, "beautify", _slow_beautify)
    monkeypatch.setattr(orchestrator, "_persist_asset", _fake_persist_asset)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    await orchestrator._stage_normalize([asset])

    assert any("elapsed" in detail for detail in details)


@pytest.mark.asyncio
async def test_stage_normalize_skips_beautify_for_large_assets(monkeypatch):
    """Oversized assets should skip beautify and keep identity normalization."""
    config = Config()
    config.parser.resolve_sourcemaps = False
    config.parser.beautify_max_bytes = 8
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    source = b'const value = 1;\nfetch("/api/users");'
    asset = JSAsset(url="https://example.com/static/large.js", content=source, content_hash="")
    asset.compute_hash()
    details: list[str] = []
    orchestrator.progress.on_stage_detail = lambda stage, detail: details.append(detail)

    async def _fake_persist_asset(asset):
        return None

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        return None

    monkeypatch.setattr(orchestrator, "_persist_asset", _fake_persist_asset)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    await orchestrator._stage_normalize([asset])

    assert asset.content == source
    assert asset.normalized_hash == asset.content_hash
    assert any("beautify skipped (size limit)" in detail for detail in details)


@pytest.mark.asyncio
async def test_stage_parse_persists_regex_literal_ast_without_pattern_objects(monkeypatch):
    """Parse stage should persist regex literal ASTs without JSON serialization errors."""
    config = Config()
    config.cache_dir = _make_test_dir() / "cache"
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]

    asset = JSAsset(
        url="https://example.com/static/regex.js",
        content=b"const re = /abc/i;",
        content_hash="",
    )
    asset.compute_hash()

    async def _fake_checkpoint(stage, seed_urls, js_refs=None, assets=None, findings=None, stage_state=None):
        return None

    monkeypatch.setattr(orchestrator, "_store_checkpoint", _fake_checkpoint)

    await orchestrator._stage_parse([asset])

    assert asset.parse_success is True
    assert asset.ast_hash
    stored_ast = await orchestrator._artifact_store.get_ast(asset.content_hash, asset.ast_hash)
    assert stored_ast is not None
    literal = stored_ast["body"][0]["declarations"][0]["init"]
    assert literal["regex"] == {"pattern": "abc", "flags": "i"}
    assert literal["value"] is None


@pytest.mark.asyncio
async def test_stage_download_propagates_cancelled_error(monkeypatch):
    """Download stage should not swallow task cancellation signals."""
    config = Config()
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com"]
    refs = [JSReference(url="https://example.com/app.js")]

    async def _cancel(_ref):
        raise asyncio.CancelledError()

    monkeypatch.setattr(orchestrator, "_download_js", _cancel)

    with pytest.raises(asyncio.CancelledError):
        await orchestrator._stage_download(refs)



# ---------------------------------------------------------------- DQ-C06: transient phase outcome

class TransientFailStaticCollector(_FakeCollector):
    """Static collector that swallows a transient 503 (yields nothing) and records it, like the
    real collectors now do."""
    instances: list[str] = []

    async def collect(self, url, scope):
        self.retryable_failures = [
            {"url": url, "reason": "HTTP 503", "status": 503, "phase": "static"}
        ]
        if False:  # pragma: no cover - keep this an async generator
            yield None


@pytest.mark.asyncio
async def test_crawl_does_not_mark_transient_phase_complete(monkeypatch):
    """DQ-C06: a transient (503) failure in a crawl phase must NOT be checkpointed as complete
    (so --resume re-runs it) and the lost coverage must be surfaced in report warnings."""
    config = Config(crawler=CrawlerConfig(max_depth=0, use_headless=False))
    orchestrator = Orchestrator(config)
    TransientFailStaticCollector.instances.clear()

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe",
                        lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.StaticCollector", TransientFailStaticCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", _FakeCollector)

    completed_phases: list[str] = []

    async def on_phase_complete(phase, refs, completed):
        completed_phases.append(phase)

    await orchestrator._crawl_url("https://example.com", on_phase_complete=on_phase_complete)

    # the transient static phase is NOT marked complete -> resume re-runs it
    assert "static" not in completed_phases
    # a phase that finished cleanly still completes
    assert "manifest" in completed_phases
    # lost coverage is surfaced (not a silent 0)
    assert any("static" in w and "503" in w for w in orchestrator._crawl_warnings)
    # the failed phase is tracked so _stage_crawl keeps the seed PARTIAL (resume re-runs only it)
    assert "static" in orchestrator._incomplete_crawl_phases.get("https://example.com", set())


@pytest.mark.asyncio
async def test_crawl_marks_empty_but_ok_phase_complete(monkeypatch):
    """Guard against over-correction: a collector that legitimately yields 0 refs WITHOUT a
    transient failure must still checkpoint the phase as complete."""
    config = Config(crawler=CrawlerConfig(max_depth=0, use_headless=False))
    orchestrator = Orchestrator(config)

    monkeypatch.setattr("bundleInspector.core.orchestrator.is_url_safe",
                        lambda url, resolve_dns=True, allow_private_ips=False: (True, "OK"))
    monkeypatch.setattr("bundleInspector.core.orchestrator.StaticCollector", _FakeCollector)
    monkeypatch.setattr("bundleInspector.core.orchestrator.ManifestCollector", _FakeCollector)

    completed_phases: list[str] = []

    async def on_phase_complete(phase, refs, completed):
        completed_phases.append(phase)

    await orchestrator._crawl_url("https://example.com", on_phase_complete=on_phase_complete)

    assert "static" in completed_phases
    assert not orchestrator._crawl_warnings
