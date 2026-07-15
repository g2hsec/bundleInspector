from __future__ import annotations

import asyncio
import json
import multiprocessing
import socket
import time
from typing import Any

import pytest

from bundleInspector.collector.headless import HeadlessCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.config import (
    AuthConfig,
    Config,
    CrawlerConfig,
    ParserConfig,
    RuleConfig,
    ScopeConfig,
)
from bundleInspector.core import safe_http
from bundleInspector.core.orchestrator import Orchestrator
from bundleInspector.core.progress import PipelineStage
from bundleInspector.core.safe_http import PinnedNetworkBackend, UnsafeNetworkTarget
from bundleInspector.correlator.graph import CorrelationGraph
from bundleInspector.reporter.public_view import PublicReportProjector
from bundleInspector.reporter.sarif_reporter import SARIFReporter
from bundleInspector.storage.models import JSAsset, JSReference


def _config(tmp_path, job_id: str, *, max_js_files: int = 100) -> Config:
    return Config(
        cache_dir=tmp_path,
        job_id=job_id,
        crawler=CrawlerConfig(
            max_js_files=max_js_files,
            max_retries=0,
            rate_limit=0,
            use_headless=False,
        ),
        parser=ParserConfig(beautify=False, resolve_sourcemaps=False),
    )


async def _noop(*_args: Any, **_kwargs: Any) -> None:
    return None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    [
        ("ssrf", "unsafe_url"),
        ("redirect_ssrf", "unsafe_redirect"),
        ("non_200", "http_status"),
        ("malformed", "malformed_sourcemap"),
    ],
)
async def test_discovered_sourcemap_failure_is_promoted_to_completeness(
    tmp_path,
    monkeypatch,
    scenario: str,
    expected_reason: str,
) -> None:
    class Response:
        def __init__(self, status: int, text: str = "", location: str | None = None) -> None:
            self.status_code = status
            self.text = text
            self.headers = {"location": location} if location else {}

    class Client:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def get(self, url: str) -> Response:
            self.calls.append(url)
            if scenario == "redirect_ssrf":
                return Response(302, location="http://127.0.0.1/private.map")
            if scenario == "non_200":
                return Response(404)
            if scenario == "malformed":
                return Response(200, "not-json")
            raise AssertionError("unsafe URL must be blocked before network egress")

        async def aclose(self) -> None:
            return None

    client = Client()

    async def setup(resolver: Any) -> None:
        resolver._client = client

    async def teardown(resolver: Any) -> None:
        resolver._client = None

    def safe_url(url: str, *_args: Any) -> tuple[bool, str]:
        return (not url.startswith("http://127.0.0.1"), "test policy")

    monkeypatch.setattr("bundleInspector.core.orchestrator.SourceMapResolver.setup", setup)
    monkeypatch.setattr("bundleInspector.core.orchestrator.SourceMapResolver.teardown", teardown)
    monkeypatch.setattr("bundleInspector.core.security.is_url_safe", safe_url)

    config = _config(tmp_path, f"sourcemap-{scenario}")
    config.parser.resolve_sourcemaps = True
    orchestrator = Orchestrator(config)
    monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
    reference = (
        "http://127.0.0.1/private.map"
        if scenario == "ssrf"
        else "https://cdn.example.com/app.js.map"
    )
    asset = JSAsset(
        url="https://example.com/app.js",
        content=f"x=1;\n//# sourceMappingURL={reference}".encode(),
    )
    asset.compute_hash()

    await orchestrator._stage_normalize([asset])

    issues = [
        issue
        for issue in orchestrator._completeness_issues
        if issue.code == "sourcemap_resolution_failed"
    ]
    assert len(issues) == 1
    assert issues[0].stage == PipelineStage.NORMALIZE.value
    assert issues[0].details["reason"] == expected_reason
    assert "private.map" not in str(issues[0].details)
    assert client.calls == ([] if scenario == "ssrf" else ["https://cdn.example.com/app.js.map"])


def _slow_only_in_child(payload):
    if multiprocessing.current_process().name != "MainProcess":
        time.sleep(10)
    return payload[0], True, [], None, [], []


@pytest.mark.asyncio
async def test_headless_body_is_attached_and_download_reuses_it(tmp_path, monkeypatch) -> None:
    class Request:
        resource_type = "script"
        method = "GET"
        frame = None

    class Response:
        url = "https://example.com/app.js"
        request = Request()
        headers = {"content-type": "application/javascript", "content-length": "17"}
        status = 206

        async def body(self) -> bytes:
            return b"const captured=1;"

    collector = HeadlessCollector(CrawlerConfig(use_headless=True))
    collector._on_response(
        Response(),  # type: ignore[arg-type]
        "https://example.com",
        ScopePolicy(ScopeConfig()),
    )
    await collector._wait_for_response_bodies()
    assert len(collector._discovered_refs) == 1
    ref = collector._discovered_refs[0]
    assert ref.captured_content == b"const captured=1;"
    assert ref.captured_status_code == 206

    orchestrator = Orchestrator(_config(tmp_path, "captured-body"))
    orchestrator._seed_urls = ["https://example.com"]

    async def forbidden_refetch(_ref: JSReference) -> JSAsset:
        raise AssertionError("browser-captured JS must not be refetched")

    monkeypatch.setattr(orchestrator, "_download_js", forbidden_refetch)
    monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
    assets = await orchestrator._stage_download([ref])
    assert len(assets) == 1
    assert assets[0].content == b"const captured=1;"
    assert assets[0].status_code == 206


@pytest.mark.asyncio
async def test_download_cap_and_provenance_are_input_order_invariant(tmp_path, monkeypatch) -> None:
    async def run(order: list[str], job_id: str) -> tuple[list[str], list[tuple[str, str]]]:
        orchestrator = Orchestrator(_config(tmp_path, job_id, max_js_files=2))
        orchestrator._seed_urls = ["https://example.com"]
        monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
        monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
        refs = [
            JSReference(
                url=f"https://example.com/{name}.js",
                initiator=f"https://example.com/{name}-parent",
                captured_content=name.encode(),
            )
            for name in order
        ]
        assets = await orchestrator._stage_download(refs)
        return (
            [asset.url for asset in assets],
            [
                (path.url, path.initiator)
                for asset in assets
                for path in asset.provenance
            ],
        )

    forward = await run(["c", "a", "b"], "cap-forward")
    reverse = await run(["b", "a", "c"], "cap-reverse")
    assert forward == reverse
    assert forward[0] == ["https://example.com/a.js", "https://example.com/b.js"]


@pytest.mark.asyncio
async def test_duplicate_content_provenance_is_completion_order_invariant(tmp_path, monkeypatch) -> None:
    async def run(delays: dict[str, float], job_id: str) -> list[tuple[str, str, str, str]]:
        orchestrator = Orchestrator(_config(tmp_path, job_id))
        orchestrator._seed_urls = ["https://example.com"]
        monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
        monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
        monkeypatch.setattr(orchestrator.rate_limiter, "acquire", _noop)

        async def download(ref: JSReference) -> JSAsset:
            await asyncio.sleep(delays[ref.url])
            asset = JSAsset(
                url=ref.url,
                content=b"identical",
                provenance=orchestrator._provenance_entries_from_ref(ref),
            )
            asset.compute_hash()
            return asset

        monkeypatch.setattr(orchestrator, "_download_js", download)
        refs = [
            JSReference(
                url="https://example.com/a.js",
                initiator="https://example.com/root-a",
            ),
            JSReference(
                url="https://example.com/b.js",
                initiator="https://example.com/root-b",
            ),
        ]
        assets = await orchestrator._stage_download(refs)
        assert len(assets) == 1
        return [
            (item.url, item.initiator, item.load_context, item.method.value)
            for item in assets[0].provenance
        ]

    first = await run(
        {"https://example.com/a.js": 0.03, "https://example.com/b.js": 0},
        "dedup-first",
    )
    second = await run(
        {"https://example.com/a.js": 0, "https://example.com/b.js": 0.03},
        "dedup-second",
    )
    assert first == second
    assert {item[0] for item in first} == {
        "https://example.com/a.js",
        "https://example.com/b.js",
    }


@pytest.mark.asyncio
async def test_dependency_frontier_reaches_fixed_point(tmp_path, monkeypatch) -> None:
    orchestrator = Orchestrator(_config(tmp_path, "frontier-chain"))
    orchestrator._seed_urls = ["https://example.com/a.js"]
    monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
    monkeypatch.setattr(orchestrator, "_persist_ast", _noop)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
    monkeypatch.setattr(orchestrator.rate_limiter, "acquire", _noop)
    sources = {
        "https://example.com/b.js": b'import "./c.js";',
        "https://example.com/c.js": b"export const c = 1;",
    }
    calls: list[str] = []

    async def download(ref: JSReference) -> JSAsset:
        calls.append(ref.url)
        asset = JSAsset(
            url=ref.url,
            content=sources[ref.url],
            provenance=orchestrator._provenance_entries_from_ref(ref),
        )
        asset.compute_hash()
        return asset

    monkeypatch.setattr(orchestrator, "_download_js", download)
    root = JSAsset(
        url="https://example.com/a.js",
        content=b'import "./b.js";',
    )
    root.compute_hash()
    await orchestrator._stage_parse([root])
    refs, assets = await orchestrator._expand_dependency_frontier(
        [JSReference(url=root.url)],
        [root],
    )
    assert calls == ["https://example.com/b.js", "https://example.com/c.js"]
    assert [ref.url for ref in refs] == sorted(ref.url for ref in refs)
    assert {asset.url for asset in assets} == {
        "https://example.com/a.js",
        "https://example.com/b.js",
        "https://example.com/c.js",
    }


@pytest.mark.asyncio
async def test_diamond_frontier_counts_unique_url_and_unions_initiators(tmp_path, monkeypatch) -> None:
    async def run(reverse: bool, job_id: str) -> tuple[int, list[str], list[str]]:
        orchestrator = Orchestrator(_config(tmp_path, job_id, max_js_files=3))
        orchestrator._seed_urls = ["https://example.com/a.js", "https://example.com/b.js"]
        monkeypatch.setattr(orchestrator, "_persist_asset", _noop)
        monkeypatch.setattr(orchestrator, "_persist_ast", _noop)
        monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
        monkeypatch.setattr(orchestrator.rate_limiter, "acquire", _noop)
        downloads = 0

        async def download(ref: JSReference) -> JSAsset:
            nonlocal downloads
            downloads += 1
            asset = JSAsset(
                url=ref.url,
                content=b"export const shared = 1;",
                provenance=orchestrator._provenance_entries_from_ref(ref),
            )
            asset.compute_hash()
            return asset

        monkeypatch.setattr(orchestrator, "_download_js", download)
        assets = [
            JSAsset(url="https://example.com/a.js", content=b'import "./shared.js";'),
            JSAsset(url="https://example.com/b.js", content=b'import "./shared.js";'),
        ]
        for asset in assets:
            asset.compute_hash()
        await orchestrator._stage_parse(assets)
        if reverse:
            assets.reverse()
        _, expanded = await orchestrator._expand_dependency_frontier(
            [JSReference(url=asset.url) for asset in assets],
            assets,
        )
        shared = next(asset for asset in expanded if asset.url.endswith("shared.js"))
        return (
            downloads,
            [item.initiator for item in shared.provenance],
            [issue.code for issue in orchestrator._completeness_issues],
        )

    forward = await run(False, "diamond-forward")
    reverse = await run(True, "diamond-reverse")
    assert forward == reverse
    assert forward[0] == 1
    assert forward[1] == ["https://example.com/a.js", "https://example.com/b.js"]
    assert "dependency_frontier_truncated" not in forward[2]


@pytest.mark.asyncio
async def test_checkpoint_merge_is_atomic_and_stage_cannot_cross_retry_barrier(tmp_path) -> None:
    class Store:
        def __init__(self) -> None:
            self.snapshots = []

        async def store_checkpoint(self, checkpoint) -> None:
            await asyncio.sleep(0.01)
            self.snapshots.append(checkpoint)

    orchestrator = Orchestrator(_config(tmp_path, "checkpoint-lock"))
    store = Store()
    orchestrator._finding_store = store  # type: ignore[assignment]
    orchestrator._retry_barriers.add(PipelineStage.CRAWL.value)
    await asyncio.gather(
        orchestrator._store_checkpoint(
            PipelineStage.PARSE,
            ["https://example.com"],
            stage_state={"parse_complete_hashes": ["a"]},
        ),
        orchestrator._store_checkpoint(
            PipelineStage.REPORT,
            ["https://example.com"],
            stage_state={"report_marker": True},
        ),
    )
    assert orchestrator._checkpoint_snapshot is not None
    state = orchestrator._checkpoint_snapshot.stage_state
    assert state["parse_complete_hashes"] == ["a"]
    assert state["report_marker"] is True
    assert orchestrator._checkpoint_snapshot.stage == PipelineStage.CRAWL.value
    assert all(item.stage == PipelineStage.CRAWL.value for item in store.snapshots)


def test_mixed_dns_answer_is_rejected(monkeypatch) -> None:
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: answers)
    with pytest.raises(UnsafeNetworkTarget):
        safe_http._resolve_validated_addresses("example.com", 443, False)


@pytest.mark.asyncio
async def test_pinned_backend_dials_only_validated_ip(monkeypatch) -> None:
    calls: list[str] = []

    class Backend:
        async def connect_tcp(self, *, host: str, **_kwargs: Any) -> object:
            calls.append(host)
            return object()

        async def sleep(self, _seconds: float) -> None:
            return None

    monkeypatch.setattr(
        safe_http,
        "_resolve_validated_addresses",
        lambda *_args: ["93.184.216.34"],
    )
    backend = PinnedNetworkBackend(backend=Backend())
    stream = await backend.connect_tcp("example.com", 443)
    assert stream is not None
    assert calls == ["93.184.216.34"]


def test_pinned_transport_constructor_fails_closed_without_supported_pool(monkeypatch) -> None:
    class UnsupportedTransport:
        def __init__(self, **_kwargs: Any) -> None:
            self._pool = object()

    monkeypatch.setattr(safe_http.httpx, "AsyncHTTPTransport", UnsupportedTransport)
    with pytest.raises(RuntimeError, match="pinnable"):
        safe_http.build_pinned_transport(allow_private_ips=False, max_connections=1)


def test_origin_bound_headers_strip_host_case_insensitively(tmp_path) -> None:
    config = _config(tmp_path, "mixed-host")
    unsafe_auth = AuthConfig.model_construct(
        headers={"hOsT": "attacker.example", "X-Allowed": "value"},
        cookies={},
        bearer_token=None,
        basic_auth=None,
    )
    object.__setattr__(config, "auth", unsafe_auth)
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com/root"]
    headers = orchestrator._origin_bound_auth_headers("https://example.com/app.js")
    assert headers == {"X-Allowed": "value"}


@pytest.mark.asyncio
@pytest.mark.parametrize("parallel", [False, True])
async def test_custom_rule_incomplete_events_promote_in_serial_and_parallel(
    tmp_path,
    monkeypatch,
    parallel: bool,
) -> None:
    rules_path = tmp_path / f"invalid-rules-{parallel}.json"
    rules_path.write_text(json.dumps({"rules": {"not": "a-list"}}), encoding="utf-8")
    config = _config(tmp_path, f"custom-events-{str(parallel).lower()}")
    config.rules = RuleConfig(custom_rules_file=rules_path)
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com/app.js"]
    monkeypatch.setattr(orchestrator, "_persist_ast", _noop)
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
    if parallel:
        monkeypatch.setenv("BUNDLEINSPECTOR_PARALLEL", "2")
    else:
        monkeypatch.delenv("BUNDLEINSPECTOR_PARALLEL", raising=False)

    asset = JSAsset(url="https://example.com/app.js", content=b"const value = true;")
    asset.compute_hash()
    if not parallel:
        await orchestrator._stage_parse([asset])
    await orchestrator._stage_analyze([asset])
    issues = orchestrator._build_completeness().issues
    custom = [issue for issue in issues if issue.code == "custom_rule_analysis_incomplete"]
    assert custom
    assert custom[0].details["component"] == "custom_rule_loader"
    assert custom[0].details["reason"] == "custom_rule_document_load_error"


@pytest.mark.asyncio
async def test_correlation_cap_promotes_to_report_sarif_and_public_details(
    tmp_path,
    monkeypatch,
) -> None:
    orchestrator = Orchestrator(_config(tmp_path, "correlation-cap"))
    orchestrator._seed_urls = ["https://example.com"]
    graph = CorrelationGraph()
    graph.telemetry.update({
        "capped_passes": {"_add_import_edges": 2},
        "truncated_candidates": 7,
        "truncated_candidates_lower_bound": 9,
        "truncated_candidates_unknown": 2,
    })
    monkeypatch.setattr(orchestrator.correlator, "correlate", lambda _findings: graph)
    monkeypatch.setattr(orchestrator, "_persist_report", _noop)
    correlated = await orchestrator._stage_correlate([])
    report = await orchestrator._stage_report(
        ["https://example.com"],
        [],
        [],
        correlated,
    )
    issue = next(
        item for item in report.completeness.issues
        if item.code == "correlation_graph_truncated"
    )
    assert issue.details["truncated_candidates_lower_bound"] == 9

    public = PublicReportProjector(b"k" * 32).project(report)
    public_issue = next(
        item for item in public.completeness.issues
        if item.code == "correlation_graph_truncated"
    )
    assert public_issue.details["capped_passes"] == {"_add_import_edges": 2}
    sarif = json.loads(SARIFReporter().generate(report))
    notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    notification = next(
        item for item in notifications
        if "correlation_graph_truncated" in item["message"]["text"]
    )
    assert notification["properties"]["details"]["truncated_candidates"] == 7


@pytest.mark.asyncio
async def test_parallel_worker_timeout_terminates_pool_and_recovers_serially(
    tmp_path,
    monkeypatch,
) -> None:
    import bundleInspector.core.orchestrator as orchestrator_module

    config = _config(tmp_path, "parallel-timeout")
    config.parser.analysis_worker_timeout = 0.1
    orchestrator = Orchestrator(config)
    orchestrator._seed_urls = ["https://example.com/app.js"]
    monkeypatch.setenv("BUNDLEINSPECTOR_PARALLEL", "2")
    monkeypatch.setattr(
        orchestrator_module,
        "analyze_asset_task_with_telemetry",
        _slow_only_in_child,
    )
    monkeypatch.setattr(orchestrator, "_store_checkpoint", _noop)
    before_children = {child.pid for child in multiprocessing.active_children()}
    asset = JSAsset(url="https://example.com/app.js", content=b"const value = 1;")
    asset.compute_hash()

    started = time.perf_counter()
    findings = await orchestrator._stage_analyze([asset])
    elapsed = time.perf_counter() - started
    await asyncio.sleep(0.1)

    assert findings == []
    assert elapsed < 3
    assert any(
        issue.code == "parallel_worker_timeout"
        for issue in orchestrator._build_completeness().issues
    )
    assert {
        child.pid for child in multiprocessing.active_children()
        if child.pid not in before_children
    } == set()
