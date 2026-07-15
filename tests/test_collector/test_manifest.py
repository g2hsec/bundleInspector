"""Tests for build manifest collection."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from bundleInspector.collector import manifest as manifest_module
from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.config import AuthConfig, CrawlerConfig, ScopeConfig, ThirdPartyPolicy
from bundleInspector.core.rate_limiter import RateLimiter
from bundleInspector.core.safe_http import UnsafeRequestTarget
from bundleInspector.storage.models import LoadMethod


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", content_type: str = "application/json"):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}


class _FakeClient:
    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses

    async def get(self, url: str) -> _FakeResponse:
        return self._responses.get(url, _FakeResponse(status_code=404, text="", content_type="text/plain"))

    async def aclose(self) -> None:
        return None


def _build_scope(seed_url: str = "https://example.com/index.html") -> ScopePolicy:
    config = ScopeConfig()
    config.add_seed_domain(seed_url)
    return ScopePolicy(config)


@pytest.mark.asyncio
async def test_parse_json_manifest_resolves_relative_paths_and_preserves_metadata():
    collector = ManifestCollector(CrawlerConfig())
    scope = _build_scope()
    manifest_url = "https://example.com/build/manifest.json"
    content = """
    {
      "entrypoints": {
        "main": ["./static/js/app.js", "../assets/chunk.js", "./static/css/app.css"]
      },
      "runtime": {
        "file": "/static/js/runtime.js"
      }
    }
    """

    refs = [
        ref
        async for ref in collector._parse_json_manifest(
            content,
            manifest_url,
            "https://example.com",
            scope,
        )
    ]

    assert {ref.url for ref in refs} == {
        "https://example.com/build/static/js/app.js",
        "https://example.com/assets/chunk.js",
        "https://example.com/static/js/runtime.js",
    }
    assert all(ref.initiator == manifest_url for ref in refs)
    assert all(ref.load_context == manifest_url for ref in refs)
    assert all(ref.method == LoadMethod.MANIFEST for ref in refs)


@pytest.mark.asyncio
async def test_parse_js_manifest_extracts_chunk_paths_relative_to_manifest():
    collector = ManifestCollector(CrawlerConfig())
    scope = _build_scope()
    manifest_url = "https://example.com/_next/static/_buildManifest.js"
    content = """
    self.__BUILD_MANIFEST = {
      rootMainFiles: ["/_next/static/chunks/main.js", "./chunks/framework.js", "/static/css/app.css"],
      lowPriorityFiles: ["chunks/abcdef12.js"]
    };
    """

    refs = [
        ref
        async for ref in collector._parse_js_manifest(
            content,
            manifest_url,
            "https://example.com",
            scope,
        )
    ]

    assert {ref.url for ref in refs} == {
        "https://example.com/_next/static/chunks/main.js",
        "https://example.com/_next/static/chunks/framework.js",
        "https://example.com/_next/static/chunks/abcdef12.js",
    }
    assert all(ref.initiator == manifest_url for ref in refs)
    assert all(ref.load_context == manifest_url for ref in refs)
    assert all(ref.method == LoadMethod.MANIFEST for ref in refs)


@pytest.mark.asyncio
async def test_collect_deduplicates_refs_across_manifest_sources_and_chunk_dirs():
    collector = ManifestCollector(CrawlerConfig())
    collector._client = _FakeClient({
        "https://example.com/asset-manifest.json": _FakeResponse(
            text='{"files":{"main":"./static/js/app.js"}}',
            content_type="application/json",
        ),
        "https://example.com/manifest.json": _FakeResponse(
            text='{"entry":{"file":"/static/js/app.js"}}',
            content_type="application/json",
        ),
        "https://example.com/static/js/": _FakeResponse(
            text='<html><body><a href="app.js">app.js</a></body></html>',
            content_type="text/html",
        ),
    })
    scope = _build_scope()

    refs = [ref async for ref in collector.collect("https://example.com/app", scope)]

    assert [ref.url for ref in refs] == ["https://example.com/static/js/app.js"]
    assert all(ref.method == LoadMethod.MANIFEST for ref in refs)


@pytest.mark.asyncio
async def test_manifest_setup_uses_pinned_transport_without_global_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    transport = object()

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def aclose(self) -> None:
            return None

    def build_transport(*, allow_private_ips: bool, max_connections: int) -> object:
        captured["transport_policy"] = (allow_private_ips, max_connections)
        return transport

    monkeypatch.setattr(manifest_module.httpx, "AsyncClient", Client)
    monkeypatch.setattr(manifest_module, "build_pinned_transport", build_transport)
    collector = ManifestCollector(
        CrawlerConfig(max_concurrent=4),
        AuthConfig(bearer_token="secret", cookies={"sid": "cookie"}),
        allow_private_ips=True,
    )

    await collector.setup()

    assert captured["transport"] is transport
    assert captured["transport_policy"] == (True, 4)
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False
    assert "cookies" not in captured
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert "Authorization" not in headers


@pytest.mark.asyncio
async def test_manifest_manual_redirect_strips_auth_and_uses_shared_limiter() -> None:
    calls: list[tuple[str, dict[str, str]]] = []
    limited: list[str] = []

    class Client:
        async def get(
            self,
            url: str,
            headers: dict[str, str] | None = None,
        ) -> httpx.Response:
            calls.append((url, dict(headers or {})))
            request = httpx.Request("GET", url, headers=headers)
            if len(calls) == 1:
                return httpx.Response(
                    302,
                    headers={"location": "https://cdn.example.net/manifest.json"},
                    request=request,
                )
            return httpx.Response(200, json={}, request=request)

    class Limiter(RateLimiter):
        async def acquire(self, url: str) -> None:
            limited.append(url)

    collector = ManifestCollector(
        CrawlerConfig(),
        AuthConfig(headers={"X-Scan": "secret"}, bearer_token="token"),
        rate_limiter=Limiter(),
    )
    collector._client = Client()
    collector._bind_auth_origin("https://example.com/root")
    scope = ScopePolicy(ScopeConfig(third_party_policy=ThirdPartyPolicy.ANALYZE))

    response = await collector._request("https://example.com/manifest.json", scope)

    assert response.status_code == 200
    assert calls[0][1] == {
        "X-Scan": "secret",
        "Authorization": "Bearer token",
    }
    assert calls[1][1] == {}
    assert limited == [
        "https://example.com/manifest.json",
        "https://cdn.example.net/manifest.json",
    ]


@pytest.mark.asyncio
async def test_manifest_request_policy_blocks_metadata_but_honors_private_opt_in() -> None:
    calls: list[str] = []

    class Client:
        async def get(self, url: str) -> httpx.Response:
            calls.append(url)
            return httpx.Response(200, json={}, request=httpx.Request("GET", url))

    scope = ScopePolicy(ScopeConfig(third_party_policy=ThirdPartyPolicy.ANALYZE))
    collector = ManifestCollector(CrawlerConfig(), allow_private_ips=True)
    collector._client = Client()

    response = await collector._request("http://10.20.30.40/manifest.json", scope)
    assert response.status_code == 200
    with pytest.raises(UnsafeRequestTarget):
        await collector._request("http://169.254.169.254/latest/meta-data/", scope)
    with pytest.raises(UnsafeRequestTarget):
        await collector._request("http://127.0.0.1/manifest.json", scope)
    assert calls == ["http://10.20.30.40/manifest.json"]


@pytest.mark.asyncio
async def test_redirect_final_manifest_base_and_vite_metadata_do_not_create_phantom_assets(
    monkeypatch,
) -> None:
    collector = ManifestCollector(CrawlerConfig())
    response = httpx.Response(
        200,
        json={
            "src/foo.js": {
                "file": "assets/app.js",
                "src": "src/foo.js",
                "imports": ["_shared.js"],
            },
            "_shared.js": {"file": "assets/shared.js"},
        },
        request=httpx.Request("GET", "https://cdn.example.net/build/manifest.json"),
    )

    async def request(_url: str, _scope: ScopePolicy) -> httpx.Response:
        return response

    collector._client = object()
    monkeypatch.setattr(collector, "_request", request)
    scope = ScopePolicy(ScopeConfig(third_party_policy=ThirdPartyPolicy.ANALYZE))
    refs = [
        ref
        async for ref in collector._parse_manifest(
            "https://app.example.com/manifest.json",
            "https://app.example.com",
            scope,
        )
    ]
    assert {ref.url for ref in refs} == {
        "https://cdn.example.net/build/assets/app.js",
        "https://cdn.example.net/build/assets/shared.js",
    }


@pytest.mark.asyncio
async def test_manifest_retries_transient_status_before_parsing() -> None:
    class Client:
        def __init__(self):
            self.calls = 0

        async def get(self, url: str) -> httpx.Response:
            self.calls += 1
            if self.calls == 1:
                return httpx.Response(503, request=httpx.Request("GET", url))
            return httpx.Response(
                200,
                json={"main": "assets/app.js"},
                request=httpx.Request("GET", url),
            )

    collector = ManifestCollector(CrawlerConfig(max_retries=1, retry_delay=0))
    client = Client()
    collector._client = client
    scope = ScopePolicy(ScopeConfig(third_party_policy=ThirdPartyPolicy.ANALYZE))
    refs = [
        ref
        async for ref in collector._parse_manifest(
            "https://example.com/manifest.json",
            "https://example.com",
            scope,
        )
    ]

    assert [ref.url for ref in refs] == ["https://example.com/assets/app.js"]
    assert client.calls == 2
