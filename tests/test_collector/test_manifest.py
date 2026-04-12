"""Tests for build manifest collection."""

from __future__ import annotations

import pytest

from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.config import CrawlerConfig, ScopeConfig
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

