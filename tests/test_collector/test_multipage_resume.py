"""Tests for multipage collector resume/progress behavior."""

from __future__ import annotations

import pytest

from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.static import MultiPageStaticCollector
from bundleInspector.config import CrawlerConfig, ScopeConfig


class _FakeResponse:
    """Minimal async HTTP response double."""

    def __init__(self, text: str, content_type: str = "text/html"):
        self.text = text
        self.headers = {"content-type": content_type}

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    """Minimal async client double for multipage static collector tests."""

    def __init__(self, responses: dict[str, _FakeResponse]):
        self._responses = responses
        self.requested_urls: list[str] = []

    async def get(self, url: str) -> _FakeResponse:
        self.requested_urls.append(url)
        return self._responses[url]


def _scope() -> ScopePolicy:
    """Create a permissive first-party scope for example.com."""
    config = ScopeConfig(allowed_domains=["example.com", "*.example.com"])
    return ScopePolicy(config)


@pytest.mark.asyncio
async def test_multipage_static_collector_streams_refs_and_tracks_page_progress():
    """Multipage static crawl should emit refs page-by-page and expose inflight/pending resume state."""
    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=2, use_headless=False))
    collector._collector._client = _FakeClient({
        "https://example.com": _FakeResponse(
            '<html><head><script src="/static/a.js"></script></head>'
            '<body><a href="/next">next</a></body></html>'
        ),
        "https://example.com/next": _FakeResponse(
            '<html><head><script src="/static/b.js"></script></head><body></body></html>'
        ),
    })

    progress_states: list[dict] = []

    async def _on_page_complete(state):
        progress_states.append(state)

    collector.on_page_complete = _on_page_complete

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]
    assert collector._collector._client.requested_urls == [
        "https://example.com",
        "https://example.com/next",
    ]
    assert progress_states[0]["inflight_page"]["url"] == "https://example.com"
    assert progress_states[0]["inflight_page"]["depth"] == 0
    assert any(
        state.get("inflight_page", {}).get("url") == "https://example.com"
        and state.get("inflight_page", {}).get("depth") == 0
        and state.get("collected_js_urls") == ["https://example.com/static/a.js"]
        and state.get("inflight_page", {}).get("discovered_refs") == [
            {"url": "https://example.com/static/a.js", "initiator": "https://example.com", "load_context": "https://example.com"}
        ]
        and state.get("inflight_page", {}).get("next_ref_index") == 1
        and state.get("inflight_page", {}).get("refs_complete") is True
        and any(pending.get("url") == "https://example.com/next" for pending in state["pending_pages"])
        for state in progress_states
    )
    assert any(
        state.get("inflight_page", {}).get("discovered_links") == ["https://example.com/next"]
        and state.get("inflight_page", {}).get("next_link_index") == 0
        for state in progress_states
    )
    assert any(
        "<script src=\"/static/a.js\"></script>" in state.get("inflight_page", {}).get("html_snapshot", "")
        for state in progress_states
        if state.get("inflight_page", {}).get("url") == "https://example.com"
    )
    assert any(
        pending.get("url") == "https://example.com/next"
        for state in progress_states
        for pending in state["pending_pages"]
    )
    assert progress_states[-1]["pending_pages"] == []
    assert progress_states[-1]["collected_js_urls"] == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]
    assert "inflight_page" not in progress_states[-1]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_from_saved_page_queue():
    """Saved visited/pending page state should let static multipage crawl continue without restarting from root."""
    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=2, use_headless=False))
    collector._collector._client = _FakeClient({
        "https://example.com": _FakeResponse(
            '<html><head><script src="/static/a.js"></script></head>'
            '<body><a href="/next">next</a></body></html>'
        ),
        "https://example.com/next": _FakeResponse(
            '<html><head><script src="/static/b.js"></script></head><body></body></html>'
        ),
    })
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "pending_pages": [{"url": "https://example.com/next", "depth": 1}],
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert collector._collector._client.requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_from_inflight_page():
    """Saved inflight page state should be re-queued first during resume."""
    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=2, use_headless=False))
    collector._collector._client = _FakeClient({
        "https://example.com/next": _FakeResponse(
            '<html><head><script src="/static/b.js"></script></head><body></body></html>'
        ),
    })
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "pending_pages": [],
        "inflight_page": {"url": "https://example.com/next", "depth": 1},
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert collector._collector._client.requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_with_collected_js_urls_and_skips_duplicate_ref():
    """Saved collected JS URLs should suppress duplicate ref emission inside a resumed inflight page."""
    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=2, use_headless=False))
    collector._collector._client = _FakeClient({
        "https://example.com/next": _FakeResponse(
            '<html><head>'
            '<script src="/static/a.js"></script>'
            '<script src="/static/b.js"></script>'
            '</head><body></body></html>'
        ),
    })
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "collected_js_urls": ["https://example.com/static/a.js"],
        "pending_pages": [],
        "inflight_page": {"url": "https://example.com/next", "depth": 1},
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert collector._collector._client.requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_with_saved_link_iteration_progress():
    """Saved inflight link progress should avoid re-extracting page links from the beginning."""
    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=2, use_headless=False))
    collector._collector._client = _FakeClient({
        "https://example.com/next": _FakeResponse(
            '<html><head><script src="/static/b.js"></script></head><body></body></html>'
        ),
    })

    def _raise_if_called(soup, base_url, scope):
        raise AssertionError("_extract_page_links should not run when inflight link progress is restored")

    collector._extract_page_links = _raise_if_called
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com/next",
            "depth": 1,
            "discovered_links": [
                "https://example.com/already-seen",
            ],
            "next_link_index": 1,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert collector._collector._client.requested_urls == ["https://example.com/next"]
    assert collector._pending_pages == []


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_with_saved_ref_iteration_progress_without_refetch():
    """Saved inflight ref progress should replay remaining refs without fetching the page again when ref discovery already completed."""

    class _RaisingClient:
        requested_urls: list[str] = []

        async def get(self, url: str):
            raise AssertionError("page fetch should not run when inflight ref progress is restored")

    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=0, use_headless=False))
    collector._collector._client = _RaisingClient()
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "discovered_refs": [
                {
                    "url": "https://example.com/static/a.js",
                    "initiator": "https://example.com",
                    "load_context": "https://example.com",
                },
                {
                    "url": "https://example.com/static/b.js",
                    "initiator": "https://example.com",
                    "load_context": "https://example.com",
                },
            ],
            "next_ref_index": 1,
            "refs_complete": True,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_partial_ref_discovery_from_html_snapshot():
    """Saved HTML snapshots should let partial ref discovery resume without refetching the page."""

    class _RaisingClient:
        requested_urls: list[str] = []

        async def get(self, url: str):
            raise AssertionError("page fetch should not run when html_snapshot is restored")

    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=0, use_headless=False))
    collector._collector._client = _RaisingClient()
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "html_snapshot": (
                '<html><head>'
                '<script src="/static/a.js"></script>'
                '<script src="/static/b.js"></script>'
                "</head><body></body></html>"
            ),
            "discovered_refs": [],
            "next_ref_index": 0,
            "refs_complete": False,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_link_extraction_from_html_snapshot_without_refetch():
    """Saved HTML snapshots should let pending link extraction resume without refetching the root page."""
    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=1, use_headless=False))
    collector._collector._client = _FakeClient({
        "https://example.com/next": _FakeResponse(
            '<html><head><script src="/static/b.js"></script></head><body></body></html>'
        ),
    })
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "html_snapshot": (
                '<html><head><script src="/static/a.js"></script></head>'
                '<body><a href="/next">next</a></body></html>'
            ),
            "discovered_refs": [
                {
                    "url": "https://example.com/static/a.js",
                    "initiator": "https://example.com",
                    "load_context": "https://example.com",
                },
            ],
            "next_ref_index": 1,
            "refs_complete": True,
            "links_complete": False,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert collector._collector._client.requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_multipage_static_collector_resumes_with_completed_empty_link_state_without_reextract():
    """Completed empty link state should suppress link extraction on resumed pages with no discovered links."""

    class _RaisingClient:
        requested_urls: list[str] = []

        async def get(self, url: str):
            raise AssertionError("page fetch should not run when ref discovery already completed")

    collector = MultiPageStaticCollector(CrawlerConfig(max_depth=2, use_headless=False))
    collector._collector._client = _RaisingClient()

    def _raise_if_called(soup, base_url, scope):
        raise AssertionError("_extract_page_links should not run when empty link completion is restored")

    collector._extract_page_links = _raise_if_called
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "discovered_refs": [
                {
                    "url": "https://example.com/static/a.js",
                    "initiator": "https://example.com",
                    "load_context": "https://example.com",
                },
            ],
            "next_ref_index": 1,
            "refs_complete": True,
            "discovered_links": [],
            "next_link_index": 0,
            "links_complete": True,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert refs == []

