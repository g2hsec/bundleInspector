"""Tests for headless collector behavior with mocked browser objects."""

from __future__ import annotations

import pytest

from bundleInspector.collector import headless as headless_module
from bundleInspector.collector.headless import HeadlessCollector, HeadlessMultiPageCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.config import AuthConfig, CrawlerConfig, ScopeConfig, ThirdPartyPolicy
from bundleInspector.storage.models import JSReference, LoadMethod


class _FakeFrame:
    def __init__(self, url: str):
        self.url = url


class _FakeRequest:
    def __init__(self, frame_url: str | None = "https://example.com/frame", headers: dict[str, str] | None = None):
        self.frame = _FakeFrame(frame_url) if frame_url else None
        self.headers = headers or {}


class _FakeResponse:
    def __init__(
        self,
        url: str,
        content_type: str = "application/javascript",
        frame_url: str | None = "https://example.com/frame",
    ):
        self.url = url
        self.headers = {"content-type": content_type}
        self.request = _FakeRequest(frame_url=frame_url)


class _FakeRoute:
    def __init__(self):
        self.continued_headers: dict[str, str] | None = None

    async def continue_(self, headers: dict[str, str]) -> None:
        self.continued_headers = headers


class _FakeElement:
    def __init__(self):
        self.click_count = 0

    async def click(self) -> None:
        self.click_count += 1


class _FakePage:
    def __init__(
        self,
        responses: list[_FakeResponse] | None = None,
        evaluate_result=None,
        fail_networkidle: bool = False,
        content_html: str = "",
        selector_elements: dict[str, object] | None = None,
        selector_lists: dict[str, list[object]] | None = None,
    ):
        self._responses = responses or []
        self._evaluate_result = evaluate_result if evaluate_result is not None else []
        self._fail_networkidle = fail_networkidle
        self._content_html = content_html
        self._selector_elements = selector_elements or {}
        self._selector_lists = selector_lists or {}
        self._emitted = False
        self.goto_calls: list[tuple[str, str, int]] = []
        self.handlers: dict[str, list] = {}
        self.url = ""

    def on(self, event: str, handler) -> None:
        self.handlers.setdefault(event, []).append(handler)

    async def goto(self, url: str, wait_until: str, timeout: int) -> None:
        self.goto_calls.append((url, wait_until, timeout))
        self.url = url
        if wait_until == "networkidle" and self._fail_networkidle:
            raise RuntimeError("networkidle timeout")
        if not self._emitted:
            self._emitted = True
            for handler in self.handlers.get("response", []):
                for response in self._responses:
                    handler(response)

    async def evaluate(self, script: str):
        return self._evaluate_result

    async def content(self) -> str:
        return self._content_html

    async def query_selector(self, selector: str):
        return self._selector_elements.get(selector)

    async def query_selector_all(self, selector: str):
        return list(self._selector_lists.get(selector, []))

    async def wait_for_load_state(self, state: str, timeout: int) -> None:
        return None


class _FakeContext:
    def __init__(self, page: _FakePage, storage_state_data: dict | None = None):
        self._page = page
        self.closed = False
        self.cookies_added: list[dict] = []
        self.routes: list[tuple[str, object]] = []
        self._storage_state_data = storage_state_data or {}

    async def new_page(self) -> _FakePage:
        return self._page

    async def add_cookies(self, cookies: list[dict]) -> None:
        self.cookies_added.extend(cookies)

    async def route(self, pattern: str, handler) -> None:
        self.routes.append((pattern, handler))

    async def close(self) -> None:
        self.closed = True

    async def storage_state(self) -> dict:
        return dict(self._storage_state_data)


class _FakeBrowser:
    def __init__(self, context: _FakeContext):
        self._context = context
        self.new_context_calls: list[dict] = []

    async def new_context(self, **kwargs) -> _FakeContext:
        self.new_context_calls.append(kwargs)
        return self._context


def _scope() -> ScopePolicy:
    config = ScopeConfig(
        allowed_domains=["example.com", "*.example.com"],
        third_party_policy=ThirdPartyPolicy.SKIP,
    )
    return ScopePolicy(config)


@pytest.fixture
def _enable_headless(monkeypatch):
    monkeypatch.setattr(headless_module, "PLAYWRIGHT_AVAILABLE", True)


@pytest.mark.asyncio
async def test_headless_create_context_applies_cookies_and_auth_headers(_enable_headless):
    page = _FakePage()
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    auth = AuthConfig(
        cookies={"session": "abc123"},
        headers={"X-Test": "1"},
        bearer_token="secret-token",
    )
    collector = HeadlessCollector(CrawlerConfig(), auth)
    collector._browser = browser

    created = await collector._create_context("https://example.com/app")

    assert created is context
    assert browser.new_context_calls
    assert browser.new_context_calls[0]["ignore_https_errors"] is True
    assert context.cookies_added == [{
        "name": "session",
        "value": "abc123",
        "domain": "example.com",
        "path": "/",
    }]
    assert context.routes and context.routes[0][0] == "**/*"

    route = _FakeRoute()
    request = _FakeRequest(headers={"Accept": "*/*"})
    await context.routes[0][1](route, request)

    assert route.continued_headers == {
        "Accept": "*/*",
        "X-Test": "1",
        "Authorization": "Bearer secret-token",
    }


@pytest.mark.asyncio
async def test_headless_create_context_restores_browser_storage_state(_enable_headless):
    page = _FakePage()
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    collector = HeadlessCollector(CrawlerConfig())
    collector._browser = browser
    collector.load_resume_state({
        "browser_storage_state": {
            "cookies": [{"name": "session", "value": "abc123"}],
            "origins": [{"origin": "https://example.com", "localStorage": []}],
        }
    })

    await collector._create_context("https://example.com/app")

    assert browser.new_context_calls[0]["storage_state"] == {
        "cookies": [{"name": "session", "value": "abc123"}],
        "origins": [{"origin": "https://example.com", "localStorage": []}],
    }


@pytest.mark.asyncio
async def test_headless_collect_falls_back_and_deduplicates_js_refs(_enable_headless):
    page = _FakePage(
        responses=[
            _FakeResponse(
                "https://example.com/static/app.js",
                content_type="application/javascript",
                frame_url="https://example.com/dashboard",
            ),
            _FakeResponse(
                "https://example.com/static/app.js",
                content_type="application/javascript",
                frame_url="https://example.com/dashboard",
            ),
            _FakeResponse(
                "https://example.com/static/chunk.js",
                content_type="text/plain",
                frame_url="https://example.com/dashboard",
            ),
            _FakeResponse(
                "https://cdn.example.net/lib.js",
                content_type="application/javascript",
                frame_url="https://example.com/dashboard",
            ),
            _FakeResponse(
                "https://example.com/static/app.css",
                content_type="text/css",
                frame_url="https://example.com/dashboard",
            ),
        ],
        fail_networkidle=True,
    )
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    collector = HeadlessCollector(
        CrawlerConfig(page_timeout=1, headless_wait_time=0, explore_routes=False)
    )
    collector._browser = browser

    refs = [ref async for ref in collector.collect("https://example.com/app", _scope())]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/app.js",
        "https://example.com/static/chunk.js",
    ]
    assert all(ref.method == LoadMethod.NETWORK_CAPTURE for ref in refs)
    assert all(ref.initiator == "https://example.com/app" for ref in refs)
    assert all(ref.load_context == "https://example.com/dashboard" for ref in refs)
    assert [call[1] for call in page.goto_calls] == ["networkidle", "domcontentloaded"]
    assert context.closed is True


@pytest.mark.asyncio
async def test_headless_collect_resumes_from_saved_current_page_url(_enable_headless):
    page = _FakePage()
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    collector = HeadlessCollector(
        CrawlerConfig(page_timeout=1, headless_wait_time=0, explore_routes=False)
    )
    collector._browser = browser
    collector.load_resume_state({
        "current_page_url": "https://example.com/app?step=2",
    })

    refs = [ref async for ref in collector.collect("https://example.com/app", _scope())]

    assert refs == []
    assert page.goto_calls[0][0] == "https://example.com/app?step=2"


@pytest.mark.asyncio
async def test_headless_multipage_find_page_links_filters_external_and_static_resources(_enable_headless):
    page = _FakePage(
        evaluate_result=[
            "https://example.com/next",
            "https://example.com/docs",
            "https://example.com/static/app.js",
            "https://example.com/image.png",
            "https://other.example.org/out",
            "https://example.com/next",
        ],
        content_html="""
            <html>
              <body>
                <a href="/next">Next</a>
                <a href="/docs">Docs</a>
              </body>
            </html>
        """,
    )
    context = _FakeContext(page)
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))

    async def _create_context(url: str):
        return context

    collector._collector._browser = object()
    collector._collector._create_context = _create_context

    links = await collector._find_page_links("https://example.com", _scope())

    assert set(links) == {
        "https://example.com/next",
        "https://example.com/docs",
    }
    assert "href=\"/next\"" in collector._inflight_html
    assert context.closed is True


@pytest.mark.asyncio
async def test_headless_multipage_collector_tracks_page_progress(_enable_headless):
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))
    requested_urls: list[str] = []

    async def _collect(url: str, scope: ScopePolicy):
        requested_urls.append(url)
        if url == "https://example.com":
            yield JSReference(url="https://example.com/static/a.js")
        elif url == "https://example.com/next":
            yield JSReference(url="https://example.com/static/b.js")

    async def _find_links(url: str, scope: ScopePolicy):
        return ["https://example.com/next"] if url == "https://example.com" else []

    progress_states: list[dict] = []

    async def _on_page_complete(state):
        progress_states.append(state)

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.on_page_complete = _on_page_complete

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]
    assert requested_urls == ["https://example.com", "https://example.com/next"]
    assert progress_states[0]["inflight_page"]["url"] == "https://example.com"
    assert progress_states[0]["inflight_page"]["depth"] == 0
    assert any(
        state.get("inflight_page", {}).get("url") == "https://example.com"
        and state.get("inflight_page", {}).get("depth") == 0
        and state.get("collected_js_urls") == ["https://example.com/static/a.js"]
        and state.get("inflight_page", {}).get("discovered_refs") == [
            {"url": "https://example.com/static/a.js"}
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
async def test_headless_multipage_collector_resumes_from_saved_page_queue(_enable_headless):
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))
    requested_urls: list[str] = []

    async def _collect(url: str, scope: ScopePolicy):
        requested_urls.append(url)
        if url == "https://example.com/next":
            yield JSReference(url="https://example.com/static/b.js")

    async def _find_links(url: str, scope: ScopePolicy):
        return []

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "pending_pages": [{"url": "https://example.com/next", "depth": 1}],
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_headless_multipage_collector_resumes_from_inflight_page(_enable_headless):
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))
    requested_urls: list[str] = []

    async def _collect(url: str, scope: ScopePolicy):
        requested_urls.append(url)
        if url == "https://example.com/next":
            yield JSReference(url="https://example.com/static/b.js")

    async def _find_links(url: str, scope: ScopePolicy):
        return []

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "pending_pages": [],
        "inflight_page": {"url": "https://example.com/next", "depth": 1},
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_headless_multipage_collector_resumes_with_collected_js_urls_and_skips_duplicate_ref(_enable_headless):
    """Saved collected JS URLs should suppress duplicate headless ref emission inside a resumed inflight page."""
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))
    requested_urls: list[str] = []

    async def _collect(url: str, scope: ScopePolicy):
        requested_urls.append(url)
        if url == "https://example.com/next":
            yield JSReference(url="https://example.com/static/a.js")
            yield JSReference(url="https://example.com/static/b.js")

    async def _find_links(url: str, scope: ScopePolicy):
        return []

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.load_resume_state({
        "visited_urls": ["https://example.com"],
        "collected_js_urls": ["https://example.com/static/a.js"],
        "pending_pages": [],
        "inflight_page": {"url": "https://example.com/next", "depth": 1},
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]
    assert requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_headless_multipage_collector_resumes_with_saved_link_iteration_progress(_enable_headless):
    """Saved inflight link progress should avoid re-extracting headless links from the beginning."""
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))
    requested_urls: list[str] = []

    async def _collect(url: str, scope: ScopePolicy):
        requested_urls.append(url)
        if url == "https://example.com/next":
            yield JSReference(url="https://example.com/static/b.js")

    async def _find_links(url: str, scope: ScopePolicy):
        raise AssertionError("_find_page_links should not run when inflight link progress is restored")

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
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
    assert requested_urls == ["https://example.com/next"]


@pytest.mark.asyncio
async def test_headless_multipage_collector_resumes_with_saved_ref_iteration_progress_without_recollect(_enable_headless):
    """Saved inflight ref progress should replay remaining refs without recollecting the page when ref discovery already completed."""
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=0, use_headless=True))

    async def _collect(url: str, scope: ScopePolicy):
        raise AssertionError("headless collect should not run when inflight ref progress is restored")
        yield  # pragma: no cover

    async def _find_links(url: str, scope: ScopePolicy):
        raise AssertionError("link extraction should not run at max_depth=0")

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "discovered_refs": [
                {"url": "https://example.com/static/a.js"},
                {"url": "https://example.com/static/b.js"},
            ],
            "next_ref_index": 1,
            "refs_complete": True,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == ["https://example.com/static/b.js"]


@pytest.mark.asyncio
async def test_headless_multipage_collector_resumes_with_completed_empty_link_state_without_reextract(_enable_headless):
    """Completed empty headless link state should suppress link extraction on resumed pages with no discovered links."""
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=2, use_headless=True))

    async def _collect(url: str, scope: ScopePolicy):
        raise AssertionError("headless collect should not run when ref discovery already completed")
        yield  # pragma: no cover

    async def _find_links(url: str, scope: ScopePolicy):
        raise AssertionError("_find_page_links should not run when empty link completion is restored")

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "discovered_refs": [
                {"url": "https://example.com/static/a.js"},
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


@pytest.mark.asyncio
async def test_headless_multipage_collector_resumes_link_extraction_from_html_snapshot_without_reopening_browser(_enable_headless):
    """Saved headless HTML snapshots should allow link extraction resume without opening a browser page again."""
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=1, use_headless=True))
    requested_urls: list[str] = []

    async def _collect(url: str, scope: ScopePolicy):
        requested_urls.append(url)
        if url == "https://example.com":
            yield JSReference(url="https://example.com/static/a.js")
        elif url == "https://example.com/next":
            yield JSReference(url="https://example.com/static/b.js")

    async def _find_links(url: str, scope: ScopePolicy):
        raise AssertionError("_find_page_links should not run when html_snapshot is restored")

    collector._collector.collect = _collect
    collector._find_page_links = _find_links
    collector.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "html_snapshot": """
                <html>
                  <body>
                    <a href="/next">Next</a>
                    <a href="/static/app.js">Static asset</a>
                    <a href="https://other.example.org/out">External</a>
                  </body>
                </html>
            """,
        },
    })

    refs = [ref async for ref in collector.collect("https://example.com", _scope())]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]
    assert requested_urls == ["https://example.com", "https://example.com/next"]


@pytest.mark.asyncio
async def test_headless_collector_resumes_route_exploration_from_saved_route_index(_enable_headless):
    """Saved route-exploration progress should skip already-clicked SPA links."""
    first = _FakeElement()
    second = _FakeElement()
    page = _FakePage(
        evaluate_result=["/first", "/second"],
        selector_elements={
            'a[href="/first"]': first,
            'a[href="/second"]': second,
        },
    )
    collector = HeadlessCollector(
        CrawlerConfig(
            page_timeout=1,
            headless_wait_time=0,
            explore_routes=True,
            max_route_exploration=10,
        )
    )
    collector.load_resume_state({
        "route_links": ["/first", "/second"],
        "next_route_index": 1,
        "route_links_complete": True,
    })

    await collector._explore_routes(page, "https://example.com/app", _scope())

    assert first.click_count == 0
    assert second.click_count == 1
    assert collector.export_resume_state()["next_route_index"] == 2
    assert collector.export_resume_state()["interactive_complete"] is True


@pytest.mark.asyncio
async def test_headless_collector_replays_pending_route_before_continuing_resume(_enable_headless):
    """Saved pending route state should replay the interrupted route before continuing later routes."""
    first = _FakeElement()
    second = _FakeElement()
    page = _FakePage(
        selector_elements={
            'a[href="/first"]': first,
            'a[href="/second"]': second,
        },
    )
    collector = HeadlessCollector(
        CrawlerConfig(
            page_timeout=1,
            headless_wait_time=0,
            explore_routes=True,
            max_route_exploration=10,
        )
    )
    collector.load_resume_state({
        "route_links": ["/first", "/second"],
        "next_route_index": 0,
        "route_links_complete": True,
        "current_route_url": "https://example.com/first",
        "route_return_pending": True,
    })

    await collector._explore_routes(page, "https://example.com/app", _scope())

    assert first.click_count == 0
    assert second.click_count == 1
    assert ("https://example.com/first", "domcontentloaded", 5000) in page.goto_calls
    assert ("https://example.com/app", "domcontentloaded", 5000) in page.goto_calls
    state = collector.export_resume_state()
    assert state["next_route_index"] == 2
    assert state["route_links_complete"] is True
    assert "current_route_url" not in state
    assert "route_return_pending" not in state


@pytest.mark.asyncio
async def test_headless_collector_replays_saved_discovered_refs_and_deduplicates_new_network_capture(_enable_headless):
    """Saved discovered refs should replay before navigation and dedupe repeated network captures on resume."""
    page = _FakePage(
        responses=[
            _FakeResponse(
                "https://example.com/static/a.js",
                content_type="application/javascript",
                frame_url="https://example.com/dashboard",
            ),
            _FakeResponse(
                "https://example.com/static/b.js",
                content_type="application/javascript",
                frame_url="https://example.com/dashboard",
            ),
        ],
    )
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    collector = HeadlessCollector(
        CrawlerConfig(page_timeout=1, headless_wait_time=0, explore_routes=False)
    )
    collector._browser = browser
    collector.load_resume_state({
        "discovered_refs": [
            {
                "url": "https://example.com/static/a.js",
                "initiator": "https://example.com/app",
                "load_context": "https://example.com/dashboard",
                "method": LoadMethod.NETWORK_CAPTURE.value,
            }
        ],
        "next_ref_index": 0,
    })

    refs = [ref async for ref in collector.collect("https://example.com/app", _scope())]

    assert [ref.url for ref in refs] == [
        "https://example.com/static/a.js",
        "https://example.com/static/b.js",
    ]


def test_headless_collector_exports_and_restores_discovered_ref_resume_state(_enable_headless):
    """Nested headless checkpoints should carry discovered network refs and replay index state."""
    collector = HeadlessCollector(CrawlerConfig(explore_routes=True))
    collector.load_resume_state({
        "discovered_refs": [
            {
                "url": "https://example.com/static/a.js",
                "initiator": "https://example.com/app",
                "load_context": "https://example.com/dashboard",
                "method": LoadMethod.NETWORK_CAPTURE.value,
            }
        ],
        "next_ref_index": 1,
        "refs_complete": True,
        "route_links": ["/next"],
        "next_route_index": 1,
        "route_links_complete": True,
    })

    state = collector.export_resume_state()

    assert state["discovered_refs"] == [
        {
            "url": "https://example.com/static/a.js",
            "initiator": "https://example.com/app",
            "load_context": "https://example.com/dashboard",
            "method": LoadMethod.NETWORK_CAPTURE.value,
        }
    ]
    assert state["next_ref_index"] == 1
    assert state["refs_complete"] is True
    assert state["route_links"] == ["/next"]


def test_headless_collector_exports_and_restores_browser_runtime_resume_state(_enable_headless):
    """Nested headless checkpoints should carry browser storage and current page URL state."""
    collector = HeadlessCollector(CrawlerConfig(explore_routes=True))
    collector.load_resume_state({
        "browser_storage_state": {
            "cookies": [{"name": "session", "value": "abc123"}],
            "origins": [{"origin": "https://example.com", "localStorage": []}],
        },
        "current_page_url": "https://example.com/app?step=2",
        "interactive_pending_selector_index": 1,
        "interactive_pending_element_index": 3,
    })

    state = collector.export_resume_state()

    assert state["browser_storage_state"] == {
        "cookies": [{"name": "session", "value": "abc123"}],
        "origins": [{"origin": "https://example.com", "localStorage": []}],
    }
    assert state["current_page_url"] == "https://example.com/app?step=2"
    assert state["interactive_pending_selector_index"] == 1
    assert state["interactive_pending_element_index"] == 3


def test_headless_multipage_collector_exports_and_restores_headless_route_resume_state(_enable_headless):
    """In-flight multipage checkpoints should carry nested headless route-exploration progress."""
    collector = HeadlessMultiPageCollector(CrawlerConfig(max_depth=1, use_headless=True, explore_routes=True))
    collector._inflight_page = ("https://example.com", 0)
    collector._collector.load_resume_state({
        "discovered_refs": [
            {
                "url": "https://example.com/static/a.js",
                "initiator": "https://example.com/app",
                "load_context": "https://example.com/dashboard",
                "method": LoadMethod.NETWORK_CAPTURE.value,
            }
        ],
        "next_ref_index": 1,
        "refs_complete": True,
        "route_links": ["/first", "/second"],
        "next_route_index": 1,
        "route_links_complete": True,
        "current_route_url": "https://example.com/second",
        "route_return_pending": True,
        "interactive_selector_index": 2,
        "interactive_element_index": 1,
        "interactive_pending_selector_index": 2,
        "interactive_pending_element_index": 1,
    })

    state = collector.export_resume_state()

    assert state["inflight_page"]["headless_route_state"] == {
        "discovered_refs": [
            {
                "url": "https://example.com/static/a.js",
                "initiator": "https://example.com/app",
                "load_context": "https://example.com/dashboard",
                "method": LoadMethod.NETWORK_CAPTURE.value,
            }
        ],
        "next_ref_index": 1,
        "refs_complete": True,
        "route_links": ["/first", "/second"],
        "next_route_index": 1,
        "route_links_complete": True,
        "current_route_url": "https://example.com/second",
        "route_return_pending": True,
        "interactive_selector_index": 2,
        "interactive_element_index": 1,
        "interactive_pending_selector_index": 2,
        "interactive_pending_element_index": 1,
        "interactive_complete": False,
    }

    restored = HeadlessMultiPageCollector(CrawlerConfig(max_depth=1, use_headless=True, explore_routes=True))
    restored.load_resume_state({
        "visited_urls": [],
        "pending_pages": [],
        "inflight_page": {
            "url": "https://example.com",
            "depth": 0,
            "headless_route_state": state["inflight_page"]["headless_route_state"],
        },
    })

    assert restored._collector.export_resume_state() == state["inflight_page"]["headless_route_state"]


@pytest.mark.asyncio
async def test_headless_collector_replays_pending_interactive_click_before_continuing_resume(_enable_headless):
    """Saved interactive-click progress should replay the interrupted click before advancing to later elements."""
    first = _FakeElement()
    second = _FakeElement()
    collector = HeadlessCollector(CrawlerConfig(explore_routes=True))
    collector.load_resume_state({
        "interactive_selector_index": 0,
        "interactive_element_index": 0,
        "interactive_pending_selector_index": 0,
        "interactive_pending_element_index": 0,
    })
    page = _FakePage(
        selector_lists={
            collector._INTERACTIVE_SELECTORS[0]: [first, second],
        }
    )

    await collector._click_interactive_elements(page)

    assert first.click_count == 1
    assert second.click_count == 1
    state = collector.export_resume_state()
    assert state["interactive_complete"] is True
    assert "interactive_pending_selector_index" not in state
    assert "interactive_pending_element_index" not in state

