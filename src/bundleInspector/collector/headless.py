"""
Headless browser-based JS collector.

Uses Playwright to render pages and capture network requests.
"""

from __future__ import annotations

import asyncio
import logging
from inspect import isawaitable
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from bundleInspector.collector.base import BaseCollector
from bundleInspector.collector.scope import ScopePolicy, normalize_url, is_js_url
from bundleInspector.config import CrawlerConfig, AuthConfig
from bundleInspector.storage.models import JSReference, LoadMethod

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Request,
        Response,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


def _serialize_reference(ref: JSReference) -> dict[str, Any]:
    """Serialize a discovered JS reference into resume-friendly state."""
    payload: dict[str, Any] = {"url": ref.url}
    if ref.initiator:
        payload["initiator"] = ref.initiator
    if ref.load_context:
        payload["load_context"] = ref.load_context
    if ref.method != LoadMethod.SCRIPT_TAG:
        payload["method"] = ref.method.value
    if ref.headers:
        payload["headers"] = dict(ref.headers)
    return payload


def _deserialize_reference(payload: Any) -> JSReference | None:
    """Restore a serialized JS reference from resume state."""
    if not isinstance(payload, dict):
        return None
    url = payload.get("url")
    if not isinstance(url, str) or not url.strip():
        return None
    method_value = payload.get("method", LoadMethod.SCRIPT_TAG.value)
    try:
        method = LoadMethod(method_value)
    except ValueError:
        method = LoadMethod.SCRIPT_TAG
    headers = payload.get("headers")
    return JSReference(
        url=url.strip(),
        initiator=payload.get("initiator", "") if isinstance(payload.get("initiator"), str) else "",
        load_context=payload.get("load_context", "") if isinstance(payload.get("load_context"), str) else "",
        method=method,
        headers=dict(headers) if isinstance(headers, dict) else {},
    )


class HeadlessCollector(BaseCollector):
    """
    Collect JS references using headless browser.

    This is Tier B collection - captures dynamically loaded JS
    through actual browser rendering.
    """

    name = "headless"
    _INTERACTIVE_SELECTORS = [
        'button:not([disabled])',
        '[role="tab"]',
        '[role="button"]',
        '.nav-link',
        '.tab',
    ]

    def __init__(
        self,
        crawler_config: CrawlerConfig,
        auth_config: AuthConfig | None = None,
    ):
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is required for headless collection. "
                "Install with: pip install playwright && playwright install chromium"
            )

        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self._playwright = None
        self._browser: Browser | None = None
        self.on_progress: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None
        self._discovered_refs: list[JSReference] = []
        self._discovered_ref_index: int = 0
        self._discovered_refs_complete: bool = False
        self._discovered_ref_keys: set[tuple[str, str, str, str]] = set()
        self._route_links: list[str] = []
        self._route_index: int = 0
        self._route_links_complete: bool = False
        self._route_current_url: str = ""
        self._route_return_pending: bool = False
        self._interactive_selector_index: int = 0
        self._interactive_element_index: int = 0
        self._interactive_pending_selector_index: int | None = None
        self._interactive_pending_element_index: int | None = None
        self._interactive_complete: bool = False
        self._browser_storage_state: dict[str, Any] = {}
        self._current_page_url: str = ""
        self._active_context: BrowserContext | None = None
        self._active_page: Page | None = None
        self._resume_loaded: bool = False

    async def setup(self) -> None:
        """Initialize browser."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
        )

    async def teardown(self) -> None:
        """Close browser."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def collect(
        self,
        url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """
        Collect JS references by rendering page.

        Args:
            url: Page URL to render
            scope: Scope policy

        Yields:
            JSReference for each discovered JS file
        """
        if not self._resume_loaded:
            self.reset_resume_state()
        self._resume_loaded = False

        if not self._browser:
            await self.setup()

        # Create browser context with auth
        context = await self._create_context(url)
        self._active_context = context

        try:
            page = await context.new_page()
            self._active_page = page

            # Set up response handler
            page.on("response", lambda res: self._on_response(res, url, scope))

            seen_urls: set[str] = set()
            async for ref in self._drain_discovered_refs(scope, seen_urls):
                yield ref

            # Navigate to page
            navigation_succeeded = False
            resume_url = self._current_page_url or url
            try:
                await page.goto(
                    resume_url,
                    wait_until="networkidle",
                    timeout=int(self.config.page_timeout * 1000),
                )
                navigation_succeeded = True
            except Exception as e:
                logger.debug(f"networkidle timeout for {resume_url}, trying domcontentloaded: {e}")
                # Try with domcontentloaded if networkidle times out
                try:
                    await page.goto(
                        resume_url,
                        wait_until="domcontentloaded",
                        timeout=int(self.config.page_timeout * 1000),
                    )
                    navigation_succeeded = True
                except Exception as e2:
                    logger.warning(f"Failed to navigate to {resume_url}: {e2}")

            if not navigation_succeeded:
                return

            self._current_page_url = str(getattr(page, "url", "") or resume_url)

            # Wait a bit for late-loading scripts
            await asyncio.sleep(self.config.headless_wait_time)

            # Explore routes if enabled
            if self.config.explore_routes:
                await self._explore_routes(page, url, scope)

            self._discovered_refs_complete = True
            await self._notify_progress()

            async for ref in self._drain_discovered_refs(scope, seen_urls):
                yield ref

        finally:
            self.reset_resume_state()
            self._active_page = None
            self._active_context = None
            await context.close()

    def reset_resume_state(self) -> None:
        """Reset in-flight route exploration resume state."""
        self._discovered_refs = []
        self._discovered_ref_index = 0
        self._discovered_refs_complete = False
        self._discovered_ref_keys = set()
        self._route_links = []
        self._route_index = 0
        self._route_links_complete = False
        self._route_current_url = ""
        self._route_return_pending = False
        self._interactive_selector_index = 0
        self._interactive_element_index = 0
        self._interactive_pending_selector_index = None
        self._interactive_pending_element_index = None
        self._interactive_complete = False
        self._browser_storage_state = {}
        self._current_page_url = ""

    def load_resume_state(self, state: dict[str, Any]) -> None:
        """Load persisted route-exploration progress for a partial headless page."""
        self.reset_resume_state()
        if not isinstance(state, dict):
            self._resume_loaded = True
            return

        self._discovered_refs = [
            ref
            for ref in (
                _deserialize_reference(item)
                for item in state.get("discovered_refs", [])
            )
            if ref
        ]
        self._discovered_ref_keys = {
            (ref.url, ref.initiator, ref.load_context, ref.method.value)
            for ref in self._discovered_refs
        }
        try:
            self._discovered_ref_index = max(0, int(state.get("next_ref_index", 0)))
        except (TypeError, ValueError):
            self._discovered_ref_index = 0
        self._discovered_ref_index = min(self._discovered_ref_index, len(self._discovered_refs))
        self._discovered_refs_complete = bool(state.get("refs_complete"))

        self._route_links = [
            link.strip()
            for link in state.get("route_links", [])
            if isinstance(link, str) and link.strip()
        ]
        try:
            self._route_index = max(0, int(state.get("next_route_index", 0)))
        except (TypeError, ValueError):
            self._route_index = 0
        self._route_current_url = (
            state.get("current_route_url", "").strip()
            if isinstance(state.get("current_route_url"), str)
            else ""
        )
        self._route_return_pending = bool(state.get("route_return_pending")) and bool(self._route_current_url)
        self._route_links_complete = (
            bool(state.get("route_links_complete"))
            or bool(self._route_links)
            or self._route_index > 0
        )
        try:
            self._interactive_selector_index = max(0, int(state.get("interactive_selector_index", 0)))
        except (TypeError, ValueError):
            self._interactive_selector_index = 0
        try:
            self._interactive_element_index = max(0, int(state.get("interactive_element_index", 0)))
        except (TypeError, ValueError):
            self._interactive_element_index = 0
        pending_selector_index = state.get("interactive_pending_selector_index")
        if pending_selector_index is None:
            self._interactive_pending_selector_index = None
        else:
            try:
                self._interactive_pending_selector_index = max(0, int(pending_selector_index))
            except (TypeError, ValueError):
                self._interactive_pending_selector_index = None
        pending_element_index = state.get("interactive_pending_element_index")
        if pending_element_index is None:
            self._interactive_pending_element_index = None
        else:
            try:
                self._interactive_pending_element_index = max(0, int(pending_element_index))
            except (TypeError, ValueError):
                self._interactive_pending_element_index = None
        self._interactive_complete = bool(state.get("interactive_complete"))
        browser_storage_state = state.get("browser_storage_state")
        if isinstance(browser_storage_state, dict):
            self._browser_storage_state = dict(browser_storage_state)
        self._current_page_url = (
            state.get("current_page_url", "").strip()
            if isinstance(state.get("current_page_url"), str)
            else ""
        )
        self._resume_loaded = True

    def export_resume_state(self) -> dict[str, Any]:
        """Export in-flight route-exploration progress for resume checkpoints."""
        state: dict[str, Any] = {}
        if self._discovered_refs or self._discovered_ref_index or self._discovered_refs_complete:
            state["discovered_refs"] = [
                _serialize_reference(ref)
                for ref in self._discovered_refs
            ]
            state["next_ref_index"] = self._discovered_ref_index
            state["refs_complete"] = self._discovered_refs_complete
        if (
            self._route_links
            or self._route_index
            or self._route_links_complete
            or self._route_current_url
            or self._route_return_pending
        ):
            state["route_links"] = list(self._route_links)
            state["next_route_index"] = self._route_index
            state["route_links_complete"] = self._route_links_complete
            if self._route_current_url:
                state["current_route_url"] = self._route_current_url
            if self._route_return_pending:
                state["route_return_pending"] = True
        if (
            self._interactive_selector_index
            or self._interactive_element_index
            or self._interactive_pending_selector_index is not None
            or self._interactive_pending_element_index is not None
            or self._interactive_complete
        ):
            state["interactive_selector_index"] = self._interactive_selector_index
            state["interactive_element_index"] = self._interactive_element_index
            if self._interactive_pending_selector_index is not None:
                state["interactive_pending_selector_index"] = self._interactive_pending_selector_index
            if self._interactive_pending_element_index is not None:
                state["interactive_pending_element_index"] = self._interactive_pending_element_index
            state["interactive_complete"] = self._interactive_complete
        if self._browser_storage_state:
            state["browser_storage_state"] = dict(self._browser_storage_state)
        if self._current_page_url:
            state["current_page_url"] = self._current_page_url
        return state

    async def _notify_progress(self) -> None:
        """Publish route-exploration progress when a callback is configured."""
        await self._capture_runtime_state()
        if not self.on_progress:
            return
        result = self.on_progress(self.export_resume_state())
        if isawaitable(result):
            await result

    async def _capture_runtime_state(self) -> None:
        """Best-effort snapshot of practical browser/page state for resume checkpoints."""
        if self._active_page is not None:
            page_url = str(getattr(self._active_page, "url", "") or "").strip()
            if page_url:
                self._current_page_url = page_url
        if self._active_context is not None and hasattr(self._active_context, "storage_state"):
            try:
                storage_state = await self._active_context.storage_state()
            except Exception as e:
                logger.debug(f"Failed to snapshot browser storage state: {e}")
            else:
                if isinstance(storage_state, dict):
                    self._browser_storage_state = dict(storage_state)

    async def _create_context(self, target_url: str) -> BrowserContext:
        """Create browser context with auth settings."""
        context_options = {
            "user_agent": self.config.user_agent,
            "viewport": {"width": 1920, "height": 1080},
            "ignore_https_errors": True,
        }
        if self._browser_storage_state:
            context_options["storage_state"] = dict(self._browser_storage_state)

        context = await self._browser.new_context(**context_options)

        # Add cookies with domain extracted from target URL
        if self.auth.cookies:
            parsed = urlparse(target_url)
            domain = parsed.hostname or parsed.netloc
            cookies = []
            for name, value in self.auth.cookies.items():
                cookies.append({
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": "/",
                })
            await context.add_cookies(cookies)

        # Add auth headers via route
        if self.auth.headers or self.auth.bearer_token or self.auth.basic_auth:
            auth_headers = self.auth.get_auth_headers()

            async def add_auth_headers(route, request):
                headers = {**request.headers, **auth_headers}
                await route.continue_(headers=headers)

            await context.route("**/*", add_auth_headers)

        return context

    def _on_response(
        self,
        response: Response,
        initiator_url: str,
        scope: ScopePolicy,
    ) -> None:
        """Handle incoming response."""
        url = response.url

        # Check if it's a JS response
        content_type = response.headers.get("content-type", "")
        is_js = (
            "javascript" in content_type.lower() or
            "ecmascript" in content_type.lower() or
            is_js_url(url)
        )

        if not is_js:
            return

        if not scope.is_allowed(url):
            return

        # Get initiator info from request
        request = response.request
        frame = request.frame
        initiator = initiator_url
        load_context = initiator_url

        if frame:
            try:
                load_context = frame.url
            except Exception as e:
                logger.debug(f"Failed to get frame URL: {e}")

        ref = JSReference(
            url=normalize_url(url),
            initiator=initiator,
            load_context=load_context,
            method=LoadMethod.NETWORK_CAPTURE,
            headers=dict(response.headers),
        )
        ref_key = (ref.url, ref.initiator, ref.load_context, ref.method.value)
        if ref_key in self._discovered_ref_keys:
            return
        self._discovered_ref_keys.add(ref_key)
        self._discovered_refs.append(ref)
        self._schedule_progress_notification()

    async def _drain_discovered_refs(
        self,
        scope: ScopePolicy,
        seen_urls: set[str],
    ) -> AsyncIterator[JSReference]:
        """Yield newly discovered refs that have not yet been replayed."""
        while self._discovered_ref_index < len(self._discovered_refs):
            ref = self._discovered_refs[self._discovered_ref_index]
            self._discovered_ref_index += 1
            await self._notify_progress()
            if ref.url in seen_urls or not scope.is_allowed(ref.url):
                continue
            seen_urls.add(ref.url)
            yield ref

    def _schedule_progress_notification(self) -> None:
        """Schedule a best-effort async progress callback from sync browser hooks."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._notify_progress())

    async def _explore_routes(
        self,
        page: Page,
        base_url: str,
        scope: ScopePolicy,
    ) -> None:
        """
        Explore SPA routes to trigger lazy-loaded chunks.
        """
        explored = 0

        if self._route_return_pending and self._route_current_url:
            await self._resume_pending_route(page, base_url)

        if not self._route_links_complete:
            try:
                raw_links = await page.evaluate("""
                    () => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => {
                            const href = a.getAttribute('href');
                            if (href && !href.startsWith('javascript:') &&
                                !href.startsWith('mailto:') &&
                                !href.startsWith('#')) {
                                links.push(href);
                            }
                        });
                        return [...new Set(links)].slice(0, 50);
                    }
                """)
            except Exception as e:
                logger.debug(f"Failed to extract links from page: {e}")
                return
            self._route_links = [
                link for link in raw_links
                if isinstance(link, str) and link
            ]
            self._route_index = min(self._route_index, len(self._route_links))
            self._route_links_complete = True
            await self._notify_progress()

        base_parsed = urlparse(base_url)

        for link in self._route_links[self._route_index:]:
            if explored >= self.config.max_route_exploration:
                break

            # Only internal links
            full_url = normalize_url(link, base_url)
            link_parsed = urlparse(full_url)

            if link_parsed.netloc.lower() != base_parsed.netloc.lower():
                continue

            if not scope.is_allowed(full_url):
                self._route_index += 1
                await self._notify_progress()
                continue

            try:
                # Try to click the link (for SPA navigation)
                # Escape quotes in href to prevent CSS selector injection
                escaped_link = link.replace("\\", "\\\\").replace('"', '\\"')
                link_selector = f'a[href="{escaped_link}"]'
                element = await page.query_selector(link_selector)

                if element:
                    explored += 1
                    self._route_current_url = full_url
                    self._route_return_pending = True
                    await self._notify_progress()
                    # Click and wait for any new JS to load
                    await element.click()
                    await asyncio.sleep(0.5)

                    # Wait for network to settle
                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=5000
                        )
                    except Exception as e:
                        logger.debug(f"Network idle timeout after clicking {link}: {e}")

                    # Navigate back to base URL for next link
                    # Using goto instead of go_back for reliability in SPA contexts
                    try:
                        await page.goto(base_url, wait_until="domcontentloaded", timeout=5000)
                    except Exception as e:
                        logger.debug(f"Failed to navigate back to {base_url}: {e}")
                    await asyncio.sleep(0.3)
                    self._route_current_url = ""
                    self._route_return_pending = False
                    await self._notify_progress()

            except Exception as e:
                logger.debug(f"Failed to explore route {link}: {e}")
            finally:
                self._route_index += 1
                await self._notify_progress()

        # Also try clicking common UI elements that might trigger lazy loads
        if not self._interactive_complete:
            try:
                await self._click_interactive_elements(page)
            except Exception as e:
                logger.debug(f"Failed to click interactive elements: {e}")

    async def _click_interactive_elements(self, page: Page) -> None:
        """Click buttons/tabs that might trigger lazy loading."""
        selectors = self._INTERACTIVE_SELECTORS
        if (
            self._interactive_pending_selector_index is not None
            and self._interactive_pending_element_index is not None
        ):
            await self._resume_pending_interactive_element(page)

        for selector_index in range(self._interactive_selector_index, len(selectors)):
            selector = selectors[selector_index]
            try:
                elements = await page.query_selector_all(selector)
                start_index = self._interactive_element_index if selector_index == self._interactive_selector_index else 0
                limited_elements = elements[:5]
                for element_index, element in enumerate(limited_elements[start_index:], start=start_index):
                    try:
                        self._interactive_pending_selector_index = selector_index
                        self._interactive_pending_element_index = element_index
                        await self._notify_progress()
                        await element.click()
                        await asyncio.sleep(0.3)
                    except Exception as e:
                        logger.debug(f"Failed to click element {selector}: {e}")
                    finally:
                        self._interactive_pending_selector_index = None
                        self._interactive_pending_element_index = None
                        self._interactive_selector_index = selector_index
                        self._interactive_element_index = element_index + 1
                        await self._notify_progress()
            except Exception as e:
                logger.debug(f"Failed to query elements {selector}: {e}")
            self._interactive_selector_index = selector_index + 1
            self._interactive_element_index = 0
            await self._notify_progress()
        self._interactive_complete = True
        await self._notify_progress()

    async def _resume_pending_interactive_element(self, page: Page) -> None:
        """Replay an interrupted interactive click before continuing the selector queue."""
        selector_index = self._interactive_pending_selector_index
        element_index = self._interactive_pending_element_index
        selectors = self._INTERACTIVE_SELECTORS
        if (
            selector_index is None
            or element_index is None
            or selector_index < 0
            or selector_index >= len(selectors)
        ):
            self._interactive_pending_selector_index = None
            self._interactive_pending_element_index = None
            return

        selector = selectors[selector_index]
        try:
            elements = await page.query_selector_all(selector)
            limited_elements = elements[:5]
            if element_index < len(limited_elements):
                await limited_elements[element_index].click()
                await asyncio.sleep(0.3)
        except Exception as e:
            logger.debug(
                f"Failed to replay interactive element {selector}[{element_index}] during resume: {e}"
            )
        finally:
            self._interactive_selector_index = selector_index
            self._interactive_element_index = element_index + 1
            self._interactive_pending_selector_index = None
            self._interactive_pending_element_index = None
            await self._notify_progress()

    async def _resume_pending_route(self, page: Page, base_url: str) -> None:
        """Replay an interrupted route action before continuing the remaining route queue."""
        pending_url = self._route_current_url
        if not pending_url:
            self._route_return_pending = False
            return

        try:
            await page.goto(pending_url, wait_until="domcontentloaded", timeout=5000)
            await asyncio.sleep(0.5)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception as e:
                logger.debug(f"Network idle timeout while resuming route {pending_url}: {e}")
            try:
                await page.goto(base_url, wait_until="domcontentloaded", timeout=5000)
            except Exception as e:
                logger.debug(f"Failed to restore base page {base_url} after pending route resume: {e}")
            await asyncio.sleep(0.3)
        except Exception as e:
            logger.debug(f"Failed to resume pending route {pending_url}: {e}")
        finally:
            if self._route_index < len(self._route_links):
                expected_url = normalize_url(self._route_links[self._route_index], base_url)
                if expected_url and normalize_url(pending_url) == expected_url:
                    self._route_index += 1
            self._route_current_url = ""
            self._route_return_pending = False
            await self._notify_progress()


class HeadlessMultiPageCollector(BaseCollector):
    """
    Multi-page headless collector.
    """

    name = "headless_crawler"

    def __init__(
        self,
        crawler_config: CrawlerConfig,
        auth_config: AuthConfig | None = None,
    ):
        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self._collector = HeadlessCollector(crawler_config, auth_config)
        self._visited_urls: set[str] = set()
        self._collected_js: set[str] = set()
        self._pending_pages: list[tuple[str, int]] = []
        self._inflight_page: tuple[str, int] | None = None
        self._inflight_refs: list[JSReference] = []
        self._inflight_ref_index: int = 0
        self._inflight_refs_complete: bool = False
        self._inflight_html: str | None = None
        self._inflight_links: list[str] = []
        self._inflight_link_index: int = 0
        self._inflight_links_complete: bool = False
        self._resume_loaded = False
        self.on_page_complete: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None

    async def setup(self) -> None:
        await self._collector.setup()

    async def teardown(self) -> None:
        await self._collector.teardown()

    async def collect(
        self,
        url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Collect from multiple pages."""
        if not self._resume_loaded:
            self._visited_urls.clear()
            self._collected_js.clear()
            self._pending_pages = [(url, 0)]
            self._inflight_page = None
            self._inflight_refs = []
            self._inflight_ref_index = 0
            self._inflight_refs_complete = False
            self._inflight_html = None
            self._inflight_links = []
            self._inflight_link_index = 0
            self._inflight_links_complete = False
            self._collector.reset_resume_state()
        elif not self._pending_pages and normalize_url(url) not in self._visited_urls:
            self._pending_pages = [(url, 0)]

        self._resume_loaded = False
        self._collector.on_progress = self._on_headless_progress

        while self._pending_pages:
            page_url, depth = self._pending_pages.pop(0)
            self._inflight_page = (page_url, depth)
            if not self._inflight_refs:
                self._inflight_ref_index = 0
                self._inflight_refs_complete = False
            if not self._inflight_links and not self._inflight_links_complete:
                self._inflight_link_index = 0
            await self._notify_page_complete()
            async for ref in self._crawl_page(page_url, scope, depth=depth):
                yield ref
            self._inflight_page = None
            self._inflight_refs = []
            self._inflight_ref_index = 0
            self._inflight_refs_complete = False
            self._inflight_html = None
            self._inflight_links = []
            self._inflight_link_index = 0
            self._inflight_links_complete = False
            self._collector.reset_resume_state()
            await self._notify_page_complete()
        self._collector.on_progress = None

    def load_resume_state(self, state: dict[str, Any]) -> None:
        """Load persisted crawl state for resuming a partial multipage crawl."""
        self._visited_urls = {
            normalized
            for normalized in (
                normalize_url(url)
                for url in state.get("visited_urls", [])
                if isinstance(url, str)
            )
            if normalized
        }
        self._collected_js = {
            url.strip()
            for url in state.get("collected_js_urls", [])
            if isinstance(url, str) and url.strip()
        }
        self._pending_pages = []
        for item in state.get("pending_pages", []):
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            depth = item.get("depth", 0)
            normalized = normalize_url(url) if isinstance(url, str) else None
            if not normalized or normalized in self._visited_urls:
                continue
            try:
                page_depth = int(depth)
            except (TypeError, ValueError):
                page_depth = 0
            self._pending_pages.append((normalized, page_depth))
        self._inflight_page = None
        self._inflight_refs = []
        self._inflight_ref_index = 0
        self._inflight_refs_complete = False
        self._inflight_html = None
        self._inflight_links = []
        self._inflight_link_index = 0
        self._inflight_links_complete = False
        self._collector.reset_resume_state()
        inflight = state.get("inflight_page")
        if isinstance(inflight, dict):
            inflight_url = inflight.get("url")
            inflight_depth = inflight.get("depth", 0)
            normalized = normalize_url(inflight_url) if isinstance(inflight_url, str) else None
            if normalized and normalized not in self._visited_urls and all(page_url != normalized for page_url, _ in self._pending_pages):
                try:
                    page_depth = int(inflight_depth)
                except (TypeError, ValueError):
                    page_depth = 0
                self._pending_pages.insert(0, (normalized, page_depth))
                self._inflight_page = (normalized, page_depth)
                self._inflight_refs = [
                    ref
                    for ref in (
                        _deserialize_reference(item)
                        for item in inflight.get("discovered_refs", [])
                    )
                    if ref
                ]
                try:
                    self._inflight_ref_index = max(0, int(inflight.get("next_ref_index", 0)))
                except (TypeError, ValueError):
                    self._inflight_ref_index = 0
                self._inflight_refs_complete = bool(inflight.get("refs_complete"))
                html_snapshot = inflight.get("html_snapshot")
                if isinstance(html_snapshot, str):
                    self._inflight_html = html_snapshot
                self._inflight_links = [
                    normalized_link
                    for normalized_link in (
                        normalize_url(link)
                        for link in inflight.get("discovered_links", [])
                        if isinstance(link, str)
                    )
                    if normalized_link
                ]
                try:
                    self._inflight_link_index = max(0, int(inflight.get("next_link_index", 0)))
                except (TypeError, ValueError):
                    self._inflight_link_index = 0
                self._inflight_links_complete = (
                    bool(inflight.get("links_complete"))
                    or bool(self._inflight_links)
                    or self._inflight_link_index > 0
                )
                headless_route_state = inflight.get("headless_route_state")
                if isinstance(headless_route_state, dict):
                    self._collector.load_resume_state(headless_route_state)
        self._resume_loaded = True

    def export_resume_state(self) -> dict[str, Any]:
        """Export the current multipage crawl state."""
        state = {
            "visited_urls": sorted(self._visited_urls),
            "collected_js_urls": sorted(self._collected_js),
            "pending_pages": [
                {"url": page_url, "depth": depth}
                for page_url, depth in self._pending_pages
            ],
        }
        if self._inflight_page:
            inflight_state = {
                "url": self._inflight_page[0],
                "depth": self._inflight_page[1],
            }
            if self._inflight_refs or self._inflight_ref_index or self._inflight_refs_complete:
                inflight_state["discovered_refs"] = [
                    _serialize_reference(ref)
                    for ref in self._inflight_refs
                ]
                inflight_state["next_ref_index"] = self._inflight_ref_index
                inflight_state["refs_complete"] = self._inflight_refs_complete
            if self._inflight_html:
                inflight_state["html_snapshot"] = self._inflight_html
            if self._inflight_links or self._inflight_link_index or self._inflight_links_complete:
                inflight_state["discovered_links"] = list(self._inflight_links)
                inflight_state["next_link_index"] = self._inflight_link_index
                inflight_state["links_complete"] = self._inflight_links_complete
            headless_route_state = self._collector.export_resume_state()
            if headless_route_state:
                inflight_state["headless_route_state"] = headless_route_state
            state["inflight_page"] = inflight_state
        return state

    async def _on_headless_progress(self, state: dict[str, Any]) -> None:
        """Publish nested headless route-exploration progress through page-level checkpoints."""
        if not self._inflight_page:
            return
        await self._notify_page_complete()

    async def _notify_page_complete(self) -> None:
        """Publish page-level crawl progress when a callback is configured."""
        if not self.on_page_complete:
            return
        result = self.on_page_complete(self.export_resume_state())
        if isawaitable(result):
            await result

    async def _crawl_page(
        self,
        url: str,
        scope: ScopePolicy,
        depth: int,
    ) -> AsyncIterator[JSReference]:
        """Recursively crawl pages."""
        if depth > self.config.max_depth:
            return

        if len(self._visited_urls) >= self.config.max_pages:
            return

        normalized = normalize_url(url)
        if normalized in self._visited_urls:
            return

        self._visited_urls.add(normalized)

        known_ref_keys = {
            (ref.url, ref.initiator, ref.load_context, ref.method.value)
            for ref in self._inflight_refs
        }
        for ref in self._inflight_refs[self._inflight_ref_index:]:
            if ref.url not in self._collected_js:
                self._collected_js.add(ref.url)
                yield ref
            self._inflight_ref_index += 1
            await self._notify_page_complete()

        if not self._inflight_refs_complete:
            async for ref in self._collector.collect(url, scope):
                ref_key = (ref.url, ref.initiator, ref.load_context, ref.method.value)
                if ref_key in known_ref_keys:
                    continue
                known_ref_keys.add(ref_key)
                self._inflight_refs.append(ref)
                if ref.url not in self._collected_js:
                    self._collected_js.add(ref.url)
                    yield ref
                self._inflight_ref_index = len(self._inflight_refs)
                await self._notify_page_complete()
            self._inflight_refs_complete = True
            await self._notify_page_complete()

        # Find links and crawl sub-pages
        # NOTE: Known performance issue - _find_page_links creates a separate
        # browser context and navigates to the same URL again. Refactoring to
        # share a single page load would require major architectural changes to
        # the collector/response-handler design.
        if depth < self.config.max_depth:
            links = list(self._inflight_links)
            if not self._inflight_links_complete:
                if self._inflight_html:
                    links = self._extract_links_from_html(self._inflight_html, url, scope)[:20]
                else:
                    links = (await self._find_page_links(url, scope))[:20]
                self._inflight_links = list(links)
                self._inflight_link_index = min(self._inflight_link_index, len(self._inflight_links))
                self._inflight_links_complete = True
                await self._notify_page_complete()
            for link in links[self._inflight_link_index:]:
                normalized_link = normalize_url(link)
                if not normalized_link:
                    self._inflight_link_index += 1
                    await self._notify_page_complete()
                    continue
                if normalized_link in self._visited_urls:
                    self._inflight_link_index += 1
                    await self._notify_page_complete()
                    continue
                if any(normalize_url(page_url) == normalized_link for page_url, _ in self._pending_pages):
                    self._inflight_link_index += 1
                    await self._notify_page_complete()
                    continue
                self._pending_pages.append((normalized_link, depth + 1))
                self._inflight_link_index += 1
                await self._notify_page_complete()

    async def _find_page_links(
        self,
        url: str,
        scope: ScopePolicy,
    ) -> list[str]:
        """Extract page links using headless browser."""
        if not self._collector._browser:
            return []

        # Use the collector's context creation to include auth settings
        context = await self._collector._create_context(url)
        try:
            page = await context.new_page()
            try:
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=int(self.config.page_timeout * 1000),
                )
            except Exception as e:
                logger.debug(f"Failed to load page for link extraction: {url}: {e}")
                return []

            try:
                html = await page.content()
                if isinstance(html, str):
                    self._inflight_html = html
            except Exception as e:
                logger.debug(f"Failed to snapshot page HTML for link extraction {url}: {e}")

            try:
                links = await page.evaluate("""
                    () => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => {
                            const href = a.href;
                            if (href && !href.startsWith('javascript:') &&
                                !href.startsWith('mailto:') &&
                                !href.startsWith('#')) {
                                links.push(href);
                            }
                        });
                        return [...new Set(links)].slice(0, 50);
                    }
                """)
            except Exception as e:
                logger.debug(f"Failed to extract links from {url}: {e}")
                if self._inflight_html:
                    return self._extract_links_from_html(self._inflight_html, url, scope)
                return []

            return self._filter_page_links(links, url, scope)
        finally:
            await context.close()

    def _extract_links_from_html(
        self,
        html: str,
        base_url: str,
        scope: ScopePolicy,
    ) -> list[str]:
        """Extract crawlable links from a stored HTML snapshot."""
        soup = BeautifulSoup(html, "lxml")
        links: list[str] = []
        for anchor in soup.select("a[href]"):
            href = anchor.get("href", "")
            if not isinstance(href, str) or not href:
                continue
            links.append(normalize_url(href, base_url))
        return self._filter_page_links(links, base_url, scope)

    def _filter_page_links(
        self,
        links: list[str],
        base_url: str,
        scope: ScopePolicy,
    ) -> list[str]:
        """Filter discovered links down to in-scope HTML pages."""
        base_parsed = urlparse(base_url)
        result = []
        for link in links:
            if not isinstance(link, str) or not link:
                continue
            link_parsed = urlparse(link)
            if link_parsed.netloc.lower() != base_parsed.netloc.lower():
                continue
            if not scope.is_allowed(link):
                continue
            resource_exts = (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".pdf", ".woff", ".woff2", ".ttf", ".ico")
            if any(link_parsed.path.endswith(ext) for ext in resource_exts):
                continue
            result.append(link)
        return list(set(result))

