"""
Static HTML-based JS collector.

Extracts JS references from HTML without rendering.
"""

from __future__ import annotations

import logging
import re
from inspect import isawaitable
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from bundleInspector.collector.base import BaseCollector
from bundleInspector.collector.scope import ScopePolicy, normalize_url, is_js_url
from bundleInspector.config import CrawlerConfig, AuthConfig
from bundleInspector.storage.models import JSReference, LoadMethod

logger = logging.getLogger(__name__)


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


class StaticCollector(BaseCollector):
    """
    Collect JS references by parsing HTML statically.

    This is Tier A collection - fast but may miss dynamically loaded JS.
    """

    name = "static"

    def __init__(
        self,
        crawler_config: CrawlerConfig,
        auth_config: AuthConfig | None = None,
    ):
        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        """Initialize HTTP client."""
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        # Add auth headers
        headers.update(self.auth.get_auth_headers())

        # Prepare cookies
        cookies = self.auth.cookies if self.auth.cookies else None

        self._client = httpx.AsyncClient(
            headers=headers,
            cookies=cookies,
            timeout=self.config.request_timeout,
            follow_redirects=self.config.follow_redirects,
            max_redirects=self.config.max_redirects,
        )

    async def teardown(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def collect(
        self,
        url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """
        Collect JS references from HTML page.

        Args:
            url: Page URL to parse
            scope: Scope policy

        Yields:
            JSReference for each discovered JS file
        """
        if not self._client:
            await self.setup()

        try:
            response = await self._client.get(url)
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error fetching {url}: {e.response.status_code}")
            return
        except httpx.RequestError as e:
            logger.warning(f"Request error fetching {url}: {e}")
            return

        content_type = response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            return

        html = response.text
        soup = BeautifulSoup(html, "lxml")

        # Track inline script URLs found in script tags to avoid duplicates
        seen_urls: set[str] = set()

        # Collect from script tags (includes inline script dynamic imports)
        async for ref in self._collect_script_tags(soup, url, scope):
            seen_urls.add(ref.url)
            yield ref

        # Collect from preload links
        async for ref in self._collect_preload_links(soup, url, scope):
            if ref.url not in seen_urls:
                seen_urls.add(ref.url)
                yield ref

    async def _collect_script_tags(
        self,
        soup: BeautifulSoup,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Extract JS from script tags."""
        for script in soup.find_all("script"):
            src = script.get("src")

            if src:
                # External script ??<script src> always loads JS by definition,
                # so we skip the is_js_url() check here
                full_url = normalize_url(src, base_url)

                if full_url and scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=base_url,
                        load_context=base_url,
                        method=LoadMethod.SCRIPT_TAG,
                    )
            else:
                # Inline script - extract any dynamic import URLs
                content = script.string
                if content:
                    async for ref in self._extract_dynamic_imports(
                        content, base_url, scope
                    ):
                        # Only set INLINE if method is still the default;
                        # _extract_dynamic_imports may have set DYNAMIC_IMPORT
                        if ref.method == LoadMethod.SCRIPT_TAG:
                            ref.method = LoadMethod.INLINE
                        yield ref

    async def _collect_preload_links(
        self,
        soup: BeautifulSoup,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Extract JS from preload/modulepreload links."""
        for link in soup.find_all("link"):
            rel = link.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]

            href = link.get("href")
            as_value = link.get("as", "")

            if not href:
                continue

            full_url = normalize_url(href, base_url)

            # Check for preload with as=script
            # as="script" explicitly declares the resource as JS, no extension check needed
            if "preload" in rel and as_value == "script":
                if scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=base_url,
                        load_context=base_url,
                        method=LoadMethod.PRELOAD,
                    )

            # Check for modulepreload (inherently JS modules)
            elif "modulepreload" in rel:
                if scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=base_url,
                        load_context=base_url,
                        method=LoadMethod.MODULE_PRELOAD,
                    )

    async def _extract_dynamic_imports(
        self,
        content: str,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Extract dynamic import URLs from JS content."""
        # Pattern for import() calls
        import_pattern = r'import\s*\(\s*["\']([^"\']+)["\']'

        for match in re.finditer(import_pattern, content):
            url = match.group(1)

            # Skip non-URL imports (npm packages, etc)
            if not url.startswith((".", "/", "http://", "https://")):
                continue

            full_url = normalize_url(url, base_url)

            # Dynamic import() is inherently JS ??skip is_js_url check
            if full_url and scope.is_allowed(full_url):
                yield JSReference(
                    url=full_url,
                    initiator=base_url,
                    load_context=base_url,
                    method=LoadMethod.DYNAMIC_IMPORT,
                )

        # Pattern for require.ensure (use [\s\S]*? for nested braces)
        ensure_pattern = r'require\.ensure\s*\([^,]*,\s*function\s*\([^)]*\)\s*\{[\s\S]*?require\s*\(\s*["\']([^"\']+)'

        for match in re.finditer(ensure_pattern, content):
            url = match.group(1)
            if url.startswith((".", "/")):
                full_url = normalize_url(url, base_url)
                # require.ensure is inherently JS ??skip is_js_url check
                if full_url and scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=base_url,
                        load_context=base_url,
                        method=LoadMethod.DYNAMIC_IMPORT,
                    )


class MultiPageStaticCollector(BaseCollector):
    """
    Multi-page static collector that crawls multiple pages.
    """

    name = "static_crawler"

    def __init__(
        self,
        crawler_config: CrawlerConfig,
        auth_config: AuthConfig | None = None,
    ):
        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self._collector = StaticCollector(crawler_config, auth_config)
        self._visited_urls: set[str] = set()
        self._collected_js: set[str] = set()
        self._pending_pages: list[tuple[str, int]] = []
        self._inflight_page: tuple[str, int] | None = None
        self._inflight_html: str | None = None
        self._inflight_refs: list[JSReference] = []
        self._inflight_ref_index: int = 0
        self._inflight_refs_complete: bool = False
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
        """
        Crawl pages and collect JS references.
        """
        if not self._resume_loaded:
            self._visited_urls.clear()
            self._collected_js.clear()
            self._pending_pages = [(url, 0)]
            self._inflight_page = None
            self._inflight_html = None
            self._inflight_refs = []
            self._inflight_ref_index = 0
            self._inflight_refs_complete = False
            self._inflight_links = []
            self._inflight_link_index = 0
            self._inflight_links_complete = False
        elif not self._pending_pages and normalize_url(url) not in self._visited_urls:
            self._pending_pages = [(url, 0)]

        self._resume_loaded = False

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
            self._inflight_html = None
            self._inflight_refs = []
            self._inflight_ref_index = 0
            self._inflight_refs_complete = False
            self._inflight_links = []
            self._inflight_link_index = 0
            self._inflight_links_complete = False
            await self._notify_page_complete()

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
        self._inflight_html = None
        self._inflight_refs = []
        self._inflight_ref_index = 0
        self._inflight_refs_complete = False
        self._inflight_links = []
        self._inflight_link_index = 0
        self._inflight_links_complete = False
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
                html_snapshot = inflight.get("html_snapshot")
                if isinstance(html_snapshot, str):
                    self._inflight_html = html_snapshot
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
            if self._inflight_html is not None:
                inflight_state["html_snapshot"] = self._inflight_html
            if self._inflight_refs or self._inflight_ref_index or self._inflight_refs_complete:
                inflight_state["discovered_refs"] = [
                    _serialize_reference(ref)
                    for ref in self._inflight_refs
                ]
                inflight_state["next_ref_index"] = self._inflight_ref_index
                inflight_state["refs_complete"] = self._inflight_refs_complete
            if self._inflight_links or self._inflight_link_index or self._inflight_links_complete:
                inflight_state["discovered_links"] = list(self._inflight_links)
                inflight_state["next_link_index"] = self._inflight_link_index
                inflight_state["links_complete"] = self._inflight_links_complete
            state["inflight_page"] = inflight_state
        return state

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

        need_page_fetch = (
            not self._inflight_refs_complete
            or (depth < self.config.max_depth and not self._inflight_links_complete)
        )
        soup: BeautifulSoup | None = None
        if need_page_fetch:
            if self._inflight_html is not None:
                soup = BeautifulSoup(self._inflight_html, "lxml")
            else:
                if not self._collector._client:
                    await self._collector.setup()

                try:
                    response = await self._collector._client.get(url)
                    response.raise_for_status()
                except httpx.HTTPStatusError as e:
                    logger.debug(f"HTTP error crawling {url}: {e.response.status_code}")
                    return
                except httpx.RequestError as e:
                    logger.debug(f"Request error crawling {url}: {e}")
                    return

                content_type = response.headers.get("content-type", "")
                if "html" not in content_type.lower():
                    return

                self._inflight_html = response.text
                soup = BeautifulSoup(response.text, "lxml")

        if soup is not None and not self._inflight_refs_complete:
            discovered_refs: list[JSReference] = []
            seen_page_urls: set[str] = set()
            async for ref in self._collector._collect_script_tags(soup, url, scope):
                if ref.url in seen_page_urls:
                    continue
                seen_page_urls.add(ref.url)
                discovered_refs.append(ref)
            async for ref in self._collector._collect_preload_links(soup, url, scope):
                if ref.url in seen_page_urls:
                    continue
                seen_page_urls.add(ref.url)
                discovered_refs.append(ref)
            self._inflight_refs = discovered_refs
            self._inflight_ref_index = min(self._inflight_ref_index, len(self._inflight_refs))
            self._inflight_refs_complete = True
            await self._notify_page_complete()

        for ref in self._inflight_refs[self._inflight_ref_index:]:
            if ref.url not in self._collected_js:
                self._collected_js.add(ref.url)
                yield ref
            self._inflight_ref_index += 1
            await self._notify_page_complete()

        # Extract page links from the same parsed HTML
        if depth < self.config.max_depth:
            links = list(self._inflight_links)
            if not self._inflight_links_complete:
                if soup is None:
                    return
                links = self._extract_page_links(soup, url, scope)[:20]
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

    def _extract_page_links(
        self,
        soup: BeautifulSoup,
        base_url: str,
        scope: ScopePolicy,
    ) -> list[str]:
        """Extract page links from already-parsed HTML."""
        links = []

        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = normalize_url(href, base_url)

            if scope.is_allowed(full_url):
                # Only HTML pages
                parsed_link = urlparse(full_url)
                resource_exts = (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".pdf", ".woff", ".woff2", ".ttf", ".ico")
                if not any(parsed_link.path.endswith(ext) for ext in resource_exts):
                    links.append(full_url)

        return list(set(links))

