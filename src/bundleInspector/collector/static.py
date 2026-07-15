"""
Static HTML-based JS collector.

Extracts JS references from HTML without rendering.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from inspect import isawaitable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from bundleInspector.collector.base import BaseCollector
from bundleInspector.collector.scope import ScopePolicy, normalize_url
from bundleInspector.config import AuthConfig, CrawlerConfig
from bundleInspector.core.rate_limiter import RateLimiter
from bundleInspector.core.safe_http import (
    ResponseTooLarge,
    UnsafeRequestTarget,
    build_pinned_transport,
    get_with_safe_redirects,
    normalized_origin,
    origin_bound_auth_headers,
)
from bundleInspector.core.url_utils import safe_urlparse as urlparse
from bundleInspector.parser.lexical_context import (
    LexicalGoal,
    is_line_terminator,
    line_comment_end,
)
from bundleInspector.storage.models import JSReference, LoadMethod

logger = logging.getLogger(__name__)

# Inline <script> types that hold executable JS (DQ-I01/I05). Empty/absent type defaults to JS.
# Everything else (application/json, importmap, text/template, application/ld+json, ...) is data,
# not analyzable JS, and must not be captured as an asset.
INLINE_JS_SCRIPT_TYPES = frozenset({
    "", "module", "text/javascript", "application/javascript",
    "text/ecmascript", "application/ecmascript", "application/x-javascript",
})

_HTML_SNIFF_LIMIT = 4096
_GENERIC_HTML_SNIFF_TYPES = frozenset({
    "", "text/plain", "application/octet-stream", "binary/octet-stream",
})
_HTML_LEADING_MARKER = re.compile(
    r"^(?:<!--(?:[^-]|-(?!->))*-->\s*)*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b|<script\b)",
    re.IGNORECASE,
)


def _is_inline_js_type(script_type: Any) -> bool:
    """True if a <script> tag's `type` marks it as executable JS (or is absent/empty)."""
    return str(script_type or "").strip().lower() in INLINE_JS_SCRIPT_TYPES


def _tag_attr_text(value: Any) -> str:
    """Normalize a BeautifulSoup scalar/list attribute to one textual value."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and value:
        return str(value[0])
    return ""


def _response_looks_like_html(response: Any) -> bool:
    """Accept HTML MIME or a strongly HTML-looking body under a generic/absent MIME."""
    headers = getattr(response, "headers", {})
    content_type = str(headers.get("content-type", "") or "").split(";", 1)[0].strip().lower()
    if "html" in content_type or content_type == "application/xhtml+xml":
        return True
    if content_type not in _GENERIC_HTML_SNIFF_TYPES:
        return False
    text = str(getattr(response, "text", "") or "")[:_HTML_SNIFF_LIMIT]
    return bool(_HTML_LEADING_MARKER.match(text.lstrip("\ufeff\x00 \t\r\n\f")))


def _response_document_url(response: Any, requested_url: str) -> str:
    """Return the normalized final response URL, falling back to the requested URL."""
    candidate = str(getattr(response, "url", "") or requested_url)
    return normalize_url(candidate) or normalize_url(requested_url) or requested_url


def _document_resolution_base(soup: BeautifulSoup, document_url: str) -> str:
    """Apply the first valid HTML base URL, as required by document base semantics."""
    for tag in soup.find_all("base", href=True):
        href = tag.get("href")
        if not isinstance(href, str) or not href.strip():
            continue
        resolved = normalize_url(href, document_url)
        if resolved:
            return resolved
    return document_url


def _can_start_regex_literal(source: str, index: int, lexical_goal: LexicalGoal) -> bool:
    """Use forward lexical context to distinguish a regex literal from division."""
    return lexical_goal.can_start_regex(source, index)


def _skip_space_and_comments(source: str, index: int) -> int:
    """Skip whitespace and comments without consuming strings or code."""
    length = len(source)
    while index < length:
        if source[index].isspace():
            index += 1
            continue
        if source.startswith("//", index):
            index = line_comment_end(source, index + 2)
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            index = length if close < 0 else close + 2
            continue
        break
    return index


def _skip_regex_literal(source: str, index: int) -> int:
    """Advance past one regex literal without crossing an ECMAScript line terminator."""
    cursor = index + 1
    in_class = False
    while cursor < len(source):
        current = source[cursor]
        if is_line_terminator(current):
            return cursor
        if current == "\\":
            if cursor + 1 >= len(source) or is_line_terminator(source[cursor + 1]):
                return cursor + 1
            cursor += 2
            continue
        if current == "[":
            in_class = True
        elif current == "]":
            in_class = False
        elif current == "/" and not in_class:
            cursor += 1
            while cursor < len(source) and source[cursor] in "dgimsuvy":
                cursor += 1
            return cursor
        cursor += 1
    return cursor


def _read_static_js_literal(source: str, index: int) -> tuple[str, int] | None:
    """Read a quoted or interpolation-free template literal at ``index``."""
    if index >= len(source) or source[index] not in "'\"`":
        return None
    quote = source[index]
    value: list[str] = []
    cursor = index + 1
    while cursor < len(source):
        char = source[cursor]
        if char == "\\":
            if cursor + 1 >= len(source):
                return None
            # Preserve the escaped value character. URL normalization does not need to retain
            # JavaScript quote escaping, while path escapes such as `\\x2f` remain visibly static.
            value.append(source[cursor + 1])
            cursor += 2
            continue
        if quote == "`" and char == "$" and cursor + 1 < len(source) and source[cursor + 1] == "{":
            return None
        if char == quote:
            return "".join(value), cursor + 1
        value.append(char)
        cursor += 1
    return None


def _skip_js_literal(source: str, index: int) -> int:
    """Advance past one lexical quote/template even when it is not statically resolvable."""
    if index >= len(source) or source[index] not in "'\"`":
        return index + 1
    quote = source[index]
    cursor = index + 1
    while cursor < len(source):
        if source[cursor] == "\\" and cursor + 1 < len(source):
            cursor += 2
            continue
        if source[cursor] == quote:
            return cursor + 1
        cursor += 1
    return len(source)


def _template_has_interpolation(source: str, index: int) -> bool:
    cursor = index + 1
    while cursor < len(source):
        if source[cursor] == "\\" and cursor + 1 < len(source):
            cursor += 2
            continue
        if source.startswith("${", cursor):
            return True
        if source[cursor] == "`":
            return False
        cursor += 1
    return False


def _mask_template_raw_text(source: str) -> str:
    """Mask interpolated-template raw text while preserving executable `${...}` code."""
    masked = list(source)
    mode = "code"
    expression_depths: list[int] = []
    lexical_goal = LexicalGoal()
    cursor = 0
    while cursor < len(source):
        char = source[cursor]
        if mode == "template":
            if char == "\\" and cursor + 1 < len(source):
                masked[cursor] = masked[cursor + 1] = " "
                cursor += 2
                continue
            if source.startswith("${", cursor):
                masked[cursor] = masked[cursor + 1] = " "
                expression_depths.append(1)
                mode = "code"
                lexical_goal.enter_template_expression()
                cursor += 2
                continue
            masked[cursor] = " "
            if char == "`":
                mode = "code"
                lexical_goal.note_operand()
            cursor += 1
            continue

        if char in "'\"":
            cursor = _skip_js_literal(source, cursor)
            lexical_goal.note_operand()
            continue
        if source.startswith("//", cursor) or source.startswith("/*", cursor):
            cursor = _skip_space_and_comments(source, cursor)
            continue
        if char == "/" and _can_start_regex_literal(source, cursor, lexical_goal):
            cursor = _skip_regex_literal(source, cursor)
            lexical_goal.note_operand()
            continue
        if char == "`":
            if _template_has_interpolation(source, cursor):
                masked[cursor] = " "
                mode = "template"
                cursor += 1
            else:
                cursor = _skip_js_literal(source, cursor)
                lexical_goal.note_operand()
            continue
        if expression_depths and char == "{":
            expression_depths[-1] += 1
        elif expression_depths and char == "}":
            expression_depths[-1] -= 1
            if expression_depths[-1] == 0:
                expression_depths.pop()
                masked[cursor] = " "
                mode = "template"
                lexical_goal.note_operand()
                cursor += 1
                continue
        lexical_goal.observe_code_char(source, cursor)
        cursor += 1
    return "".join(masked)


def _iter_static_dependencies(source: str) -> Iterator[str]:
    """Yield statically resolvable import()/import/require specifiers in source order."""
    source = _mask_template_raw_text(source)
    cursor = 0
    length = len(source)
    lexical_goal = LexicalGoal()
    while cursor < length:
        char = source[cursor]
        if source.startswith("//", cursor):
            cursor = _skip_space_and_comments(source, cursor)
            continue
        if source.startswith("/*", cursor):
            cursor = _skip_space_and_comments(source, cursor)
            continue
        if char in "'\"`":
            literal = _read_static_js_literal(source, cursor)
            cursor = literal[1] if literal else _skip_js_literal(source, cursor)
            lexical_goal.note_operand()
            continue
        if char == "/" and _can_start_regex_literal(source, cursor, lexical_goal):
            cursor = _skip_regex_literal(source, cursor)
            lexical_goal.note_operand()
            continue
        if not (char.isalpha() or char in "_$"):
            lexical_goal.observe_code_char(source, cursor)
            cursor += 1
            continue

        start = cursor
        lexical_goal.observe_code_char(source, cursor)
        cursor += 1
        while cursor < length and (source[cursor].isalnum() or source[cursor] in "_$"):
            cursor += 1
        token = source[start:cursor]
        if token not in {"import", "require", "from"}:
            continue

        argument = _skip_space_and_comments(source, cursor)
        if argument < length and source[argument] == "(":
            argument = _skip_space_and_comments(source, argument + 1)
        elif token in {"import", "from"}:
            # Side-effect import: `import "./setup.js"`.
            pass
        else:
            continue
        literal = _read_static_js_literal(source, argument)
        if literal is not None:
            yield literal[0]


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
    if ref.inline_content is not None:
        # DQ-I01: an inline-script ref has no fetchable URL; without round-tripping the body,
        # a resumed inline ref would try to download its synthetic URL and be lost.
        payload["inline_content"] = ref.inline_content
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
    inline_content = payload.get("inline_content")
    return JSReference(
        url=url.strip(),
        initiator=payload.get("initiator", "") if isinstance(payload.get("initiator"), str) else "",
        load_context=payload.get("load_context", "") if isinstance(payload.get("load_context"), str) else "",
        method=method,
        headers=dict(headers) if isinstance(headers, dict) else {},
        inline_content=inline_content if isinstance(inline_content, str) else None,
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
        *,
        allow_private_ips: bool = False,
        rate_limiter: RateLimiter | None = None,
    ):
        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self.allow_private_ips = allow_private_ips
        self.rate_limiter = rate_limiter
        self._client: httpx.AsyncClient | None = None
        self._auth_origins: set[tuple[str, str, int]] = set()

    async def setup(self) -> None:
        """Initialize HTTP client."""
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=self.config.request_timeout,
            follow_redirects=False,
            max_redirects=self.config.max_redirects,
            transport=build_pinned_transport(
                allow_private_ips=self.allow_private_ips,
                max_connections=self.config.max_concurrent,
            ),
            trust_env=False,
        )

    async def teardown(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _bind_auth_origin(self, url: str) -> None:
        origin = normalized_origin(url)
        self._auth_origins = {origin} if origin is not None else set()

    def _request_headers(self, url: str) -> dict[str, str]:
        return origin_bound_auth_headers(
            url,
            self._auth_origins,
            self.auth.get_auth_headers(),
            self.auth.cookies,
        )

    async def _request(self, url: str, scope: ScopePolicy) -> httpx.Response:
        client = self._client
        if client is None:
            raise RuntimeError("StaticCollector must be set up before requesting a page")
        attempts = max(0, self.config.max_retries) + 1
        for attempt in range(attempts):
            try:
                response = await get_with_safe_redirects(
                    client,
                    url,
                    allow_private_ips=self.allow_private_ips,
                    follow_redirects=self.config.follow_redirects,
                    max_redirects=self.config.max_redirects,
                    is_allowed=scope.is_allowed,
                    headers_for_url=self._request_headers,
                    before_request=self.rate_limiter.acquire if self.rate_limiter else None,
                    max_response_bytes=self.config.max_file_size,
                )
            except (UnsafeRequestTarget, ResponseTooLarge, httpx.TooManyRedirects):
                raise
            except httpx.RequestError:
                await self._record_rate_feedback("record_error", url, 0)
                if attempt + 1 >= attempts:
                    raise
                await asyncio.sleep(max(0.0, self.config.retry_delay))
                continue

            feedback_url = str(getattr(response, "url", "") or url)
            if self._is_transient_http_status(response.status_code):
                await self._record_rate_feedback("record_error", feedback_url, response.status_code)
                if attempt + 1 < attempts:
                    await response.aclose()
                    await asyncio.sleep(max(0.0, self.config.retry_delay))
                    continue
            else:
                await self._record_rate_feedback("record_success", feedback_url)
            return response
        raise RuntimeError("static request retry loop exhausted without a response")

    async def _record_rate_feedback(self, method: str, *args: Any) -> None:
        limiter_method = getattr(self.rate_limiter, method, None)
        if callable(limiter_method):
            result = limiter_method(*args)
            if isawaitable(result):
                await result

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
        client = self._client
        if client is None:
            return
        self._bind_auth_origin(url)

        try:
            response = await self._request(url, scope)
            response.raise_for_status()
        except UnsafeRequestTarget as e:
            logger.warning("Blocked unsafe static request %s: %s", e.url, e.reason)
            return
        except ResponseTooLarge as e:
            logger.warning("Static response exceeded body limit for %s", e.url)
            return
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            logger.warning(f"HTTP error fetching {url}: {status}")
            if self._is_transient_http_status(status):
                self._record_retryable_failure(url, f"HTTP {status}", status)  # DQ-C06
            return
        except httpx.RequestError as e:
            logger.warning(f"Request error fetching {url}: {e}")
            self._record_retryable_failure(url, f"request error: {type(e).__name__}")  # DQ-C06
            return

        if not _response_looks_like_html(response):
            return

        html = response.text
        soup = BeautifulSoup(html, "lxml")
        document_url = _response_document_url(response, url)

        # Track inline script URLs found in script tags to avoid duplicates
        seen_urls: set[str] = set()

        # Collect from script tags (includes inline script dynamic imports)
        async for ref in self._collect_script_tags(soup, document_url, scope):
            seen_urls.add(ref.url)
            yield ref

        # Collect from preload links
        async for ref in self._collect_preload_links(soup, document_url, scope):
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
        document_url = base_url
        resolution_base = _document_resolution_base(soup, document_url)
        for i, script in enumerate(soup.find_all("script")):
            src = _tag_attr_text(script.get("src"))

            if src:
                # External script ??<script src> always loads JS by definition,
                # so we skip the is_js_url() check here
                full_url = normalize_url(src, resolution_base)

                if full_url and scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=document_url,
                        load_context=document_url,
                        method=LoadMethod.SCRIPT_TAG,
                    )
            else:
                # Inline script - extract any dynamic import URLs
                content = script.string
                if content:
                    async for ref in self._extract_dynamic_imports(
                        str(content), resolution_base, scope, initiator_url=document_url
                    ):
                        # Only set INLINE if method is still the default;
                        # _extract_dynamic_imports may have set DYNAMIC_IMPORT
                        if ref.method == LoadMethod.SCRIPT_TAG:
                            ref.method = LoadMethod.INLINE
                        yield ref

                # DQ-I01: capture the inline body as an analyzable asset so endpoints/secrets/sinks
                # in inline JS are no longer missed. get_text() handles multi-child scripts where
                # .string is None. The synthetic URL uses a query marker (not a #fragment, which the
                # dedup normalizer strips -> would collapse every inline script of a page to one).
                if _is_inline_js_type(script.get("type")):
                    body = script.get_text()
                    if body and body.strip():
                        yield JSReference(
                            url=self._inline_asset_url(document_url, i, body),
                            initiator=document_url,
                            load_context=document_url,
                            method=LoadMethod.INLINE,
                            inline_content=body,
                        )

    @staticmethod
    def _inline_asset_url(base_url: str, index: int, body: str) -> str:
        """Synthetic, dedup-stable URL for an inline <script> (DQ-I01). A query marker survives the
        dedup normalizer (which drops fragments and would otherwise collapse all inline scripts of a
        page to one); the page host is preserved so first-party/scope classification is correct.
        The body hash disambiguates two DIFFERENT inline scripts whose page paths normalize together
        in the dedup cache (e.g. /a and /a/, which DedupCache._normalize_url rstrips to one path) --
        without it, the later, distinct-content script is silently dropped (INV-02). Identical bodies
        still collapse, matching external-asset content dedup."""
        parts = urlsplit(base_url)
        body_hash = hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()[:8]
        marker = f"__bi_inline={index}&__bi_h={body_hash}"
        query = f"{parts.query}&{marker}" if parts.query else marker
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))

    async def _collect_preload_links(
        self,
        soup: BeautifulSoup,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Extract JS from preload/modulepreload links."""
        document_url = base_url
        resolution_base = _document_resolution_base(soup, document_url)
        for link in soup.find_all("link"):
            raw_rel = link.get("rel")
            if isinstance(raw_rel, str):
                rel = [raw_rel]
            elif isinstance(raw_rel, (list, tuple)):
                rel = [str(item) for item in raw_rel]
            else:
                rel = []
            # HTML link `rel` / `as` tokens are case-insensitive; lowercase so capitalized
            # variants (rel="Preload", as="Script") are not missed.
            rel = [str(r).lower() for r in rel]

            href = _tag_attr_text(link.get("href"))
            as_value = str(link.get("as", "") or "").lower()

            if not href:
                continue

            full_url = normalize_url(href, resolution_base)

            # Check for preload with as=script
            # as="script" explicitly declares the resource as JS, no extension check needed
            if "preload" in rel and as_value == "script":
                if scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=document_url,
                        load_context=document_url,
                        method=LoadMethod.PRELOAD,
                    )

            # Check for modulepreload (inherently JS modules)
            elif "modulepreload" in rel:
                if scope.is_allowed(full_url):
                    yield JSReference(
                        url=full_url,
                        initiator=document_url,
                        load_context=document_url,
                        method=LoadMethod.MODULE_PRELOAD,
                    )

    async def _extract_dynamic_imports(
        self,
        content: str,
        base_url: str,
        scope: ScopePolicy,
        initiator_url: str | None = None,
    ) -> AsyncIterator[JSReference]:
        """Extract dynamic import URLs from JS content."""
        initiator = initiator_url or base_url
        seen: set[str] = set()
        for url in _iter_static_dependencies(content):
            if not url.startswith((".", "/", "http://", "https://")):
                continue
            full_url = normalize_url(url, base_url)
            if full_url and full_url not in seen and scope.is_allowed(full_url):
                seen.add(full_url)
                yield JSReference(
                    url=full_url,
                    initiator=initiator,
                    load_context=initiator,
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
        *,
        allow_private_ips: bool = False,
        rate_limiter: RateLimiter | None = None,
    ):
        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self._collector = StaticCollector(
            crawler_config,
            auth_config,
            allow_private_ips=allow_private_ips,
            rate_limiter=rate_limiter,
        )
        self._visited_urls: set[str] = set()
        self._collected_js: set[str] = set()
        self._pending_pages: list[tuple[str, int]] = []
        self._inflight_page: tuple[str, int] | None = None
        self._inflight_html: str | None = None
        self._inflight_document_url: str | None = None
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
            self._inflight_document_url = None
            self._inflight_refs = []
            self._inflight_ref_index = 0
            self._inflight_refs_complete = False
            self._inflight_links = []
            self._inflight_link_index = 0
            self._inflight_links_complete = False
        elif not self._pending_pages and normalize_url(url) not in self._visited_urls:
            self._pending_pages = [(url, 0)]

        self._resume_loaded = False
        self._collector._bind_auth_origin(url)

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
            self._inflight_document_url = None
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
        self._inflight_document_url = None
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
                document_url = inflight.get("document_url")
                if isinstance(document_url, str):
                    self._inflight_document_url = normalize_url(document_url) or None
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
            if self._inflight_document_url:
                inflight_state["document_url"] = self._inflight_document_url
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
                if not self._inflight_document_url:
                    self._inflight_document_url = normalized or url
            else:
                if not self._collector._client:
                    await self._collector.setup()
                if self._collector._client is None:
                    return

                try:
                    response = await self._collector._request(url, scope)
                    response.raise_for_status()
                except UnsafeRequestTarget as e:
                    logger.warning("Blocked unsafe static crawl request %s: %s", e.url, e.reason)
                    return
                except ResponseTooLarge as e:
                    logger.warning("Static crawl response exceeded body limit for %s", e.url)
                    return
                except httpx.HTTPStatusError as e:
                    status = e.response.status_code
                    logger.debug(f"HTTP error crawling {url}: {status}")
                    if self._is_transient_http_status(status):
                        self._record_retryable_failure(url, f"HTTP {status}", status)  # DQ-C06
                    return
                except httpx.RequestError as e:
                    logger.debug(f"Request error crawling {url}: {e}")
                    self._record_retryable_failure(url, f"request error: {type(e).__name__}")  # DQ-C06
                    return

                if not _response_looks_like_html(response):
                    return

                self._inflight_document_url = _response_document_url(response, url)
                self._inflight_html = response.text
                soup = BeautifulSoup(response.text, "lxml")

        document_url = self._inflight_document_url or normalized or url
        if soup is not None and not self._inflight_refs_complete:
            discovered_refs: list[JSReference] = []
            seen_page_urls: set[str] = set()
            async for ref in self._collector._collect_script_tags(soup, document_url, scope):
                if ref.url in seen_page_urls:
                    continue
                seen_page_urls.add(ref.url)
                discovered_refs.append(ref)
            async for ref in self._collector._collect_preload_links(soup, document_url, scope):
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
                links = self._extract_page_links(soup, document_url, scope)[:20]
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
        resolution_base = _document_resolution_base(soup, base_url)

        for a in soup.find_all("a", href=True):
            href = _tag_attr_text(a.get("href"))
            full_url = normalize_url(href, resolution_base)

            if scope.is_allowed(full_url):
                # Only HTML pages
                parsed_link = urlparse(full_url)
                resource_exts = (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".pdf", ".woff", ".woff2", ".ttf", ".ico")
                if not any(parsed_link.path.endswith(ext) for ext in resource_exts):
                    links.append(full_url)

        # dict.fromkeys dedups while PRESERVING document order; list(set(...)) randomized it,
        # so which pages the caller's "first N" cap kept (and thus which JS was discovered)
        # differed every run.
        return list(dict.fromkeys(links))
