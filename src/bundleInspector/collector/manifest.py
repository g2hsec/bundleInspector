"""
Build manifest parser for discovering JS chunks.

Parses webpack/vite/next.js manifests to find all JS assets.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncIterator
from inspect import isawaitable
from typing import Any
from urllib.parse import urljoin

import httpx

from bundleInspector.collector.base import BaseCollector
from bundleInspector.collector.scope import ScopePolicy, is_js_url, normalize_url
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
from bundleInspector.storage.models import JSReference, LoadMethod

logger = logging.getLogger(__name__)


class ManifestCollector(BaseCollector):
    """
    Collect JS references from build manifests.

    This is Tier C collection - discovers JS from build tool artifacts.
    """

    name = "manifest"

    # Common manifest paths
    MANIFEST_PATHS = [
        # Webpack
        "/asset-manifest.json",
        "/manifest.json",
        "/webpack-manifest.json",
        "/static/asset-manifest.json",
        "/build/asset-manifest.json",

        # Vite
        "/.vite/manifest.json",

        # Next.js
        "/_next/static/chunks/webpack.js",
        "/_buildManifest.js",
        "/_ssgManifest.js",

        # Create React App
        "/static/js/main.js",
    ]

    # Common chunk directories
    CHUNK_DIRS = [
        "/static/js/",
        "/static/chunks/",
        "/_next/static/chunks/",
        "/assets/",
        "/js/",
        "/dist/",
        "/build/static/js/",
    ]

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
            "Accept": "*/*",
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
            raise RuntimeError("ManifestCollector must be set up before requesting a URL")
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
        raise RuntimeError("manifest request retry loop exhausted without a response")

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
        Collect JS references from manifests.

        Args:
            url: Base URL to check for manifests
            scope: Scope policy

        Yields:
            JSReference for each discovered JS file
        """
        if not self._client:
            await self.setup()
        self._bind_auth_origin(url)

        base_url = self._get_base_url(url)
        seen_urls: set[str] = set()

        # Try to fetch manifests
        for manifest_path in self.MANIFEST_PATHS:
            # Skip paths with glob patterns (e.g., "*.js") - not valid HTTP URLs
            if "*" in manifest_path or "?" in manifest_path:
                logger.debug(f"Skipping manifest path with glob pattern: {manifest_path}")
                continue
            manifest_url = urljoin(base_url, manifest_path)

            async for ref in self._parse_manifest(manifest_url, base_url, scope):
                if ref.url not in seen_urls:
                    seen_urls.add(ref.url)
                    yield ref

        # Try to discover chunk directories
        async for ref in self._discover_chunk_dirs(base_url, scope):
            if ref.url not in seen_urls:
                seen_urls.add(ref.url)
                yield ref

    def _get_base_url(self, url: str) -> str:
        """Get base URL (scheme + netloc)."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _parse_manifest(
        self,
        manifest_url: str,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Parse a manifest file for JS references."""
        client = self._client
        if client is None:
            raise RuntimeError("ManifestCollector must be set up before parsing a manifest")
        try:
            response = await self._request(manifest_url, scope)
            if response.status_code != 200:
                if self._is_transient_http_status(response.status_code):  # DQ-C06
                    self._record_retryable_failure(
                        manifest_url, f"HTTP {response.status_code}", response.status_code
                    )
                return
        except UnsafeRequestTarget as e:
            logger.warning("Blocked unsafe manifest request %s: %s", e.url, e.reason)
            return
        except ResponseTooLarge as e:
            logger.warning("Manifest response exceeded body limit for %s", e.url)
            return
        except httpx.HTTPError as e:
            self._record_retryable_failure(manifest_url, f"request error: {type(e).__name__}")  # DQ-C06
            return

        content = response.text
        response_url = str(getattr(response, "url", "") or manifest_url)
        content_type = response.headers.get("content-type", "")

        # Handle JSON manifests (only by content-type, not by content shape)
        if "json" in content_type:
            async for ref in self._parse_json_manifest(
                content, response_url, base_url, scope
            ):
                yield ref

        # Handle JS manifests (like Next.js buildManifest)
        elif "javascript" in content_type or response_url.endswith(".js"):
            async for ref in self._parse_js_manifest(
                content, response_url, base_url, scope
            ):
                yield ref

        # Shape-based fallback: a build manifest served with an ambiguous content-type (text/plain,
        # application/octet-stream, none) at a known .json manifest path is otherwise silently
        # dropped. Gated by the .json path AND a JSON-container shape; _parse_json_manifest only
        # yields refs whose paths pass is_js_url + scope, so arbitrary/non-manifest JSON (e.g. a PWA
        # manifest of .png icons) still produces zero references (DQ-I07).
        elif response_url.endswith(".json") and self._looks_like_json_manifest(content):
            async for ref in self._parse_json_manifest(
                content, response_url, base_url, scope
            ):
                yield ref

    @staticmethod
    def _looks_like_json_manifest(content: str) -> bool:
        """Best-effort shape check: is `content` a JSON object/array (a possible build manifest)?"""
        stripped = content.lstrip()
        if not stripped.startswith(("{", "[")):
            return False
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, RecursionError):
            return False
        return isinstance(data, (dict, list))

    async def _parse_json_manifest(
        self,
        content: str,
        manifest_url: str,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Parse JSON manifest file."""
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, RecursionError):
            # A deeply-nested manifest served by the target must not abort the crawl.
            return

        # Extract all string values that look like JS paths
        js_paths = self._extract_js_paths_from_json(data)

        # Vite serves its manifest at <base>/.vite/manifest.json, but its `file` values are relative
        # to the deployment BASE, not the manifest's own directory. Resolving them against
        # manifest_url yields non-existent /.vite/assets/... URLs (404 -> never analyzed). Strip the
        # .vite/manifest.json suffix to recover the deployment base (default "/" or a sub-path base).
        # All other manifests keep resolving against manifest_url unchanged (DQ-I06).
        resolution_base = manifest_url
        _vite_marker = "/.vite/manifest.json"
        if urlparse(manifest_url).path.endswith(_vite_marker):
            resolution_base = manifest_url[: manifest_url.rfind(_vite_marker)] + "/"

        for path in js_paths:
            # Resolve relative paths against the resolution base (deployment base for Vite,
            # manifest location otherwise), not site root.
            full_url = normalize_url(path, resolution_base)

            if scope.is_allowed(full_url) and is_js_url(full_url):
                yield JSReference(
                    url=full_url,
                    initiator=manifest_url,
                    load_context=manifest_url,
                    method=LoadMethod.MANIFEST,
                )

    def _extract_js_paths_from_json(self, data: Any, paths: list[str] | None = None) -> list[str]:
        """Iteratively extract JS paths from JSON data.

        Explicit stack rather than recursion so a deeply-nested manifest (trivial for a broken
        build tool or an attacker to emit) cannot raise RecursionError and abort the crawl.
        Visits the same node set as the old recursive version.
        """
        if paths is None:
            paths = []

        stack: list[Any] = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                if is_js_url(node) or node.endswith(".js"):
                    paths.append(node)
            elif isinstance(node, dict):
                for key, value in node.items():
                    # Vite's `src` is an input path and its import arrays contain manifest entry
                    # keys, not emitted URLs. Treating either as an output invents phantom assets.
                    if key in {"src", "imports", "dynamicImports"}:
                        continue
                    # Common manifest keys
                    if key in ("file", "url", "path", "js", "main", "module"):
                        if isinstance(value, str):
                            paths.append(value)
                            continue
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(item, str):
                                    paths.append(item)
                                else:
                                    stack.append(item)
                            continue
                    stack.append(value)
            elif isinstance(node, list):
                for item in node:
                    stack.append(item)

        return paths

    async def _parse_js_manifest(
        self,
        content: str,
        manifest_url: str,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Parse JS manifest file (like Next.js buildManifest)."""
        # Extract paths from JS content
        found_paths: set[str] = set()

        # Pattern 1: Individual JS file paths in quotes
        for match in re.finditer(r'["\']([^"\']+\.js)["\']', content):
            path = match.group(1).strip()
            if path and is_js_url(path):
                found_paths.add(path)

        # Pattern 2: Chunk hashes - use full match (chunks/hash.js)
        for match in re.finditer(r'chunks/([a-f0-9]+\.js)', content):
            path = f"chunks/{match.group(1)}"
            found_paths.add(path)

        for path in found_paths:
            # Resolve relative paths against manifest location, not site root
            full_url = normalize_url(path, manifest_url)

            if scope.is_allowed(full_url):
                yield JSReference(
                    url=full_url,
                    initiator=manifest_url,
                    load_context=manifest_url,
                    method=LoadMethod.MANIFEST,
                )

    async def _discover_chunk_dirs(
        self,
        base_url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """Try to discover JS in common chunk directories."""
        client = self._client
        if client is None:
            raise RuntimeError("ManifestCollector must be set up before discovering chunk directories")
        for chunk_dir in self.CHUNK_DIRS:
            dir_url = urljoin(base_url, chunk_dir)

            # Try to list directory (unlikely to work but worth trying)
            try:
                response = await self._request(dir_url, scope)
                if response.status_code == 200:
                    response_url = str(getattr(response, "url", "") or dir_url)
                    # Look for JS file references in directory listing
                    for match in re.finditer(
                        r'href=["\']([^"\']+\.js)["\']',
                        response.text
                    ):
                        path = match.group(1)
                        full_url = normalize_url(path, response_url)

                        if scope.is_allowed(full_url):
                            yield JSReference(
                                url=full_url,
                                initiator=response_url,
                                load_context=response_url,
                                method=LoadMethod.MANIFEST,
                            )
            except UnsafeRequestTarget as e:
                logger.warning("Blocked unsafe chunk-directory request %s: %s", e.url, e.reason)
            except ResponseTooLarge as e:
                logger.warning("Chunk-directory response exceeded body limit for %s", e.url)
            except httpx.HTTPError:
                pass
