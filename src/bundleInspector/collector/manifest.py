"""
Build manifest parser for discovering JS chunks.

Parses webpack/vite/next.js manifests to find all JS assets.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

from bundleInspector.collector.base import BaseCollector
from bundleInspector.collector.scope import ScopePolicy, normalize_url, is_js_url
from bundleInspector.config import CrawlerConfig, AuthConfig
from bundleInspector.storage.models import JSReference, LoadMethod


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
    ):
        self.config = crawler_config
        self.auth = auth_config or AuthConfig()
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        """Initialize HTTP client."""
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
        }
        headers.update(self.auth.get_auth_headers())

        self._client = httpx.AsyncClient(
            headers=headers,
            cookies=self.auth.cookies if self.auth.cookies else None,
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
        Collect JS references from manifests.

        Args:
            url: Base URL to check for manifests
            scope: Scope policy

        Yields:
            JSReference for each discovered JS file
        """
        if not self._client:
            await self.setup()

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
        try:
            response = await self._client.get(manifest_url)
            if response.status_code != 200:
                return
        except httpx.HTTPError:
            return

        content = response.text
        content_type = response.headers.get("content-type", "")

        # Handle JSON manifests (only by content-type, not by content shape)
        if "json" in content_type:
            async for ref in self._parse_json_manifest(
                content, manifest_url, base_url, scope
            ):
                yield ref

        # Handle JS manifests (like Next.js buildManifest)
        elif "javascript" in content_type or manifest_url.endswith(".js"):
            async for ref in self._parse_js_manifest(
                content, manifest_url, base_url, scope
            ):
                yield ref

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
        except json.JSONDecodeError:
            return

        # Extract all string values that look like JS paths
        js_paths = self._extract_js_paths_from_json(data)

        for path in js_paths:
            # Resolve relative paths against manifest location, not site root
            full_url = normalize_url(path, manifest_url)

            if scope.is_allowed(full_url) and is_js_url(full_url):
                yield JSReference(
                    url=full_url,
                    initiator=manifest_url,
                    load_context=manifest_url,
                    method=LoadMethod.MANIFEST,
                )

    def _extract_js_paths_from_json(self, data: Any, paths: list[str] | None = None) -> list[str]:
        """Recursively extract JS paths from JSON data."""
        if paths is None:
            paths = []

        if isinstance(data, str):
            if is_js_url(data) or data.endswith(".js"):
                paths.append(data)
        elif isinstance(data, dict):
            for key, value in data.items():
                # Common manifest keys
                if key in ("src", "file", "url", "path", "js", "main", "module"):
                    if isinstance(value, str):
                        paths.append(value)
                        continue
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                paths.append(item)
                            else:
                                self._extract_js_paths_from_json(item, paths)
                        continue

                self._extract_js_paths_from_json(value, paths)

        elif isinstance(data, list):
            for item in data:
                self._extract_js_paths_from_json(item, paths)

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
        for chunk_dir in self.CHUNK_DIRS:
            dir_url = urljoin(base_url, chunk_dir)

            # Try to list directory (unlikely to work but worth trying)
            try:
                response = await self._client.get(dir_url)
                if response.status_code == 200:
                    # Look for JS file references in directory listing
                    for match in re.finditer(
                        r'href=["\']([^"\']+\.js)["\']',
                        response.text
                    ):
                        path = match.group(1)
                        full_url = normalize_url(path, dir_url)

                        if scope.is_allowed(full_url):
                            yield JSReference(
                                url=full_url,
                                initiator=dir_url,
                                load_context=dir_url,
                                method=LoadMethod.MANIFEST,
                            )
            except httpx.HTTPError:
                pass

