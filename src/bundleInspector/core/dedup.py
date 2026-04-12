"""
Deduplication cache.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional


@dataclass
class CacheEntry:
    """Cache entry."""
    key: str
    content_hash: Optional[str] = None
    metadata: Optional[dict] = None


class DedupCache:
    """
    Deduplication cache for URLs and content.

    Uses OrderedDict with maxsize to prevent unbounded memory growth.
    When full, the oldest entries are evicted (FIFO).
    """

    def __init__(self, max_urls: int = 100_000, max_hashes: int = 50_000):
        self._max_urls = max_urls
        self._max_hashes = max_hashes
        self._url_cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._hash_cache: OrderedDict[str, str] = OrderedDict()  # content_hash -> first_url

    def has_url(self, url: str) -> bool:
        """Check if URL has been seen."""
        normalized = self._normalize_url(url)
        return normalized in self._url_cache

    def add_url(self, url: str, content_hash: Optional[str] = None) -> bool:
        """
        Add URL to cache.

        Args:
            url: URL to add
            content_hash: Optional content hash

        Returns:
            True if new, False if duplicate
        """
        normalized = self._normalize_url(url)

        if normalized in self._url_cache:
            return False

        entry = CacheEntry(key=normalized, content_hash=content_hash)
        self._url_cache[normalized] = entry

        # Evict oldest if over limit
        while len(self._url_cache) > self._max_urls:
            self._url_cache.popitem(last=False)

        if content_hash:
            if content_hash not in self._hash_cache:
                self._hash_cache[content_hash] = url

        return True

    def has_content(self, content_hash: str) -> bool:
        """Check if content hash has been seen."""
        return content_hash in self._hash_cache

    def get_url_for_hash(self, content_hash: str) -> Optional[str]:
        """Get first URL for a content hash."""
        return self._hash_cache.get(content_hash)

    def add_content(self, content_hash: str, url: str) -> bool:
        """
        Add content hash to cache.

        Args:
            content_hash: Content hash
            url: URL of the content

        Returns:
            True if new, False if duplicate
        """
        if content_hash in self._hash_cache:
            return False

        self._hash_cache[content_hash] = url

        # Evict oldest if over limit
        while len(self._hash_cache) > self._max_hashes:
            self._hash_cache.popitem(last=False)

        return True

    def compute_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content).hexdigest()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)

        # Strip default ports (:80 for http, :443 for https)
        netloc = parsed.netloc.lower()
        scheme = parsed.scheme.lower()
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Strip trailing slashes from path
        path = parsed.path.rstrip("/")

        # Remove fragment, normalize scheme and host
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            "",  # No fragment
        ))

        return normalized

    @property
    def url_count(self) -> int:
        """Number of cached URLs."""
        return len(self._url_cache)

    @property
    def content_count(self) -> int:
        """Number of unique content hashes."""
        return len(self._hash_cache)

    def clear(self) -> None:
        """Clear the cache."""
        self._url_cache.clear()
        self._hash_cache.clear()
