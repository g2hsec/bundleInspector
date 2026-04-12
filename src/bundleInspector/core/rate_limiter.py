"""
Rate limiting utilities for HTTP requests.

Provides rate limiting to prevent overwhelming target servers
and to comply with rate limit policies.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class RateLimiter:
    """
    Token bucket rate limiter for HTTP requests.

    Ensures requests are spaced out by at least `interval` seconds
    and limits concurrent requests to `max_concurrent`.
    """

    interval: float = 1.0  # Minimum seconds between requests
    max_concurrent: int = 10  # Maximum concurrent requests
    per_domain: bool = True  # Apply limits per-domain

    # Internal state
    _semaphore: asyncio.Semaphore = field(init=False)
    _last_request_time: dict[str, float] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL, normalizing default ports."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        if port and not (
            (parsed.scheme == "http" and port == 80)
            or (parsed.scheme == "https" and port == 443)
        ):
            return f"{hostname}:{port}"
        return hostname

    async def acquire(self, url: str = "") -> None:
        """
        Acquire rate limit permission for a URL.

        Blocks until it's safe to make the request.
        Note: This method only handles timing, not concurrency.
        Use acquire_slot() for concurrent limiting.
        """
        key = self._get_domain(url) if self.per_domain else "__global__"

        while True:
            async with self._lock:
                now = time.monotonic()
                last_time = self._last_request_time.get(key, 0)
                wait_time = max(0, self.interval - (now - last_time))

                if wait_time <= 0:
                    self._last_request_time[key] = time.monotonic()
                    return

            # Sleep OUTSIDE the lock so other domains aren't blocked
            await asyncio.sleep(wait_time)

    async def acquire_slot(self) -> None:
        """Acquire a concurrent slot (semaphore)."""
        await self._semaphore.acquire()

    def release_slot(self) -> None:
        """Release a concurrent slot (semaphore)."""
        self._semaphore.release()

    async def __aenter__(self):
        """Context manager entry - acquires a slot."""
        await self.acquire_slot()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - releases the slot."""
        self.release_slot()


@dataclass
class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that backs off on errors.

    Automatically increases delay when receiving rate limit errors (429)
    or server errors (5xx).
    """

    base_interval: float = 1.0
    max_interval: float = 60.0
    backoff_factor: float = 2.0
    recovery_factor: float = 0.9

    _error_counts: dict[str, int] = field(default_factory=dict)
    _current_intervals: dict[str, float] = field(default_factory=dict)

    def __post_init__(self):
        super().__post_init__()
        self.interval = self.base_interval

    def _get_interval(self, key: str) -> float:
        """Get current interval for a domain."""
        return self._current_intervals.get(key, self.base_interval)

    async def acquire(self, url: str = "") -> None:
        """Acquire with adaptive interval (timing only, no concurrency control)."""
        key = self._get_domain(url) if self.per_domain else "__global__"

        while True:
            async with self._lock:
                now = time.monotonic()
                last_time = self._last_request_time.get(key, 0)
                current_interval = self._get_interval(key)
                wait_time = max(0, current_interval - (now - last_time))

                if wait_time <= 0:
                    self._last_request_time[key] = time.monotonic()
                    return

            # Sleep OUTSIDE the lock so other domains aren't blocked
            await asyncio.sleep(wait_time)

    async def record_success(self, url: str) -> None:
        """Record successful request - gradually reduce interval."""
        key = self._get_domain(url) if self.per_domain else "__global__"

        async with self._lock:
            current = self._current_intervals.get(key, self.base_interval)
            new_interval = max(
                self.base_interval,
                current * self.recovery_factor
            )
            self._current_intervals[key] = new_interval
            self._error_counts[key] = 0

    async def record_error(self, url: str, status_code: int = 0) -> None:
        """
        Record failed request - increase interval on rate limit/server errors.

        Args:
            url: Request URL
            status_code: HTTP status code (429 for rate limit, 5xx for server error)
        """
        key = self._get_domain(url) if self.per_domain else "__global__"

        async with self._lock:
            # Only back off on rate limits (429) or server errors (5xx)
            if status_code == 429 or (500 <= status_code < 600):
                self._error_counts[key] = self._error_counts.get(key, 0) + 1
                current = self._current_intervals.get(key, self.base_interval)
                new_interval = min(
                    self.max_interval,
                    current * self.backoff_factor
                )
                self._current_intervals[key] = new_interval


@dataclass
class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter.

    Limits requests to `max_requests` within a `window_seconds` period.
    """

    max_requests: int = 10
    window_seconds: float = 1.0
    per_domain: bool = True

    _request_times: dict[str, deque] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        if self.max_requests < 1:
            raise ValueError("max_requests must be at least 1")

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL, normalizing default ports."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        if port and not (
            (parsed.scheme == "http" and port == 80)
            or (parsed.scheme == "https" and port == 443)
        ):
            return f"{hostname}:{port}"
        return hostname

    async def acquire(self, url: str = "") -> None:
        """Acquire permission to make a request."""
        key = self._get_domain(url) if self.per_domain else "__global__"

        while True:
            async with self._lock:
                now = time.monotonic()

                # Initialize deque for this domain
                if key not in self._request_times:
                    self._request_times[key] = deque()

                times = self._request_times[key]

                # Remove old timestamps outside the window
                cutoff = now - self.window_seconds
                while times and times[0] < cutoff:
                    times.popleft()

                # If under the limit, record and return
                if len(times) < self.max_requests:
                    times.append(now)
                    return

                # Calculate wait time before releasing lock
                wait_time = times[0] + self.window_seconds - now

            # Sleep OUTSIDE the lock so other domains aren't blocked
            if wait_time > 0:
                await asyncio.sleep(wait_time)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
