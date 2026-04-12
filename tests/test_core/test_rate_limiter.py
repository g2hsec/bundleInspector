"""Tests for rate limiter."""

import asyncio
import time

import pytest

from bundleInspector.core.rate_limiter import (
    RateLimiter,
    AdaptiveRateLimiter,
    SlidingWindowRateLimiter,
)


class TestRateLimiter:
    """Tests for basic RateLimiter."""

    @pytest.mark.asyncio
    async def test_rate_limit_interval(self):
        """Test that requests are spaced by interval."""
        limiter = RateLimiter(interval=0.1, max_concurrent=10)

        times = []
        for _ in range(3):
            await limiter.acquire("https://example.com")
            times.append(time.monotonic())

        # Check intervals (allow 50ms tolerance)
        for i in range(1, len(times)):
            diff = times[i] - times[i - 1]
            assert diff >= 0.08, f"Interval too short: {diff}s"

    @pytest.mark.asyncio
    async def test_per_domain_rate_limiting(self):
        """Test that different domains have separate limits."""
        limiter = RateLimiter(interval=0.2, max_concurrent=10, per_domain=True)

        start = time.monotonic()

        # Requests to different domains should not wait for each other
        await asyncio.gather(
            limiter.acquire("https://example.com/page1"),
            limiter.acquire("https://other.com/page1"),
        )

        elapsed = time.monotonic() - start
        # Should be fast since different domains
        assert elapsed < 0.15

    @pytest.mark.asyncio
    async def test_concurrent_limit(self):
        """Test maximum concurrent requests."""
        limiter = RateLimiter(interval=0, max_concurrent=2)
        active = [0]
        max_active = [0]

        async def worker(url: str):
            async with limiter:  # Use context manager for slot management
                await limiter.acquire(url)  # Handle timing
                active[0] += 1
                max_active[0] = max(max_active[0], active[0])
                await asyncio.sleep(0.05)
                active[0] -= 1

        await asyncio.gather(*[
            worker(f"https://example.com/{i}")
            for i in range(5)
        ])

        assert max_active[0] <= 2


class TestAdaptiveRateLimiter:
    """Tests for AdaptiveRateLimiter."""

    @pytest.mark.asyncio
    async def test_backoff_on_rate_limit(self):
        """Test that limiter backs off on 429 errors."""
        limiter = AdaptiveRateLimiter(
            base_interval=0.1,
            max_interval=1.0,
            backoff_factor=2.0,
        )

        url = "https://example.com"

        # Record some errors
        await limiter.record_error(url, 429)
        await limiter.record_error(url, 429)

        # Interval should have increased
        assert limiter._current_intervals.get(
            limiter._get_domain(url), 0.1
        ) > 0.1

    @pytest.mark.asyncio
    async def test_recovery_on_success(self):
        """Test that limiter recovers on successful requests."""
        limiter = AdaptiveRateLimiter(
            base_interval=0.1,
            recovery_factor=0.5,
        )

        url = "https://example.com"

        # Set high interval
        limiter._current_intervals[limiter._get_domain(url)] = 1.0

        # Record success
        await limiter.record_success(url)

        # Interval should decrease
        assert limiter._current_intervals[limiter._get_domain(url)] < 1.0

    @pytest.mark.asyncio
    async def test_max_interval_limit(self):
        """Test that interval doesn't exceed max."""
        limiter = AdaptiveRateLimiter(
            base_interval=0.1,
            max_interval=0.5,
            backoff_factor=10.0,
        )

        url = "https://example.com"

        # Record many errors
        for _ in range(10):
            await limiter.record_error(url, 429)

        # Should not exceed max
        assert limiter._current_intervals[limiter._get_domain(url)] <= 0.5


class TestSlidingWindowRateLimiter:
    """Tests for SlidingWindowRateLimiter."""

    @pytest.mark.asyncio
    async def test_window_limit(self):
        """Test sliding window limits requests."""
        limiter = SlidingWindowRateLimiter(
            max_requests=3,
            window_seconds=0.5,
        )

        url = "https://example.com"
        start = time.monotonic()

        # Make 5 requests (should take at least 1 window)
        for _ in range(5):
            await limiter.acquire(url)

        elapsed = time.monotonic() - start
        # Should have waited for window to expire
        assert elapsed >= 0.4

    @pytest.mark.asyncio
    async def test_per_domain_windows(self):
        """Test separate windows per domain."""
        limiter = SlidingWindowRateLimiter(
            max_requests=2,
            window_seconds=1.0,
            per_domain=True,
        )

        start = time.monotonic()

        # 2 requests to each domain should be fast
        await asyncio.gather(
            limiter.acquire("https://example.com/1"),
            limiter.acquire("https://example.com/2"),
            limiter.acquire("https://other.com/1"),
            limiter.acquire("https://other.com/2"),
        )

        elapsed = time.monotonic() - start
        # Should be fast since different domains
        assert elapsed < 0.2

