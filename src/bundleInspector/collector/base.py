"""
Base collector classes and interfaces.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from types import TracebackType
from typing import TYPE_CHECKING, Any

from bundleInspector.storage.models import JSReference

if TYPE_CHECKING:
    from bundleInspector.collector.scope import ScopePolicy


class BaseCollector(ABC):
    """Abstract base class for JS collectors."""

    name: str = "base"

    @abstractmethod
    def collect(
        self,
        url: str,
        scope: ScopePolicy,
    ) -> AsyncIterator[JSReference]:
        """
        Collect JS references from a URL.

        Args:
            url: The URL to collect from
            scope: Scope policy for filtering

        Yields:
            JSReference objects for discovered JS files
        """
        raise NotImplementedError

    async def setup(self) -> None:
        """Setup collector resources. Override if needed."""
        return None

    async def teardown(self) -> None:
        """Cleanup collector resources. Override if needed."""
        return None

    async def __aenter__(self) -> BaseCollector:
        await self.setup()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.teardown()

    # ------------------------------------------------------------ transient-failure accounting
    # DQ-C06: collectors historically SWALLOWED transient fetch/navigation failures (429/5xx/
    # timeout/nav-fail) by returning from collect(), and the orchestrator then checkpointed the
    # phase as complete -- freezing lost coverage as a finished 0-result with no retry and no
    # report telemetry. Collectors now record such failures here; the orchestrator reads them to
    # avoid a false-complete checkpoint and to surface the lost coverage.

    @property
    def retryable_failures(self) -> list[dict[str, Any]]:
        """Transient (retryable) failures swallowed during collect(). Lazily initialized so
        subclasses need not call super().__init__()."""
        fails = getattr(self, "_retryable_failures", None)
        if fails is None:
            fails = []
            self._retryable_failures = fails
        return fails

    def _record_retryable_failure(
        self, url: str, reason: str, status: int | None = None
    ) -> None:
        """Record a swallowed transient failure so the phase is not frozen as complete."""
        self.retryable_failures.append(
            {"url": url, "reason": reason, "status": status, "phase": getattr(self, "name", "")}
        )

    @staticmethod
    def _is_transient_http_status(status: int) -> bool:
        """429 and 5xx are retryable; other 4xx are terminal (page genuinely absent/forbidden)."""
        return status == 429 or status >= 500
