"""
Base collector classes and interfaces.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from bundleInspector.storage.models import JSReference


class BaseCollector(ABC):
    """Abstract base class for JS collectors."""

    name: str = "base"

    @abstractmethod
    async def collect(
        self,
        url: str,
        scope: "ScopePolicy",
    ) -> AsyncIterator[JSReference]:
        """
        Collect JS references from a URL.

        Args:
            url: The URL to collect from
            scope: Scope policy for filtering

        Yields:
            JSReference objects for discovered JS files
        """
        pass

    async def setup(self) -> None:
        """Setup collector resources. Override if needed."""
        pass

    async def teardown(self) -> None:
        """Cleanup collector resources. Override if needed."""
        pass

    async def __aenter__(self) -> "BaseCollector":
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.teardown()

