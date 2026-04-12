"""
Base reporter class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from bundleInspector.storage.models import Report


class BaseReporter(ABC):
    """Abstract base class for reporters."""

    name: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def generate(self, report: Report) -> str:
        """
        Generate report content.

        Args:
            report: Report to generate

        Returns:
            Report content as string
        """
        pass

    async def write(
        self,
        report: Report,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Write report to file.

        Args:
            report: Report to write
            output_path: Output file path

        Returns:
            Path to written file
        """
        content = self.generate(report)

        if output_path is None:
            output_path = Path(f"bundleInspector_report_{report.id[:8]}{self.extension}")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

        return output_path

