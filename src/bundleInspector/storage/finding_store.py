"""
Finding storage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import aiofiles

from bundleInspector.storage.models import Finding, PipelineCheckpoint, Report


class FindingStore:
    """
    Store for findings and reports.
    """

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self._findings_path = base_path / "findings"
        self._reports_path = base_path / "reports"
        self._checkpoint_path = base_path / "checkpoint.json"

        for path in [self._findings_path, self._reports_path]:
            path.mkdir(parents=True, exist_ok=True)

    async def store_finding(self, finding: Finding) -> None:
        """Store a finding."""
        file_path = self._findings_path / f"{finding.id}.json"

        async with aiofiles.open(file_path, "w") as f:
            await f.write(finding.model_dump_json(indent=2))

    async def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID."""
        file_path = self._findings_path / f"{finding_id}.json"

        if not file_path.exists():
            return None

        async with aiofiles.open(file_path, "r") as f:
            data = json.loads(await f.read())
            return Finding.model_validate(data)

    async def store_report(self, report: Report) -> Path:
        """
        Store a report.

        Returns:
            Path to stored report
        """
        file_path = self._reports_path / f"{report.id}.json"

        async with aiofiles.open(file_path, "w") as f:
            await f.write(report.model_dump_json(indent=2))

        return file_path

    async def get_report(self, report_id: str) -> Optional[Report]:
        """Get a report by ID."""
        file_path = self._reports_path / f"{report_id}.json"

        if not file_path.exists():
            return None

        async with aiofiles.open(file_path, "r") as f:
            data = json.loads(await f.read())
            return Report.model_validate(data)

    async def list_reports(self) -> list[str]:
        """List all report IDs."""
        return [
            f.stem for f in self._reports_path.iterdir()
            if f.suffix == ".json"
        ]

    async def get_latest_report(self) -> Optional[Report]:
        """Get the most recently written report for this job."""
        report_files = [
            f for f in self._reports_path.iterdir()
            if f.suffix == ".json" and f.is_file()
        ]
        if not report_files:
            return None

        latest = max(report_files, key=lambda f: f.stat().st_mtime)
        async with aiofiles.open(latest, "r") as f:
            data = json.loads(await f.read())
            return Report.model_validate(data)

    async def store_checkpoint(self, checkpoint: PipelineCheckpoint) -> Path:
        """Store a pipeline checkpoint for stage resume."""
        async with aiofiles.open(self._checkpoint_path, "w") as f:
            await f.write(checkpoint.model_dump_json(indent=2))
        return self._checkpoint_path

    async def get_checkpoint(self) -> Optional[PipelineCheckpoint]:
        """Load a stored pipeline checkpoint if present."""
        if not self._checkpoint_path.exists():
            return None

        async with aiofiles.open(self._checkpoint_path, "r") as f:
            data = json.loads(await f.read())
            return PipelineCheckpoint.model_validate(data)

