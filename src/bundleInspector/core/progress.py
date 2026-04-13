"""
Progress tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class PipelineStage(Enum):
    """Pipeline stages."""
    INIT = "init"
    CRAWL = "crawl"
    DOWNLOAD = "download"
    NORMALIZE = "normalize"
    PARSE = "parse"
    ANALYZE = "analyze"
    CORRELATE = "correlate"
    CLASSIFY = "classify"
    REPORT = "report"
    COMPLETE = "complete"


@dataclass
class StageProgress:
    """Progress for a single stage."""
    stage: PipelineStage
    total: int = 0
    completed: int = 0
    failed: int = 0
    detail: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 0.0
        return ((self.completed + self.failed) / self.total) * 100

    @property
    def is_complete(self) -> bool:
        return self.completed + self.failed >= self.total


@dataclass
class ProgressTracker:
    """
    Track progress through the pipeline.
    """

    current_stage: PipelineStage = PipelineStage.INIT
    stages: dict[PipelineStage, StageProgress] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    # Callbacks
    on_stage_start: Optional[Callable[[PipelineStage], None]] = None
    on_stage_complete: Optional[Callable[[PipelineStage, StageProgress], None]] = None
    on_progress: Optional[Callable[[PipelineStage, int, int], None]] = None
    on_stage_detail: Optional[Callable[[PipelineStage, str], None]] = None

    def start_stage(self, stage: PipelineStage, total: int = 0) -> None:
        """Start a pipeline stage."""
        self.current_stage = stage
        self.stages[stage] = StageProgress(
            stage=stage,
            total=total,
            started_at=datetime.now(timezone.utc),
        )

        if self.on_stage_start:
            self.on_stage_start(stage)

    def update(self, completed: int = 1, failed: int = 0) -> None:
        """Update progress for current stage."""
        if self.current_stage not in self.stages:
            return

        progress = self.stages[self.current_stage]
        progress.completed += completed
        progress.failed += failed

        if self.on_progress:
            self.on_progress(
                self.current_stage,
                progress.completed + progress.failed,
                progress.total,
            )

    def set_total(self, total: int) -> None:
        """Set total for current stage."""
        if self.current_stage in self.stages:
            self.stages[self.current_stage].total = total

    def set_detail(self, detail: str) -> None:
        """Update detail text for the current stage without changing counters."""
        if self.current_stage not in self.stages:
            return

        progress = self.stages[self.current_stage]
        progress.detail = detail

        if self.on_stage_detail:
            self.on_stage_detail(self.current_stage, detail)

    def complete_stage(self) -> None:
        """Complete current stage."""
        if self.current_stage in self.stages:
            progress = self.stages[self.current_stage]
            progress.completed_at = datetime.now(timezone.utc)

            if self.on_stage_complete:
                self.on_stage_complete(self.current_stage, progress)

    def complete(self) -> None:
        """Complete the entire pipeline."""
        self.completed_at = datetime.now(timezone.utc)
        self.current_stage = PipelineStage.COMPLETE

    @property
    def duration(self) -> float:
        """Total duration in seconds."""
        end = self.completed_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    @property
    def overall_percent(self) -> float:
        """Overall progress percentage."""
        # Use fixed stage count (exclude INIT and COMPLETE pseudo-stages)
        total_stages = len(PipelineStage) - 2
        if total_stages <= 0:
            return 0.0
        completed_stages = sum(
            1 for s in self.stages.values()
            if s.completed_at is not None
        )
        return (completed_stages / total_stages) * 100

    def get_summary(self) -> dict:
        """Get progress summary."""
        return {
            "current_stage": self.current_stage.value,
            "overall_percent": self.overall_percent,
            "duration_seconds": self.duration,
            "stages": {
                stage.value: {
                    "total": progress.total,
                    "completed": progress.completed,
                    "failed": progress.failed,
                    "percent": progress.percent,
                }
                for stage, progress in self.stages.items()
            },
        }
