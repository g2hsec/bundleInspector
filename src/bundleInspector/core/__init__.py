"""Core orchestration module."""

# Light re-exports (no browser/network stack). PipelineStage lives in core.progress; import
# it from there rather than via the orchestrator so this package stays importable without
# pulling in playwright/httpx.
from bundleInspector.core.dedup import DedupCache
from bundleInspector.core.progress import PipelineStage, ProgressTracker

__all__ = [
    "BundleInspector",
    "Orchestrator",
    "PipelineStage",
    "JobQueue",
    "Job",
    "JobStatus",
    "DedupCache",
    "ProgressTracker",
]


def __getattr__(name):
    # Lazy: the orchestrator (BundleInspector/Orchestrator) drags in playwright/httpx, and
    # JobQueue transitively imports the orchestrator too. Deferring them keeps
    # `import bundleInspector.core.asset_analysis` (the spawned-worker entry) light while
    # `from bundleInspector.core import Orchestrator` still resolves.
    if name in ("BundleInspector", "Orchestrator"):
        from bundleInspector.core import orchestrator

        return getattr(orchestrator, name)
    if name in ("JobQueue", "Job", "JobStatus"):
        from bundleInspector.core import job_queue

        return getattr(job_queue, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

