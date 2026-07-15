"""
Job queue for pipeline orchestration.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class JobStatus(Enum):
    """Job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """A job in the queue."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    status: JobStatus = JobStatus.PENDING
    data: Any = None
    result: Any = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    cancel_requested: bool = False


class JobQueue:
    """
    Async job queue for managing pipeline tasks.
    """

    def __init__(self, max_concurrent: int = 10):
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self.max_concurrent = max_concurrent
        self._queue: asyncio.Queue[Job] = asyncio.Queue()
        self._jobs: dict[str, Job] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._running_tasks: dict[str, asyncio.Task[None]] = {}
        self._state_lock = asyncio.Lock()

    async def add(self, name: str, data: Any = None) -> Job:
        """Add a job to the queue."""
        job = Job(name=name, data=data)
        self._jobs[job.id] = job
        await self._queue.put(job)
        return job

    async def process(
        self,
        handler: Callable[[Job], Awaitable[Any]],
    ) -> list[Job]:
        """
        Process all jobs in queue.

        Args:
            handler: Async function to handle each job

        Returns:
            List of all processed jobs (completed and failed)
        """
        self._running = True
        tasks: set[asyncio.Task[None]] = set()

        try:
            while not self._queue.empty() or tasks:
                while not self._queue.empty() and len(tasks) < self.max_concurrent:
                    job = await self._queue.get()
                    if job.cancel_requested or job.status == JobStatus.CANCELLED:
                        self._queue.task_done()
                        continue
                    task = asyncio.create_task(
                        self._run_job(job, handler),
                        name=f"bundleInspector-job-{job.id}",
                    )
                    self._running_tasks[job.id] = task
                    tasks.add(task)

                if tasks:
                    _, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            return list(self._jobs.values())
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._running_tasks.clear()
            self._running = False

    async def _run_job(
        self,
        job: Job,
        handler: Callable[[Job], Awaitable[Any]],
    ) -> None:
        """Run a single job."""
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)

        try:
            if job.cancel_requested:
                job.status = JobStatus.CANCELLED
                return
            job.result = await handler(job)
            job.status = JobStatus.CANCELLED if job.cancel_requested else JobStatus.COMPLETED
        except asyncio.CancelledError:
            job.cancel_requested = True
            job.status = JobStatus.CANCELLED
        except Exception as e:
            job.error = str(e)
            job.status = JobStatus.FAILED
        finally:
            job.completed_at = datetime.now(timezone.utc)
            self._running_tasks.pop(job.id, None)
            self._queue.task_done()

    async def cancel(self, job_id: str) -> bool:
        """Cancel a pending/running job and wait for its handler cleanup to finish."""
        async with self._state_lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in {
                JobStatus.COMPLETED,
                JobStatus.FAILED,
                JobStatus.CANCELLED,
            }:
                return False
            job.cancel_requested = True
            job.status = JobStatus.CANCELLED
            task = self._running_tasks.get(job_id)
            if task is None:
                job.completed_at = datetime.now(timezone.utc)
                return True
            task.cancel()

        if task is not asyncio.current_task():
            await asyncio.gather(task, return_exceptions=True)
        return True

    def get_job(self, job_id: str) -> Job | None:
        """Get job by ID."""
        return self._jobs.get(job_id)

    def get_completed(self) -> list[Job]:
        """Get all completed jobs."""
        return [j for j in self._jobs.values() if j.status == JobStatus.COMPLETED]

    def get_failed(self) -> list[Job]:
        """Get all failed jobs."""
        return [j for j in self._jobs.values() if j.status == JobStatus.FAILED]

    def get_cancelled(self) -> list[Job]:
        """Get all cancelled jobs."""
        return [j for j in self._jobs.values() if j.status == JobStatus.CANCELLED]

    @property
    def pending_count(self) -> int:
        """Number of pending jobs."""
        return self._queue.qsize()

    @property
    def total_count(self) -> int:
        """Total number of jobs."""
        return len(self._jobs)
