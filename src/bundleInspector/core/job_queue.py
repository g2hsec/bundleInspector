"""
Job queue for pipeline orchestration.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Optional
import uuid


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
    error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


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
        tasks = []

        while not self._queue.empty() or tasks:
            # Start new tasks up to concurrency limit
            while not self._queue.empty() and len(tasks) < self.max_concurrent:
                job = await self._queue.get()
                task = asyncio.create_task(self._run_job(job, handler))
                tasks.append(task)

            if tasks:
                # Wait for at least one task to complete
                done, pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                tasks = list(pending)

        self._running = False
        return list(self._jobs.values())

    async def _run_job(
        self,
        job: Job,
        handler: Callable[[Job], Awaitable[Any]],
    ) -> None:
        """Run a single job."""
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)

        try:
            job.result = await handler(job)
            job.status = JobStatus.COMPLETED
        except Exception as e:
            job.error = str(e)
            job.status = JobStatus.FAILED
        finally:
            job.completed_at = datetime.now(timezone.utc)

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID."""
        return self._jobs.get(job_id)

    def get_completed(self) -> list[Job]:
        """Get all completed jobs."""
        return [j for j in self._jobs.values() if j.status == JobStatus.COMPLETED]

    def get_failed(self) -> list[Job]:
        """Get all failed jobs."""
        return [j for j in self._jobs.values() if j.status == JobStatus.FAILED]

    @property
    def pending_count(self) -> int:
        """Number of pending jobs."""
        return self._queue.qsize()

    @property
    def total_count(self) -> int:
        """Total number of jobs."""
        return len(self._jobs)
