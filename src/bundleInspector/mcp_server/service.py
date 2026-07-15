"""Protocol-neutral application service used by the MCP adapter."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Protocol

from pydantic import ValidationError

from bundleInspector.core.job_queue import Job
from bundleInspector.reporter.public_view import (
    PublicPageKind,
    PublicReportProjector,
    opaque_public_id,
)
from bundleInspector.storage.job_repository import JobAccessError, JobRepository
from bundleInspector.storage.models import CompletenessStatus

_PUBLIC_TOKEN = re.compile(r"[A-Za-z0-9_-]{24}\Z")
_MAX_CURSOR_LENGTH = 4096


class PublicResourceUnavailable(LookupError):
    """Stable public error for missing, malformed, and unauthorized identifiers."""

    def __init__(self) -> None:
        super().__init__("resource unavailable")


class JobStatusReader(Protocol):
    """Read-only queue capability accepted by the public MCP service."""

    def get_job(self, job_id: str) -> Job | None: ...


class MCPService:
    def __init__(
        self,
        repository: JobRepository,
        *,
        queue: JobStatusReader | None = None,
        principal_id: str = "local",
    ):
        self.repository = repository
        self._status_reader = queue
        self.principal_id = principal_id
        self._key = repository.public_signing_key
        self.projector = PublicReportProjector(self._key)

    async def list_jobs(self, *, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be in [1, 100]")
        offset = 0
        state: dict[str, object] | None = None
        if cursor:
            state = self._decode_cursor(cursor)
            raw_offset = state.get("offset")
            if isinstance(raw_offset, bool) or not isinstance(raw_offset, int) or raw_offset < 0:
                raise ValueError("job cursor offset is invalid")
            offset = raw_offset
        job_ids = self.repository.list_job_ids(self.principal_id)

        digest = hashlib.sha256(b"bundle-inspector-public-jobs-v2\0")
        page: list[dict[str, Any]] = []
        visible_count = 0
        for raw_job_id in job_ids:
            try:
                row = await self._job_status(raw_job_id)
            except PublicResourceUnavailable:
                continue
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            if offset <= visible_count < offset + limit:
                page.append(row)
            visible_count += 1
        revision = digest.hexdigest()[:24]
        if offset > visible_count:
            raise ValueError("job cursor offset is invalid")
        if state is not None:
            expected = {"kind": "jobs", "revision": revision, "limit": limit,
                        "principal": self._public_id("principal", self.principal_id)}
            if any(state.get(key) != value for key, value in expected.items()):
                raise ValueError("job cursor does not match this revision and request context")
        next_offset = offset + len(page)
        next_cursor = None
        if next_offset < visible_count:
            next_cursor = self._encode_cursor({
                "kind": "jobs", "revision": revision, "limit": limit,
                "principal": self._public_id("principal", self.principal_id),
                "offset": next_offset,
            })
        return {
            "schema_version": 1,
            "revision": revision,
            "page_total": visible_count,
            "page_offset": offset,
            "page_count": len(page),
            "page_truncated": next_offset < visible_count,
            "jobs": page,
            "next_cursor": next_cursor,
        }

    async def get_report_page(
        self,
        job_id: str,
        *,
        report_id: str | None = None,
        page_kind: PublicPageKind = "findings",
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        if cursor is not None and (
            not isinstance(cursor, str) or len(cursor) > _MAX_CURSOR_LENGTH
        ):
            raise ValueError("cursor is malformed")
        raw_job_id = self._resolve_job_id(job_id)
        raw_report_id = await self._resolve_report_id(raw_job_id, report_id)
        try:
            report = await self.repository.get_report(
                raw_job_id,
                self.principal_id,
                raw_report_id,
            )
        except (FileNotFoundError, JobAccessError, OSError, ValueError):
            raise PublicResourceUnavailable() from None
        if report is None:
            raise PublicResourceUnavailable()
        try:
            view = self.projector.project(
                report,
                page_kind=page_kind,
                limit=limit,
                cursor=cursor,
                principal_id=self.principal_id,
            )
        except ValidationError:
            raise PublicResourceUnavailable() from None
        return view.model_dump(mode="json")

    async def get_job_status(self, job_id: str) -> dict[str, Any]:
        raw_job_id = self._resolve_job_id(job_id)
        return await self._job_status(raw_job_id)

    async def _job_status(self, raw_job_id: str) -> dict[str, Any]:
        job = self._status_reader.get_job(raw_job_id) if self._status_reader else None
        public_job_id = self._public_id("job", raw_job_id)
        if job is not None:
            return {
                "job_id": public_job_id,
                "status": job.status.value,
                "status_source": "queue",
                "completeness_status": None,
                "created_at": job.created_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            }
        try:
            report = await self.repository.get_report(raw_job_id, self.principal_id)
        except (FileNotFoundError, JobAccessError, OSError, ValueError):
            raise PublicResourceUnavailable() from None
        return {
            "job_id": public_job_id,
            "status": (
                "completed"
                if report and report.completeness.status == CompletenessStatus.COMPLETE
                else ("partial" if report else "unknown")
            ),
            "status_source": "report" if report else "repository",
            "completeness_status": report.completeness.status.value if report else "unknown",
            "report_id": self._public_id("report", report.id) if report else None,
            "completed_at": report.completed_at.isoformat() if report and report.completed_at else None,
        }

    def _resolve_job_id(self, supplied_id: str) -> str:
        if not self._valid_public_id("job", supplied_id):
            raise PublicResourceUnavailable()
        for raw_job_id in self.repository.list_job_ids(self.principal_id):
            if hmac.compare_digest(
                supplied_id,
                self._public_id("job", raw_job_id),
            ):
                return raw_job_id
        raise PublicResourceUnavailable()

    async def _resolve_report_id(
        self,
        raw_job_id: str,
        supplied_id: str | None,
    ) -> str | None:
        if supplied_id is None:
            return None
        if not self._valid_public_id("report", supplied_id):
            raise PublicResourceUnavailable()
        try:
            report_ids = await self.repository.list_report_ids(raw_job_id, self.principal_id)
        except (FileNotFoundError, JobAccessError, OSError, ValueError):
            raise PublicResourceUnavailable() from None
        for raw_report_id in report_ids:
            if hmac.compare_digest(
                supplied_id,
                self._public_id("report", raw_report_id),
            ):
                return raw_report_id
        raise PublicResourceUnavailable()

    def _public_id(self, kind: str, raw_id: str) -> str:
        return opaque_public_id(self._key, kind, raw_id)

    @staticmethod
    def _valid_public_id(kind: str, supplied_id: object) -> bool:
        if not isinstance(supplied_id, str):
            return False
        prefix = f"{kind}-"
        return supplied_id.startswith(prefix) and bool(
            _PUBLIC_TOKEN.fullmatch(supplied_id[len(prefix) :])
        )

    def _encode_cursor(self, state: dict[str, object]) -> str:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self._key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).rstrip(b"=").decode("ascii")

    def _decode_cursor(self, cursor: str) -> dict[str, object]:
        if not isinstance(cursor, str) or len(cursor) > _MAX_CURSOR_LENGTH:
            raise ValueError("cursor is malformed")
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            packed = base64.urlsafe_b64decode(padded.encode("ascii"))
            canonical = base64.urlsafe_b64encode(packed).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(cursor, canonical):
                raise ValueError("cursor encoding is not canonical")
            payload, signature = packed[:-32], packed[-32:]
            expected = hmac.new(self._key, payload, hashlib.sha256).digest()
            if len(signature) != 32 or not hmac.compare_digest(signature, expected):
                raise ValueError("cursor signature is invalid")
            state = json.loads(payload)
            if not isinstance(state, dict):
                raise ValueError("cursor payload is invalid")
            return state
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("cursor is malformed") from exc
