"""Principal-aware job/report lookup for public services."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from bundleInspector.storage.atomic import (
    atomic_create_or_validate_bytes,
    atomic_read_text,
    ensure_safe_directory,
    is_safe_regular_file,
    load_or_create_key,
)
from bundleInspector.storage.identifiers import (
    is_portable_component,
    is_reparse_path,
    validate_portable_component,
)
from bundleInspector.storage.models import Report

_PRINCIPAL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_REGISTRATION_INTENT_PREFIX = ".job-owner-intent."
_LEGACY_MARKERS: dict[str, str] = {
    "artifacts": "directory",
    "findings": "directory",
    "reports": "directory",
    "checkpoint.json": "file",
    ".checkpoint-key": "file",
}


class JobAccessError(PermissionError):
    """Raised when a principal does not own the requested job."""


class JobRepository:
    def __init__(self, base_path: Path):
        self.base_path = ensure_safe_directory(base_path)
        self._public_key_path = self.base_path / ".public-view-key"

    @property
    def public_signing_key(self) -> bytes:
        self._assert_plain_child(self._public_key_path, allow_missing=True)
        try:
            return load_or_create_key(self._public_key_path)
        except ValueError as exc:
            raise ValueError("invalid public cursor signing key") from exc

    def register_owner(self, job_id: str, principal_id: str) -> None:
        path = self._job_path(job_id)
        if not _PRINCIPAL_ID_RE.fullmatch(principal_id):
            raise ValueError("principal_id is invalid")
        intent_path = self._registration_intent_path(job_id)
        owner_path = path / ".owner"

        def validate_principal(payload: bytes, *, assigned_message: str) -> None:
            try:
                existing = payload.decode("utf-8").strip()
            except UnicodeDecodeError:
                raise JobAccessError(assigned_message) from None
            if not _PRINCIPAL_ID_RE.fullmatch(existing) or not hmac_compare(existing, principal_id):
                raise JobAccessError(assigned_message) from None

        def validate_owner(payload: bytes) -> None:
            validate_principal(payload, assigned_message="job ownership is already assigned")

        def validate_intent(payload: bytes) -> None:
            validate_principal(payload, assigned_message="job registration is already assigned")

        path_existed = self._path_entry_exists(path)
        if path_existed:
            if not path.is_dir():
                raise JobAccessError("job storage path is unavailable")
            self._assert_plain_child(owner_path, parent=path, allow_missing=True)
            if self._path_entry_exists(owner_path):
                if not owner_path.is_file():
                    raise JobAccessError("job ownership is already assigned")
                atomic_create_or_validate_bytes(
                    owner_path,
                    principal_id.encode("utf-8"),
                    validate_owner,
                )
                return
            if not self._path_entry_exists(intent_path):
                raise JobAccessError("pre-existing ownerless job storage cannot be adopted")

        self._assert_plain_child(intent_path, allow_missing=True)
        if self._path_entry_exists(intent_path) and not intent_path.is_file():
            raise JobAccessError("job registration is unavailable")
        atomic_create_or_validate_bytes(
            intent_path,
            principal_id.encode("utf-8"),
            validate_intent,
        )

        if not path_existed:
            try:
                path.mkdir(exist_ok=False)
            except FileExistsError:
                self._assert_plain_child(path)
                if not path.is_dir():
                    raise JobAccessError("job storage path is unavailable") from None
            self._assert_plain_child(path)

        self._assert_plain_child(owner_path, parent=path, allow_missing=True)

        atomic_create_or_validate_bytes(
            owner_path,
            principal_id.encode("utf-8"),
            validate_owner,
        )

    def prepare_job(
        self,
        job_id: str,
        principal_id: str,
        *,
        create: bool,
        allow_legacy: bool = False,
    ) -> tuple[Path | None, bool]:
        """Authorize or create a job before any mutating storage object is constructed.

        The boolean is true only for repository-owned jobs. Recognized ownerless legacy jobs may
        be returned for private compatibility, but are never assigned an owner by this method.
        """
        if create:
            try:
                self.register_owner(job_id, principal_id)
            except JobAccessError:
                if not allow_legacy:
                    raise
                return self._prepare_legacy_job(job_id), False
            return self.assert_access(job_id, principal_id), True

        try:
            return self.assert_access(job_id, principal_id), True
        except FileNotFoundError:
            return None, False
        except JobAccessError:
            if not allow_legacy:
                raise
            return self._prepare_legacy_job(job_id), False

    def assert_access(self, job_id: str, principal_id: str) -> Path:
        path = self._job_path(job_id)
        if not path.is_dir():
            raise FileNotFoundError(f"job not found: {job_id}")
        owner_path = path / ".owner"
        self._assert_plain_child(owner_path, parent=path, allow_missing=True)
        if not owner_path.is_file():
            raise JobAccessError("job ownership is unavailable")
        try:
            owner = atomic_read_text(owner_path).strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise JobAccessError("job ownership is unavailable") from exc
        if not _PRINCIPAL_ID_RE.fullmatch(owner) or not hmac_compare(owner, principal_id):
            raise JobAccessError("job is not accessible to this principal")
        return path

    def list_job_ids(self, principal_id: str) -> list[str]:
        jobs: list[tuple[float, str]] = []
        for path in self.base_path.iterdir():
            if not path.is_dir() or not is_portable_component(path.name):
                continue
            try:
                self.assert_access(path.name, principal_id)
            except (JobAccessError, FileNotFoundError, OSError):
                continue
            jobs.append((path.stat().st_mtime, path.name))
        jobs.sort(key=lambda item: (-item[0], item[1]))
        return [job_id for _, job_id in jobs]

    async def get_report(
        self,
        job_id: str,
        principal_id: str,
        report_id: str | None = None,
    ) -> Report | None:
        path = self.assert_access(job_id, principal_id)
        reports_path = path / "reports"
        self._assert_plain_child(reports_path, parent=path, allow_missing=True)
        if not reports_path.exists():
            return None
        self._assert_plain_child(reports_path, parent=path)
        if report_id is None:
            candidates = self._report_files(reports_path)
            if not candidates:
                return None
            report_id = max(candidates, key=lambda item: item.stat().st_mtime).stem
        validate_portable_component(report_id, label="report_id")
        report_path = reports_path / f"{report_id}.json"
        self._assert_plain_child(report_path, parent=reports_path, allow_missing=True)
        if not report_path.is_file():
            return None
        try:
            payload = await asyncio.to_thread(atomic_read_text, report_path)
        except FileNotFoundError:
            return None
        report = Report.model_validate_json(payload)
        if report.id != report_id or report.job_id != job_id:
            raise ValueError("stored report identity does not match its repository path")
        return report

    async def list_report_ids(self, job_id: str, principal_id: str) -> list[str]:
        """List safe report IDs without following report-directory or file links."""
        path = self.assert_access(job_id, principal_id)
        reports_path = path / "reports"
        self._assert_plain_child(reports_path, parent=path, allow_missing=True)
        if not reports_path.exists():
            return []
        self._assert_plain_child(reports_path, parent=path)
        return sorted(item.stem for item in self._report_files(reports_path))

    def _job_path(self, job_id: str) -> Path:
        validate_portable_component(job_id, label="job_id")
        path = self.base_path / job_id
        self._assert_plain_child(path, allow_missing=True)
        return path

    def _registration_intent_path(self, job_id: str) -> Path:
        path = self.base_path / f"{_REGISTRATION_INTENT_PREFIX}{job_id}"
        self._assert_plain_child(path, allow_missing=True)
        return path

    def _prepare_legacy_job(self, job_id: str) -> Path:
        path = self._job_path(job_id)
        owner_path = path / ".owner"
        intent_path = self._registration_intent_path(job_id)
        try:
            self._assert_plain_child(path)
            if not path.is_dir():
                raise ValueError("legacy job path is not a directory")
            self._assert_plain_child(owner_path, parent=path, allow_missing=True)
            if self._path_entry_exists(owner_path):
                raise ValueError("legacy job has an ownership record")
            self._assert_plain_child(intent_path, allow_missing=True)
            if self._path_entry_exists(intent_path):
                raise ValueError("legacy job has an active ownership registration")

            recognized = False
            for name, expected_kind in _LEGACY_MARKERS.items():
                marker = path / name
                if not self._path_entry_exists(marker):
                    continue
                recognized = True
                self._assert_plain_child(marker, parent=path)
                if expected_kind == "directory" and not marker.is_dir():
                    raise ValueError(f"legacy marker is not a directory: {name}")
                if expected_kind == "file" and not marker.is_file():
                    raise ValueError(f"legacy marker is not a file: {name}")
            if not recognized:
                raise ValueError("ownerless job storage is not a recognized legacy cache")

            artifacts_path = path / "artifacts"
            if artifacts_path.is_dir():
                for name in ("js", "ast", "sourcemap", "meta"):
                    child = artifacts_path / name
                    if not self._path_entry_exists(child):
                        continue
                    self._assert_plain_child(child, parent=artifacts_path)
                    if not child.is_dir():
                        raise ValueError(f"legacy artifact path is not a directory: {name}")
        except (OSError, ValueError) as exc:
            raise JobAccessError("legacy job storage is unsafe") from exc
        return path

    @staticmethod
    def _path_entry_exists(path: Path) -> bool:
        return path.exists() or is_reparse_path(path)

    def _report_files(self, reports_path: Path) -> list[Path]:
        files: list[Path] = []
        for item in reports_path.iterdir():
            if item.suffix != ".json" or not is_portable_component(item.stem):
                continue
            try:
                self._assert_plain_child(item, parent=reports_path)
            except ValueError:
                continue
            if is_safe_regular_file(item):
                files.append(item)
        return files

    def _assert_plain_child(
        self,
        path: Path,
        *,
        parent: Path | None = None,
        allow_missing: bool = False,
    ) -> None:
        """Reject links/junctions and paths resolving outside their expected parent."""
        expected_parent = (parent or self.base_path).resolve()
        if not allow_missing and not path.exists():
            raise ValueError("repository path is unavailable")
        if is_reparse_path(path):
            raise ValueError("repository links are not allowed")
        if path.resolve(strict=False).parent != expected_parent:
            raise ValueError("repository path escapes its parent")


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time principal comparison without exposing repository internals."""
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
