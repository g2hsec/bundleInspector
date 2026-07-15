"""
Finding storage.
"""

from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bundleInspector.reporter.redaction import (
    sanitize_finding_copy,
    sanitize_report_copy,
)
from bundleInspector.storage.atomic import (
    UnsafePathError,
    atomic_read_text,
    atomic_update_bytes,
    atomic_write_bytes,
    atomic_write_text,
    ensure_safe_directory,
    is_safe_regular_file,
    load_or_create_key,
)
from bundleInspector.storage.identifiers import (
    is_portable_component,
    validate_portable_component,
)
from bundleInspector.storage.models import Finding, PipelineCheckpoint, Report

_CHECKPOINT_MAGIC = b"BICP1"


class FindingStore:
    """
    Store for findings and reports.
    """

    def __init__(self, base_path: Path):
        self.base_path = ensure_safe_directory(base_path)
        self._findings_path = self.base_path / "findings"
        self._reports_path = self.base_path / "reports"
        self._checkpoint_path = self.base_path / "checkpoint.json"
        self._checkpoint_key_path = self.base_path / ".checkpoint-key"
        # Serialize concurrent checkpoint writers (overlapping background progress
        # tasks) so they can't interleave into a torn/corrupt file.
        self._checkpoint_lock = asyncio.Lock()

        resolved_base = self.base_path
        for path in [self._findings_path, self._reports_path]:
            resolved_child = ensure_safe_directory(path)
            if resolved_child.parent != resolved_base:
                raise UnsafePathError(
                    errno.EINVAL,
                    "storage directory escaped the finding-store base path",
                    str(path),
                )

    async def store_finding(self, finding: Finding) -> None:
        """Store a finding."""
        validate_portable_component(finding.id, label="finding id")
        file_path = self._findings_path / f"{finding.id}.json"
        sanitized = sanitize_finding_copy(finding)
        await asyncio.to_thread(atomic_write_text, file_path, sanitized.model_dump_json(indent=2))

    async def get_finding(self, finding_id: str) -> Finding | None:
        """Get a finding by ID."""
        if not is_portable_component(finding_id):
            return None
        file_path = self._findings_path / f"{finding_id}.json"

        try:
            payload = await asyncio.to_thread(atomic_read_text, file_path)
        except FileNotFoundError:
            return None
        finding = Finding.model_validate_json(payload)
        if finding.id != finding_id:
            raise ValueError("stored finding identity does not match its path")
        return finding

    async def store_report(self, report: Report) -> Path:
        """
        Store a report.

        Returns:
            Path to stored report
        """
        validate_portable_component(report.id, label="report id")
        file_path = self._reports_path / f"{report.id}.json"
        sanitized = sanitize_report_copy(report)
        payload = sanitized.model_dump_json(
            indent=2,
            exclude={"assets": {"__all__": {"content", "sourcemap_content"}}},
        )
        await asyncio.to_thread(atomic_write_text, file_path, payload)

        return file_path

    async def get_report(self, report_id: str) -> Report | None:
        """Get a report by ID."""
        if not is_portable_component(report_id):
            return None
        file_path = self._reports_path / f"{report_id}.json"

        try:
            payload = await asyncio.to_thread(atomic_read_text, file_path)
        except FileNotFoundError:
            return None
        report = Report.model_validate_json(payload)
        if report.id != report_id:
            raise ValueError("stored report identity does not match its path")
        return report

    async def list_reports(self) -> list[str]:
        """List all report IDs."""
        return [
            f.stem for f in self._reports_path.iterdir()
            if (
                f.suffix == ".json"
                and is_portable_component(f.stem)
                and is_safe_regular_file(f)
            )
        ]

    async def get_latest_report(self) -> Report | None:
        """Get the most recently written report for this job."""
        report_files = [
            f for f in self._reports_path.iterdir()
            if (
                f.suffix == ".json"
                and is_portable_component(f.stem)
                and is_safe_regular_file(f)
            )
        ]
        if not report_files:
            return None

        latest = max(report_files, key=lambda f: f.lstat().st_mtime)
        try:
            payload = await asyncio.to_thread(atomic_read_text, latest)
        except FileNotFoundError:
            return None
        report = Report.model_validate_json(payload)
        if report.id != latest.stem:
            raise ValueError("stored report identity does not match its path")
        return report

    async def store_checkpoint(self, checkpoint: PipelineCheckpoint) -> Path:
        """Store a pipeline checkpoint for stage resume.

        Writes to a temp file then atomically renames it into place, so a reader
        (or a `--resume` on the next run) never observes a half-written file, and
        the lock prevents concurrent writers from corrupting the temp file.
        """
        payload = checkpoint.model_dump_json(indent=2).encode("utf-8")
        async with self._checkpoint_lock:
            sealed = await asyncio.to_thread(self._seal_checkpoint, payload)
            await asyncio.to_thread(atomic_write_bytes, self._checkpoint_path, sealed)
        return self._checkpoint_path

    async def get_checkpoint(self) -> PipelineCheckpoint | None:
        """Load a stored pipeline checkpoint if present."""
        try:
            await asyncio.to_thread(self._checkpoint_path.lstat)
        except FileNotFoundError:
            return None
        if not await asyncio.to_thread(is_safe_regular_file, self._checkpoint_path):
            raise UnsafePathError(
                errno.EINVAL,
                "unsafe checkpoint persistent file",
                str(self._checkpoint_path),
            )
        cipher = await asyncio.to_thread(self._checkpoint_cipher)

        def migrate_legacy(payload: bytes) -> bytes | None:
            if payload.startswith(_CHECKPOINT_MAGIC):
                return None
            # Validate before sealing so corrupt data is never legitimized as a checkpoint.
            PipelineCheckpoint.model_validate_json(payload)
            return self._seal_checkpoint_with_cipher(payload, cipher)

        try:
            payload = await asyncio.to_thread(
                atomic_update_bytes,
                self._checkpoint_path,
                migrate_legacy,
            )
        except FileNotFoundError:
            return None
        decoded = await asyncio.to_thread(self._open_checkpoint_with_cipher, payload, cipher)
        return PipelineCheckpoint.model_validate_json(decoded)

    def _load_or_create_checkpoint_key(self) -> bytes:
        try:
            return load_or_create_key(self._checkpoint_key_path)
        except ValueError as exc:
            raise ValueError("invalid checkpoint encryption key") from exc

    def _checkpoint_cipher(self) -> AESGCM:
        return AESGCM(self._load_or_create_checkpoint_key())

    def _seal_checkpoint(self, payload: bytes) -> bytes:
        return self._seal_checkpoint_with_cipher(payload, self._checkpoint_cipher())

    def _seal_checkpoint_with_cipher(self, payload: bytes, cipher: AESGCM) -> bytes:
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, payload, self._checkpoint_path.name.encode("ascii"))
        return _CHECKPOINT_MAGIC + nonce + ciphertext

    def _open_checkpoint(self, payload: bytes) -> bytes:
        return self._open_checkpoint_with_cipher(payload, self._checkpoint_cipher())

    def _open_checkpoint_with_cipher(self, payload: bytes, cipher: AESGCM) -> bytes:
        minimum_size = len(_CHECKPOINT_MAGIC) + 12 + 16
        if len(payload) < minimum_size:
            raise ValueError("invalid sealed checkpoint")
        nonce_start = len(_CHECKPOINT_MAGIC)
        nonce = payload[nonce_start:nonce_start + 12]
        ciphertext = payload[nonce_start + 12:]
        return cipher.decrypt(nonce, ciphertext, self._checkpoint_path.name.encode("ascii"))
