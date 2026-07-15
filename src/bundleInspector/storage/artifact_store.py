"""
Artifact storage for JS files and ASTs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bundleInspector.reporter.redaction import redact_tree
from bundleInspector.storage.atomic import (
    UnsafePathError,
    atomic_create_or_refresh_bytes,
    atomic_read_bytes,
    atomic_read_text,
    atomic_unlink_if,
    atomic_update_bytes,
    atomic_write_bytes,
    atomic_write_text,
    load_or_create_key,
)
from bundleInspector.storage.identifiers import is_reparse_path
from bundleInspector.storage.models import JSAsset

# A content-addressable hash used as a path component must be plain lowercase hex, so a tampered
# checkpoint hash like "../../../etc/hosts" can never traverse outside the cache directory.
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_DERIVED_HASH_RE = re.compile(r"[0-9a-f]{16}\Z")
_SEALED_MAGIC = b"BIC1"
_SEALED_MIN_SIZE = len(_SEALED_MAGIC) + 12 + 16


def _safe_sha256(*hashes: str) -> bool:
    """True only if every value is an exact lowercase SHA-256 hex digest."""
    return all(isinstance(value, str) and _SHA256_RE.fullmatch(value) for value in hashes)


def _safe_derived_hash(*hashes: str) -> bool:
    """True only if every value is an exact lowercase 16-hex derived digest."""
    return all(isinstance(value, str) and _DERIVED_HASH_RE.fullmatch(value) for value in hashes)


def _plain_directory(
    path: Path,
    *,
    expected_parent: Path | None = None,
    create_parents: bool = False,
) -> Path:
    """Create and return a resolved directory without accepting links or junctions."""
    if is_reparse_path(path):
        raise ValueError(f"artifact storage directory links are not allowed: {path.name}")
    try:
        path.mkdir(parents=create_parents, exist_ok=True)
    except FileExistsError as exc:
        raise ValueError(f"artifact storage path is not a directory: {path.name}") from exc
    if is_reparse_path(path) or not path.is_dir():
        raise ValueError(f"artifact storage path is not a plain directory: {path.name}")
    resolved = path.resolve(strict=True)
    if expected_parent is not None and resolved.parent != expected_parent:
        raise ValueError(f"artifact storage directory escapes its parent: {path.name}")
    return resolved


def _validate_js_payload(path: Path, payload: bytes) -> None:
    expected_hash = path.stem
    if len(expected_hash) != 64 or hashlib.sha256(payload).hexdigest() != expected_hash:
        raise ValueError(f"JS cache content hash mismatch: {path.name}")


def _decode_validated_ast(path: Path, payload: bytes) -> dict[str, Any]:
    content_hash, separator, ast_hash = path.stem.rpartition("_")
    if (
        not separator
        or len(ast_hash) != 16
        or not _safe_sha256(content_hash)
        or not _safe_derived_hash(ast_hash)
    ):
        raise ValueError(f"invalid AST cache filename: {path.name}")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid AST cache payload: {path.name}") from exc
    if not isinstance(decoded, dict):
        raise ValueError("stored AST is not an object")
    canonical = json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest()[:16] != ast_hash:
        raise ValueError(f"AST cache content hash mismatch: {path.name}")
    return cast(dict[str, Any], decoded)


def _validate_sourcemap_payload(path: Path, payload: bytes) -> None:
    js_hash, separator, sm_hash = path.stem.rpartition("_")
    if (
        not separator
        or len(sm_hash) != 16
        or not _safe_sha256(js_hash)
        or not _safe_derived_hash(sm_hash)
        or hashlib.sha256(payload).hexdigest()[:16] != sm_hash
    ):
        raise ValueError(f"source map cache content hash mismatch: {path.name}")


class ArtifactStore:
    """
    Store for JS artifacts (files, ASTs, source maps).

    Uses content-addressable storage based on SHA-256 hashes.
    """

    def __init__(self, base_path: Path):
        self.base_path = _plain_directory(base_path, create_parents=True)
        self._js_path = _plain_directory(self.base_path / "js", expected_parent=self.base_path)
        self._ast_path = _plain_directory(self.base_path / "ast", expected_parent=self.base_path)
        self._sourcemap_path = _plain_directory(
            self.base_path / "sourcemap",
            expected_parent=self.base_path,
        )
        self._meta_path = _plain_directory(self.base_path / "meta", expected_parent=self.base_path)
        self._key_path = self.base_path / ".artifact-key"

        self._cipher = AESGCM(self._load_or_create_key())
        self._migrate_plaintext_cache()

    def _load_or_create_key(self) -> bytes:
        try:
            return load_or_create_key(self._key_path)
        except ValueError as exc:
            raise ValueError("invalid artifact encryption key") from exc

    def _seal(self, path: Path, payload: bytes) -> bytes:
        nonce = os.urandom(12)
        return _SEALED_MAGIC + nonce + self._cipher.encrypt(nonce, payload, path.name.encode())

    def _open(self, path: Path, payload: bytes) -> bytes:
        if not payload.startswith(_SEALED_MAGIC) or len(payload) < _SEALED_MIN_SIZE:
            raise ValueError(f"unsealed artifact cache entry: {path.name}")
        nonce_start = len(_SEALED_MAGIC)
        nonce = payload[nonce_start:nonce_start + 12]
        ciphertext = payload[nonce_start + 12:]
        return self._cipher.decrypt(nonce, ciphertext, path.name.encode())

    def _migrate_plaintext_cache(self) -> None:
        """Seal legacy cache entries before the store can expose or reuse them."""
        cache_kinds: tuple[
            tuple[Path, set[str], Callable[[Path, bytes], object]],
            ...,
        ] = (
            (self._js_path, {".js"}, _validate_js_payload),
            (self._ast_path, {".json"}, _decode_validated_ast),
            (self._sourcemap_path, {".map"}, _validate_sourcemap_payload),
        )
        for directory, suffixes, validator in cache_kinds:
            for path in directory.iterdir():
                if not path.is_file() or path.suffix not in suffixes:
                    continue

                def migrate(
                    payload: bytes,
                    target: Path = path,
                    validate: Callable[[Path, bytes], object] = validator,
                ) -> bytes | None:
                    if payload.startswith(_SEALED_MAGIC) and len(payload) >= _SEALED_MIN_SIZE:
                        try:
                            opened = self._open(target, payload)
                        except InvalidTag as sealed_error:
                            try:
                                validate(target, payload)
                            except ValueError:
                                raise sealed_error from None
                        else:
                            validate(target, opened)
                            return None
                    else:
                        validate(target, payload)
                    return self._seal(target, payload)

                try:
                    atomic_update_bytes(path, migrate)
                except FileNotFoundError:
                    # A cooperative cleanup may evict an entry found by iterdir().
                    continue
                except UnsafePathError:
                    # Enumeration never follows or migrates candidates rejected by the common
                    # link, regular-file, link-count and identity boundary.
                    continue

    async def store_js(
        self,
        content: bytes,
        url: str,
    ) -> tuple[str, bool]:
        """
        Store JS content.

        Args:
            content: JS file content
            url: Original URL

        Returns:
            (content_hash, is_new)
        """
        content_hash = hashlib.sha256(content).hexdigest()
        file_path = self._js_path / f"{content_hash}.js"

        sealed = self._seal(file_path, content)

        def validate_existing(payload: bytes) -> None:
            opened = self._open(file_path, payload)
            _validate_js_payload(file_path, opened)

        is_new = await asyncio.to_thread(
            atomic_create_or_refresh_bytes,
            file_path,
            sealed,
            validate_existing,
        )

        return content_hash, is_new

    async def get_js(self, content_hash: str) -> bytes | None:
        """Get JS content by hash."""
        if not _safe_sha256(content_hash):
            return None
        file_path = self._js_path / f"{content_hash}.js"

        try:
            payload = await asyncio.to_thread(atomic_read_bytes, file_path)
        except FileNotFoundError:
            return None
        content = self._open(file_path, payload)
        _validate_js_payload(file_path, content)
        return content

    async def store_ast(
        self,
        ast: dict,
        content_hash: str,
    ) -> str:
        """
        Store parsed AST.

        Args:
            ast: AST dictionary
            content_hash: Hash of original JS

        Returns:
            AST hash
        """
        if not _safe_sha256(content_hash):
            raise ValueError("unsafe content_hash for AST storage path")
        ast_json = json.dumps(ast, separators=(",", ":"), sort_keys=True)
        ast_hash = hashlib.sha256(ast_json.encode()).hexdigest()[:16]

        file_path = self._ast_path / f"{content_hash}_{ast_hash}.json"

        await asyncio.to_thread(
            atomic_write_bytes,
            file_path,
            self._seal(file_path, ast_json.encode("utf-8")),
        )

        return ast_hash

    async def get_ast(
        self,
        content_hash: str,
        ast_hash: str,
    ) -> dict | None:
        """Get AST by hash."""
        if not _safe_sha256(content_hash) or not _safe_derived_hash(ast_hash):
            return None
        file_path = self._ast_path / f"{content_hash}_{ast_hash}.json"

        try:
            payload = await asyncio.to_thread(atomic_read_bytes, file_path)
        except FileNotFoundError:
            return None
        content = self._open(file_path, payload)
        return _decode_validated_ast(file_path, content)

    async def store_sourcemap(
        self,
        content: bytes,
        js_hash: str,
    ) -> str:
        """Store source map."""
        if not _safe_sha256(js_hash):
            raise ValueError("unsafe js_hash for sourcemap storage path")
        sm_hash = hashlib.sha256(content).hexdigest()[:16]
        file_path = self._sourcemap_path / f"{js_hash}_{sm_hash}.map"

        await asyncio.to_thread(
            atomic_write_bytes,
            file_path,
            self._seal(file_path, content),
        )

        return sm_hash

    async def get_sourcemap(
        self,
        js_hash: str,
        sm_hash: str,
    ) -> bytes | None:
        """Get source map content by JS hash and source map hash."""
        if not _safe_sha256(js_hash) or not _safe_derived_hash(sm_hash):
            return None
        file_path = self._sourcemap_path / f"{js_hash}_{sm_hash}.map"

        try:
            payload = await asyncio.to_thread(atomic_read_bytes, file_path)
        except FileNotFoundError:
            return None
        content = self._open(file_path, payload)
        _validate_sourcemap_payload(file_path, content)
        return content

    async def store_asset_meta(self, asset: JSAsset) -> None:
        """Store asset metadata."""
        if not asset.content_hash:
            asset.compute_hash()
        if not _safe_sha256(asset.content_hash):
            raise ValueError("asset metadata content_hash must be a lowercase SHA-256 digest")

        current_hash = hashlib.sha256(asset.content).hexdigest()
        if asset.normalized_hash is None:
            if current_hash != asset.content_hash:
                raise ValueError("asset metadata content_hash does not match content")
        else:
            if not _safe_sha256(asset.normalized_hash):
                raise ValueError("asset metadata normalized_hash must be a lowercase SHA-256 digest")
            if current_hash != asset.normalized_hash:
                raise ValueError("asset metadata normalized_hash does not match content")
            if asset.normalized_hash != asset.content_hash and not self.has_js(asset.content_hash):
                raise ValueError("asset metadata original content_hash has no valid JS cache entry")

        file_path = self._meta_path / f"{asset.content_hash}.json"

        # Don't include raw content in metadata
        data = redact_tree(
            asset.model_dump(mode="json", exclude={"content", "sourcemap_content"}),
        )
        await asyncio.to_thread(
            atomic_write_text,
            file_path,
            json.dumps(data, indent=2),
        )

    async def get_asset_meta(self, content_hash: str) -> JSAsset | None:
        """Get asset metadata."""
        if not _safe_sha256(content_hash):
            return None
        file_path = self._meta_path / f"{content_hash}.json"

        try:
            payload = await asyncio.to_thread(atomic_read_text, file_path)
        except FileNotFoundError:
            return None
        return JSAsset.model_validate_json(payload)

    def has_js(self, content_hash: str) -> bool:
        """Return a locked point-in-time check that a valid JS cache entry exists."""
        if not _safe_sha256(content_hash):
            return False
        file_path = self._js_path / f"{content_hash}.js"
        try:
            payload = atomic_read_bytes(file_path)
            content = self._open(file_path, payload)
            _validate_js_payload(file_path, content)
        except (FileNotFoundError, UnsafePathError, InvalidTag, ValueError):
            return False
        return True

    async def cleanup(self, max_age_days: int = 7) -> int:
        """
        Clean up old artifacts.

        Args:
            max_age_days: Max age in days

        Returns:
            Number of files deleted
        """
        import time

        now = time.time()
        max_age = max_age_days * 24 * 60 * 60
        deleted = 0

        payload_suffixes = {
            self._js_path: {".js"},
            self._ast_path: {".json"},
            self._sourcemap_path: {".map"},
            self._meta_path: {".json"},
        }
        for path, suffixes in payload_suffixes.items():
            for file in path.iterdir():
                if file.is_file() and file.suffix in suffixes:
                    try:
                        was_deleted = await asyncio.to_thread(
                            atomic_unlink_if,
                            file,
                            lambda current: now - current.st_mtime > max_age,
                        )
                    except UnsafePathError:
                        continue
                    deleted += int(was_deleted)

        return deleted
