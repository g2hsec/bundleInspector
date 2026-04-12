"""
Artifact storage for JS files and ASTs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

import aiofiles

from bundleInspector.storage.models import JSAsset


class ArtifactStore:
    """
    Store for JS artifacts (files, ASTs, source maps).

    Uses content-addressable storage based on SHA-256 hashes.
    """

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self._js_path = base_path / "js"
        self._ast_path = base_path / "ast"
        self._sourcemap_path = base_path / "sourcemap"
        self._meta_path = base_path / "meta"

        # Create directories
        for path in [self._js_path, self._ast_path, self._sourcemap_path, self._meta_path]:
            path.mkdir(parents=True, exist_ok=True)

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

        is_new = not file_path.exists()

        if is_new:
            async with aiofiles.open(file_path, "wb") as f:
                await f.write(content)

        return content_hash, is_new

    async def get_js(self, content_hash: str) -> Optional[bytes]:
        """Get JS content by hash."""
        file_path = self._js_path / f"{content_hash}.js"

        if not file_path.exists():
            return None

        async with aiofiles.open(file_path, "rb") as f:
            return await f.read()

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
        ast_json = json.dumps(ast, separators=(",", ":"), sort_keys=True)
        ast_hash = hashlib.sha256(ast_json.encode()).hexdigest()[:16]

        file_path = self._ast_path / f"{content_hash}_{ast_hash}.json"

        async with aiofiles.open(file_path, "w") as f:
            await f.write(ast_json)

        return ast_hash

    async def get_ast(
        self,
        content_hash: str,
        ast_hash: str,
    ) -> Optional[dict]:
        """Get AST by hash."""
        file_path = self._ast_path / f"{content_hash}_{ast_hash}.json"

        if not file_path.exists():
            return None

        async with aiofiles.open(file_path, "r") as f:
            content = await f.read()
            return json.loads(content)

    async def store_sourcemap(
        self,
        content: bytes,
        js_hash: str,
    ) -> str:
        """Store source map."""
        sm_hash = hashlib.sha256(content).hexdigest()[:16]
        file_path = self._sourcemap_path / f"{js_hash}_{sm_hash}.map"

        async with aiofiles.open(file_path, "wb") as f:
            await f.write(content)

        return sm_hash

    async def get_sourcemap(
        self,
        js_hash: str,
        sm_hash: str,
    ) -> Optional[bytes]:
        """Get source map content by JS hash and source map hash."""
        file_path = self._sourcemap_path / f"{js_hash}_{sm_hash}.map"

        if not file_path.exists():
            return None

        async with aiofiles.open(file_path, "rb") as f:
            return await f.read()

    async def store_asset_meta(self, asset: JSAsset) -> None:
        """Store asset metadata."""
        if not asset.content_hash:
            asset.compute_hash()
        file_path = self._meta_path / f"{asset.content_hash}.json"

        # Don't include raw content in metadata
        data = asset.model_dump(mode="json", exclude={"content", "sourcemap_content"})

        async with aiofiles.open(file_path, "w") as f:
            await f.write(json.dumps(data, indent=2))

    async def get_asset_meta(self, content_hash: str) -> Optional[JSAsset]:
        """Get asset metadata."""
        file_path = self._meta_path / f"{content_hash}.json"

        if not file_path.exists():
            return None

        async with aiofiles.open(file_path, "r") as f:
            data = json.loads(await f.read())
            return JSAsset.model_validate(data)

    def has_js(self, content_hash: str) -> bool:
        """Check if JS exists."""
        return (self._js_path / f"{content_hash}.js").exists()

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

        for path in [self._js_path, self._ast_path, self._sourcemap_path, self._meta_path]:
            for file in path.iterdir():
                if file.is_file():
                    age = now - file.stat().st_mtime
                    if age > max_age:
                        file.unlink()
                        deleted += 1

        return deleted

