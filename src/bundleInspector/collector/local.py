"""
Local file collector.

Collects JavaScript files from local filesystem without network traffic.
"""

from __future__ import annotations

import hashlib
import logging
import mimetypes
from pathlib import Path
from typing import AsyncIterator, Optional

from bundleInspector.core.security import is_path_safe, sanitize_path
from bundleInspector.storage.models import JSAsset, AssetSource, LoadMethod

logger = logging.getLogger(__name__)


class LocalCollector:
    """
    Collect JS files from local filesystem.

    Supports single files, directories, and glob patterns.
    """

    # JavaScript file extensions
    JS_EXTENSIONS = {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'}

    # Additional extensions to check
    RELATED_EXTENSIONS = {'.map', '.json'}

    def __init__(
        self,
        include_source_maps: bool = True,
        include_json: bool = False,
        recursive: bool = True,
        max_file_size_mb: float = 10.0,
        allowed_bases: Optional[list[Path]] = None,
        allow_symlinks: bool = False,
    ):
        """
        Initialize local collector.

        Args:
            include_source_maps: Include .map files
            include_json: Include .json files (for configs)
            recursive: Recursively scan directories
            max_file_size_mb: Maximum file size to process
            allowed_bases: Base directories allowed for traversal (security)
            allow_symlinks: Whether to allow following symlinks
        """
        self.include_source_maps = include_source_maps
        self.include_json = include_json
        self.recursive = recursive
        self.max_file_size = int(max_file_size_mb * 1024 * 1024)
        self.allowed_bases = allowed_bases or []
        self.allow_symlinks = allow_symlinks

    def _validate_path(self, path: Path) -> bool:
        """
        Validate path against allowed bases (path traversal protection).

        Args:
            path: Path to validate

        Returns:
            True if path is safe, False otherwise
        """
        # If no allowed bases configured, allow any path (backwards compat)
        if not self.allowed_bases:
            return True

        is_safe, reason = is_path_safe(
            path,
            self.allowed_bases,
            allow_symlinks=self.allow_symlinks,
        )

        if not is_safe:
            logger.warning(
                f"Path traversal blocked: {path} - {reason}"
            )

        return is_safe

    def _should_include(self, path: Path) -> bool:
        """Check if file should be included."""
        suffix = path.suffix.lower()

        if suffix in self.JS_EXTENSIONS:
            return True
        if suffix == '.map' and self.include_source_maps:
            return True
        if suffix == '.json' and self.include_json:
            return True

        return False

    def _compute_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content).hexdigest()

    async def collect_file(self, file_path: Path) -> JSAsset | None:
        """
        Collect a single JS file.

        Args:
            file_path: Path to the file

        Returns:
            JSAsset or None if file should be skipped
        """
        if not file_path.exists():
            return None

        if not file_path.is_file():
            return None

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            return None

        if not self._should_include(file_path):
            return None

        try:
            content_bytes = file_path.read_bytes()

            # Create asset
            content_hash = self._compute_hash(content_bytes)

            # Use file:// URL scheme for local files
            file_url = file_path.absolute().as_uri()

            return JSAsset(
                id=f"local_{content_hash[:12]}",
                url=file_url,
                content=content_bytes,
                content_hash=content_hash,
                size=file_size,
                source=AssetSource.LOCAL,
                load_method=LoadMethod.LOCAL_FILE,
                initiator=str(file_path.parent),
                is_first_party=True,
            )

        except PermissionError as e:
            logger.warning(f"Permission denied reading {file_path}: {e}")
            return None
        except OSError as e:
            logger.warning(f"OS error reading {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error reading {file_path}: {e}")
            return None

    async def collect_directory(
        self,
        dir_path: Path,
    ) -> AsyncIterator[JSAsset]:
        """
        Collect JS files from a directory.

        Args:
            dir_path: Path to directory

        Yields:
            JSAsset for each JS file found
        """
        if not dir_path.exists() or not dir_path.is_dir():
            return

        # Validate directory path
        if not self._validate_path(dir_path):
            return

        pattern = '**/*' if self.recursive else '*'

        for file_path in dir_path.glob(pattern):
            # Validate each file path (protection against symlink attacks)
            if file_path.is_file() and self._validate_path(file_path):
                asset = await self.collect_file(file_path)
                if asset:
                    yield asset

    async def collect(
        self,
        paths: list[str | Path],
    ) -> AsyncIterator[JSAsset]:
        """
        Collect JS files from multiple paths.

        Args:
            paths: List of file or directory paths

        Yields:
            JSAsset for each JS file found
        """
        seen_hashes: set[str] = set()

        for path in paths:
            path = Path(path)

            # Path traversal protection
            if not self._validate_path(path):
                continue

            if path.is_file():
                asset = await self.collect_file(path)
                if asset and asset.content_hash not in seen_hashes:
                    seen_hashes.add(asset.content_hash)
                    yield asset

            elif path.is_dir():
                async for asset in self.collect_directory(path):
                    if asset.content_hash not in seen_hashes:
                        seen_hashes.add(asset.content_hash)
                        yield asset

            elif '*' in str(path):
                # Handle glob patterns
                path_str = str(path)
                prefix = path_str.split('*')[0]
                if prefix:
                    base_path = Path(prefix)
                    glob_pattern = path_str[len(str(base_path)):].lstrip('/\\')
                else:
                    base_path = Path('.')
                    glob_pattern = path_str

                # Validate base path of glob pattern
                if not self._validate_path(base_path):
                    continue

                if base_path.exists():
                    for file_path in base_path.glob(glob_pattern):
                        # Validate each matched file
                        if file_path.is_file() and self._validate_path(file_path):
                            asset = await self.collect_file(file_path)
                            if asset and asset.content_hash not in seen_hashes:
                                seen_hashes.add(asset.content_hash)
                                yield asset

            else:
                logger.warning(f"Path does not exist or is not accessible: {path}")


def is_local_path(path: str) -> bool:
    """
    Check if a path is a local filesystem path (not a URL).

    Args:
        path: Path or URL string

    Returns:
        True if local path, False if URL
    """
    # Check for URL schemes
    if path.startswith(('http://', 'https://', 'file://')):
        return path.startswith('file://')

    # Check if it looks like a path
    p = Path(path)

    # Windows absolute path (C:\...)
    if len(path) > 1 and path[1] == ':':
        return True

    # Unix absolute path (/...)
    if path.startswith('/'):
        return True

    # Relative path that exists
    if p.exists():
        return True

    # Contains path separators and no dots in first segment (likely not a domain)
    if ('/' in path or '\\' in path):
        first_segment = path.split('/')[0].split('\\')[0]
        if '.' not in first_segment:
            return True

    return False

