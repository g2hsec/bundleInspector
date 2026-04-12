"""Tests for local file collector."""

import uuid
from pathlib import Path

import pytest

from bundleInspector.collector.local import LocalCollector, is_local_path

TEST_TMP_ROOT = Path(".tmp_test_artifacts")
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _make_test_path(name: str) -> Path:
    """Create a unique path under the workspace-local sandbox."""
    return TEST_TMP_ROOT / f"{uuid.uuid4().hex}_{name}"


class TestLocalCollector:
    """Tests for LocalCollector."""

    @pytest.fixture
    def temp_js_file(self):
        """Create a temporary JS file."""
        file_path = _make_test_path("hello.js")
        file_path.write_text('const hello = "world";', encoding="utf-8")
        return file_path

    @pytest.fixture
    def temp_dir_with_js(self):
        """Create a temporary directory with JS files."""
        tmppath = _make_test_path("dir")
        tmppath.mkdir(parents=True, exist_ok=True)

        # Create some JS files
        (tmppath / "app.js").write_text('const app = {};', encoding="utf-8")
        (tmppath / "util.ts").write_text('export const util = {};', encoding="utf-8")
        (tmppath / "style.css").write_text('.foo {}', encoding="utf-8")

        # Create subdirectory
        subdir = tmppath / "lib"
        subdir.mkdir()
        (subdir / "helper.js").write_text('function help() {}', encoding="utf-8")

        return tmppath

    @pytest.mark.asyncio
    async def test_collect_single_file(self, temp_js_file):
        """Test collecting a single JS file."""
        collector = LocalCollector()

        assets = []
        async for asset in collector.collect([str(temp_js_file)]):
            assets.append(asset)

        assert len(assets) == 1
        assert assets[0].content == b'const hello = "world";'
        assert assets[0].is_first_party is True

    @pytest.mark.asyncio
    async def test_collect_directory_recursive(self, temp_dir_with_js):
        """Test collecting from directory recursively."""
        collector = LocalCollector(recursive=True)

        assets = []
        async for asset in collector.collect([str(temp_dir_with_js)]):
            assets.append(asset)

        # Should find app.js, util.ts, and lib/helper.js (not style.css)
        assert len(assets) == 3
        urls = [a.url for a in assets]
        assert any("app.js" in u for u in urls)
        assert any("util.ts" in u for u in urls)
        assert any("helper.js" in u for u in urls)
        assert not any("style.css" in u for u in urls)

    @pytest.mark.asyncio
    async def test_collect_directory_non_recursive(self, temp_dir_with_js):
        """Test collecting from directory non-recursively."""
        collector = LocalCollector(recursive=False)

        assets = []
        async for asset in collector.collect([str(temp_dir_with_js)]):
            assets.append(asset)

        # Should find app.js and util.ts (not lib/helper.js)
        assert len(assets) == 2
        urls = [a.url for a in assets]
        assert any("app.js" in u for u in urls)
        assert not any("helper.js" in u for u in urls)

    @pytest.mark.asyncio
    async def test_include_json(self, temp_dir_with_js):
        """Test including JSON files."""
        # Add a JSON file
        (temp_dir_with_js / "package.json").write_text('{"name": "test"}')

        collector = LocalCollector(include_json=True)

        assets = []
        async for asset in collector.collect([str(temp_dir_with_js)]):
            assets.append(asset)

        # Should include the JSON file
        urls = [a.url for a in assets]
        assert any("package.json" in u for u in urls)

    @pytest.mark.asyncio
    async def test_dedup_by_hash(self, temp_dir_with_js):
        """Test deduplication by content hash."""
        # Create duplicate content
        (temp_dir_with_js / "copy.js").write_text('const app = {};', encoding="utf-8")  # Same as app.js

        collector = LocalCollector()

        assets = []
        async for asset in collector.collect([str(temp_dir_with_js)]):
            assets.append(asset)

        # Should deduplicate identical content
        hashes = [a.content_hash for a in assets]
        assert len(hashes) == len(set(hashes))

    @pytest.mark.asyncio
    async def test_skip_large_files(self):
        """Test skipping files that exceed size limit."""
        large_file = _make_test_path("large.js")
        large_file.write_text('x' * (11 * 1024 * 1024), encoding="utf-8")

        collector = LocalCollector(max_file_size_mb=10.0)

        assets = []
        async for asset in collector.collect([str(large_file)]):
            assets.append(asset)

        # Should skip the large file
        assert len(assets) == 0

    @pytest.mark.asyncio
    async def test_content_hash(self, temp_js_file):
        """Test that content hash is computed correctly."""
        collector = LocalCollector()

        assets = []
        async for asset in collector.collect([str(temp_js_file)]):
            assets.append(asset)

        assert len(assets) == 1
        assert assets[0].content_hash is not None
        assert len(assets[0].content_hash) == 64  # SHA-256 hex length


class TestIsLocalPath:
    """Tests for is_local_path function."""

    def test_http_url(self):
        """Test HTTP URLs are not local paths."""
        assert not is_local_path("http://example.com/app.js")
        assert not is_local_path("https://example.com/app.js")

    def test_file_url(self):
        """Test file:// URLs are local paths."""
        assert is_local_path("file:///home/user/app.js")

    def test_unix_absolute_path(self):
        """Test Unix absolute paths."""
        assert is_local_path("/home/user/app.js")
        assert is_local_path("/var/www/js/")

    def test_windows_absolute_path(self):
        """Test Windows absolute paths."""
        assert is_local_path("C:\\Users\\test\\app.js")
        assert is_local_path("D:\\projects\\js\\")

    def test_relative_path(self):
        """Test relative paths that exist."""
        # This depends on current directory having some file
        # Use a path that likely exists
        assert is_local_path("./")

    def test_path_with_separators(self):
        """Test paths with separators but no dots."""
        assert is_local_path("src/app/main")
        assert is_local_path("lib\\utils\\helper")

