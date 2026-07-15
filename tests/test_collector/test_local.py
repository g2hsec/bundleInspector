"""Tests for local file collector."""

import uuid
from pathlib import Path

import pytest

from bundleInspector.collector.local import LocalCollector, is_local_path
from bundleInspector.storage.models import JSAsset

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
        assert {
            (item.code, item.reason, item.affected_count)
            for item in collector.diagnostics
        } == {("local_file_oversized", "file_size_limit", 1)}

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



async def test_glob_wildcard_in_filename_collects_matching_files(tmp_path):
    """A wildcard INSIDE a filename (`vendor*.js`) must collect the matching files -- the glob base
    was mis-computed as a partial filename that is not a directory, so nothing was collected."""
    (tmp_path / "vendor-a.js").write_text('fetch("/a");')
    (tmp_path / "vendor-b.js").write_text('fetch("/b");')
    (tmp_path / "other.js").write_text('fetch("/c");')
    names = sorted([a.url.rsplit("/", 1)[-1]
                    async for a in LocalCollector().collect([str(tmp_path / "vendor*.js")])])
    assert "vendor-a.js" in names and "vendor-b.js" in names
    assert "other.js" not in names


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "expected_hint"),
    [
        ("module.mts", "typescript"),
        ("module.cts", "typescript"),
        ("component.tsx", "tsx"),
        ("component.jsx", "jsx"),
        ("module.mjs", "javascript"),
    ],
)
async def test_language_extensions_are_collected_with_explicit_grammar(
    tmp_path, name, expected_hint
):
    path = tmp_path / name
    path.write_text(f'fetch("/api/{name}");', encoding="utf-8")

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert len(assets) == 1
    assert assets[0].language_hint == expected_hint


@pytest.mark.asyncio
async def test_component_markup_is_not_analyzed_and_supported_script_is_virtualized(tmp_path):
    component = tmp_path / "Account.vue"
    component.write_text(
        """
        <template><a href="/api/template-only">Account</a></template>
        <script setup lang="ts">
        const endpoint: string = "/api/vue-script";
        fetch(endpoint);
        </script>
        <script type="application/json">{"url":"/api/json-only"}</script>
        <script src="./external.js"></script>
        """,
        encoding="utf-8",
    )
    collector = LocalCollector()

    assets = [asset async for asset in collector.collect([tmp_path])]

    assert len(assets) == 1
    asset = assets[0]
    assert asset.language_hint == "typescript"
    assert "/api/vue-script" in asset.content.decode()
    assert "/api/template-only" not in asset.content.decode()
    assert asset.url.startswith(component.as_uri() + "#bundleinspector-script-")
    assert asset.initiator == component.as_uri()
    assert asset.load_context == component.as_uri()
    assert [item.url for item in asset.provenance] == [component.as_uri()]
    reasons = {(item.code, item.reason) for item in collector.diagnostics}
    assert ("local_component_unsupported", "non_javascript_script_type") in reasons
    assert ("local_component_unsupported", "external_script") in reasons


@pytest.mark.asyncio
async def test_svelte_and_astro_scripts_preserve_language_and_source_order(tmp_path):
    (tmp_path / "A.svelte").write_text(
        '<script lang="tsx">const a = <div />; fetch("/api/svelte");</script>',
        encoding="utf-8",
    )
    (tmp_path / "B.astro").write_text(
        """---
const frontmatter: string = "/api/astro-frontmatter";
fetch(frontmatter);
---
<main>Body</main>
<script>fetch("/api/astro-script");</script>
""",
        encoding="utf-8",
    )

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert [asset.language_hint for asset in assets] == ["tsx", "typescript", "javascript"]
    assert [asset.url.split("#", 1)[0] for asset in assets] == [
        (tmp_path / "A.svelte").as_uri(),
        (tmp_path / "B.astro").as_uri(),
        (tmp_path / "B.astro").as_uri(),
    ]


@pytest.mark.asyncio
async def test_component_script_count_and_unclosed_blocks_are_reported(tmp_path):
    capped = tmp_path / "cap.vue"
    capped.write_text(
        "".join(f'<script>fetch("/api/{index}");</script>' for index in range(3)),
        encoding="utf-8",
    )
    unclosed = tmp_path / "unclosed.svelte"
    unclosed.write_text('<script lang="ts">fetch("/api/unclosed");', encoding="utf-8")
    collector = LocalCollector()
    collector.MAX_COMPONENT_SCRIPTS = 2

    assets = [asset async for asset in collector.collect([tmp_path])]

    assert len(assets) == 3
    assert any("local_component:unclosed_script" in asset.parse_errors for asset in assets)
    reasons = {(item.code, item.reason) for item in collector.diagnostics}
    assert ("local_component_truncated", "script_count_cap") in reasons
    assert ("local_component_malformed", "unclosed_script") in reasons


@pytest.mark.asyncio
async def test_map_is_attached_to_code_but_never_emitted_as_executable_asset(tmp_path):
    source = tmp_path / "app.mts"
    source.write_text('fetch("/api/generated");', encoding="utf-8")
    map_path = tmp_path / "app.mts.map"
    map_path.write_text(
        '{"version":3,"sources":["src/app.ts"],"sourcesContent":["fetch(\\"/api/source\\");"],"names":[],"mappings":"AAAA"}',
        encoding="utf-8",
    )

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert len(assets) == 1
    assert assets[0].url == source.as_uri()
    assert assets[0].has_sourcemap is True
    assert assets[0].sourcemap_url == map_path.as_uri()
    assert assets[0].sourcemap_content == map_path.read_bytes()
    assert assets[0].sourcemap_hash is not None

    map_only = [asset async for asset in LocalCollector().collect([map_path])]
    assert map_only == []


@pytest.mark.asyncio
async def test_explicit_map_traversal_is_blocked_under_discovery_root(tmp_path):
    outside_map = tmp_path / "outside.map"
    outside_map.write_text('{"version":3,"sources":[],"names":[],"mappings":""}')
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "app.js"
    source.write_text('fetch("/api/app");\n//# sourceMappingURL=../outside.map')
    collector = LocalCollector()

    assets = [asset async for asset in collector.collect([source_dir])]

    assert len(assets) == 1
    assert assets[0].has_sourcemap is False
    assert any(item.code == "local_sourcemap_blocked" for item in collector.diagnostics)


@pytest.mark.asyncio
async def test_conventional_map_size_limit_is_rejected(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "app.js"
    source.write_text('fetch("/api/app");')
    (source_dir / "app.js.map").write_bytes(b"x" * 2_000)
    collector = LocalCollector(max_file_size_mb=0.001)
    oversized = [asset async for asset in collector.collect([source_dir])]
    assert len(oversized) == 1
    assert oversized[0].has_sourcemap is False
    assert any(item.code == "local_sourcemap_oversized" for item in collector.diagnostics)


@pytest.mark.asyncio
async def test_unreadable_discovered_source_is_reported(monkeypatch, tmp_path):
    source = tmp_path / "unreadable.js"
    source.write_text('fetch("/api/unreadable");', encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def fail_selected(path):
        if path == source:
            raise PermissionError("denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_selected)
    collector = LocalCollector()

    assets = [asset async for asset in collector.collect([source])]

    assert assets == []
    assert {
        (item.code, item.reason, item.affected_count)
        for item in collector.diagnostics
    } == {("local_file_unreadable", "permission_denied", 1)}


@pytest.mark.asyncio
async def test_identical_bytes_with_different_grammars_are_both_collected(tmp_path):
    source = 'const value: string = location.hash; document.body.innerHTML = value;'
    (tmp_path / "a.js").write_text(source, encoding="utf-8")
    (tmp_path / "b.ts").write_text(source, encoding="utf-8")

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert len(assets) == 2
    assert {asset.language_hint for asset in assets} == {"javascript", "typescript"}
    assert len({asset.id for asset in assets}) == 2
    assert {asset.content_hash for asset in assets} == {assets[0].content_hash}


@pytest.mark.asyncio
async def test_identical_bytes_with_different_maps_preserve_each_map(tmp_path):
    source = 'const value = location.hash;\n//# sourceMappingURL=app.js.map\n'
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "app.js").write_text(source, encoding="utf-8")
    (second / "app.js").write_text(source, encoding="utf-8")
    (first / "app.js.map").write_text(
        '{"version":3,"sources":["/from-a.ts"],"names":[],"mappings":"",'
        '"sourcesContent":["fetch(\\"/api/a\\");"]}',
        encoding="utf-8",
    )
    (second / "app.js.map").write_text(
        '{"version":3,"sources":["/from-b.ts"],"names":[],"mappings":"",'
        '"sourcesContent":["fetch(\\"/api/b\\");"]}',
        encoding="utf-8",
    )

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert len(assets) == 2
    assert len({asset.id for asset in assets}) == 2
    maps_by_parent = {
        Path(asset.url.removeprefix("file:///")).parent.name:
            asset.sourcemap_content.decode("utf-8")
        for asset in assets
        if asset.sourcemap_content is not None
    }
    assert "/from-a.ts" in maps_by_parent["a"]
    assert "/from-b.ts" in maps_by_parent["b"]


@pytest.mark.asyncio
async def test_identical_plain_javascript_still_deduplicates_with_provenance(tmp_path):
    source = 'fetch("/api/shared");'
    (tmp_path / "a.js").write_text(source, encoding="utf-8")
    (tmp_path / "b.js").write_text(source, encoding="utf-8")

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert len(assets) == 1
    assert {Path(item.url.removeprefix("file:///")).name for item in assets[0].provenance} == {
        "a.js",
        "b.js",
    }


@pytest.mark.asyncio
async def test_identical_component_scripts_keep_distinct_virtual_sources(tmp_path):
    body = '<script lang="ts">fetch("/api/shared");</script>'
    (tmp_path / "A.vue").write_text(body, encoding="utf-8")
    (tmp_path / "B.vue").write_text(body, encoding="utf-8")

    assets = [asset async for asset in LocalCollector().collect([tmp_path])]

    assert len(assets) == 2
    assert len({asset.url for asset in assets}) == 2
    assert len({asset.id for asset in assets}) == 2


def test_local_asset_ids_do_not_collide_on_known_32_bit_url_digest_pair():
    collector = LocalCollector()
    urls = [
        "file:///collision/81218.js",
        "file:///collision/120355.js",
    ]

    assets = [
        collector._make_asset(
            content=b"same content",
            url=url,
            language_hint="javascript",
            initiator="file:///collision",
            load_context=url,
            provenance_url=url,
        )
        for url in urls
    ]

    assert len({asset.id for asset in assets}) == 2


def test_language_hint_round_trips_and_rejects_unknown_values():
    asset = JSAsset(url="file:///module.mts", language_hint="typescript")
    restored = JSAsset.model_validate_json(asset.model_dump_json())
    assert restored.language_hint == "typescript"
    with pytest.raises(ValueError):
        JSAsset(url="file:///module.py", language_hint="python")
