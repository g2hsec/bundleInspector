"""Content-addressable hashes are used as path components, so a tampered/malformed hash (e.g. from a
crafted checkpoint's asset_hashes) must never traverse outside the cache dir -- validated as plain
hex before any path is built."""

import os
import subprocess

import pytest

from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.job_repository import JobRepository
from bundleInspector.storage.models import JSAsset


def test_has_js_rejects_traversal_hash(tmp_path):
    store = ArtifactStore(tmp_path)
    assert store.has_js("../../../../etc/hosts") is False
    assert store.has_js("../secret") is False
    assert store.has_js("has/slash") is False


async def test_get_methods_reject_traversal_hash(tmp_path):
    store = ArtifactStore(tmp_path)
    assert await store.get_js("../../etc/hosts") is None
    assert await store.get_ast("../../etc", "hosts") is None
    assert await store.get_sourcemap("..", "..") is None
    assert await store.get_asset_meta("../../../etc/hosts") is None


async def test_store_methods_reject_traversal_hash(tmp_path):
    store = ArtifactStore(tmp_path)
    with pytest.raises(ValueError):
        await store.store_ast({"type": "Program"}, "../../../evil")
    with pytest.raises(ValueError):
        await store.store_sourcemap(b"{}", "../../../evil")

    asset = JSAsset(
        url="https://example.test/app.js",
        content=b"safe",
        content_hash="../../../evil",
    )
    with pytest.raises(ValueError, match="content_hash"):
        await store.store_asset_meta(asset)
    assert not (tmp_path.parent / "evil.json").exists()


@pytest.mark.asyncio
async def test_artifact_methods_reject_short_content_hash_aliases(tmp_path):
    store = ArtifactStore(tmp_path)
    with pytest.raises(ValueError, match="content_hash"):
        await store.store_ast({"type": "Program"}, "deadbeef")
    with pytest.raises(ValueError, match="js_hash"):
        await store.store_sourcemap(b"{}", "deadbeef")
    assert await store.get_js("deadbeef") is None
    assert await store.get_ast("deadbeef", "a" * 16) is None
    assert await store.get_sourcemap("deadbeef", "a" * 16) is None
    assert store.has_js("deadbeef") is False


@pytest.mark.asyncio
async def test_asset_metadata_rejects_noncanonical_and_mismatched_hashes(tmp_path):
    store = ArtifactStore(tmp_path)
    asset = JSAsset(url="https://example.test/app.js", content=b"actual")
    asset.compute_hash()

    asset.content_hash = "a" * 63
    with pytest.raises(ValueError, match="SHA-256"):
        await store.store_asset_meta(asset)

    asset.content_hash = "A" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        await store.store_asset_meta(asset)

    asset.content_hash = "0" * 64
    with pytest.raises(ValueError, match="does not match"):
        await store.store_asset_meta(asset)

    assert await store.get_asset_meta("a" * 63) is None
    assert not list((tmp_path / "meta").glob("*.json"))


@pytest.mark.asyncio
async def test_normalized_asset_metadata_requires_current_and_original_content_hashes(tmp_path):
    store = ArtifactStore(tmp_path)
    raw = b"const  value=1;"
    normalized = b"const value = 1;"
    raw_hash, _ = await store.store_js(raw, "https://example.test/app.js")
    normalized_hash, _ = await store.store_js(normalized, "https://example.test/app.js")
    asset = JSAsset(
        url="https://example.test/app.js",
        content=normalized,
        content_hash=raw_hash,
        normalized_hash=normalized_hash,
    )

    await store.store_asset_meta(asset)
    restored = await store.get_asset_meta(raw_hash)
    assert restored is not None
    assert restored.content_hash == raw_hash
    assert restored.normalized_hash == normalized_hash

    asset.normalized_hash = "f" * 64
    with pytest.raises(ValueError, match="normalized_hash does not match"):
        await store.store_asset_meta(asset)

    orphan = asset.model_copy(update={"normalized_hash": normalized_hash, "content_hash": "e" * 64})
    with pytest.raises(ValueError, match="original content_hash"):
        await store.store_asset_meta(orphan)


async def test_valid_hash_roundtrip_still_works(tmp_path):
    """A legitimate (hex) hash path must still store and retrieve normally."""
    store = ArtifactStore(tmp_path)
    content_hash, is_new = await store.store_js(b"console.log(1)", "http://x/a.js")
    assert is_new and store.has_js(content_hash)
    assert await store.get_js(content_hash) == b"console.log(1)"
    ast = {"type": "Program", "body": []}
    ast_hash = await store.store_ast(ast, content_hash)
    assert await store.get_ast(content_hash, ast_hash) == ast


def test_artifact_store_rejects_nonplain_storage_directories(tmp_path):
    file_base = tmp_path / "file-base"
    file_base.write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="directory"):
        ArtifactStore(file_base)

    child_base = tmp_path / "child-base"
    child_base.mkdir()
    (child_base / "js").write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="directory"):
        ArtifactStore(child_base)


def test_artifact_store_rejects_linked_storage_directories(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_base = tmp_path / "linked-base"
    try:
        linked_base.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable on this platform")
    with pytest.raises(ValueError, match="links"):
        ArtifactStore(linked_base)

    child_base = tmp_path / "child-links"
    child_base.mkdir()
    (child_base / "js").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="links"):
        ArtifactStore(child_base)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_storage_boundaries_reject_windows_junction_on_all_supported_python_versions(tmp_path):
    outside = tmp_path / "outside-junction"
    outside.mkdir()
    junction = tmp_path / "artifact-junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("junction creation is unavailable on this platform")
    try:
        with pytest.raises(ValueError, match="links"):
            ArtifactStore(junction)
    finally:
        junction.rmdir()

    repository = JobRepository(tmp_path / "cache")
    job_junction = repository.base_path / "linked-job"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(job_junction), str(outside)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("job junction creation is unavailable on this platform")
    try:
        with pytest.raises(ValueError, match="links"):
            repository.assert_access("linked-job", "local")
    finally:
        job_junction.rmdir()


@pytest.mark.asyncio
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
async def test_artifact_payload_links_are_not_read_migrated_or_cleaned(tmp_path, link_kind):
    store = ArtifactStore(tmp_path / "artifacts")
    content = b"console.log('linked')"
    content_hash, _ = await store.store_js(content, "https://example.test/app.js")
    payload_path = store.base_path / "js" / f"{content_hash}.js"
    outside = tmp_path / f"outside-{link_kind}.js"
    outside.write_bytes(payload_path.read_bytes())
    payload_path.unlink()
    try:
        if link_kind == "symlink":
            payload_path.symlink_to(outside)
        else:
            os.link(outside, payload_path)
    except OSError:
        pytest.skip(f"{link_kind} creation is unavailable on this platform")

    with pytest.raises(OSError, match="unsafe persistent file"):
        await store.get_js(content_hash)
    assert store.has_js(content_hash) is False
    assert await store.cleanup(max_age_days=-1) == 0
    assert outside.read_bytes()

    # Startup migration sees the candidate but the atomic layer rejects it without touching the
    # outside target or preventing other safe cache entries from opening.
    reopened = ArtifactStore(store.base_path)
    assert reopened.has_js(content_hash) is False
    assert outside.read_bytes()
