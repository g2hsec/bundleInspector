"""Regression: JSON stores must round-trip non-ASCII regardless of OS locale.

On a Korean Windows the default text encoding is cp949, which cannot encode
characters such as 'é' (\\xe9) that appear in JS bundle content/snippets. The
stores pin encoding="utf-8" so writes/reads never depend on the ambient locale.
"""

import hashlib

import pytest

from bundleInspector.config import Config
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.models import JSAsset, PipelineCheckpoint

# Mix of Latin-1-only, CJK, and emoji — none encodable as cp949.
NON_ASCII = "café résumé — 한국어 テスト 🚀 é"


@pytest.mark.asyncio
async def test_checkpoint_roundtrips_non_ascii(tmp_path):
    store = FindingStore(tmp_path)
    checkpoint = PipelineCheckpoint(
        job_id="j",
        seed_urls=["http://x"],
        stage="analyze",
        stage_state={"note": NON_ASCII},
    )

    path = await store.store_checkpoint(checkpoint)

    # Checkpoints are encrypted at rest; the decoded model still round-trips Unicode.
    assert path.read_bytes().startswith(b"BICP1")
    assert "café".encode() not in path.read_bytes()

    restored = await store.get_checkpoint()
    assert restored is not None
    assert restored.stage_state["note"] == NON_ASCII


@pytest.mark.asyncio
async def test_asset_meta_roundtrips_non_ascii(tmp_path):
    store = ArtifactStore(tmp_path)
    asset = JSAsset(url=f"https://x/{NON_ASCII}.js", content="var s = 'é';")
    asset.compute_hash()

    await store.store_asset_meta(asset)
    restored = await store.get_asset_meta(asset.content_hash)

    assert restored is not None
    assert restored.url == asset.url


@pytest.mark.asyncio
async def test_ast_roundtrips_non_ascii(tmp_path):
    store = ArtifactStore(tmp_path)
    ast = {"type": "Literal", "value": NON_ASCII}
    content_hash = hashlib.sha256(b"source").hexdigest()

    ast_hash = await store.store_ast(ast, content_hash)
    restored = await store.get_ast(content_hash, ast_hash)

    assert restored == ast


def test_config_from_file_reads_non_ascii(tmp_path):
    """Config.from_file must decode as UTF-8, not the ambient locale codec."""
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"# {NON_ASCII}\nauth:\n  cookies:\n    session: \"{NON_ASCII}\"\n",
        encoding="utf-8",
    )

    config = Config.from_file(cfg)

    assert config.auth.cookies["session"] == NON_ASCII
