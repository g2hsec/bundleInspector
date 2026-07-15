from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

import bundleInspector.storage.artifact_store as artifact_store_module
import bundleInspector.storage.atomic as atomic_module
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.atomic import (
    atomic_read_bytes,
    atomic_update_bytes,
    atomic_write_bytes,
)
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    JSReference,
    LoadMethod,
    PipelineCheckpoint,
    Severity,
)


@pytest.mark.asyncio
async def test_artifact_cache_never_persists_raw_canary(tmp_path) -> None:
    canary = b"CACHE_SECRET_CANARY_0123456789"
    store = ArtifactStore(tmp_path)
    content_hash, _ = await store.store_js(canary, "https://example.com/a.js")
    ast_hash = await store.store_ast({"value": canary.decode()}, content_hash)
    sm_hash = await store.store_sourcemap(canary, content_hash)

    assert await store.get_js(content_hash) == canary
    assert (await store.get_ast(content_hash, ast_hash))["value"] == canary.decode()
    assert await store.get_sourcemap(content_hash, sm_hash) == canary
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert canary not in path.read_bytes(), path


def _checkpoint(*secrets: str) -> PipelineCheckpoint:
    return PipelineCheckpoint(
        job_id="job-1",
        seed_urls=["https://example.com"],
        stage="analyze",
        findings=[
            Finding(
                rule_id="secret",
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Secret",
                evidence=Evidence(file_url="a.js", file_hash="h", line=index + 1),
                extracted_value=secret,
            )
            for index, secret in enumerate(secrets)
        ],
    )


@pytest.mark.asyncio
async def test_checkpoint_is_sealed_and_restores_distinct_secret_semantics(tmp_path) -> None:
    secrets = ("CHECKPOINT_SECRET_ALPHA_012345", "CHECKPOINT_SECRET_BRAVO_987654")
    store = FindingStore(tmp_path)
    await store.store_checkpoint(_checkpoint(*secrets))
    restored = await store.get_checkpoint()
    assert restored is not None
    assert [item.extracted_value for item in restored.findings] == list(secrets)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            payload = path.read_bytes()
            assert all(secret.encode() not in payload for secret in secrets)


@pytest.mark.asyncio
async def test_sealed_checkpoint_restores_browser_captured_body_without_plaintext(tmp_path) -> None:
    captured = b"AUTHENTICATED_BROWSER_BODY_CANARY"
    checkpoint = PipelineCheckpoint(
        job_id="job-browser-body",
        seed_urls=["https://example.com"],
        stage="crawl",
        js_refs=[
            JSReference(
                url="https://example.com/private.js",
                method=LoadMethod.NETWORK_CAPTURE,
                captured_content=captured,
                captured_status_code=200,
            )
        ],
    )
    store = FindingStore(tmp_path)
    await store.store_checkpoint(checkpoint)
    restored = await store.get_checkpoint()

    assert restored is not None
    assert restored.js_refs[0].captured_content == captured
    assert all(captured not in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())


@pytest.mark.asyncio
async def test_legacy_plaintext_checkpoint_is_validated_then_migrated(tmp_path) -> None:
    store = FindingStore(tmp_path)
    checkpoint = _checkpoint("LEGACY_CHECKPOINT_SECRET_012345")
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(checkpoint.model_dump_json(), encoding="utf-8")
    restored = await store.get_checkpoint()
    assert restored is not None
    assert restored.findings[0].extracted_value == "LEGACY_CHECKPOINT_SECRET_012345"
    migrated = checkpoint_path.read_bytes()
    assert migrated.startswith(b"BICP1")
    assert b"LEGACY_CHECKPOINT_SECRET_012345" not in migrated


@pytest.mark.asyncio
async def test_concurrent_legacy_checkpoint_read_seals_once(tmp_path, monkeypatch) -> None:
    checkpoint = _checkpoint("CONCURRENT_LEGACY_CHECKPOINT_SECRET_012345")
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(checkpoint.model_dump_json(), encoding="utf-8")
    seal_calls = 0
    seal_calls_lock = threading.Lock()
    original_seal = FindingStore._seal_checkpoint_with_cipher

    def slow_seal(self: FindingStore, payload: bytes, cipher) -> bytes:
        nonlocal seal_calls
        with seal_calls_lock:
            seal_calls += 1
        time.sleep(0.05)
        return original_seal(self, payload, cipher)

    monkeypatch.setattr(FindingStore, "_seal_checkpoint_with_cipher", slow_seal)
    stores = [FindingStore(tmp_path) for _ in range(8)]
    restored = await asyncio.gather(*[store.get_checkpoint() for store in stores])

    assert seal_calls == 1
    assert all(item == checkpoint for item in restored)
    assert checkpoint_path.read_bytes().startswith(b"BICP1")


@pytest.mark.asyncio
async def test_checkpoint_ciphertext_and_wrong_key_fail_closed(tmp_path) -> None:
    store = FindingStore(tmp_path)
    await store.store_checkpoint(_checkpoint("TAMPER_CHECKPOINT_SECRET_012345"))
    checkpoint_path = tmp_path / "checkpoint.json"
    tampered = bytearray(checkpoint_path.read_bytes())
    tampered[-1] ^= 1
    checkpoint_path.write_bytes(tampered)
    with pytest.raises(InvalidTag):
        await store.get_checkpoint()

    await store.store_checkpoint(_checkpoint("WRONG_KEY_CHECKPOINT_SECRET_012345"))
    (tmp_path / ".checkpoint-key").write_bytes(os.urandom(32))
    with pytest.raises(InvalidTag):
        await store.get_checkpoint()


@pytest.mark.asyncio
async def test_artifact_legacy_migration_tamper_and_concurrent_key_creation(
    tmp_path,
    monkeypatch,
) -> None:
    legacy = b"LEGACY_ARTIFACT_SECRET_012345"
    content_hash = hashlib.sha256(legacy).hexdigest()
    legacy_path = tmp_path / "js" / f"{content_hash}.js"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_bytes(legacy)

    seal_calls = 0
    seal_calls_lock = threading.Lock()
    original_seal = ArtifactStore._seal

    def slow_seal(self: ArtifactStore, path: Path, payload: bytes) -> bytes:
        nonlocal seal_calls
        if path == legacy_path and payload == legacy:
            with seal_calls_lock:
                seal_calls += 1
            # Give every competing initializer time to reach the same entry.
            time.sleep(0.05)
        return original_seal(self, path, payload)

    monkeypatch.setattr(ArtifactStore, "_seal", slow_seal)
    stores = await asyncio.gather(
        *[asyncio.to_thread(ArtifactStore, tmp_path) for _ in range(8)]
    )
    assert seal_calls == 1
    assert len((tmp_path / ".artifact-key").read_bytes()) == 32
    assert await stores[0].get_js(content_hash) == legacy
    assert legacy not in legacy_path.read_bytes()

    tampered = bytearray(legacy_path.read_bytes())
    tampered[-1] ^= 1
    legacy_path.write_bytes(tampered)
    with pytest.raises(InvalidTag):
        await stores[-1].get_js(content_hash)


@pytest.mark.asyncio
async def test_atomic_update_queues_more_than_ten_contenders(tmp_path) -> None:
    target = tmp_path / "counter.bin"
    atomic_write_bytes(target, b"0")

    def increment(current: bytes) -> bytes:
        time.sleep(0.002)
        return str(int(current) + 1).encode("ascii")

    await asyncio.gather(
        *[
            asyncio.to_thread(atomic_update_bytes, target, increment)
            for _ in range(32)
        ]
    )
    assert atomic_read_bytes(target) == b"32"


def test_atomic_update_serializes_independent_processes(tmp_path) -> None:
    target = tmp_path / "process-counter.bin"
    start = tmp_path / "process-start"
    atomic_write_bytes(target, b"0")
    worker = """
import sys
import time
from pathlib import Path
from bundleInspector.storage.atomic import atomic_update_bytes

target, start, ready = map(Path, sys.argv[1:])
ready.write_bytes(b"")
deadline = time.monotonic() + 15
while not start.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("process start barrier timed out")
    time.sleep(0.005)

def increment(current: bytes) -> bytes:
    time.sleep(0.03)
    return str(int(current) + 1).encode("ascii")

atomic_update_bytes(target, increment)
"""
    processes: list[subprocess.Popen[str]] = []
    try:
        for index in range(8):
            ready = tmp_path / f"ready-{index}"
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-c", worker, str(target), str(start), str(ready)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
        deadline = time.monotonic() + 15
        while not all((tmp_path / f"ready-{index}").exists() for index in range(8)):
            if time.monotonic() >= deadline:
                raise TimeoutError("workers did not reach the process barrier")
            time.sleep(0.01)
        start.write_bytes(b"")
        for process in processes:
            remaining = max(0.1, deadline - time.monotonic())
            stdout, stderr = process.communicate(timeout=remaining)
            assert process.returncode == 0, (stdout, stderr)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    assert atomic_read_bytes(target) == b"8"


@pytest.mark.skipif(os.name == "nt", reason="directory fsync is a POSIX durability gate")
def test_atomic_replace_fsyncs_parent_directory(tmp_path, monkeypatch) -> None:
    synced_directories: list[tuple[int, int]] = []
    original_fsync = os.fsync

    def track_fsync(file_descriptor: int) -> None:
        metadata = os.fstat(file_descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            synced_directories.append((metadata.st_dev, metadata.st_ino))
        original_fsync(file_descriptor)

    monkeypatch.setattr(os, "fsync", track_fsync)
    atomic_write_bytes(tmp_path / "durable.bin", b"durable")
    root_stat = tmp_path.stat()

    assert (root_stat.st_dev, root_stat.st_ino) in synced_directories


@pytest.mark.asyncio
async def test_atomic_reader_blocks_replacement_until_handle_closes(
    tmp_path,
    monkeypatch,
) -> None:
    target = tmp_path / "read-replace.bin"
    atomic_write_bytes(target, b"before")
    reader_open = threading.Event()
    release_reader = threading.Event()
    original_read_bytes = atomic_module._read_existing_regular_bytes

    def blocking_read(path: Path) -> bytes:
        if path != target:
            return original_read_bytes(path)
        with atomic_module._open_existing_regular_handle(path) as handle:
            reader_open.set()
            assert release_reader.wait(timeout=5)
            payload = handle.read()
            atomic_module._verify_regular_identity(path, handle.fileno())
            return payload

    monkeypatch.setattr(atomic_module, "_read_existing_regular_bytes", blocking_read)
    read_task = asyncio.create_task(asyncio.to_thread(atomic_read_bytes, target))
    assert await asyncio.to_thread(reader_open.wait, 5)
    write_task = asyncio.create_task(asyncio.to_thread(atomic_write_bytes, target, b"after"))
    await asyncio.sleep(0.05)
    assert not write_task.done()
    release_reader.set()

    assert await read_task == b"before"
    await write_task
    assert atomic_read_bytes(target) == b"after"


@pytest.mark.asyncio
async def test_sealed_artifact_and_checkpoint_reads_use_read_only_sidecars(
    tmp_path,
    monkeypatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_store = ArtifactStore(artifact_root)
    content = b"read-only-sealed-artifact"
    content_hash, _ = await artifact_store.store_js(content, "https://example.com/a.js")
    checkpoint_root = tmp_path / "checkpoint"
    checkpoint_store = FindingStore(checkpoint_root)
    checkpoint = _checkpoint("READ_ONLY_CHECKPOINT_SECRET_012345")
    await checkpoint_store.store_checkpoint(checkpoint)

    js_path = artifact_root / "js" / f"{content_hash}.js"
    guarded_locks = {
        atomic_module._lock_path(artifact_root / ".artifact-key"),
        atomic_module._lock_path(js_path),
        atomic_module._lock_path(checkpoint_root / ".checkpoint-key"),
        atomic_module._lock_path(checkpoint_root / "checkpoint.json"),
    }
    original_open = atomic_module._open_lock_handle

    def reject_writable(path: Path, *, writable: bool, create: bool):
        if path in guarded_locks and writable:
            raise PermissionError(errno.EACCES, "read-only sidecar", str(path))
        return original_open(path, writable=writable, create=create)

    monkeypatch.setattr(atomic_module, "_open_lock_handle", reject_writable)
    read_only_artifacts = ArtifactStore(artifact_root)
    read_only_checkpoints = FindingStore(checkpoint_root)

    assert await read_only_artifacts.get_js(content_hash) == content
    assert await read_only_checkpoints.get_checkpoint() == checkpoint


@pytest.mark.asyncio
async def test_concurrent_store_js_has_one_creator_and_refresh_survives_cleanup(
    tmp_path,
    monkeypatch,
) -> None:
    stores = await asyncio.gather(
        *[asyncio.to_thread(ArtifactStore, tmp_path) for _ in range(16)]
    )
    content = b"linearizable-content-addressed-entry"
    results = await asyncio.gather(
        *[store.store_js(content, "https://example.com/a.js") for store in stores]
    )
    assert sum(int(is_new) for _, is_new in results) == 1

    content_hash = results[0][0]
    payload_path = tmp_path / "js" / f"{content_hash}.js"
    os.utime(payload_path, (1, 1))
    refresh_holds_lock = threading.Event()
    release_refresh = threading.Event()
    original_create_or_refresh = artifact_store_module.atomic_create_or_refresh_bytes

    def blocking_create_or_refresh(path, payload, validate_existing):
        def blocking_validate(current: bytes) -> None:
            validate_existing(current)
            refresh_holds_lock.set()
            assert release_refresh.wait(timeout=5)

        return original_create_or_refresh(path, payload, blocking_validate)

    monkeypatch.setattr(
        artifact_store_module,
        "atomic_create_or_refresh_bytes",
        blocking_create_or_refresh,
    )
    refresh_task = asyncio.create_task(
        stores[0].store_js(content, "https://example.com/a.js")
    )
    assert await asyncio.to_thread(refresh_holds_lock.wait, 5)
    cleanup_task = asyncio.create_task(stores[1].cleanup(max_age_days=0))
    await asyncio.sleep(0.05)
    assert not cleanup_task.done()
    release_refresh.set()

    assert await refresh_task == (content_hash, False)
    assert await cleanup_task == 0
    assert await stores[-1].get_js(content_hash) == content


@pytest.mark.asyncio
async def test_magic_prefixed_legacy_js_is_identified_by_content_hash(tmp_path) -> None:
    legacy = b"BIC1; console.log('legacy payload longer than a sealed header');"
    content_hash = hashlib.sha256(legacy).hexdigest()
    legacy_path = tmp_path / "js" / f"{content_hash}.js"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_bytes(legacy)

    store = ArtifactStore(tmp_path)

    assert legacy_path.read_bytes().startswith(b"BIC1")
    assert legacy_path.read_bytes() != legacy
    assert await store.get_js(content_hash) == legacy


@pytest.mark.parametrize(
    ("directory", "filename", "payload"),
    (
        ("js", f"{'0' * 64}.js", b"wrong JS payload"),
        ("ast", f"{'a' * 64}_{'0' * 16}.json", b'{"type":"Program"}'),
        ("sourcemap", f"{'a' * 64}_{'0' * 16}.map", b'{"version":3}'),
    ),
)
def test_legacy_artifact_hash_mismatches_fail_closed(
    tmp_path,
    directory: str,
    filename: str,
    payload: bytes,
) -> None:
    legacy_path = tmp_path / directory / filename
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_bytes(payload)

    with pytest.raises(ValueError, match="hash mismatch"):
        ArtifactStore(tmp_path)


@pytest.mark.asyncio
async def test_cleanup_preserves_lock_files_during_concurrent_write(tmp_path) -> None:
    store = ArtifactStore(tmp_path)
    content = b"cleanup-lock-contract"
    content_hash, _ = await store.store_js(content, "https://example.com/a.js")
    payload_path = tmp_path / "js" / f"{content_hash}.js"
    lock_path = atomic_module._lock_path(payload_path)
    old = 1
    os.utime(payload_path, (old, old))
    os.utime(lock_path, (old, old))

    await asyncio.gather(
        store.cleanup(max_age_days=0),
        store.store_js(content, "https://example.com/a.js"),
    )
    assert lock_path.exists()
    await store.store_js(content, "https://example.com/a.js")
    assert await store.get_js(content_hash) == content
