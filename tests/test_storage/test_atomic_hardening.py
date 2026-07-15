from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO, cast

import pytest

import bundleInspector.storage.atomic as atomic_module
from bundleInspector.storage.atomic import (
    AtomicCommitError,
    AtomicLockReentryError,
    UnsafePathError,
    atomic_create_or_refresh_bytes,
    atomic_publish_text,
    atomic_read_bytes,
    atomic_unlink_if,
    atomic_update_bytes,
    atomic_write_bytes,
)


def _make_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")


def test_lock_shards_are_stable_across_process_hash_seeds(tmp_path: Path) -> None:
    target = tmp_path / "Case-Sensitive-Name.json"
    expected = atomic_module._lock_path(target).name
    script = (
        "import sys; from pathlib import Path; "
        "from bundleInspector.storage.atomic import _lock_path; "
        "print(_lock_path(Path(sys.argv[1])).name)"
    )

    observed = {
        subprocess.check_output(
            [sys.executable, "-c", script, str(target)],
            cwd=Path(__file__).parents[2],
            env={**os.environ, "PYTHONHASHSEED": seed},
            text=True,
        ).strip()
        for seed in ("0", "1", "12345", "random")
    }

    assert observed == {expected}
    assert atomic_module._lock_path(target) == atomic_module._lock_path(
        target.with_name(target.name.swapcase())
    )


def test_many_payloads_create_at_most_sixty_four_persistent_sidecars(
    tmp_path: Path,
) -> None:
    targets = [tmp_path / f"payload-{index:03d}.bin" for index in range(256)]
    for index, target in enumerate(targets):
        atomic_write_bytes(target, str(index).encode("ascii"))

    sidecars = set(tmp_path.glob(".bundleinspector-lock-*"))
    expected = {atomic_module._lock_path(target) for target in targets}

    assert sidecars == expected
    assert len(sidecars) <= 64
    assert not list(tmp_path.glob("*.lock"))


def test_same_target_updates_remain_serialized_across_threads(tmp_path: Path) -> None:
    target = tmp_path / "counter.bin"
    atomic_write_bytes(target, b"0")
    barrier = threading.Barrier(24)

    def increment(_: int) -> None:
        barrier.wait(timeout=5)

        def update(current: bytes) -> bytes:
            time.sleep(0.001)
            return str(int(current) + 1).encode("ascii")

        atomic_update_bytes(target, update)

    with ThreadPoolExecutor(max_workers=24) as executor:
        list(executor.map(increment, range(24)))

    assert atomic_read_bytes(target) == b"24"


def test_targets_on_different_shards_can_progress_concurrently(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = next(
        tmp_path / f"second-{index}.bin"
        for index in range(256)
        if atomic_module._lock_path(tmp_path / f"second-{index}.bin")
        != atomic_module._lock_path(first)
    )
    atomic_write_bytes(first, b"first")
    atomic_write_bytes(second, b"second")
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()

    def hold_first(current: bytes) -> bytes:
        first_entered.set()
        assert release_first.wait(timeout=5)
        return current

    def enter_second(current: bytes) -> bytes:
        second_entered.set()
        return current

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(atomic_update_bytes, first, hold_first)
        assert first_entered.wait(timeout=5)
        second_future = executor.submit(atomic_update_bytes, second, enter_second)
        try:
            assert second_entered.wait(timeout=5)
        finally:
            release_first.set()
        first_future.result(timeout=5)
        second_future.result(timeout=5)


def test_different_targets_on_the_same_shard_are_serialized(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = next(
        tmp_path / f"collision-{index}.bin"
        for index in range(4096)
        if atomic_module._lock_path(tmp_path / f"collision-{index}.bin")
        == atomic_module._lock_path(first)
    )
    atomic_write_bytes(first, b"first")
    atomic_write_bytes(second, b"second")
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()

    def hold_first(current: bytes) -> bytes:
        first_entered.set()
        assert release_first.wait(timeout=5)
        return current

    def enter_second(current: bytes) -> bytes:
        second_entered.set()
        return current

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(atomic_update_bytes, first, hold_first)
        assert first_entered.wait(timeout=5)
        second_future = executor.submit(atomic_update_bytes, second, enter_second)
        try:
            assert not second_entered.wait(timeout=0.15)
        finally:
            release_first.set()
        first_future.result(timeout=5)
        second_future.result(timeout=5)
        assert second_entered.is_set()


def test_nested_atomic_callback_on_the_same_shard_fails_fast(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = next(
        tmp_path / f"collision-{index}.bin"
        for index in range(4096)
        if atomic_module._lock_path(tmp_path / f"collision-{index}.bin")
        == atomic_module._lock_path(first)
    )
    atomic_write_bytes(first, b"first")
    atomic_write_bytes(second, b"second")

    def nested_read(current: bytes) -> bytes:
        atomic_read_bytes(second)
        return current

    with pytest.raises(AtomicLockReentryError, match="nested atomic path locks"):
        atomic_update_bytes(first, nested_read)

    assert atomic_read_bytes(first) == b"first"
    assert atomic_read_bytes(second) == b"second"


def test_nested_atomic_callback_on_a_different_shard_fails_fast(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = next(
        tmp_path / f"different-{index}.bin"
        for index in range(256)
        if atomic_module._lock_path(tmp_path / f"different-{index}.bin")
        != atomic_module._lock_path(first)
    )
    atomic_write_bytes(first, b"first")
    atomic_write_bytes(second, b"second")

    def nested_read(current: bytes) -> bytes:
        atomic_read_bytes(second)
        return current

    with pytest.raises(AtomicLockReentryError, match="nested atomic path locks"):
        atomic_update_bytes(first, nested_read)

    assert atomic_read_bytes(first) == b"first"
    assert atomic_read_bytes(second) == b"second"


def test_symbolic_link_lock_sidecar_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    attacker_file = tmp_path / "attacker.bin"
    attacker_file.write_bytes(b"attacker")
    _make_symlink(atomic_module._lock_path(target), attacker_file)

    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"payload")

    assert attacker_file.read_bytes() == b"attacker"
    assert not target.exists()


def test_lock_symlink_swap_before_open_normalizes_eloop_to_unsafe_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    outside = tmp_path / "outside.lock"
    outside.write_bytes(b"outside")
    lock_path = atomic_module._lock_path(target)
    original_open = atomic_module.os.open
    swapped = False

    def swap_before_open(path: Path, flags: int, mode: int = 0o777) -> int:
        nonlocal swapped
        if Path(path) == lock_path and not swapped:
            swapped = True
            _make_symlink(lock_path, outside)
            raise OSError(errno.ELOOP, "injected no-follow rejection", str(path))
        return original_open(path, flags, mode)

    monkeypatch.setattr(atomic_module.os, "open", swap_before_open)

    with pytest.raises(UnsafePathError, match="became a symbolic link") as exc_info:
        atomic_write_bytes(target, b"payload")

    assert isinstance(exc_info.value.__cause__, OSError)
    assert outside.read_bytes() == b"outside"
    assert not target.exists()


def test_directory_lock_sidecar_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    atomic_module._lock_path(target).mkdir()

    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"payload")

    assert not target.exists()


def test_hard_link_lock_sidecar_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    attacker_file = tmp_path / "attacker.bin"
    attacker_file.write_bytes(b"attacker")
    try:
        os.link(attacker_file, atomic_module._lock_path(target))
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"payload")

    assert attacker_file.read_bytes() == b"attacker"
    assert not target.exists()


@pytest.mark.skipif(os.name == "nt", reason="FIFOs are a POSIX filesystem primitive")
def test_fifo_lock_sidecar_fails_without_blocking(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    os.mkfifo(atomic_module._lock_path(target))
    started = time.monotonic()

    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"payload")

    assert time.monotonic() - started < 2


@pytest.mark.skipif(os.name == "nt", reason="Windows prevents renaming the locked handle")
def test_lock_identity_swap_before_payload_access_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    lock_path = atomic_module._lock_path(target)
    lock_path.write_bytes(b"")
    replacement = tmp_path / "replacement.lock"
    replacement.write_bytes(b"")
    backup = tmp_path / "original.lock"
    original_lock = atomic_module._lock_file

    def lock_then_swap(handle: BinaryIO) -> None:
        original_lock(handle)
        lock_path.replace(backup)
        replacement.replace(lock_path)

    monkeypatch.setattr(atomic_module, "_lock_file", lock_then_swap)

    with pytest.raises(UnsafePathError, match="no longer matches"):
        atomic_write_bytes(target, b"payload")

    assert not target.exists()


def test_reparse_metadata_is_rejected_even_without_pathlib_junction_support() -> None:
    metadata = cast(
        os.stat_result,
        SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
            st_file_attributes=0x400,
        ),
    )

    with pytest.raises(UnsafePathError, match="symbolic link or junction"):
        atomic_module._validate_lock_stat(metadata, Path("lock"))


def test_read_only_fallback_requires_a_precreated_safe_shard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    atomic_write_bytes(target, b"payload")
    lock_path = atomic_module._lock_path(target)
    original_open = atomic_module._open_lock_handle

    def reject_writable(
        path: Path,
        *,
        writable: bool,
        create: bool,
    ) -> BinaryIO:
        if path == lock_path and writable:
            raise PermissionError(errno.EACCES, "read-only shard", str(path))
        return original_open(path, writable=writable, create=create)

    monkeypatch.setattr(atomic_module, "_open_lock_handle", reject_writable)
    assert atomic_read_bytes(target) == b"payload"

    lock_path.unlink()
    with pytest.raises(FileNotFoundError):
        atomic_read_bytes(target)


def test_injected_replace_failure_preserves_payload_and_cleans_temp_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    atomic_write_bytes(target, b"before")

    def fail_replace(source: str | bytes | os.PathLike[str] | os.PathLike[bytes], destination: object) -> None:
        raise OSError(errno.EIO, "injected replace failure", str(destination))

    monkeypatch.setattr(atomic_module, "_replace_path", fail_replace)

    with pytest.raises(OSError, match="injected replace failure"):
        atomic_write_bytes(target, b"after")

    assert target.read_bytes() == b"before"
    assert not list(tmp_path.glob(f"{target.name}.*.tmp"))


def test_one_shot_publisher_preserves_prior_bytes_on_precommit_failure_without_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "nested" / "report.json"
    atomic_publish_text(target, "before")

    def fail_replace(source: str | Path, destination: object) -> None:
        raise OSError(errno.EIO, "injected output failure", str(destination))

    monkeypatch.setattr(atomic_module, "_replace_path", fail_replace)

    with pytest.raises(OSError, match="injected output failure"):
        atomic_publish_text(target, "after")

    assert target.read_text(encoding="utf-8") == "before"
    assert not list(target.parent.glob(".bundleinspector-lock-*"))
    assert not list(target.parent.glob(f"{target.name}.*.tmp"))


def test_windows_replace_requests_replace_existing_and_write_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str, int]] = []

    def succeed(source: str, destination: str, flags: int) -> tuple[bool, int]:
        observed.append((source, destination, flags))
        return True, 0

    monkeypatch.setattr(atomic_module, "_call_windows_move_file_ex", succeed)

    atomic_module._windows_replace(Path("source.tmp"), Path("report.json"))

    assert observed == [(
        "source.tmp",
        "report.json",
        atomic_module._MOVEFILE_REPLACE_EXISTING | atomic_module._MOVEFILE_WRITE_THROUGH,
    )]


def test_windows_replace_propagates_the_captured_last_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = OSError(errno.EACCES, "injected MoveFileExW failure", "report.json")
    observed_errors: list[tuple[int, Path]] = []
    monkeypatch.setattr(
        atomic_module,
        "_call_windows_move_file_ex",
        lambda source, destination, flags: (False, 1234),
    )

    def make_error(error_code: int, path: Path) -> OSError:
        observed_errors.append((error_code, path))
        return expected

    monkeypatch.setattr(atomic_module, "_windows_os_error", make_error)

    with pytest.raises(OSError) as exc_info:
        atomic_module._windows_replace(Path("source.tmp"), Path("report.json"))

    assert exc_info.value is expected
    assert observed_errors == [(1234, Path("report.json"))]


@pytest.mark.skipif(os.name != "nt", reason="WinError mapping is Windows-specific")
def test_windows_error_preserves_winerror_mapping_and_destination() -> None:
    destination = Path("report.json")

    error = atomic_module._windows_os_error(5, destination)

    assert isinstance(error, PermissionError)
    assert error.errno == errno.EACCES
    assert getattr(error, "winerror", None) == 5
    assert error.filename == str(destination)


def test_post_replace_fsync_failure_reports_committed_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    atomic_write_bytes(target, b"before")

    def fail_fsync(directory: Path) -> None:
        raise OSError(errno.EIO, "injected directory fsync failure", str(directory))

    monkeypatch.setattr(atomic_module, "_fsync_parent_directory", fail_fsync)

    with pytest.raises(AtomicCommitError, match="committed") as exc_info:
        atomic_write_bytes(target, b"after")

    assert exc_info.value.operation == "replace"
    assert isinstance(exc_info.value.cause, OSError)
    assert target.read_bytes() == b"after"


def test_publish_detects_immediate_single_link_identity_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    attacker = tmp_path / "attacker.bin"
    attacker.write_bytes(b"attacker")
    original_replace = atomic_module._replace_path

    def publish_then_swap(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        original_replace(source, Path(destination))
        os.replace(attacker, destination)

    monkeypatch.setattr(atomic_module, "_replace_path", publish_then_swap)

    with pytest.raises(AtomicCommitError, match="committed") as exc_info:
        atomic_write_bytes(target, b"payload")

    assert exc_info.value.operation == "replace"
    assert isinstance(exc_info.value.cause, UnsafePathError)
    assert "prepared temporary file" in str(exc_info.value.cause)
    assert target.read_bytes() == b"attacker"
    assert not list(tmp_path.glob(f"{target.name}.*.tmp"))


def test_refresh_updates_timestamp_through_the_verified_open_handle(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    created = atomic_create_or_refresh_bytes(target, b"payload", lambda _: None)
    assert created
    os.utime(target, (1, 1))

    created = atomic_create_or_refresh_bytes(target, b"unused", lambda value: value)

    assert not created
    assert target.stat().st_mtime > 1
    assert target.read_bytes() == b"payload"


def test_hard_link_payload_is_rejected_by_read_write_and_unlink(tmp_path: Path) -> None:
    attacker_file = tmp_path / "attacker.bin"
    target = tmp_path / "payload.bin"
    attacker_file.write_bytes(b"attacker")
    try:
        os.link(attacker_file, target)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        atomic_read_bytes(target)
    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"replacement")
    with pytest.raises(UnsafePathError):
        atomic_unlink_if(target, lambda _: True)

    assert attacker_file.read_bytes() == b"attacker"
    assert target.exists()


def test_payload_symlink_swap_before_open_normalizes_eloop_to_unsafe_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    outside = tmp_path / "outside.bin"
    atomic_write_bytes(target, b"payload")
    outside.write_bytes(b"outside")
    original_open = atomic_module.os.open
    swapped = False

    def swap_before_open(path: Path, flags: int, mode: int = 0o777) -> int:
        nonlocal swapped
        if Path(path) == target and not swapped:
            swapped = True
            target.unlink()
            _make_symlink(target, outside)
            raise OSError(errno.ELOOP, "injected no-follow rejection", str(path))
        return original_open(path, flags, mode)

    monkeypatch.setattr(atomic_module.os, "open", swap_before_open)

    with pytest.raises(UnsafePathError, match="became a symbolic link") as exc_info:
        atomic_read_bytes(target)

    assert isinstance(exc_info.value.__cause__, OSError)
    assert outside.read_bytes() == b"outside"


def test_directory_payload_is_rejected_by_read_write_and_unlink(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    target.mkdir()

    with pytest.raises(UnsafePathError):
        atomic_read_bytes(target)
    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"replacement")
    with pytest.raises(UnsafePathError):
        atomic_unlink_if(target, lambda _: True)

    assert target.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="FIFOs are a POSIX filesystem primitive")
def test_fifo_payload_is_rejected_without_blocking(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    os.mkfifo(target)
    started = time.monotonic()

    with pytest.raises(UnsafePathError):
        atomic_read_bytes(target)
    with pytest.raises(UnsafePathError):
        atomic_write_bytes(target, b"replacement")

    assert time.monotonic() - started < 2


@pytest.mark.skipif(os.name == "nt", reason="POSIX permits replacing an open file")
def test_unlink_revalidates_identity_after_the_handle_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    replacement = tmp_path / "replacement.bin"
    backup = tmp_path / "backup.bin"
    atomic_write_bytes(target, b"original")
    replacement.write_bytes(b"replacement")
    original_verify = atomic_module._verify_regular_identity
    calls = 0

    def verify_then_swap(path: Path, file_descriptor: int) -> os.stat_result:
        nonlocal calls
        metadata = original_verify(path, file_descriptor)
        if path == target:
            calls += 1
            if calls == 3:
                target.replace(backup)
                replacement.replace(target)
        return metadata

    monkeypatch.setattr(atomic_module, "_verify_regular_identity", verify_then_swap)

    with pytest.raises(UnsafePathError, match="changed before unlink"):
        atomic_unlink_if(target, lambda _: True)

    assert target.read_bytes() == b"replacement"
    assert backup.read_bytes() == b"original"


def test_successful_unlink_fsyncs_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    atomic_write_bytes(target, b"payload")
    synced: list[Path] = []
    original_fsync_parent = atomic_module._fsync_parent_directory

    def track_fsync(directory: Path) -> None:
        synced.append(directory)
        original_fsync_parent(directory)

    monkeypatch.setattr(atomic_module, "_fsync_parent_directory", track_fsync)

    assert atomic_unlink_if(target, lambda _: True)
    assert synced == [tmp_path]
    assert not target.exists()


def test_post_unlink_fsync_failure_reports_committed_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.bin"
    atomic_write_bytes(target, b"payload")

    def fail_fsync(directory: Path) -> None:
        raise OSError(errno.EIO, "injected directory fsync failure", str(directory))

    monkeypatch.setattr(atomic_module, "_fsync_parent_directory", fail_fsync)

    with pytest.raises(AtomicCommitError, match="committed") as exc_info:
        atomic_unlink_if(target, lambda _: True)

    assert exc_info.value.operation == "unlink"
    assert isinstance(exc_info.value.cause, OSError)
    assert not target.exists()
