"""Small cross-process atomic file-write helpers used by persistent stores."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from typing import BinaryIO, Literal

_LOCK_SHARD_COUNT = 64
_LOCK_FILE_PREFIX = ".bundleinspector-lock-"
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008


class _PathLockState(threading.local):
    active_path: Path | None = None


_PATH_LOCK_STATE = _PathLockState()


class UnsafePathError(OSError):
    """A persistent path failed the no-link, regular-file safety contract."""


class AtomicLockReentryError(RuntimeError):
    """An atomic callback attempted to acquire a second path lock on the same thread."""


class AtomicCommitError(OSError):
    """A namespace change committed before post-commit verification or durability failed."""

    def __init__(
        self,
        path: Path,
        *,
        operation: Literal["replace", "unlink"],
        cause: Exception,
    ) -> None:
        error_number = cause.errno if isinstance(cause, OSError) and cause.errno else errno.EIO
        super().__init__(
            error_number,
            f"atomic {operation} committed but post-commit processing failed: {cause}",
            str(path),
        )
        self.operation = operation
        self.cause = cause


def _call_windows_move_file_ex(
    source: str,
    destination: str,
    flags: int,
) -> tuple[bool, int]:
    """Call MoveFileExW and return its success state plus the captured last-error code."""
    import ctypes
    from ctypes import wintypes

    move_file_ex = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file_ex.restype = wintypes.BOOL
    succeeded = bool(move_file_ex(source, destination, flags))
    return succeeded, 0 if succeeded else ctypes.get_last_error()


def _windows_os_error(error_code: int, path: Path) -> OSError:
    import ctypes

    error = ctypes.WinError(error_code)
    error.filename = str(path)
    return error


def _windows_replace(source: str | Path, destination: Path) -> None:
    flags = _MOVEFILE_REPLACE_EXISTING | _MOVEFILE_WRITE_THROUGH
    succeeded, error_code = _call_windows_move_file_ex(
        os.fspath(source),
        os.fspath(destination),
        flags,
    )
    if not succeeded:
        raise _windows_os_error(error_code, destination)


def _replace_path(source: str | Path, destination: Path) -> None:
    if os.name == "nt":
        _windows_replace(source, destination)
        return
    os.replace(source, destination)


def _windows_file_lock(handle: BinaryIO, *, unlock: bool = False) -> None:
    """Acquire or release a blocking one-byte Windows file lock."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    overlapped = Overlapped()
    os_handle = wintypes.HANDLE(msvcrt.get_osfhandle(handle.fileno()))
    if unlock:
        operation = kernel32.UnlockFileEx
        operation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(Overlapped),
        ]
        operation.restype = wintypes.BOOL
        succeeded = operation(os_handle, 0, 1, 0, ctypes.byref(overlapped))
    else:
        operation = kernel32.LockFileEx
        operation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(Overlapped),
        ]
        operation.restype = wintypes.BOOL
        succeeded = operation(os_handle, 0x00000002, 0, 1, 0, ctypes.byref(overlapped))
    if not succeeded:
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))


def _lock_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        _windows_file_lock(handle)
        return

    fcntl = import_module("fcntl")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        _windows_file_lock(handle, unlock=True)
        return

    fcntl = import_module("fcntl")
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_only_lock_fallback_allowed(error: OSError) -> bool:
    return isinstance(error, PermissionError) or error.errno in {
        errno.EACCES,
        errno.EPERM,
        errno.EROFS,
    }


def _lock_path(path: Path) -> Path:
    """Map a payload to one of a bounded number of deterministic sibling lock shards."""
    canonical_name = path.name.casefold().encode("utf-8", "surrogatepass")
    digest = hashlib.blake2s(canonical_name, digest_size=2).digest()
    shard = int.from_bytes(digest, "big") % _LOCK_SHARD_COUNT
    return path.parent / f"{_LOCK_FILE_PREFIX}{shard:02x}"


def _unsafe_path_error(path: Path, kind: str, reason: str) -> UnsafePathError:
    return UnsafePathError(errno.EINVAL, f"unsafe {kind}: {reason}", str(path))


def _is_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _validate_regular_stat(metadata: os.stat_result, path: Path, *, kind: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise _unsafe_path_error(path, kind, "path is not a regular file")
    if _is_reparse_point(metadata):
        raise _unsafe_path_error(path, kind, "path is a symbolic link or junction")
    if metadata.st_nlink != 1:
        raise _unsafe_path_error(path, kind, "path link count is not one")


def _validate_lock_stat(metadata: os.stat_result, path: Path) -> None:
    _validate_regular_stat(metadata, path, kind="lock sidecar")


def _unsafe_open_failure(
    path: Path,
    *,
    kind: str,
    error: OSError,
) -> UnsafePathError | None:
    """Classify an open failure as unsafe only when no-follow or current metadata proves it."""
    if error.errno == errno.ELOOP:
        return _unsafe_path_error(path, kind, "path became a symbolic link before open")
    try:
        metadata = os.lstat(path)
    except OSError:
        return None
    try:
        _validate_regular_stat(metadata, path, kind=kind)
    except UnsafePathError as unsafe:
        return unsafe
    return None


def _validate_existing_lock_path(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    _validate_lock_stat(metadata, path)


def _verify_lock_identity(path: Path, file_descriptor: int) -> None:
    opened = os.fstat(file_descriptor)
    _validate_lock_stat(opened, path)
    try:
        current = os.lstat(path)
    except FileNotFoundError as exc:
        raise _unsafe_path_error(path, "lock sidecar", "path disappeared after open") from exc
    _validate_lock_stat(current, path)
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise _unsafe_path_error(
            path,
            "lock sidecar",
            "opened file no longer matches its path",
        )


def _open_lock_handle(
    path: Path,
    *,
    writable: bool,
    create: bool,
) -> BinaryIO:
    _validate_existing_lock_path(path)
    flags = os.O_RDWR if writable else os.O_RDONLY
    if create:
        flags |= os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        unsafe = _unsafe_open_failure(path, kind="lock sidecar", error=exc)
        if unsafe is not None:
            raise unsafe from exc
        raise
    try:
        _verify_lock_identity(path, file_descriptor)
        return os.fdopen(file_descriptor, "r+b" if writable else "rb")
    except BaseException:
        os.close(file_descriptor)
        raise


def _verify_regular_identity(path: Path, file_descriptor: int) -> os.stat_result:
    opened = os.fstat(file_descriptor)
    _validate_regular_stat(opened, path, kind="persistent file")
    try:
        current = os.lstat(path)
    except FileNotFoundError as exc:
        raise _unsafe_path_error(
            path,
            "persistent file",
            "path disappeared after open",
        ) from exc
    _validate_regular_stat(current, path, kind="persistent file")
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise _unsafe_path_error(
            path,
            "persistent file",
            "opened file no longer matches its path",
        )
    return opened


def _open_existing_regular_handle(path: Path, *, writable: bool = False) -> BinaryIO:
    metadata = os.lstat(path)
    _validate_regular_stat(metadata, path, kind="persistent file")
    flags = os.O_RDWR if writable else os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(path, flags)
    except OSError as exc:
        unsafe = _unsafe_open_failure(path, kind="persistent file", error=exc)
        if unsafe is not None:
            raise unsafe from exc
        raise
    try:
        _verify_regular_identity(path, file_descriptor)
        return os.fdopen(file_descriptor, "r+b" if writable else "rb")
    except BaseException:
        os.close(file_descriptor)
        raise


def _read_existing_regular_bytes(path: Path) -> bytes:
    with _open_existing_regular_handle(path) as handle:
        payload = handle.read()
        _verify_regular_identity(path, handle.fileno())
        return payload


def _touch_open_file(handle: BinaryIO) -> None:
    if os.name != "nt":
        os.utime(handle.fileno())
        return

    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    now = FileTime()
    kernel32.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(FileTime)]
    kernel32.GetSystemTimeAsFileTime.restype = None
    kernel32.SetFileTime.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
    ]
    kernel32.SetFileTime.restype = wintypes.BOOL
    kernel32.GetSystemTimeAsFileTime(ctypes.byref(now))
    os_handle = wintypes.HANDLE(msvcrt.get_osfhandle(handle.fileno()))
    if not kernel32.SetFileTime(os_handle, None, ctypes.byref(now), ctypes.byref(now)):
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))


def _set_private_mode(file_descriptor: int, path: Path) -> None:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(file_descriptor, 0o600)
        return
    if os.name != "nt":
        raise OSError(errno.ENOSYS, "file-descriptor chmod is unavailable")

    # CPython 3.10 on Windows has no os.fchmod. The mkstemp handle remains open,
    # which prevents rename-based swaps on Windows; verify identity around the
    # only supported pre-publication chmod fallback as an additional guard.
    _verify_regular_identity(path, file_descriptor)
    os.chmod(path, 0o600)
    _verify_regular_identity(path, file_descriptor)


def is_safe_regular_file(path: Path) -> bool:
    """Return whether *path* currently names one non-linked regular file."""
    try:
        metadata = os.lstat(path)
        _validate_regular_stat(metadata, path, kind="persistent file")
    except OSError:
        return False
    return True


def ensure_safe_directory(path: Path) -> Path:
    """Create *path* if needed and return its verified, non-reparse resolved path."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        # A dangling link or non-directory final entry is still inspectable by
        # lstat and should be reported as an explicit unsafe storage path.
        pass
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise _unsafe_path_error(
            path,
            "storage directory",
            "path is a symbolic link or junction",
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise _unsafe_path_error(path, "storage directory", "path is not a directory")
    return path.resolve(strict=True)


def _open_lock_with_fallback(path: Path, *, read_only_fallback: bool) -> BinaryIO:
    """Open a still-exclusively-locked local-cache sidecar, with no unlocked fallback."""
    try:
        return _open_lock_handle(path, writable=True, create=True)
    except OSError as exc:
        if not read_only_fallback or not _read_only_lock_fallback_allowed(exc):
            raise
    # Never create an unlocked read-only sidecar: it must have been provisioned
    # by an earlier cooperating writer and pass the same identity checks.
    return _open_lock_handle(path, writable=False, create=False)


@contextmanager
def _path_lock(path: Path, *, read_only_fallback: bool = False) -> Iterator[None]:
    """Serialize cooperating operations for *path* across threads and processes."""
    lock_path = _lock_path(path)
    active_path = _PATH_LOCK_STATE.active_path
    if active_path is not None:
        raise AtomicLockReentryError(
            f"nested atomic path locks are not allowed: {active_path} -> {lock_path}"
        )
    _PATH_LOCK_STATE.active_path = lock_path
    try:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            if not read_only_fallback or not _read_only_lock_fallback_allowed(exc):
                raise
            lock_handle = _open_lock_handle(lock_path, writable=False, create=False)
        else:
            lock_handle = _open_lock_with_fallback(
                lock_path,
                read_only_fallback=read_only_fallback,
            )
        with lock_handle:
            _lock_file(lock_handle)
            try:
                _verify_lock_identity(lock_path, lock_handle.fileno())
                yield
            except BaseException:
                raise
            else:
                _verify_lock_identity(lock_path, lock_handle.fileno())
            finally:
                _unlock_file(lock_handle)
    finally:
        _PATH_LOCK_STATE.active_path = None


def _replace_with_writer(path: Path, writer: Callable[[BinaryIO], None]) -> None:
    """Prepare, sync and replace *path*; callers choose whether serialization is required."""
    tmp_name = ""
    temporary_stat: os.stat_result | None = None
    try:
        try:
            existing = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            _validate_regular_stat(existing, path, kind="persistent file")
        fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "wb") as handle:
            writer(handle)
            handle.flush()
            _set_private_mode(handle.fileno(), Path(tmp_name))
            os.fsync(handle.fileno())
            temporary_stat = os.fstat(handle.fileno())
            _validate_regular_stat(temporary_stat, Path(tmp_name), kind="temporary file")
        try:
            existing = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            _validate_regular_stat(existing, path, kind="persistent file")
        _replace_path(tmp_name, path)
        try:
            published = os.lstat(path)
            _validate_regular_stat(published, path, kind="persistent file")
            if temporary_stat is None or (
                temporary_stat.st_dev,
                temporary_stat.st_ino,
            ) != (published.st_dev, published.st_ino):
                raise _unsafe_path_error(
                    path,
                    "persistent file",
                    "published file does not match the prepared temporary file",
                )
            _fsync_parent_directory(path.parent)
        except Exception as exc:
            raise AtomicCommitError(path, operation="replace", cause=exc) from exc
    finally:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass


def _fsync_parent_directory(directory: Path) -> None:
    """Persist a directory entry after replace on POSIX when the filesystem supports it."""
    if os.name == "nt":
        return
    unsupported = {
        errno.EBADF,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(directory, flags)
    except OSError as exc:
        if exc.errno in unsupported:
            return
        raise
    try:
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            if exc.errno not in unsupported:
                raise
    finally:
        os.close(directory_fd)


def _write_payload_locked(path: Path, payload: bytes) -> None:
    def write(handle: BinaryIO) -> None:
        handle.write(payload)

    _replace_with_writer(path, write)


def _atomic_write(path: Path, writer: Callable[[BinaryIO], None]) -> None:
    with _path_lock(path):
        _replace_with_writer(path, writer)


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Serialize writers and atomically replace *path* with binary payload."""

    def write(handle: BinaryIO) -> None:
        handle.write(payload)

    _atomic_write(path, write)


def atomic_write_text(path: Path, payload: str) -> None:
    """Serialize writers and atomically replace *path* with UTF-8 text."""
    atomic_write_bytes(path, payload.encode("utf-8"))


def atomic_publish_bytes(path: Path, payload: bytes) -> None:
    """Publish one complete output without a persistent lock sidecar.

    Concurrent publishers are whole-file, last-completed-writer wins. This is intended for
    one-shot user outputs, not shared mutable storage that requires cross-process serialization.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_payload_locked(path, payload)


def atomic_publish_text(path: Path, payload: str) -> None:
    """Publish one UTF-8 output atomically without a persistent lock sidecar."""
    atomic_publish_bytes(path, payload.encode("utf-8"))


def atomic_read_bytes(path: Path) -> bytes:
    """Read *path* without racing a cooperating Windows replacement."""
    with _path_lock(path, read_only_fallback=True):
        return _read_existing_regular_bytes(path)


def atomic_read_text(path: Path) -> str:
    """Read a UTF-8 file without racing a cooperating replacement."""
    return atomic_read_bytes(path).decode("utf-8")


def atomic_update_bytes(
    path: Path,
    update: Callable[[bytes], bytes | None],
) -> bytes:
    """Atomically read and optionally replace *path* under one exclusive lock.

    The callback runs while the cross-process lock is held. Returning ``None``
    preserves the current bytes; otherwise the replacement is fsynced and
    atomically installed. The resulting snapshot is returned in either case.
    """
    with _path_lock(path, read_only_fallback=True):
        current = _read_existing_regular_bytes(path)
        replacement = update(current)
        if replacement is None:
            return current
        _write_payload_locked(path, replacement)
        return replacement


def _create_or_validate_locked(
    path: Path,
    payload: bytes,
    validate_existing: Callable[[bytes], None],
    *,
    refresh_existing: bool,
) -> bool:
    try:
        existing_handle = _open_existing_regular_handle(path, writable=refresh_existing)
    except FileNotFoundError:
        _write_payload_locked(path, payload)
        return True
    with existing_handle:
        current = existing_handle.read()
        _verify_regular_identity(path, existing_handle.fileno())
        validate_existing(current)
        if refresh_existing:
            _touch_open_file(existing_handle)
            _verify_regular_identity(path, existing_handle.fileno())
        return False


def atomic_create_or_validate_bytes(
    path: Path,
    payload: bytes,
    validate_existing: Callable[[bytes], None],
) -> bool:
    """Create a complete file or validate the existing snapshot under one path lock."""
    with _path_lock(path):
        return _create_or_validate_locked(
            path,
            payload,
            validate_existing,
            refresh_existing=False,
        )


def atomic_create_or_refresh_bytes(
    path: Path,
    payload: bytes,
    validate_existing: Callable[[bytes], None],
) -> bool:
    """Create *path* or validate and refresh its existing contents atomically."""
    with _path_lock(path):
        return _create_or_validate_locked(
            path,
            payload,
            validate_existing,
            refresh_existing=True,
        )


def atomic_unlink_if(path: Path, predicate: Callable[[os.stat_result], bool]) -> bool:
    """Delete *path* only when its locked, current stat satisfies *predicate*."""
    with _path_lock(path):
        try:
            handle = _open_existing_regular_handle(path)
        except FileNotFoundError:
            return False
        with handle:
            current_stat = _verify_regular_identity(path, handle.fileno())
            if not predicate(current_stat):
                return False
            _verify_regular_identity(path, handle.fileno())
        # Windows cannot unlink a CRT-open file. Revalidate immediately after close;
        # a hostile writer with parent-directory access remains outside the cooperative contract.
        try:
            current_path_stat = os.lstat(path)
        except FileNotFoundError:
            return False
        _validate_regular_stat(current_path_stat, path, kind="persistent file")
        if (current_stat.st_dev, current_stat.st_ino) != (
            current_path_stat.st_dev,
            current_path_stat.st_ino,
        ):
            raise _unsafe_path_error(
                path,
                "persistent file",
                "file changed before unlink",
            )
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        try:
            _fsync_parent_directory(path.parent)
        except Exception as exc:
            raise AtomicCommitError(path, operation="unlink", cause=exc) from exc
        return True


def load_or_create_key(path: Path, *, length: int = 32) -> bytes:
    """Load or create a fixed-size key under the same cross-process lock discipline."""
    with _path_lock(path, read_only_fallback=True):
        try:
            key = _read_existing_regular_bytes(path)
        except FileNotFoundError:
            key = os.urandom(length)
            _write_payload_locked(path, key)
            return key
        else:
            if len(key) != length:
                raise ValueError("invalid encryption key length")
            return key
