"""Fail-closed verification for BundleInspector wheel and sdist contents."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

SCHEMA_VERSION = 1
MAX_ARCHIVE_MEMBERS = 4_096
MAX_ARCHIVE_SIZE = 512 * 1024 * 1024
MAX_CENTRAL_DIRECTORY_SIZE = 16 * 1024 * 1024
MAX_MANIFEST_SIZE = 2 * 1024 * 1024
MAX_MEMBER_SIZE = 64 * 1024 * 1024
MAX_TOTAL_SIZE = 256 * 1024 * 1024
MAX_TAR_PADDING = 1024 * 1024
MAX_TAR_STREAM_SIZE = MAX_TOTAL_SIZE + (MAX_ARCHIVE_MEMBERS * 2048) + MAX_TAR_PADDING
_IO_CHUNK_SIZE = 1024 * 1024
_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_WINDOWS_RESERVED = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_TEXT_SUFFIXES = {
    ".js",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".pyi",
    ".sha256",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".typed",
    ".yaml",
    ".yml",
}
_NAME_ONLY_FILES = {".gitignore", "license", "metadata", "pkg-info", "record", "wheel"}
_REVIEWED_BINARY_PATHS = {"tests/heldout/frozen-governance.zip"}
_REVIEWED_CHECKSUM_PATHS = {"tests/heldout/frozen-governance.sha256"}


class DistributionVerificationError(ValueError):
    """The manifest or an archive violates the reviewed distribution contract."""


@dataclass(frozen=True)
class ArchivePolicy:
    filename: str
    files: tuple[str, ...]
    directories: tuple[str, ...] = ()


@dataclass(frozen=True)
class DistributionManifest:
    normalized_name: str
    version: str
    wheel: ArchivePolicy
    sdist: ArchivePolicy
    sdist_root: str
    sdist_root_directory: bool


def _fail(message: str) -> DistributionVerificationError:
    return DistributionVerificationError(message)


def _reject_json_constant(value: str) -> None:
    raise _fail(f"manifest contains non-finite JSON value {value}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail(f"manifest contains duplicate key {key!r}")
        result[key] = value
    return result


def _expect_object(value: object, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"{context} must be a JSON object")
    actual = set(value)
    if actual != keys:
        raise _fail(
            f"{context} keys differ: missing={sorted(keys - actual)!r}, "
            f"unexpected={sorted(actual - keys)!r}"
        )
    if not all(isinstance(key, str) for key in value):
        raise _fail(f"{context} keys must be strings")
    return value


def _expect_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise _fail(f"{context} must be a non-empty string")
    return value


def _expect_bool(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise _fail(f"{context} must be a JSON boolean")
    return value


def _collision_key(path: str) -> str:
    return unicodedata.normalize("NFKC", path).casefold()


def _validate_archive_path(path: str, context: str) -> str:
    if not path or path != unicodedata.normalize("NFC", path):
        raise _fail(f"{context} is empty or not NFC-normalized: {path!r}")
    if path.startswith("/") or "\\" in path or "\x00" in path:
        raise _fail(f"{context} is not a relative POSIX path: {path!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise _fail(f"{context} contains a control character: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _fail(f"{context} contains an empty or traversal component: {path!r}")
    for part in parts:
        if part.endswith((" ", ".")) or any(character in '<>:"|?*' for character in part):
            raise _fail(f"{context} contains a non-portable component: {path!r}")
        basename = part.split(".", 1)[0].casefold()
        if basename in _WINDOWS_RESERVED:
            raise _fail(f"{context} contains a reserved component: {path!r}")
    return path


def _validate_sensitive_path(path: str, context: str) -> None:
    lowered_parts = tuple(part.casefold() for part in path.split("/"))
    if any(part == ".env" or part.startswith(".env.") for part in lowered_parts):
        raise _fail(f"{context} contains a forbidden environment file: {path!r}")


def _validate_payload_path(path: str, context: str) -> None:
    _validate_sensitive_path(path, context)
    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    suffix = PurePosixPath(lowered).suffix
    if name in _NAME_ONLY_FILES:
        return
    if suffix == ".zip" and lowered not in _REVIEWED_BINARY_PATHS:
        raise _fail(f"{context} contains an unreviewed binary archive: {path!r}")
    if suffix == ".sha256" and lowered not in _REVIEWED_CHECKSUM_PATHS:
        raise _fail(f"{context} contains an unreviewed checksum artifact: {path!r}")
    if suffix not in _TEXT_SUFFIXES and lowered not in _REVIEWED_BINARY_PATHS:
        raise _fail(f"{context} contains an unreviewed file type: {path!r}")


def _validate_paths(value: object, context: str, *, payloads: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _fail(f"{context} must be a sorted JSON string array")
    paths = tuple(value)
    if list(paths) != sorted(paths):
        raise _fail(f"{context} must be sorted exactly")
    seen: set[str] = set()
    aliases: dict[str, str] = {}
    for path in paths:
        _validate_archive_path(path, context)
        if payloads:
            _validate_payload_path(path, context)
        else:
            _validate_sensitive_path(path, context)
        if path in seen:
            raise _fail(f"{context} contains duplicate path {path!r}")
        alias = _collision_key(path)
        previous = aliases.get(alias)
        if previous is not None:
            raise _fail(f"{context} contains portable path collision {previous!r} / {path!r}")
        seen.add(path)
        aliases[alias] = path
    return paths


def load_manifest(path: Path) -> DistributionManifest:
    try:
        with _open_reviewed_file(path, "manifest", MAX_MANIFEST_SIZE) as source:
            encoded = source.read(MAX_MANIFEST_SIZE + 1)
        raw = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise _fail("manifest is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise _fail("manifest is not valid strict JSON") from exc
    except RecursionError as exc:
        raise _fail("manifest nesting exceeds the release bound") from exc
    root = _expect_object(raw, {"distribution", "schema_version", "sdist", "wheel"}, "manifest")
    if type(root["schema_version"]) is not int or root["schema_version"] != SCHEMA_VERSION:
        raise _fail(f"manifest schema_version must be exactly {SCHEMA_VERSION}")
    distribution = _expect_object(
        root["distribution"], {"normalized_name", "version"}, "manifest.distribution"
    )
    wheel = _expect_object(root["wheel"], {"filename", "files"}, "manifest.wheel")
    sdist = _expect_object(
        root["sdist"],
        {"directories", "filename", "files", "root", "root_directory"},
        "manifest.sdist",
    )
    normalized_name = _expect_string(distribution["normalized_name"], "normalized_name")
    version = _expect_string(distribution["version"], "version")
    sdist_root = _validate_archive_path(_expect_string(sdist["root"], "sdist.root"), "sdist.root")
    if "/" in sdist_root:
        raise _fail("sdist.root must be one portable path component")
    wheel_files = _validate_paths(wheel["files"], "manifest.wheel.files", payloads=True)
    sdist_files = _validate_paths(sdist["files"], "manifest.sdist.files", payloads=True)
    sdist_directories = _validate_paths(
        sdist["directories"], "manifest.sdist.directories", payloads=False
    )
    overlap = set(sdist_files) & set(sdist_directories)
    if overlap:
        raise _fail(f"sdist file/directory paths overlap: {sorted(overlap)!r}")
    combined_aliases: dict[str, str] = {}
    for member in (*sdist_files, *sdist_directories):
        alias = _collision_key(member)
        previous = combined_aliases.get(alias)
        if previous is not None:
            raise _fail(f"sdist paths collide portably: {previous!r} / {member!r}")
        combined_aliases[alias] = member
    return DistributionManifest(
        normalized_name=normalized_name,
        version=version,
        wheel=ArchivePolicy(
            filename=_expect_string(wheel["filename"], "wheel.filename"),
            files=wheel_files,
        ),
        sdist=ArchivePolicy(
            filename=_expect_string(sdist["filename"], "sdist.filename"),
            files=sdist_files,
            directories=sdist_directories,
        ),
        sdist_root=sdist_root,
        sdist_root_directory=_expect_bool(sdist["root_directory"], "sdist.root_directory"),
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


@contextlib.contextmanager
def _open_reviewed_file(path: Path, role: str, maximum_size: int) -> Iterator[BinaryIO]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise _fail(f"{role} artifact is unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise _fail(f"{role} artifact must be a regular, single-link, non-reparse file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _fail(f"{role} artifact cannot be opened without following links") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _is_reparse(opened)
            or not _same_file(before, opened)
        ):
            raise _fail(f"{role} artifact identity changed while opening")
        if opened.st_size <= 0 or opened.st_size > maximum_size:
            raise _fail(f"{role} artifact physical size exceeds the release bound")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            yield source
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextlib.contextmanager
def _open_input_file(path: Path, expected_filename: str, role: str) -> Iterator[BinaryIO]:
    if path.name != expected_filename:
        raise _fail(f"{role} filename must be {expected_filename!r}, got {path.name!r}")
    with _open_reviewed_file(path, role, MAX_ARCHIVE_SIZE) as source:
        yield source


def _record_member_path(
    path: str,
    *,
    context: str,
    exact: set[str],
    aliases: dict[str, str],
) -> None:
    _validate_archive_path(path, context)
    if path in exact:
        raise _fail(f"{context} contains duplicate path {path!r}")
    alias = _collision_key(path)
    previous = aliases.get(alias)
    if previous is not None:
        raise _fail(f"{context} contains portable path collision {previous!r} / {path!r}")
    exact.add(path)
    aliases[alias] = path


def _compare_exact(actual: set[str], expected: tuple[str, ...], context: str) -> None:
    expected_set = set(expected)
    missing = sorted(expected_set - actual)
    unexpected = sorted(actual - expected_set)
    if missing or unexpected:
        raise _fail(
            f"{context} member set differs: missing={missing[:20]!r}, "
            f"unexpected={unexpected[:20]!r}"
        )


def _verify_wheel_container(source: BinaryIO) -> tuple[int, int]:
    source.seek(0, os.SEEK_END)
    physical_size = source.tell()
    if physical_size < _ZIP_EOCD.size:
        raise _fail("wheel is too short to contain an end-of-central-directory record")
    source.seek(0)
    if source.read(len(_ZIP_LOCAL_SIGNATURE)) != _ZIP_LOCAL_SIGNATURE:
        raise _fail("wheel must begin with a local-file header")
    source.seek(physical_size - _ZIP_EOCD.size)
    encoded = source.read(_ZIP_EOCD.size)
    if len(encoded) != _ZIP_EOCD.size:
        raise _fail("wheel end-of-central-directory record is truncated")
    (
        signature,
        disk_number,
        central_directory_disk,
        entries_on_disk,
        total_entries,
        central_directory_size,
        central_directory_offset,
        comment_size,
    ) = _ZIP_EOCD.unpack(encoded)
    if signature != _ZIP_EOCD_SIGNATURE or comment_size != 0:
        raise _fail("wheel EOCD must be the exact physical EOF with no archive comment")
    if disk_number != 0 or central_directory_disk != 0 or entries_on_disk != total_entries:
        raise _fail("wheel must be a single-disk ZIP archive")
    if total_entries == 0xFFFF or central_directory_size == 0xFFFFFFFF:
        raise _fail("wheel ZIP64 containers are outside the reviewed release bound")
    if central_directory_offset == 0xFFFFFFFF:
        raise _fail("wheel ZIP64 containers are outside the reviewed release bound")
    if total_entries > MAX_ARCHIVE_MEMBERS:
        raise _fail("wheel has too many members")
    if central_directory_size > MAX_CENTRAL_DIRECTORY_SIZE:
        raise _fail("wheel central directory exceeds the release bound")
    eocd_offset = physical_size - _ZIP_EOCD.size
    if central_directory_offset + central_directory_size != eocd_offset:
        raise _fail("wheel contains prepended, embedded, or trailing bytes outside the exact ZIP")
    source.seek(0)
    return total_entries, central_directory_offset


def _verify_wheel_local_layout(
    source: BinaryIO,
    members: list[zipfile.ZipInfo],
    central_directory_offset: int,
) -> None:
    expected_offset = 0
    for member in sorted(members, key=lambda item: item.header_offset):
        if member.header_offset != expected_offset:
            raise _fail("wheel contains an unreferenced prefix, local record, or data gap")
        if member.orig_filename != member.filename:
            raise _fail("wheel member name contains an embedded NUL byte")
        if member.extra or member.comment:
            raise _fail("wheel members must not carry unreviewed extra fields or comments")
        source.seek(member.header_offset)
        encoded_header = source.read(_ZIP_LOCAL_HEADER.size)
        if len(encoded_header) != _ZIP_LOCAL_HEADER.size:
            raise _fail(f"wheel local header is truncated: {member.filename!r}")
        (
            signature,
            _extract_version,
            flags,
            compression,
            _modified_time,
            _modified_date,
            crc,
            compressed_size,
            file_size,
            filename_size,
            extra_size,
        ) = _ZIP_LOCAL_HEADER.unpack(encoded_header)
        if signature != _ZIP_LOCAL_SIGNATURE:
            raise _fail(f"wheel local header signature is invalid: {member.filename!r}")
        if flags & 0x08:
            raise _fail("wheel data-descriptor records are outside the exact layout contract")
        if (
            flags != member.flag_bits
            or compression != member.compress_type
            or crc != member.CRC
            or compressed_size != member.compress_size
            or file_size != member.file_size
        ):
            raise _fail(f"wheel local and central headers differ: {member.filename!r}")
        encoded_name = source.read(filename_size)
        encoding = "utf-8" if flags & 0x800 else "cp437"
        try:
            local_name = encoded_name.decode(encoding)
        except UnicodeDecodeError as exc:
            raise _fail(f"wheel local member name is not valid {encoding}") from exc
        if local_name != member.orig_filename or extra_size != 0:
            raise _fail(f"wheel local member metadata differs: {member.filename!r}")
        expected_offset = source.tell() + member.compress_size
        if expected_offset > central_directory_offset:
            raise _fail(f"wheel member overlaps the central directory: {member.filename!r}")
    if expected_offset != central_directory_offset:
        raise _fail("wheel contains unreferenced bytes before the central directory")
    source.seek(0)


def verify_wheel(path: Path, policy: ArchivePolicy) -> None:
    try:
        with _open_input_file(path, policy.filename, "wheel") as source:
            container_entries, central_directory_offset = _verify_wheel_container(source)
            with zipfile.ZipFile(source, "r") as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise _fail("wheel has too many members")
                if container_entries != len(members):
                    raise _fail("wheel central-directory entry count is inconsistent")
                if archive.start_dir != central_directory_offset:
                    raise _fail("wheel central-directory offset is inconsistent")
                _verify_wheel_local_layout(source, members, central_directory_offset)
                actual: set[str] = set()
                aliases: dict[str, str] = {}
                total_size = 0
                for member in members:
                    name = member.filename
                    _record_member_path(name, context="wheel", exact=actual, aliases=aliases)
                    _validate_payload_path(name, "wheel")
                    if member.is_dir() or name.endswith("/"):
                        raise _fail(f"wheel member must be a regular file: {name!r}")
                    mode = (member.external_attr >> 16) & 0xFFFF
                    kind = stat.S_IFMT(mode)
                    if kind not in {0, stat.S_IFREG}:
                        raise _fail(f"wheel member has a special file type: {name!r}")
                    if member.flag_bits & 0x1:
                        raise _fail(f"wheel member is encrypted: {name!r}")
                    if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        raise _fail(f"wheel member uses an unreviewed compression method: {name!r}")
                    if member.file_size < 0 or member.file_size > MAX_MEMBER_SIZE:
                        raise _fail(f"wheel member size exceeds the release bound: {name!r}")
                    total_size += member.file_size
                    if total_size > MAX_TOTAL_SIZE:
                        raise _fail("wheel uncompressed size exceeds the release bound")
                _compare_exact(actual, policy.files, "wheel")
                corrupt = archive.testzip()
                if corrupt is not None:
                    raise _fail(f"wheel member failed CRC verification: {corrupt!r}")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise _fail("wheel is not a readable ZIP archive") from exc


def _read_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> None:
    source = archive.extractfile(member)
    if source is None:
        raise _fail(f"sdist regular member cannot be read: {member.name!r}")
    read_size = 0
    with source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            read_size += len(chunk)
            if read_size > member.size:
                raise _fail(f"sdist member expands beyond its header size: {member.name!r}")
    if read_size != member.size:
        raise _fail(f"sdist member is truncated: {member.name!r}")


def _verify_single_gzip_stream(source: BinaryIO) -> None:
    source.seek(0)
    decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
    expanded_size = 0
    stream_finished = False
    try:
        while not stream_finished:
            chunk = source.read(_IO_CHUNK_SIZE)
            if not chunk:
                break
            pending = chunk
            while pending:
                previous_size = len(pending)
                expanded = decompressor.decompress(pending, _IO_CHUNK_SIZE)
                expanded_size += len(expanded)
                if expanded_size > MAX_TAR_STREAM_SIZE:
                    raise _fail("sdist expanded tar stream exceeds the release bound")
                if decompressor.eof:
                    if decompressor.unused_data or source.read(1):
                        raise _fail("sdist must contain exactly one gzip stream at physical EOF")
                    stream_finished = True
                    break
                pending = decompressor.unconsumed_tail
                if pending and len(pending) == previous_size and not expanded:
                    raise _fail("sdist gzip stream made no decompression progress")
        if not stream_finished or not decompressor.eof:
            raise _fail("sdist gzip stream is truncated")
    except zlib.error as exc:
        raise _fail("sdist is not a valid gzip stream") from exc
    finally:
        source.seek(0)


def _verify_tar_logical_eof(archive: tarfile.TarFile, expected_offset: int) -> None:
    fileobj = archive.fileobj
    if fileobj is None:
        raise _fail("sdist tar stream is unavailable for EOF verification")
    fileobj.seek(expected_offset)
    tail = fileobj.read(MAX_TAR_PADDING + 1)
    if len(tail) < 1024 or len(tail) > MAX_TAR_PADDING:
        raise _fail("sdist tar EOF padding is missing or exceeds the release bound")
    if len(tail) % tarfile.BLOCKSIZE != 0 or any(tail):
        raise _fail("sdist contains non-zero data after the logical tar EOF")


def _verify_tar_member_layout(member: tarfile.TarInfo, expected_offset: int) -> int:
    if (
        member.offset != expected_offset
        or member.offset_data != member.offset + tarfile.BLOCKSIZE
        or member.pax_headers
    ):
        raise _fail(f"sdist contains a hidden metadata header or data gap: {member.name!r}")
    if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
        raise _fail(f"sdist member has an unreviewed raw tar type: {member.name!r}")
    payload_blocks = 0
    if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
        payload_blocks = (member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
    return member.offset_data + (payload_blocks * tarfile.BLOCKSIZE)


def verify_sdist(
    path: Path,
    policy: ArchivePolicy,
    expected_root: str,
    expected_root_directory: bool = False,
) -> None:
    try:
        with _open_input_file(path, policy.filename, "sdist") as source:
            _verify_single_gzip_stream(source)
            with tarfile.open(fileobj=source, mode="r:gz") as archive:
                actual_files: set[str] = set()
                actual_directories: set[str] = set()
                exact: set[str] = set()
                aliases: dict[str, str] = {}
                total_size = 0
                member_count = 0
                expected_member_offset = 0
                root_directory_seen = False
                prefix = f"{expected_root}/"
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_MEMBERS:
                        raise _fail("sdist has too many members")
                    expected_member_offset = _verify_tar_member_layout(
                        member, expected_member_offset
                    )
                    full_name = member.name
                    _validate_archive_path(full_name, "sdist")
                    if full_name == expected_root:
                        if root_directory_seen:
                            raise _fail("sdist contains a duplicate top-level root directory")
                        if (
                            member.type != tarfile.DIRTYPE
                            or member.linkname
                            or member.size != 0
                            or member.mode & 0o7000
                        ):
                            raise _fail("sdist top-level root member must be a plain directory")
                        root_directory_seen = True
                        continue
                    if not full_name.startswith(prefix):
                        raise _fail(
                            f"sdist member is not beneath the single expected root {expected_root!r}: "
                            f"{full_name!r}"
                        )
                    relative = full_name[len(prefix) :]
                    _record_member_path(relative, context="sdist", exact=exact, aliases=aliases)
                    if member.linkname:
                        raise _fail(f"sdist member carries a link target: {full_name!r}")
                    if member.mode & 0o7000:
                        raise _fail(f"sdist member carries special permission bits: {full_name!r}")
                    if member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
                        _validate_payload_path(relative, "sdist")
                        if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                            raise _fail(
                                f"sdist member size exceeds the release bound: {full_name!r}"
                            )
                        total_size += member.size
                        if total_size > MAX_TOTAL_SIZE:
                            raise _fail("sdist uncompressed size exceeds the release bound")
                        actual_files.add(relative)
                        _read_tar_member(archive, member)
                    elif member.type == tarfile.DIRTYPE:
                        _validate_sensitive_path(relative, "sdist")
                        if member.size != 0:
                            raise _fail(f"sdist directory has a non-zero payload: {full_name!r}")
                        actual_directories.add(relative)
                    else:
                        raise _fail(
                            f"sdist member is not a regular file or directory: {full_name!r}"
                        )
                if archive.offset != expected_member_offset:
                    raise _fail("sdist tar parser offset differs from the exact member layout")
                _compare_exact(actual_files, policy.files, "sdist files")
                _compare_exact(actual_directories, policy.directories, "sdist directories")
                if root_directory_seen != expected_root_directory:
                    raise _fail(
                        "sdist top-level root directory presence differs from the exact manifest"
                    )
                _verify_tar_logical_eof(archive, expected_member_offset)
    except (OSError, tarfile.TarError) as exc:
        raise _fail("sdist is not a readable tar archive") from exc


def verify_distribution_artifacts(manifest_path: Path, wheel: Path, sdist: Path) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    verify_wheel(wheel, manifest.wheel)
    verify_sdist(
        sdist,
        manifest.sdist,
        manifest.sdist_root,
        manifest.sdist_root_directory,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "wheel": wheel.name,
        "wheel_file_count": len(manifest.wheel.files),
        "sdist": sdist.name,
        "sdist_directory_count": len(manifest.sdist.directories),
        "sdist_file_count": len(manifest.sdist.files),
        "passed": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sdist", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_distribution_artifacts(args.manifest, args.wheel, args.sdist)
    except (DistributionVerificationError, OSError) as exc:
        parser.exit(2, f"distribution verification error: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
