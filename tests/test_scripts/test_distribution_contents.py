"""Exact, fail-closed wheel and sdist member contracts."""

from __future__ import annotations

import gzip
import io
import json
import stat
import struct
import subprocess
import sys
import tarfile
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest

from scripts import update_distribution_manifest as updater
from scripts import verify_distribution_contents as verifier


def _policy() -> dict[str, Any]:
    return {
        "distribution": {"normalized_name": "demo", "version": "1.0"},
        "schema_version": 1,
        "sdist": {
            "directories": ["docs"],
            "filename": "demo-1.0.tar.gz",
            "files": ["PKG-INFO", "pyproject.toml"],
            "root": "demo-1.0",
            "root_directory": False,
        },
        "wheel": {
            "filename": "demo-1.0-py3-none-any.whl",
            "files": ["demo-1.0.dist-info/METADATA", "demo/__init__.py"],
        },
    }


def _write_manifest(path: Path, policy: dict[str, Any] | None = None) -> None:
    path.write_text(
        json.dumps(policy or _policy(), allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_wheel(
    path: Path,
    members: list[tuple[str, bytes, int]] | None = None,
) -> None:
    reviewed = members or [
        ("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.4\n", stat.S_IFREG | 0o644),
        ("demo/__init__.py", b"", stat.S_IFREG | 0o644),
    ]
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content, mode in reviewed:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content)


def _prepend_unreferenced_local_record(path: Path) -> None:
    encoded = bytearray(path.read_bytes())
    eocd_offset = len(encoded) - verifier._ZIP_EOCD.size
    central_offset = struct.unpack_from("<L", encoded, eocd_offset + 16)[0]
    prefix = b"PK\x03\x04" + (b"\x00" * 26)
    cursor = central_offset
    while cursor < eocd_offset:
        assert encoded[cursor : cursor + 4] == b"PK\x01\x02"
        name_size, extra_size, comment_size = struct.unpack_from("<3H", encoded, cursor + 28)
        local_offset = struct.unpack_from("<L", encoded, cursor + 42)[0]
        struct.pack_into("<L", encoded, cursor + 42, local_offset + len(prefix))
        cursor += 46 + name_size + extra_size + comment_size
    assert cursor == eocd_offset
    struct.pack_into("<L", encoded, eocd_offset + 16, central_offset + len(prefix))
    path.write_bytes(prefix + encoded)


def _tar_member(name: str, content: bytes, member_type: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.mode = 0o755 if member_type == tarfile.DIRTYPE else 0o644
    member.size = len(content) if member_type == tarfile.REGTYPE else 0
    if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
        member.linkname = "demo-1.0/pyproject.toml"
    return member


def _write_sdist(
    path: Path,
    members: list[tuple[str, bytes, bytes]] | None = None,
) -> None:
    reviewed = members or [
        ("demo-1.0/PKG-INFO", b"Metadata-Version: 2.4\n", tarfile.REGTYPE),
        ("demo-1.0/docs", b"", tarfile.DIRTYPE),
        ("demo-1.0/pyproject.toml", b"[project]\n", tarfile.REGTYPE),
    ]
    with tarfile.open(path, "w:gz") as archive:
        for name, content, member_type in reviewed:
            member = _tar_member(name, content, member_type)
            if member_type == tarfile.REGTYPE:
                archive.addfile(member, io.BytesIO(content))
            else:
                archive.addfile(member)


def _write_sdist_with_hidden_pax_header(path: Path) -> None:
    reviewed = [
        ("demo-1.0/PKG-INFO", b"Metadata-Version: 2.4\n", tarfile.REGTYPE),
        ("demo-1.0/docs", b"", tarfile.DIRTYPE),
        ("demo-1.0/pyproject.toml", b"[project]\n", tarfile.REGTYPE),
    ]
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, content, member_type in reviewed:
            member = _tar_member(name, content, member_type)
            if name.endswith("pyproject.toml"):
                member.pax_headers = {"comment": "unreviewed-hidden-header"}
            archive.addfile(
                member,
                io.BytesIO(content) if member_type == tarfile.REGTYPE else None,
            )


@pytest.fixture
def valid_artifacts(tmp_path: Path) -> tuple[Path, Path, Path]:
    manifest = tmp_path / "manifest.json"
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    sdist = tmp_path / "demo-1.0.tar.gz"
    _write_manifest(manifest)
    _write_wheel(wheel)
    _write_sdist(sdist)
    return manifest, wheel, sdist


def test_valid_exact_artifacts_and_cli_pass(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, wheel, sdist = valid_artifacts

    result = verifier.verify_distribution_artifacts(manifest, wheel, sdist)
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/verify_distribution_contents.py",
            "--manifest",
            str(manifest),
            "--wheel",
            str(wheel),
            "--sdist",
            str(sdist),
        ],
        cwd=updater.REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result["passed"] is True
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert json.loads(completed.stdout)["passed"] is True


def test_exact_top_level_root_directory_policy(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    with_root = _policy()
    with_root["sdist"]["root_directory"] = True
    _write_manifest(manifest, with_root)
    _write_sdist(
        sdist,
        [
            ("demo-1.0", b"", tarfile.DIRTYPE),
            ("demo-1.0/PKG-INFO", b"", tarfile.REGTYPE),
            ("demo-1.0/docs", b"", tarfile.DIRTYPE),
            ("demo-1.0/pyproject.toml", b"", tarfile.REGTYPE),
        ],
    )

    policy = verifier.load_manifest(manifest)
    verifier.verify_sdist(
        sdist,
        policy.sdist,
        policy.sdist_root,
        policy.sdist_root_directory,
    )
    with pytest.raises(verifier.DistributionVerificationError, match="root directory presence"):
        verifier.verify_sdist(sdist, policy.sdist, policy.sdist_root, False)


def test_manifest_and_archive_inputs_reject_multiple_hardlinks(
    valid_artifacts: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    manifest_link = tmp_path / "manifest-hardlink.json"
    wheel_link = tmp_path / wheel.name
    manifest.rename(tmp_path / "manifest-original.json")
    manifest = tmp_path / "manifest-original.json"
    wheel.rename(tmp_path / "wheel-original.whl")
    wheel = tmp_path / "wheel-original.whl"
    manifest_link.hardlink_to(manifest)
    wheel_link.hardlink_to(wheel)

    with pytest.raises(verifier.DistributionVerificationError, match="single-link"):
        verifier.load_manifest(manifest)
    with pytest.raises(verifier.DistributionVerificationError, match="single-link"):
        verifier.verify_wheel(
            wheel_link,
            verifier.ArchivePolicy(filename=wheel_link.name, files=()),
        )


def test_manifest_and_archive_physical_sizes_are_bounded(
    valid_artifacts: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    monkeypatch.setattr(verifier, "MAX_MANIFEST_SIZE", 1)
    with pytest.raises(verifier.DistributionVerificationError, match="physical size"):
        verifier.load_manifest(manifest)
    monkeypatch.setattr(verifier, "MAX_ARCHIVE_SIZE", 1)
    with pytest.raises(verifier.DistributionVerificationError, match="physical size"):
        verifier.verify_wheel(wheel, verifier.ArchivePolicy(filename=wheel.name, files=()))


def test_wheel_rejects_trailing_data_comments_and_concatenated_zip(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).wheel
    original = wheel.read_bytes()

    attacks = (original + b"trailing-junk", original + original)
    for attack in attacks:
        wheel.write_bytes(attack)
        with pytest.raises(verifier.DistributionVerificationError):
            verifier.verify_wheel(wheel, policy)

    wheel.write_bytes(original)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.comment = b"release-comment"
    with pytest.raises(verifier.DistributionVerificationError, match="no archive comment"):
        verifier.verify_wheel(wheel, policy)


def test_wheel_rejects_unreferenced_local_header_prefix(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).wheel
    _prepend_unreferenced_local_record(wheel)

    with zipfile.ZipFile(wheel) as archive:
        assert min(member.header_offset for member in archive.infolist()) > 0
    with pytest.raises(verifier.DistributionVerificationError, match="unreferenced prefix"):
        verifier.verify_wheel(wheel, policy)


def test_wheel_rejects_member_count_before_zipfile_construction(
    valid_artifacts: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _manifest, wheel, _sdist = valid_artifacts
    encoded = bytearray(wheel.read_bytes())
    eocd_offset = len(encoded) - verifier._ZIP_EOCD.size
    too_many = verifier.MAX_ARCHIVE_MEMBERS + 1
    struct.pack_into("<H", encoded, eocd_offset + 8, too_many)
    struct.pack_into("<H", encoded, eocd_offset + 10, too_many)
    wheel.write_bytes(encoded)
    monkeypatch.setattr(
        verifier.zipfile,
        "ZipFile",
        lambda *_args, **_kwargs: pytest.fail("ZipFile constructed before EOCD count rejection"),
    )

    with pytest.raises(verifier.DistributionVerificationError, match="too many members"):
        verifier.verify_wheel(
            wheel,
            verifier.ArchivePolicy(filename=wheel.name, files=()),
        )


def test_wheel_rejects_central_directory_size_before_zipfile_construction(
    valid_artifacts: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _manifest, wheel, _sdist = valid_artifacts
    monkeypatch.setattr(verifier, "MAX_CENTRAL_DIRECTORY_SIZE", 1)
    monkeypatch.setattr(
        verifier.zipfile,
        "ZipFile",
        lambda *_args, **_kwargs: pytest.fail(
            "ZipFile constructed before central-directory size rejection"
        ),
    )

    with pytest.raises(verifier.DistributionVerificationError, match="central directory"):
        verifier.verify_wheel(
            wheel,
            verifier.ArchivePolicy(filename=wheel.name, files=()),
        )


def test_missing_or_unlisted_wheel_members_fail(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    _write_wheel(
        wheel,
        [
            ("demo/__init__.py", b"", stat.S_IFREG | 0o644),
            ("demo/extra.py", b"", stat.S_IFREG | 0o644),
        ],
    )

    with pytest.raises(verifier.DistributionVerificationError, match="member set differs"):
        verifier.verify_wheel(wheel, verifier.load_manifest(manifest).wheel)


@pytest.mark.parametrize("name", ["demo/.env", "demo/payload.bin", "demo/notes.txt"])
def test_wheel_rejects_environment_binary_and_unlisted_files(
    valid_artifacts: tuple[Path, Path, Path],
    name: str,
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    members = [
        ("demo-1.0.dist-info/METADATA", b"", stat.S_IFREG | 0o644),
        ("demo/__init__.py", b"", stat.S_IFREG | 0o644),
        (name, b"unreviewed", stat.S_IFREG | 0o644),
    ]
    _write_wheel(wheel, members)

    with pytest.raises(verifier.DistributionVerificationError):
        verifier.verify_wheel(wheel, verifier.load_manifest(manifest).wheel)


def test_wheel_rejects_symlink_duplicate_case_collision_and_traversal(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, wheel, _sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).wheel
    attacks = (
        [
            ("demo-1.0.dist-info/METADATA", b"", stat.S_IFREG | 0o644),
            ("demo/__init__.py", b"target", stat.S_IFLNK | 0o777),
        ],
        [
            ("demo-1.0.dist-info/METADATA", b"", stat.S_IFREG | 0o644),
            ("demo/__init__.py", b"", stat.S_IFREG | 0o644),
            ("demo/__init__.py", b"again", stat.S_IFREG | 0o644),
        ],
        [
            ("demo-1.0.dist-info/METADATA", b"", stat.S_IFREG | 0o644),
            ("demo/__init__.py", b"", stat.S_IFREG | 0o644),
            ("DEMO/__init__.py", b"", stat.S_IFREG | 0o644),
        ],
        [
            ("demo-1.0.dist-info/METADATA", b"", stat.S_IFREG | 0o644),
            ("../escape.py", b"", stat.S_IFREG | 0o644),
        ],
    )
    for attack in attacks:
        _write_wheel(wheel, attack)
        with pytest.raises(verifier.DistributionVerificationError):
            verifier.verify_wheel(wheel, policy)


@pytest.mark.parametrize(
    "member_type",
    [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE],
)
def test_sdist_rejects_links_devices_and_fifo(
    valid_artifacts: tuple[Path, Path, Path],
    member_type: bytes,
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    members = [
        ("demo-1.0/PKG-INFO", b"", tarfile.REGTYPE),
        ("demo-1.0/docs", b"", tarfile.DIRTYPE),
        ("demo-1.0/pyproject.toml", b"", tarfile.REGTYPE),
        ("demo-1.0/special.py", b"", member_type),
    ]
    _write_sdist(sdist, members)

    with pytest.raises(verifier.DistributionVerificationError):
        verifier.verify_sdist(sdist, verifier.load_manifest(manifest).sdist, "demo-1.0")


@pytest.mark.parametrize(
    "name",
    [
        "demo-1.0/.env",
        "demo-1.0/payload.bin",
        "demo-1.0/notes.txt",
        "other-root/escape.py",
        "demo-1.0/../escape.py",
    ],
)
def test_sdist_rejects_sensitive_binary_unlisted_root_and_traversal(
    valid_artifacts: tuple[Path, Path, Path],
    name: str,
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    members = [
        ("demo-1.0/PKG-INFO", b"", tarfile.REGTYPE),
        ("demo-1.0/docs", b"", tarfile.DIRTYPE),
        ("demo-1.0/pyproject.toml", b"", tarfile.REGTYPE),
        (name, b"unreviewed", tarfile.REGTYPE),
    ]
    _write_sdist(sdist, members)

    with pytest.raises(verifier.DistributionVerificationError):
        verifier.verify_sdist(sdist, verifier.load_manifest(manifest).sdist, "demo-1.0")


def test_sdist_rejects_duplicate_and_casefold_collision(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).sdist
    attacks = (
        [
            ("demo-1.0/PKG-INFO", b"", tarfile.REGTYPE),
            ("demo-1.0/docs", b"", tarfile.DIRTYPE),
            ("demo-1.0/pyproject.toml", b"", tarfile.REGTYPE),
            ("demo-1.0/pyproject.toml", b"again", tarfile.REGTYPE),
        ],
        [
            ("demo-1.0/PKG-INFO", b"", tarfile.REGTYPE),
            ("demo-1.0/docs", b"", tarfile.DIRTYPE),
            ("demo-1.0/pyproject.toml", b"", tarfile.REGTYPE),
            ("demo-1.0/PYPROJECT.TOML", b"", tarfile.REGTYPE),
        ],
    )
    for attack in attacks:
        _write_sdist(sdist, attack)
        with pytest.raises(verifier.DistributionVerificationError):
            verifier.verify_sdist(sdist, policy, "demo-1.0")


def test_sdist_rejects_appended_junk_concatenated_gzip_and_logical_payload(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).sdist
    original = sdist.read_bytes()
    expanded = gzip.decompress(original)
    attacks = (
        original + b"trailing-junk",
        original + gzip.compress(b"second-stream"),
        gzip.compress(expanded + b"non-zero-logical-tail"),
    )

    for attack in attacks:
        sdist.write_bytes(attack)
        with pytest.raises(verifier.DistributionVerificationError):
            verifier.verify_sdist(sdist, policy, "demo-1.0")


def test_sdist_member_count_is_rejected_without_getmembers(
    valid_artifacts: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).sdist
    monkeypatch.setattr(verifier, "MAX_ARCHIVE_MEMBERS", 2)
    monkeypatch.setattr(
        tarfile.TarFile,
        "getmembers",
        lambda _self: pytest.fail("getmembers materialized the complete attacker-controlled tar"),
    )

    with pytest.raises(verifier.DistributionVerificationError, match="too many members"):
        verifier.verify_sdist(sdist, policy, "demo-1.0")


def test_sdist_rejects_hidden_pax_extension_member(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).sdist
    _write_sdist_with_hidden_pax_header(sdist)

    with pytest.raises(verifier.DistributionVerificationError, match="hidden metadata"):
        verifier.verify_sdist(sdist, policy, "demo-1.0")


def test_sdist_rejects_trailing_global_pax_header(
    valid_artifacts: tuple[Path, Path, Path],
) -> None:
    manifest, _wheel, sdist = valid_artifacts
    policy = verifier.load_manifest(manifest).sdist
    expanded = gzip.decompress(sdist.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        archive.getmembers()
        reviewed_end = archive.offset
    hidden_header = tarfile.TarInfo.create_pax_global_header(
        {"comment": "trailing-unreviewed-metadata"}
    )
    attacked = expanded[:reviewed_end] + hidden_header + (b"\0" * 1024)
    attacked += b"\0" * (-len(attacked) % tarfile.RECORDSIZE)
    sdist.write_bytes(gzip.compress(attacked))

    with pytest.raises(verifier.DistributionVerificationError):
        verifier.verify_sdist(sdist, policy, "demo-1.0")


def test_sdist_expansion_bound_runs_before_tar_parser(
    valid_artifacts: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _manifest, _wheel, sdist = valid_artifacts
    monkeypatch.setattr(verifier, "MAX_TAR_STREAM_SIZE", 1)
    monkeypatch.setattr(
        verifier.tarfile,
        "open",
        lambda *_args, **_kwargs: pytest.fail("tar parser ran before gzip expansion rejection"),
    )

    with sdist.open("rb") as source:
        with pytest.raises(verifier.DistributionVerificationError, match="expanded tar stream"):
            verifier._verify_single_gzip_stream(source)


def test_manifest_schema_rejects_duplicate_keys_unknown_binary_and_collisions(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(verifier.DistributionVerificationError, match="duplicate key"):
        verifier.load_manifest(duplicate)

    binary_policy = _policy()
    binary_policy["sdist"]["files"] = ["PKG-INFO", "payload.bin", "pyproject.toml"]
    binary = tmp_path / "binary.json"
    _write_manifest(binary, binary_policy)
    with pytest.raises(verifier.DistributionVerificationError, match="unreviewed file type"):
        verifier.load_manifest(binary)

    collision_policy = _policy()
    collision_policy["wheel"]["files"] = ["demo/FILE.py", "demo/file.py"]
    collision = tmp_path / "collision.json"
    _write_manifest(collision, collision_policy)
    with pytest.raises(verifier.DistributionVerificationError, match="collision"):
        verifier.load_manifest(collision)


def test_committed_manifest_is_generated_from_the_reviewed_source_tree() -> None:
    generated, missing = updater.build_manifest(
        updater.REPO_ROOT,
        allow_missing_baselines=True,
    )
    committed = json.loads(updater.DEFAULT_MANIFEST.read_text(encoding="utf-8"))

    assert generated == committed
    assert set(missing) <= set(updater.BASELINE_PATHS)
    expected = set(committed["sdist"]["files"])
    assert set(updater.REQUIRED_POLICY_PATHS) <= expected
    assert "next_plan/FINAL_COMPLETION_REPORT.md" not in expected


def test_generator_rejects_environment_files_and_unreviewed_binary_types(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(updater, "ROOT_FILES", ())
    monkeypatch.setattr(updater, "TREE_ROOTS", ("src",))
    monkeypatch.setattr(updater, "REQUIRED_POLICY_PATHS", ())
    monkeypatch.setattr(updater, "BASELINE_PATHS", ())

    for name in (".env", "payload.bin"):
        attack = tmp_path / "src" / name
        attack.write_bytes(b"secret")
        with pytest.raises(verifier.DistributionVerificationError):
            updater.build_manifest(tmp_path)
        attack.unlink()
