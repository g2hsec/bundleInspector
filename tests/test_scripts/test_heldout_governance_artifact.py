"""Frozen governance corpus and artifact publication contracts."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import build_heldout_governance_corpus as builder
from scripts import update_heldout_governance_artifact as updater


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_builder_reproduces_reviewed_manifest_gates_and_assets(tmp_path: Path) -> None:
    generated = tmp_path / "corpus"

    case_count, label_count = builder.build_corpus(generated)

    expected = _tree_bytes(updater.DEFAULT_SOURCE / "corpus")
    expected.pop("baseline.json")
    actual = _tree_bytes(generated)
    assert case_count == 11
    assert label_count == 2_193
    assert actual == expected


def test_committed_artifact_is_byte_reproducible_and_default_gate_passes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(updater.DEFAULT_SOURCE, source)
    (source / "heldout.json").unlink()
    archive = tmp_path / "frozen-governance.zip"
    checksum = tmp_path / "frozen-governance.sha256"

    digest = updater.publish_artifact(source, archive, checksum)

    assert digest == hashlib.sha256(updater.DEFAULT_ARCHIVE.read_bytes()).hexdigest()
    assert archive.read_bytes() == updater.DEFAULT_ARCHIVE.read_bytes()
    assert checksum.read_bytes() == updater.DEFAULT_CHECKSUM.read_bytes()
    assert (source / "heldout.json").read_bytes() == (updater.DEFAULT_SOURCE / "heldout.json").read_bytes()
    completed = subprocess.run(
        [sys.executable, "scripts/run_heldout_detection_gate.py", "run"],
        cwd=updater.REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert payload == {
        "case_count": 11,
        "passed": True,
        "reason": None,
        "schema_version": 2,
        "split": "held-out",
    }
    assert "governance-" not in completed.stdout


def test_publication_does_not_write_when_complete_gate_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(updater.DEFAULT_SOURCE, source)
    (source / "heldout.json").unlink()
    archive = tmp_path / "frozen-governance.zip"
    checksum = tmp_path / "frozen-governance.sha256"
    monkeypatch.setattr(
        updater.heldout,
        "execute_gate",
        lambda _bundle: {"passed": False},
    )

    with pytest.raises(ValueError, match="complete gate"):
        updater.publish_artifact(source, archive, checksum)

    assert not (source / "heldout.json").exists()
    assert not archive.exists()
    assert not checksum.exists()


def test_publication_restores_all_prior_files_when_second_promotion_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = tuple(tmp_path / name for name in ("metadata.json", "artifact.zip", "artifact.sha256"))
    old = (b"old-metadata", b"old-archive", b"old-checksum")
    new = (b"new-metadata", b"new-archive", b"new-checksum")
    for path, content in zip(paths, old, strict=True):
        path.write_bytes(content)
    original_replace = updater.os.replace
    failed = False

    def fail_second_stage(source: str | Path, destination: str | Path) -> None:
        nonlocal failed
        if not failed and Path(source).suffix == ".stage" and Path(destination) == paths[1]:
            failed = True
            raise OSError("injected governance promotion failure")
        original_replace(source, destination)

    monkeypatch.setattr(updater.os, "replace", fail_second_stage)

    with pytest.raises(OSError, match="injected"):
        updater._publish(paths, new, replace=True)

    assert tuple(path.read_bytes() for path in paths) == old
    assert list(tmp_path.glob(".*.stage")) == []
    assert list(tmp_path.glob(".*.backup")) == []
