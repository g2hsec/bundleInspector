from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import bundleInspector.storage.atomic as atomic_module
import bundleInspector.storage.finding_store as finding_store_module
import bundleInspector.storage.identifiers as identifier_module
from bundleInspector.config import Config
from bundleInspector.storage.atomic import UnsafePathError
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.identifiers import (
    PORTABLE_COMPONENT_MAX_LENGTH,
    is_portable_component,
    is_reparse_path,
    validate_portable_component,
)
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    PipelineCheckpoint,
    Report,
    Severity,
)


def _finding(identifier: str = "finding-1") -> Finding:
    return Finding(
        id=identifier,
        rule_id="portable-storage",
        category=Category.ENDPOINT,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Portable storage finding",
        evidence=Evidence(file_url="app.js", file_hash="hash", line=1),
        extracted_value="/api/users",
    )


def _report(identifier: str = "report-1") -> Report:
    return Report(id=identifier, findings=[_finding()])


def _checkpoint() -> PipelineCheckpoint:
    return PipelineCheckpoint(
        job_id="job-1",
        seed_urls=["https://example.com"],
        stage="analyze",
        findings=[_finding()],
    )


def _make_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")


@pytest.mark.parametrize(
    "identifier",
    [
        "a",
        "job-1",
        "report_1.json",
        "a.b-c_d",
        "com10",
        "console",
        "z" * PORTABLE_COMPONENT_MAX_LENGTH,
    ],
)
def test_portable_component_accepts_one_canonical_cross_platform_spelling(
    identifier: str,
) -> None:
    assert is_portable_component(identifier)
    assert validate_portable_component(identifier) == identifier


@pytest.mark.parametrize(
    "identifier",
    [
        "",
        "UPPER",
        "Mixed-Case",
        "../escape",
        "path/name",
        r"path\name",
        ".hidden",
        "trailing.",
        "colon:name",
        "space name",
        "caf\u00e9",
        "con",
        "con.txt",
        "prn.data",
        "aux",
        "nul.txt",
        "com1",
        "com9.log",
        "lpt1",
        "lpt9.log",
        "z" * (PORTABLE_COMPONENT_MAX_LENGTH + 1),
    ],
)
def test_portable_component_rejects_aliases_paths_and_reserved_names(
    identifier: str,
) -> None:
    assert not is_portable_component(identifier)
    with pytest.raises(ValueError, match="lowercase portable identifier"):
        validate_portable_component(identifier, label="test id")


def test_config_validates_job_id_on_construction_and_assignment() -> None:
    assert Config(job_id="portable-job").job_id == "portable-job"
    with pytest.raises(ValidationError):
        Config(job_id="Portable-Job")

    config = Config()
    with pytest.raises(ValidationError):
        config.job_id = "../escape"
    assert config.job_id is None


def test_reparse_path_contract_handles_missing_and_windows_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not is_reparse_path(tmp_path / "missing")
    fake_metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_file_attributes=0x400,
    )
    monkeypatch.setattr(identifier_module.os, "lstat", lambda _: fake_metadata)
    assert is_reparse_path(tmp_path / "junction")


def test_reparse_path_detects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    _make_symlink(link, target)

    assert is_reparse_path(link)
    assert not is_reparse_path(target)


@pytest.mark.asyncio
async def test_finding_store_round_trips_portable_ids_and_rejects_unsafe_ids(
    tmp_path: Path,
) -> None:
    store = FindingStore(tmp_path)
    finding = _finding()
    report = _report()

    await store.store_finding(finding)
    await store.store_report(report)

    assert await store.get_finding(finding.id) == finding
    restored_report = await store.get_report(report.id)
    assert restored_report is not None and restored_report.id == report.id
    assert await store.get_finding("../escape") is None
    assert await store.get_report("Report-1") is None

    with pytest.raises(ValueError, match="finding id"):
        await store.store_finding(_finding("Finding-1"))
    with pytest.raises(ValueError, match="report id"):
        await store.store_report(_report("con"))


@pytest.mark.asyncio
async def test_finding_store_rejects_payload_identity_mismatches(tmp_path: Path) -> None:
    store = FindingStore(tmp_path)
    finding_path = store.base_path / "findings" / "expected.json"
    report_path = store.base_path / "reports" / "expected.json"
    finding_path.write_text(_finding("different").model_dump_json(), encoding="utf-8")
    report_path.write_text(_report("different").model_dump_json(), encoding="utf-8")

    with pytest.raises(ValueError, match="finding identity"):
        await store.get_finding("expected")
    with pytest.raises(ValueError, match="report identity"):
        await store.get_report("expected")


@pytest.mark.asyncio
async def test_report_listing_filters_nonportable_and_nonregular_entries(
    tmp_path: Path,
) -> None:
    store = FindingStore(tmp_path)
    await store.store_report(_report("good"))
    reports_path = store.base_path / "reports"
    (reports_path / "Bad.json").write_text(_report("Bad").model_dump_json(), encoding="utf-8")
    (reports_path / "con.json").write_text(_report("con").model_dump_json(), encoding="utf-8")
    (reports_path / "directory.json").mkdir()

    assert await store.list_reports() == ["good"]
    latest = await store.get_latest_report()
    assert latest is not None and latest.id == "good"


@pytest.mark.asyncio
async def test_report_listing_and_latest_ignore_symbolic_links(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "store")
    await store.store_report(_report("good"))
    outside = tmp_path / "outside.json"
    outside.write_text(_report("linked").model_dump_json(), encoding="utf-8")
    os.utime(outside, (2_000_000_000, 2_000_000_000))
    linked = store.base_path / "reports" / "linked.json"
    _make_symlink(linked, outside)

    assert await store.list_reports() == ["good"]
    latest = await store.get_latest_report()
    assert latest is not None and latest.id == "good"
    with pytest.raises(UnsafePathError):
        await store.get_report("linked")


@pytest.mark.asyncio
async def test_finding_and_report_symbolic_links_fail_closed_on_read_and_write(
    tmp_path: Path,
) -> None:
    store = FindingStore(tmp_path / "store")
    outside_finding = tmp_path / "outside-finding.json"
    outside_report = tmp_path / "outside-report.json"
    outside_finding_payload = _finding("linked").model_dump_json()
    outside_report_payload = _report("linked").model_dump_json()
    outside_finding.write_text(outside_finding_payload, encoding="utf-8")
    outside_report.write_text(outside_report_payload, encoding="utf-8")
    finding_link = store.base_path / "findings" / "linked.json"
    report_link = store.base_path / "reports" / "linked.json"
    _make_symlink(finding_link, outside_finding)
    _make_symlink(report_link, outside_report)

    with pytest.raises(UnsafePathError):
        await store.get_finding("linked")
    with pytest.raises(UnsafePathError):
        await store.store_finding(_finding("linked"))
    with pytest.raises(UnsafePathError):
        await store.get_report("linked")
    with pytest.raises(UnsafePathError):
        await store.store_report(_report("linked"))

    assert outside_finding.read_text(encoding="utf-8") == outside_finding_payload
    assert outside_report.read_text(encoding="utf-8") == outside_report_payload


@pytest.mark.asyncio
async def test_finding_and_report_hard_links_fail_closed(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "store")
    outside_finding = tmp_path / "outside-finding.json"
    outside_report = tmp_path / "outside-report.json"
    outside_finding.write_text(_finding("linked").model_dump_json(), encoding="utf-8")
    outside_report.write_text(_report("linked").model_dump_json(), encoding="utf-8")
    try:
        os.link(outside_finding, store.base_path / "findings" / "linked.json")
        os.link(outside_report, store.base_path / "reports" / "linked.json")
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        await store.get_finding("linked")
    with pytest.raises(UnsafePathError):
        await store.store_finding(_finding("linked"))
    with pytest.raises(UnsafePathError):
        await store.get_report("linked")
    with pytest.raises(UnsafePathError):
        await store.store_report(_report("linked"))


@pytest.mark.asyncio
async def test_checkpoint_symbolic_link_fails_closed_without_touching_target(
    tmp_path: Path,
) -> None:
    store = FindingStore(tmp_path / "store")
    outside = tmp_path / "outside-checkpoint.json"
    outside.write_bytes(b"outside checkpoint")
    checkpoint_link = store.base_path / "checkpoint.json"
    _make_symlink(checkpoint_link, outside)

    with pytest.raises(UnsafePathError):
        await store.get_checkpoint()
    with pytest.raises(UnsafePathError):
        await store.store_checkpoint(_checkpoint())

    assert outside.read_bytes() == b"outside checkpoint"


@pytest.mark.asyncio
async def test_checkpoint_and_key_hard_links_fail_closed(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "store")
    outside_checkpoint = tmp_path / "outside-checkpoint.json"
    outside_checkpoint.write_bytes(b"outside checkpoint")
    try:
        os.link(outside_checkpoint, store.base_path / "checkpoint.json")
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        await store.get_checkpoint()
    with pytest.raises(UnsafePathError):
        await store.store_checkpoint(_checkpoint())

    (store.base_path / "checkpoint.json").unlink()
    (store.base_path / ".checkpoint-key").unlink(missing_ok=True)
    checkpoint_payload = _checkpoint().model_dump_json().encode("utf-8")
    (store.base_path / "checkpoint.json").write_bytes(checkpoint_payload)
    outside_key = tmp_path / "outside-key"
    outside_key.write_bytes(os.urandom(32))
    os.link(outside_key, store.base_path / ".checkpoint-key")

    with pytest.raises(UnsafePathError):
        await store.get_checkpoint()
    assert outside_key.read_bytes() != b""


@pytest.mark.asyncio
async def test_checkpoint_key_symbolic_link_fails_closed(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "store")
    (store.base_path / "checkpoint.json").write_bytes(
        _checkpoint().model_dump_json().encode("utf-8")
    )
    outside_key = tmp_path / "outside-key"
    outside_key.write_bytes(os.urandom(32))
    _make_symlink(store.base_path / ".checkpoint-key", outside_key)

    with pytest.raises(UnsafePathError):
        await store.get_checkpoint()


def test_finding_store_creates_and_resolves_normal_directories(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "new" / "store")

    assert store.base_path == (tmp_path / "new" / "store").resolve()
    assert (store.base_path / "findings").is_dir()
    assert (store.base_path / "reports").is_dir()


def test_finding_store_rejects_base_and_child_symbolic_links(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    base_link = tmp_path / "base-link"
    _make_symlink(base_link, outside)
    with pytest.raises(UnsafePathError):
        FindingStore(base_link)

    base = tmp_path / "store"
    base.mkdir()
    _make_symlink(base / "findings", outside)
    with pytest.raises(UnsafePathError):
        FindingStore(base)


def test_finding_store_rejects_a_dangling_base_symbolic_link(tmp_path: Path) -> None:
    base_link = tmp_path / "base-link"
    _make_symlink(base_link, tmp_path / "missing-target")

    with pytest.raises(UnsafePathError):
        FindingStore(base_link)


@pytest.mark.parametrize("reparse_entry", ["base", "findings", "reports"])
def test_finding_store_rejects_windows_reparse_metadata_without_pathlib_junction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reparse_entry: str,
) -> None:
    base = tmp_path / "store"
    base.mkdir()
    (base / "findings").mkdir()
    (base / "reports").mkdir()
    target = base if reparse_entry == "base" else base / reparse_entry
    original_lstat = atomic_module.os.lstat

    def mark_reparse(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if Path(path) == target:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_file_attributes=0x400,
            )
        return metadata

    monkeypatch.setattr(atomic_module.os, "lstat", mark_reparse)

    with pytest.raises(UnsafePathError, match="symbolic link or junction"):
        FindingStore(base)


@pytest.mark.parametrize("entry_name", ["findings", "reports"])
def test_finding_store_rejects_non_directory_storage_entries(
    tmp_path: Path,
    entry_name: str,
) -> None:
    base = tmp_path / "store"
    base.mkdir()
    (base / entry_name).write_text("not a directory", encoding="utf-8")

    with pytest.raises(OSError):
        FindingStore(base)


def test_finding_store_rejects_resolved_child_containment_violation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path / "store"
    outside = tmp_path / "outside" / "findings"
    original_ensure = finding_store_module.ensure_safe_directory

    def escape_findings(path: Path) -> Path:
        if path.name == "findings":
            outside.mkdir(parents=True, exist_ok=True)
            return outside.resolve()
        return original_ensure(path)

    monkeypatch.setattr(finding_store_module, "ensure_safe_directory", escape_findings)

    with pytest.raises(UnsafePathError, match="escaped"):
        FindingStore(base)
