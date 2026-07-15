"""Fail-closed tests for the frozen held-out governance gate."""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_heldout_detection_gate as heldout


def _write_case_corpus(
    root: Path,
    prefix: str,
    count: int,
    *,
    private_style: bool = False,
) -> list[dict[str, str]]:
    root.mkdir(parents=True)
    cases: list[dict[str, str]] = []
    manifest_lines: list[str] = []
    for index in range(count):
        case_id = f"{prefix}-case-{index}"
        asset_name = f"assets/{case_id}.js"
        asset = root / asset_name
        asset.parent.mkdir(exist_ok=True)
        source = (
            f"class Frozen{index}{{static path(){{return '/{prefix}/{index}';}}}}\n"
            if private_style
            else f"function expose_{prefix}_{index}(){{const value='/{prefix}/{index}';return value;}}\n"
        )
        asset.write_text(source, encoding="utf-8")
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        cases.append({"case_id": case_id, "asset_sha256": digest})
        manifest_lines.append(json.dumps({
            "case_id": case_id,
            "asset": asset_name,
            "evaluated_categories": ["endpoint"],
        }, sort_keys=True))
    (root / "manifest.jsonl").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    (root / "gates.json").write_text("{}\n", encoding="utf-8")
    (root / "baseline.json").write_text("{}\n", encoding="utf-8")
    return cases


def _write_public_partition(root: Path, cases: list[dict[str, str]]) -> Path:
    training_count = round(len(cases) * 0.75)
    partition = root / "partition.json"
    partition.write_text(json.dumps({
        "schema_version": 2,
        "target_fractions": {
            "training_calibration": 0.6,
            "validation": 0.2,
            "held_out": 0.2,
        },
        "cases": [
            {
                "case_id": case["case_id"],
                "split": (
                    "training_calibration" if index < training_count else "validation"
                ),
                "group_id": f"public-group-{index}",
                "vendor_family_id": f"public-vendor-{index}",
            }
            for index, case in enumerate(cases)
        ],
    }, sort_keys=True), encoding="utf-8")
    return partition


def _build_archive(
    tmp_path: Path,
    *,
    heldout_count: int = 1,
) -> tuple[Path, str, Path, Path]:
    public = tmp_path / "public"
    public_cases = _write_case_corpus(public, "public", heldout_count * 4)
    partition = _write_public_partition(public, public_cases)
    identity = heldout.load_public_identity(public, partition)

    source = tmp_path / "governance-source"
    corpus = source / "corpus"
    private_cases = _write_case_corpus(
        corpus,
        "governance",
        heldout_count,
        private_style=True,
    )
    if heldout_count > 1:
        second_asset = corpus / "assets" / "governance-case-1.js"
        second_asset.write_text(
            "const frozenRoute={endpoint:'/governance/1'};\n"
            "Promise.resolve(frozenRoute).then(console.info);\n",
            encoding="utf-8",
        )
        private_cases[1]["asset_sha256"] = hashlib.sha256(
            second_asset.read_bytes()
        ).hexdigest()
    gates = json.loads((corpus / "gates.json").read_text(encoding="utf-8"))
    baseline = (corpus / "baseline.json").read_bytes()
    metadata = {
        "schema_version": 2,
        "split": "held-out",
        "target_fraction": 0.2,
        "source_clone_policy_version": heldout.CLONE_POLICY_VERSION,
        "public_snapshot_sha256": identity.snapshot_sha256,
        "public_partition_sha256": identity.partition_sha256,
        "public_case_count": len(public_cases),
        "held_out_case_count": len(private_cases),
        "gates_sha256": heldout._canonical_digest(gates),
        "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
        "cases": [
            {
                **case,
                "group_id": f"governance-group-{index}",
                "vendor_family_id": f"governance-vendor-{index}",
            }
            for index, case in enumerate(private_cases)
        ],
    }
    (source / "heldout.json").write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
    archive = tmp_path / "heldout.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(source).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, digest, public, partition


def _extract_valid_bundle(tmp_path: Path) -> tuple[heldout.HeldOutBundle, Path, str, Path, Path]:
    archive, digest, public, partition = _build_archive(tmp_path)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    bundle = heldout.validate_heldout_bundle(extracted, public, partition)
    return bundle, archive, digest, public, partition


def test_valid_bundle_is_exact_twenty_percent_and_non_overlapping(tmp_path: Path) -> None:
    bundle, _archive, _digest, _public, _partition = _extract_valid_bundle(tmp_path)

    assert bundle.case_count == 1
    assert bundle.public_identity.split_counts == {"training_calibration": 3, "validation": 1}


def test_archive_rejects_checksum_mismatch_before_extraction(tmp_path: Path) -> None:
    archive, _digest, _public, _partition = _build_archive(tmp_path)

    with pytest.raises(heldout.HeldOutGateError, match="archive-checksum-mismatch"):
        heldout.extract_archive(archive, "0" * 64, tmp_path / "extracted")


def test_archive_rejects_traversal_member(tmp_path: Path) -> None:
    archive = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../heldout.json", "{}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()

    with pytest.raises(heldout.HeldOutGateError, match="archive-member-invalid"):
        heldout.extract_archive(archive, digest, tmp_path / "extracted")


def test_bundle_rejects_public_source_overlap(tmp_path: Path) -> None:
    archive, digest, public, partition = _build_archive(tmp_path)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    metadata_path = extracted / "heldout.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    public_asset = next((public / "assets").glob("*.js"))
    private_asset = next((extracted / "corpus" / "assets").glob("*.js"))
    private_asset.write_bytes(public_asset.read_bytes())
    overlap_digest = hashlib.sha256(private_asset.read_bytes()).hexdigest()
    metadata["cases"][0]["asset_sha256"] = overlap_digest
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-source-overlap"):
        heldout.validate_heldout_bundle(extracted, public, partition)


def test_bundle_rejects_group_overlap(tmp_path: Path) -> None:
    archive, digest, public, partition = _build_archive(tmp_path)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    metadata_path = extracted / "heldout.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["cases"][0]["group_id"] = "public-group-0"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-group-overlap"):
        heldout.validate_heldout_bundle(extracted, public, partition)


def test_bundle_rejects_non_twenty_percent_split(tmp_path: Path) -> None:
    archive, digest, public, partition = _build_archive(tmp_path)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    metadata_path = extracted / "heldout.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["held_out_case_count"] = 2
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-case-count-mismatch"):
        heldout.validate_heldout_bundle(extracted, public, partition)


def test_metric_failure_does_not_return_sensitive_failure_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _archive, _digest, _public, _partition = _extract_valid_bundle(tmp_path)
    result = SimpleNamespace(case_count=1, passed=True)
    monkeypatch.setattr(heldout, "run_corpus", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(heldout, "load_regression_baseline", lambda _path: {})
    monkeypatch.setattr(
        heldout,
        "evaluate_regression_baseline",
        lambda _result, _baseline: ["PRIVATE_CASE_AND_LABEL_CANARY"],
    )

    payload = heldout.execute_gate(bundle)

    assert payload == {
        "schema_version": 2,
        "split": "held-out",
        "case_count": 1,
        "passed": False,
        "reason": "metric-gate-failed",
    }
    assert "PRIVATE_CASE_AND_LABEL_CANARY" not in json.dumps(payload)


def test_public_partition_rejects_semantic_group_crossing_splits(tmp_path: Path) -> None:
    public = tmp_path / "public"
    cases = _write_case_corpus(public, "public", 4)
    partition = _write_public_partition(public, cases)
    payload = json.loads(partition.read_text(encoding="utf-8"))
    payload["cases"][1]["group_id"] = payload["cases"][0]["group_id"]
    payload["cases"][1]["split"] = "validation"
    partition.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="public-group-crosses-splits"):
        heldout.load_public_identity(public, partition)


def test_public_partition_rejects_vendor_family_crossing_splits(tmp_path: Path) -> None:
    public = tmp_path / "public"
    cases = _write_case_corpus(public, "public", 4)
    partition = _write_public_partition(public, cases)
    payload = json.loads(partition.read_text(encoding="utf-8"))
    payload["cases"][1]["vendor_family_id"] = payload["cases"][0]["vendor_family_id"]
    payload["cases"][1]["split"] = "validation"
    partition.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="public-vendor-crosses-splits"):
        heldout.load_public_identity(public, partition)


def test_bundle_rejects_vendor_overlap(tmp_path: Path) -> None:
    archive, digest, public, partition = _build_archive(tmp_path)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    metadata_path = extracted / "heldout.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["cases"][0]["vendor_family_id"] = "public-vendor-0"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-vendor-overlap"):
        heldout.validate_heldout_bundle(extracted, public, partition)


def test_bundle_rejects_near_clone_after_format_only_change(tmp_path: Path) -> None:
    archive, digest, public, partition = _build_archive(tmp_path)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    public_asset = next((public / "assets").glob("*.js"))
    governance_asset = next((extracted / "corpus" / "assets").glob("*.js"))
    governance_asset.write_bytes(public_asset.read_bytes() + b"\n// formatting-only change\n")
    metadata_path = extracted / "heldout.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["cases"][0]["asset_sha256"] = hashlib.sha256(governance_asset.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-source-near-clone"):
        heldout.validate_heldout_bundle(extracted, public, partition)


def test_bundle_rejects_internal_near_clone_after_format_only_change(
    tmp_path: Path,
) -> None:
    archive, digest, public, partition = _build_archive(tmp_path, heldout_count=2)
    extracted = tmp_path / "extracted"
    heldout.extract_archive(archive, digest, extracted)
    heldout.validate_heldout_bundle(extracted, public, partition)
    assets = sorted((extracted / "corpus" / "assets").glob("*.js"))
    assets[1].write_bytes(assets[0].read_bytes() + b"\n// formatting-only change\n")
    metadata_path = extracted / "heldout.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    second_case_id = assets[1].stem
    second_metadata = next(
        case for case in metadata["cases"] if case["case_id"] == second_case_id
    )
    second_metadata["asset_sha256"] = hashlib.sha256(assets[1].read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-internal-near-clone"):
        heldout.validate_heldout_bundle(extracted, public, partition)


def test_public_snapshot_rejects_hardlinked_asset(tmp_path: Path) -> None:
    public = tmp_path / "public"
    cases = _write_case_corpus(public, "public", 4)
    partition = _write_public_partition(public, cases)
    asset = next((public / "assets").glob("*.js"))
    replacement = tmp_path / "hardlink-source.js"
    replacement.write_bytes(asset.read_bytes())
    asset.unlink()
    try:
        os.link(replacement, asset)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(heldout.HeldOutGateError, match="public-corpus-incomplete"):
        heldout.load_public_identity(public, partition)


def test_archive_normalizes_crc_stream_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, digest, _public, _partition = _build_archive(tmp_path)

    def fail_open(*_args: object, **_kwargs: object) -> object:
        raise zipfile.BadZipFile("private CRC detail")

    monkeypatch.setattr(zipfile.ZipFile, "open", fail_open)
    with pytest.raises(heldout.HeldOutGateError, match="archive-extraction-failed"):
        heldout.extract_archive(archive, digest, tmp_path / "extracted")


def test_short_source_clone_policy_rejects_formatting_and_identifier_renames() -> None:
    original = heldout._source_profile(b"const a=1;")
    format_only = heldout._source_profile(b"  const a=1; // changed formatting\n")
    renamed = heldout._source_profile(b"const renamed=2;")

    assert heldout._is_near_clone(original, format_only)
    assert heldout._is_near_clone(original, renamed)


def test_checksum_file_is_bound_to_archive_basename(tmp_path: Path) -> None:
    archive = tmp_path / "reviewed-custom.zip"
    archive.write_bytes(b"reviewed archive bytes")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = tmp_path / "reviewed-custom.sha256"
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")

    assert heldout._checksum_from_file(checksum, archive.name) == digest
    checksum.write_text(f"{digest}  different.zip\n", encoding="ascii")
    with pytest.raises(heldout.HeldOutGateError, match="archive-checksum-file-invalid"):
        heldout._checksum_from_file(checksum, archive.name)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--archive", "custom.zip"],
        ["--sha256", "0" * 64],
        ["--sha256-file", "custom.sha256"],
        ["--public-corpus", "custom-corpus"],
        ["--partition", "custom-partition.json"],
    ],
)
def test_run_rejects_custom_governance_inputs(arguments: list[str]) -> None:
    with pytest.raises(SystemExit, match="2"):
        heldout.main(["run", *arguments])


def test_metadata_duplicate_keys_fail_closed(tmp_path: Path) -> None:
    bundle, _archive, _digest, public, partition = _extract_valid_bundle(tmp_path)
    metadata_path = bundle.corpus_root.parent / "heldout.json"
    original = metadata_path.read_text(encoding="utf-8")
    metadata_path.write_text(original[:-1] + ',"split":"held-out"}', encoding="utf-8")

    with pytest.raises(heldout.HeldOutGateError, match="heldout-metadata-invalid"):
        heldout.validate_heldout_bundle(bundle.corpus_root.parent, public, partition)
