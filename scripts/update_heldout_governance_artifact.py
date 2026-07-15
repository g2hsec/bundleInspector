"""Validate and publish the committed frozen governance ZIP and checksum."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
for import_root in (REPO_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from bundleInspector.validation.metrics import CorpusError, load_manifest  # noqa: E402
from scripts import run_heldout_detection_gate as heldout  # noqa: E402

DEFAULT_SOURCE = REPO_ROOT / "tests" / "heldout" / "source"
DEFAULT_ARCHIVE = REPO_ROOT / "tests" / "heldout" / "frozen-governance.zip"
DEFAULT_CHECKSUM = REPO_ROOT / "tests" / "heldout" / "frozen-governance.sha256"
DEFAULT_PUBLIC_CORPUS = REPO_ROOT / "tests" / "corpus"
DEFAULT_PARTITION = DEFAULT_PUBLIC_CORPUS / "partition.json"
VENDOR_FAMILY_ID = "bundleinspector-frozen-governance-v1"
CASE_GROUPS = {
    "governance-credential-object-a": "frozen-credential-object-a",
    "governance-credential-object-b": "frozen-credential-object-b",
    "governance-contract-batch-a": "frozen-contract-batch-a",
    "governance-contract-batch-b": "frozen-contract-batch-b",
    "governance-contract-batch-c": "frozen-contract-batch-c",
    "governance-endpoint-batch": "frozen-endpoint-batch",
    "governance-surface-a": "frozen-detector-surface-a",
    "governance-surface-b": "frozen-detector-surface-b",
    "governance-confirmed-boundary": "frozen-confirmed-boundary",
    "governance-probable-a": "frozen-probable-a",
    "governance-probable-b": "frozen-probable-b",
}


def _metadata_payload(source: Path, public_corpus: Path, partition: Path) -> dict[str, Any]:
    corpus_root = source / "corpus"
    identity = heldout.load_public_identity(public_corpus, partition)
    safe_inputs = heldout._safe_corpus_inputs(corpus_root, "heldout-corpus-invalid")
    try:
        cases = load_manifest(corpus_root)
    except CorpusError as exc:
        raise ValueError("held-out corpus manifest is invalid") from exc
    by_case = {case.case_id: case for case in cases}
    if set(by_case) != set(CASE_GROUPS):
        raise ValueError("held-out corpus cases do not match the frozen case registry")
    gates = heldout._strict_json_bytes(
        safe_inputs[(corpus_root / "gates.json").absolute()],
        "heldout-corpus-invalid",
    )
    baseline = safe_inputs[(corpus_root / "baseline.json").absolute()]
    return {
        "schema_version": 2,
        "split": "held-out",
        "target_fraction": 0.2,
        "source_clone_policy_version": heldout.CLONE_POLICY_VERSION,
        "public_snapshot_sha256": identity.snapshot_sha256,
        "public_partition_sha256": identity.partition_sha256,
        "public_case_count": len(identity.case_ids),
        "held_out_case_count": len(cases),
        "gates_sha256": heldout._canonical_digest(gates),
        "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
        "cases": [
            {
                "case_id": case_id,
                "group_id": CASE_GROUPS[case_id],
                "vendor_family_id": VENDOR_FAMILY_ID,
                "asset_sha256": by_case[case_id].asset_fingerprint,
            }
            for case_id in sorted(by_case)
        ],
    }


def _review_tree(source: Path, destination: Path, metadata: dict[str, Any]) -> None:
    source_corpus = source / "corpus"
    safe_inputs = heldout._safe_corpus_inputs(source_corpus, "heldout-corpus-invalid")
    destination_corpus = destination / "corpus"
    for path, content in sorted(safe_inputs.items(), key=lambda item: item[0].as_posix()):
        relative = path.relative_to(source_corpus.absolute())
        target = destination_corpus / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (destination / heldout.METADATA_NAME).write_text(
        json.dumps(metadata, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _archive_bytes(review_root: Path) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        files = sorted(
            (path for path in review_root.rglob("*") if path.is_file()),
            key=lambda path: path.relative_to(review_root).as_posix(),
        )
        for path in files:
            relative = path.relative_to(review_root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def _stage(path: Path, content: bytes, suffix: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "xb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=suffix,
            delete=False,
        ) as output:
            temporary_name = output.name
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        result = Path(temporary_name)
        temporary_name = None
        return result
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _publish(paths: tuple[Path, ...], contents: tuple[bytes, ...], *, replace: bool) -> None:
    existing = tuple(path.exists() for path in paths)
    if any(existing) and not all(existing):
        raise FileExistsError("governance artifact publication is incomplete")
    if all(existing) and not replace:
        raise FileExistsError("governance artifacts exist; pass --replace after review")
    staged: list[Path] = []
    backups: list[Path | None] = [None] * len(paths)
    promoted = 0
    try:
        for destination, content in zip(paths, contents, strict=True):
            staged.append(_stage(destination, content, ".stage"))
        if all(existing):
            for index, destination in enumerate(paths):
                backups[index] = _stage(destination, destination.read_bytes(), ".backup")
        for index, (staged_path, destination) in enumerate(zip(staged, paths, strict=True)):
            os.replace(staged_path, destination)
            promoted = index + 1
    except Exception:
        for promoted_path in paths[:promoted]:
            promoted_path.unlink(missing_ok=True)
        for backup_path, destination in zip(backups, paths, strict=True):
            if backup_path is not None:
                os.replace(backup_path, destination)
        raise
    finally:
        for temporary_path in (*staged, *backups):
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def publish_artifact(
    source: Path = DEFAULT_SOURCE,
    archive: Path = DEFAULT_ARCHIVE,
    checksum: Path = DEFAULT_CHECKSUM,
    public_corpus: Path = DEFAULT_PUBLIC_CORPUS,
    partition: Path = DEFAULT_PARTITION,
    *,
    replace: bool = False,
) -> str:
    metadata = _metadata_payload(source, public_corpus, partition)
    with tempfile.TemporaryDirectory(prefix="bundleinspector-governance-review-") as temporary:
        review_root = Path(temporary) / "review"
        review_root.mkdir()
        _review_tree(source, review_root, metadata)
        bundle = heldout.validate_heldout_bundle(review_root, public_corpus, partition)
        result = heldout.execute_gate(bundle)
        if result["passed"] is not True:
            raise ValueError("frozen governance corpus did not pass its complete gate")
        archive_content = _archive_bytes(review_root)
        digest = hashlib.sha256(archive_content).hexdigest()
        metadata_content = (review_root / heldout.METADATA_NAME).read_bytes()
    checksum_content = f"{digest}  {archive.name}\n".encode("ascii")
    _publish(
        (source / heldout.METADATA_NAME, archive, checksum),
        (metadata_content, archive_content, checksum_content),
        replace=replace,
    )
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--checksum", type=Path, default=DEFAULT_CHECKSUM)
    parser.add_argument("--public-corpus", type=Path, default=DEFAULT_PUBLIC_CORPUS)
    parser.add_argument("--partition", type=Path, default=DEFAULT_PARTITION)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        digest = publish_artifact(
            args.source,
            args.archive,
            args.checksum,
            args.public_corpus,
            args.partition,
            replace=args.replace,
        )
    except (CorpusError, FileExistsError, OSError, RuntimeError, TypeError, ValueError) as exc:
        parser.exit(2, f"governance artifact error: {exc}\n")
    print(json.dumps({"archive_sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
