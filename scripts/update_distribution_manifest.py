"""Generate or check the reviewed exact wheel/sdist member manifest."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import verify_distribution_contents as verifier  # noqa: E402

DEFAULT_MANIFEST = REPO_ROOT / "packaging" / "distribution-manifest.json"
NORMALIZED_NAME = "bundleinspector"
VERSION = "0.1.0"
ROOT_FILES = (
    ".github/workflows/quality.yml",
    ".gitignore",
    "LICENSE",
    "README.en.md",
    "README.ko.md",
    "README.md",
    "pyproject.toml",
)
TREE_ROOTS = ("benchmarks", "docs", "examples", "packaging", "scripts", "src", "tests")
GENERATED_DIRECTORIES = {"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
BASELINE_PATHS = (
    "benchmarks/baselines/correlator.json",
    "benchmarks/baselines/detection.json",
)
REQUIRED_POLICY_PATHS = (
    *BASELINE_PATHS,
    "benchmarks/packaging-constraints.txt",
    "benchmarks/performance-constraints.txt",
    "packaging/distribution-manifest.json",
    "tests/heldout/frozen-governance.sha256",
    "tests/heldout/frozen-governance.zip",
    "tests/heldout/source/heldout.json",
)
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _relative_posix(path: Path, repository_root: Path) -> str:
    try:
        result = path.relative_to(repository_root).as_posix()
    except ValueError as exc:
        raise verifier.DistributionVerificationError("source path escapes repository root") from exc
    verifier._validate_archive_path(result, "distribution source")
    verifier._validate_payload_path(result, "distribution source")
    return result


def _collect_tree(path: Path, repository_root: Path, output: set[str]) -> None:
    try:
        with os.scandir(path) as scan:
            entries = sorted(scan, key=lambda entry: entry.name)
    except OSError as exc:
        raise verifier.DistributionVerificationError(f"cannot scan distribution source {path}") from exc
    for entry in entries:
        child = Path(entry.path)
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise verifier.DistributionVerificationError(
                f"cannot inspect distribution source {child}"
            ) from exc
        if entry.is_symlink() or _is_reparse(metadata):
            raise verifier.DistributionVerificationError(
                f"distribution source must not contain links or reparse points: {child}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            if entry.name in GENERATED_DIRECTORIES:
                continue
            _collect_tree(child, repository_root, output)
        elif stat.S_ISREG(metadata.st_mode):
            relative = _relative_posix(child, repository_root)
            if relative in output:
                raise verifier.DistributionVerificationError(
                    f"distribution source contains duplicate path {relative!r}"
                )
            output.add(relative)
        else:
            raise verifier.DistributionVerificationError(
                f"distribution source contains a special file: {child}"
            )

def _collect_sources(repository_root: Path) -> set[str]:
    result: set[str] = set()
    for relative in ROOT_FILES:
        path = repository_root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise verifier.DistributionVerificationError(
                f"required distribution source is missing: {relative}"
            ) from exc
        if path.is_symlink() or _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise verifier.DistributionVerificationError(
                f"required distribution source is not a regular file: {relative}"
            )
        result.add(_relative_posix(path, repository_root))
    for relative in TREE_ROOTS:
        path = repository_root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise verifier.DistributionVerificationError(
                f"required distribution tree is missing: {relative}"
            ) from exc
        if path.is_symlink() or _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise verifier.DistributionVerificationError(
                f"required distribution tree is not a regular directory: {relative}"
            )
        _collect_tree(path, repository_root, result)
    # The manifest is self-describing and therefore absent only during first publication.
    result.add("packaging/distribution-manifest.json")
    aliases: dict[str, str] = {}
    for relative in sorted(result):
        alias = verifier._collision_key(relative)
        previous = aliases.get(alias)
        if previous is not None:
            raise verifier.DistributionVerificationError(
                f"distribution sources collide portably: {previous!r} / {relative!r}"
            )
        aliases[alias] = relative
    return result


def build_manifest(
    repository_root: Path = REPO_ROOT,
    *,
    allow_missing_baselines: bool = False,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    repository_root = repository_root.absolute()
    sources = _collect_sources(repository_root)
    missing = tuple(path for path in REQUIRED_POLICY_PATHS if path not in sources)
    forbidden_missing = tuple(path for path in missing if path not in BASELINE_PATHS)
    if forbidden_missing:
        raise verifier.DistributionVerificationError(
            f"required distribution policy files are missing: {list(forbidden_missing)!r}"
        )
    if missing and not allow_missing_baselines:
        raise verifier.DistributionVerificationError(
            f"performance baselines are missing: {list(missing)!r}"
        )
    sources.update(BASELINE_PATHS)
    package_prefix = "src/bundleInspector/"
    package_files = sorted(
        path[len("src/") :] for path in sources if path.startswith(package_prefix)
    )
    dist_info = f"{NORMALIZED_NAME}-{VERSION}.dist-info"
    wheel_files = sorted(
        (
            *package_files,
            f"{dist_info}/METADATA",
            f"{dist_info}/RECORD",
            f"{dist_info}/WHEEL",
            f"{dist_info}/entry_points.txt",
            f"{dist_info}/licenses/LICENSE",
        )
    )
    sdist_files = sorted((*sources, "PKG-INFO"))
    manifest: dict[str, Any] = {
        "distribution": {"normalized_name": NORMALIZED_NAME, "version": VERSION},
        "schema_version": verifier.SCHEMA_VERSION,
        "sdist": {
            "directories": [],
            "filename": f"{NORMALIZED_NAME}-{VERSION}.tar.gz",
            "files": sdist_files,
            "root": f"{NORMALIZED_NAME}-{VERSION}",
            "root_directory": False,
        },
        "wheel": {
            "filename": f"{NORMALIZED_NAME}-{VERSION}-py3-none-any.whl",
            "files": wheel_files,
        },
    }
    encoded = json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n"
    with tempfile.TemporaryDirectory(prefix="bundleinspector-manifest-review-") as temporary:
        review_path = Path(temporary) / "manifest.json"
        review_path.write_text(encoded, encoding="utf-8", newline="\n")
        verifier.load_manifest(review_path)
    return manifest, missing


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def publish_manifest(path: Path, content: bytes, *, replace: bool) -> None:
    if path.exists() and not replace:
        raise FileExistsError("distribution manifest exists; pass --replace after review")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "xb", dir=path.parent, prefix=f".{path.name}.", suffix=".stage", delete=False
        ) as output:
            temporary_name = output.name
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--allow-missing-baselines", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest, missing = build_manifest(
            args.repository_root,
            allow_missing_baselines=args.allow_missing_baselines,
        )
        content = _manifest_bytes(manifest)
        if args.check:
            with verifier._open_reviewed_file(
                args.manifest, "manifest", verifier.MAX_MANIFEST_SIZE
            ) as source:
                existing = source.read(verifier.MAX_MANIFEST_SIZE + 1)
            if existing != content:
                raise verifier.DistributionVerificationError(
                    "committed distribution manifest is stale"
                )
        else:
            publish_manifest(args.manifest, content, replace=args.replace)
    except (
        FileExistsError,
        OSError,
        TypeError,
        verifier.DistributionVerificationError,
        ValueError,
    ) as exc:
        parser.exit(2, f"distribution manifest error: {exc}\n")
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "missing_expected_baselines": list(missing),
                "passed": True,
                "schema_version": verifier.SCHEMA_VERSION,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
