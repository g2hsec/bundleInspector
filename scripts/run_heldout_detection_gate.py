"""Validate and execute the frozen held-out governance detection corpus."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from bundleInspector.validation.metrics import (  # noqa: E402
    RELEASE_GATE_KEYS,
    CorpusCase,
    CorpusError,
    evaluate_regression_baseline,
    load_manifest,
    load_regression_baseline,
    run_corpus,
)

ARCHIVE_MAX_BYTES = 100 * 1024 * 1024
EXTRACTED_MAX_BYTES = 256 * 1024 * 1024
MEMBER_MAX_BYTES = 32 * 1024 * 1024
MEMBER_MAX_COUNT = 2_048
MAX_COMPRESSION_RATIO = 1_000
METADATA_NAME = "heldout.json"
CORPUS_PREFIX = "corpus/"
DEFAULT_ARCHIVE = REPO_ROOT / "tests" / "heldout" / "frozen-governance.zip"
DEFAULT_CHECKSUM = REPO_ROOT / "tests" / "heldout" / "frozen-governance.sha256"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_GROUP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CHECKSUM_FILE_RE = re.compile(
    r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip)(?:\r?\n)?\Z"
)
_JS_TOKEN_RE = re.compile(
    r"(?P<comment>//[^\r\n]*|/\*.*?\*/)"
    r"|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)"
    r"|(?P<number>\b(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)\b)"
    r"|(?P<identifier>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"|(?P<operator>===|!==|=>|==|!=|<=|>=|\?\?|&&|\|\||\+\+|--|\*\*|\?\.|\S)",
    re.DOTALL,
)
_JS_KEYWORDS = frozenset(
    {
        "async", "await", "break", "case", "catch", "class", "const", "continue",
        "debugger", "default", "delete", "do", "else", "export", "extends", "false",
        "finally", "for", "from", "function", "if", "import", "in", "instanceof", "let",
        "new", "null", "of", "return", "static", "super", "switch", "this", "throw",
        "true", "try", "typeof", "undefined", "var", "void", "while", "with", "yield",
    }
)
CLONE_POLICY_VERSION = 1
CLONE_SHINGLE_WIDTH = 8
_PUBLIC_SPLITS = ("training_calibration", "validation")
_TARGET_FRACTIONS = {
    "training_calibration": 0.6,
    "validation": 0.2,
    "held_out": 0.2,
}


class HeldOutGateError(ValueError):
    """Fail-closed held-out artifact validation error with a non-sensitive code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _BoundedTextSink(io.StringIO):
    """Keep detector diagnostics private and bounded in memory."""

    def __init__(self, limit: int = 1024 * 1024):
        self._limit = limit
        self._size = 0

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        encoded_size = len(value.encode("utf-8", errors="replace"))
        if self._size + encoded_size > self._limit:
            raise HeldOutGateError("diagnostic-limit-exceeded")
        self._size += encoded_size
        return len(value)


@dataclass(frozen=True)
class PublicIdentity:
    snapshot_sha256: str
    partition_sha256: str
    case_ids: frozenset[str]
    asset_sha256: frozenset[str]
    group_ids: frozenset[str]
    vendor_family_ids: frozenset[str]
    source_profiles: tuple[SourceProfile, ...]
    split_counts: dict[str, int]


@dataclass(frozen=True)
class HeldOutBundle:
    corpus_root: Path
    case_count: int
    public_identity: PublicIdentity


@dataclass(frozen=True)
class SourceProfile:
    lexical_shingles: frozenset[str]
    structural_shingles: frozenset[str]


def _fail(code: str) -> NoReturn:
    raise HeldOutGateError(code)


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _plain_directory(path: Path, code: str) -> os.stat_result:
    try:
        file_stat = path.lstat()
    except OSError:
        _fail(code)
    if not stat.S_ISDIR(file_stat.st_mode) or stat.S_ISLNK(file_stat.st_mode) or _is_reparse_point(file_stat):
        _fail(code)
    return file_stat


def _safe_file_bytes(path: Path, root: Path, code: str, *, max_bytes: int | None = None) -> bytes:
    root_absolute = root.absolute()
    candidate = path.absolute()
    try:
        candidate.relative_to(root_absolute)
    except ValueError:
        _fail(code)
    _plain_directory(root_absolute, code)
    current = candidate.parent
    while current != root_absolute:
        _plain_directory(current, code)
        parent = current.parent
        if parent == current:
            _fail(code)
        current = parent
    try:
        before = candidate.lstat()
    except OSError:
        _fail(code)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or before.st_nlink != 1
    ):
        _fail(code)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError:
        _fail(code)
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            _fail(code)
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            content = source.read(None if max_bytes is None else max_bytes + 1)
    except OSError:
        _fail(code)
    finally:
        os.close(descriptor)
    if max_bytes is not None and len(content) > max_bytes:
        _fail(code)
    return content


def _manifest_asset_paths(corpus_root: Path, code: str) -> list[Path]:
    content = _safe_file_bytes(corpus_root / "manifest.jsonl", corpus_root, code)
    assets: list[Path] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        raw = _strict_json_bytes(line, code)
        if not isinstance(raw, dict) or not isinstance(raw.get("asset"), str):
            _fail(code)
        relative = PurePosixPath(raw["asset"])
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            _fail(code)
        assets.append(corpus_root / Path(*relative.parts))
    if not assets:
        _fail(code)
    return assets


def _safe_corpus_inputs(corpus_root: Path, code: str) -> dict[Path, bytes]:
    _plain_directory(corpus_root.absolute(), code)
    required = [
        corpus_root / "manifest.jsonl",
        corpus_root / "gates.json",
        corpus_root / "baseline.json",
        *_manifest_asset_paths(corpus_root, code),
    ]
    return {
        path.absolute(): _safe_file_bytes(path, corpus_root, code)
        for path in required
    }


def _source_tokens(content: bytes) -> tuple[list[str], list[str]]:
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError:
        _fail("corpus-source-invalid")
    lexical: list[str] = []
    structural: list[str] = []
    for match in _JS_TOKEN_RE.finditer(source):
        kind = match.lastgroup
        token = match.group(0)
        if kind == "comment":
            continue
        lexical.append(token)
        if kind == "identifier" and token not in _JS_KEYWORDS:
            structural.append("<id>")
        elif kind == "string":
            structural.append("<str>")
        elif kind == "number":
            structural.append("<num>")
        else:
            structural.append(token)
    return lexical, structural


def _token_shingles(tokens: list[str]) -> frozenset[str]:
    if not tokens:
        return frozenset()
    width = min(CLONE_SHINGLE_WIDTH, len(tokens))
    return frozenset(
        hashlib.sha256("\0".join(tokens[index:index + width]).encode("utf-8")).hexdigest()
        for index in range(len(tokens) - width + 1)
    )


def _source_profile(content: bytes) -> SourceProfile:
    lexical, structural = _source_tokens(content)
    return SourceProfile(
        lexical_shingles=_token_shingles(lexical),
        structural_shingles=_token_shingles(structural),
    )


def _similarity(left: frozenset[str], right: frozenset[str]) -> tuple[float, float, float]:
    if not left or not right:
        return 0.0, 0.0, 0.0
    overlap = len(left & right)
    return (
        overlap / len(left | right),
        overlap / min(len(left), len(right)),
        min(len(left), len(right)) / max(len(left), len(right)),
    )


def _is_near_clone(left: SourceProfile, right: SourceProfile) -> bool:
    lexical_jaccard, lexical_containment, _ = _similarity(
        left.lexical_shingles,
        right.lexical_shingles,
    )
    if lexical_jaccard >= 0.75 or lexical_containment >= 0.90:
        return True
    structural_jaccard, _, size_ratio = _similarity(
        left.structural_shingles,
        right.structural_shingles,
    )
    return size_ratio >= 0.70 and structural_jaccard >= 0.90


def _strict_json_bytes(content: bytes, code: str) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(code)
            result[key] = value
        return result

    def reject_constant(_value: str) -> NoReturn:
        _fail(code)

    try:
        return json.loads(
            content.decode("utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(code)


def _strict_json_file(path: Path, code: str, *, root: Path | None = None) -> Any:
    content = _safe_file_bytes(path, root or path.parent, code)
    return _strict_json_bytes(content, code)


def _expect_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(code)
    return value


def _positive_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(code)
    return int(value)


def _sha256(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _snapshot_digest(corpus_root: Path, cases: list[CorpusCase]) -> str:
    safe_inputs = _safe_corpus_inputs(corpus_root, "public-corpus-incomplete")
    unique = sorted(safe_inputs, key=lambda path: path.as_posix())
    digest = hashlib.sha256()
    root = corpus_root.absolute()
    for path in unique:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = safe_inputs[path]
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def load_public_identity(corpus_root: Path, partition_path: Path) -> PublicIdentity:
    safe_inputs = _safe_corpus_inputs(corpus_root, "public-corpus-incomplete")
    try:
        cases = load_manifest(corpus_root)
    except CorpusError:
        _fail("public-corpus-invalid")
    root = _expect_keys(
        _strict_json_file(partition_path, "public-partition-invalid", root=partition_path.parent),
        {"schema_version", "target_fractions", "cases"},
        "public-partition-invalid",
    )
    if root["schema_version"] != 2:
        _fail("public-partition-invalid")
    fractions = _expect_keys(
        root["target_fractions"],
        set(_TARGET_FRACTIONS),
        "public-partition-invalid",
    )
    for name, expected in _TARGET_FRACTIONS.items():
        value = fractions[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            _fail("public-partition-invalid")
        if not math.isfinite(float(value)) or float(value) != expected:
            _fail("public-partition-invalid")

    entries = root["cases"]
    if not isinstance(entries, list) or not entries:
        _fail("public-partition-invalid")
    by_case: dict[str, tuple[str, str, str]] = {}
    group_splits: dict[str, str] = {}
    vendor_splits: dict[str, str] = {}
    split_counts = dict.fromkeys(_PUBLIC_SPLITS, 0)
    for raw in entries:
        entry = _expect_keys(
            raw,
            {"case_id", "split", "group_id", "vendor_family_id"},
            "public-partition-invalid",
        )
        case_id = entry["case_id"]
        split = entry["split"]
        group_id = entry["group_id"]
        vendor_family_id = entry["vendor_family_id"]
        if not isinstance(case_id, str) or not case_id or case_id in by_case:
            _fail("public-partition-invalid")
        if split not in _PUBLIC_SPLITS:
            _fail("public-partition-invalid")
        if not isinstance(group_id, str) or _GROUP_RE.fullmatch(group_id) is None:
            _fail("public-partition-invalid")
        if not isinstance(vendor_family_id, str) or _GROUP_RE.fullmatch(vendor_family_id) is None:
            _fail("public-partition-invalid")
        if group_id in group_splits and group_splits[group_id] != split:
            _fail("public-group-crosses-splits")
        group_splits[group_id] = split
        if vendor_family_id in vendor_splits and vendor_splits[vendor_family_id] != split:
            _fail("public-vendor-crosses-splits")
        vendor_splits[vendor_family_id] = split
        by_case[case_id] = (split, group_id, vendor_family_id)
        split_counts[split] += 1

    manifest_ids = {case.case_id for case in cases}
    if set(by_case) != manifest_ids:
        _fail("public-partition-case-mismatch")
    source_profiles = tuple(
        _source_profile(safe_inputs[case.asset.absolute()])
        for case in cases
    )
    return PublicIdentity(
        snapshot_sha256=_snapshot_digest(corpus_root, cases),
        partition_sha256=_canonical_digest(root),
        case_ids=frozenset(manifest_ids),
        asset_sha256=frozenset(case.asset_fingerprint for case in cases),
        group_ids=frozenset(group_splits),
        vendor_family_ids=frozenset(vendor_splits),
        source_profiles=source_profiles,
        split_counts=split_counts,
    )


def public_identity_payload(identity: PublicIdentity) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "source_clone_policy_version": CLONE_POLICY_VERSION,
        "public_snapshot_sha256": identity.snapshot_sha256,
        "public_partition_sha256": identity.partition_sha256,
        "public_case_count": len(identity.case_ids),
        "public_vendor_family_count": len(identity.vendor_family_ids),
        "training_calibration_case_count": identity.split_counts["training_calibration"],
        "validation_case_count": identity.split_counts["validation"],
        "target_fractions": dict(_TARGET_FRACTIONS),
    }


def _validated_archive_member(info: zipfile.ZipInfo) -> PurePosixPath | None:
    name = info.filename
    if not name or "\\" in name or "\x00" in name:
        _fail("archive-member-invalid")
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        _fail("archive-member-invalid")
    mode = info.external_attr >> 16
    if mode and stat.S_ISLNK(mode):
        _fail("archive-link-forbidden")
    if info.flag_bits & 0x1:
        _fail("archive-encryption-forbidden")
    if info.is_dir():
        return None
    if name != METADATA_NAME and not name.startswith(CORPUS_PREFIX):
        _fail("archive-layout-invalid")
    if info.file_size > MEMBER_MAX_BYTES or info.compress_size < 0:
        _fail("archive-member-too-large")
    if info.compress_size == 0 and info.file_size:
        _fail("archive-compression-invalid")
    if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
        _fail("archive-compression-invalid")
    return relative


def extract_archive(archive_path: Path, expected_sha256: str, destination: Path) -> None:
    expected = _sha256(expected_sha256, "archive-checksum-invalid")
    content = _safe_file_bytes(
        archive_path,
        archive_path.parent,
        "archive-unavailable",
        max_bytes=ARCHIVE_MAX_BYTES,
    )
    size = len(content)
    if size < 1 or size > ARCHIVE_MAX_BYTES:
        _fail("archive-size-invalid")
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        _fail("archive-checksum-mismatch")

    destination.mkdir(parents=True, exist_ok=False)
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except (OSError, zipfile.BadZipFile):
        _fail("archive-format-invalid")
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MEMBER_MAX_COUNT:
            _fail("archive-member-count-invalid")
        total_size = sum(info.file_size for info in infos)
        if total_size > EXTRACTED_MAX_BYTES:
            _fail("archive-expanded-size-invalid")
        seen: set[str] = set()
        extracted: set[str] = set()
        root = destination.resolve()
        for info in infos:
            relative = _validated_archive_member(info)
            if relative is None:
                continue
            collision_key = relative.as_posix().casefold()
            if collision_key in seen:
                _fail("archive-member-duplicate")
            seen.add(collision_key)
            target = (destination / Path(*relative.parts)).resolve()
            if not target.is_relative_to(root):
                _fail("archive-member-invalid")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > info.file_size or written > MEMBER_MAX_BYTES:
                            _fail("archive-member-size-mismatch")
                        output.write(chunk)
            except (NotImplementedError, OSError, RuntimeError, zipfile.BadZipFile):
                _fail("archive-extraction-failed")
            if written != info.file_size:
                _fail("archive-member-size-mismatch")
            extracted.add(relative.as_posix())
        required = {
            METADATA_NAME,
            "corpus/manifest.jsonl",
            "corpus/gates.json",
            "corpus/baseline.json",
        }
        if not required <= extracted:
            _fail("archive-layout-invalid")


def validate_heldout_bundle(
    extracted_root: Path,
    public_corpus: Path,
    public_partition: Path,
) -> HeldOutBundle:
    identity = load_public_identity(public_corpus, public_partition)
    metadata = _expect_keys(
        _strict_json_file(
            extracted_root / METADATA_NAME,
            "heldout-metadata-invalid",
            root=extracted_root,
        ),
        {
            "schema_version",
            "split",
            "target_fraction",
            "source_clone_policy_version",
            "public_snapshot_sha256",
            "public_partition_sha256",
            "public_case_count",
            "held_out_case_count",
            "gates_sha256",
            "baseline_sha256",
            "cases",
        },
        "heldout-metadata-invalid",
    )
    if metadata["schema_version"] != 2 or metadata["split"] != "held-out":
        _fail("heldout-metadata-invalid")
    if metadata["source_clone_policy_version"] != CLONE_POLICY_VERSION:
        _fail("heldout-clone-policy-mismatch")
    if metadata["target_fraction"] != _TARGET_FRACTIONS["held_out"]:
        _fail("heldout-metadata-invalid")
    if _sha256(metadata["public_snapshot_sha256"], "heldout-metadata-invalid") != identity.snapshot_sha256:
        _fail("heldout-public-snapshot-mismatch")
    if _sha256(metadata["public_partition_sha256"], "heldout-metadata-invalid") != identity.partition_sha256:
        _fail("heldout-public-partition-mismatch")
    if _positive_int(metadata["public_case_count"], "heldout-metadata-invalid") != len(identity.case_ids):
        _fail("heldout-public-count-mismatch")

    corpus_root = extracted_root / "corpus"
    safe_inputs = _safe_corpus_inputs(corpus_root, "heldout-corpus-invalid")
    gates_path = (corpus_root / "gates.json").absolute()
    baseline_path = (corpus_root / "baseline.json").absolute()
    gates = _strict_json_bytes(safe_inputs[gates_path], "heldout-corpus-invalid")
    if _sha256(metadata["gates_sha256"], "heldout-metadata-invalid") != _canonical_digest(gates):
        _fail("heldout-gates-digest-mismatch")
    if _sha256(metadata["baseline_sha256"], "heldout-metadata-invalid") != hashlib.sha256(
        safe_inputs[baseline_path]
    ).hexdigest():
        _fail("heldout-baseline-digest-mismatch")
    try:
        cases = load_manifest(corpus_root)
    except CorpusError:
        _fail("heldout-corpus-invalid")
    heldout_count = _positive_int(metadata["held_out_case_count"], "heldout-metadata-invalid")
    if heldout_count != len(cases):
        _fail("heldout-case-count-mismatch")
    total = len(identity.case_ids) + heldout_count
    observed_counts = {
        **identity.split_counts,
        "held_out": heldout_count,
    }
    for split, target in _TARGET_FRACTIONS.items():
        expected_count = math.floor(total * target + 0.5)
        if observed_counts[split] != expected_count:
            _fail("heldout-split-fraction-mismatch")

    metadata_cases = metadata["cases"]
    if not isinstance(metadata_cases, list) or not metadata_cases:
        _fail("heldout-metadata-invalid")
    declared: dict[str, tuple[str, str, str]] = {}
    for raw in metadata_cases:
        entry = _expect_keys(
            raw,
            {"case_id", "group_id", "vendor_family_id", "asset_sha256"},
            "heldout-metadata-invalid",
        )
        case_id = entry["case_id"]
        group_id = entry["group_id"]
        vendor_family_id = entry["vendor_family_id"]
        asset_sha256 = _sha256(entry["asset_sha256"], "heldout-metadata-invalid")
        if not isinstance(case_id, str) or not case_id or case_id in declared:
            _fail("heldout-metadata-invalid")
        if not isinstance(group_id, str) or _GROUP_RE.fullmatch(group_id) is None:
            _fail("heldout-metadata-invalid")
        if not isinstance(vendor_family_id, str) or _GROUP_RE.fullmatch(vendor_family_id) is None:
            _fail("heldout-metadata-invalid")
        declared[case_id] = (group_id, vendor_family_id, asset_sha256)
    by_case = {case.case_id: case for case in cases}
    if set(declared) != set(by_case):
        _fail("heldout-case-metadata-mismatch")
    if set(by_case) & identity.case_ids:
        _fail("heldout-case-overlap")
    heldout_profiles: list[SourceProfile] = []
    for case_id, case in by_case.items():
        group_id, vendor_family_id, asset_sha256 = declared[case_id]
        if group_id in identity.group_ids:
            _fail("heldout-group-overlap")
        if vendor_family_id in identity.vendor_family_ids:
            _fail("heldout-vendor-overlap")
        if asset_sha256 != case.asset_fingerprint:
            _fail("heldout-asset-digest-mismatch")
        if asset_sha256 in identity.asset_sha256:
            _fail("heldout-source-overlap")
        profile = _source_profile(safe_inputs[case.asset.absolute()])
        if any(_is_near_clone(profile, public_profile) for public_profile in identity.source_profiles):
            _fail("heldout-source-near-clone")
        if any(_is_near_clone(profile, existing) for existing in heldout_profiles):
            _fail("heldout-internal-near-clone")
        heldout_profiles.append(profile)
    return HeldOutBundle(
        corpus_root=corpus_root,
        case_count=heldout_count,
        public_identity=identity,
    )


def execute_gate(bundle: HeldOutBundle) -> dict[str, Any]:
    sink = _BoundedTextSink()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            result = run_corpus(
                bundle.corpus_root,
                gates_path=bundle.corpus_root / "gates.json",
                required_gate_keys=RELEASE_GATE_KEYS,
            )
            regressions = evaluate_regression_baseline(
                result,
                load_regression_baseline(bundle.corpus_root / "baseline.json"),
            )
    except HeldOutGateError:
        raise
    except (CorpusError, OSError, RuntimeError, ValueError):
        _fail("heldout-metric-execution-error")
    if result.case_count != bundle.case_count:
        _fail("heldout-result-count-mismatch")
    passed = result.passed and not regressions
    return {
        "schema_version": 2,
        "split": "held-out",
        "case_count": bundle.case_count,
        "passed": passed,
        "reason": None if passed else "metric-gate-failed",
    }


def _render(payload: dict[str, Any]) -> str:
    return json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _checksum_from_file(path: Path, archive_name: str) -> str:
    try:
        content = _safe_file_bytes(path, path.parent, "archive-checksum-file-invalid", max_bytes=256)
        decoded = content.decode("ascii")
    except UnicodeDecodeError:
        _fail("archive-checksum-file-invalid")
    match = _CHECKSUM_FILE_RE.fullmatch(decoded)
    if match is None or match.group(2) != archive_name:
        _fail("archive-checksum-file-invalid")
    return match.group(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    identity_parser = subparsers.add_parser("identity", help="Print the non-sensitive public snapshot identity")
    identity_parser.add_argument("--public-corpus", type=Path, default=REPO_ROOT / "tests" / "corpus")
    identity_parser.add_argument(
        "--partition",
        type=Path,
        default=REPO_ROOT / "tests" / "corpus" / "partition.json",
    )
    subparsers.add_parser("run", help="Validate and execute the committed frozen governance ZIP")
    args = parser.parse_args(argv)
    try:
        if args.command == "identity":
            print(_render(public_identity_payload(load_public_identity(args.public_corpus, args.partition))))
            return 0
        with tempfile.TemporaryDirectory(prefix="bundleinspector-heldout-") as temporary:
            extracted = Path(temporary) / "extracted"
            digest = _checksum_from_file(DEFAULT_CHECKSUM, DEFAULT_ARCHIVE.name)
            extract_archive(DEFAULT_ARCHIVE, digest, extracted)
            bundle = validate_heldout_bundle(
                extracted,
                REPO_ROOT / "tests" / "corpus",
                REPO_ROOT / "tests" / "corpus" / "partition.json",
            )
            payload = execute_gate(bundle)
    except HeldOutGateError as exc:
        parser.exit(2, f"held-out gate error: {exc.code}\n")
    print(_render(payload))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
