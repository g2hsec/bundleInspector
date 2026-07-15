"""Write reviewed performance baselines from completed release benchmark JSON."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.benchmark_correlator import (  # noqa: E402
    create_baseline_payload as create_correlator_baseline,
)
from scripts.benchmark_correlator import (  # noqa: E402
    validate_result_document as validate_correlator_result,
)
from scripts.benchmark_detection import (  # noqa: E402
    create_baseline_payload as create_detection_baseline,
)
from scripts.benchmark_detection import (  # noqa: E402
    validate_result_document as validate_detection_result,
)

DEFAULT_OUTPUT_DIR = REPO_ROOT / "benchmarks" / "baselines"
CORRELATOR_BASELINE_NAME = "correlator.json"
DETECTION_BASELINE_NAME = "detection.json"


def _strict_json(path: Path) -> dict[str, Any]:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant {value}")

    raw = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=pairs_hook,
        parse_constant=reject_constant,
    )
    if not isinstance(raw, dict):
        raise ValueError("benchmark result root must be a JSON object")
    return raw


def _validated_source(payload: dict[str, Any], benchmark: str) -> dict[str, Any]:
    if benchmark == "correlator":
        return validate_correlator_result(payload, require_runtime_compatibility=True)
    if benchmark == "detection":
        return validate_detection_result(payload, require_runtime_compatibility=True)
    raise ValueError(f"unsupported benchmark role {benchmark!r}")


def _serialize_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ) + "\n").encode("utf-8")


def _stage_content(path: Path, content: bytes, *, suffix: str) -> Path:
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
        staged = Path(temporary_name)
        temporary_name = None
        return staged
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _publish_pair(paths: tuple[Path, Path], contents: tuple[bytes, bytes], *, replace: bool) -> None:
    existing = tuple(path.exists() for path in paths)
    if existing[0] != existing[1]:
        raise FileExistsError("baseline directory contains an incomplete pair")
    if existing[0] and not replace:
        raise FileExistsError("baseline pair exists; pass --replace after review")

    staged_list: list[Path] = []
    try:
        for path, content in zip(paths, contents, strict=True):
            staged_list.append(_stage_content(path, content, suffix=".stage"))
    except Exception:
        for temporary in staged_list:
            temporary.unlink(missing_ok=True)
        raise
    staged = tuple(staged_list)
    backups: list[Path | None] = [None, None]
    promoted = 0
    try:
        if existing[0]:
            for index, path in enumerate(paths):
                backup = _stage_content(
                    path,
                    path.read_bytes(),
                    suffix=".backup",
                )
                backups[index] = backup
        for index, (stage, path) in enumerate(zip(staged, paths, strict=True)):
            os.replace(stage, path)
            promoted = index + 1
    except Exception:
        for index in range(promoted):
            paths[index].unlink(missing_ok=True)
        for backup_path, destination in zip(backups, paths, strict=True):
            if backup_path is not None:
                os.replace(backup_path, destination)
        raise
    finally:
        for temporary_path in (*staged, *backups):
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def write_baselines(
    correlator_result: Path,
    detection_result: Path,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    *,
    replace: bool = False,
) -> tuple[Path, Path]:
    correlator_raw = _strict_json(correlator_result)
    detection_raw = _strict_json(detection_result)
    correlator_source = _validated_source(correlator_raw, "correlator")
    detection_source = _validated_source(detection_raw, "detection")
    correlator_scenarios = correlator_source["scenarios"]
    detection_scenarios = detection_source["scenarios"]
    if not isinstance(correlator_scenarios, list):
        raise ValueError("correlator scenarios must be an array")
    if not isinstance(detection_scenarios, dict):
        raise ValueError("detection scenarios must be an object")
    correlator_baseline = create_correlator_baseline(
        correlator_scenarios,
        correlator_source["measurement_environment"],
    )
    detection_baseline = create_detection_baseline(
        detection_scenarios,
        detection_source["measurement_environment"],
    )
    correlator_path = output_dir / CORRELATOR_BASELINE_NAME
    detection_path = output_dir / DETECTION_BASELINE_NAME
    _publish_pair(
        (correlator_path, detection_path),
        (_serialize_json(correlator_baseline), _serialize_json(detection_baseline)),
        replace=replace,
    )
    return correlator_path, detection_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--correlator-result", type=Path, required=True)
    parser.add_argument("--detection-result", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        paths = write_baselines(
            args.correlator_result,
            args.detection_result,
            args.output_dir,
            replace=args.replace,
        )
    except (FileExistsError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"baseline writer error: {exc}\n")
    print(json.dumps({"written": [str(path.resolve()) for path in paths]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
