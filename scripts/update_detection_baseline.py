"""Explicitly regenerate the committed detection-regression baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from bundleInspector.validation.metrics import (  # noqa: E402
    RELEASE_GATE_KEYS,
    CorpusError,
    build_regression_baseline,
    run_corpus,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=REPO_ROOT / "tests" / "corpus",
    )
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--gates", type=Path, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Explicit destination for the reviewed baseline JSON",
    )
    args = parser.parse_args(argv)

    manifest = args.manifest or args.corpus / "manifest.jsonl"
    gates = args.gates or args.corpus / "gates.json"
    output = args.output.resolve()
    protected_inputs = {manifest.resolve(), gates.resolve()}
    if output in protected_inputs or output.suffix.lower() != ".json":
        parser.error("--output must be a dedicated .json file, not a manifest or gate input")

    try:
        result = run_corpus(
            args.corpus,
            manifest_path=manifest,
            gates_path=gates,
            required_gate_keys=RELEASE_GATE_KEYS,
        )
        payload = build_regression_baseline(result)
    except CorpusError as exc:
        parser.exit(2, f"baseline error: {exc}\n")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    print(json.dumps({
        "baseline": str(output),
        "corpus_fingerprint": payload["corpus_fingerprint"],
        "gate_profile_fingerprint": payload["gate_profile_fingerprint"],
    }, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
