"""Run the strict labeled detection corpus and enforce release gates."""

from __future__ import annotations

import argparse
import contextlib
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
    evaluate_regression_baseline,
    load_regression_baseline,
    run_corpus,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=REPO_ROOT / "tests" / "corpus",
        help="Corpus root containing manifest.jsonl and source assets",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Optional manifest path; defaults to <corpus>/manifest.jsonl",
    )
    parser.add_argument(
        "--gates",
        type=Path,
        default=None,
        help="Gate JSON path; defaults to <corpus>/gates.json when present",
    )
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON result file")
    parser.add_argument(
        "--allow-custom-gates",
        action="store_true",
        help="Allow a custom metric gate subset instead of the complete release profile",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Compare against the committed corpus baseline and fail on any regression",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Regression baseline path; defaults to <corpus>/baseline.json",
    )
    args = parser.parse_args(argv)

    if args.baseline is not None and not args.fail_on_regression:
        parser.error("--baseline requires --fail-on-regression")
    if args.allow_custom_gates and args.fail_on_regression:
        parser.error("--allow-custom-gates cannot be combined with --fail-on-regression")

    gates = args.gates
    default_gates = args.corpus / "gates.json"
    if gates is None:
        gates = default_gates
    baseline_path = args.baseline or args.corpus / "baseline.json"
    try:
        # Detector warnings are operational diagnostics. Keep stdout as one valid JSON document so
        # CI and release tooling cannot be broken by a contained rule warning.
        with contextlib.redirect_stdout(sys.stderr):
            result = run_corpus(
                args.corpus,
                manifest_path=args.manifest,
                gates_path=gates,
                required_gate_keys=None if args.allow_custom_gates else RELEASE_GATE_KEYS,
            )
        regression_failures = (
            evaluate_regression_baseline(
                result,
                load_regression_baseline(baseline_path),
            )
            if args.fail_on_regression
            else []
        )
    except CorpusError as exc:
        parser.exit(2, f"corpus error: {exc}\n")

    result_payload = result.to_dict()
    result_payload["regression_failures"] = regression_failures
    result_payload["regression_baseline"] = (
        str(baseline_path.resolve()) if args.fail_on_regression else None
    )
    result_payload["passed"] = result.passed and not regression_failures
    payload = json.dumps(result_payload, indent=2, sort_keys=True, allow_nan=False)
    print(payload)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    return 0 if result_payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
