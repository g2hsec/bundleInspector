"""Executable contracts for parser and detector resource release gates."""

from __future__ import annotations

import copy
import gc
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts import benchmark_detection
from scripts.benchmark_detection import (
    CUSTOM_REGEX_WALL_MS,
    LEXICAL_P95_MS,
    LEXICAL_PEAK_RSS_BYTES,
    MIB,
    MODERN_PARSE_P95_MS,
    MODERN_PARSE_PEAK_RSS_BYTES,
    RELEASE_RUNS,
    RELEASE_WARMUPS,
    build_lexical_fixture,
    build_modern_source,
    create_baseline_payload,
    evaluate_gates,
    run_suite,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def executed_scenarios() -> dict[str, Any]:
    """Execute every production-path fixture once without treating it as a performance sample."""
    return run_suite(runs=1, warmups=0)


def _as_release_result(scenarios: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(scenarios)
    for scenario in result.values():
        scenario["runs"] = RELEASE_RUNS
        scenario["warmups"] = RELEASE_WARMUPS
        scenario["peak_rss_bytes"] = MIB
        _set_constant_timing(scenario, 1.0)
    result["custom_regex"]["timeout_disclosures"] = RELEASE_RUNS
    result["custom_regex"]["prior_result_preserved_runs"] = RELEASE_RUNS
    result["lexical_candidates"]["successful_runs"] = RELEASE_RUNS
    result["lexical_candidates"]["partial_disclosures"] = RELEASE_RUNS
    return result


def _set_constant_timing(scenario: dict[str, Any], value: float) -> None:
    scenario["timings_ms"] = {
        "min": value,
        "p50": value,
        "p95": value,
        "max": value,
        "mean": value,
        "coefficient_of_variation": 0.0,
        "p50_bootstrap_95_ci": [value, value],
        "p95_bootstrap_95_ci": [value, value],
        "samples": [value] * int(scenario["runs"]),
    }


def _baseline_payload(scenarios: dict[str, Any]) -> dict[str, Any]:
    return create_baseline_payload(
        scenarios,
        _baseline_environment(),
    )


def _baseline_environment() -> dict[str, Any]:
    return {
        "os": "Linux",
        "os_release": "test-provenance-only",
        "machine": "x86_64",
        "python": "3.13.0",
        "implementation": "CPython",
        "measurement_origin": "local-wsl",
        "cpu_model": "Test Release CPU",
        "dependencies": {
            "bundleInspector": "0.1.0",
            "pydantic": "2.13.4",
            "pydantic-core": "2.46.4",
            "regex": "2026.7.10",
            "tree-sitter": "0.26.0",
            "tree-sitter-javascript": "0.25.0",
            "tree-sitter-typescript": "0.23.2",
        },
    }


def test_release_result_self_identifies_profile_environment_and_fixture(
    executed_scenarios: dict[str, Any],
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    environment = _baseline_environment()
    payload = benchmark_detection.create_result_payload(
        scenarios,
        environment,
        runs=RELEASE_RUNS,
        warmups=RELEASE_WARMUPS,
        gate_failures=[],
    )

    assert payload["benchmark"] == "detection"
    assert payload["profile"] == benchmark_detection.BASELINE_PROFILE
    assert payload["measurement_environment"] == environment
    assert payload["scenario_contract_sha256"] == benchmark_detection._canonical_sha256(
        benchmark_detection._expected_detection_contract()
    )
    assert benchmark_detection.validate_result_document(
        copy.deepcopy(payload),
        require_runtime_compatibility=False,
    ) == payload


def test_release_result_rejects_cross_environment_and_misrouted_role(
    executed_scenarios: dict[str, Any],
) -> None:
    payload = benchmark_detection.create_result_payload(
        _as_release_result(executed_scenarios),
        _baseline_environment(),
        runs=RELEASE_RUNS,
        warmups=RELEASE_WARMUPS,
        gate_failures=[],
    )
    cross_environment = copy.deepcopy(payload)
    cross_environment["measurement_environment"]["os"] = "Darwin"
    with pytest.raises(ValueError, match="platform is incompatible"):
        benchmark_detection.validate_result_document(
            cross_environment,
            require_runtime_compatibility=False,
        )

    misrouted = copy.deepcopy(payload)
    misrouted["benchmark"] = "correlator"
    with pytest.raises(ValueError, match="benchmark profile is incompatible"):
        benchmark_detection.validate_result_document(
            misrouted,
            require_runtime_compatibility=False,
        )


@pytest.mark.parametrize(
    ("cpu_model", "expected_state"),
    [
        ("Test Release CPU", "applied_same_hardware"),
        (
            "Different Hosted CPU",
            "applied_cross_hardware_attribution_unavailable",
        ),
    ],
)
def test_detection_main_applies_timing_regression_gate_on_every_hardware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    executed_scenarios: dict[str, Any],
    cpu_model: str,
    expected_state: str,
) -> None:
    baseline_scenarios = _as_release_result(executed_scenarios)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_baseline_payload(baseline_scenarios)), encoding="utf-8")
    current = copy.deepcopy(baseline_scenarios)
    for scenario in current.values():
        _set_constant_timing(scenario, 2.0)
    environment = _baseline_environment()
    environment["cpu_model"] = cpu_model
    monkeypatch.setattr(benchmark_detection, "runtime_environment", lambda: environment)
    monkeypatch.setattr(benchmark_detection, "run_suite", lambda _runs, _warmups: current)

    return_code = benchmark_detection.main([
        "--runs", str(RELEASE_RUNS),
        "--warmups", str(RELEASE_WARMUPS),
        "--assert-gates",
        "--baseline", str(baseline),
    ])
    payload = json.loads(capsys.readouterr().out)

    assert return_code == 1
    assert payload["relative_baseline_comparison"] == expected_state
    assert any("regressed more than 20%" in failure for failure in payload["gate_failures"])


def test_detection_cross_hardware_still_rejects_rss_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    executed_scenarios: dict[str, Any],
) -> None:
    baseline_scenarios = _as_release_result(executed_scenarios)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_baseline_payload(baseline_scenarios)), encoding="utf-8")
    current = copy.deepcopy(baseline_scenarios)
    for scenario in current.values():
        scenario["peak_rss_bytes"] = MIB * 2
    environment = _baseline_environment()
    environment["cpu_model"] = "Different Hosted CPU"
    monkeypatch.setattr(benchmark_detection, "runtime_environment", lambda: environment)
    monkeypatch.setattr(benchmark_detection, "run_suite", lambda _runs, _warmups: current)

    return_code = benchmark_detection.main([
        "--runs", str(RELEASE_RUNS),
        "--warmups", str(RELEASE_WARMUPS),
        "--assert-gates",
        "--baseline", str(baseline),
    ])
    payload = json.loads(capsys.readouterr().out)

    assert return_code == 1
    assert (
        payload["relative_baseline_comparison"]
        == "applied_cross_hardware_attribution_unavailable"
    )
    assert any("peak RSS regressed more than 25%" in item for item in payload["gate_failures"])


def test_detection_cross_hardware_malformed_timing_fails_without_exception(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline = _baseline_payload(copy.deepcopy(current))
    current["modern_parse"]["timings_ms"]["p95_bootstrap_95_ci"] = ["bad", 1.0]

    failures = evaluate_gates(
        current,
        baseline=baseline,
        cross_hardware_baseline=True,
    )

    assert any("p95_bootstrap_95_ci" in failure for failure in failures)
    assert any("baseline comparison unavailable" in failure for failure in failures)


def test_modern_typescript_scenario_is_exact_complete_and_preserves_literal(
    executed_scenarios: dict[str, Any],
) -> None:
    source = build_modern_source()
    result = executed_scenarios["modern_parse"]

    assert len(source.encode("utf-8")) == MIB
    assert "interface Envelope<T>" in source
    assert "#token: string" in source
    assert result["source_bytes"] == MIB
    assert result["parser_variants"] == ["tree-sitter-typescript"]
    assert result["partial_runs"] == 0
    assert result["error_runs"] == 0
    assert result["endpoint_preserved"] is True
    assert result["signature_variants"] == 1
    assert result["timings_ms"]["samples"][0] > 0
    assert result["peak_rss_bytes"] > 0


def test_adversarial_custom_regex_times_out_after_preserving_prior_result(
    executed_scenarios: dict[str, Any],
) -> None:
    result = executed_scenarios["custom_regex"]

    assert result["timeout_disclosures"] == 1
    assert result["prior_result_preserved_runs"] == 1
    assert result["signature_variants"] == 1
    assert result["timings_ms"]["samples"][0] > 0
    assert result["peak_rss_bytes"] > 0


def test_custom_regex_benchmark_keeps_stdout_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    benchmark_detection.benchmark_custom_regex(runs=1, warmups=0)

    assert capsys.readouterr().out == ""


def test_lexical_flood_preserves_independent_quote_budgets_and_discloses_partial(
    executed_scenarios: dict[str, Any],
) -> None:
    source = build_lexical_fixture()
    result = executed_scenarios["lexical_candidates"]

    assert source.count('"noise-') == 10_001
    assert "/api/single-before-flood" in source
    assert "/api/template-after-flood" in source
    assert result["input_double_candidates"] == 10_001
    assert result["retained_candidate_counts"] == [10_002]
    assert result["retained_by_quote_variants"] == [
        {"double": 10_000, "single": 1, "template": 1}
    ]
    assert result["starvation_missing"] == []
    assert result["successful_runs"] == 1
    assert result["partial_disclosures"] == 1
    assert result["signature_variants"] == 1
    assert result["timings_ms"]["samples"][0] > 0
    assert result["peak_rss_bytes"] > 0


@pytest.mark.parametrize("initially_enabled", [True, False])
def test_timed_lexical_parse_restores_callers_gc_state(
    monkeypatch: pytest.MonkeyPatch,
    initially_enabled: bool,
) -> None:
    parser = benchmark_detection.JSParser()
    observed_gc_states: list[bool] = []
    expected = object()

    def parse(_source: str) -> object:
        observed_gc_states.append(gc.isenabled())
        return expected

    original_state = gc.isenabled()
    try:
        gc.enable() if initially_enabled else gc.disable()
        monkeypatch.setattr(parser, "_parse_regex_fallback", parse)

        elapsed_ms, parsed = benchmark_detection._timed_lexical_parse(parser, "fixture")

        assert parsed is expected
        assert elapsed_ms >= 0
        assert observed_gc_states == [False]
        assert gc.isenabled() is initially_enabled
    finally:
        gc.enable() if original_state else gc.disable()


def test_timed_lexical_parse_restores_gc_after_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = benchmark_detection.JSParser()

    def fail(_source: str) -> object:
        assert gc.isenabled() is False
        raise RuntimeError("expected benchmark probe")

    original_state = gc.isenabled()
    try:
        gc.enable()
        monkeypatch.setattr(parser, "_parse_regex_fallback", fail)

        with pytest.raises(RuntimeError, match="expected benchmark probe"):
            benchmark_detection._timed_lexical_parse(parser, "fixture")

        assert gc.isenabled() is True
    finally:
        gc.enable() if original_state else gc.disable()


def test_release_gates_accept_executed_scenarios_at_required_sample_count(
    executed_scenarios: dict[str, Any],
) -> None:
    scenarios = _as_release_result(executed_scenarios)

    assert evaluate_gates(
        scenarios,
        expected_runs=RELEASE_RUNS,
        expected_warmups=RELEASE_WARMUPS,
    ) == []


def test_release_gate_requires_two_warmups_for_every_scenario(
    executed_scenarios: dict[str, Any],
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    for scenario in scenarios.values():
        scenario["warmups"] = RELEASE_WARMUPS - 1

    failures = evaluate_gates(scenarios)

    assert all(
        f"{name}: release gate requires at least {RELEASE_WARMUPS} warm-up runs" in failures
        for name in ("modern_parse", "custom_regex", "lexical_candidates")
    )


@pytest.mark.parametrize(
    ("scenario_name", "limit", "expected"),
    [
        (
            "modern_parse",
            MODERN_PARSE_P95_MS,
            "modern_parse: p95 exceeds 2,000 ms",
        ),
        (
            "custom_regex",
            CUSTOM_REGEX_WALL_MS,
            "custom_regex: wall time exceeded the bounded 750 ms allowance",
        ),
        (
            "lexical_candidates",
            LEXICAL_P95_MS,
            "lexical_candidates: p95 exceeds 2,000 ms",
        ),
    ],
)
def test_release_gate_rejects_absolute_timing_limit_overrun(
    executed_scenarios: dict[str, Any],
    scenario_name: str,
    limit: float,
    expected: str,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    _set_constant_timing(scenarios[scenario_name], limit + 0.001)

    assert expected in evaluate_gates(scenarios)


@pytest.mark.parametrize(
    ("scenario_name", "limit", "expected"),
    [
        (
            "modern_parse",
            MODERN_PARSE_PEAK_RSS_BYTES,
            "modern_parse: peak RSS exceeds 1 GiB",
        ),
        (
            "lexical_candidates",
            LEXICAL_PEAK_RSS_BYTES,
            "lexical_candidates: peak RSS exceeds 1 GiB",
        ),
    ],
)
def test_release_gate_rejects_absolute_memory_limit_overrun(
    executed_scenarios: dict[str, Any],
    scenario_name: str,
    limit: int,
    expected: str,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    scenarios[scenario_name]["peak_rss_bytes"] = limit + 1

    assert expected in evaluate_gates(scenarios)


def test_release_gate_binds_requested_counts_and_cross_scenario_counts(
    executed_scenarios: dict[str, Any],
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    scenarios["modern_parse"]["runs"] = RELEASE_RUNS + 1
    scenarios["modern_parse"]["warmups"] = RELEASE_WARMUPS + 1
    _set_constant_timing(scenarios["modern_parse"], 10.0)

    failures = evaluate_gates(
        scenarios,
        expected_runs=RELEASE_RUNS,
        expected_warmups=RELEASE_WARMUPS,
    )

    assert "modern_parse: measured run count differs from the requested run count" in failures
    assert "modern_parse: warm-up count differs from the requested warm-up count" in failures
    assert "suite: measured run counts differ across scenarios" in failures
    assert "suite: warm-up counts differ across scenarios" in failures


def test_release_gate_rejects_non_object_suite_without_exception() -> None:
    assert evaluate_gates([]) == [
        "suite: benchmark results are unavailable or malformed"
    ]


@pytest.mark.parametrize("scenario_name", ["modern_parse", "custom_regex", "lexical_candidates"])
def test_release_gate_rejects_nondeterministic_signatures(
    executed_scenarios: dict[str, Any],
    scenario_name: str,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    scenarios[scenario_name]["signature_variants"] = 2

    failures = evaluate_gates(scenarios)

    assert f"{scenario_name}: output signature changed across identical runs" in failures


def test_release_gate_rejects_high_variance_as_invalid_measurement(
    executed_scenarios: dict[str, Any],
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    samples = [1.0] * (RELEASE_RUNS - 1) + [100.0]
    timings = scenarios["modern_parse"]["timings_ms"]
    timings["samples"] = samples
    timings["p95"] = benchmark_detection._percentile(samples, 0.95)
    timings["max"] = max(samples)
    timings["coefficient_of_variation"] = (
        benchmark_detection.statistics.pstdev(samples)
        / benchmark_detection.statistics.fmean(samples)
    )

    failures = evaluate_gates(scenarios)

    assert (
        "modern_parse: invalid measurement; timing coefficient of variation exceeds 0.25"
        in failures
    )


def test_baseline_allows_exact_twenty_and_twenty_five_percent_boundaries(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline_scenarios = copy.deepcopy(current)
    for name in current:
        _set_constant_timing(baseline_scenarios[name], 100.0)
        baseline_scenarios[name]["peak_rss_bytes"] = 100
        _set_constant_timing(current[name], 120.0)
        current[name]["peak_rss_bytes"] = 125
    baseline = _baseline_payload(baseline_scenarios)

    assert evaluate_gates(current, baseline=baseline) == []


def test_baseline_rejects_more_than_twenty_percent_p95_regression(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline_scenarios = copy.deepcopy(current)
    _set_constant_timing(baseline_scenarios["modern_parse"], 100.0)
    baseline = _baseline_payload(baseline_scenarios)
    _set_constant_timing(current["modern_parse"], 120.001)

    failures = evaluate_gates(current, baseline=baseline)

    assert "modern_parse: p95 regressed more than 20% from baseline" in failures


def test_baseline_rejects_more_than_twenty_five_percent_memory_regression(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline_scenarios = copy.deepcopy(current)
    baseline_scenarios["custom_regex"]["peak_rss_bytes"] = 100
    baseline = _baseline_payload(baseline_scenarios)
    current["custom_regex"]["peak_rss_bytes"] = 126

    failures = evaluate_gates(current, baseline=baseline)

    assert "custom_regex: peak RSS regressed more than 25% from baseline" in failures


@pytest.mark.parametrize(
    "baseline",
    [
        {},
        {"scenarios": []},
        {"scenarios": {"modern_parse": {}}},
        {"scenarios": {name: {} for name in ("modern_parse", "custom_regex", "lexical_candidates")}},
    ],
)
def test_malformed_baseline_fails_closed_without_exception(
    executed_scenarios: dict[str, Any],
    baseline: dict[str, Any],
) -> None:
    failures = evaluate_gates(_as_release_result(executed_scenarios), baseline=baseline)

    assert any(failure.startswith("baseline:") for failure in failures)


def test_baseline_rejects_rehashed_timing_sample_tamper(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline = _baseline_payload(copy.deepcopy(current))
    baseline["scenarios"]["modern_parse"]["timings_ms"]["samples"][0] = 2.0
    baseline["result_sha256"] = benchmark_detection._canonical_sha256(baseline["scenarios"])

    failures = evaluate_gates(current, baseline=baseline)

    assert any("stored scenarios fail release integrity" in failure for failure in failures)


def test_baseline_rejects_rehashed_semantic_invariant_tamper(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline = _baseline_payload(copy.deepcopy(current))
    baseline["scenarios"]["modern_parse"]["endpoint_preserved"] = False
    baseline["result_sha256"] = benchmark_detection._canonical_sha256(baseline["scenarios"])

    failures = evaluate_gates(current, baseline=baseline)

    assert any("stored scenarios fail release integrity" in failure for failure in failures)


def test_baseline_rejects_dependency_fingerprint_tamper(
    executed_scenarios: dict[str, Any],
) -> None:
    current = _as_release_result(executed_scenarios)
    baseline = _baseline_payload(copy.deepcopy(current))
    baseline["measurement_environment"]["dependencies"]["tree-sitter"] = "0.26.1"

    failures = evaluate_gates(current, baseline=baseline)

    assert any("dependency fingerprint is incompatible" in failure for failure in failures)


def test_runtime_compatibility_rejects_dependency_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline_environment = _baseline_environment()
    current_environment = copy.deepcopy(baseline_environment)
    current_environment["dependencies"]["tree-sitter-typescript"] = "0.23.3"
    monkeypatch.setattr(benchmark_detection, "runtime_environment", lambda: current_environment)

    with pytest.raises(ValueError, match="current runtime is incompatible"):
        benchmark_detection.validate_runtime_compatibility(baseline_environment)


def test_malformed_scenario_fails_closed_without_exception() -> None:
    failures = evaluate_gates({"modern_parse": None})

    assert all("unavailable or malformed" in failure for failure in failures)


def test_release_gate_rejects_counter_only_run_forgery(
    executed_scenarios: dict[str, Any],
) -> None:
    scenarios = copy.deepcopy(executed_scenarios)
    for scenario in scenarios.values():
        scenario["runs"] = RELEASE_RUNS
    scenarios["custom_regex"]["timeout_disclosures"] = RELEASE_RUNS
    scenarios["custom_regex"]["prior_result_preserved_runs"] = RELEASE_RUNS
    scenarios["lexical_candidates"]["successful_runs"] = RELEASE_RUNS
    scenarios["lexical_candidates"]["partial_disclosures"] = RELEASE_RUNS

    failures = evaluate_gates(scenarios)

    assert all(
        f"{name}: timing sample count differs from measured runs" in failures
        for name in ("modern_parse", "custom_regex", "lexical_candidates")
    )


@pytest.mark.parametrize("invalid_sample", [float("nan"), float("inf"), float("-inf")])
def test_release_gate_rejects_nonfinite_timing_samples(
    executed_scenarios: dict[str, Any],
    invalid_sample: float,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    scenarios["modern_parse"]["timings_ms"]["samples"][0] = invalid_sample

    failures = evaluate_gates(scenarios)

    assert any("modern_parse: timings_ms.samples[0] must be finite" in item for item in failures)


@pytest.mark.parametrize("field", ["p50_bootstrap_95_ci", "p95_bootstrap_95_ci"])
def test_release_gate_rejects_bootstrap_interval_mutation(
    executed_scenarios: dict[str, Any],
    field: str,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    scenarios["modern_parse"]["timings_ms"][field][1] += 0.1

    failures = evaluate_gates(scenarios)

    assert f"modern_parse: reported {field} differs from timing samples" in failures


@pytest.mark.parametrize(
    ("scenario_name", "field", "replacement", "expected"),
    [
        (
            "modern_parse",
            "language_hint",
            "javascript",
            "modern_parse: fixture language hint is not TypeScript",
        ),
        (
            "custom_regex",
            "configured_timeout_seconds",
            999.0,
            "custom_regex: configured timeout differs from production",
        ),
        (
            "custom_regex",
            "source_bytes",
            1,
            "custom_regex: fixture source size drifted",
        ),
        (
            "custom_regex",
            "source_sha256",
            "0" * 64,
            "custom_regex: fixture content digest drifted",
        ),
        (
            "lexical_candidates",
            "input_double_candidates",
            10_002,
            "lexical_candidates: fixture candidate count drifted",
        ),
        (
            "lexical_candidates",
            "source_bytes",
            1,
            "lexical_candidates: fixture source size drifted",
        ),
        (
            "modern_parse",
            "source_sha256",
            "0" * 64,
            "modern_parse: fixture content digest drifted",
        ),
    ],
)
def test_release_gate_rejects_fixture_contract_drift(
    executed_scenarios: dict[str, Any],
    scenario_name: str,
    field: str,
    replacement: object,
    expected: str,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    scenarios[scenario_name][field] = replacement

    assert expected in evaluate_gates(scenarios)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["--runs", "0"], "--runs must be at least 1"),
        (["--warmups", "-1"], "--warmups must be non-negative"),
        (
            ["--runs", str(RELEASE_RUNS - 1), "--assert-gates"],
            f"--assert-gates requires --runs {RELEASE_RUNS}",
        ),
        (
            [
                "--runs",
                str(RELEASE_RUNS),
                "--warmups",
                str(RELEASE_WARMUPS - 1),
                "--assert-gates",
            ],
            f"--assert-gates requires --warmups {RELEASE_WARMUPS}",
        ),
        (
            ["--runs", str(RELEASE_RUNS + 1), "--warmups", str(RELEASE_WARMUPS), "--assert-gates"],
            f"--assert-gates requires --runs {RELEASE_RUNS}",
        ),
        (
            ["--runs", str(RELEASE_RUNS), "--warmups", str(RELEASE_WARMUPS + 1), "--assert-gates"],
            f"--assert-gates requires --warmups {RELEASE_WARMUPS}",
        ),
        (
            ["--runs", str(RELEASE_RUNS), "--warmups", str(RELEASE_WARMUPS), "--assert-gates"],
            "--assert-gates requires --baseline",
        ),
        (["--baseline", "unused.json"], "--baseline requires --assert-gates"),
    ],
)
def test_cli_rejects_invalid_release_arguments_without_traceback(
    arguments: list[str],
    expected: str,
) -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/benchmark_detection.py", *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    combined = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode != 0
    assert expected in combined
    assert "Traceback" not in combined


def test_cli_rejects_malformed_baseline_before_running_suite(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("[]", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/benchmark_detection.py",
            "--runs",
            str(RELEASE_RUNS),
            "--warmups",
            str(RELEASE_WARMUPS),
            "--assert-gates",
            "--baseline",
            str(baseline),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    combined = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 2
    assert "baseline root must be a JSON object" in combined
    assert "Traceback" not in combined


def test_cli_returns_one_and_machine_readable_json_when_a_gate_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    executed_scenarios: dict[str, Any],
    tmp_path: Path,
) -> None:
    scenarios = _as_release_result(executed_scenarios)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_baseline_payload(scenarios)), encoding="utf-8")
    scenarios["modern_parse"]["endpoint_preserved"] = False
    monkeypatch.setattr(benchmark_detection, "run_suite", lambda _runs, _warmups: scenarios)
    monkeypatch.setattr(benchmark_detection, "runtime_environment", _baseline_environment)

    return_code = benchmark_detection.main(
        [
            "--runs",
            str(RELEASE_RUNS),
            "--warmups",
            str(RELEASE_WARMUPS),
            "--assert-gates",
            "--baseline",
            str(baseline),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert return_code == 1
    assert payload["passed"] is False
    assert "modern_parse: known endpoint literal was not structurally preserved" in payload[
        "gate_failures"
    ]
