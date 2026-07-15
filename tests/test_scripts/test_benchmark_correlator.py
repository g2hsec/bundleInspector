"""Tests for the benchmark script interface."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

from scripts import benchmark_correlator
from scripts.benchmark_correlator import (
    RELEASE_RUNS,
    RELEASE_WARMUPS,
    build_synthetic_findings,
    create_baseline_payload,
    evaluate_gates,
    run_benchmark,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def valid_release_result() -> dict[str, object]:
    return _promote_to_release(
        run_benchmark(modules=80, fanout=3, load_contexts=4, runs=1, warmups=0)
    )


def _promote_to_release(result: dict[str, object]) -> dict[str, object]:
    promoted = copy.deepcopy(result)
    timings = promoted["timings_ms"]
    assert isinstance(timings, dict)
    promoted["runs"] = RELEASE_RUNS
    promoted["warmups"] = RELEASE_WARMUPS
    promoted["timings_ms"] = benchmark_correlator._timing_summary([1.0] * RELEASE_RUNS)
    return promoted


def _baseline_environment() -> dict[str, object]:
    return {
        "os": "Linux",
        "os_release": "test-provenance-only",
        "machine": "x86_64",
        "python": "3.13.0",
        "implementation": "CPython",
        "measurement_origin": "local-wsl",
        "cpu_model": "Test Release CPU",
        "dependencies": {
            "bundleInspector": version("bundleInspector"),
            "pydantic": version("pydantic"),
            "pydantic-core": version("pydantic-core"),
        },
    }


@pytest.fixture(scope="module")
def valid_release_suite() -> list[dict[str, object]]:
    return [
        _promote_to_release(
            run_benchmark(modules=modules, fanout=3, load_contexts=4, runs=1, warmups=0)
        )
        for modules in (80, 200, 500)
    ]


def test_release_result_self_identifies_profile_environment_and_fixture(
    valid_release_suite: list[dict[str, object]],
) -> None:
    environment = _baseline_environment()
    payload = benchmark_correlator.create_result_payload(
        copy.deepcopy(valid_release_suite),
        environment,
        runs=RELEASE_RUNS,
        warmups=RELEASE_WARMUPS,
        gate_failures=[],
    )

    assert payload["benchmark"] == "correlator"
    assert payload["profile"] == benchmark_correlator.BASELINE_PROFILE
    assert payload["measurement_environment"] == environment
    assert payload["scenario_contract_sha256"] == benchmark_correlator._canonical_sha256(
        benchmark_correlator._expected_correlator_contract()
    )
    assert benchmark_correlator.validate_result_document(
        copy.deepcopy(payload),
        require_runtime_compatibility=False,
    ) == payload


def test_release_result_rejects_cross_environment_and_misrouted_role(
    valid_release_suite: list[dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _baseline_environment()
    payload = benchmark_correlator.create_result_payload(
        copy.deepcopy(valid_release_suite),
        environment,
        runs=RELEASE_RUNS,
        warmups=RELEASE_WARMUPS,
        gate_failures=[],
    )
    monkeypatch.setattr(benchmark_correlator, "runtime_environment", lambda: environment)
    cross_environment = copy.deepcopy(payload)
    cross_environment["measurement_environment"]["dependencies"]["pydantic"] = "999.0"
    with pytest.raises(ValueError, match="current runtime is incompatible"):
        benchmark_correlator.validate_result_document(cross_environment)

    misrouted = copy.deepcopy(payload)
    misrouted["benchmark"] = "detection"
    with pytest.raises(ValueError, match="benchmark profile is incompatible"):
        benchmark_correlator.validate_result_document(
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
def test_correlator_main_applies_timing_regression_gate_on_every_hardware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    valid_release_suite: list[dict[str, object]],
    cpu_model: str,
    expected_state: str,
) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(create_baseline_payload(valid_release_suite, _baseline_environment())),
        encoding="utf-8",
    )
    current = copy.deepcopy(valid_release_suite)
    for scenario in current:
        scenario["timings_ms"] = benchmark_correlator._timing_summary([2.0] * RELEASE_RUNS)
    by_modules = {scenario["modules"]: scenario for scenario in current}
    environment = _baseline_environment()
    environment["cpu_model"] = cpu_model
    monkeypatch.setattr(benchmark_correlator, "runtime_environment", lambda: environment)
    monkeypatch.setattr(
        benchmark_correlator,
        "run_benchmark",
        lambda modules, *_args, **_kwargs: copy.deepcopy(by_modules[modules]),
    )

    return_code = benchmark_correlator.main([
        "--suite",
        "--runs", str(RELEASE_RUNS),
        "--warmups", str(RELEASE_WARMUPS),
        "--assert-gates",
        "--baseline", str(baseline),
    ])
    payload = json.loads(capsys.readouterr().out)

    assert return_code == 1
    assert payload["relative_baseline_comparison"] == expected_state
    assert any("regressed more than 20%" in failure for failure in payload["gate_failures"])


def test_correlator_cross_hardware_still_rejects_rss_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    valid_release_suite: list[dict[str, object]],
) -> None:
    baseline_payload = create_baseline_payload(valid_release_suite, _baseline_environment())
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(baseline_payload), encoding="utf-8")
    current = copy.deepcopy(valid_release_suite)
    baseline_by_modules = {
        scenario["modules"]: scenario for scenario in baseline_payload["scenarios"]
    }
    for scenario in current:
        previous = baseline_by_modules[scenario["modules"]]
        scenario["peak_rss_bytes"] = int(previous["peak_rss_bytes"]) * 2
    by_modules = {scenario["modules"]: scenario for scenario in current}
    environment = _baseline_environment()
    environment["cpu_model"] = "Different Hosted CPU"
    monkeypatch.setattr(benchmark_correlator, "runtime_environment", lambda: environment)
    monkeypatch.setattr(
        benchmark_correlator,
        "run_benchmark",
        lambda modules, *_args, **_kwargs: copy.deepcopy(by_modules[modules]),
    )

    return_code = benchmark_correlator.main([
        "--suite",
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


def test_benchmark_script_rejects_zero_rounds_without_traceback():
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_correlator.py", "--rounds", "0"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    combined = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0
    assert "--rounds must be at least 1" in combined
    assert "Traceback" not in combined


def test_fixture_builds_exact_requested_load_context_count() -> None:
    findings = build_synthetic_findings(modules=10, fanout=1, load_contexts=4)

    contexts = {finding.metadata.get("load_context") for finding in findings}
    assert contexts == {"/route/0", "/route/1", "/route/2", "/route/3"}


@pytest.mark.parametrize("load_contexts", [0, 5])
def test_fixture_rejects_impossible_load_context_count(load_contexts: int) -> None:
    with pytest.raises(ValueError, match="load_contexts"):
        build_synthetic_findings(modules=4, fanout=1, load_contexts=load_contexts)


def test_benchmark_reports_determinism_percentiles_and_memory() -> None:
    result = run_benchmark(modules=8, fanout=1, load_contexts=4, runs=2, warmups=0)

    assert result["actual_load_contexts"] == 4
    assert result["edge_signature_variants"] == 1
    assert result["cluster_signature_variants"] == 1
    assert result["peak_rss_bytes"] > 0
    assert result["python_tracemalloc_peak_bytes"] > 0
    assert len(result["timings_ms"]["samples"]) == 2
    assert len(result["timings_ms"]["p95_bootstrap_95_ci"]) == 2


def test_release_gate_fails_closed_without_runs_threshold_and_telemetry() -> None:
    result = run_benchmark(modules=80, fanout=1, load_contexts=4, runs=1, warmups=0)
    result["telemetry"] = None

    failures = evaluate_gates(result)

    assert "release gate requires at least 30 measured runs" in failures
    assert any("telemetry" in failure for failure in failures)


def test_release_gate_accepts_exact_fixed_semantic_fixture(
    valid_release_result: dict[str, object],
) -> None:
    assert evaluate_gates(copy.deepcopy(valid_release_result)) == []


@pytest.mark.parametrize(
    "field",
    [
        "fixture_sha256",
        "edge_signature_sha256",
        "cluster_signature_sha256",
        "telemetry_sha256",
    ],
)
def test_release_gate_rejects_semantic_digest_mutation(
    valid_release_result: dict[str, object],
    field: str,
) -> None:
    result = copy.deepcopy(valid_release_result)
    result[field] = "0" * 64

    failures = evaluate_gates(result)

    assert f"{field} differs from fixed semantic fixture" in failures


@pytest.mark.parametrize("value", [None, "", "g" * 64, "A" * 64])
def test_release_gate_rejects_malformed_semantic_digest(
    valid_release_result: dict[str, object],
    value: object,
) -> None:
    result = copy.deepcopy(valid_release_result)
    result["fixture_sha256"] = value

    failures = evaluate_gates(result)

    assert "fixture_sha256 must be a lowercase SHA-256 digest" in failures


def test_release_gate_rejects_zero_graph_even_with_shallow_counters_forged(
    valid_release_result: dict[str, object],
) -> None:
    result = copy.deepcopy(valid_release_result)
    result["fanout"] = 0
    result["requested_load_contexts"] = 1
    result["actual_load_contexts"] = 1
    result["edges"] = 0
    result["clusters"] = 0
    telemetry = result["telemetry"]
    assert isinstance(telemetry, dict)
    telemetry.update({
        "candidates": 0,
        "candidate_attempts": 0,
        "emitted": 0,
        "dropped": 0,
        "duplicate_dropped": 0,
    })

    failures = evaluate_gates(result)

    assert any("fixture fanout" in failure for failure in failures)
    assert any("fixture edges" in failure for failure in failures)
    assert any("fixture clusters" in failure for failure in failures)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("p95", float("nan")),
        ("p95", float("inf")),
        ("coefficient_of_variation", float("nan")),
        ("coefficient_of_variation", float("inf")),
    ],
)
def test_release_gate_rejects_nonfinite_timing_values(
    valid_release_result: dict[str, object],
    field: str,
    value: float,
) -> None:
    result = copy.deepcopy(valid_release_result)
    timings = result["timings_ms"]
    assert isinstance(timings, dict)
    timings[field] = value

    failures = evaluate_gates(result)

    assert any("finite" in failure for failure in failures)


@pytest.mark.parametrize(
    "field",
    ["min", "p50", "p95", "max", "mean", "coefficient_of_variation"],
)
def test_release_gate_rejects_reported_timing_mutation(
    valid_release_result: dict[str, object],
    field: str,
) -> None:
    result = copy.deepcopy(valid_release_result)
    timings = result["timings_ms"]
    assert isinstance(timings, dict)
    timings[field] += 0.1

    failures = evaluate_gates(result)

    assert f"reported {field} differs from timing samples" in failures


@pytest.mark.parametrize("field", ["p50_bootstrap_95_ci", "p95_bootstrap_95_ci"])
def test_release_gate_rejects_bootstrap_interval_mutation(
    valid_release_result: dict[str, object],
    field: str,
) -> None:
    result = copy.deepcopy(valid_release_result)
    timings = result["timings_ms"]
    assert isinstance(timings, dict)
    timings[field][1] += 0.1

    failures = evaluate_gates(result)

    assert f"reported {field} differs from timing samples" in failures


def test_release_gate_rejects_nonpositive_sample_and_memory(
    valid_release_result: dict[str, object],
) -> None:
    result = copy.deepcopy(valid_release_result)
    timings = result["timings_ms"]
    assert isinstance(timings, dict)
    timings["samples"] = [0.0] * 30
    result["peak_rss_bytes"] = 0
    result["python_tracemalloc_peak_bytes"] = 0

    failures = evaluate_gates(result)

    assert "timing samples must be positive" in failures
    assert "peak_rss_bytes must be positive" in failures
    assert "python_tracemalloc_peak_bytes must be positive" in failures


def test_release_gate_binds_requested_run_and_warmup_counts(
    valid_release_result: dict[str, object],
) -> None:
    failures = evaluate_gates(
        copy.deepcopy(valid_release_result),
        expected_runs=31,
        expected_warmups=1,
    )

    assert "measured run count differs from the requested run count" in failures
    assert "warm-up count differs from the requested warm-up count" in failures


def test_release_gate_rejects_inconsistent_nested_telemetry(
    valid_release_result: dict[str, object],
) -> None:
    result = copy.deepcopy(valid_release_result)
    telemetry = result["telemetry"]
    assert isinstance(telemetry, dict)
    telemetry["candidates"] += 1
    passes = telemetry["passes"]
    assert isinstance(passes, dict)
    first_pass = next(iter(passes.values()))
    assert isinstance(first_pass, dict)
    first_pass["cap_dropped"] += 1

    failures = evaluate_gates(result)

    assert "telemetry.candidates differs from candidate_attempts" in failures
    assert any("pass total for cap_dropped" in failure for failure in failures)


@pytest.mark.parametrize(
    "baseline",
    [
        {},
        {"scenarios": []},
        {"scenarios": [{"modules": 80}]},
        {
            "scenarios": [{
                "modules": 80,
                "timings_ms": {"p95": float("nan")},
                "peak_rss_bytes": 1,
            }]
        },
        {
            "scenarios": [{
                "modules": 80,
                "timings_ms": {"p95": 1.0},
                "peak_rss_bytes": True,
            }]
        },
    ],
)
def test_release_gate_rejects_malformed_baseline_without_exception(
    valid_release_result: dict[str, object],
    baseline: dict[str, object],
) -> None:
    failures = evaluate_gates(copy.deepcopy(valid_release_result), baseline=baseline)

    assert any("baseline" in failure for failure in failures)


def test_release_gate_rejects_malformed_result_without_exception() -> None:
    failures = evaluate_gates({})

    assert failures
    assert any("must be" in failure or "unavailable" in failure for failure in failures)


def test_cli_rejects_baseline_without_assert_gates(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/benchmark_correlator.py", "--baseline", str(baseline)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "--baseline requires --assert-gates" in result.stderr


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (
            ["--runs", "30", "--warmups", "2", "--assert-gates"],
            "--assert-gates requires --suite",
        ),
        (
            ["--suite", "--runs", "29", "--warmups", "2", "--assert-gates"],
            "--assert-gates requires --runs 30",
        ),
        (
            ["--suite", "--runs", "31", "--warmups", "2", "--assert-gates"],
            "--assert-gates requires --runs 30",
        ),
        (
            ["--suite", "--runs", "30", "--warmups", "1", "--assert-gates"],
            "--assert-gates requires --warmups 2",
        ),
        (
            ["--suite", "--runs", "30", "--warmups", "3", "--assert-gates"],
            "--assert-gates requires --warmups 2",
        ),
        (
            ["--suite", "--runs", "30", "--warmups", "2", "--assert-gates"],
            "--assert-gates requires --baseline",
        ),
    ],
)
def test_cli_rejects_incomplete_release_profile_without_running(
    arguments: list[str],
    expected: str,
) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_correlator.py", *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert expected in result.stderr
    assert "Traceback" not in result.stderr


def test_correlator_baseline_replays_full_stored_release_integrity(
    valid_release_suite: list[dict[str, object]],
) -> None:
    baseline = create_baseline_payload(valid_release_suite, _baseline_environment())

    assert benchmark_correlator.validate_baseline_document(copy.deepcopy(baseline)) == baseline


def test_correlator_baseline_rejects_rehashed_sample_tamper(
    valid_release_suite: list[dict[str, object]],
) -> None:
    baseline = create_baseline_payload(valid_release_suite, _baseline_environment())
    scenario = baseline["scenarios"][0]
    scenario["timings_ms"]["samples"][0] += 1.0
    baseline["result_sha256"] = benchmark_correlator._canonical_sha256(baseline["scenarios"])

    failures = evaluate_gates(copy.deepcopy(valid_release_suite[0]), baseline=baseline)

    assert any("stored scenario 80 fails release integrity" in failure for failure in failures)


def test_correlator_baseline_rejects_rehashed_telemetry_tamper(
    valid_release_suite: list[dict[str, object]],
) -> None:
    baseline = create_baseline_payload(valid_release_suite, _baseline_environment())
    scenario = baseline["scenarios"][0]
    scenario["telemetry"]["candidates"] += 1
    scenario["telemetry_sha256"] = benchmark_correlator._canonical_sha256(scenario["telemetry"])
    baseline["result_sha256"] = benchmark_correlator._canonical_sha256(baseline["scenarios"])

    failures = evaluate_gates(copy.deepcopy(valid_release_suite[0]), baseline=baseline)

    assert any("fixture" in failure or "integrity" in failure for failure in failures)


def test_correlator_relative_p95_and_rss_thresholds_are_strict(
    valid_release_suite: list[dict[str, object]],
) -> None:
    baseline = create_baseline_payload(valid_release_suite, _baseline_environment())
    current = copy.deepcopy(valid_release_suite[0])
    previous = baseline["scenarios"][0]
    previous_p95 = float(previous["timings_ms"]["p95"])
    current["timings_ms"] = benchmark_correlator._timing_summary(
        [previous_p95 * 1.201] * RELEASE_RUNS
    )
    current["peak_rss_bytes"] = int(previous["peak_rss_bytes"] * 1.251) + 1

    failures = evaluate_gates(current, baseline=baseline)

    assert "p95 regressed more than 20% from baseline" in failures
    assert "peak RSS regressed more than 25% from baseline" in failures


def test_correlator_runtime_compatibility_rejects_dependency_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline_environment = _baseline_environment()
    current_environment = copy.deepcopy(baseline_environment)
    current_environment["dependencies"]["pydantic"] = "999.0"
    monkeypatch.setattr(benchmark_correlator, "runtime_environment", lambda: current_environment)

    with pytest.raises(ValueError, match="current runtime is incompatible"):
        benchmark_correlator.validate_runtime_compatibility(baseline_environment)
