"""Deterministic correlator performance and completeness release gate."""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import importlib
import json
import math
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from bundleInspector.correlator.graph import Correlator  # noqa: E402
from bundleInspector.storage.models import (  # noqa: E402
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)


@dataclass(frozen=True)
class ScenarioGate:
    modules: int
    findings: int
    fanout: int
    load_contexts: int
    edges: int
    clusters: int
    cap_dropped: int
    p95_ms: float
    fixture_sha256: str
    edge_sha256: str
    cluster_sha256: str
    telemetry_sha256: str
    peak_rss_bytes: int | None = None


SCENARIO_GATES = {
    80: ScenarioGate(
        80,
        160,
        3,
        4,
        1_130,
        1,
        21,
        1_000.0,
        "7a6dcd98c5974c77d712e3d4c1104a58d6d15088fa4b0a804acfe44de9a8cd04",
        "672f475e4825fa0be7e83d96a972be09700f4d74d85e3c1343a87811c71b505b",
        "101ab6d34bd5636ec2106efd15f75d3299f29ec43eed5876e1853496df79d6ac",
        "3b26db3e65a37ec80a01468fcf299044d1307950132584d30a479c9ded0ee084",
    ),
    200: ScenarioGate(
        200,
        400,
        3,
        4,
        1_250,
        1,
        21,
        2_500.0,
        "35a92df9d614a5f4795d7311db4f0a739840a3c0869bda333b0ccab41568f63d",
        "267a50eacf1cd4076a8ceb924647c57c70de3762b1189ac058d2cb584c44cc52",
        "86e9d628a9c80b8e3bf251facbf5c30bc6dd7c4eb5f3d4bb4983265a69502f15",
        "a37d18bad2ab343a6a9c0572687d2c31d1ad5bc802ac2f67dbcf57751665c318",
    ),
    500: ScenarioGate(
        500,
        1_000,
        3,
        4,
        1_550,
        1,
        21,
        8_000.0,
        "861b18e3dab13ff38e7c4176f15a00ea642d0d0d7576a8e532785081a69e196f",
        "caacdbf8a5b5b7a1826436499fd4fdef2a9e59204c5c1eac852f63e6be53b23c",
        "d237ce25b2669c3320a6ed676c20b09ebf6c64bddc738782fd2a797a30931d69",
        "7870b81b1cab9c7a5130e40cd4aa2bff8d3a0169061aff7518e6a507eb9b92b7",
        1024 * 1024 * 1024,
    ),
}

RELEASE_RUNS = 30
RELEASE_WARMUPS = 2
BASELINE_SCHEMA_VERSION = 1
BASELINE_PROFILE = "linux-x86_64-python3.13-release"
RAW_RESULT_SCHEMA_VERSION = 1
UNPROFILED_RESULT_PROFILE = "unprofiled"
CORRELATOR_DEPENDENCY_NAMES = ("bundleInspector", "pydantic", "pydantic-core")
_BASELINE_FIELDS = frozenset({
    "schema_version",
    "benchmark",
    "profile",
    "measurement_environment",
    "scenario_contract_sha256",
    "result_sha256",
    "runs",
    "warmups",
    "scenarios",
})
_RAW_RESULT_FIELDS = frozenset({
    "schema_version",
    "benchmark",
    "profile",
    "measurement_environment",
    "scenario_contract_sha256",
    "result_sha256",
    "runs",
    "warmups",
    "passed",
    "gate_failures",
    "relative_baseline_comparison",
    "scenarios",
})
_ENVIRONMENT_FIELDS = frozenset({
    "os",
    "os_release",
    "machine",
    "python",
    "implementation",
    "measurement_origin",
    "cpu_model",
    "dependencies",
})
_MEASUREMENT_ORIGINS = frozenset({
    "github-hosted",
    "local-wsl",
    "local-linux",
    "local-windows",
    "container",
    "unknown",
})
_EXPECTED_CAPPED_PASSES = {
    "_add_call_graph_edges": 1,
    "_add_dynamic_import_edges": 1,
    "_add_import_chain_edges": 1,
    "_add_import_edges": 1,
    "_add_inter_module_call_edges": 1,
    "_add_load_context_call_chain_edges": 1,
    "_add_load_context_downstream_call_chain_edges": 2,
    "_add_load_context_import_chain_edges": 1,
    "_add_load_context_runtime_execution_graph_edges": 1,
    "_add_load_context_scope_call_chain_edges": 1,
    "_add_runtime_downstream_call_chain_edges": 2,
    "_add_runtime_edges": 1,
    "_add_runtime_execution_graph_edges": 1,
    "_add_runtime_scope_call_chain_edges": 4,
    "_add_secret_endpoint_edges": 1,
    "_add_transitive_import_edges": 1,
}
_EXPECTED_PASS_NAMES = frozenset({
    "_add_same_file_edges",
    *_EXPECTED_CAPPED_PASSES,
})


def _make_finding(
    finding_id: str,
    file_url: str,
    category: Category,
    extracted_value: str,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        rule_id=f"rule-{finding_id}",
        category=category,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title=f"Finding {finding_id}",
        description="synthetic benchmark finding",
        evidence=Evidence(
            file_url=file_url,
            file_hash=f"hash-{finding_id}",
            line=10,
            column=0,
            snippet="",
            snippet_lines=(0, 0),
            ast_node_type="Literal",
        ),
        extracted_value=extracted_value,
        value_type="benchmark",
        metadata=metadata or {},
    )


def build_synthetic_findings(modules: int, fanout: int, load_contexts: int) -> list[Finding]:
    """Build a fixed graph with exactly the requested number of load contexts."""
    if modules < 1:
        raise ValueError("modules must be at least 1")
    if fanout < 0:
        raise ValueError("fanout must be non-negative")
    if load_contexts < 1 or load_contexts > modules:
        raise ValueError("load_contexts must be between 1 and modules")

    findings: list[Finding] = []
    for index in range(modules):
        file_url = f"file:///bench/module{index}.js"
        exports = [f"fn{index}"]
        import_bindings: list[dict[str, Any]] = []
        scoped_calls: dict[str, list[str]] = {"function:boot": []}
        imports: list[str] = []
        dynamic_imports: list[str] = []

        for offset in range(1, fanout + 1):
            target_index = index + offset
            if target_index >= modules:
                break
            source = f"./module{target_index}"
            imports.append(source)
            if offset % 2 == 0:
                dynamic_imports.append(source)
            import_bindings.append(
                {
                    "source": source,
                    "imported": f"fn{target_index}",
                    "local": f"fn{target_index}",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": offset % 2 == 0,
                }
            )
            scoped_calls["function:boot"].append(f"fn{target_index}")

        load_context = f"/route/{index % load_contexts}"
        metadata = {
            "enclosing_scope": "function:boot",
            "imports": imports,
            "dynamic_imports": dynamic_imports,
            "import_bindings": import_bindings,
            "exports": exports,
            "export_scopes": {f"fn{index}": [f"function:fn{index}"]},
            "call_graph": {"function:boot": [f"function:fn{index}"]},
            "scoped_calls": scoped_calls,
            "load_context": load_context,
        }
        findings.append(
            _make_finding(
                f"endpoint-{index}",
                file_url,
                Category.ENDPOINT,
                f"/api/{index}",
                metadata=metadata,
            )
        )
        findings.append(
            _make_finding(
                f"secret-{index}",
                file_url,
                Category.SECRET,
                f"benchmark_secret_{index:04d}_abcdefghijklmnopqrstuvwxyz123456",
                metadata={
                    "enclosing_scope": f"function:fn{index}",
                    "exports": exports,
                    "export_scopes": {f"fn{index}": [f"function:fn{index}"]},
                    "call_graph": {f"function:fn{index}": []},
                    "load_context": load_context,
                },
            )
        )

    actual_contexts = {
        str(finding.metadata.get("load_context") or "")
        for finding in findings
        if finding.metadata.get("load_context")
    }
    if len(actual_contexts) != load_contexts:
        raise RuntimeError(
            f"synthetic fixture requested {load_contexts} load contexts but built {len(actual_contexts)}"
        )
    return findings


def _percentile(values: list[float], percentile: float) -> float:
    """Linear-interpolated percentile with stable behavior for small samples."""
    if not values:
        raise ValueError("percentile requires at least one value")
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _bootstrap_interval(
    values: list[float],
    statistic: Callable[[list[float]], float],
    *,
    samples: int = 1_000,
    seed: int = 0,
) -> tuple[float, float]:
    """Deterministic percentile bootstrap confidence interval."""
    if not values:
        raise ValueError("bootstrap requires at least one value")
    if len(values) == 1:
        return values[0], values[0]
    rng = random.Random(seed)
    size = len(values)
    estimates = [
        float(statistic([values[rng.randrange(size)] for _ in range(size)]))
        for _ in range(samples)
    ]
    return _percentile(estimates, 0.025), _percentile(estimates, 0.975)


def _timing_summary(samples: list[float]) -> dict[str, Any]:
    """Build every reported statistic from the exact serialized samples."""
    serialized = [round(sample, 3) for sample in samples]
    mean = statistics.fmean(serialized)
    variation = statistics.pstdev(serialized) / mean if len(serialized) > 1 and mean else 0.0
    p50_ci = _bootstrap_interval(serialized, statistics.median)
    p95_ci = _bootstrap_interval(serialized, lambda sample: _percentile(sample, 0.95))
    return {
        "min": round(min(serialized), 3),
        "p50": round(statistics.median(serialized), 3),
        "p95": round(_percentile(serialized, 0.95), 3),
        "max": round(max(serialized), 3),
        "mean": round(mean, 3),
        "coefficient_of_variation": round(variation, 6),
        "p50_bootstrap_95_ci": [round(value, 3) for value in p50_ci],
        "p95_bootstrap_95_ci": [round(value, 3) for value in p95_ci],
        "samples": serialized,
    }


def _current_peak_rss_bytes() -> int:
    """Return process peak resident memory without an optional dependency."""
    if os.name == "nt":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        handle = kernel32.GetCurrentProcess()
        ok = psapi.GetProcessMemoryInfo(
            handle,
            ctypes.byref(counters),
            counters.cb,
        )
        if not ok:
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)

    resource = importlib.import_module("resource")
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(usage if sys.platform == "darwin" else usage * 1024)


def _edge_signature(graph: Any) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        sorted(
            (
                edge.source_id,
                edge.target_id,
                edge.edge_type.value,
                edge.reasoning,
            )
            for edge in graph.edges
        )
    )


def _cluster_signature(graph: Any) -> tuple[tuple[str, ...], ...]:
    return tuple(sorted(tuple(sorted(cluster.finding_ids)) for cluster in graph.clusters))


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _fixture_signature(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        finding.model_dump(
            mode="json",
            exclude={"created_at", "value_hash"},
        )
        for finding in findings
    ]


def _telemetry_dict(graph: Any) -> dict[str, Any] | None:
    telemetry = getattr(graph, "telemetry", None)
    if telemetry is None:
        return None
    if hasattr(telemetry, "model_dump"):
        raw = telemetry.model_dump(mode="json")
    elif hasattr(telemetry, "__dict__"):
        raw = vars(telemetry)
    elif isinstance(telemetry, dict):
        raw = telemetry
    else:
        return None
    return {str(key): value for key, value in raw.items()}


def run_benchmark(
    modules: int,
    fanout: int,
    load_contexts: int,
    runs: int,
    *,
    warmups: int = 1,
) -> dict[str, Any]:
    """Run one scenario and return deterministic timing/resource/completeness evidence."""
    if runs < 1:
        raise ValueError("runs must be at least 1")
    if warmups < 0:
        raise ValueError("warmups must be non-negative")
    finding_templates = build_synthetic_findings(modules, fanout, load_contexts)
    fixture_sha256 = _canonical_sha256(_fixture_signature(finding_templates))
    actual_contexts = len(
        {
            str(finding.metadata.get("load_context"))
            for finding in finding_templates
            if finding.metadata.get("load_context")
        }
    )
    for _ in range(warmups):
        warmup_findings = [finding.model_copy(deep=True) for finding in finding_templates]
        Correlator().correlate(warmup_findings)

    timings_ms: list[float] = []
    edge_signature_hashes: set[str] = set()
    cluster_signature_hashes: set[str] = set()
    telemetry_samples: list[dict[str, Any] | None] = []
    graph = None
    tracemalloc.start()
    try:
        for _ in range(runs):
            # Correlation annotates cluster/correlation IDs on findings. Fresh deep copies prevent
            # one measured run from inheriting state from a previous run.
            findings = [finding.model_copy(deep=True) for finding in finding_templates]
            start = time.perf_counter()
            graph = Correlator().correlate(findings)
            timings_ms.append((time.perf_counter() - start) * 1000)
            edge_signature_hashes.add(_canonical_sha256(_edge_signature(graph)))
            cluster_signature_hashes.add(_canonical_sha256(_cluster_signature(graph)))
            telemetry_samples.append(_telemetry_dict(graph))
        _, python_peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    if graph is None:
        raise RuntimeError("benchmark produced no graph")

    stable_telemetry = telemetry_samples[0] if telemetry_samples and all(
        sample == telemetry_samples[0] for sample in telemetry_samples
    ) else None

    return {
        "modules": modules,
        "findings": len(finding_templates),
        "fanout": fanout,
        "requested_load_contexts": load_contexts,
        "actual_load_contexts": actual_contexts,
        "warmups": warmups,
        "runs": runs,
        "edges": len(graph.edges),
        "clusters": len(graph.clusters),
        "fixture_sha256": fixture_sha256,
        "edge_signature_sha256": (
            next(iter(edge_signature_hashes)) if len(edge_signature_hashes) == 1 else None
        ),
        "cluster_signature_sha256": (
            next(iter(cluster_signature_hashes)) if len(cluster_signature_hashes) == 1 else None
        ),
        "telemetry_sha256": (
            _canonical_sha256(stable_telemetry) if stable_telemetry is not None else None
        ),
        "edge_signature_variants": len(edge_signature_hashes),
        "cluster_signature_variants": len(cluster_signature_hashes),
        "telemetry": stable_telemetry,
        "telemetry_stable": stable_telemetry is not None,
        "peak_rss_bytes": _current_peak_rss_bytes(),
        "python_tracemalloc_peak_bytes": python_peak_bytes,
        "timings_ms": _timing_summary(timings_ms),
    }


def _baseline_scenario(baseline: dict[str, Any], modules: int) -> dict[str, Any] | None:
    scenarios = baseline.get("scenarios")
    if isinstance(scenarios, list):
        for scenario in scenarios:
            if isinstance(scenario, dict) and scenario.get("modules") == modules:
                return scenario
    if baseline.get("modules") == modules:
        return baseline
    return None


_TELEMETRY_COUNTERS = (
    "candidates",
    "candidate_attempts",
    "emitted",
    "dropped",
    "duplicate_dropped",
    "cap_dropped",
    "truncated_candidates",
    "truncated_candidates_lower_bound",
    "truncated_candidates_unknown",
)
_PASS_COUNTERS = (
    "candidate_attempts",
    "emitted",
    "duplicate_dropped",
    "cap_dropped",
    "truncated_candidates",
    "truncated_candidates_lower_bound",
    "truncated_candidates_unknown",
)


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return int(value)


def _finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return number


def _expected_correlator_contract() -> list[dict[str, Any]]:
    return [
        {
            "modules": gate.modules,
            "findings": gate.findings,
            "fanout": gate.fanout,
            "load_contexts": gate.load_contexts,
            "edges": gate.edges,
            "clusters": gate.clusters,
            "cap_dropped": gate.cap_dropped,
            "absolute_p95_ms": gate.p95_ms,
            "absolute_peak_rss_bytes": gate.peak_rss_bytes,
            "fixture_sha256": gate.fixture_sha256,
            "edge_signature_sha256": gate.edge_sha256,
            "cluster_signature_sha256": gate.cluster_sha256,
            "telemetry_sha256": gate.telemetry_sha256,
        }
        for gate in SCENARIO_GATES.values()
    ]


def _correlator_contract(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for scenario in scenarios:
        modules = scenario.get("modules")
        gate = SCENARIO_GATES.get(modules) if isinstance(modules, int) else None
        telemetry = scenario.get("telemetry")
        cap_dropped = telemetry.get("cap_dropped") if isinstance(telemetry, Mapping) else None
        result.append({
            "modules": modules,
            "findings": scenario.get("findings"),
            "fanout": scenario.get("fanout"),
            "load_contexts": scenario.get("requested_load_contexts"),
            "edges": scenario.get("edges"),
            "clusters": scenario.get("clusters"),
            "cap_dropped": cap_dropped,
            "absolute_p95_ms": gate.p95_ms if gate is not None else None,
            "absolute_peak_rss_bytes": gate.peak_rss_bytes if gate is not None else None,
            "fixture_sha256": scenario.get("fixture_sha256"),
            "edge_signature_sha256": scenario.get("edge_signature_sha256"),
            "cluster_signature_sha256": scenario.get("cluster_signature_sha256"),
            "telemetry_sha256": scenario.get("telemetry_sha256"),
        })
    return result


def _normalize_machine(value: str) -> str:
    normalized = value.strip().lower()
    return "x86_64" if normalized in {"amd64", "x64", "x86_64"} else normalized


def _python_minor(value: str) -> tuple[int, int]:
    components = value.split(".")
    if len(components) < 2 or not all(component.isdigit() for component in components[:2]):
        raise ValueError("Python version is malformed")
    return int(components[0]), int(components[1])


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                value = " ".join(line.split(":", 1)[1].split())
                if value:
                    return value
    except OSError:
        pass
    return " ".join((platform.processor() or platform.machine() or "unknown").split())


def _measurement_origin() -> str:
    configured = os.environ.get("BUNDLEINSPECTOR_BENCHMARK_ORIGIN")
    if configured is not None:
        if configured not in _MEASUREMENT_ORIGINS:
            raise ValueError("BUNDLEINSPECTOR_BENCHMARK_ORIGIN is unsupported")
        return configured
    release = platform.release().lower()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return "github-hosted"
    if platform.system() == "Linux" and "microsoft" in release:
        return "local-wsl"
    if platform.system() == "Linux":
        return "local-linux"
    if platform.system() == "Windows":
        return "local-windows"
    return "unknown"


def runtime_environment() -> dict[str, Any]:
    dependencies: dict[str, str] = {}
    for distribution in CORRELATOR_DEPENDENCY_NAMES:
        try:
            dependencies[distribution] = version(distribution)
        except PackageNotFoundError:
            dependencies[distribution] = "missing"
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": _normalize_machine(platform.machine()),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "measurement_origin": _measurement_origin(),
        "cpu_model": _cpu_model(),
        "dependencies": dependencies,
    }


def _validate_environment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ENVIRONMENT_FIELDS:
        raise ValueError("measurement_environment is unavailable or malformed")
    scalar_fields = _ENVIRONMENT_FIELDS - {"dependencies"}
    if any(not isinstance(value[name], str) or not value[name].strip() for name in scalar_fields):
        raise ValueError("measurement_environment values must be non-empty strings")
    dependencies = value["dependencies"]
    if not isinstance(dependencies, dict) or set(dependencies) != set(CORRELATOR_DEPENDENCY_NAMES):
        raise ValueError("measurement_environment dependency fingerprint is malformed")
    if any(not isinstance(item, str) or not item or item == "missing" for item in dependencies.values()):
        raise ValueError("measurement_environment dependency fingerprint is incomplete")
    if value["measurement_origin"] not in _MEASUREMENT_ORIGINS:
        raise ValueError("measurement_environment origin is incompatible")
    if value["os"] != "Linux" or _normalize_machine(value["machine"]) != "x86_64":
        raise ValueError("measurement_environment platform is incompatible")
    if _python_minor(value["python"]) != (3, 13) or value["implementation"] != "CPython":
        raise ValueError("measurement_environment Python runtime is incompatible")
    return copy.deepcopy(value)


def same_hardware(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return " ".join(str(left.get("cpu_model", "")).split()).casefold() == " ".join(
        str(right.get("cpu_model", "")).split()
    ).casefold()


def validate_runtime_compatibility(baseline_environment: Any) -> None:
    baseline = _validate_environment(baseline_environment)
    current = runtime_environment()
    try:
        compatible = (
            current["os"] == baseline["os"]
            and _normalize_machine(str(current["machine"]))
            == _normalize_machine(str(baseline["machine"]))
            and _python_minor(str(current["python"])) == _python_minor(str(baseline["python"]))
            and current["implementation"] == baseline["implementation"]
            and current["dependencies"] == baseline["dependencies"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("current runtime profile is unavailable") from exc
    if not compatible:
        raise ValueError("current runtime is incompatible with the baseline profile")


def validate_baseline_document(baseline: Any) -> dict[str, Any]:
    if not isinstance(baseline, dict) or set(baseline) != _BASELINE_FIELDS:
        raise ValueError("root object has an invalid baseline schema")
    if baseline.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError("schema_version is unsupported")
    if baseline.get("benchmark") != "correlator" or baseline.get("profile") != BASELINE_PROFILE:
        raise ValueError("benchmark profile is incompatible")
    _validate_environment(baseline.get("measurement_environment"))
    if _nonnegative_int(baseline.get("runs"), "baseline.runs") != RELEASE_RUNS:
        raise ValueError("measured run count is incompatible")
    if _nonnegative_int(baseline.get("warmups"), "baseline.warmups") != RELEASE_WARMUPS:
        raise ValueError("warm-up count is incompatible")
    scenarios = baseline.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != len(SCENARIO_GATES):
        raise ValueError("scenarios array is unavailable or malformed")
    by_modules: dict[int, dict[str, Any]] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError("scenario is malformed")
        modules = _nonnegative_int(scenario.get("modules"), "baseline.scenario.modules")
        if modules in by_modules:
            raise ValueError("scenario modules are duplicated")
        by_modules[modules] = scenario
    if set(by_modules) != set(SCENARIO_GATES):
        raise ValueError("scenario module profile is incompatible")
    if baseline.get("scenario_contract_sha256") != _canonical_sha256(
        _expected_correlator_contract()
    ):
        raise ValueError("scenario contract digest is incompatible")
    if baseline.get("result_sha256") != _canonical_sha256(scenarios):
        raise ValueError("result digest differs from baseline scenarios")
    for modules, gate in SCENARIO_GATES.items():
        scenario = by_modules[modules]
        exact_values = {
            "findings": gate.findings,
            "fanout": gate.fanout,
            "requested_load_contexts": gate.load_contexts,
            "actual_load_contexts": gate.load_contexts,
            "edges": gate.edges,
            "clusters": gate.clusters,
            "fixture_sha256": gate.fixture_sha256,
            "edge_signature_sha256": gate.edge_sha256,
            "cluster_signature_sha256": gate.cluster_sha256,
            "telemetry_sha256": gate.telemetry_sha256,
        }
        if any(scenario.get(name) != expected for name, expected in exact_values.items()):
            raise ValueError(f"scenario {modules} fixture contract is incompatible")
        if _nonnegative_int(scenario.get("runs"), f"baseline.{modules}.runs") != RELEASE_RUNS:
            raise ValueError(f"scenario {modules} measured run count is incompatible")
        if _nonnegative_int(scenario.get("warmups"), f"baseline.{modules}.warmups") != RELEASE_WARMUPS:
            raise ValueError(f"scenario {modules} warm-up count is incompatible")
        timings = scenario.get("timings_ms")
        if not isinstance(timings, Mapping):
            raise ValueError(f"scenario {modules} timings are malformed")
        if _finite_number(timings.get("p95"), f"baseline.{modules}.timings_ms.p95") <= 0:
            raise ValueError(f"scenario {modules} p95 must be positive")
        if _nonnegative_int(scenario.get("peak_rss_bytes"), f"baseline.{modules}.peak_rss_bytes") <= 0:
            raise ValueError(f"scenario {modules} peak RSS must be positive")
        integrity_failures = evaluate_gates(
            scenario,
            expected_runs=RELEASE_RUNS,
            expected_warmups=RELEASE_WARMUPS,
        )
        if integrity_failures:
            raise ValueError(
                f"stored scenario {modules} fails release integrity: {integrity_failures}"
            )
    return baseline


def _sha256_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timing_interval(timings: Mapping[str, Any], name: str) -> list[float]:
    raw = timings.get(name)
    if not isinstance(raw, list) or len(raw) != 2:
        raise ValueError(f"timings_ms.{name} must contain exactly two values")
    interval = [
        _finite_number(value, f"timings_ms.{name}[{index}]")
        for index, value in enumerate(raw)
    ]
    if interval[0] > interval[1]:
        raise ValueError(f"timings_ms.{name} lower bound exceeds upper bound")
    return interval


def _validate_telemetry(
    telemetry: object,
    *,
    edges: int | None,
    expected_cap_dropped: int | None,
) -> list[str]:
    if not isinstance(telemetry, Mapping):
        return ["correlator completeness telemetry is unavailable or malformed"]
    failures: list[str] = []
    counters: dict[str, int] = {}
    for name in _TELEMETRY_COUNTERS:
        try:
            counters[name] = _nonnegative_int(telemetry.get(name), f"telemetry.{name}")
        except ValueError as exc:
            failures.append(str(exc))
    if len(counters) != len(_TELEMETRY_COUNTERS):
        return failures

    if edges is not None and counters["emitted"] != edges:
        failures.append("telemetry.emitted differs from graph edge count")
    if counters["candidates"] != counters["candidate_attempts"]:
        failures.append("telemetry.candidates differs from candidate_attempts")
    if counters["candidate_attempts"] != (
        counters["emitted"] + counters["duplicate_dropped"]
    ):
        failures.append("telemetry attempted candidates are not fully accounted")
    if counters["dropped"] != counters["duplicate_dropped"]:
        failures.append("telemetry.dropped differs from duplicate_dropped")
    if counters["cap_dropped"] != counters["truncated_candidates_lower_bound"]:
        failures.append("telemetry cap lower-bound counters disagree")
    if counters["truncated_candidates"] > counters["truncated_candidates_lower_bound"]:
        failures.append("telemetry exact truncation exceeds its lower bound")
    if counters["truncated_candidates_unknown"] > counters["cap_dropped"]:
        failures.append("telemetry unknown truncation count exceeds cap lower bound")

    capped_passes = telemetry.get("capped_passes")
    capped_pass_total: int | None = None
    capped_passes_valid = False
    if isinstance(capped_passes, Mapping):
        capped_passes_valid = not any(
            not isinstance(name, str)
            or not name
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count <= 0
            for name, count in capped_passes.items()
        )
        if capped_passes_valid:
            capped_pass_total = sum(int(count) for count in capped_passes.values())
    if not capped_passes_valid:
        failures.append("telemetry.capped_passes is unavailable or malformed")

    passes = telemetry.get("passes")
    pass_totals: dict[str, int] = dict.fromkeys(_PASS_COUNTERS, 0)
    if not isinstance(passes, Mapping) or not passes:
        failures.append("telemetry.passes is unavailable or malformed")
    else:
        for pass_name, stats in passes.items():
            if not isinstance(pass_name, str) or not pass_name or not isinstance(stats, Mapping):
                failures.append("telemetry.passes contains a malformed pass")
                continue
            for counter_name in _PASS_COUNTERS:
                try:
                    pass_totals[counter_name] += _nonnegative_int(
                        stats.get(counter_name),
                        f"telemetry.passes.{pass_name}.{counter_name}",
                    )
                except ValueError as exc:
                    failures.append(str(exc))
        for counter_name, total in pass_totals.items():
            if total != counters[counter_name]:
                failures.append(
                    f"telemetry pass total for {counter_name} differs from global counter"
                )

    if expected_cap_dropped is not None:
        expected = {
            "candidates": edges,
            "candidate_attempts": edges,
            "emitted": edges,
            "dropped": 0,
            "duplicate_dropped": 0,
            "cap_dropped": expected_cap_dropped,
            "truncated_candidates": 0,
            "truncated_candidates_lower_bound": expected_cap_dropped,
            "truncated_candidates_unknown": expected_cap_dropped,
        }
        for name, expected_value in expected.items():
            if expected_value is not None and counters[name] != expected_value:
                failures.append(
                    f"telemetry.{name} {counters[name]} != expected {expected_value}"
                )
        if capped_pass_total is not None and capped_pass_total != expected_cap_dropped:
            failures.append("telemetry capped-pass count differs from expected cap disclosure")
        if (
            isinstance(capped_passes, Mapping)
            and capped_passes_valid
            and dict(capped_passes) != _EXPECTED_CAPPED_PASSES
        ):
            failures.append("telemetry capped-pass distribution differs from fixed fixture")
        if isinstance(passes, Mapping) and set(passes) != _EXPECTED_PASS_NAMES:
            failures.append("telemetry pass set differs from fixed fixture")
        if telemetry.get("ambiguous_imports") != []:
            failures.append("fixed benchmark fixture produced ambiguous import telemetry")
    return failures


def evaluate_gates(
    result: dict[str, Any],
    *,
    baseline: dict[str, Any] | None = None,
    cross_hardware_baseline: bool = False,
    require_telemetry: bool = True,
    expected_runs: int | None = None,
    expected_warmups: int | None = None,
) -> list[str]:
    """Return every gate failure; an empty list means PASS."""
    failures: list[str] = []
    if not isinstance(result, Mapping):
        return ["benchmark result is unavailable or malformed"]
    if cross_hardware_baseline and baseline is None:
        return ["cross-hardware comparison requires a baseline"]

    integers: dict[str, int] = {}
    for name in (
        "modules",
        "findings",
        "fanout",
        "requested_load_contexts",
        "actual_load_contexts",
        "warmups",
        "runs",
        "edges",
        "clusters",
        "edge_signature_variants",
        "cluster_signature_variants",
        "peak_rss_bytes",
        "python_tracemalloc_peak_bytes",
    ):
        try:
            integers[name] = _nonnegative_int(result.get(name), name)
        except ValueError as exc:
            failures.append(str(exc))

    modules = integers.get("modules")
    gate = SCENARIO_GATES.get(modules) if modules is not None else None
    timings = result.get("timings_ms")
    timing_metrics: dict[str, float] = {}
    timing_intervals: dict[str, list[float]] = {}
    timing_samples: list[float] | None = None
    if not isinstance(timings, Mapping):
        failures.append("timings_ms must be an object")
    else:
        for name in ("min", "p50", "p95", "max", "mean", "coefficient_of_variation"):
            try:
                timing_metrics[name] = _finite_number(
                    timings.get(name),
                    f"timings_ms.{name}",
                )
            except ValueError as exc:
                failures.append(str(exc))
        for name in ("p50_bootstrap_95_ci", "p95_bootstrap_95_ci"):
            try:
                timing_intervals[name] = _timing_interval(timings, name)
            except ValueError as exc:
                failures.append(str(exc))
        raw_samples = timings.get("samples")
        if not isinstance(raw_samples, list):
            failures.append("timings_ms.samples must be an array")
        else:
            try:
                timing_samples = [
                    _finite_number(sample, f"timings_ms.samples[{index}]")
                    for index, sample in enumerate(raw_samples)
                ]
            except ValueError as exc:
                failures.append(str(exc))

    runs = integers.get("runs")
    warmups = integers.get("warmups")
    if runs is not None and runs < 30:
        failures.append("release gate requires at least 30 measured runs")
    if expected_runs is not None and runs is not None and runs != expected_runs:
        failures.append("measured run count differs from the requested run count")
    if expected_warmups is not None and warmups is not None and warmups != expected_warmups:
        failures.append("warm-up count differs from the requested warm-up count")
    if runs is not None and timing_samples is not None and len(timing_samples) != runs:
        failures.append("timing sample count differs from measured runs")
    if timing_samples:
        if not all(sample > 0 for sample in timing_samples):
            failures.append("timing samples must be positive")
        recalculated = _timing_summary(timing_samples)
        for name in ("min", "p50", "p95", "max", "mean", "coefficient_of_variation"):
            reported = timing_metrics.get(name)
            if reported is not None and abs(float(recalculated[name]) - reported) > 1e-9:
                failures.append(f"reported {name} differs from timing samples")
        for name in ("p50_bootstrap_95_ci", "p95_bootstrap_95_ci"):
            reported_interval = timing_intervals.get(name)
            expected_interval = recalculated[name]
            if reported_interval is not None and reported_interval != expected_interval:
                failures.append(f"reported {name} differs from timing samples")

    p95 = timing_metrics.get("p95")
    variation = timing_metrics.get("coefficient_of_variation")

    if (
        integers.get("actual_load_contexts") is not None
        and integers.get("requested_load_contexts") is not None
        and integers["actual_load_contexts"] != integers["requested_load_contexts"]
    ):
        failures.append("actual load-context count differs from requested fixture shape")
    if (
        integers.get("edge_signature_variants") is not None
        and integers.get("cluster_signature_variants") is not None
        and (
            integers["edge_signature_variants"] != 1
            or integers["cluster_signature_variants"] != 1
        )
    ):
        failures.append("edge or cluster signature changed across identical runs")
    if variation is not None and variation > 0.25:
        failures.append("runner timing coefficient of variation exceeds 0.25")
    for name in ("peak_rss_bytes", "python_tracemalloc_peak_bytes"):
        if name in integers and integers[name] <= 0:
            failures.append(f"{name} must be positive")
    if require_telemetry:
        if result.get("telemetry_stable") is not True:
            failures.append("correlator completeness telemetry changed across identical runs")
        failures.extend(_validate_telemetry(
            result.get("telemetry"),
            edges=integers.get("edges"),
            expected_cap_dropped=gate.cap_dropped if gate is not None else None,
        ))
    if gate is None:
        failures.append(f"no fixed release threshold for {modules!r} modules")
    else:
        expected_integers = {
            "modules": gate.modules,
            "findings": gate.findings,
            "fanout": gate.fanout,
            "requested_load_contexts": gate.load_contexts,
            "actual_load_contexts": gate.load_contexts,
            "edges": gate.edges,
            "clusters": gate.clusters,
        }
        for name, expected_value in expected_integers.items():
            if name in integers and integers[name] != expected_value:
                failures.append(
                    f"fixture {name} {integers[name]} != expected {expected_value}"
                )
        expected_hashes = {
            "fixture_sha256": gate.fixture_sha256,
            "edge_signature_sha256": gate.edge_sha256,
            "cluster_signature_sha256": gate.cluster_sha256,
            "telemetry_sha256": gate.telemetry_sha256,
        }
        for name, expected_digest in expected_hashes.items():
            try:
                observed_digest = _sha256_digest(result.get(name), name)
            except ValueError as exc:
                failures.append(str(exc))
            else:
                if observed_digest != expected_digest:
                    failures.append(f"{name} differs from fixed semantic fixture")
        if isinstance(result.get("telemetry"), Mapping):
            telemetry_digest = _canonical_sha256(result["telemetry"])
            if telemetry_digest != result.get("telemetry_sha256"):
                failures.append("telemetry_sha256 differs from telemetry payload")
        if p95 is not None and p95 > gate.p95_ms:
            failures.append(f"p95 {p95} ms exceeds {gate.p95_ms} ms")
        peak_rss = integers.get("peak_rss_bytes")
        if (
            gate.peak_rss_bytes is not None
            and peak_rss is not None
            and peak_rss > gate.peak_rss_bytes
        ):
            failures.append(
                f"peak RSS {peak_rss} exceeds {gate.peak_rss_bytes} bytes"
            )
    if baseline is not None:
        try:
            validated_baseline = validate_baseline_document(baseline)
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(f"baseline: {exc}")
        else:
            previous = _baseline_scenario(validated_baseline, modules) if modules is not None else None
            if previous is None:
                failures.append(f"baseline has no {modules}-module scenario")
            else:
                try:
                    previous_timings = previous.get("timings_ms")
                    if not isinstance(previous_timings, Mapping):
                        raise ValueError("baseline timings_ms must be an object")
                    previous_p95 = _finite_number(
                        previous_timings.get("p95"),
                        "baseline timings_ms.p95",
                    )
                    previous_p95_interval = _timing_interval(
                        previous_timings,
                        "p95_bootstrap_95_ci",
                    )
                    previous_rss = _nonnegative_int(
                        previous.get("peak_rss_bytes"),
                        "baseline peak_rss_bytes",
                    )
                except ValueError as exc:
                    failures.append(str(exc))
                else:
                    if cross_hardware_baseline:
                        current_p95_interval = timing_intervals.get(
                            "p95_bootstrap_95_ci"
                        )
                        if current_p95_interval is not None and (
                            current_p95_interval[0] > previous_p95_interval[1] * 1.20
                        ):
                            failures.append(
                                "p95 bootstrap CI regressed more than 20% from "
                                "cross-hardware baseline"
                            )
                    elif p95 is not None and p95 > previous_p95 * 1.20:
                        failures.append("p95 regressed more than 20% from baseline")
                    peak_rss = integers.get("peak_rss_bytes")
                    if peak_rss is not None and peak_rss > previous_rss * 1.25:
                        failures.append("peak RSS regressed more than 25% from baseline")
    return failures


def create_baseline_payload(
    scenarios: list[dict[str, Any]],
    measurement_environment: dict[str, Any],
) -> dict[str, Any]:
    if len(scenarios) != len(SCENARIO_GATES):
        raise ValueError("correlator result must contain the complete release suite")
    failures: list[str] = []
    for scenario in scenarios:
        modules = scenario.get("modules")
        failures.extend(
            f"{modules} modules: {failure}"
            for failure in evaluate_gates(
                scenario,
                expected_runs=RELEASE_RUNS,
                expected_warmups=RELEASE_WARMUPS,
            )
        )
    if failures:
        raise ValueError(f"correlator result is not release-valid: {failures}")
    environment = _validate_environment(measurement_environment)
    frozen = copy.deepcopy(scenarios)
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "benchmark": "correlator",
        "profile": BASELINE_PROFILE,
        "measurement_environment": environment,
        "scenario_contract_sha256": _canonical_sha256(_expected_correlator_contract()),
        "result_sha256": _canonical_sha256(frozen),
        "runs": RELEASE_RUNS,
        "warmups": RELEASE_WARMUPS,
        "scenarios": frozen,
    }
    return validate_baseline_document(payload)


def create_result_payload(
    scenarios: list[dict[str, Any]],
    measurement_environment: dict[str, Any],
    *,
    runs: int,
    warmups: int,
    gate_failures: list[str],
    relative_baseline_comparison: str = "not_requested",
) -> dict[str, Any]:
    if relative_baseline_comparison not in {
        "not_requested",
        "applied_same_hardware",
        "applied_cross_hardware_attribution_unavailable",
    }:
        raise ValueError("relative baseline comparison state is invalid")
    environment = copy.deepcopy(measurement_environment)
    try:
        _validate_environment(environment)
    except ValueError:
        profile = UNPROFILED_RESULT_PROFILE
    else:
        profile = BASELINE_PROFILE
    frozen = copy.deepcopy(scenarios)
    contract = _correlator_contract(frozen)
    return {
        "schema_version": RAW_RESULT_SCHEMA_VERSION,
        "benchmark": "correlator",
        "profile": profile,
        "measurement_environment": environment,
        "scenario_contract_sha256": _canonical_sha256(contract),
        "result_sha256": _canonical_sha256(frozen),
        "runs": runs,
        "warmups": warmups,
        "passed": not gate_failures,
        "gate_failures": list(gate_failures),
        "relative_baseline_comparison": relative_baseline_comparison,
        "scenarios": frozen,
    }


def validate_result_document(result: Any, *, require_runtime_compatibility: bool = True) -> dict[str, Any]:
    if not isinstance(result, dict) or set(result) != _RAW_RESULT_FIELDS:
        raise ValueError("root object has an invalid correlator result schema")
    if result.get("schema_version") != RAW_RESULT_SCHEMA_VERSION:
        raise ValueError("correlator result schema_version is unsupported")
    if result.get("benchmark") != "correlator" or result.get("profile") != BASELINE_PROFILE:
        raise ValueError("correlator result benchmark profile is incompatible")
    environment = _validate_environment(result.get("measurement_environment"))
    if require_runtime_compatibility:
        validate_runtime_compatibility(environment)
    if _nonnegative_int(result.get("runs"), "result.runs") != RELEASE_RUNS:
        raise ValueError("correlator result measured run count is incompatible")
    if _nonnegative_int(result.get("warmups"), "result.warmups") != RELEASE_WARMUPS:
        raise ValueError("correlator result warm-up count is incompatible")
    if result.get("passed") is not True or result.get("gate_failures") != []:
        raise ValueError("correlator source result is not a clean benchmark payload")
    if result.get("relative_baseline_comparison") != "not_requested":
        raise ValueError("correlator baseline source must be measured without a prior baseline")
    scenarios = result.get("scenarios")
    if not isinstance(scenarios, list) or not all(isinstance(item, dict) for item in scenarios):
        raise ValueError("correlator result scenarios are malformed")
    contract = _correlator_contract(scenarios)
    if contract != _expected_correlator_contract():
        raise ValueError("correlator result scenario fixture contract is incompatible")
    if result.get("scenario_contract_sha256") != _canonical_sha256(contract):
        raise ValueError("correlator result scenario contract digest is incompatible")
    if result.get("result_sha256") != _canonical_sha256(scenarios):
        raise ValueError("correlator result digest differs from scenarios")
    failures: list[str] = []
    for scenario in scenarios:
        modules = scenario.get("modules")
        failures.extend(
            f"{modules} modules: {failure}"
            for failure in evaluate_gates(
                scenario,
                expected_runs=RELEASE_RUNS,
                expected_warmups=RELEASE_WARMUPS,
            )
        )
    if failures:
        raise ValueError(f"correlator result fails release integrity: {failures}")
    return copy.deepcopy(result)


def _load_baseline(
    path: Path | None,
    *,
    require_runtime_compatibility: bool = False,
) -> dict[str, Any] | None:
    if path is None:
        return None
    raw = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"baseline contains non-finite constant {value}")
        ),
    )
    if not isinstance(raw, dict):
        raise ValueError("baseline root must be a JSON object")
    baseline = validate_baseline_document(raw)
    if require_runtime_compatibility:
        validate_runtime_compatibility(baseline["measurement_environment"])
    return baseline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", type=int, default=80, help="Number of synthetic modules")
    parser.add_argument("--fanout", type=int, default=3, help="Import fanout per module")
    parser.add_argument("--load-contexts", type=int, default=4, help="Distinct load contexts")
    parser.add_argument("--runs", "--rounds", dest="runs", type=int, default=5, help="Measured runs")
    parser.add_argument("--warmups", type=int, default=1, help="Warm-up runs")
    parser.add_argument("--suite", action="store_true", help="Run fixed 80/200/500 scenarios")
    parser.add_argument("--assert-gates", action="store_true", help="Fail unless release gates pass")
    parser.add_argument("--baseline", type=Path, default=None, help="Required release baseline JSON")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON result path")
    args = parser.parse_args(argv)

    if args.runs < 1:
        parser.error("--rounds must be at least 1 (--runs is the preferred alias)")
    if args.warmups < 0:
        parser.error("--warmups must be non-negative")
    if args.assert_gates and not args.suite:
        parser.error("--assert-gates requires --suite")
    if args.assert_gates and args.runs != RELEASE_RUNS:
        parser.error(f"--assert-gates requires --runs {RELEASE_RUNS}")
    if args.assert_gates and args.warmups != RELEASE_WARMUPS:
        parser.error(f"--assert-gates requires --warmups {RELEASE_WARMUPS}")
    if args.assert_gates and args.baseline is None:
        parser.error("--assert-gates requires --baseline")
    if args.baseline is not None and not args.assert_gates:
        parser.error("--baseline requires --assert-gates")
    try:
        baseline = _load_baseline(args.baseline, require_runtime_compatibility=args.assert_gates)
        environment = runtime_environment()
        comparison_state = "not_requested"
        cross_hardware_baseline = False
        if args.assert_gates and baseline is not None:
            if same_hardware(environment, baseline["measurement_environment"]):
                comparison_state = "applied_same_hardware"
            else:
                comparison_state = "applied_cross_hardware_attribution_unavailable"
                cross_hardware_baseline = True
        module_counts = [80, 200, 500] if args.suite else [args.modules]
        scenarios = [
            run_benchmark(
                modules,
                args.fanout,
                args.load_contexts,
                args.runs,
                warmups=args.warmups,
            )
            for modules in module_counts
        ]
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        parser.exit(2, f"benchmark error: {exc}\n")

    failures: list[str] = []
    if args.assert_gates:
        for scenario in scenarios:
            scenario_failures = evaluate_gates(
                scenario,
                baseline=baseline,
                cross_hardware_baseline=cross_hardware_baseline,
                expected_runs=args.runs,
                expected_warmups=args.warmups,
            )
            scenario["gate_failures"] = scenario_failures
            scenario["passed"] = not scenario_failures
            failures.extend(f"{scenario['modules']} modules: {failure}" for failure in scenario_failures)
    payload = create_result_payload(
        scenarios,
        environment,
        runs=args.runs,
        warmups=args.warmups,
        gate_failures=failures,
        relative_baseline_comparison=comparison_state,
    )
    rendered = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
