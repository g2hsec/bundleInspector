"""Deterministic parser, custom-regex, and lexical-fallback resource gates."""

from __future__ import annotations

import argparse
import copy
import ctypes
import gc
import hashlib
import importlib
import io
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from collections.abc import Callable
from contextlib import redirect_stdout
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from bundleInspector.parser.ir_builder import build_ir  # noqa: E402
from bundleInspector.parser.js_parser import JSParser, ParseResult, parse_js  # noqa: E402
from bundleInspector.rules.base import AnalysisContext  # noqa: E402
from bundleInspector.rules.custom import (  # noqa: E402
    CUSTOM_REGEX_TIMEOUT_SECONDS,
    CustomRegexRule,
    CustomRuleSpec,
)
from bundleInspector.storage.models import Category, IntermediateRepresentation  # noqa: E402

MIB = 1024 * 1024
MODERN_PARSE_P95_MS = 2_000.0
MODERN_PARSE_PEAK_RSS_BYTES = 1024 * MIB
CUSTOM_REGEX_WALL_MS = 750.0
LEXICAL_P95_MS = 2_000.0
LEXICAL_PEAK_RSS_BYTES = 1024 * MIB
RELEASE_RUNS = 30
RELEASE_WARMUPS = 2
BASELINE_SCHEMA_VERSION = 1
BASELINE_PROFILE = "linux-x86_64-python3.13-release"
RAW_RESULT_SCHEMA_VERSION = 1
UNPROFILED_RESULT_PROFILE = "unprofiled"
DETECTION_DEPENDENCY_VERSIONS = {
    "bundleInspector": "0.1.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "regex": "2026.7.10",
    "tree-sitter": "0.26.0",
    "tree-sitter-javascript": "0.25.0",
    "tree-sitter-typescript": "0.23.2",
}
_CUSTOM_REGEX_SOURCE = f"/* SAFE */ const value = '{'a' * 20_000}!';"
CUSTOM_REGEX_SOURCE_BYTES = len(_CUSTOM_REGEX_SOURCE.encode("utf-8"))
MODERN_SOURCE_SHA256 = "680367a475b6c3996dd075cc1a06e6be0e7933c7e147494c2d26882314283a34"
CUSTOM_REGEX_SOURCE_SHA256 = "6fcd68e3c4309fde481a00829306b184118a5c1d9b6c98474a3db57fb410b81e"
LEXICAL_SOURCE_SHA256 = "9b5b91469f32046800c5f57e452df21393188b765f5f19db30b6d4a92ba4e826"
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


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one sample")
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
    """Return a deterministic percentile-bootstrap confidence interval."""
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
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)

    resource = importlib.import_module("resource")
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(usage if sys.platform == "darwin" else usage * 1024)


def build_modern_source(target_bytes: int = MIB) -> str:
    """Build exact-size, syntactically complete modern TypeScript input."""
    prefix = (
        "interface Envelope<T> { value: T }\n"
        "class Service {\n"
        "  #token: string = 'fixture-only';\n"
        "  async load<T>(path: string): Promise<T> {\n"
        "    return (await fetch(path)).json() as Promise<T>;\n"
        "  }\n"
        "}\n"
        "const service = new Service();\n"
        "void service.load<Envelope<string>>('/api/modern-resource');\n"
    )
    if target_bytes < len(prefix.encode("utf-8")) + 4:
        raise ValueError("target_bytes is too small for the modern fixture")
    parts = [prefix]
    size = len(prefix.encode("utf-8"))
    index = 0
    while True:
        line = f'const typed_{index}: string = "resource-{index:06d}";\n'
        encoded = len(line.encode("utf-8"))
        if size + encoded > target_bytes - 4:
            break
        parts.append(line)
        size += encoded
        index += 1
    padding = target_bytes - size
    parts.append("/*" + ("x" * (padding - 4)) + "*/")
    source = "".join(parts)
    if len(source.encode("utf-8")) != target_bytes:
        raise RuntimeError("modern fixture byte size drifted")
    return source


def _contains_literal(ast: dict[str, Any], expected: str) -> bool:
    stack: list[Any] = [ast]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            if value.get("value") == expected:
                return True
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return False


def benchmark_modern_parse(runs: int, warmups: int, *, target_bytes: int = MIB) -> dict[str, Any]:
    source = build_modern_source(target_bytes)
    for _ in range(warmups):
        warmup = parse_js(source, language_hint="typescript")
        if not warmup.success or warmup.ast is None:
            raise RuntimeError(f"modern parser warm-up failed: {warmup.errors}")
        del warmup
        gc.collect()

    timings: list[float] = []
    parser_variants: set[str] = set()
    partial_runs = 0
    error_runs = 0
    signature_variants: set[tuple[str, bool, str, int]] = set()
    endpoint_preserved = True
    for _ in range(runs):
        started = time.perf_counter()
        parsed = parse_js(source, language_hint="typescript")
        timings.append((time.perf_counter() - started) * 1000)
        parser_variants.add(parsed.parser_used)
        partial_runs += int(parsed.partial)
        error_runs += int(bool(parsed.errors) or not parsed.success or parsed.ast is None)
        if parsed.ast is not None:
            body = parsed.ast.get("body", [])
            source_language = str(parsed.ast.get("source_language") or "")
            signature_variants.add(
                (parsed.parser_used, parsed.partial, source_language, len(body) if isinstance(body, list) else -1)
            )
            endpoint_preserved = endpoint_preserved and _contains_literal(
                parsed.ast,
                "/api/modern-resource",
            )
        else:
            endpoint_preserved = False
        del parsed
        gc.collect()
    return {
        "name": "modern_parse",
        "runs": runs,
        "warmups": warmups,
        "source_bytes": len(source.encode("utf-8")),
        "source_sha256": _sha256_text(source),
        "language_hint": "typescript",
        "parser_variants": sorted(parser_variants),
        "signature_variants": len(signature_variants),
        "partial_runs": partial_runs,
        "error_runs": error_runs,
        "endpoint_preserved": endpoint_preserved,
        "peak_rss_bytes": _current_peak_rss_bytes(),
        "timings_ms": _timing_summary(timings),
    }


def _custom_regex_fixture() -> tuple[CustomRegexRule, IntermediateRepresentation, str]:
    source = _CUSTOM_REGEX_SOURCE
    parsed = parse_js(source, language_hint="javascript")
    if not parsed.success or parsed.ast is None:
        raise RuntimeError(f"custom-regex fixture parse failed: {parsed.errors}")
    ir = build_ir(parsed.ast, "file:///benchmark/custom-regex.js", "benchmark-regex")
    rule = CustomRegexRule(
        CustomRuleSpec(
            id="benchmark-regex-timeout",
            title="benchmark regex timeout",
            category=Category.DEBUG,
            pattern=r"SAFE|(a|aa)+$",
        )
    )
    return rule, ir, source


def benchmark_custom_regex(runs: int, warmups: int) -> dict[str, Any]:
    rule, ir, source = _custom_regex_fixture()

    def run_once() -> tuple[float, bool, bool, tuple[object, ...]]:
        context = AnalysisContext(
            file_url="file:///benchmark/custom-regex.js",
            file_hash="benchmark-regex",
            source_content=source,
        )
        started = time.perf_counter()
        # The production rule logs its disclosed timeout. Keep benchmark stdout machine-readable;
        # the structured context event below is the evidence this scenario evaluates.
        with redirect_stdout(io.StringIO()):
            findings = list(rule.match(ir, context))
        elapsed = (time.perf_counter() - started) * 1000
        events = context.metadata.get("analysis_incomplete", [])
        timed_out = isinstance(events, list) and any(
            isinstance(event, dict)
            and event.get("reason") == "regex_timeout"
            and event.get("partial_results") is True
            for event in events
        )
        extracted_values = tuple(finding.extracted_value for finding in findings)
        preserved = extracted_values == ("SAFE",)
        event_signature = tuple(
            sorted(
                (
                    str(event.get("component") or ""),
                    str(event.get("rule_id") or ""),
                    str(event.get("reason") or ""),
                    bool(event.get("partial_results")),
                )
                for event in events
                if isinstance(event, dict)
            )
        ) if isinstance(events, list) else ()
        return elapsed, timed_out, preserved, (extracted_values, event_signature)

    for _ in range(warmups):
        run_once()
    samples = [run_once() for _ in range(runs)]
    return {
        "name": "custom_regex",
        "runs": runs,
        "warmups": warmups,
        "configured_timeout_seconds": CUSTOM_REGEX_TIMEOUT_SECONDS,
        "source_bytes": len(source.encode("utf-8")),
        "source_sha256": _sha256_text(source),
        "timeout_disclosures": sum(int(sample[1]) for sample in samples),
        "prior_result_preserved_runs": sum(int(sample[2]) for sample in samples),
        "signature_variants": len({sample[3] for sample in samples}),
        "peak_rss_bytes": _current_peak_rss_bytes(),
        "timings_ms": _timing_summary([sample[0] for sample in samples]),
    }


def build_lexical_fixture(double_candidates: int = 10_001) -> str:
    if double_candidates < 10_001:
        raise ValueError("release lexical fixture requires at least 10,001 double candidates")
    middle = "".join(f'"noise-{index:05d}";\n' for index in range(double_candidates))
    return (
        "const first = '/api/single-before-flood';\n"
        + middle
        + "const last = `/api/template-after-flood`;\n"
        + '// "/api/comment-decoy"\n'
    )


def _literal_records(parsed: ParseResult) -> list[tuple[str, str]]:
    if parsed.ast is None:
        return []
    records: list[tuple[str, str]] = []
    body = parsed.ast.get("body", [])
    if not isinstance(body, list):
        return records
    for statement in body:
        if not isinstance(statement, dict):
            continue
        expression = statement.get("expression")
        if isinstance(expression, dict) and isinstance(expression.get("value"), str):
            records.append((expression["value"], str(expression.get("raw") or "")))
    return records


def _quote_counts(records: list[tuple[str, str]]) -> tuple[int, int, int]:
    counts = {'"': 0, "'": 0, "`": 0}
    for _value, raw in records:
        if raw[:1] in counts:
            counts[raw[0]] += 1
    return counts['"'], counts["'"], counts["`"]


def _timed_lexical_parse(parser: JSParser, source: str) -> tuple[float, ParseResult]:
    automatic_gc_enabled = gc.isenabled()
    gc.disable()
    try:
        started = time.perf_counter()
        parsed = parser._parse_regex_fallback(source)
        elapsed_ms = (time.perf_counter() - started) * 1000
    finally:
        if automatic_gc_enabled:
            gc.enable()
        else:
            gc.disable()
    return elapsed_ms, parsed


def benchmark_lexical_candidates(
    runs: int,
    warmups: int,
    *,
    double_candidates: int = 10_001,
) -> dict[str, Any]:
    source = build_lexical_fixture(double_candidates)
    parser = JSParser()
    for _ in range(warmups):
        gc.collect()
        _elapsed_ms, warmup = _timed_lexical_parse(parser, source)
        del warmup
    gc.collect()
    samples: list[float] = []
    retained_counts: set[int] = set()
    retained_quote_counts: set[tuple[int, int, int]] = set()
    missing_sentinels: set[str] = set()
    partial_disclosures = 0
    successful_runs = 0
    signature_variants: set[tuple[str, ...]] = set()
    for _ in range(runs):
        gc.collect()
        elapsed_ms, parsed = _timed_lexical_parse(parser, source)
        samples.append(elapsed_ms)
        records = _literal_records(parsed)
        values = [value for value, _raw in records]
        retained_counts.add(len(values))
        retained_quote_counts.add(_quote_counts(records))
        missing = tuple(
            sentinel
            for sentinel in ("/api/single-before-flood", "/api/template-after-flood")
            if sentinel not in values
        )
        missing_sentinels.update(missing)
        successful_runs += int(parsed.success and parsed.ast is not None)
        partial_disclosures += int(
            parsed.partial
            and any("literal count cap" in reason for reason in parsed.truncation_reasons)
        )
        signature_variants.add(tuple(values))
        del parsed, records, values
    return {
        "name": "lexical_candidates",
        "runs": runs,
        "warmups": warmups,
        "source_bytes": len(source.encode("utf-8")),
        "source_sha256": _sha256_text(source),
        "input_double_candidates": double_candidates,
        "expected_retained_candidates": JSParser.MAX_STRINGS_EXTRACTED + 2,
        "expected_retained_by_quote": {
            "double": JSParser.MAX_STRINGS_EXTRACTED,
            "single": 1,
            "template": 1,
        },
        "retained_candidate_counts": sorted(retained_counts),
        "retained_by_quote_variants": [
            {"double": double, "single": single, "template": template}
            for double, single, template in sorted(retained_quote_counts)
        ],
        "signature_variants": len(signature_variants),
        "starvation_missing": sorted(missing_sentinels),
        "successful_runs": successful_runs,
        "partial_disclosures": partial_disclosures,
        "peak_rss_bytes": _current_peak_rss_bytes(),
        "timings_ms": _timing_summary(samples),
    }


def run_suite(runs: int, warmups: int) -> dict[str, Any]:
    if runs < 1:
        raise ValueError("runs must be at least 1")
    if warmups < 0:
        raise ValueError("warmups must be non-negative")
    return {
        "modern_parse": benchmark_modern_parse(runs, warmups),
        "custom_regex": benchmark_custom_regex(runs, warmups),
        "lexical_candidates": benchmark_lexical_candidates(runs, warmups),
    }


_SCENARIO_NAMES = ("modern_parse", "custom_regex", "lexical_candidates")


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


def _timing_metric(result: dict[str, Any], metric: str) -> float:
    timings = result.get("timings_ms")
    if not isinstance(timings, dict):
        raise ValueError("timings_ms must be an object")
    return _finite_number(timings.get(metric), f"timings_ms.{metric}")


def _timing_samples(result: dict[str, Any], runs: int) -> list[float]:
    timings = result.get("timings_ms")
    if not isinstance(timings, dict):
        raise ValueError("timings_ms must be an object")
    raw_samples = timings.get("samples")
    if not isinstance(raw_samples, list):
        raise ValueError("timings_ms.samples must be an array")
    samples = [
        _finite_number(sample, f"timings_ms.samples[{index}]")
        for index, sample in enumerate(raw_samples)
    ]
    if len(samples) != runs:
        raise ValueError("timing sample count differs from measured runs")
    return samples


def _timing_interval(result: dict[str, Any], name: str) -> list[float]:
    timings = result.get("timings_ms")
    if not isinstance(timings, dict):
        raise ValueError("timings_ms must be an object")
    raw = timings.get(name)
    if not isinstance(raw, list) or len(raw) != 2:
        raise ValueError(f"timings_ms.{name} must contain exactly two values")
    return [_finite_number(value, f"timings_ms.{name}[{index}]") for index, value in enumerate(raw)]


def _detection_contract(scenarios: dict[str, Any]) -> dict[str, Any]:
    try:
        modern = scenarios["modern_parse"]
        custom = scenarios["custom_regex"]
        lexical = scenarios["lexical_candidates"]
        if not all(isinstance(value, dict) for value in (modern, custom, lexical)):
            raise TypeError
        return {
            "modern_parse": {
                "name": modern.get("name"),
                "source_bytes": modern.get("source_bytes"),
                "source_sha256": modern.get("source_sha256"),
                "language_hint": modern.get("language_hint"),
                "parser_variants": modern.get("parser_variants"),
            },
            "custom_regex": {
                "name": custom.get("name"),
                "source_bytes": custom.get("source_bytes"),
                "source_sha256": custom.get("source_sha256"),
                "configured_timeout_seconds": custom.get("configured_timeout_seconds"),
            },
            "lexical_candidates": {
                "name": lexical.get("name"),
                "source_bytes": lexical.get("source_bytes"),
                "source_sha256": lexical.get("source_sha256"),
                "input_double_candidates": lexical.get("input_double_candidates"),
                "expected_retained_candidates": lexical.get("expected_retained_candidates"),
                "expected_retained_by_quote": lexical.get("expected_retained_by_quote"),
            },
        }
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("scenario contract is unavailable") from exc


def _expected_detection_contract() -> dict[str, Any]:
    return {
        "modern_parse": {
            "name": "modern_parse",
            "source_bytes": MIB,
            "source_sha256": MODERN_SOURCE_SHA256,
            "language_hint": "typescript",
            "parser_variants": ["tree-sitter-typescript"],
        },
        "custom_regex": {
            "name": "custom_regex",
            "source_bytes": CUSTOM_REGEX_SOURCE_BYTES,
            "source_sha256": CUSTOM_REGEX_SOURCE_SHA256,
            "configured_timeout_seconds": CUSTOM_REGEX_TIMEOUT_SECONDS,
        },
        "lexical_candidates": {
            "name": "lexical_candidates",
            "source_bytes": len(build_lexical_fixture().encode("utf-8")),
            "source_sha256": LEXICAL_SOURCE_SHA256,
            "input_double_candidates": 10_001,
            "expected_retained_candidates": JSParser.MAX_STRINGS_EXTRACTED + 2,
            "expected_retained_by_quote": {
                "double": JSParser.MAX_STRINGS_EXTRACTED,
                "single": 1,
                "template": 1,
            },
        },
    }


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
    for distribution in DETECTION_DEPENDENCY_VERSIONS:
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
    if not isinstance(dependencies, dict) or set(dependencies) != set(DETECTION_DEPENDENCY_VERSIONS):
        raise ValueError("measurement_environment dependency fingerprint is malformed")
    if dependencies != DETECTION_DEPENDENCY_VERSIONS:
        raise ValueError("measurement_environment dependency fingerprint is incompatible")
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
    if baseline.get("benchmark") != "detection" or baseline.get("profile") != BASELINE_PROFILE:
        raise ValueError("benchmark profile is incompatible")
    _validate_environment(baseline.get("measurement_environment"))
    if _nonnegative_int(baseline.get("runs"), "baseline.runs") != RELEASE_RUNS:
        raise ValueError("measured run count is incompatible")
    if _nonnegative_int(baseline.get("warmups"), "baseline.warmups") != RELEASE_WARMUPS:
        raise ValueError("warm-up count is incompatible")
    scenarios = baseline.get("scenarios")
    if not isinstance(scenarios, dict) or set(scenarios) != set(_SCENARIO_NAMES):
        raise ValueError("scenarios object is unavailable or malformed")
    expected_contract = _expected_detection_contract()
    contract = _detection_contract(scenarios)
    if contract != expected_contract:
        raise ValueError("scenario fixture contract is incompatible")
    expected_contract_sha256 = _canonical_sha256(expected_contract)
    if baseline.get("scenario_contract_sha256") != expected_contract_sha256:
        raise ValueError("scenario contract digest is incompatible")
    if baseline.get("result_sha256") != _canonical_sha256(scenarios):
        raise ValueError("result digest differs from baseline scenarios")
    for name in _SCENARIO_NAMES:
        scenario = scenarios[name]
        if not isinstance(scenario, dict):
            raise ValueError(f"scenario {name!r} is malformed")
        if _nonnegative_int(scenario.get("runs"), f"baseline.{name}.runs") != RELEASE_RUNS:
            raise ValueError(f"scenario {name!r} measured run count is incompatible")
        if _nonnegative_int(scenario.get("warmups"), f"baseline.{name}.warmups") != RELEASE_WARMUPS:
            raise ValueError(f"scenario {name!r} warm-up count is incompatible")
        if _timing_metric(scenario, "p95") <= 0:
            raise ValueError(f"scenario {name!r} p95 must be positive")
        if _nonnegative_int(scenario.get("peak_rss_bytes"), f"baseline.{name}.peak_rss_bytes") <= 0:
            raise ValueError(f"scenario {name!r} peak RSS must be positive")
    integrity_failures = evaluate_gates(
        scenarios,
        expected_runs=RELEASE_RUNS,
        expected_warmups=RELEASE_WARMUPS,
    )
    if integrity_failures:
        raise ValueError(f"stored scenarios fail release integrity: {integrity_failures}")
    return baseline


def evaluate_gates(
    scenarios: Any,
    *,
    baseline: dict[str, Any] | None = None,
    cross_hardware_baseline: bool = False,
    expected_runs: int | None = None,
    expected_warmups: int | None = None,
) -> list[str]:
    if not isinstance(scenarios, dict):
        return ["suite: benchmark results are unavailable or malformed"]
    if cross_hardware_baseline and baseline is None:
        return ["suite: cross-hardware comparison requires a baseline"]
    failures: list[str] = []
    available: dict[str, dict[str, Any]] = {}
    observed_runs: set[int] = set()
    observed_warmups: set[int] = set()
    for name in _SCENARIO_NAMES:
        result = scenarios.get(name)
        if not isinstance(result, dict):
            failures.append(f"{name}: benchmark result is unavailable or malformed")
            continue
        available[name] = result
        if result.get("name") != name:
            failures.append(f"{name}: scenario identity is unavailable or malformed")
        try:
            runs = _nonnegative_int(result.get("runs"), f"{name}.runs")
            warmups = _nonnegative_int(result.get("warmups"), f"{name}.warmups")
            signature_variants = _nonnegative_int(
                result.get("signature_variants"),
                f"{name}.signature_variants",
            )
            peak_rss = _nonnegative_int(
                result.get("peak_rss_bytes"),
                f"{name}.peak_rss_bytes",
            )
        except ValueError:
            failures.append(f"{name}: benchmark result is unavailable or malformed")
            continue
        observed_runs.add(runs)
        observed_warmups.add(warmups)
        if expected_runs is not None and runs != expected_runs:
            failures.append(f"{name}: measured run count differs from the requested run count")
        if expected_warmups is not None and warmups != expected_warmups:
            failures.append(f"{name}: warm-up count differs from the requested warm-up count")
        if peak_rss <= 0:
            failures.append(f"{name}: peak RSS must be positive")
        if runs < RELEASE_RUNS:
            failures.append(f"{name}: release gate requires at least {RELEASE_RUNS} measured runs")
        if warmups < RELEASE_WARMUPS:
            failures.append(
                f"{name}: release gate requires at least {RELEASE_WARMUPS} warm-up runs"
            )
        if signature_variants != 1:
            failures.append(f"{name}: output signature changed across identical runs")
        try:
            samples = _timing_samples(result, runs)
            if not all(sample > 0 for sample in samples):
                raise ValueError("timing samples must be positive")
            reported_min = _timing_metric(result, "min")
            reported_p50 = _timing_metric(result, "p50")
            reported_p95 = _timing_metric(result, "p95")
            reported_max = _timing_metric(result, "max")
            reported_mean = _timing_metric(result, "mean")
            variation = _timing_metric(result, "coefficient_of_variation")
            reported_p50_ci = _timing_interval(result, "p50_bootstrap_95_ci")
            reported_p95_ci = _timing_interval(result, "p95_bootstrap_95_ci")
        except ValueError as exc:
            failures.append(f"{name}: {exc}")
        else:
            recalculated = _timing_summary(samples)
            if abs(float(recalculated["min"]) - reported_min) > 0.002:
                failures.append(f"{name}: reported min differs from timing samples")
            if abs(float(recalculated["p50"]) - reported_p50) > 0.002:
                failures.append(f"{name}: reported p50 differs from timing samples")
            if abs(float(recalculated["p95"]) - reported_p95) > 0.002:
                failures.append(f"{name}: reported p95 differs from timing samples")
            if abs(float(recalculated["max"]) - reported_max) > 0.002:
                failures.append(f"{name}: reported max differs from timing samples")
            if abs(float(recalculated["mean"]) - reported_mean) > 0.002:
                failures.append(f"{name}: reported mean differs from timing samples")
            if abs(float(recalculated["coefficient_of_variation"]) - variation) > 0.001:
                failures.append(
                    f"{name}: reported timing variation differs from timing samples"
                )
            for interval_name, reported in (
                ("p50_bootstrap_95_ci", reported_p50_ci),
                ("p95_bootstrap_95_ci", reported_p95_ci),
            ):
                expected_interval = recalculated[interval_name]
                if any(
                    abs(float(expected) - actual) > 0.002
                    for expected, actual in zip(expected_interval, reported, strict=True)
                ):
                    failures.append(
                        f"{name}: reported {interval_name} differs from timing samples"
                    )
            if variation > 0.25:
                failures.append(
                    f"{name}: invalid measurement; timing coefficient of variation exceeds 0.25"
                )

    if len(observed_runs) > 1:
        failures.append("suite: measured run counts differ across scenarios")
    if len(observed_warmups) > 1:
        failures.append("suite: warm-up counts differ across scenarios")

    modern = available.get("modern_parse")
    if modern is not None:
        try:
            if _nonnegative_int(modern.get("source_bytes"), "modern_parse.source_bytes") != MIB:
                failures.append("modern_parse: fixture is not exactly 1 MiB")
            if modern.get("language_hint") != "typescript":
                failures.append("modern_parse: fixture language hint is not TypeScript")
            if modern.get("source_sha256") != MODERN_SOURCE_SHA256:
                failures.append("modern_parse: fixture content digest drifted")
            if modern.get("parser_variants") != ["tree-sitter-typescript"]:
                failures.append(
                    "modern_parse: official TypeScript structural backend was not used exclusively"
                )
            if _nonnegative_int(modern.get("partial_runs"), "modern_parse.partial_runs") or (
                _nonnegative_int(modern.get("error_runs"), "modern_parse.error_runs")
            ):
                failures.append("modern_parse: one or more parses were partial or failed")
            if modern.get("endpoint_preserved") is not True:
                failures.append("modern_parse: known endpoint literal was not structurally preserved")
            if _timing_metric(modern, "p95") > MODERN_PARSE_P95_MS:
                failures.append("modern_parse: p95 exceeds 2,000 ms")
            if (
                _nonnegative_int(modern.get("peak_rss_bytes"), "modern_parse.peak_rss_bytes")
                > MODERN_PARSE_PEAK_RSS_BYTES
            ):
                failures.append("modern_parse: peak RSS exceeds 1 GiB")
        except ValueError:
            failures.append("modern_parse: benchmark result is unavailable or malformed")

    regex_result = available.get("custom_regex")
    if regex_result is not None:
        try:
            regex_runs = _nonnegative_int(regex_result.get("runs"), "custom_regex.runs")
            if (
                _finite_number(
                    regex_result.get("configured_timeout_seconds"),
                    "custom_regex.configured_timeout_seconds",
                )
                != CUSTOM_REGEX_TIMEOUT_SECONDS
            ):
                failures.append("custom_regex: configured timeout differs from production")
            if (
                _nonnegative_int(
                    regex_result.get("source_bytes"),
                    "custom_regex.source_bytes",
                )
                != CUSTOM_REGEX_SOURCE_BYTES
            ):
                failures.append("custom_regex: fixture source size drifted")
            if regex_result.get("source_sha256") != CUSTOM_REGEX_SOURCE_SHA256:
                failures.append("custom_regex: fixture content digest drifted")
            if (
                _nonnegative_int(
                    regex_result.get("timeout_disclosures"),
                    "custom_regex.timeout_disclosures",
                )
                != regex_runs
            ):
                failures.append(
                    "custom_regex: timeout/partial disclosure missing from one or more runs"
                )
            if (
                _nonnegative_int(
                    regex_result.get("prior_result_preserved_runs"),
                    "custom_regex.prior_result_preserved_runs",
                )
                != regex_runs
            ):
                failures.append("custom_regex: a result produced before timeout was lost")
            if _timing_metric(regex_result, "max") > CUSTOM_REGEX_WALL_MS:
                failures.append("custom_regex: wall time exceeded the bounded 750 ms allowance")
        except ValueError:
            failures.append("custom_regex: benchmark result is unavailable or malformed")

    lexical = available.get("lexical_candidates")
    if lexical is not None:
        try:
            lexical_runs = _nonnegative_int(lexical.get("runs"), "lexical_candidates.runs")
            if _nonnegative_int(
                lexical.get("input_double_candidates"),
                "lexical_candidates.input_double_candidates",
            ) != 10_001:
                failures.append(
                    "lexical_candidates: fixture candidate count drifted"
                )
            if _nonnegative_int(
                lexical.get("source_bytes"),
                "lexical_candidates.source_bytes",
            ) != len(build_lexical_fixture().encode("utf-8")):
                failures.append("lexical_candidates: fixture source size drifted")
            if lexical.get("source_sha256") != LEXICAL_SOURCE_SHA256:
                failures.append("lexical_candidates: fixture content digest drifted")
            expected_candidates = JSParser.MAX_STRINGS_EXTRACTED + 2
            expected_by_quote = {
                "double": JSParser.MAX_STRINGS_EXTRACTED,
                "single": 1,
                "template": 1,
            }
            if lexical.get("expected_retained_candidates") != expected_candidates:
                raise ValueError("lexical candidate expectation drifted")
            if lexical.get("retained_candidate_counts") != [expected_candidates]:
                failures.append(
                    "lexical_candidates: retained counts differ from fair per-quote caps"
                )
            if lexical.get("expected_retained_by_quote") != expected_by_quote:
                raise ValueError("lexical quote expectation drifted")
            if lexical.get("retained_by_quote_variants") != [expected_by_quote]:
                failures.append(
                    "lexical_candidates: retained quote counts differ from independent caps"
                )
            starvation_missing = lexical.get("starvation_missing")
            if not isinstance(starvation_missing, list):
                raise ValueError("lexical_candidates.starvation_missing must be a list")
            if starvation_missing:
                failures.append("lexical_candidates: quote/category starvation dropped a sentinel")
            if (
                _nonnegative_int(
                    lexical.get("successful_runs"),
                    "lexical_candidates.successful_runs",
                )
                != lexical_runs
            ):
                failures.append("lexical_candidates: lexical fallback failed in one or more runs")
            if (
                _nonnegative_int(
                    lexical.get("partial_disclosures"),
                    "lexical_candidates.partial_disclosures",
                )
                != lexical_runs
            ):
                failures.append(
                    "lexical_candidates: cap truncation was not disclosed in every run"
                )
            if _timing_metric(lexical, "p95") > LEXICAL_P95_MS:
                failures.append("lexical_candidates: p95 exceeds 2,000 ms")
            if (
                _nonnegative_int(
                    lexical.get("peak_rss_bytes"),
                    "lexical_candidates.peak_rss_bytes",
                )
                > LEXICAL_PEAK_RSS_BYTES
            ):
                failures.append("lexical_candidates: peak RSS exceeds 1 GiB")
        except ValueError:
            failures.append("lexical_candidates: benchmark result is unavailable or malformed")

    if baseline is not None:
        try:
            validated_baseline = validate_baseline_document(baseline)
            baseline_scenarios = validated_baseline["scenarios"]
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(f"baseline: {exc}")
        else:
            for name in _SCENARIO_NAMES:
                result = available.get(name)
                if result is None:
                    continue
                previous = baseline_scenarios[name]
                try:
                    current_p95 = _timing_metric(result, "p95")
                    previous_p95 = _timing_metric(previous, "p95")
                    current_rss = _nonnegative_int(
                        result.get("peak_rss_bytes"),
                        f"{name}.peak_rss_bytes",
                    )
                    previous_rss = _nonnegative_int(
                        previous.get("peak_rss_bytes"),
                        f"baseline.{name}.peak_rss_bytes",
                    )
                    if cross_hardware_baseline:
                        current_p95_lower = _timing_interval(
                            result,
                            "p95_bootstrap_95_ci",
                        )[0]
                        previous_p95_upper = _timing_interval(
                            previous,
                            "p95_bootstrap_95_ci",
                        )[1]
                except ValueError as exc:
                    failures.append(f"{name}: baseline comparison unavailable: {exc}")
                    continue
                if cross_hardware_baseline:
                    if current_p95_lower > previous_p95_upper * 1.20:
                        failures.append(
                            f"{name}: p95 bootstrap CI regressed more than 20% "
                            "from cross-hardware baseline"
                        )
                elif current_p95 > previous_p95 * 1.20:
                    failures.append(f"{name}: p95 regressed more than 20% from baseline")
                if current_rss > previous_rss * 1.25:
                    failures.append(f"{name}: peak RSS regressed more than 25% from baseline")
    return list(dict.fromkeys(failures))


def create_baseline_payload(
    scenarios: dict[str, Any],
    measurement_environment: dict[str, Any],
) -> dict[str, Any]:
    failures = evaluate_gates(
        scenarios,
        expected_runs=RELEASE_RUNS,
        expected_warmups=RELEASE_WARMUPS,
    )
    if failures:
        raise ValueError(f"detection result is not release-valid: {failures}")
    environment = _validate_environment(measurement_environment)
    frozen = copy.deepcopy(scenarios)
    contract = _expected_detection_contract()
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "benchmark": "detection",
        "profile": BASELINE_PROFILE,
        "measurement_environment": environment,
        "scenario_contract_sha256": _canonical_sha256(contract),
        "result_sha256": _canonical_sha256(frozen),
        "runs": RELEASE_RUNS,
        "warmups": RELEASE_WARMUPS,
        "scenarios": frozen,
    }
    return validate_baseline_document(payload)


def create_result_payload(
    scenarios: dict[str, Any],
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
    contract = _detection_contract(frozen)
    return {
        "schema_version": RAW_RESULT_SCHEMA_VERSION,
        "benchmark": "detection",
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
        raise ValueError("root object has an invalid detection result schema")
    if result.get("schema_version") != RAW_RESULT_SCHEMA_VERSION:
        raise ValueError("detection result schema_version is unsupported")
    if result.get("benchmark") != "detection" or result.get("profile") != BASELINE_PROFILE:
        raise ValueError("detection result benchmark profile is incompatible")
    environment = _validate_environment(result.get("measurement_environment"))
    if require_runtime_compatibility:
        validate_runtime_compatibility(environment)
    if _nonnegative_int(result.get("runs"), "result.runs") != RELEASE_RUNS:
        raise ValueError("detection result measured run count is incompatible")
    if _nonnegative_int(result.get("warmups"), "result.warmups") != RELEASE_WARMUPS:
        raise ValueError("detection result warm-up count is incompatible")
    if result.get("passed") is not True or result.get("gate_failures") != []:
        raise ValueError("detection source result is not a clean benchmark payload")
    if result.get("relative_baseline_comparison") != "not_requested":
        raise ValueError("detection baseline source must be measured without a prior baseline")
    scenarios = result.get("scenarios")
    if not isinstance(scenarios, dict):
        raise ValueError("detection result scenarios are malformed")
    contract = _detection_contract(scenarios)
    if contract != _expected_detection_contract():
        raise ValueError("detection result scenario fixture contract is incompatible")
    if result.get("scenario_contract_sha256") != _canonical_sha256(contract):
        raise ValueError("detection result scenario contract digest is incompatible")
    if result.get("result_sha256") != _canonical_sha256(scenarios):
        raise ValueError("detection result digest differs from scenarios")
    failures = evaluate_gates(
        scenarios,
        expected_runs=RELEASE_RUNS,
        expected_warmups=RELEASE_WARMUPS,
    )
    if failures:
        raise ValueError(f"detection result fails release integrity: {failures}")
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
    parser.add_argument("--runs", type=int, default=5, help="Measured runs per scenario")
    parser.add_argument("--warmups", type=int, default=1, help="Warm-up runs per scenario")
    parser.add_argument("--assert-gates", action="store_true", help="Enforce release thresholds")
    parser.add_argument("--baseline", type=Path, default=None, help="Required release baseline JSON")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON result path")
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.warmups < 0:
        parser.error("--warmups must be non-negative")
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
        scenarios = run_suite(args.runs, args.warmups)
        failures = (
            evaluate_gates(
                scenarios,
                baseline=baseline,
                cross_hardware_baseline=cross_hardware_baseline,
                expected_runs=args.runs,
                expected_warmups=args.warmups,
            )
            if args.assert_gates
            else []
        )
        payload = create_result_payload(
            scenarios,
            environment,
            runs=args.runs,
            warmups=args.warmups,
            gate_failures=failures,
            relative_baseline_comparison=comparison_state,
        )
        rendered = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
    except (
        KeyError,
        OSError,
        OverflowError,
        TypeError,
        ValueError,
        RuntimeError,
        json.JSONDecodeError,
    ) as exc:
        parser.exit(2, f"benchmark error: {exc}\n")
    print(rendered)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
