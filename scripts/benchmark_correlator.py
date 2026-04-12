"""Synthetic correlator benchmark for larger inter-module/runtime graphs."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from bundleInspector.correlator.graph import Correlator  # noqa: E402
from bundleInspector.storage.models import Category, Confidence, Evidence, Finding, Severity  # noqa: E402


def _make_finding(
    finding_id: str,
    file_url: str,
    category: Category,
    extracted_value: str,
    metadata: dict | None = None,
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
    findings: list[Finding] = []
    for index in range(modules):
        file_url = f"file:///bench/module{index}.js"
        exports = [f"fn{index}"]
        import_bindings = []
        scoped_calls = {"function:boot": []}
        imports = []
        dynamic_imports = []

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

        metadata = {
            "enclosing_scope": "function:boot",
            "imports": imports,
            "dynamic_imports": dynamic_imports,
            "import_bindings": import_bindings,
            "exports": exports,
            "export_scopes": {
                f"fn{index}": [f"function:fn{index}"],
            },
            "call_graph": {
                "function:boot": [f"function:fn{index}"],
            },
            "scoped_calls": scoped_calls,
        }
        if index % max(1, modules // max(1, load_contexts)) == 0:
            metadata["load_context"] = f"/route/{index % max(1, load_contexts)}"

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
                # Keep this secret-like for benchmark shape, but avoid a real
                # provider prefix so public repos don't trigger avoidable secret
                # scanning noise.
                f"benchmark_secret_{index:04d}_abcdefghijklmnopqrstuvwxyz123456",
                metadata={
                    "enclosing_scope": f"function:fn{index}",
                    "exports": exports,
                    "export_scopes": {
                        f"fn{index}": [f"function:fn{index}"],
                    },
                    "call_graph": {
                        f"function:fn{index}": [],
                    },
                },
            )
        )

    return findings


def run_benchmark(modules: int, fanout: int, load_contexts: int, rounds: int) -> dict[str, object]:
    findings = build_synthetic_findings(modules, fanout, load_contexts)
    timings_ms: list[float] = []
    edges = 0
    clusters = 0

    for _ in range(rounds):
        start = time.perf_counter()
        graph = Correlator().correlate(findings)
        elapsed_ms = (time.perf_counter() - start) * 1000
        timings_ms.append(elapsed_ms)
        edges = len(graph.edges)
        clusters = len(graph.clusters)

    return {
        "modules": modules,
        "findings": len(findings),
        "fanout": fanout,
        "load_contexts": load_contexts,
        "rounds": rounds,
        "edges": edges,
        "clusters": clusters,
        "timings_ms": {
            "min": round(min(timings_ms), 3),
            "median": round(statistics.median(timings_ms), 3),
            "max": round(max(timings_ms), 3),
            "mean": round(statistics.fmean(timings_ms), 3),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", type=int, default=80, help="Number of synthetic modules")
    parser.add_argument("--fanout", type=int, default=3, help="Import fanout per module")
    parser.add_argument("--load-contexts", type=int, default=4, help="Number of synthetic load contexts")
    parser.add_argument("--rounds", type=int, default=5, help="Benchmark rounds")
    args = parser.parse_args()

    result = run_benchmark(
        modules=args.modules,
        fanout=args.fanout,
        load_contexts=args.load_contexts,
        rounds=args.rounds,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

