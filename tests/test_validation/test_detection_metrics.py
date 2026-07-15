"""Tests for strict corpus matching and release gates."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bundleInspector.correlator.graph import CorrelationGraph
from bundleInspector.parser.js_parser import ParseResult
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Edge,
    EdgeType,
    Evidence,
    Finding,
    Severity,
)
from bundleInspector.validation import metrics as metrics_module
from bundleInspector.validation.metrics import (
    CorpusError,
    build_regression_baseline,
    canonicalize_value,
    evaluate_regression_baseline,
    load_gates,
    load_manifest,
    load_regression_baseline,
    run_corpus,
    wilson_lower,
)
from scripts.build_detection_corpus import build_corpus

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_case(
    root: Path,
    *,
    case_id: str,
    source: str,
    labels: list[dict[str, object]],
    forbidden: list[dict[str, object]] | None = None,
    semantic_group: str = "",
) -> dict[str, object]:
    asset = root / f"{case_id}.js"
    asset.write_text(source, encoding="utf-8")
    return {
        "case_id": case_id,
        "asset": asset.name,
        "language": "javascript",
        "parser_expectation": "full_ast",
        "labels": labels,
        "forbidden": forbidden or [],
        "evaluated_categories": ["endpoint"],
        "negative_opportunities": {"endpoint": 1},
        "completeness": {"must_not_be_partial": True},
        "semantic_group": semantic_group,
    }


def _write_manifest(root: Path, cases: list[dict[str, object]]) -> Path:
    path = root / "manifest.jsonl"
    path.write_text("\n".join(json.dumps(case) for case in cases) + "\n", encoding="utf-8")
    return path


def _write_gates(
    root: Path,
    *,
    min_positives: int = 1,
    min_positive_cases: int = 0,
) -> Path:
    path = root / "gates.json"
    path.write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "name": "endpoint",
                        "key": "endpoint",
                        "precision": 0.2,
                        "recall": 0.2,
                        "min_positives": min_positives,
                        "min_positive_cases": min_positive_cases,
                        "min_negatives": 1,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_live_endpoint_corpus_passes_one_to_one_gate(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="endpoint",
        source='fetch("/api/users", {method: "DELETE"});',
        labels=[{"category": "endpoint", "value": "/api/users", "method": "DELETE"}],
    )
    _write_manifest(tmp_path, [case])
    gates = _write_gates(tmp_path)

    result = run_corpus(tmp_path, gates_path=gates)

    assert result.passed, result.to_dict()
    assert result.metrics["endpoint"].tp == 1
    assert result.metrics["endpoint"].fn == 0
    assert result.metrics["endpoint"].fp == 0


def test_unmatched_and_forbidden_prediction_is_a_false_positive(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="forbidden",
        source='fetch("/api/real"); fetch("/api/cache-key");',
        labels=[{"category": "endpoint", "value": "/api/real"}],
        forbidden=[{"category": "endpoint", "value": "/api/cache-key"}],
    )
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert not result.passed
    assert result.metrics["endpoint"].tp == 1
    assert result.metrics["endpoint"].fp >= 1
    assert result.forbidden_hits


def test_semantic_group_detects_prediction_drift(tmp_path: Path) -> None:
    first = _write_case(
        tmp_path,
        case_id="quote-a",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
        semantic_group="quote",
    )
    second = _write_case(
        tmp_path,
        case_id="quote-b",
        source="fetch('/api/b');",
        labels=[{"category": "endpoint", "value": "/api/b"}],
        semantic_group="quote",
    )
    _write_manifest(tmp_path, [first, second])

    result = run_corpus(tmp_path)

    assert not result.passed
    assert result.invariance_failures


def test_gate_fails_closed_on_insufficient_samples(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="small",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    _write_manifest(tmp_path, [case])
    gates = _write_gates(tmp_path, min_positives=50)

    result = run_corpus(tmp_path, gates_path=gates)

    assert not result.passed
    assert "positive samples 1 < 50" in result.gates[0].reasons


def test_gate_rejects_many_cloned_labels_from_one_case(tmp_path: Path) -> None:
    source = "\n".join(f'fetch("/api/{index}");' for index in range(50))
    labels = [
        {"category": "endpoint", "value": f"/api/{index}", "line": index + 1}
        for index in range(50)
    ]
    case = _write_case(
        tmp_path,
        case_id="cloned-samples",
        source=source,
        labels=labels,
    )
    _write_manifest(tmp_path, [case])
    gates = _write_gates(
        tmp_path,
        min_positives=50,
        min_positive_cases=2,
    )

    result = run_corpus(tmp_path, gates_path=gates)

    assert not result.passed
    assert "independent positive cases 1 < 2" in result.gates[0].reasons


def test_negative_opportunities_use_case_local_false_positive_delta(tmp_path: Path) -> None:
    first = _write_case(
        tmp_path,
        case_id="negative-a",
        source='fetch("/api/unexpected-a");',
        labels=[],
    )
    second = _write_case(
        tmp_path,
        case_id="negative-b",
        source='fetch("/api/unexpected-b");',
        labels=[],
    )
    _write_manifest(tmp_path, [first, second])

    result = run_corpus(tmp_path)

    assert result.metrics["endpoint"].fp == 2
    assert result.metrics["endpoint"].tn == 0


def test_request_contract_mismatch_is_attributed_per_field(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="method-mismatch",
        source='fetch("/api/a", {method: "POST"});',
        labels=[{"category": "endpoint", "value": "/api/a", "method": "DELETE"}],
    )
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert result.metrics["contract/method"].tp == 0
    assert result.metrics["contract/method"].fp == 1
    assert result.metrics["contract/method"].fn == 1


def test_location_accuracy_is_reported_separately(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="location-mismatch",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a", "line": 2}],
    )
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert result.metrics["location"].tp == 0
    assert result.metrics["location"].fp == 1
    assert result.metrics["location"].fn == 1


def test_contract_metrics_penalize_extra_fields_and_pair_repeated_calls(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="repeated-contracts",
        source=(
            'fetch("/api/a",{headers:{"X-Mode":"one","X-Extra":"wrong"}});\n'
            'fetch("/api/a",{headers:{"X-Mode":"two"}});'
        ),
        labels=[
            {
                "category": "endpoint",
                "value": "/api/a",
                "contract": {"headers": {"X-Mode": "two"}},
            },
            {
                "category": "endpoint",
                "value": "/api/a",
                "contract": {"headers": {"X-Mode": "one"}},
            },
        ],
    )
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert result.metrics["contract/headers"].tp == 1
    assert result.metrics["contract/headers"].fp == 1
    assert result.metrics["contract/headers"].fn == 1


def test_manifest_rejects_assets_outside_corpus(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.js"
    outside.write_text("var x = 1;", encoding="utf-8")
    _write_manifest(
        tmp_path,
        [
            {
                "case_id": "escape",
                "asset": "../outside.js",
                "labels": [{"category": "endpoint", "value": "/api/a"}],
            }
        ],
    )

    with pytest.raises(CorpusError, match="inside corpus root"):
        load_manifest(tmp_path)


def test_manifest_rejects_unknown_fields_and_duplicate_ground_truth(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="strict-schema",
        source='fetch("/api/a");',
        labels=[
            {"category": "endpoint", "value": "/api/a"},
            {"category": "endpoint", "value": "/api/a"},
        ],
    )
    case["typo_lables"] = []
    _write_manifest(tmp_path, [case])

    with pytest.raises(CorpusError, match="unknown fields"):
        load_manifest(tmp_path)

    case.pop("typo_lables")
    _write_manifest(tmp_path, [case])
    with pytest.raises(CorpusError, match="duplicate ground-truth"):
        load_manifest(tmp_path)


def test_manifest_rejects_overlapping_wildcard_ground_truth(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="overlapping-labels",
        source='fetch("/api/a");',
        labels=[
            {"category": "endpoint", "value": "/api/a", "line": 1},
            {
                "category": "endpoint",
                "subtype": "*",
                "value": "/api/a",
                "line": 2,
                "line_tolerance": 1,
            },
        ],
    )
    _write_manifest(tmp_path, [case])

    with pytest.raises(CorpusError, match="ambiguous overlapping"):
        load_manifest(tmp_path)


def test_evaluated_subtypes_cannot_hide_category_false_positives(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="subtype-fp",
        source='const routes=[{path:"/admin",component:Admin}];',
        labels=[],
    )
    case["evaluated_subtypes"] = {"endpoint": ["api_endpoint"]}
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert result.metrics["endpoint"].fp >= 1
    assert result.metrics["endpoint/client_route"].fp >= 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("language", "python", "unsupported language"),
        ("completeness", {"must_not_be_partial": "false"}, "must be a boolean"),
    ],
)
def test_manifest_rejects_ambiguous_schema_values(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="invalid-schema",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    case[field] = value
    _write_manifest(tmp_path, [case])

    with pytest.raises(CorpusError, match=message):
        load_manifest(tmp_path)


@pytest.mark.parametrize(
    ("graph", "message"),
    [
        (None, "graph must be an object"),
        ([], "graph must be an object"),
        ({"typo": True}, "unknown fields"),
        ({"must_not_truncate": "true"}, "must be a boolean"),
        ({"permutation_invariant": 1}, "must be a boolean"),
        ({"min_edges": -1}, "must be a non-negative integer"),
        ({"min_edges": 1.5}, "must be a non-negative integer"),
        ({"required_edge_types": "same_file"}, "must be an array"),
        ({"required_edge_types": [1]}, "entries must be non-empty strings"),
        ({"required_edge_types": ["unknown"]}, "unsupported edge types"),
        (
            {"required_edge_types": ["same_file", "same_file"]},
            "contains duplicate edge types",
        ),
        ({}, "must activate at least one gate"),
        ({"min_edges": 0}, "must activate at least one gate"),
    ],
)
def test_manifest_graph_contract_fails_closed(
    tmp_path: Path,
    graph: object,
    message: str,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="invalid-graph",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    case["graph"] = graph
    _write_manifest(tmp_path, [case])

    with pytest.raises(CorpusError, match=message):
        load_manifest(tmp_path)


def test_graph_contract_validates_real_edges_telemetry_and_json(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="graph-pass",
        source='fetch("/api/a"); fetch("/api/b");',
        labels=[
            {"category": "endpoint", "value": "/api/a"},
            {"category": "endpoint", "value": "/api/b"},
        ],
    )
    case["graph"] = {
        "must_not_truncate": True,
        "required_edge_types": ["same_file"],
        "min_edges": 1,
        "permutation_invariant": True,
    }
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert result.passed, result.to_dict()
    assert result.graph_failures == []
    assert result.to_dict()["graph_failures"] == []


def test_graph_contract_surfaces_forced_truncation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="graph-truncated",
        source='fetch("/api/a"); fetch("/api/b");',
        labels=[
            {"category": "endpoint", "value": "/api/a"},
            {"category": "endpoint", "value": "/api/b"},
        ],
    )
    case["graph"] = {"must_not_truncate": True}
    _write_manifest(tmp_path, [case])

    class TruncatingCorrelator:
        def correlate(self, _findings: list[Finding]) -> CorrelationGraph:
            graph = CorrelationGraph()
            graph.note_cap("forced_test_cap", truncated_candidates=3)
            return graph

    monkeypatch.setattr(metrics_module, "Correlator", TruncatingCorrelator)

    result = run_corpus(tmp_path)

    assert not result.passed
    assert any("cap_dropped=3" in failure for failure in result.graph_failures)


def test_graph_observation_excludes_platform_specific_same_file_paths() -> None:
    file_hash = "a" * 64

    def observe(file_url: str) -> dict[str, object]:
        findings = [
            Finding(
                id="endpoint",
                rule_id="endpoint-detector",
                category=Category.ENDPOINT,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="Endpoint",
                evidence=Evidence(
                    file_url=file_url,
                    file_hash=file_hash,
                    line=1,
                    column=1,
                ),
                extracted_value="/api/platform-independent",
                value_type="api_endpoint",
            ),
            Finding(
                id="sink",
                rule_id="sink-detector",
                category=Category.SINK,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="Sink",
                evidence=Evidence(
                    file_url=file_url,
                    file_hash=file_hash,
                    line=2,
                    column=1,
                ),
                extracted_value="innerHTML=",
                value_type="dom_html_sink",
            ),
        ]
        graph = CorrelationGraph()
        graph.add_edge(
            Edge(
                source_id="endpoint",
                target_id="sink",
                edge_type=EdgeType.SAME_FILE,
                confidence=Confidence.HIGH,
                reasoning=f"Both findings in same file: {file_url}",
                metadata={"file_url": file_url},
            ),
            pass_name="same_file_test",
        )
        return metrics_module._graph_observation(graph, findings)

    windows = observe("file:///C:/work/bundleInspector/tests/corpus/case.tsx")
    posix = observe("file:///home/runner/work/bundleInspector/tests/corpus/case.tsx")

    assert windows == posix


def test_graph_contract_detects_finding_order_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="graph-order-drift",
        source='fetch("/api/a"); fetch("/api/b");',
        labels=[
            {"category": "endpoint", "value": "/api/a"},
            {"category": "endpoint", "value": "/api/b"},
        ],
    )
    case["graph"] = {
        "required_edge_types": ["import"],
        "min_edges": 1,
        "permutation_invariant": True,
    }
    _write_manifest(tmp_path, [case])

    class OrderSensitiveCorrelator:
        def correlate(self, findings: list[Finding]) -> CorrelationGraph:
            graph = CorrelationGraph()
            graph.add_edge(
                Edge(
                    source_id=findings[0].id,
                    target_id=findings[1].id,
                    edge_type=EdgeType.IMPORT,
                    reasoning="input-order edge",
                )
            )
            return graph

    monkeypatch.setattr(metrics_module, "Correlator", OrderSensitiveCorrelator)

    result = run_corpus(tmp_path)

    assert not result.passed
    assert any("signature changed" in failure for failure in result.graph_failures)


def test_wilson_lower_bound_is_conservative() -> None:
    assert wilson_lower(50, 50) is not None
    assert 0.92 < (wilson_lower(50, 50) or 0) < 1.0
    assert wilson_lower(0, 0) is None


def test_f1_gate_enforces_conservative_wilson_bound(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="one-sample-f1",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    _write_manifest(tmp_path, [case])
    gates = tmp_path / "gates.json"
    gates.write_text(
        json.dumps({
            "gates": [{
                "name": "unsupported-perfect-f1",
                "key": "endpoint",
                "f1": 1.0,
                "min_positives": 1,
                "min_positive_cases": 1,
            }]
        }),
        encoding="utf-8",
    )

    result = run_corpus(tmp_path, gates_path=gates)

    assert not result.passed
    assert any("f1 conservative Wilson lower" in reason for reason in result.gates[0].reasons)


def test_gate_schema_rejects_disabled_wilson_and_unsampled_hard_zero(tmp_path: Path) -> None:
    gates = tmp_path / "gates.json"
    gates.write_text(
        json.dumps({
            "gates": [{
                "name": "disabled-wilson",
                "key": "endpoint",
                "precision": 1.0,
                "wilson_margin": 0.031,
            }]
        }),
        encoding="utf-8",
    )
    with pytest.raises(CorpusError, match="wilson_margin"):
        load_gates(gates)

    gates.write_text(
        json.dumps({
            "gates": [{
                "name": "inert-hard-zero",
                "key": "endpoint/never_observed",
                "hard_zero_fp": True,
            }]
        }),
        encoding="utf-8",
    )
    with pytest.raises(CorpusError, match="hard_zero_fp requires"):
        load_gates(gates)

    gates.write_text(
        json.dumps({
            "gates": [
                {"name": "endpoint-a", "key": "endpoint", "precision": 0.9},
                {"name": "endpoint-b", "key": "endpoint", "recall": 0.9},
            ]
        }),
        encoding="utf-8",
    )
    with pytest.raises(CorpusError, match="duplicate gate key"):
        load_gates(gates)


def test_wildcard_label_cannot_credit_subtype_or_evidence_state(tmp_path: Path) -> None:
    asset = tmp_path / "wildcard.js"
    asset.write_text("target.innerHTML=location.hash;", encoding="utf-8")
    case = {
        "case_id": "wildcard-state",
        "asset": asset.name,
        "language": "javascript",
        "parser_expectation": "full_ast",
        "labels": [{
            "category": "sink",
            "value": "URL/location -> innerhtml=",
            "line": 1,
        }],
        "forbidden": [],
        "evaluated_categories": ["sink"],
        "negative_opportunities": {},
        "completeness": {"must_not_be_partial": True},
    }
    _write_manifest(tmp_path, [case])

    result = run_corpus(tmp_path)

    assert result.metrics["sink"].tp == 1
    assert "sink/taint_flow@confirmed" not in result.metrics
    assert "sink/taint_flow" not in result.metrics


def test_independent_case_gate_uses_distinct_source_fingerprints(tmp_path: Path) -> None:
    first = _write_case(
        tmp_path,
        case_id="clone-a",
        source='fetch("/api/clone");',
        labels=[{"category": "endpoint", "value": "/api/clone"}],
    )
    second = dict(first)
    second["case_id"] = "clone-b"
    _write_manifest(tmp_path, [first, second])
    gates = _write_gates(tmp_path, min_positives=2, min_positive_cases=2)

    result = run_corpus(tmp_path, gates_path=gates)

    assert not result.passed
    assert "independent positive cases 1 < 2" in result.gates[0].reasons
    metric = result.metrics["endpoint"]
    assert len(metric.positive_case_ids) == 2
    assert len(metric.positive_case_fingerprints) == 1


def test_corpus_fingerprint_binds_normalized_asset_path(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="asset-path-identity",
        source='fetch("/api/path-bound");',
        labels=[{"category": "endpoint", "value": "/api/path-bound"}],
    )
    _write_manifest(tmp_path, [case])
    original_fingerprint = run_corpus(tmp_path).corpus_fingerprint

    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / str(case["asset"])).replace(nested / str(case["asset"]))
    case["asset"] = f"nested/{case['asset']}"
    _write_manifest(tmp_path, [case])

    assert run_corpus(tmp_path).corpus_fingerprint != original_fingerprint


@pytest.mark.parametrize(
    "manifest_text",
    [
        (
            '{"case_id":"duplicate-json","asset":"case.js",'
            '"labels":[{"category":"secret","category":"endpoint","value":"/api/a"}],'
            '"evaluated_categories":["endpoint"]}\n'
        ),
        (
            '{"case_id":"nan-json","asset":"case.js",'
            '"labels":[{"category":"endpoint","value":"/api/a",'
            '"metadata":{"score":NaN}}],"evaluated_categories":["endpoint"]}\n'
        ),
    ],
)
def test_manifest_rejects_duplicate_keys_and_non_finite_json(
    tmp_path: Path,
    manifest_text: str,
) -> None:
    (tmp_path / "case.js").write_text('fetch("/api/a");', encoding="utf-8")
    (tmp_path / "manifest.jsonl").write_text(manifest_text, encoding="utf-8")

    with pytest.raises(CorpusError, match="invalid JSON"):
        load_manifest(tmp_path)


def test_manifest_rejects_duplicate_normalized_scope_and_orphan_assets(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="duplicate-scope",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    case["evaluated_categories"] = ["endpoint", " Endpoint "]
    _write_manifest(tmp_path, [case])
    with pytest.raises(CorpusError, match="duplicate categories"):
        load_manifest(tmp_path)

    case["evaluated_categories"] = ["endpoint"]
    _write_manifest(tmp_path, [case])
    (tmp_path / "unlabeled.ts").write_text("const ignored: string = 'x';", encoding="utf-8")
    with pytest.raises(CorpusError, match="unreferenced analyzable"):
        load_manifest(tmp_path)


def test_contract_schema_scores_contract_only_method_and_rejects_ignored_keys(
    tmp_path: Path,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="contract-method",
        source='fetch("/api/a", {method:"POST"});',
        labels=[{
            "category": "endpoint",
            "value": "/api/a",
            "contract": {"method": "post"},
        }],
    )
    _write_manifest(tmp_path, [case])
    result = run_corpus(tmp_path)
    assert result.metrics["contract/method"].tp == 1

    labels = case["labels"]
    assert isinstance(labels, list)
    label = labels[0]
    assert isinstance(label, dict)
    label["contract"] = {"auth": {"scheme": "bearer", "token": "ignored"}}
    _write_manifest(tmp_path, [case])
    with pytest.raises(CorpusError, match="unknown fields"):
        load_manifest(tmp_path)

    label["contract"] = {"headers": {"X-Mode": "one", "x-mode": "two"}}
    _write_manifest(tmp_path, [case])
    with pytest.raises(CorpusError, match="duplicate case-insensitive"):
        load_manifest(tmp_path)


def test_endpoint_canonicalizer_handles_ipv6_default_ports_and_malformed_ports() -> None:
    assert (
        canonicalize_value("endpoint", "HTTPS://[2001:DB8::1]:443/api")
        == "https://[2001:db8::1]/api"
    )
    malformed = "http://example.test:not-a-port/api"
    assert canonicalize_value("endpoint", malformed) == malformed


def test_semantic_invariance_includes_request_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _write_case(
        tmp_path,
        case_id="contract-a",
        source='fetch("/api/invariant");',
        labels=[{"category": "endpoint", "value": "/api/invariant"}],
        semantic_group="contract-invariance",
    )
    second = _write_case(
        tmp_path,
        case_id="contract-b",
        source="fetch('/api/invariant');",
        labels=[{"category": "endpoint", "value": "/api/invariant"}],
        semantic_group="contract-invariance",
    )
    _write_manifest(tmp_path, [first, second])

    def analyze(case: metrics_module.CorpusCase) -> tuple[
        list[metrics_module.Prediction],
        bool,
        list[str],
        list[dict[str, object]],
        str,
        list[str],
        dict[str, object] | None,
    ]:
        header = "one" if case.case_id.endswith("a") else "two"
        prediction = metrics_module.Prediction(
            category="endpoint",
            subtype="api_endpoint",
            value="/api/invariant",
            method="GET",
            line=1,
            contract={"method": "GET", "headers": {"X-Mode": header}},
            metadata={},
            finding_id=case.case_id,
        )
        return [prediction], False, [], [], "tree-sitter-javascript", [], None

    monkeypatch.setattr(metrics_module, "_analyze_case", analyze)

    result = run_corpus(tmp_path)

    assert not result.passed
    assert any("contract-invariance" in failure for failure in result.invariance_failures)


def test_graph_gate_rejects_globally_and_per_pass_inconsistent_telemetry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="graph-telemetry-algebra",
        source='fetch("/api/a"); fetch("/api/b");',
        labels=[
            {"category": "endpoint", "value": "/api/a"},
            {"category": "endpoint", "value": "/api/b"},
        ],
    )
    case["graph"] = {"must_not_truncate": True, "min_edges": 1}
    _write_manifest(tmp_path, [case])

    class InconsistentTelemetryCorrelator:
        def correlate(self, findings: list[Finding]) -> CorrelationGraph:
            graph = CorrelationGraph()
            graph.edges.append(
                Edge(
                    source_id=findings[0].id,
                    target_id=findings[1].id,
                    edge_type=EdgeType.IMPORT,
                    reasoning="bypassed telemetry",
                )
            )
            graph.telemetry["emitted"] = 1
            return graph

    monkeypatch.setattr(metrics_module, "Correlator", InconsistentTelemetryCorrelator)

    result = run_corpus(tmp_path)

    assert not result.passed
    assert any("telemetry integrity failed" in failure for failure in result.graph_failures)
    assert any("candidate_attempts" in failure for failure in result.graph_failures)


def test_graph_gate_checks_rotation_not_only_reverse_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = ["/api/a", "/api/b", "/api/c"]
    case = _write_case(
        tmp_path,
        case_id="graph-rotation-drift",
        source=" ".join(f'fetch("{value}");' for value in values),
        labels=[{"category": "endpoint", "value": value} for value in values],
    )
    case["graph"] = {
        "required_edge_types": ["import"],
        "min_edges": 1,
        "permutation_invariant": True,
    }
    _write_manifest(tmp_path, [case])

    class MiddleSensitiveCorrelator:
        def correlate(self, findings: list[Finding]) -> CorrelationGraph:
            graph = CorrelationGraph()
            source = findings[len(findings) // 2]
            target = min(findings, key=lambda finding: finding.extracted_value)
            graph.add_edge(
                Edge(
                    source_id=source.id,
                    target_id=target.id,
                    edge_type=EdgeType.IMPORT,
                    reasoning="middle-sensitive edge",
                )
            )
            return graph

    monkeypatch.setattr(metrics_module, "Correlator", MiddleSensitiveCorrelator)

    result = run_corpus(tmp_path)

    assert not result.passed
    assert any("rotated" in failure for failure in result.graph_failures)


def test_case_language_selects_explicit_structural_grammar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="tsx-language",
        source='const view = <Panel url="/api/tsx" />; fetch("/api/tsx");',
        labels=[{"category": "endpoint", "value": "/api/tsx"}],
    )
    case["language"] = "tsx"
    _write_manifest(tmp_path, [case])
    seen_hints: list[str | None] = []
    real_parse_js = metrics_module.parse_js

    def recording_parse_js(source: str, **kwargs: object) -> ParseResult:
        hint = kwargs.get("language_hint")
        seen_hints.append(hint if isinstance(hint, str) else None)
        return real_parse_js(source, **kwargs)

    monkeypatch.setattr(metrics_module, "parse_js", recording_parse_js)

    result = run_corpus(tmp_path)

    assert result.passed, result.to_dict()
    assert seen_hints == ["tsx"]


def test_detector_incomplete_event_fails_must_not_be_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _write_case(
        tmp_path,
        case_id="detector-partial",
        source="const harmless = true;",
        labels=[],
    )
    _write_manifest(tmp_path, [case])

    class PartialRuleEngine:
        def __init__(self, _config: object) -> None:
            pass

        def register_defaults(self) -> None:
            pass

        def analyze(self, _ir: object, context: AnalysisContext) -> list[Finding]:
            context.metadata["analysis_incomplete"] = [
                {
                    "component": "rule_engine",
                    "reason": "rule_execution_error",
                    "partial_results": True,
                }
            ]
            return []

    monkeypatch.setattr(metrics_module, "RuleEngine", PartialRuleEngine)

    result = run_corpus(tmp_path)

    assert not result.passed
    assert len(result.completeness_failures) == 1
    assert "rule_execution_error" in result.completeness_failures[0]


def test_committed_release_corpus_passes_all_gates() -> None:
    corpus = REPO_ROOT / "tests" / "corpus"

    result = run_corpus(corpus, gates_path=corpus / "gates.json")

    assert result.case_count >= 45
    assert result.label_count >= 1900
    assert result.passed, result.to_dict()
    assert all(gate.passed for gate in result.gates)
    gate_keys = {gate.key for gate in result.gates}
    assert gate_keys == metrics_module.RELEASE_GATE_KEYS
    cases = load_manifest(corpus)
    assert any(case.graph is not None for case in cases)


def test_corpus_generation_is_byte_reproducible(tmp_path: Path) -> None:
    build_corpus(tmp_path)
    first = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }

    build_corpus(tmp_path)
    second = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }

    assert first == second


def test_corpus_builder_removes_stale_analyzable_assets(tmp_path: Path) -> None:
    stale = tmp_path / "manual" / "stale.ts"
    stale.parent.mkdir(parents=True)
    stale.write_text("const stale: boolean = true;", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_bytes(b"reviewed baseline sentinel\n")

    build_corpus(tmp_path)

    assert not stale.exists()
    assert baseline.read_bytes() == b"reviewed baseline sentinel\n"
    cases = load_manifest(tmp_path)
    assert len(cases) >= 45


def test_committed_family_gates_require_validation_matrix_negative_minimum() -> None:
    gates = load_gates(REPO_ROOT / "tests" / "corpus" / "gates.json")
    family_keys = {
        "domain",
        "flag",
        "debug",
        "upload",
        "endpoint/webpack_named_chunk",
    }

    minima = {gate.key: gate.min_negatives for gate in gates if gate.key in family_keys}

    assert minima == dict.fromkeys(family_keys, 500)


def test_metric_cli_stdout_is_one_machine_readable_json_document() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_detection_metrics.py",
            "--corpus",
            "tests/corpus",
            "--fail-on-regression",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    payload = json.loads(result.stdout)
    assert isinstance(payload["passed"], bool)
    assert payload["regression_failures"] == []
    assert payload["case_count"] >= 1


def test_metric_cli_fails_closed_when_default_gate_file_is_missing(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="missing-release-gates",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    _write_manifest(tmp_path, [case])

    result = subprocess.run(
        [sys.executable, "scripts/run_detection_metrics.py", "--corpus", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid gate file" in result.stderr


def test_metric_cli_requires_complete_release_gate_profile_by_default(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        case_id="partial-release-gates",
        source='fetch("/api/a");',
        labels=[{"category": "endpoint", "value": "/api/a"}],
    )
    _write_manifest(tmp_path, [case])
    _write_gates(tmp_path)

    strict = subprocess.run(
        [sys.executable, "scripts/run_detection_metrics.py", "--corpus", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    custom = subprocess.run(
        [
            sys.executable,
            "scripts/run_detection_metrics.py",
            "--corpus",
            str(tmp_path),
            "--allow-custom-gates",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert strict.returncode == 2
    assert "missing required keys" in strict.stderr
    assert custom.returncode == 0
    assert json.loads(custom.stdout)["passed"] is True


def test_metric_cli_rejects_extended_release_gate_profile(tmp_path: Path) -> None:
    corpus = REPO_ROOT / "tests" / "corpus"
    payload = json.loads((corpus / "gates.json").read_text(encoding="utf-8"))
    payload["gates"].append({
        "name": "unreviewed extra subtype",
        "key": "endpoint/unreviewed_extra",
        "precision": 0.9,
        "min_positives": 1,
    })
    gates = tmp_path / "extended-gates.json"
    gates.write_text(json.dumps(payload), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_detection_metrics.py",
            "--corpus",
            "tests/corpus",
            "--gates",
            str(gates),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "unexpected keys" in result.stderr


def test_regression_baseline_schema_rejects_nan_and_missing_keys(tmp_path: Path) -> None:
    committed = json.loads(
        (REPO_ROOT / "tests" / "corpus" / "baseline.json").read_text(encoding="utf-8")
    )

    missing_metric = copy.deepcopy(committed)
    missing_metric["metrics"].pop("endpoint")
    missing_metric_path = tmp_path / "missing-metric.json"
    missing_metric_path.write_text(json.dumps(missing_metric), encoding="utf-8")
    with pytest.raises(CorpusError, match="exact release metric keys"):
        load_regression_baseline(missing_metric_path)

    missing_identity = copy.deepcopy(committed)
    missing_identity.pop("corpus_fingerprint")
    missing_identity_path = tmp_path / "missing-identity.json"
    missing_identity_path.write_text(json.dumps(missing_identity), encoding="utf-8")
    with pytest.raises(CorpusError, match="missing fields"):
        load_regression_baseline(missing_identity_path)

    boolean_schema_version = copy.deepcopy(committed)
    boolean_schema_version["schema_version"] = True
    boolean_schema_path = tmp_path / "boolean-schema-version.json"
    boolean_schema_path.write_text(json.dumps(boolean_schema_version), encoding="utf-8")
    with pytest.raises(CorpusError, match="schema_version must equal"):
        load_regression_baseline(boolean_schema_path)

    float_canonicalizer_version = copy.deepcopy(committed)
    float_canonicalizer_version["canonicalizer_version"] = 2.0
    float_canonicalizer_path = tmp_path / "float-canonicalizer-version.json"
    float_canonicalizer_path.write_text(
        json.dumps(float_canonicalizer_version),
        encoding="utf-8",
    )
    with pytest.raises(CorpusError, match="canonicalizer_version must equal"):
        load_regression_baseline(float_canonicalizer_path)

    non_finite = copy.deepcopy(committed)
    non_finite["metrics"]["endpoint"]["precision"] = float("nan")
    non_finite_path = tmp_path / "non-finite.json"
    non_finite_path.write_text(json.dumps(non_finite), encoding="utf-8")
    with pytest.raises(CorpusError, match="non-finite"):
        load_regression_baseline(non_finite_path)

    oversized_count = copy.deepcopy(committed)
    oversized_count["metrics"]["endpoint"]["tp"] = 10**400
    oversized_count_path = tmp_path / "oversized-count.json"
    oversized_count_path.write_text(json.dumps(oversized_count), encoding="utf-8")
    with pytest.raises(CorpusError, match="non-negative integer no greater than"):
        load_regression_baseline(oversized_count_path)

    inconsistent_ratio = copy.deepcopy(committed)
    inconsistent_ratio["metrics"]["endpoint"]["precision"] = 0.99
    inconsistent_ratio_path = tmp_path / "inconsistent-ratio.json"
    inconsistent_ratio_path.write_text(json.dumps(inconsistent_ratio), encoding="utf-8")
    with pytest.raises(CorpusError, match="inconsistent with metric counts"):
        load_regression_baseline(inconsistent_ratio_path)

    nonzero_invariant = copy.deepcopy(committed)
    nonzero_invariant["invariants"]["graph_failure_count"] = 1
    nonzero_invariant_path = tmp_path / "nonzero-invariant.json"
    nonzero_invariant_path.write_text(json.dumps(nonzero_invariant), encoding="utf-8")
    with pytest.raises(CorpusError, match="must be zero"):
        load_regression_baseline(nonzero_invariant_path)

    excessive_positive_cases = copy.deepcopy(committed)
    metric = excessive_positive_cases["metrics"]["secret/aws_access_key"]
    metric["tp"] = 0
    metric["fn"] = 0
    metric["positive_case_count"] = 1
    excessive_positive_path = tmp_path / "excessive-positive-cases.json"
    excessive_positive_path.write_text(json.dumps(excessive_positive_cases), encoding="utf-8")
    with pytest.raises(CorpusError, match="positive_case_count exceeds positive samples"):
        load_regression_baseline(excessive_positive_path)

    excessive_negative_cases = copy.deepcopy(committed)
    metric = next(
        candidate
        for candidate in excessive_negative_cases["metrics"].values()
        if candidate["fp"] + candidate["tn"] < excessive_negative_cases["case_count"]
    )
    metric["negative_case_count"] = metric["fp"] + metric["tn"] + 1
    excessive_negative_path = tmp_path / "excessive-negative-cases.json"
    excessive_negative_path.write_text(json.dumps(excessive_negative_cases), encoding="utf-8")
    with pytest.raises(CorpusError, match="negative_case_count exceeds negative samples"):
        load_regression_baseline(excessive_negative_path)


def test_regression_baseline_ratchets_metrics_graph_and_invariants() -> None:
    corpus = REPO_ROOT / "tests" / "corpus"
    result = run_corpus(
        corpus,
        gates_path=corpus / "gates.json",
        required_gate_keys=metrics_module.RELEASE_GATE_KEYS,
    )
    baseline = load_regression_baseline(corpus / "baseline.json")

    assert build_regression_baseline(result) == baseline
    assert evaluate_regression_baseline(result, baseline) == []

    result.prediction_count += 1
    prediction_failures = evaluate_regression_baseline(result, baseline)
    assert any("identity.prediction_count changed" in failure for failure in prediction_failures)
    result.prediction_count -= 1

    result.metrics["endpoint"].fp += 1
    result.graph_failures.append("forced graph regression")
    graph_case = next(iter(result.graph_observations))
    result.graph_observations[graph_case] = {
        **result.graph_observations[graph_case],
        "semantic_sha256": "0" * 64,
    }

    failures = evaluate_regression_baseline(result, baseline)

    assert any("metric endpoint.fp regressed" in failure for failure in failures)
    assert any("graph_failure_count regressed" in failure for failure in failures)
    assert "graph observations differ from the committed semantic baseline" in failures


def test_regression_baseline_rejects_malformed_current_metric_values() -> None:
    corpus = REPO_ROOT / "tests" / "corpus"
    result = run_corpus(
        corpus,
        gates_path=corpus / "gates.json",
        required_gate_keys=metrics_module.RELEASE_GATE_KEYS,
    )
    baseline = load_regression_baseline(corpus / "baseline.json")
    endpoint = result.metrics["endpoint"]

    for field_name, invalid_value in (
        ("tp", float("nan")),
        ("fp", -1),
        ("fn", "not-an-integer"),
    ):
        original_value = getattr(endpoint, field_name)
        setattr(endpoint, field_name, invalid_value)
        failures = evaluate_regression_baseline(result, baseline)
        assert any(
            f"metric endpoint.{field_name} has invalid current count" in failure
            for failure in failures
        )
        setattr(endpoint, field_name, original_value)

    class NonFinitePrecisionMetric(metrics_module.DetectionMetric):
        @property
        def precision(self) -> float | None:
            return float("nan")

    result.metrics["endpoint"] = NonFinitePrecisionMetric(
        key=endpoint.key,
        tp=endpoint.tp,
        fp=endpoint.fp,
        fn=endpoint.fn,
        tn=endpoint.tn,
        positive_case_ids=set(endpoint.positive_case_ids),
        negative_case_ids=set(endpoint.negative_case_ids),
        positive_case_fingerprints=set(endpoint.positive_case_fingerprints),
        negative_case_fingerprints=set(endpoint.negative_case_fingerprints),
    )
    failures = evaluate_regression_baseline(result, baseline)
    assert any(
        "metric endpoint.precision has invalid current ratio" in failure
        for failure in failures
    )


def test_regression_baseline_rejects_corpus_and_weakened_gate_identity(tmp_path: Path) -> None:
    corpus = REPO_ROOT / "tests" / "corpus"
    baseline = load_regression_baseline(corpus / "baseline.json")
    gates = json.loads((corpus / "gates.json").read_text(encoding="utf-8"))
    endpoint_gate = next(gate for gate in gates["gates"] if gate["key"] == "endpoint")
    endpoint_gate["precision"] = 0.5
    weakened_gates = tmp_path / "gates.json"
    weakened_gates.write_text(json.dumps(gates), encoding="utf-8")

    result = run_corpus(
        corpus,
        gates_path=weakened_gates,
        required_gate_keys=metrics_module.RELEASE_GATE_KEYS,
    )
    assert result.passed
    failures = evaluate_regression_baseline(result, baseline)
    assert any("gate_profile_fingerprint changed" in failure for failure in failures)

    result.corpus_fingerprint = "0" * 64
    failures = evaluate_regression_baseline(result, baseline)
    assert any("corpus_fingerprint changed" in failure for failure in failures)


def test_metric_cli_baseline_flags_fail_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    missing_result = subprocess.run(
        [
            sys.executable,
            "scripts/run_detection_metrics.py",
            "--corpus",
            "tests/corpus",
            "--fail-on-regression",
            "--baseline",
            str(missing),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    baseline_without_flag = subprocess.run(
        [
            sys.executable,
            "scripts/run_detection_metrics.py",
            "--corpus",
            "tests/corpus",
            "--baseline",
            "tests/corpus/baseline.json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert missing_result.returncode == 2
    assert "invalid regression baseline" in missing_result.stderr
    assert baseline_without_flag.returncode == 2
    assert "--baseline requires --fail-on-regression" in baseline_without_flag.stderr


def test_baseline_update_is_explicit_and_byte_reproducible(tmp_path: Path) -> None:
    without_output = subprocess.run(
        [sys.executable, "scripts/update_detection_baseline.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    generated = tmp_path / "baseline.json"
    with_output = subprocess.run(
        [
            sys.executable,
            "scripts/update_detection_baseline.py",
            "--corpus",
            "tests/corpus",
            "--output",
            str(generated),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert without_output.returncode == 2
    assert "--output" in without_output.stderr
    assert with_output.returncode == 0, with_output.stderr
    assert generated.read_bytes() == (
        REPO_ROOT / "tests" / "corpus" / "baseline.json"
    ).read_bytes()
