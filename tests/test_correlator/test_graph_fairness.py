"""Adversarial cap-fairness and clustering invariants for correlation."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from bundleInspector.correlator.cluster import ClusterBuilder, canonicalize_origin
from bundleInspector.correlator.edges import create_runtime_edge
from bundleInspector.correlator.graph import CorrelationGraph, Correlator
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Edge,
    EdgeType,
    Evidence,
    Finding,
    Severity,
)


def _finding(
    finding_id: str,
    file_url: str,
    category: Category = Category.FLAG,
    value: str = "value",
    *,
    line: int = 10,
    value_type: str = "test",
    metadata: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        rule_id=f"rule-{finding_id}",
        category=category,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title=finding_id,
        evidence=Evidence(
            file_url=file_url,
            file_hash=f"hash-{finding_id}",
            line=line,
            column=0,
            snippet="",
            snippet_lines=(line, line),
            ast_node_type="Literal",
        ),
        extracted_value=value,
        value_type=value_type,
        metadata=metadata or {},
    )


def _edge_candidates(prefix: str, count: int) -> Iterable[Edge]:
    for index in range(count):
        yield create_runtime_edge(prefix, f"{prefix}-{index:02d}", prefix)


@pytest.mark.parametrize(
    ("candidate_count", "expected_capped", "expected_unknown"),
    [(49, False, 0), (50, False, 0), (51, True, 1)],
)
def test_lazy_fair_scheduler_n_minus_one_n_n_plus_one_boundaries(
    candidate_count: int,
    expected_capped: bool,
    expected_unknown: int,
) -> None:
    graph = CorrelationGraph()

    Correlator()._emit_fair_edges(graph, [("only", _edge_candidates("only", candidate_count))])

    assert len(graph.edges) == min(candidate_count, 50)
    assert graph.telemetry["candidate_attempts"] == min(candidate_count, 50)
    assert bool(graph.telemetry["capped_passes"]) is expected_capped
    assert graph.telemetry["truncated_candidates_unknown"] == expected_unknown
    assert graph.telemetry["truncated_candidates_lower_bound"] == expected_unknown


def test_lazy_scheduler_is_round_robin_and_partition_order_invariant() -> None:
    def run(reverse: bool) -> list[tuple[str, str]]:
        partitions = [
            ("a", _edge_candidates("a", 50)),
            ("z", _edge_candidates("z", 1)),
        ]
        if reverse:
            partitions.reverse()
        graph = CorrelationGraph()
        Correlator()._emit_fair_edges(graph, partitions, limit=4)
        return [(edge.source_id, edge.target_id) for edge in graph.edges]

    assert run(False) == run(True) == [
        ("a", "a-00"),
        ("z", "z-00"),
        ("a", "a-01"),
        ("a", "a-02"),
    ]


def test_compound_partition_keys_are_collision_free() -> None:
    correlator = Correlator()

    assert correlator._compound_partition_key("a", "bc") != correlator._compound_partition_key(
        "ab", "c"
    )


def test_runtime_context_cap_does_not_starve_late_context_under_permutations() -> None:
    early = [
        _finding(
            f"early-{index:02d}",
            f"file:///early-{index:02d}.js",
            metadata={"load_context": "/a"},
        )
        for index in range(12)
    ]
    late = [
        _finding("late-1", "file:///late-1.js", metadata={"load_context": "/z"}),
        _finding("late-2", "file:///late-2.js", metadata={"load_context": "/z"}),
    ]

    for findings in (early + late, list(reversed(early + late))):
        graph = Correlator().correlate(findings)
        runtime_edges = [
            edge
            for edge in graph.edges
            if edge.edge_type == EdgeType.RUNTIME
            and edge.metadata.get("context") in {"load_context:/a", "load_context:/z"}
        ]
        assert len(runtime_edges) == 50
        assert any(
            edge.metadata.get("context") == "load_context:/z"
            and {edge.source_id, edge.target_id} == {"late-1", "late-2"}
            for edge in runtime_edges
        )


@pytest.mark.parametrize(
    ("metadata_key", "late_import_source"),
    [("imports", "./late"), ("dynamic_imports", "dynamic:./late")],
)
def test_import_cap_is_global_and_fair_to_late_source_partition(
    metadata_key: str,
    late_import_source: str,
) -> None:
    findings = [
        _finding("early-source", "file:///a.js", metadata={metadata_key: ["./bulk"]}),
        *[
            _finding(f"bulk-{index:02d}", "file:///bulk.js")
            for index in range(60)
        ],
        _finding("late-source", "file:///z.js", metadata={metadata_key: ["./late"]}),
        _finding("late-target", "file:///late.js"),
    ]

    graph = Correlator().correlate(list(reversed(findings)))
    matching_pass = [
        edge
        for edge in graph.edges
        if edge.edge_type == EdgeType.IMPORT
        and str(edge.metadata.get("import_source", "")).startswith(
            "dynamic:" if metadata_key == "dynamic_imports" else "./"
        )
    ]

    assert len(matching_pass) <= 50
    assert any(
        edge.source_id == "late-source"
        and edge.target_id == "late-target"
        and edge.metadata.get("import_source") == late_import_source
        for edge in matching_pass
    )


def test_initiator_root_cap_does_not_starve_late_root() -> None:
    findings = [
        _finding("early-root", "file:///a-root.js", metadata={"load_context": "/a"}),
        *[
            _finding(
                f"early-child-{index:02d}",
                "file:///a-child.js",
                metadata={"initiator": "file:///a-root.js"},
            )
            for index in range(60)
        ],
        _finding("late-root", "file:///z-root.js", metadata={"load_context": "/z"}),
        _finding(
            "late-child",
            "file:///z-child.js",
            metadata={"initiator": "file:///z-root.js"},
        ),
    ]

    graph = Correlator().correlate(findings)

    assert any(
        edge.source_id == "late-root"
        and edge.target_id == "late-child"
        and edge.metadata.get("context") == "initiator_chain:file:///z-root.js"
        for edge in graph.edges
    )
    assert any(
        edge.source_id == "late-root"
        and edge.target_id == "late-child"
        and edge.metadata.get("context") == "load_context_chain:/z -> file:///z-root.js"
        for edge in graph.edges
    )


def test_transitive_import_cap_does_not_starve_late_source_partition() -> None:
    findings = [
        _finding("early-root", "file:///a-root.js", metadata={"imports": ["./a-middle"]}),
        _finding("early-middle", "file:///a-middle.js", metadata={"imports": ["./a-leaf"]}),
        *[
            _finding(f"early-leaf-{index:02d}", "file:///a-leaf.js")
            for index in range(60)
        ],
        _finding("late-root", "file:///z-root.js", metadata={"imports": ["./z-middle"]}),
        _finding("late-middle", "file:///z-middle.js", metadata={"imports": ["./z-leaf"]}),
        _finding("late-leaf", "file:///z-leaf.js"),
    ]

    graph = Correlator().correlate(list(reversed(findings)))

    assert any(
        edge.source_id == "late-root"
        and edge.target_id == "late-leaf"
        and edge.edge_type == EdgeType.IMPORT
        and edge.metadata.get("import_source") == "transitive:./z-middle -> ./z-leaf"
        for edge in graph.edges
    )


def test_load_context_chain_is_fair_between_contexts_on_one_source() -> None:
    findings = [
        _finding(
            "root-a",
            "file:///root.js",
            metadata={"imports": ["./leaf"], "load_context": "/a"},
        ),
        _finding(
            "root-z",
            "file:///root.js",
            metadata={"imports": ["./leaf"], "load_context": "/z"},
        ),
        *[
            _finding(f"leaf-{index:02d}", "file:///leaf.js")
            for index in range(60)
        ],
    ]

    graph = Correlator().correlate(list(reversed(findings)))

    assert any(
        edge.metadata.get("context") == "load_context_import_chain:/z -> ./leaf"
        for edge in graph.edges
    )


def test_call_graph_file_cap_does_not_starve_late_file() -> None:
    call_graph = {"function:entry": ["function:target"]}
    findings = [
        _finding(
            "early-call-source",
            "file:///a-call.js",
            metadata={"enclosing_scope": "function:entry", "call_graph": call_graph},
        ),
        *[
            _finding(
                f"early-call-target-{index:02d}",
                "file:///a-call.js",
                metadata={"enclosing_scope": "function:target", "call_graph": call_graph},
            )
            for index in range(60)
        ],
        _finding(
            "late-call-source",
            "file:///z-call.js",
            metadata={"enclosing_scope": "function:entry", "call_graph": call_graph},
        ),
        _finding(
            "late-call-target",
            "file:///z-call.js",
            metadata={"enclosing_scope": "function:target", "call_graph": call_graph},
        ),
    ]

    graph = Correlator().correlate(findings)

    assert any(
        edge.source_id == "late-call-source"
        and edge.target_id == "late-call-target"
        and edge.edge_type == EdgeType.CALL_CHAIN
        and edge.metadata.get("chain") == ["function:entry", "function:target"]
        for edge in graph.edges
    )


def test_secret_endpoint_file_cap_does_not_starve_late_file() -> None:
    findings = [
        _finding("early-secret", "file:///a-secret.js", Category.SECRET, "secret", line=10),
        *[
            _finding(
                f"early-endpoint-{index:02d}",
                "file:///a-secret.js",
                Category.ENDPOINT,
                f"/early/{index}",
                line=11,
            )
            for index in range(60)
        ],
        _finding("late-secret", "file:///z-secret.js", Category.SECRET, "secret", line=10),
        _finding(
            "late-endpoint",
            "file:///z-secret.js",
            Category.ENDPOINT,
            "/late",
            line=11,
        ),
    ]

    graph = Correlator().correlate(findings)

    assert any(
        edge.source_id == "late-secret"
        and edge.target_id == "late-endpoint"
        and edge.reasoning == "Secret and endpoint in close proximity"
        for edge in graph.edges
    )


def test_light_taint_file_cap_does_not_starve_late_file() -> None:
    def sink(finding_id: str, file_url: str) -> Finding:
        return _finding(
            finding_id,
            file_url,
            Category.SINK,
            "imageUrl",
            value_type="dom_attr_sink",
            metadata={"sink_attr": "src", "sink_source": "imageUrl"},
        )

    findings = [
        _finding("early-upload", "file:///a-taint.js", Category.UPLOAD, "upload"),
        *[sink(f"early-sink-{index:02d}", "file:///a-taint.js") for index in range(60)],
        _finding("late-upload", "file:///z-taint.js", Category.UPLOAD, "upload"),
        sink("late-sink", "file:///z-taint.js"),
    ]

    graph = Correlator().correlate(findings)

    assert any(
        edge.source_id == "late-upload"
        and edge.target_id == "late-sink"
        and edge.edge_type == EdgeType.TAINT
        for edge in graph.edges
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://User:Pass@EXAMPLE.com:443/api", "https://example.com"),
        ("https://user:pass@EXAMPLE.com:443/api", "https://example.com"),
        ("http://EXAMPLE.com:80/api", "http://example.com"),
        ("https://EXAMPLE.com:8443/api", "https://example.com:8443"),
        ("https://[2001:DB8::1]:443/api", "https://[2001:db8::1]"),
        ("https://[2001:0DB8:0:0:0:0:0:1]/api", "https://[2001:db8::1]"),
        ("https://B\u00dcCHER.example./api", "https://xn--bcher-kva.example"),
        ("//User:Pass@EXAMPLE.com:443/api", "//example.com:443"),
        ("https://example.com:99999/api", ""),
        ("https://[broken/api", ""),
        ("/relative", ""),
    ],
)
def test_canonicalize_origin(value: str, expected: str) -> None:
    assert canonicalize_origin(value) == expected


def test_cluster_origin_canonicalization_is_credential_free_and_shared_with_config_edges() -> None:
    first = _finding(
        "first-origin",
        "file:///one.js",
        Category.ENDPOINT,
        "https://user:pass@EXAMPLE.com:443/alpha",
    )
    second = _finding(
        "second-origin",
        "file:///two.js",
        Category.ENDPOINT,
        "https://example.com/beta",
    )

    graph = Correlator().correlate([first, second])
    base_clusters = [cluster for cluster in graph.clusters if cluster.id.startswith("base_url:")]

    assert [cluster.id for cluster in base_clusters] == ["base_url:https://example.com"]
    assert base_clusters[0].finding_ids == ["first-origin", "second-origin"]
    assert "user" not in base_clusters[0].model_dump_json()
    assert any(
        edge.edge_type == EdgeType.CONFIG
        and edge.metadata.get("config_key") == "baseURL: https://example.com"
        for edge in graph.edges
    )


def test_correlator_clears_stale_cluster_id_when_membership_changes() -> None:
    first = _finding(
        "cluster-first",
        "file:///one.js",
        Category.ENDPOINT,
        "https://example.com/alpha",
    )
    second = _finding(
        "cluster-second",
        "file:///two.js",
        Category.ENDPOINT,
        "https://example.com/beta",
    )
    correlator = Correlator()

    correlator.correlate([first, second])
    assert first.cluster_id == "base_url:https://example.com"

    second.extracted_value = "https://other.example/gamma"
    graph = correlator.correlate([first, second])

    assert graph.clusters == []
    assert first.cluster_id is None
    assert second.cluster_id is None


def test_functionality_clustering_uses_tokens_not_substrings() -> None:
    builder = ClusterBuilder()
    findings = [
        _finding("author-1", "file:///1.js", Category.ENDPOINT, "/authors/1"),
        _finding("author-2", "file:///2.js", Category.ENDPOINT, "/authority/list"),
        _finding("auth-1", "file:///3.js", Category.ENDPOINT, "/oauth/callback"),
        _finding("auth-2", "file:///4.js", Category.ENDPOINT, "/userLogin/start"),
    ]

    clusters = builder.build(findings)
    auth_cluster = next(cluster for cluster in clusters if cluster.id == "func:auth")

    assert auth_cluster.finding_ids == ["auth-1", "auth-2"]
    assert "author-1" not in auth_cluster.finding_ids
    assert "author-2" not in auth_cluster.finding_ids


def test_cluster_builder_is_input_order_invariant() -> None:
    findings = [
        _finding("b", "file:///b.js", Category.ENDPOINT, "https://example.com/b"),
        _finding("a", "file:///a.js", Category.ENDPOINT, "https://EXAMPLE.com:443/a"),
    ]

    forward = ClusterBuilder().build(findings)
    reverse = ClusterBuilder().build(list(reversed(findings)))

    assert [cluster.model_dump(mode="json") for cluster in forward] == [
        cluster.model_dump(mode="json") for cluster in reverse
    ]
