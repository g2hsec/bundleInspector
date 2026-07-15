"""
Correlation graph for connecting findings.
"""

from __future__ import annotations

import json
import posixpath
import sys
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Iterator
from pathlib import PurePosixPath
from typing import Any, TypeVar, cast

from bundleInspector.correlator.cluster import ClusterBuilder, canonicalize_origin
from bundleInspector.correlator.edges import (
    create_call_chain_edge,
    create_config_edge,
    create_import_edge,
    create_runtime_edge,
    create_same_file_edge,
    create_taint_edge,
)
from bundleInspector.storage.models import (
    Category,
    Cluster,
    Correlation,
    Edge,
    EdgeType,
    Finding,
    Severity,
)

# DQ-G04: edge types whose two endpoints are interchangeable -- co-occurrence within the same
# file / base URL / environment. For these, A-B and B-A denote the same relation and must
# deduplicate together. All other edge types (IMPORT, CALL_CHAIN, RUNTIME, TAINT) are directed:
# A->B and B->A are distinct, so their orientation is preserved in the dedup key.
_SYMMETRIC_EDGE_TYPES = frozenset({EdgeType.SAME_FILE, EdgeType.CONFIG, EdgeType.ENV})
_T = TypeVar("_T")


class _TelemetryEdgeCap(int):
    """An integer cap that records the exact `count >= cap` saturation point."""

    _graph: CorrelationGraph
    _pass_name: str
    _possible_candidates: int | None

    def __new__(
        cls,
        value: int,
        graph: CorrelationGraph,
        pass_name: str,
        possible_candidates: int | None,
    ) -> _TelemetryEdgeCap:
        instance = int.__new__(cls, value)
        instance._graph = graph
        instance._pass_name = pass_name
        instance._possible_candidates = possible_candidates
        return instance

    def __le__(self, other: object) -> bool:
        if not isinstance(other, int):
            return NotImplemented
        reached = other >= int(self)
        if reached:
            remaining = (
                max(self._possible_candidates - other, 0)
                if self._possible_candidates is not None
                else None
            )
            self._graph.note_cap(self._pass_name, truncated_candidates=remaining)
        return reached


class CorrelationGraph:
    """
    Graph of correlations between findings.
    """

    def __init__(self) -> None:
        self.edges: list[Edge] = []
        self.clusters: list[Cluster] = []
        self._edge_keys: set[tuple[str, str, EdgeType, str]] = set()

        # Indexes
        self._by_source: dict[str, list[Edge]] = defaultdict(list)
        self._by_target: dict[str, list[Edge]] = defaultdict(list)
        self.telemetry: dict[str, Any] = {
            "candidates": 0,
            "candidate_attempts": 0,
            "emitted": 0,
            "dropped": 0,
            "duplicate_dropped": 0,
            "cap_dropped": 0,
            "truncated_candidates": 0,
            "truncated_candidates_lower_bound": 0,
            "truncated_candidates_unknown": 0,
            "capped_passes": {},
            "passes": {},
        }
        self._last_cap_markers: dict[str, int] = {}

    def _pass_stats(self, pass_name: str) -> dict[str, int]:
        passes = self.telemetry["passes"]
        assert isinstance(passes, dict)
        stats = passes.setdefault(
            pass_name,
            {
                "candidate_attempts": 0,
                "emitted": 0,
                "duplicate_dropped": 0,
                "cap_dropped": 0,
                "truncated_candidates": 0,
                "truncated_candidates_lower_bound": 0,
                "truncated_candidates_unknown": 0,
            },
        )
        return cast(dict[str, int], stats)

    def edge_cap(
        self,
        value: int,
        possible_candidates: int | None = None,
        *,
        pass_name: str | None = None,
    ) -> _TelemetryEdgeCap:
        """Create a cap, optionally with an exact pre-cap candidate cardinality."""
        effective_pass_name = pass_name or sys._getframe(1).f_code.co_name
        return _TelemetryEdgeCap(value, self, effective_pass_name, possible_candidates)

    def note_cap(
        self,
        pass_name: str,
        truncated_candidates: int | None = None,
    ) -> None:
        """Record truncation separately from candidates actually evaluated by ``add_edge``.

        When a pass can supply its full candidate cardinality, ``truncated_candidates`` is exact.
        Otherwise telemetry records a one-candidate lower bound and increments the unknown counter.
        """
        stats = self._pass_stats(pass_name)
        marker = stats["emitted"] + stats["duplicate_dropped"]
        if self._last_cap_markers.get(pass_name) == marker:
            return
        if truncated_candidates == 0:
            return
        self._last_cap_markers[pass_name] = marker
        lower_bound = truncated_candidates if truncated_candidates is not None else 1
        self.telemetry["cap_dropped"] += lower_bound
        self.telemetry["truncated_candidates_lower_bound"] += lower_bound
        stats["cap_dropped"] += lower_bound
        stats["truncated_candidates_lower_bound"] += lower_bound
        if truncated_candidates is None:
            self.telemetry["truncated_candidates_unknown"] += 1
            stats["truncated_candidates_unknown"] += 1
        else:
            self.telemetry["truncated_candidates"] += truncated_candidates
            stats["truncated_candidates"] += truncated_candidates
        capped_passes = self.telemetry["capped_passes"]
        assert isinstance(capped_passes, dict)
        capped_passes[pass_name] = capped_passes.get(pass_name, 0) + 1

    def add_edge(self, edge: Edge, *, pass_name: str | None = None) -> None:
        """Add an edge to the graph, deduplicating identical relations.

        DQ-G04: only symmetric edge types sort their endpoints so A-B and B-A collapse to one.
        Directed types keep their orientation, so a genuine reverse edge (e.g. a circular import
        A->B and B->A) is preserved instead of being silently dropped."""
        effective_pass_name = pass_name or sys._getframe(1).f_code.co_name
        stats = self._pass_stats(effective_pass_name)
        self.telemetry["candidate_attempts"] += 1
        self.telemetry["candidates"] += 1
        stats["candidate_attempts"] += 1
        if edge.edge_type in _SYMMETRIC_EDGE_TYPES:
            source_id, target_id = sorted([edge.source_id, edge.target_id])
        else:
            source_id, target_id = edge.source_id, edge.target_id
        edge_key = (source_id, target_id, edge.edge_type, edge.reasoning)
        if edge_key in self._edge_keys:
            self.telemetry["duplicate_dropped"] += 1
            self.telemetry["dropped"] += 1
            stats["duplicate_dropped"] += 1
            return
        self._edge_keys.add(edge_key)
        self.edges.append(edge)
        self.telemetry["emitted"] += 1
        stats["emitted"] += 1
        self._by_source[edge.source_id].append(edge)
        self._by_target[edge.target_id].append(edge)

    def get_edges_from(self, finding_id: str) -> list[Edge]:
        """Get all edges originating from a finding."""
        return self._by_source.get(finding_id, [])

    def get_edges_to(self, finding_id: str) -> list[Edge]:
        """Get all edges pointing to a finding."""
        return self._by_target.get(finding_id, [])

    def get_related(self, finding_id: str) -> set[str]:
        """Get all related finding IDs."""
        related = set()

        for edge in self.get_edges_from(finding_id):
            related.add(edge.target_id)

        for edge in self.get_edges_to(finding_id):
            related.add(edge.source_id)

        return related

    def to_correlations(self) -> list[Correlation]:
        """Convert edges to Correlation objects."""
        return [
            Correlation(
                id=edge.id,
                edge_type=edge.edge_type,
                source_finding_id=edge.source_id,
                target_finding_id=edge.target_id,
                confidence=edge.confidence,
                reasoning=edge.reasoning,
            )
            for edge in self.edges
        ]


class Correlator:
    """
    Build correlations between findings.
    """

    def __init__(self) -> None:
        self._cluster_builder = ClusterBuilder()
        self._correlation_cache: dict[tuple[object, ...], object] | None = None
        self._ambiguous_import_resolutions: set[tuple[str, str, tuple[str, ...]]] = set()

    @staticmethod
    def _finding_sort_key(f: Finding) -> tuple:
        """Stable semantic ordering with ID only as a final tie for identical findings."""
        ev = getattr(f, "evidence", None)
        cat = getattr(f, "category", None)
        sev = getattr(f, "severity", None)
        confidence = getattr(f, "confidence", None)
        metadata = json.dumps(
            getattr(f, "metadata", {}) or {},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return (
            (getattr(ev, "file_url", "") or "") if ev else "",
            (getattr(ev, "line", 0) or 0) if ev else 0,
            (getattr(ev, "column", 0) or 0) if ev else 0,
            getattr(cat, "value", "") if cat is not None else "",
            getattr(f, "rule_id", "") or "",
            getattr(sev, "value", "") if sev is not None else "",
            getattr(confidence, "value", "") if confidence is not None else "",
            str(getattr(f, "extracted_value", "") or ""),
            getattr(f, "value_type", "") or "",
            getattr(f, "title", "") or "",
            getattr(f, "description", "") or "",
            tuple(sorted(getattr(f, "tags", []) or [])),
            metadata,
            getattr(f, "id", "") or "",
        )

    def correlate(self, findings: list[Finding]) -> CorrelationGraph:
        """
        Build correlation graph from findings.

        Args:
            findings: List of findings to correlate

        Returns:
            CorrelationGraph
        """
        graph = CorrelationGraph()
        self._correlation_cache = {}
        self._ambiguous_import_resolutions = set()

        # DQ-G02: process findings in a deterministic content order so the correlation output -- which
        # the per-pass edge caps make order-sensitive -- does not depend on the CALLER's finding order
        # (reversing it previously flipped which related edges/risk survived the cap). A local copy;
        # the caller's list is not reordered.
        findings = sorted(findings, key=self._finding_sort_key)
        for finding in findings:
            finding.cluster_id = None

        try:
            # Index findings by various attributes
            by_file = self._group_by_file(findings)
            by_base_url = self._group_by_base_url(findings)

            # Create same-file edges
            for file_url, file_findings in by_file.items():
                self._add_same_file_edges(graph, file_findings, file_url)

            # Create config edges (same base URL)
            for base_url, url_findings in by_base_url.items():
                self._add_config_edges(graph, url_findings, base_url)

            # Create import-graph edges
            self._add_import_edges(graph, by_file)
            self._add_dynamic_import_edges(graph, by_file)
            self._add_transitive_import_edges(graph, by_file)

            # Create runtime edges
            self._add_runtime_edges(graph, findings)
            self._add_import_chain_edges(graph, by_file)
            self._add_import_scope_call_chain_edges(graph, by_file)
            self._add_import_call_chain_edges(graph, by_file)
            self._add_initiator_chain_edges(graph, by_file)
            self._add_execution_chain_edges(graph, by_file)
            self._add_runtime_execution_graph_edges(graph, by_file)
            self._add_initiator_execution_scope_call_chain_edges(graph, by_file)
            self._add_initiator_execution_call_chain_edges(graph, by_file)
            self._add_execution_scope_call_chain_edges(graph, by_file)
            self._add_execution_call_chain_edges(graph, by_file)
            self._add_runtime_execution_scope_call_graph_edges(graph, by_file)
            self._add_runtime_execution_call_graph_edges(graph, by_file)
            self._add_load_context_chain_edges(graph, by_file)
            self._add_load_context_import_chain_edges(graph, by_file)
            self._add_load_context_execution_chain_edges(graph, by_file)
            self._add_load_context_runtime_execution_graph_edges(graph, by_file)
            self._add_load_context_initiator_scope_call_chain_edges(graph, by_file)
            self._add_load_context_import_scope_call_chain_edges(graph, by_file)
            self._add_load_context_initiator_call_chain_edges(graph, by_file)
            self._add_load_context_import_call_chain_edges(graph, by_file)
            self._add_load_context_execution_scope_call_chain_edges(graph, by_file)
            self._add_load_context_execution_call_chain_edges(graph, by_file)
            self._add_load_context_runtime_execution_scope_call_graph_edges(graph, by_file)
            self._add_load_context_runtime_execution_call_graph_edges(graph, by_file)
            self._add_load_context_scope_call_chain_edges(graph, by_file)
            self._add_load_context_call_chain_edges(graph, by_file)

            # Create call-graph edges
            self._add_call_graph_edges(graph, by_file)

            # Create inter-module imported-call edges
            self._add_inter_module_call_edges(graph, by_file)

            # Create secret-endpoint edges
            self._add_secret_endpoint_edges(graph, findings)

            # Light taint: connect an upload surface / response field to a DOM src/href sink
            self._add_taint_chain_edges(graph, by_file)

            # Build clusters
            graph.clusters = self._cluster_builder.build(findings)

            # Assign findings to clusters (dict lookup instead of O(N) scan)
            # Each finding gets assigned to the first matching cluster only
            findings_by_id = {f.id: f for f in findings}
            for cluster in graph.clusters:
                for finding_id in cluster.finding_ids:
                    clustered_finding = findings_by_id.get(finding_id)
                    if clustered_finding and not clustered_finding.cluster_id:
                        clustered_finding.cluster_id = cluster.id

            # DQ-G04: surface each finding's correlation neighborhood. Finding.correlation_ids was
            # declared but never populated; downstream consumers (reporters, triage) can now read a
            # finding's related IDs directly instead of re-walking the graph.
            for finding in findings:
                related = graph.get_related(finding.id) - {finding.id}
                finding.correlation_ids = sorted(related)

            graph.telemetry["ambiguous_imports"] = [
                {
                    "importer": importer,
                    "source": source,
                    "candidate_targets": list(targets),
                }
                for importer, source, targets in sorted(self._ambiguous_import_resolutions)
            ]

            return graph
        finally:
            self._correlation_cache = None

    def _cache_result(
        self,
        key: tuple[object, ...],
        factory: Callable[[], _T],
    ) -> _T:
        """Reuse expensive correlation-pass computations during one correlate() call."""
        cache = self._correlation_cache
        if cache is None:
            return factory()
        if key not in cache:
            cache[key] = factory()
        return cast(_T, cache[key])

    def _emit_fair_edges(
        self,
        graph: CorrelationGraph,
        partitions: Iterable[tuple[str, Iterable[Edge]]],
        limit: int = 50,
    ) -> None:
        """Emit a globally bounded, deterministic round-robin sample of partitioned candidates.

        Candidate iterables stay lazy: only one candidate per active partition is constructed in a
        round, and at most one candidate beyond ``limit`` is requested to prove truncation. This
        prevents an early source/context/file from consuming the complete pass budget without
        materializing the Cartesian products that the cap exists to bound.
        """
        pass_name = sys._getframe(1).f_code.co_name
        max_edges = graph.edge_cap(limit, pass_name=pass_name)
        active: deque[tuple[str, Iterator[Edge]]] = deque(
            (partition_key, iter(candidates))
            for partition_key, candidates in sorted(partitions, key=lambda item: item[0])
        )
        count = 0
        while active:
            partition_key, candidates = active.popleft()
            try:
                edge = next(candidates)
            except StopIteration:
                continue
            if count >= max_edges:
                return
            graph.add_edge(edge, pass_name=pass_name)
            count += 1
            active.append((partition_key, candidates))

    @staticmethod
    def _compound_partition_key(*components: str) -> str:
        """Build a collision-free sortable key for a compound semantic partition."""
        return "".join(f"{len(component)}:{component}" for component in components)

    def _group_by_file(
        self,
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """Group findings by file URL."""
        groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            file_url = finding.evidence.file_url
            groups[file_url].append(finding)

        return groups

    def _group_by_base_url(
        self,
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """Group endpoint findings by base URL."""
        groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.category == Category.ENDPOINT:
                base = canonicalize_origin(finding.extracted_value)
                if base:
                    groups[base].append(finding)

        return groups

    def _add_same_file_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
        file_url: str,
    ) -> None:
        """Add edges for findings in the same file."""
        # Sort by severity (highest first) to prioritize important findings
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity, 0),
            reverse=True,
        )
        possible_candidates = len(sorted_findings) * (len(sorted_findings) - 1) // 2
        max_edges = graph.edge_cap(50, possible_candidates=possible_candidates)

        count = 0
        for i, f1 in enumerate(sorted_findings):
            for f2 in sorted_findings[i + 1 :]:
                if count >= max_edges:
                    return

                graph.add_edge(create_same_file_edge(f1.id, f2.id, file_url))
                count += 1

    def _add_config_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
        base_url: str,
    ) -> None:
        """Add edges for findings sharing config."""
        possible_candidates = len(findings) * (len(findings) - 1) // 2
        max_edges = graph.edge_cap(30, possible_candidates=possible_candidates)

        count = 0
        for i, f1 in enumerate(findings):
            for f2 in findings[i + 1 :]:
                if count >= max_edges:
                    return

                graph.add_edge(create_config_edge(f1.id, f2.id, f"baseURL: {base_url}"))
                count += 1

    def _add_import_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add edges for findings connected by imports between files."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}

        def candidates_for(file_url: str, source_findings: list[Finding]) -> Iterator[Edge]:
            imports = self._collect_imports(source_findings)
            for import_source in sorted(imports):
                target_urls = self._resolve_import_targets(
                    import_source,
                    file_url,
                    file_aliases,
                )
                for target_url in target_urls:
                    target_findings = by_file[target_url]

                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            yield create_import_edge(
                                source_finding.id,
                                target_finding.id,
                                import_source,
                            )

        self._emit_fair_edges(
            graph,
            (
                (file_url, candidates_for(file_url, by_file[file_url]))
                for file_url in sorted(by_file)
            ),
        )

    def _add_dynamic_import_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add edges for findings connected by dynamic imports between files."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}

        def candidates_for(file_url: str, source_findings: list[Finding]) -> Iterator[Edge]:
            dynamic_imports = self._collect_dynamic_imports(source_findings)
            for import_source in sorted(dynamic_imports):
                target_urls = self._resolve_import_targets(
                    import_source,
                    file_url,
                    file_aliases,
                )
                for target_url in target_urls:
                    target_findings = by_file[target_url]

                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            yield create_import_edge(
                                source_finding.id,
                                target_finding.id,
                                f"dynamic:{import_source}",
                            )

        self._emit_fair_edges(
            graph,
            (
                (file_url, candidates_for(file_url, by_file[file_url]))
                for file_url in sorted(by_file)
            ),
        )

    def _add_transitive_import_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add import edges for multi-hop import chains across files."""
        dependency_graph = self._build_dependency_graph(by_file)

        def candidates_for(
            source_url: str,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings:
                return

            for target_url in sorted(reachable):
                import_chains = reachable[target_url]
                if target_url == source_url or not import_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue
                for import_chain in import_chains:
                    if len(import_chain) < 2:
                        continue
                    context = f"transitive:{' -> '.join(import_chain)}"
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            yield create_import_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, dependency_graph[source_url]))
                for source_url in sorted(dependency_graph)
            ),
        )

    def _add_runtime_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
    ) -> None:
        """Add edges for findings loaded together by runtime context."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            load_context = (finding.metadata.get("load_context") or "").strip()
            initiator = (finding.metadata.get("initiator") or "").strip()
            if load_context:
                groups[f"load_context:{load_context}"].append(finding)
            if initiator:
                groups[f"initiator:{initiator}"].append(finding)

        def candidates_for(context: str, group: list[Finding]) -> Iterator[Edge]:
            for i, f1 in enumerate(group):
                for f2 in group[i + 1 :]:
                    if f1.evidence.file_url == f2.evidence.file_url:
                        continue
                    yield create_runtime_edge(
                        f1.id,
                        f2.id,
                        context,
                    )

        self._emit_fair_edges(
            graph,
            ((context, candidates_for(context, groups[context])) for context in sorted(groups)),
        )

    def _add_initiator_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges from initiating JS files to directly or transitively loaded files."""
        initiator_map = self._build_initiator_map(by_file)
        root_inputs: dict[str, list[tuple[Finding, list[str]]]] = defaultdict(list)

        for target_url in sorted(by_file):
            target_findings = by_file[target_url]
            ancestor_chains = self._collect_initiator_ancestor_chains(target_url, initiator_map)
            if not ancestor_chains:
                continue
            for target_finding in target_findings:
                for ancestor_chain in ancestor_chains:
                    root_inputs[ancestor_chain[0]].append((target_finding, ancestor_chain))

        def candidates_for(
            source_url: str,
            inputs: list[tuple[Finding, list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            for target_finding, ancestor_chain in inputs:
                if len(ancestor_chain) == 1:
                    context = f"initiator_chain:{source_url}"
                else:
                    context = f"initiator_chain:{' -> '.join(ancestor_chain)}"
                for source_finding in source_findings:
                    if source_finding.id == target_finding.id:
                        continue
                    yield create_runtime_edge(
                        source_finding.id,
                        target_finding.id,
                        context,
                    )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, root_inputs[source_url]))
                for source_url in sorted(root_inputs)
            ),
        )

    def _add_execution_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for mixed import/initiator execution paths without requiring load-context metadata."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))

        def candidates_for(source_url: str, source_findings: list[Finding]) -> Iterator[Edge]:
            if not source_findings:
                return

            reachable = self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url in sorted(reachable):
                execution_chains = reachable[target_url]
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for execution_chain in execution_chains:
                    context = f"execution_chain:{source_url} -> {' -> '.join(execution_chain)}"
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if source_finding.id == target_finding.id:
                                continue
                            yield create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, by_file[source_url]))
                for source_url in sorted(by_file)
            ),
        )

    def _add_runtime_execution_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add unified runtime edges across practical import/dynamic/initiator execution paths."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))

        def candidates_for(source_url: str, source_findings: list[Finding]) -> Iterator[Edge]:
            if not source_findings:
                return
            reachable = self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url in sorted(reachable):
                execution_chains = reachable[target_url]
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue
                for execution_chain in execution_chains:
                    context = (
                        f"runtime_execution_graph:{source_url} -> {' -> '.join(execution_chain)}"
                    )
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if source_finding.id == target_finding.id:
                                continue
                            yield create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, by_file[source_url]))
                for source_url in sorted(by_file)
            ),
        )

    def _add_load_context_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges from load-context roots through transitive initiator chains."""
        initiator_map = self._build_initiator_map(by_file)
        file_load_contexts = self._build_file_load_contexts(by_file)
        root_inputs: dict[str, list[tuple[Finding, list[str]]]] = defaultdict(list)

        for target_url in sorted(by_file):
            target_findings = by_file[target_url]
            ancestor_chains = self._collect_initiator_ancestor_chains(target_url, initiator_map)
            if not ancestor_chains:
                continue
            for target_finding in target_findings:
                for ancestor_chain in ancestor_chains:
                    root_inputs[ancestor_chain[0]].append((target_finding, ancestor_chain))

        def candidates_for(
            source_url: str,
            load_context: str,
            inputs: list[tuple[Finding, list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            for target_finding, ancestor_chain in inputs:
                if len(ancestor_chain) == 1:
                    base_chain = source_url
                else:
                    base_chain = " -> ".join(ancestor_chain)
                context = f"load_context_chain:{load_context} -> {base_chain}"
                for source_finding in source_findings:
                    if source_finding.id == target_finding.id:
                        continue
                    yield create_runtime_edge(
                        source_finding.id,
                        target_finding.id,
                        context,
                    )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(source_url, load_context),
                    candidates_for(source_url, load_context, root_inputs[source_url]),
                )
                for source_url in sorted(root_inputs)
                for load_context in sorted(file_load_contexts.get(source_url, set()))
            ),
        )

    def _add_initiator_execution_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for imported call chains reached through initiator-loaded descendants."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_initiator_descendant_paths(
                source_url,
                initiator_children,
            )
            for source_url in by_file
        }
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(
            source_url: str,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                return

            for intermediate_url in sorted(reachable):
                path_chains = reachable[intermediate_url]
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted(
                    {
                        (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                        for finding in intermediate_findings
                    }
                )

                for intermediate_scope in intermediate_scopes:
                    cache_key = (intermediate_url, intermediate_scope)
                    if cache_key not in scope_target_cache:
                        scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                            intermediate_url,
                            intermediate_scope,
                            by_file,
                            file_aliases,
                        )

                    for target_finding, target_chain in scope_target_cache[cache_key]:
                        if target_finding.evidence.file_url == source_url:
                            continue
                        for path_chain in path_chains:
                            context = (
                                f"initiator_execution_call_chain:{source_url} -> "
                                + " -> ".join([*path_chain, intermediate_scope, *target_chain])
                            )
                            for source_finding in source_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, reachable_by_source[source_url]))
                for source_url in sorted(reachable_by_source)
            ),
        )

    def _add_initiator_execution_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside initiator-loaded descendants."""
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_initiator_descendant_paths(
                source_url,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "initiator_execution_scope_call_chain",
        )

    def _add_import_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges through pure transitive import chains without load-context metadata."""
        dependency_graph = self._build_dependency_graph(by_file)

        def candidates_for(
            source_url: str,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                return

            for target_url in sorted(reachable):
                import_chains = reachable[target_url]
                if target_url == source_url or not import_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for import_chain in import_chains:
                    if not import_chain:
                        continue
                    context = f"import_chain:{source_url} -> {' -> '.join(import_chain)}"
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if source_finding.id == target_finding.id:
                                continue
                            yield create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, dependency_graph[source_url]))
                for source_url in sorted(dependency_graph)
            ),
        )

    def _add_import_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for downstream-module imported call chains on pure import paths."""
        dependency_graph = self._build_dependency_graph(by_file)
        self._add_runtime_downstream_call_chain_edges(
            graph,
            by_file,
            dependency_graph,
            "import_call_chain",
        )

    def _add_import_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside pure import-path modules."""
        dependency_graph = self._build_dependency_graph(by_file)
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            dependency_graph,
            "import_scope_call_chain",
        )

    def _add_execution_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for downstream-module imported call chains on mixed execution paths without load-context metadata."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(source_url: str, source_findings: list[Finding]) -> Iterator[Edge]:
            if not source_findings:
                return

            reachable = self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for intermediate_url in sorted(reachable):
                path_chains = reachable[intermediate_url]
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted(
                    {
                        (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                        for finding in intermediate_findings
                    }
                )

                for intermediate_scope in intermediate_scopes:
                    cache_key = (intermediate_url, intermediate_scope)
                    if cache_key not in scope_target_cache:
                        scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                            intermediate_url,
                            intermediate_scope,
                            by_file,
                            file_aliases,
                        )

                    for target_finding, target_chain in scope_target_cache[cache_key]:
                        if target_finding.evidence.file_url == source_url:
                            continue
                        for path_chain in path_chains:
                            context = f"execution_call_chain:{source_url} -> " + " -> ".join(
                                [*path_chain, intermediate_scope, *target_chain]
                            )
                            for source_finding in source_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, by_file[source_url]))
                for source_url in sorted(by_file)
            ),
        )

    def _add_execution_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside mixed execution-path modules."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "execution_scope_call_chain",
        )

    def _add_runtime_execution_scope_call_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add same-file runtime call-graph edges on unified execution paths."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "runtime_execution_scope_call_graph",
        )

    def _add_runtime_execution_call_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add downstream inter-module runtime call-graph edges on unified execution paths."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_downstream_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "runtime_execution_call_graph",
        )

    def _add_load_context_import_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges from load-context roots through transitive import chains."""
        dependency_graph = self._build_dependency_graph(by_file)
        file_load_contexts = self._build_file_load_contexts(by_file)

        def candidates_for(
            source_url: str,
            load_context: str,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings:
                return

            for target_url in sorted(reachable):
                import_chains = reachable[target_url]
                if target_url == source_url or not import_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for import_chain in import_chains:
                    if not import_chain:
                        continue
                    context = f"load_context_import_chain:{load_context} -> {' -> '.join(import_chain)}"
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if source_finding.id == target_finding.id:
                                continue
                            yield create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(source_url, load_context),
                    candidates_for(source_url, load_context, dependency_graph[source_url]),
                )
                for source_url in sorted(dependency_graph)
                for load_context in sorted(file_load_contexts.get(source_url, set()))
            ),
        )

    def _add_load_context_execution_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for mixed import/initiator execution paths from load-context roots."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        file_load_contexts = self._build_file_load_contexts(by_file)

        def candidates_for(
            source_url: str,
            load_context: str,
            source_findings: list[Finding],
        ) -> Iterator[Edge]:
            if not source_findings:
                return

            reachable = self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url in sorted(reachable):
                execution_chains = reachable[target_url]
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for execution_chain in execution_chains:
                    context = (
                        "load_context_execution_chain:"
                        f"{load_context} -> {' -> '.join(execution_chain)}"
                    )
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if source_finding.id == target_finding.id:
                                continue
                            yield create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(source_url, load_context),
                    candidates_for(source_url, load_context, by_file[source_url]),
                )
                for source_url in sorted(by_file)
                for load_context in sorted(file_load_contexts.get(source_url, set()))
            ),
        )

    def _add_load_context_runtime_execution_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add unified runtime edges from load-context roots across any practical execution path."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        file_load_contexts = self._build_file_load_contexts(by_file)

        def candidates_for(
            source_url: str,
            load_context: str,
            source_findings: list[Finding],
        ) -> Iterator[Edge]:
            if not source_findings:
                return
            reachable = self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url in sorted(reachable):
                execution_chains = reachable[target_url]
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue
                for execution_chain in execution_chains:
                    context = (
                        "load_context_runtime_execution_graph:"
                        f"{load_context} -> {' -> '.join(execution_chain)}"
                    )
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if source_finding.id == target_finding.id:
                                continue
                            yield create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(source_url, load_context),
                    candidates_for(source_url, load_context, by_file[source_url]),
                )
                for source_url in sorted(by_file)
                for load_context in sorted(file_load_contexts.get(source_url, set()))
            ),
        )

    def _add_load_context_import_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for downstream-module imported call chains on load-context import paths."""
        self._add_load_context_downstream_call_chain_edges(
            graph,
            by_file,
            self._build_dependency_graph(by_file),
            "load_context_import_call_chain",
        )

    def _add_load_context_execution_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for downstream-module imported call chains on mixed execution paths."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        execution_paths = {
            source_url: self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_load_context_downstream_call_chain_edges(
            graph,
            by_file,
            execution_paths,
            "load_context_execution_call_chain",
        )

    def _add_load_context_runtime_execution_scope_call_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add same-file runtime call-graph edges on unified execution paths from load-context roots."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "load_context_runtime_execution_scope_call_graph",
            include_load_context=True,
        )

    def _add_load_context_runtime_execution_call_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add downstream inter-module runtime call-graph edges on unified execution paths from load-context roots."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_load_context_downstream_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "load_context_runtime_execution_call_graph",
        )

    def _add_load_context_initiator_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for downstream imported call chains on pure initiator paths with load context."""
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_initiator_descendant_paths(
                source_url,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_load_context_downstream_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "load_context_initiator_call_chain",
        )

    def _add_load_context_import_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside transitive import-path modules with load context."""
        dependency_graph = self._build_dependency_graph(by_file)
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            dependency_graph,
            "load_context_import_scope_call_chain",
            include_load_context=True,
        )

    def _add_load_context_execution_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside mixed execution-path modules with load context."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "load_context_execution_scope_call_chain",
            include_load_context=True,
        )

    def _add_load_context_initiator_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside pure initiator-path modules with load context."""
        initiator_children = self._build_initiator_children_map(self._build_initiator_map(by_file))
        reachable_by_source = {
            source_url: self._collect_initiator_descendant_paths(
                source_url,
                initiator_children,
            )
            for source_url in by_file
        }
        self._add_runtime_scope_call_chain_edges(
            graph,
            by_file,
            reachable_by_source,
            "load_context_initiator_scope_call_chain",
            include_load_context=True,
        )

    def _add_load_context_downstream_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
        reachable_by_source: dict[str, dict[str, list[list[str]]]],
        context_prefix: str,
    ) -> None:
        """Add runtime edges for downstream-module imported call chains reached from load-context roots."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        file_load_contexts = self._build_file_load_contexts(by_file)
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(
            source_url: str,
            load_context: str,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                return

            for intermediate_url in sorted(reachable):
                path_chains = reachable[intermediate_url]
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted(
                    {
                        (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                        for finding in intermediate_findings
                    }
                )

                for intermediate_scope in intermediate_scopes:
                    cache_key = (intermediate_url, intermediate_scope)
                    if cache_key not in scope_target_cache:
                        scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                            intermediate_url,
                            intermediate_scope,
                            by_file,
                            file_aliases,
                        )

                    for target_finding, target_chain in scope_target_cache[cache_key]:
                        if target_finding.evidence.file_url == source_url:
                            continue
                        for path_chain in path_chains:
                            context_chain = [*path_chain, intermediate_scope, *target_chain]
                            context_suffix = " -> ".join(context_chain)
                            context = f"{context_prefix}:{load_context} -> {context_suffix}"
                            for source_finding in source_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(source_url, load_context),
                    candidates_for(source_url, load_context, reachable_by_source[source_url]),
                )
                for source_url in sorted(reachable_by_source)
                for load_context in sorted(file_load_contexts.get(source_url, set()))
            ),
        )

    def _add_runtime_downstream_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
        reachable_by_source: dict[str, dict[str, list[list[str]]]],
        context_prefix: str,
    ) -> None:
        """Add runtime edges for downstream-module imported call chains without load-context metadata."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(
            source_url: str,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                return

            for intermediate_url in sorted(reachable):
                path_chains = reachable[intermediate_url]
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted(
                    {
                        (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                        for finding in intermediate_findings
                    }
                )

                for intermediate_scope in intermediate_scopes:
                    cache_key = (intermediate_url, intermediate_scope)
                    if cache_key not in scope_target_cache:
                        scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                            intermediate_url,
                            intermediate_scope,
                            by_file,
                            file_aliases,
                        )

                    for target_finding, target_chain in scope_target_cache[cache_key]:
                        if target_finding.evidence.file_url == source_url:
                            continue
                        for path_chain in path_chains:
                            context_suffix = " -> ".join(
                                [*path_chain, intermediate_scope, *target_chain]
                            )
                            context = f"{context_prefix}:{source_url} -> {context_suffix}"
                            for source_finding in source_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                )

        self._emit_fair_edges(
            graph,
            (
                (source_url, candidates_for(source_url, reachable_by_source[source_url]))
                for source_url in sorted(reachable_by_source)
            ),
        )

    def _add_runtime_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
        reachable_by_source: dict[str, dict[str, list[list[str]]]],
        context_prefix: str,
        include_load_context: bool = False,
    ) -> None:
        """Add runtime edges for same-file call chains inside runtime-reached modules."""
        file_load_contexts = self._build_file_load_contexts(by_file) if include_load_context else {}
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(
            source_url: str,
            load_context: str | None,
            reachable: dict[str, list[list[str]]],
        ) -> Iterator[Edge]:
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                return

            if include_load_context and load_context is None:
                return

            for intermediate_url in sorted(reachable):
                path_chains = reachable[intermediate_url]
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted(
                    {
                        (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                        for finding in intermediate_findings
                    }
                )
                if not intermediate_scopes:
                    continue

                for intermediate_scope in intermediate_scopes:
                    cache_key = (intermediate_url, intermediate_scope)
                    if cache_key not in scope_target_cache:
                        scope_target_cache[cache_key] = self._resolve_intra_module_call_targets(
                            intermediate_findings,
                            intermediate_scope,
                        )

                    for target_finding, target_chain in scope_target_cache[cache_key]:
                        if target_finding.evidence.file_url == source_url:
                            continue
                        for path_chain in path_chains:
                            context_suffix = " -> ".join(
                                [*path_chain, intermediate_scope, *target_chain]
                            )
                            context = (
                                f"{context_prefix}:{load_context} -> {context_suffix}"
                                if include_load_context
                                else f"{context_prefix}:{source_url} -> {context_suffix}"
                            )
                            for source_finding in source_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                )

        partitions = (
            (
                self._compound_partition_key(source_url, load_context),
                candidates_for(source_url, load_context, reachable_by_source[source_url]),
            )
            for source_url in sorted(reachable_by_source)
            for load_context in sorted(file_load_contexts.get(source_url, set()))
        ) if include_load_context else (
            (
                source_url,
                candidates_for(source_url, None, reachable_by_source[source_url]),
            )
            for source_url in sorted(reachable_by_source)
        )

        self._emit_fair_edges(
            graph,
            partitions,
        )

    def _add_call_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add edges for findings connected through intra-file function call graphs."""
        def candidates_for(file_findings: list[Finding]) -> Iterator[Edge]:
            call_graph = self._collect_call_graph(file_findings)
            if not call_graph:
                return

            by_scope: dict[str, list[Finding]] = defaultdict(list)
            for finding in file_findings:
                scope = (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                by_scope[scope].append(finding)

            for source_scope in sorted(call_graph):
                source_findings = by_scope.get(source_scope, [])
                if not source_findings:
                    continue

                reachable_scopes = self._collect_transitive_scope_paths(call_graph, source_scope)
                for target_scope, target_chains in reachable_scopes.items():
                    target_findings = by_scope.get(target_scope, [])
                    if not target_findings:
                        continue

                    for target_chain in target_chains:
                        for source_finding in source_findings:
                            for target_finding in target_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_call_chain_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    [source_scope, *target_chain],
                                )

        self._emit_fair_edges(
            graph,
            (
                (file_url, candidates_for(by_file[file_url]))
                for file_url in sorted(by_file)
            ),
        )

    def _add_inter_module_call_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add call-chain edges for imported symbols actually invoked by scope."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(file_url: str, source_findings: list[Finding]) -> Iterator[Edge]:
            for source_finding in source_findings:
                source_scope = (
                    source_finding.metadata.get("enclosing_scope") or "global"
                ).strip() or "global"
                cache_key = (file_url, source_scope)
                if cache_key not in scope_target_cache:
                    scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                        file_url,
                        source_scope,
                        by_file,
                        file_aliases,
                    )

                for target_finding, target_chain in scope_target_cache[cache_key]:
                    if source_finding.id == target_finding.id:
                        continue
                    yield create_call_chain_edge(
                        source_finding.id,
                        target_finding.id,
                        [source_scope, *target_chain],
                    )

        self._emit_fair_edges(
            graph,
            (
                (file_url, candidates_for(file_url, by_file[file_url]))
                for file_url in sorted(by_file)
            ),
        )

    def _add_load_context_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for load-context-rooted imported call chains."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        file_load_contexts = self._build_file_load_contexts(by_file)
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        def candidates_for(
            file_url: str,
            load_context: str,
            source_findings: list[Finding],
        ) -> Iterator[Edge]:
            if not source_findings:
                return

            for source_finding in source_findings:
                source_scope = (
                    source_finding.metadata.get("enclosing_scope") or "global"
                ).strip() or "global"
                cache_key = (file_url, source_scope)
                if cache_key not in scope_target_cache:
                    scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                        file_url,
                        source_scope,
                        by_file,
                        file_aliases,
                    )

                for target_finding, target_chain in scope_target_cache[cache_key]:
                    if source_finding.id == target_finding.id:
                        continue
                    yield create_runtime_edge(
                        source_finding.id,
                        target_finding.id,
                        "load_context_call_chain:"
                        f"{load_context} -> {' -> '.join([source_scope, *target_chain])}",
                    )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(file_url, load_context),
                    candidates_for(file_url, load_context, by_file[file_url]),
                )
                for file_url in sorted(by_file)
                for load_context in sorted(file_load_contexts.get(file_url, set()))
            ),
        )

    def _add_load_context_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file transitive call chains inside load-context root files."""
        file_load_contexts = self._build_file_load_contexts(by_file)

        def candidates_for(
            file_url: str,
            load_context: str,
            file_findings: list[Finding],
        ) -> Iterator[Edge]:
            if not file_findings:
                return

            call_graph = self._collect_call_graph(file_findings)
            if not call_graph:
                return

            by_scope: dict[str, list[Finding]] = defaultdict(list)
            for finding in file_findings:
                scope = (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                by_scope[scope].append(finding)

            for source_scope in sorted(call_graph):
                source_findings = by_scope.get(source_scope, [])
                if not source_findings:
                    continue

                reachable_scopes = self._collect_transitive_scope_paths(call_graph, source_scope)
                for target_scope, target_chains in reachable_scopes.items():
                    target_findings = by_scope.get(target_scope, [])
                    if not target_findings:
                        continue

                    for target_chain in target_chains:
                        chain_context = " -> ".join([source_scope, *target_chain])
                        context = (
                            f"load_context_scope_call_chain:{load_context} -> {chain_context}"
                        )
                        for source_finding in source_findings:
                            for target_finding in target_findings:
                                if source_finding.id == target_finding.id:
                                    continue
                                yield create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                )

        self._emit_fair_edges(
            graph,
            (
                (
                    self._compound_partition_key(file_url, load_context),
                    candidates_for(file_url, load_context, by_file[file_url]),
                )
                for file_url in sorted(by_file)
                for load_context in sorted(file_load_contexts.get(file_url, set()))
            ),
        )

    def _add_secret_endpoint_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
    ) -> None:
        """Add edges between secrets and endpoints in same file."""
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            by_file[finding.evidence.file_url].append(finding)

        def candidates_for(file_findings: list[Finding]) -> Iterator[Edge]:
            secrets = [finding for finding in file_findings if finding.category == Category.SECRET]
            endpoints = [
                finding for finding in file_findings if finding.category == Category.ENDPOINT
            ]
            for secret in secrets:
                for endpoint in endpoints:
                    if (
                        secret.evidence.line > 0
                        and endpoint.evidence.line > 0
                        and abs(secret.evidence.line - endpoint.evidence.line) < 20
                    ):
                        yield Edge(
                            source_id=secret.id,
                            target_id=endpoint.id,
                            edge_type=EdgeType.CALL_CHAIN,
                            confidence=secret.confidence,
                            reasoning="Secret and endpoint in close proximity",
                            metadata={
                                "secret_line": secret.evidence.line,
                                "endpoint_line": endpoint.evidence.line,
                            },
                        )

        self._emit_fair_edges(
            graph,
            (
                (file_url, candidates_for(by_file[file_url]))
                for file_url in sorted(by_file)
            ),
        )

    # Upload-source and media-sink recognition for the light taint pass.
    _TAINT_UPLOAD_EP_HINTS = ("upload", "file", "attach", "image", "img", "photo", "avatar")
    _TAINT_SINK_ATTRS = frozenset({"src", "href", "srcdoc", "poster", "background", "xlink:href"})
    # DQ-G03: media/upload tokens matched as a SUBSTRING (imageUrl, avatarUrl, fileData).
    _TAINT_SOURCE_HINTS = ("image", "img", "photo", "avatar", "thumb", "file", "upload", "attach")
    # DQ-G03: response-OBJECT root tokens for the canonical upload response (response.url / data.url /
    # res.data). Matched ONLY as the sink expression's FIRST identifier -- NOT a raw substring -- so
    # `data.url` matches but chartData / metadata / dataset / searchResult do not (those substring
    # matches were the false-positive class). Generic PROPERTY tokens (url/src/path/content) stay
    # excluded: they name properties on non-response objects too (config.cdnUrl, router.currentPath).
    _TAINT_SOURCE_ROOTS = ("response", "data", "result", "res")

    @staticmethod
    def _sink_source_root(expr: str) -> str:
        """DQ-G03: the FIRST identifier of a sink expression (already lowercased), skipping a leading
        `${`/whitespace wrapper -- so `${data.url}` -> 'data' but `${chartData}` -> 'chartdata'. Lets
        response-object roots be matched as the root, not a substring."""
        expr = expr.strip()
        if expr.startswith("${"):
            expr = expr[2:]
        i = 0
        n = len(expr)
        while i < n and not (
            expr[i].isalpha() or expr[i] == "_"
        ):  # NOT '$' -> not an interpolation marker
            i += 1
        j = i
        while j < n and (expr[j].isalnum() or expr[j] in "_$"):
            j += 1
        return expr[i:j]

    def _add_taint_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Light taint correlation: within one asset, connect a file-upload surface (or an
        upload/file/image endpoint) to a DOM `src`/`href`/`on*` sink whose interpolated value
        looks like file/image/upload/response data -- automatically surfacing the
        `upload -> <img src>` stored/DOM-XSS chain a tester would otherwise assemble by hand.
        Name/context heuristic (not full dataflow) -> MEDIUM confidence. Iterates lists in a
        fixed order, so edge selection under the cap is deterministic."""
        def candidates_for(file_findings: list[Finding]) -> Iterator[Edge]:
            sources = []
            for f in file_findings:
                if f.category == Category.UPLOAD:
                    sources.append(f)
                elif f.category == Category.ENDPOINT:
                    v = (f.extracted_value or "").lower()
                    if any(h in v for h in self._TAINT_UPLOAD_EP_HINTS):
                        sources.append(f)
            if not sources:
                return

            for sink in file_findings:
                if sink.category != Category.SINK:
                    continue
                if sink.value_type not in ("dom_attr_injection", "dom_attr_sink"):
                    continue
                attr = str(sink.metadata.get("sink_attr", "")).lower()
                src_expr = str(sink.metadata.get("sink_source", "")).lower()
                if attr not in self._TAINT_SINK_ATTRS:
                    continue
                # media token as a substring, OR a response-object root as the FIRST identifier.
                if not (
                    any(h in src_expr for h in self._TAINT_SOURCE_HINTS)
                    or self._sink_source_root(src_expr) in self._TAINT_SOURCE_ROOTS
                ):
                    continue

                # One representative source per sink (prefer an explicit upload surface over an
                # upload/file endpoint) so a widget validated in two places is not linked twice.
                source = next((s for s in sources if s.category == Category.UPLOAD), sources[0])
                if source.category == Category.UPLOAD:
                    label = f"file-upload surface ({source.extracted_value})"
                else:
                    label = f"upload/file endpoint {source.extracted_value[:40]}"
                yield create_taint_edge(
                    source.id,
                    sink.id,
                    reasoning=(
                        f"Potential upload->stored/DOM-XSS chain: {label} + a dynamic "
                        f"'{sink.metadata.get('sink_attr', '')}' value "
                        f"({sink.metadata.get('sink_source', '')}) reaching a DOM sink in the "
                        f"same asset -- verify the value is user/upload-controlled and unencoded"
                    ),
                    sink_source=str(sink.metadata.get("sink_source", "")),
                    sink_attr=str(sink.metadata.get("sink_attr", "")),
                )

        self._emit_fair_edges(
            graph,
            (
                (file_url, candidates_for(by_file[file_url]))
                for file_url in sorted(by_file)
            ),
        )

    def _collect_imports(self, findings: list[Finding]) -> set[str]:
        """Collect unique import sources from finding metadata."""
        imports: set[str] = set()
        for finding in findings:
            for source in finding.metadata.get("imports", []):
                if isinstance(source, str) and source.strip():
                    imports.add(source.strip())
        return imports

    def _collect_dynamic_imports(self, findings: list[Finding]) -> set[str]:
        """Collect unique dynamic import sources from finding metadata."""
        imports: set[str] = set()
        for finding in findings:
            for source in finding.metadata.get("dynamic_imports", []):
                if isinstance(source, str) and source.strip():
                    imports.add(source.strip())
        return imports

    def _collect_call_graph(self, findings: list[Finding]) -> dict[str, list[str]]:
        """Collect a merged call graph from finding metadata."""
        merged: dict[str, set[str]] = defaultdict(set)
        for finding in findings:
            raw_graph = finding.metadata.get("call_graph", {})
            if not isinstance(raw_graph, dict):
                continue
            for source_scope, targets in raw_graph.items():
                if not isinstance(source_scope, str):
                    continue
                for target in targets or []:
                    if isinstance(target, str) and target:
                        merged[source_scope].add(target)
        return {scope: sorted(targets) for scope, targets in merged.items()}

    def _collect_import_bindings(self, findings: list[Finding]) -> list[dict[str, object]]:
        """Collect structured import bindings from finding metadata."""
        bindings: list[dict[str, object]] = []
        seen: set[tuple[str, str, str, str, str, bool, bool, bool, bool]] = set()

        for finding in findings:
            raw_bindings = [
                *finding.metadata.get("import_bindings", []),
                *finding.metadata.get("re_export_bindings", []),
            ]
            for binding in raw_bindings:
                if not isinstance(binding, dict):
                    continue
                source = str(binding.get("source") or "").strip()
                local = str(binding.get("local") or "").strip()
                imported = str(binding.get("imported") or "").strip()
                kind = str(binding.get("kind") or "").strip()
                scope = str(binding.get("scope") or "global").strip() or "global"
                is_dynamic = bool(binding.get("is_dynamic"))
                is_reexport = bool(binding.get("is_reexport"))
                is_reexport_all = bool(binding.get("is_reexport_all"))
                is_commonjs_reexport = bool(binding.get("is_commonjs_reexport"))
                key = (
                    source,
                    local,
                    imported,
                    kind,
                    scope,
                    is_dynamic,
                    is_reexport,
                    is_reexport_all,
                    is_commonjs_reexport,
                )
                if not source or not local or key in seen:
                    continue
                seen.add(key)
                bindings.append(
                    {
                        "source": source,
                        "local": local,
                        "imported": imported,
                        "kind": kind,
                        "scope": scope,
                        "is_dynamic": is_dynamic,
                        "is_reexport": is_reexport,
                        "is_reexport_all": is_reexport_all,
                        "is_commonjs_reexport": is_commonjs_reexport,
                    }
                )
        return bindings

    def _collect_scoped_calls(self, findings: list[Finding]) -> dict[str, list[str]]:
        """Collect scope-local call names from finding metadata."""
        merged: dict[str, set[str]] = defaultdict(set)
        for finding in findings:
            raw_calls = finding.metadata.get("scoped_calls", {})
            if not isinstance(raw_calls, dict):
                continue
            for scope, calls in raw_calls.items():
                if not isinstance(scope, str):
                    continue
                for call_name in calls or []:
                    if isinstance(call_name, str) and call_name:
                        merged[scope].add(call_name)
        return {scope: sorted(call_names) for scope, call_names in merged.items()}

    def _collect_export_scopes(self, findings: list[Finding]) -> dict[str, list[str]]:
        """Collect exported-symbol entry scopes from finding metadata."""
        merged: dict[str, set[str]] = defaultdict(set)
        for finding in findings:
            raw_export_scopes = finding.metadata.get("export_scopes", {})
            if not isinstance(raw_export_scopes, dict):
                continue
            for export_name, scopes in raw_export_scopes.items():
                if not isinstance(export_name, str):
                    continue
                for scope in scopes or []:
                    if isinstance(scope, str) and scope:
                        merged[export_name].add(scope)
        return {export_name: sorted(scopes) for export_name, scopes in merged.items()}

    def _collect_default_object_exports(self, findings: list[Finding]) -> set[str]:
        """Collect callable members exposed through a module's default object export."""
        exports: set[str] = set()
        for finding in findings:
            raw_members = finding.metadata.get("default_object_exports", [])
            if not isinstance(raw_members, list):
                continue
            for member in raw_members:
                if isinstance(member, str) and member:
                    exports.add(member)
        return exports

    def _collect_named_object_exports(self, findings: list[Finding]) -> dict[str, set[str]]:
        """Collect callable members exposed through named object exports."""
        exports: dict[str, set[str]] = defaultdict(set)
        for finding in findings:
            raw_members = finding.metadata.get("named_object_exports", {})
            if not isinstance(raw_members, dict):
                continue
            for export_name, members in raw_members.items():
                if not isinstance(export_name, str):
                    continue
                for member in members or []:
                    if isinstance(member, str) and member:
                        exports[export_name].add(member)
        return exports

    def _collect_scope_parents(self, findings: list[Finding]) -> dict[str, list[str]]:
        """Collect lexical parent-scope chains from finding metadata."""
        merged: dict[str, list[str]] = {}
        for finding in findings:
            raw_scope_parents = finding.metadata.get("scope_parents", {})
            if not isinstance(raw_scope_parents, dict):
                continue
            for scope, parents in raw_scope_parents.items():
                if not isinstance(scope, str):
                    continue
                normalized_parents = [
                    parent for parent in (parents or []) if isinstance(parent, str) and parent
                ]
                if not normalized_parents:
                    continue
                existing = merged.get(scope)
                if existing is None or len(normalized_parents) < len(existing):
                    merged[scope] = normalized_parents
        return merged

    def _requested_export_name_for_binding(
        self,
        binding: dict[str, object],
    ) -> str:
        """Resolve the current-module export name accessed through a binding."""
        imported = str(binding.get("imported") or "").strip()
        kind = str(binding.get("kind") or "").strip()
        local = str(binding.get("local") or "").strip()
        if imported and imported not in {"*", "default"}:
            return imported
        if imported == "default" or kind == "default":
            return "default"
        if imported == "*" or kind == "namespace":
            return "*"
        return local

    def _resolve_imported_call_symbol(
        self,
        binding: dict[str, object],
        scope_calls: list[str],
    ) -> tuple[str, str, bool]:
        """Resolve which exported symbol a scope invokes and how it was accessed."""
        local = str(binding.get("local") or "")
        kind = str(binding.get("kind") or "")
        if not local:
            return "", "", False

        for call_name in scope_calls:
            if call_name == local:
                imported = str(binding.get("imported") or "")
                if imported and imported not in {"*", "default"}:
                    return imported, imported, False
                return (
                    local if kind != "default" else "default",
                    self._requested_export_name_for_binding(binding),
                    False,
                )
            if call_name.startswith(f"{local}."):
                member_name = call_name[len(local) + 1 :].split(".", 1)[0]
                if member_name:
                    return member_name, self._requested_export_name_for_binding(binding), True

        return "", "", False

    def _resolve_reexported_symbol(
        self,
        binding: dict[str, object],
        requested_symbol: str,
        requested_export: str,
        requested_member_access: bool,
    ) -> str:
        """Resolve a forwarded symbol through a practical re-export binding."""
        if not binding.get("is_reexport"):
            return ""
        local = str(binding.get("local") or "").strip()
        imported = str(binding.get("imported") or "").strip()
        kind = str(binding.get("kind") or "").strip()

        if binding.get("is_reexport_all"):
            if local not in {"", "*"}:
                if requested_member_access and requested_export == local and kind == "namespace":
                    return requested_symbol
                return ""
            return requested_symbol

        if requested_member_access:
            if (
                requested_export == "default"
                and bool(binding.get("is_commonjs_reexport"))
                and local == requested_symbol
                and imported
                and imported not in {"*", "default"}
            ):
                return imported
            if not local or requested_export != local:
                return ""
            if imported == "*" and kind == "namespace":
                return requested_symbol
            return ""

        if not local or local != (requested_export or requested_symbol):
            return ""
        if imported and imported not in {"*", "default"}:
            return imported
        return local if kind != "default" else "default"

    def _resolve_inter_module_call_targets(
        self,
        file_url: str,
        entry_scope: str,
        by_file: dict[str, list[Finding]],
        file_aliases: dict[str, set[str]],
        max_depth: int = 3,
        visited: set[tuple[str, str]] | None = None,
        requested_symbol: str = "",
        requested_export: str = "",
        requested_member_access: bool = False,
    ) -> list[tuple[Finding, list[str]]]:
        """Resolve directly and transitively reachable cross-module call targets."""
        visited_key = tuple(sorted(visited or set()))
        return self._cache_result(
            (
                "resolve_inter_module_call_targets",
                file_url,
                entry_scope,
                id(by_file),
                id(file_aliases),
                max_depth,
                visited_key,
                requested_symbol,
                requested_export,
                requested_member_access,
            ),
            lambda: self._resolve_inter_module_call_targets_uncached(
                file_url,
                entry_scope,
                by_file,
                file_aliases,
                max_depth=max_depth,
                visited=visited,
                requested_symbol=requested_symbol,
                requested_export=requested_export,
                requested_member_access=requested_member_access,
            ),
        )

    def _resolve_inter_module_call_targets_uncached(
        self,
        file_url: str,
        entry_scope: str,
        by_file: dict[str, list[Finding]],
        file_aliases: dict[str, set[str]],
        max_depth: int = 3,
        visited: set[tuple[str, str]] | None = None,
        requested_symbol: str = "",
        requested_export: str = "",
        requested_member_access: bool = False,
    ) -> list[tuple[Finding, list[str]]]:
        """Resolve directly and transitively reachable cross-module call targets."""
        if max_depth <= 0:
            return []

        visit_key = (
            file_url,
            f"{entry_scope}:{requested_export}:{requested_symbol}:{int(requested_member_access)}",
        )
        if visited and visit_key in visited:
            return []

        module_findings = by_file.get(file_url, [])
        if not module_findings:
            return []

        bindings = self._collect_import_bindings(module_findings)
        scope_call_map = self._collect_scoped_calls(module_findings)
        scope_parents = self._collect_scope_parents(module_findings)
        if not bindings:
            return []
        if not scope_call_map and not requested_symbol:
            return []

        call_graph = self._collect_call_graph(module_findings)
        scope_paths: dict[str, list[list[str]]] = {entry_scope: [[]]}
        scope_paths.update(self._collect_transitive_scope_paths(call_graph, entry_scope))

        next_visited = set(visited or set())
        next_visited.add(visit_key)
        resolved: dict[str, tuple[Finding, list[list[str]]]] = {}

        for scope, scope_prefixes in scope_paths.items():
            scope_calls = scope_call_map.get(scope, [])
            if not scope_calls and not requested_symbol:
                continue

            for scope_prefix in scope_prefixes:
                for binding in bindings:
                    if not self._binding_visible_in_scope(
                        str(binding.get("scope") or "global"),
                        scope,
                        entry_scope,
                        scope_parents,
                    ):
                        continue
                    target_symbol, target_export, target_member_access = (
                        self._resolve_imported_call_symbol(
                            binding,
                            scope_calls,
                        )
                    )
                    if not target_symbol and requested_symbol:
                        target_symbol = self._resolve_reexported_symbol(
                            binding,
                            requested_symbol,
                            requested_export,
                            requested_member_access,
                        )
                        target_export = requested_export
                        target_member_access = requested_member_access
                    can_forward_default_object_member = (
                        not target_symbol
                        and requested_symbol
                        and requested_member_access
                        and requested_export == "default"
                        and str(binding.get("imported") or "").strip() == "default"
                        and str(binding.get("kind") or "").strip() == "default"
                        and bool(binding.get("is_reexport"))
                    )
                    can_forward_named_object_member = (
                        not target_symbol
                        and requested_symbol
                        and requested_member_access
                        and requested_export
                        and requested_export == str(binding.get("local") or "").strip()
                        and bool(binding.get("is_reexport"))
                        and str(binding.get("imported") or "").strip() not in {"", "*", "default"}
                    )
                    if (
                        not target_symbol
                        and not can_forward_default_object_member
                        and not can_forward_named_object_member
                    ):
                        continue

                    import_source = str(binding.get("source") or "")
                    import_prefix = "dynamic:" if binding.get("is_dynamic") else ""

                    target_urls = self._resolve_import_targets(
                        import_source,
                        file_url,
                        file_aliases,
                    )
                    for target_url in target_urls:
                        target_findings = by_file[target_url]
                        effective_target_symbol = target_symbol
                        if (
                            not effective_target_symbol
                            and can_forward_default_object_member
                            and requested_symbol
                            in self._collect_default_object_exports(target_findings)
                        ):
                            effective_target_symbol = requested_symbol
                        if not effective_target_symbol and can_forward_named_object_member:
                            imported_symbol = str(binding.get("imported") or "").strip()
                            if requested_symbol in self._collect_named_object_exports(
                                target_findings
                            ).get(imported_symbol, set()):
                                effective_target_symbol = requested_symbol
                        if not effective_target_symbol:
                            continue

                        next_requested_export = target_export
                        next_requested_member_access = target_member_access
                        if can_forward_default_object_member:
                            next_requested_export = "default"
                            next_requested_member_access = True
                        elif can_forward_named_object_member:
                            next_requested_export = str(binding.get("imported") or "").strip()
                            next_requested_member_access = True

                        matched_targets = self._match_exported_target_findings(
                            target_findings,
                            effective_target_symbol,
                        )
                        for target_finding, target_chain in matched_targets:
                            effective_import_step = (
                                f"{import_prefix}{import_source}:{effective_target_symbol}"
                            )
                            chain = [*scope_prefix, effective_import_step, *target_chain]
                            self._store_shortest_target_chain(
                                resolved,
                                target_finding,
                                chain,
                            )

                        for target_entry_scope in self._entry_scopes_for_symbol(
                            target_findings,
                            effective_target_symbol,
                        ):
                            downstream_targets = self._resolve_inter_module_call_targets(
                                target_url,
                                target_entry_scope,
                                by_file,
                                file_aliases,
                                max_depth=max_depth - 1,
                                visited=next_visited,
                                requested_symbol=effective_target_symbol,
                                requested_export=next_requested_export,
                                requested_member_access=next_requested_member_access,
                            )
                            for target_finding, downstream_chain in downstream_targets:
                                effective_import_step = (
                                    f"{import_prefix}{import_source}:{effective_target_symbol}"
                                )
                                chain = [*scope_prefix, effective_import_step, *downstream_chain]
                                self._store_shortest_target_chain(
                                    resolved,
                                    target_finding,
                                    chain,
                                )

        return self._flatten_resolved_target_chains(resolved)

    def _binding_visible_in_scope(
        self,
        binding_scope: str,
        current_scope: str,
        entry_scope: str,
        scope_parents: dict[str, list[str]],
    ) -> bool:
        """Approximate whether an import binding is usable from a given scope."""
        normalized = (binding_scope or "global").strip() or "global"
        if normalized == "global":
            return True
        if normalized in {current_scope, entry_scope}:
            return True
        return normalized in scope_parents.get(
            current_scope, []
        ) or normalized in scope_parents.get(entry_scope, [])

    def _store_shortest_target_chain(
        self,
        resolved: dict[str, tuple[Finding, list[list[str]]]],
        finding: Finding,
        chain: list[str],
        max_chains: int = 3,
    ) -> None:
        """Keep a small set of distinct shortest chains for a target finding."""
        existing = resolved.get(finding.id)
        if existing is None:
            resolved[finding.id] = (finding, [chain])
            return
        chains = existing[1]
        if chain in chains:
            return
        chains.append(chain)
        chains.sort(key=len)
        del chains[max_chains:]

    def _store_shortest_path_group(
        self,
        resolved: dict[_T, list[list[str]]],
        key: _T,
        chain: list[str],
        max_chains: int = 3,
    ) -> bool:
        """Keep a bounded set of shortest paths and report whether `chain` survived."""
        existing = resolved.get(key)
        if existing is None:
            resolved[key] = [chain]
            return True
        if chain in existing:
            return False
        existing.append(chain)
        existing.sort(key=len)
        del existing[max_chains:]
        return chain in existing

    def _flatten_resolved_target_chains(
        self,
        resolved: dict[str, tuple[Finding, list[list[str]]]],
    ) -> list[tuple[Finding, list[str]]]:
        """Flatten stored chain groups into `(finding, chain)` pairs."""
        flattened: list[tuple[Finding, list[str]]] = []
        for finding, chains in resolved.values():
            for chain in chains:
                flattened.append((finding, chain))
        return flattened

    def _resolve_intra_module_call_targets(
        self,
        findings: list[Finding],
        entry_scope: str,
    ) -> list[tuple[Finding, list[str]]]:
        """Resolve same-file target findings reachable from an entry scope via call graph."""
        return self._cache_result(
            ("resolve_intra_module_call_targets", id(findings), entry_scope),
            lambda: self._resolve_intra_module_call_targets_uncached(findings, entry_scope),
        )

    def _resolve_intra_module_call_targets_uncached(
        self,
        findings: list[Finding],
        entry_scope: str,
    ) -> list[tuple[Finding, list[str]]]:
        """Resolve same-file target findings reachable from an entry scope via call graph."""
        call_graph = self._collect_call_graph(findings)
        if not call_graph:
            return []

        by_scope: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            scope = (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
            by_scope[scope].append(finding)

        reachable_scopes = self._collect_transitive_scope_paths(call_graph, entry_scope)
        if not reachable_scopes:
            return []

        resolved: dict[str, tuple[Finding, list[list[str]]]] = {}
        for target_scope, target_chains in reachable_scopes.items():
            target_findings = by_scope.get(target_scope, [])
            if not target_findings:
                continue
            for target_chain in target_chains:
                for target_finding in target_findings:
                    self._store_shortest_target_chain(
                        resolved,
                        target_finding,
                        target_chain,
                    )
        return self._flatten_resolved_target_chains(resolved)

    def _entry_scope_for_symbol(self, symbol: str) -> str:
        """Map an imported symbol name to its likely entry scope."""
        if symbol and symbol != "default":
            return f"function:{symbol}"
        return "global"

    def _entry_scopes_for_symbol(
        self,
        findings: list[Finding],
        symbol: str,
    ) -> list[str]:
        """Resolve likely entry scopes for an imported/exported symbol."""
        explicit_scopes = self._collect_export_scopes(findings).get(symbol, [])
        if explicit_scopes:
            return explicit_scopes
        return [self._entry_scope_for_symbol(symbol)]

    def _match_exported_target_findings(
        self,
        findings: list[Finding],
        target_symbol: str,
    ) -> list[tuple[Finding, list[str]]]:
        """Find target findings most likely associated with an imported symbol."""
        matches: dict[str, tuple[Finding, list[list[str]]]] = {}
        global_fallback: dict[str, tuple[Finding, list[list[str]]]] = {}
        entry_scopes = self._entry_scopes_for_symbol(findings, target_symbol)
        call_graph = self._collect_call_graph(findings)
        reachable_scopes_by_entry = {
            entry_scope: self._collect_transitive_scope_paths(call_graph, entry_scope)
            for entry_scope in entry_scopes
        }

        for finding in findings:
            scope = (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
            exports = {
                export_name
                for export_name in finding.metadata.get("exports", [])
                if isinstance(export_name, str) and export_name
            }
            for entry_scope in entry_scopes:
                if scope == entry_scope:
                    self._store_shortest_target_chain(matches, finding, [])
                    break
                reachable_scopes = reachable_scopes_by_entry.get(entry_scope, {})
                for reachable_chain in reachable_scopes.get(scope, []):
                    self._store_shortest_target_chain(
                        matches,
                        finding,
                        reachable_chain,
                    )
                if finding.id in matches:
                    break
            if finding.id in matches:
                continue
            if target_symbol in exports and scope == "global":
                self._store_shortest_target_chain(global_fallback, finding, [])
                continue
            if target_symbol == "default" and "default" in exports:
                self._store_shortest_target_chain(global_fallback, finding, [])

        return (
            self._flatten_resolved_target_chains(matches)
            or self._flatten_resolved_target_chains(global_fallback)[:1]
        )

    def _build_initiator_map(
        self,
        by_file: dict[str, list[Finding]],
    ) -> dict[str, set[str]]:
        """Build a direct child->initiator file map from finding metadata."""
        return self._cache_result(
            ("initiator_map", id(by_file)),
            lambda: self._build_initiator_map_uncached(by_file),
        )

    def _build_initiator_map_uncached(
        self,
        by_file: dict[str, list[Finding]],
    ) -> dict[str, set[str]]:
        """Build a direct child->initiator file map from finding metadata."""
        initiator_map: dict[str, set[str]] = defaultdict(set)
        for file_url, findings in by_file.items():
            for finding in findings:
                initiator = (finding.metadata.get("initiator") or "").strip()
                if initiator and initiator != file_url:
                    initiator_map[file_url].add(initiator)
        return initiator_map

    def _build_initiator_children_map(
        self,
        initiator_map: dict[str, set[str]],
    ) -> dict[str, set[str]]:
        """Build a direct initiator->children file map from a child->initiator map."""
        return self._cache_result(
            ("initiator_children_map", id(initiator_map)),
            lambda: self._build_initiator_children_map_uncached(initiator_map),
        )

    def _build_initiator_children_map_uncached(
        self,
        initiator_map: dict[str, set[str]],
    ) -> dict[str, set[str]]:
        """Build a direct initiator->children file map from a child->initiator map."""
        initiator_children: dict[str, set[str]] = defaultdict(set)
        for child_url, initiators in initiator_map.items():
            for initiator in initiators:
                initiator_children[initiator].add(child_url)
        return initiator_children

    def _build_file_load_contexts(
        self,
        by_file: dict[str, list[Finding]],
    ) -> dict[str, set[str]]:
        """Build a file->load-context map from finding metadata."""
        return self._cache_result(
            ("file_load_contexts", id(by_file)),
            lambda: self._build_file_load_contexts_uncached(by_file),
        )

    def _build_file_load_contexts_uncached(
        self,
        by_file: dict[str, list[Finding]],
    ) -> dict[str, set[str]]:
        """Build a file->load-context map from finding metadata."""
        load_contexts: dict[str, set[str]] = defaultdict(set)
        for file_url, findings in by_file.items():
            for finding in findings:
                load_context = (finding.metadata.get("load_context") or "").strip()
                if load_context:
                    load_contexts[file_url].add(load_context)
        return load_contexts

    def _collect_initiator_ancestor_chains(
        self,
        file_url: str,
        initiator_map: dict[str, set[str]],
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Collect direct and transitive initiator chains for a target file."""
        return self._cache_result(
            ("initiator_ancestor_chains", file_url, id(initiator_map), max_depth),
            lambda: self._collect_initiator_ancestor_chains_uncached(
                file_url, initiator_map, max_depth
            ),
        )

    def _collect_initiator_ancestor_chains_uncached(
        self,
        file_url: str,
        initiator_map: dict[str, set[str]],
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Collect direct and transitive initiator chains for a target file."""
        chains: list[list[str]] = []
        queue: list[tuple[str, list[str], set[str], int]] = [(file_url, [], {file_url}, 0)]

        while queue:
            current, ancestry, visited, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            initiators = sorted(initiator_map.get(current, set()))
            for initiator in initiators:
                if initiator in visited:
                    continue
                next_ancestry = [initiator, *ancestry]
                chains.append(next_ancestry)
                queue.append((initiator, next_ancestry, {initiator, *visited}, depth + 1))

        chains.sort(key=len, reverse=True)
        return chains

    def _collect_initiator_descendant_paths(
        self,
        source_url: str,
        initiator_children: dict[str, set[str]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, list[list[str]]]:
        """Collect direct and transitive initiator-descendant paths from a root file."""
        return self._cache_result(
            (
                "initiator_descendant_paths",
                source_url,
                id(initiator_children),
                max_depth,
                max_paths_per_target,
            ),
            lambda: self._collect_initiator_descendant_paths_uncached(
                source_url,
                initiator_children,
                max_depth,
                max_paths_per_target,
            ),
        )

    def _collect_initiator_descendant_paths_uncached(
        self,
        source_url: str,
        initiator_children: dict[str, set[str]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, list[list[str]]]:
        """Collect direct and transitive initiator-descendant paths from a root file."""
        paths: dict[str, list[list[str]]] = {}
        queue: deque[tuple[str, list[str], set[str], int]] = deque(
            [(source_url, [], {source_url}, 0)]
        )

        while queue:
            current_url, current_path, visited, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for child_url in sorted(initiator_children.get(current_url, set())):
                if child_url in visited:
                    continue
                next_path = [*current_path, f"initiator:{child_url}"]
                retained = self._store_shortest_path_group(
                    paths, child_url, next_path, max_chains=max_paths_per_target
                )
                if retained:
                    queue.append((child_url, next_path, {child_url, *visited}, depth + 1))

        return paths

    def _collect_transitive_scope_paths(
        self,
        call_graph: dict[str, list[str]],
        entry_scope: str,
        max_depth: int = 5,
    ) -> dict[str, list[list[str]]]:
        """Collect reachable intra-module call-graph scopes from an exported entry scope."""
        # NOT cached by id(call_graph): call_graph is a transient dict freed after use, and
        # CPython reuses the freed address for the next module's call_graph, so an id-keyed
        # cache would return scope paths computed for an UNRELATED module -> wrong inter-module
        # edges and non-deterministic risk scores. Each (call_graph, entry_scope) is computed
        # once per graph, so dropping the cache costs nothing.
        return self._collect_transitive_scope_paths_uncached(call_graph, entry_scope, max_depth)

    def _collect_transitive_scope_paths_uncached(
        self,
        call_graph: dict[str, list[str]],
        entry_scope: str,
        max_depth: int = 5,
    ) -> dict[str, list[list[str]]]:
        """Collect reachable intra-module call-graph scopes from an exported entry scope."""
        if not entry_scope:
            return {}

        paths: dict[str, list[list[str]]] = {entry_scope: [[]]}
        queue: deque[tuple[str, list[str], int]] = deque([(entry_scope, [], 0)])

        while queue:
            current_scope, current_path, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for target_scope in call_graph.get(current_scope, []):
                next_path = [*current_path, target_scope]
                existing = paths.get(target_scope, [])
                if next_path in existing:
                    continue
                if any(len(path) < len(next_path) for path in existing):
                    continue
                if self._store_shortest_path_group(paths, target_scope, next_path):
                    queue.append((target_scope, next_path, depth + 1))

        paths.pop(entry_scope, None)
        return paths

    def _build_file_aliases(self, file_url: str) -> set[str]:
        """Build import-match aliases for a finding file URL."""
        return self._cache_result(
            ("file_aliases", file_url),
            lambda: self._build_file_aliases_uncached(file_url),
        )

    def _build_file_aliases_uncached(self, file_url: str) -> set[str]:
        """Build import-match aliases for a finding file URL."""
        from bundleInspector.core.url_utils import safe_urlparse as urlparse

        parsed = urlparse(file_url)
        raw_path = parsed.path or file_url
        path = PurePosixPath(raw_path.replace("\\", "/"))

        aliases = {
            str(path).lower(),
            path.name.lower(),
            path.stem.lower(),
        }
        if path.stem == "index" and path.parent.name:
            aliases.add(path.parent.name.lower())
            # DQ-G01: expose the full parent-directory path so an implicit directory-index import
            # ("./x/y" -> "/x/y/index.js") matches the directory, not just its last segment.
            aliases.add(str(path.parent).lower())
        if path.suffix:
            aliases.add(str(path.with_suffix("")).lower())
        return {alias for alias in aliases if alias}

    def _normalize_import_source(self, import_source: str) -> set[str]:
        """Normalize an import source into comparable aliases."""
        value = import_source.split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
        path = PurePosixPath(value)
        parts = [p for p in path.parts if p not in (".", "..", "/")]

        if len(parts) > 1:
            # DQ-G01: a MULTI-segment specifier ("./admin/api") must be matched against the target's
            # PATH TAIL, never its bare basename -- otherwise it links any file whose basename is
            # 'api' (e.g. public/api.js). Emit the relative tail plus its trailing sub-suffixes of
            # length >= 2 (so a path-alias rewrite like "@/components/Button" still matches
            # "src/components/Button.js" via "components/button"), the ext-stripped variant, and the
            # index->dir variant. Deliberately NO length-1 basename alias (that is the FP being fixed).
            last = PurePosixPath(parts[-1])
            noext = parts[:-1] + [last.stem] if last.suffix else list(parts)
            aliases = {"/".join(parts).lower(), "/".join(noext).lower()}
            for k in range(2, len(noext)):
                aliases.add("/".join(noext[-k:]).lower())
            if last.stem == "index" and len(noext) >= 2:
                aliases.add("/".join(noext[:-1]).lower())
                for k in range(2, len(noext) - 1):
                    aliases.add("/".join(noext[:-1][-k:]).lower())
            return {alias for alias in aliases if alias}

        # single-segment specifier ("./api", "api", "react") -- unchanged
        aliases = {
            value.lower(),
            path.name.lower(),
            path.stem.lower(),
        }
        if path.stem == "index" and path.parent.name:
            aliases.add(path.parent.name.lower())
        if path.suffix:
            aliases.add(str(path.with_suffix("")).lower())
        return {alias for alias in aliases if alias}

    def _resolve_import_targets(
        self,
        import_source: str,
        importer_url: str,
        file_aliases: dict[str, set[str]],
    ) -> list[str]:
        """Cached import target resolution for one importer/source/file-set tuple."""
        return self._cache_result(
            (
                "import_targets",
                import_source,
                importer_url,
                tuple(sorted(file_aliases)),
            ),
            lambda: self._resolve_import_targets_uncached(
                import_source,
                importer_url,
                file_aliases,
            ),
        )

    def _resolve_import_targets_uncached(
        self,
        import_source: str,
        importer_url: str,
        file_aliases: dict[str, set[str]],
    ) -> list[str]:
        """Resolve one import without turning an ambiguous basename into confirmed edges.

        Relative and root-relative sources first use the importer's directory and normal
        file/extension/index precedence. Alias matching remains a fallback for package aliases and
        rewritten paths, but it must identify exactly one target.
        """
        from bundleInspector.core.url_utils import safe_urlparse as urlparse

        value = import_source.split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
        is_path_relative = value.startswith(("./", "../", "/"))
        if is_path_relative:
            importer = urlparse(importer_url)
            importer_path = importer.path or importer_url
            if value.startswith("/"):
                resolved_path = posixpath.normpath(value)
            else:
                resolved_path = posixpath.normpath(
                    posixpath.join(posixpath.dirname(importer_path), value)
                )
            resolved_path = "/" + resolved_path.lstrip("/")
            ranked: dict[int, list[str]] = defaultdict(list)
            requested_has_suffix = bool(posixpath.splitext(resolved_path)[1])
            for target_url in sorted(file_aliases):
                if target_url == importer_url:
                    continue
                (
                    target_scheme,
                    target_netloc,
                    target_path,
                    target_without_suffix,
                    target_parent,
                    target_is_index,
                ) = self._import_target_record(target_url)
                if (importer.scheme, importer.netloc) != (target_scheme, target_netloc):
                    continue
                rank: int | None = None
                if target_path.lower() == resolved_path.lower():
                    rank = 0
                elif (
                    not requested_has_suffix
                    and target_without_suffix != target_path
                    and target_without_suffix.lower() == resolved_path.lower()
                ):
                    rank = 1
                elif (
                    not requested_has_suffix
                    and target_is_index
                    and target_parent.lower() == resolved_path.lower()
                ):
                    rank = 2
                if rank is not None:
                    ranked[rank].append(target_url)

            if ranked:
                best_targets = sorted(ranked[min(ranked)])
                if len(best_targets) == 1:
                    return best_targets
                self._record_ambiguous_import(importer_url, import_source, best_targets)
                return []

        normalized_import = self._normalize_import_source(import_source)
        if not normalized_import:
            return []
        matched = sorted(
            target_url
            for target_url, target_aliases in file_aliases.items()
            if target_url != importer_url
            and self._import_matches(normalized_import, target_aliases)
        )
        if len(matched) == 1:
            return matched
        if len(matched) > 1:
            self._record_ambiguous_import(importer_url, import_source, matched)
        return []

    def _import_target_record(self, target_url: str) -> tuple[str, str, str, str, str, bool]:
        """Cache normalized target URL/path fields used by relative import resolution."""
        from bundleInspector.core.url_utils import safe_urlparse as urlparse

        def build() -> tuple[str, str, str, str, str, bool]:
            target = urlparse(target_url)
            target_path = "/" + posixpath.normpath(target.path or target_url).lstrip("/")
            target_without_suffix = posixpath.splitext(target_path)[0]
            target_name = posixpath.basename(target_without_suffix).lower()
            return (
                target.scheme,
                target.netloc,
                target_path,
                target_without_suffix,
                posixpath.dirname(target_path),
                target_name == "index",
            )

        return self._cache_result(("import_target_record", target_url), build)

    def _record_ambiguous_import(
        self,
        importer_url: str,
        import_source: str,
        targets: list[str],
    ) -> None:
        """Store one deterministic unresolved-import diagnostic for graph telemetry."""
        self._ambiguous_import_resolutions.add(
            (importer_url, import_source, tuple(sorted(targets)))
        )

    def _import_matches(self, import_aliases: set[str], target_aliases: set[str]) -> bool:
        """Check whether an import source likely refers to a target file."""
        for import_alias in import_aliases:
            import_multi = "/" in import_alias
            for target_alias in target_aliases:
                if import_alias == target_alias:
                    return True
                # The target PATH ends with the import alias on a '/' boundary (import "./api" ->
                # file "api.js", "./admin/api" -> ".../admin/api.js").
                if self._alias_path_suffix(target_alias, import_alias):
                    return True
                # Reverse (import alias ends with the target's short alias) ONLY for a SINGLE-segment
                # import: a multi-segment import tail must be a genuine path suffix of the target and
                # must NOT be satisfied by the target's bare basename (DQ-G01: 'admin/api' ends with
                # '/api', but that must not link 'public/api.js'). A raw endswith is boundary-gated so
                # "./auth" still does not link "oauth.js".
                if not import_multi and self._alias_path_suffix(import_alias, target_alias):
                    return True
        return False

    @staticmethod
    def _alias_path_suffix(alias: str, suffix: str) -> bool:
        """True when `suffix` is a strict path-segment suffix of `alias` (the character before the
        match is a '/'), so 'oauth' does NOT match 'auth' but '/src/api' matches 'api'."""
        return len(suffix) < len(alias) and ("/" + alias).endswith("/" + suffix)

    def _build_dependency_graph(
        self,
        by_file: dict[str, list[Finding]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, dict[str, list[list[str]]]]:
        """Build direct and transitive import reachability between files."""
        return self._cache_result(
            ("dependency_graph", id(by_file), max_depth, max_paths_per_target),
            lambda: self._build_dependency_graph_uncached(by_file, max_depth, max_paths_per_target),
        )

    def _build_dependency_graph_uncached(
        self,
        by_file: dict[str, list[Finding]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, dict[str, list[list[str]]]]:
        """Build direct and transitive import reachability between files."""
        direct_edges = self._build_direct_dependency_edges(by_file)

        reachable: dict[str, dict[str, list[list[str]]]] = {}
        for source_url in by_file:
            source_reachable: dict[str, list[list[str]]] = {}
            queue: deque[tuple[str, list[str], int, set[str]]] = deque(
                (
                    target_url,
                    [label],
                    1,
                    {source_url, target_url},
                )
                for target_url, label in direct_edges.get(source_url, [])
            )
            while queue:
                current_url, chain, depth, visited = queue.popleft()
                if depth > max_depth:
                    continue
                retained = self._store_shortest_path_group(
                    source_reachable,
                    current_url,
                    chain,
                    max_chains=max_paths_per_target,
                )
                if not retained:
                    continue
                if depth == max_depth:
                    continue
                for next_url, label in direct_edges.get(current_url, []):
                    if next_url in visited:
                        continue
                    queue.append(
                        (
                            next_url,
                            [*chain, label],
                            depth + 1,
                            {next_url, *visited},
                        )
                    )
            reachable[source_url] = source_reachable

        return reachable

    def _build_direct_dependency_edges(
        self,
        by_file: dict[str, list[Finding]],
    ) -> dict[str, list[tuple[str, str]]]:
        """Build direct dependency edges between files from import and binding metadata."""
        return self._cache_result(
            ("direct_dependency_edges", id(by_file)),
            lambda: self._build_direct_dependency_edges_uncached(by_file),
        )

    def _build_direct_dependency_edges_uncached(
        self,
        by_file: dict[str, list[Finding]],
    ) -> dict[str, list[tuple[str, str]]]:
        """Build direct dependency edges between files from import and binding metadata."""
        file_aliases = {file_url: self._build_file_aliases(file_url) for file_url in by_file}
        direct_edges: dict[str, list[tuple[str, str]]] = defaultdict(list)

        for file_url, source_findings in by_file.items():
            imports = {
                (import_source, False) for import_source in self._collect_imports(source_findings)
            }
            imports.update(
                (import_source, True)
                for import_source in self._collect_dynamic_imports(source_findings)
            )
            for binding in self._collect_import_bindings(source_findings):
                import_source = str(binding.get("source") or "").strip()
                if not import_source:
                    continue
                imports.add((import_source, bool(binding.get("is_dynamic"))))

            for import_source, is_dynamic in sorted(imports):
                target_urls = self._resolve_import_targets(
                    import_source,
                    file_url,
                    file_aliases,
                )
                for target_url in target_urls:
                    direct_edges[file_url].append(
                        (
                            target_url,
                            f"dynamic:{import_source}" if is_dynamic else import_source,
                        )
                    )

        return direct_edges

    def _collect_mixed_runtime_execution_paths(
        self,
        source_url: str,
        direct_dependency_edges: dict[str, list[tuple[str, str]]],
        initiator_children: dict[str, set[str]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, list[list[str]]]:
        """Collect mixed import/initiator execution paths that start from one root file."""
        return self._cache_result(
            (
                "mixed_runtime_execution_paths",
                source_url,
                id(direct_dependency_edges),
                id(initiator_children),
                max_depth,
                max_paths_per_target,
            ),
            lambda: self._collect_mixed_runtime_execution_paths_uncached(
                source_url,
                direct_dependency_edges,
                initiator_children,
                max_depth,
                max_paths_per_target,
            ),
        )

    def _collect_mixed_runtime_execution_paths_uncached(
        self,
        source_url: str,
        direct_dependency_edges: dict[str, list[tuple[str, str]]],
        initiator_children: dict[str, set[str]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, list[list[str]]]:
        """Collect mixed import/initiator execution paths that start from one root file."""
        resolved: dict[str, list[list[str]]] = {}
        queued_paths: dict[tuple[str, bool, bool], list[list[str]]] = {
            (source_url, False, False): [[]]
        }
        queue: deque[tuple[str, list[str], bool, bool, set[str], int]] = deque(
            [(source_url, [], False, False, {source_url}, 0)]
        )

        while queue:
            current_url, chain, saw_import, saw_initiator, visited, depth = queue.popleft()
            if depth >= max_depth:
                continue

            next_steps: list[tuple[str, str, bool, bool]] = [
                (target_url, label, True, False)
                for target_url, label in direct_dependency_edges.get(current_url, [])
            ]
            next_steps.extend(
                (child_url, f"initiator:{child_url}", False, True)
                for child_url in sorted(initiator_children.get(current_url, set()))
            )

            for next_url, step_label, is_import, is_initiator in next_steps:
                if next_url in visited:
                    continue
                next_chain = [*chain, step_label]
                next_saw_import = saw_import or is_import
                next_saw_initiator = saw_initiator or is_initiator
                if next_saw_import and next_saw_initiator:
                    self._store_shortest_path_group(
                        resolved,
                        next_url,
                        next_chain,
                        max_chains=max_paths_per_target,
                    )
                state_key = (next_url, next_saw_import, next_saw_initiator)
                if not self._store_shortest_path_group(
                    queued_paths,
                    state_key,
                    next_chain,
                    max_chains=max_paths_per_target,
                ):
                    continue
                queue.append(
                    (
                        next_url,
                        next_chain,
                        next_saw_import,
                        next_saw_initiator,
                        {next_url, *visited},
                        depth + 1,
                    )
                )

        return resolved

    def _collect_runtime_execution_paths(
        self,
        source_url: str,
        direct_dependency_edges: dict[str, list[tuple[str, str]]],
        initiator_children: dict[str, set[str]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, list[list[str]]]:
        """Collect transitive runtime execution paths across any practical import/dynamic/initiator mix."""
        return self._cache_result(
            (
                "runtime_execution_paths",
                source_url,
                id(direct_dependency_edges),
                id(initiator_children),
                max_depth,
                max_paths_per_target,
            ),
            lambda: self._collect_runtime_execution_paths_uncached(
                source_url,
                direct_dependency_edges,
                initiator_children,
                max_depth,
                max_paths_per_target,
            ),
        )

    def _collect_runtime_execution_paths_uncached(
        self,
        source_url: str,
        direct_dependency_edges: dict[str, list[tuple[str, str]]],
        initiator_children: dict[str, set[str]],
        max_depth: int = 5,
        max_paths_per_target: int = 3,
    ) -> dict[str, list[list[str]]]:
        """Collect transitive runtime execution paths across any practical import/dynamic/initiator mix."""
        resolved: dict[str, list[list[str]]] = {}
        queue: deque[tuple[str, list[str], set[str], int]] = deque(
            [(source_url, [], {source_url}, 0)]
        )

        while queue:
            current_url, chain, visited, depth = queue.popleft()
            if depth >= max_depth:
                continue

            next_steps: list[tuple[str, str]] = [
                (target_url, label)
                for target_url, label in direct_dependency_edges.get(current_url, [])
            ]
            next_steps.extend(
                (child_url, f"initiator:{child_url}")
                for child_url in sorted(initiator_children.get(current_url, set()))
            )

            for next_url, step_label in next_steps:
                if next_url in visited:
                    continue
                next_chain = [*chain, step_label]
                retained = self._store_shortest_path_group(
                    resolved,
                    next_url,
                    next_chain,
                    max_chains=max_paths_per_target,
                )
                if not retained:
                    continue
                queue.append(
                    (
                        next_url,
                        next_chain,
                        {next_url, *visited},
                        depth + 1,
                    )
                )

        return resolved

    def _chain_targets(
        self,
        source_url: str,
        chain: list[str],
        direct_edges: dict[str, list[tuple[str, str]]],
    ) -> list[tuple[str, str]]:
        """Resolve the visited target sequence for a label chain."""
        visited: list[tuple[str, str]] = []
        current_url = source_url
        for label in chain:
            next_match = next(
                (
                    (target_url, edge_label)
                    for target_url, edge_label in direct_edges.get(current_url, [])
                    if edge_label == label
                ),
                None,
            )
            if not next_match:
                break
            visited.append(next_match)
            current_url = next_match[0]
        return visited
