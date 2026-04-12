"""
Correlation graph for connecting findings.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
from bundleInspector.correlator.edges import (
    create_call_chain_edge,
    create_import_edge,
    create_same_file_edge,
    create_config_edge,
    create_runtime_edge,
)
from bundleInspector.correlator.cluster import ClusterBuilder
from bundleInspector.storage.models import (
    Category,
    Cluster,
    Correlation,
    Edge,
    EdgeType,
    Finding,
    Severity,
)


class CorrelationGraph:
    """
    Graph of correlations between findings.
    """

    def __init__(self):
        self.edges: list[Edge] = []
        self.clusters: list[Cluster] = []
        self._edge_keys: set[tuple[str, str, EdgeType, str]] = set()

        # Indexes
        self._by_source: dict[str, list[Edge]] = defaultdict(list)
        self._by_target: dict[str, list[Edge]] = defaultdict(list)

    def add_edge(self, edge: Edge) -> None:
        """Add an edge to the graph."""
        source_id, target_id = sorted([edge.source_id, edge.target_id])
        edge_key = (source_id, target_id, edge.edge_type, edge.reasoning)
        if edge_key in self._edge_keys:
            return
        self._edge_keys.add(edge_key)
        self.edges.append(edge)
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

    def __init__(self):
        self._cluster_builder = ClusterBuilder()
        self._correlation_cache: dict[tuple[object, ...], object] | None = None

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

            # Build clusters
            graph.clusters = self._cluster_builder.build(findings)

            # Assign findings to clusters (dict lookup instead of O(N) scan)
            # Each finding gets assigned to the first matching cluster only
            findings_by_id = {f.id: f for f in findings}
            for cluster in graph.clusters:
                for finding_id in cluster.finding_ids:
                    finding = findings_by_id.get(finding_id)
                    if finding and not finding.cluster_id:
                        finding.cluster_id = cluster.id

            return graph
        finally:
            self._correlation_cache = None

    def _cache_result(
        self,
        key: tuple[object, ...],
        factory,
    ):
        """Reuse expensive correlation-pass computations during one correlate() call."""
        cache = self._correlation_cache
        if cache is None:
            return factory()
        if key not in cache:
            cache[key] = factory()
        return cache[key]

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
        from urllib.parse import urlparse

        groups: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.category == Category.ENDPOINT:
                value = finding.extracted_value
                if value.startswith(("http://", "https://")):
                    parsed = urlparse(value)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    groups[base].append(finding)

        return groups

    def _add_same_file_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
        file_url: str,
    ) -> None:
        """Add edges for findings in the same file."""
        # Limit to avoid explosion
        max_edges = 50

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

        count = 0
        for i, f1 in enumerate(sorted_findings):
            for f2 in sorted_findings[i+1:]:
                if count >= max_edges:
                    return

                graph.add_edge(create_same_file_edge(
                    f1.id, f2.id, file_url
                ))
                count += 1

    def _add_config_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
        base_url: str,
    ) -> None:
        """Add edges for findings sharing config."""
        max_edges = 30

        count = 0
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                if count >= max_edges:
                    return

                graph.add_edge(create_config_edge(
                    f1.id, f2.id, f"baseURL: {base_url}"
                ))
                count += 1

    def _add_import_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add edges for findings connected by imports between files."""
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }

        for file_url, source_findings in by_file.items():
            imports = self._collect_imports(source_findings)
            if not imports:
                continue

            for import_source in imports:
                normalized_import = self._normalize_import_source(import_source)
                if not normalized_import:
                    continue

                for target_url, target_findings in by_file.items():
                    if target_url == file_url:
                        continue
                    if not self._import_matches(normalized_import, file_aliases[target_url]):
                        continue

                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if count >= max_edges:
                                return
                            graph.add_edge(create_import_edge(
                                source_finding.id,
                                target_finding.id,
                                import_source,
                            ))
                            count += 1

    def _add_dynamic_import_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add edges for findings connected by dynamic imports between files."""
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }

        for file_url, source_findings in by_file.items():
            dynamic_imports = self._collect_dynamic_imports(source_findings)
            if not dynamic_imports:
                continue

            for import_source in dynamic_imports:
                normalized_import = self._normalize_import_source(import_source)
                if not normalized_import:
                    continue

                for target_url, target_findings in by_file.items():
                    if target_url == file_url:
                        continue
                    if not self._import_matches(normalized_import, file_aliases[target_url]):
                        continue

                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if count >= max_edges:
                                return
                            graph.add_edge(create_import_edge(
                                source_finding.id,
                                target_finding.id,
                                f"dynamic:{import_source}",
                            ))
                            count += 1

    def _add_transitive_import_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add import edges for multi-hop import chains across files."""
        max_edges = 50
        count = 0
        dependency_graph = self._build_dependency_graph(by_file)

        for source_url, reachable in dependency_graph.items():
            source_findings = by_file.get(source_url, [])
            if not source_findings:
                continue

            for target_url, import_chains in reachable.items():
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
                            if count >= max_edges:
                                return
                            graph.add_edge(create_import_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            ))
                            count += 1

    def _add_runtime_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
    ) -> None:
        """Add edges for findings loaded together by runtime context."""
        max_edges = 50
        count = 0

        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            load_context = (finding.metadata.get("load_context") or "").strip()
            initiator = (finding.metadata.get("initiator") or "").strip()
            if load_context:
                groups[f"load_context:{load_context}"].append(finding)
            if initiator:
                groups[f"initiator:{initiator}"].append(finding)

        for context, group in groups.items():
            for i, f1 in enumerate(group):
                for f2 in group[i+1:]:
                    if count >= max_edges:
                        return
                    if f1.evidence.file_url == f2.evidence.file_url:
                        continue
                    graph.add_edge(create_runtime_edge(
                        f1.id,
                        f2.id,
                        context,
                    ))
                    count += 1

    def _add_initiator_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges from initiating JS files to directly or transitively loaded files."""
        max_edges = 50
        count = 0
        initiator_map = self._build_initiator_map(by_file)

        for target_url, target_findings in by_file.items():
            ancestor_chains = self._collect_initiator_ancestor_chains(target_url, initiator_map)
            if not ancestor_chains:
                continue
            for target_finding in target_findings:
                for ancestor_chain in ancestor_chains:
                    source_url = ancestor_chain[0]
                    source_findings = by_file.get(source_url, [])
                    if not source_findings:
                        continue
                    if len(ancestor_chain) == 1:
                        context = f"initiator_chain:{source_url}"
                    else:
                        context = f"initiator_chain:{' -> '.join(ancestor_chain)}"
                    for source_finding in source_findings:
                        if count >= max_edges:
                            return
                        if source_finding.id == target_finding.id:
                            continue
                        graph.add_edge(create_runtime_edge(
                            source_finding.id,
                            target_finding.id,
                            context,
                        ))
                        count += 1

    def _add_execution_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for mixed import/initiator execution paths without requiring load-context metadata."""
        max_edges = 50
        count = 0
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )

        for source_url, source_findings in by_file.items():
            if not source_findings:
                continue

            reachable = self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url, execution_chains in reachable.items():
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for execution_chain in execution_chains:
                    context = f"execution_chain:{source_url} -> {' -> '.join(execution_chain)}"
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if count >= max_edges:
                                return
                            if source_finding.id == target_finding.id:
                                continue
                            graph.add_edge(create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            ))
                            count += 1

    def _add_runtime_execution_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add unified runtime edges across practical import/dynamic/initiator execution paths."""
        max_edges = 50
        count = 0
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )

        for source_url, source_findings in by_file.items():
            if not source_findings:
                continue
            reachable = self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url, execution_chains in reachable.items():
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue
                for execution_chain in execution_chains:
                    context = f"runtime_execution_graph:{source_url} -> {' -> '.join(execution_chain)}"
                    for source_finding in source_findings:
                        for target_finding in target_findings:
                            if count >= max_edges:
                                return
                            if source_finding.id == target_finding.id:
                                continue
                            graph.add_edge(create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            ))
                            count += 1

    def _add_load_context_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges from load-context roots through transitive initiator chains."""
        max_edges = 50
        count = 0
        initiator_map = self._build_initiator_map(by_file)
        file_load_contexts = self._build_file_load_contexts(by_file)

        for target_url, target_findings in by_file.items():
            ancestor_chains = self._collect_initiator_ancestor_chains(target_url, initiator_map)
            if not ancestor_chains:
                continue
            for target_finding in target_findings:
                for ancestor_chain in ancestor_chains:
                    source_url = ancestor_chain[0]
                    source_findings = by_file.get(source_url, [])
                    load_contexts = sorted(file_load_contexts.get(source_url, set()))
                    if not source_findings or not load_contexts:
                        continue
                    if len(ancestor_chain) == 1:
                        base_chain = source_url
                    else:
                        base_chain = " -> ".join(ancestor_chain)
                    for load_context in load_contexts:
                        context = f"load_context_chain:{load_context} -> {base_chain}"
                        for source_finding in source_findings:
                            if count >= max_edges:
                                return
                            if source_finding.id == target_finding.id:
                                continue
                            graph.add_edge(create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            ))
                            count += 1

    def _add_initiator_execution_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for imported call chains reached through initiator-loaded descendants."""
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
        reachable_by_source = {
            source_url: self._collect_initiator_descendant_paths(
                source_url,
                initiator_children,
            )
            for source_url in by_file
        }
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for source_url, reachable in reachable_by_source.items():
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                continue

            for intermediate_url, path_chains in reachable.items():
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted({
                    (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                    for finding in intermediate_findings
                })

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
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                ))
                                count += 1

    def _add_initiator_execution_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside initiator-loaded descendants."""
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        max_edges = 50
        count = 0
        dependency_graph = self._build_dependency_graph(by_file)

        for source_url, reachable in dependency_graph.items():
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                continue

            for target_url, import_chains in reachable.items():
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
                            if count >= max_edges:
                                return
                            if source_finding.id == target_finding.id:
                                continue
                            graph.add_edge(create_runtime_edge(
                                source_finding.id,
                                target_finding.id,
                                context,
                            ))
                            count += 1

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
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for source_url, source_findings in by_file.items():
            if not source_findings:
                continue

            reachable = self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for intermediate_url, path_chains in reachable.items():
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted({
                    (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                    for finding in intermediate_findings
                })

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
                                f"execution_call_chain:{source_url} -> "
                                + " -> ".join([*path_chain, intermediate_scope, *target_chain])
                            )
                            for source_finding in source_findings:
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                ))
                                count += 1

    def _add_execution_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file call chains inside mixed execution-path modules."""
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        max_edges = 50
        count = 0
        dependency_graph = self._build_dependency_graph(by_file)
        file_load_contexts = self._build_file_load_contexts(by_file)

        for source_url, reachable in dependency_graph.items():
            source_findings = by_file.get(source_url, [])
            load_contexts = sorted(file_load_contexts.get(source_url, set()))
            if not source_findings or not load_contexts:
                continue

            for target_url, import_chains in reachable.items():
                if target_url == source_url or not import_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for import_chain in import_chains:
                    if not import_chain:
                        continue
                    for load_context in load_contexts:
                        context = f"load_context_import_chain:{load_context} -> {' -> '.join(import_chain)}"
                        for source_finding in source_findings:
                            for target_finding in target_findings:
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                ))
                                count += 1

    def _add_load_context_execution_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for mixed import/initiator execution paths from load-context roots."""
        max_edges = 50
        count = 0
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
        file_load_contexts = self._build_file_load_contexts(by_file)

        for source_url, source_findings in by_file.items():
            load_contexts = sorted(file_load_contexts.get(source_url, set()))
            if not source_findings or not load_contexts:
                continue

            reachable = self._collect_mixed_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url, execution_chains in reachable.items():
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue

                for execution_chain in execution_chains:
                    for load_context in load_contexts:
                        context = (
                            "load_context_execution_chain:"
                            f"{load_context} -> {' -> '.join(execution_chain)}"
                        )
                        for source_finding in source_findings:
                            for target_finding in target_findings:
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                ))
                                count += 1

    def _add_load_context_runtime_execution_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add unified runtime edges from load-context roots across any practical execution path."""
        max_edges = 50
        count = 0
        direct_dependency_edges = self._build_direct_dependency_edges(by_file)
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
        file_load_contexts = self._build_file_load_contexts(by_file)

        for source_url, source_findings in by_file.items():
            load_contexts = sorted(file_load_contexts.get(source_url, set()))
            if not source_findings or not load_contexts:
                continue
            reachable = self._collect_runtime_execution_paths(
                source_url,
                direct_dependency_edges,
                initiator_children,
            )
            for target_url, execution_chains in reachable.items():
                if target_url == source_url or not execution_chains:
                    continue
                target_findings = by_file.get(target_url, [])
                if not target_findings:
                    continue
                for execution_chain in execution_chains:
                    for load_context in load_contexts:
                        context = (
                            "load_context_runtime_execution_graph:"
                            f"{load_context} -> {' -> '.join(execution_chain)}"
                        )
                        for source_finding in source_findings:
                            for target_finding in target_findings:
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                ))
                                count += 1

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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        initiator_children = self._build_initiator_children_map(
            self._build_initiator_map(by_file)
        )
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
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        file_load_contexts = self._build_file_load_contexts(by_file)
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for source_url, reachable in reachable_by_source.items():
            source_findings = by_file.get(source_url, [])
            load_contexts = sorted(file_load_contexts.get(source_url, set()))
            if not source_findings or not load_contexts or not reachable:
                continue

            for intermediate_url, path_chains in reachable.items():
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted({
                    (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                    for finding in intermediate_findings
                })

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
                            for load_context in load_contexts:
                                context = f"{context_prefix}:{load_context} -> {context_suffix}"
                                for source_finding in source_findings:
                                    if count >= max_edges:
                                        return
                                    if source_finding.id == target_finding.id:
                                        continue
                                    graph.add_edge(create_runtime_edge(
                                        source_finding.id,
                                        target_finding.id,
                                        context,
                                    ))
                                    count += 1

    def _add_runtime_downstream_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
        reachable_by_source: dict[str, dict[str, list[list[str]]]],
        context_prefix: str,
    ) -> None:
        """Add runtime edges for downstream-module imported call chains without load-context metadata."""
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for source_url, reachable in reachable_by_source.items():
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                continue

            for intermediate_url, path_chains in reachable.items():
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted({
                    (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                    for finding in intermediate_findings
                })

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
                            context_suffix = " -> ".join([*path_chain, intermediate_scope, *target_chain])
                            context = f"{context_prefix}:{source_url} -> {context_suffix}"
                            for source_finding in source_findings:
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_runtime_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    context,
                                ))
                                count += 1

    def _add_runtime_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
        reachable_by_source: dict[str, dict[str, list[list[str]]]],
        context_prefix: str,
        include_load_context: bool = False,
    ) -> None:
        """Add runtime edges for same-file call chains inside runtime-reached modules."""
        max_edges = 50
        count = 0
        file_load_contexts = self._build_file_load_contexts(by_file) if include_load_context else {}
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for source_url, reachable in reachable_by_source.items():
            source_findings = by_file.get(source_url, [])
            if not source_findings or not reachable:
                continue

            load_contexts = sorted(file_load_contexts.get(source_url, set())) if include_load_context else []
            if include_load_context and not load_contexts:
                continue

            for intermediate_url, path_chains in reachable.items():
                if intermediate_url == source_url or not path_chains:
                    continue
                intermediate_findings = by_file.get(intermediate_url, [])
                if not intermediate_findings:
                    continue

                intermediate_scopes = sorted({
                    (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                    for finding in intermediate_findings
                })
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
                            context_suffix = " -> ".join([*path_chain, intermediate_scope, *target_chain])
                            contexts = (
                                [f"{context_prefix}:{load_context} -> {context_suffix}" for load_context in load_contexts]
                                if include_load_context
                                else [f"{context_prefix}:{source_url} -> {context_suffix}"]
                            )
                            for context in contexts:
                                for source_finding in source_findings:
                                    if count >= max_edges:
                                        return
                                    if source_finding.id == target_finding.id:
                                        continue
                                    graph.add_edge(create_runtime_edge(
                                        source_finding.id,
                                        target_finding.id,
                                        context,
                                    ))
                                    count += 1

    def _add_call_graph_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add edges for findings connected through intra-file function call graphs."""
        max_edges = 50
        count = 0

        for file_findings in by_file.values():
            call_graph = self._collect_call_graph(file_findings)
            if not call_graph:
                continue

            by_scope: dict[str, list[Finding]] = defaultdict(list)
            for finding in file_findings:
                scope = (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                by_scope[scope].append(finding)

            for source_scope in call_graph:
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
                                if count >= max_edges:
                                    return
                                if source_finding.id == target_finding.id:
                                    continue
                                graph.add_edge(create_call_chain_edge(
                                    source_finding.id,
                                    target_finding.id,
                                    [source_scope, *target_chain],
                                ))
                                count += 1

    def _add_inter_module_call_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add call-chain edges for imported symbols actually invoked by scope."""
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for file_url, source_findings in by_file.items():
            for source_finding in source_findings:
                source_scope = (source_finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                cache_key = (file_url, source_scope)
                if cache_key not in scope_target_cache:
                    scope_target_cache[cache_key] = self._resolve_inter_module_call_targets(
                        file_url,
                        source_scope,
                        by_file,
                        file_aliases,
                    )

                for target_finding, target_chain in scope_target_cache[cache_key]:
                    if count >= max_edges:
                        return
                    if source_finding.id == target_finding.id:
                        continue
                    graph.add_edge(create_call_chain_edge(
                        source_finding.id,
                        target_finding.id,
                        [source_scope, *target_chain],
                    ))
                    count += 1

    def _add_load_context_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for load-context-rooted imported call chains."""
        max_edges = 50
        count = 0
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        file_load_contexts = self._build_file_load_contexts(by_file)
        scope_target_cache: dict[tuple[str, str], list[tuple[Finding, list[str]]]] = {}

        for file_url, source_findings in by_file.items():
            load_contexts = sorted(file_load_contexts.get(file_url, set()))
            if not source_findings or not load_contexts:
                continue

            for source_finding in source_findings:
                source_scope = (source_finding.metadata.get("enclosing_scope") or "global").strip() or "global"
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
                    for load_context in load_contexts:
                        if count >= max_edges:
                            return
                        graph.add_edge(create_runtime_edge(
                            source_finding.id,
                            target_finding.id,
                            "load_context_call_chain:"
                            f"{load_context} -> {' -> '.join([source_scope, *target_chain])}",
                        ))
                        count += 1

    def _add_load_context_scope_call_chain_edges(
        self,
        graph: CorrelationGraph,
        by_file: dict[str, list[Finding]],
    ) -> None:
        """Add runtime edges for same-file transitive call chains inside load-context root files."""
        max_edges = 50
        count = 0
        file_load_contexts = self._build_file_load_contexts(by_file)

        for file_url, file_findings in by_file.items():
            load_contexts = sorted(file_load_contexts.get(file_url, set()))
            if not file_findings or not load_contexts:
                continue

            call_graph = self._collect_call_graph(file_findings)
            if not call_graph:
                continue

            by_scope: dict[str, list[Finding]] = defaultdict(list)
            for finding in file_findings:
                scope = (finding.metadata.get("enclosing_scope") or "global").strip() or "global"
                by_scope[scope].append(finding)

            for source_scope in call_graph:
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
                        for load_context in load_contexts:
                            context = f"load_context_scope_call_chain:{load_context} -> {chain_context}"
                            for source_finding in source_findings:
                                for target_finding in target_findings:
                                    if count >= max_edges:
                                        return
                                    if source_finding.id == target_finding.id:
                                        continue
                                    graph.add_edge(create_runtime_edge(
                                        source_finding.id,
                                        target_finding.id,
                                        context,
                                    ))
                                    count += 1

    def _add_secret_endpoint_edges(
        self,
        graph: CorrelationGraph,
        findings: list[Finding],
    ) -> None:
        """Add edges between secrets and endpoints in same file."""
        secrets = [f for f in findings if f.category == Category.SECRET]
        endpoints = [f for f in findings if f.category == Category.ENDPOINT]
        max_edges = 50
        count = 0

        for secret in secrets:
            for endpoint in endpoints:
                if count >= max_edges:
                    return
                # Same file
                if secret.evidence.file_url == endpoint.evidence.file_url:
                    # Close proximity (within 20 lines); skip unknown lines (0)
                    if (secret.evidence.line > 0 and endpoint.evidence.line > 0
                            and abs(secret.evidence.line - endpoint.evidence.line) < 20):
                        graph.add_edge(Edge(
                            source_id=secret.id,
                            target_id=endpoint.id,
                            edge_type=EdgeType.CALL_CHAIN,
                            confidence=secret.confidence,
                            reasoning="Secret and endpoint in close proximity",
                            metadata={
                                "secret_line": secret.evidence.line,
                                "endpoint_line": endpoint.evidence.line,
                            },
                        ))
                        count += 1

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
        return {
            scope: sorted(targets)
            for scope, targets in merged.items()
        }

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
                bindings.append({
                    "source": source,
                    "local": local,
                    "imported": imported,
                    "kind": kind,
                    "scope": scope,
                    "is_dynamic": is_dynamic,
                    "is_reexport": is_reexport,
                    "is_reexport_all": is_reexport_all,
                    "is_commonjs_reexport": is_commonjs_reexport,
                })
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
        return {
            scope: sorted(call_names)
            for scope, call_names in merged.items()
        }

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
        return {
            export_name: sorted(scopes)
            for export_name, scopes in merged.items()
        }

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
                    parent for parent in (parents or [])
                    if isinstance(parent, str) and parent
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
        local = binding.get("local", "")
        kind = binding.get("kind", "")
        if not local:
            return "", "", False

        for call_name in scope_calls:
            if call_name == local:
                imported = binding.get("imported", "")
                if imported and imported not in {"*", "default"}:
                    return imported, imported, False
                return local if kind != "default" else "default", self._requested_export_name_for_binding(binding), False
            if call_name.startswith(f"{local}."):
                member_name = call_name[len(local) + 1:].split(".", 1)[0]
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
                    target_symbol, target_export, target_member_access = self._resolve_imported_call_symbol(
                        binding,
                        scope_calls,
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

                    import_source = binding.get("source", "")
                    import_aliases = self._normalize_import_source(import_source)
                    if not import_aliases:
                        continue

                    import_prefix = "dynamic:" if binding.get("is_dynamic") else ""

                    for target_url, target_findings in by_file.items():
                        if target_url == file_url:
                            continue
                        if not self._import_matches(import_aliases, file_aliases[target_url]):
                            continue
                        effective_target_symbol = target_symbol
                        if (
                            not effective_target_symbol
                            and can_forward_default_object_member
                            and requested_symbol in self._collect_default_object_exports(target_findings)
                        ):
                            effective_target_symbol = requested_symbol
                        if not effective_target_symbol and can_forward_named_object_member:
                            imported_symbol = str(binding.get("imported") or "").strip()
                            if requested_symbol in self._collect_named_object_exports(target_findings).get(imported_symbol, set()):
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
                            effective_import_step = f"{import_prefix}{import_source}:{effective_target_symbol}"
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
                                effective_import_step = f"{import_prefix}{import_source}:{effective_target_symbol}"
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
        return (
            normalized in scope_parents.get(current_scope, [])
            or normalized in scope_parents.get(entry_scope, [])
        )

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
        resolved: dict[str, list[list[str]]],
        key: str,
        chain: list[str],
        max_chains: int = 3,
    ) -> None:
        """Keep a small set of distinct shortest paths for a string key."""
        existing = resolved.get(key)
        if existing is None:
            resolved[key] = [chain]
            return
        if chain in existing:
            return
        existing.append(chain)
        existing.sort(key=len)
        del existing[max_chains:]

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
                export_name for export_name in finding.metadata.get("exports", [])
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
            lambda: self._collect_initiator_ancestor_chains_uncached(file_url, initiator_map, max_depth),
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
        queue: list[tuple[str, list[str], set[str], int]] = [(source_url, [], {source_url}, 0)]

        while queue:
            current_url, current_path, visited, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for child_url in sorted(initiator_children.get(current_url, set())):
                if child_url in visited:
                    continue
                next_path = [*current_path, f"initiator:{child_url}"]
                self._store_shortest_path_group(paths, child_url, next_path, max_chains=max_paths_per_target)
                queue.append((child_url, next_path, {child_url, *visited}, depth + 1))

        return paths

    def _collect_transitive_scope_paths(
        self,
        call_graph: dict[str, list[str]],
        entry_scope: str,
        max_depth: int = 5,
    ) -> dict[str, list[list[str]]]:
        """Collect reachable intra-module call-graph scopes from an exported entry scope."""
        return self._cache_result(
            ("transitive_scope_paths", id(call_graph), entry_scope, max_depth),
            lambda: self._collect_transitive_scope_paths_uncached(call_graph, entry_scope, max_depth),
        )

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
        queue: list[tuple[str, list[str], int]] = [(entry_scope, [], 0)]

        while queue:
            current_scope, current_path, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for target_scope in call_graph.get(current_scope, []):
                next_path = [*current_path, target_scope]
                existing = paths.get(target_scope, [])
                if next_path in existing:
                    continue
                if any(len(path) < len(next_path) for path in existing):
                    continue
                self._store_shortest_path_group(paths, target_scope, next_path)
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
        from urllib.parse import urlparse

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
        if path.suffix:
            aliases.add(str(path.with_suffix("")).lower())
        return {alias for alias in aliases if alias}

    def _normalize_import_source(self, import_source: str) -> set[str]:
        """Normalize an import source into comparable aliases."""
        value = import_source.split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
        path = PurePosixPath(value)

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

    def _import_matches(self, import_aliases: set[str], target_aliases: set[str]) -> bool:
        """Check whether an import source likely refers to a target file."""
        for import_alias in import_aliases:
            for target_alias in target_aliases:
                if import_alias == target_alias:
                    return True
                if target_alias.endswith(import_alias) or import_alias.endswith(target_alias):
                    return True
        return False

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
            queue: list[tuple[str, list[str], int]] = [
                (target_url, [label], 1)
                for target_url, label in direct_edges.get(source_url, [])
            ]
            while queue:
                current_url, chain, depth = queue.pop(0)
                if depth > max_depth:
                    continue
                existing = source_reachable.setdefault(current_url, [])
                if chain not in existing:
                    existing.append(chain)
                    existing.sort(key=len)
                    del existing[max_paths_per_target:]
                if depth == max_depth:
                    continue
                for next_url, label in direct_edges.get(current_url, []):
                    if next_url == source_url:
                        continue
                    if next_url in {
                        step_target
                        for step_target, _ in self._chain_targets(source_url, chain, direct_edges)
                    }:
                        continue
                    queue.append((next_url, [*chain, label], depth + 1))
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
        file_aliases = {
            file_url: self._build_file_aliases(file_url)
            for file_url in by_file
        }
        direct_edges: dict[str, list[tuple[str, str]]] = defaultdict(list)

        for file_url, source_findings in by_file.items():
            imports = {
                (import_source, False)
                for import_source in self._collect_imports(source_findings)
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
                normalized_import = self._normalize_import_source(import_source)
                if not normalized_import:
                    continue
                for target_url, target_aliases in file_aliases.items():
                    if target_url == file_url:
                        continue
                    if self._import_matches(normalized_import, target_aliases):
                        direct_edges[file_url].append(
                            (target_url, f"dynamic:{import_source}" if is_dynamic else import_source)
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
        queue: list[tuple[str, list[str], bool, bool, set[str], int]] = [
            (source_url, [], False, False, {source_url}, 0)
        ]

        while queue:
            current_url, chain, saw_import, saw_initiator, visited, depth = queue.pop(0)
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
                    existing = resolved.setdefault(next_url, [])
                    if next_chain not in existing:
                        existing.append(next_chain)
                        existing.sort(key=len)
                        del existing[max_paths_per_target:]
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
        queue: list[tuple[str, list[str], set[str], int]] = [
            (source_url, [], {source_url}, 0)
        ]

        while queue:
            current_url, chain, visited, depth = queue.pop(0)
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
                self._store_shortest_path_group(
                    resolved,
                    next_url,
                    next_chain,
                    max_chains=max_paths_per_target,
                )
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

