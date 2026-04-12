"""
Edge types for correlation graph.
"""

from __future__ import annotations

from bundleInspector.storage.models import Edge, EdgeType, Confidence


def create_same_file_edge(
    source_id: str,
    target_id: str,
    file_url: str,
) -> Edge:
    """Create edge for findings in the same file."""
    return Edge(
        source_id=source_id,
        target_id=target_id,
        edge_type=EdgeType.SAME_FILE,
        confidence=Confidence.HIGH,
        reasoning=f"Both findings in same file: {file_url}",
        metadata={"file_url": file_url},
    )


def create_import_edge(
    source_id: str,
    target_id: str,
    import_source: str,
) -> Edge:
    """Create edge for findings connected by an import relationship."""
    return Edge(
        source_id=source_id,
        target_id=target_id,
        edge_type=EdgeType.IMPORT,
        confidence=Confidence.MEDIUM,
        reasoning=f"Connected via import: {import_source}",
        metadata={"import_source": import_source},
    )


def create_call_chain_edge(
    source_id: str,
    target_id: str,
    chain: list[str],
) -> Edge:
    """Create edge for findings connected by call chain."""
    return Edge(
        source_id=source_id,
        target_id=target_id,
        edge_type=EdgeType.CALL_CHAIN,
        confidence=Confidence.MEDIUM,
        reasoning=f"Connected via call chain: {' -> '.join(chain)}",
        metadata={"chain": chain},
    )


def create_config_edge(
    source_id: str,
    target_id: str,
    config_key: str,
) -> Edge:
    """Create edge for findings sharing config."""
    return Edge(
        source_id=source_id,
        target_id=target_id,
        edge_type=EdgeType.CONFIG,
        confidence=Confidence.MEDIUM,
        reasoning=f"Share common config: {config_key}",
        metadata={"config_key": config_key},
    )


def create_env_edge(
    source_id: str,
    target_id: str,
    env: str,
) -> Edge:
    """Create edge for findings in same environment branch."""
    return Edge(
        source_id=source_id,
        target_id=target_id,
        edge_type=EdgeType.ENV,
        confidence=Confidence.MEDIUM,
        reasoning=f"Same environment branch: {env}",
        metadata={"environment": env},
    )


def create_runtime_edge(
    source_id: str,
    target_id: str,
    context: str,
) -> Edge:
    """Create edge for findings loaded together at runtime."""
    return Edge(
        source_id=source_id,
        target_id=target_id,
        edge_type=EdgeType.RUNTIME,
        confidence=Confidence.MEDIUM,
        reasoning=f"Loaded together: {context}",
        metadata={"context": context},
    )

