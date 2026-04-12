"""Tests for correlation graph enrichment."""

from tests.fixtures.fake_secrets import FAKE_STRIPE_LIVE
from bundleInspector.correlator.graph import Correlator
from bundleInspector.storage.models import (
    Category,
    Confidence,
    EdgeType,
    Evidence,
    Finding,
    Severity,
)


def _make_finding(
    finding_id: str,
    file_url: str,
    category: Category,
    extracted_value: str,
    metadata: dict | None = None,
) -> Finding:
    """Create a minimal finding for correlator tests."""
    return Finding(
        id=finding_id,
        rule_id=f"rule-{finding_id}",
        category=category,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title=f"Finding {finding_id}",
        description="",
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
        value_type="test",
        metadata=metadata or {},
    )


def test_correlator_adds_import_edges_from_metadata():
    """Files that import another finding file should correlate via import edges."""
    source_finding = _make_finding(
        "source",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={"imports": ["./api"]},
    )
    target_finding = _make_finding(
        "target",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([source_finding, target_finding])

    assert any(edge.edge_type == EdgeType.IMPORT for edge in graph.edges)


def test_correlator_adds_runtime_edges_from_shared_context():
    """Findings loaded in the same runtime context should receive runtime edges."""
    first = _make_finding(
        "first",
        "https://example.com/static/a.js",
        Category.ENDPOINT,
        "/api/a",
        metadata={"load_context": "/dashboard"},
    )
    second = _make_finding(
        "second",
        "https://example.com/static/b.js",
        Category.DEBUG,
        "/debug",
        metadata={"load_context": "/dashboard"},
    )

    graph = Correlator().correlate([first, second])

    assert any(edge.edge_type == EdgeType.RUNTIME for edge in graph.edges)


def test_correlator_adds_call_graph_edges_from_scopes():
    """Findings in caller/callee scopes should receive call-chain edges."""
    caller = _make_finding(
        "caller",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/outer",
        metadata={
            "enclosing_scope": "function:outer",
            "call_graph": {
                "function:outer": ["function:inner"],
            },
        },
    )
    callee = _make_finding(
        "callee",
        "file:///src/app.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:inner",
            "call_graph": {
                "function:outer": ["function:inner"],
            },
        },
    )

    graph = Correlator().correlate([caller, callee])

    assert any(edge.edge_type == EdgeType.CALL_CHAIN for edge in graph.edges)


def test_correlator_preserves_multiple_transitive_intra_file_call_paths():
    """Distinct practical same-file transitive call paths should be preserved."""
    caller = _make_finding(
        "caller-transitive-intra-file",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/outer",
        metadata={
            "enclosing_scope": "function:outer",
            "call_graph": {
                "function:outer": ["function:midA", "function:midB"],
                "function:midA": ["function:inner"],
                "function:midB": ["function:inner"],
            },
        },
    )
    callee = _make_finding(
        "callee-transitive-intra-file",
        "file:///src/app.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:inner",
            "call_graph": {
                "function:outer": ["function:midA", "function:midB"],
                "function:midA": ["function:inner"],
                "function:midB": ["function:inner"],
            },
        },
    )

    graph = Correlator().correlate([caller, callee])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "caller-transitive-intra-file"
        and edge.target_id == "callee-transitive-intra-file"
        and edge.metadata.get("chain") == [
            "function:outer",
            "function:midA",
            "function:inner",
        ]
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "caller-transitive-intra-file"
        and edge.target_id == "callee-transitive-intra-file"
        and edge.metadata.get("chain") == [
            "function:outer",
            "function:midB",
            "function:inner",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_inter_module_call_edges_from_imported_symbol_usage():
    """Imported symbols that are actually invoked by scope should correlate across files."""
    source = _make_finding(
        "source",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={
            "enclosing_scope": "function:loadUsers",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "fetchUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:loadUsers": ["fetchUsers"],
            },
        },
    )
    target = _make_finding(
        "target",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.metadata.get("chain") == ["function:loadUsers", "./api:fetchUsers"]
        for edge in graph.edges
    )


def test_correlator_adds_named_alias_export_call_edges():
    """Aliased named exports should correlate to the underlying exported function scope."""
    source = _make_finding(
        "source-alias-export",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-alias-export",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["loadUsers"],
            "export_scopes": {
                "loadUsers": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.metadata.get("chain") == ["function:boot", "./api:loadUsers"]
        for edge in graph.edges
    )


def test_correlator_does_not_add_inter_module_call_edge_without_invocation():
    """Imported symbols should not create cross-file call edges unless they are invoked."""
    source = _make_finding(
        "source-no-call",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={
            "enclosing_scope": "function:loadUsers",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "fetchUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:loadUsers": ["console.log"],
            },
        },
    )
    target = _make_finding(
        "target-no-call",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.metadata.get("chain") == ["function:loadUsers", "./api:fetchUsers"]
        for edge in graph.edges
    )


def test_correlator_adds_dynamic_import_edges_from_metadata():
    """Dynamic imports should correlate a source file with the loaded chunk file."""
    source = _make_finding(
        "source-dynamic",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    target = _make_finding(
        "target-dynamic",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug",
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.IMPORT
        and edge.metadata.get("import_source") == "dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_runtime_edges_for_initiator_chain():
    """Loaded files should correlate back to the JS file that initiated them."""
    source = _make_finding(
        "source-initiator",
        "https://example.com/static/main.js",
        Category.ENDPOINT,
        "/api/main",
    )
    target = _make_finding(
        "target-initiator",
        "https://example.com/static/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "https://example.com/static/main.js"},
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context") == "initiator_chain:https://example.com/static/main.js"
        for edge in graph.edges
    )


def test_correlator_adds_runtime_edges_for_multiple_possible_initiators():
    """Files seen under multiple initiators should correlate against each initiator chain."""
    main = _make_finding(
        "root-main-runtime",
        "https://example.com/static/main.js",
        Category.ENDPOINT,
        "/api/main",
    )
    vendor = _make_finding(
        "root-vendor-runtime",
        "https://example.com/static/vendor.js",
        Category.ENDPOINT,
        "/api/vendor",
    )
    target_from_main = _make_finding(
        "target-multi-parent-main",
        "https://example.com/static/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "https://example.com/static/main.js"},
    )
    target_from_vendor = _make_finding(
        "target-multi-parent-vendor",
        "https://example.com/static/chunk.js",
        Category.DEBUG,
        "debug",
        metadata={"initiator": "https://example.com/static/vendor.js"},
    )

    graph = Correlator().correlate([main, vendor, target_from_main, target_from_vendor])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-main-runtime"
        and edge.target_id in {"target-multi-parent-main", "target-multi-parent-vendor"}
        and edge.metadata.get("context") == "initiator_chain:https://example.com/static/main.js"
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-vendor-runtime"
        and edge.target_id in {"target-multi-parent-main", "target-multi-parent-vendor"}
        and edge.metadata.get("context") == "initiator_chain:https://example.com/static/vendor.js"
        for edge in graph.edges
    )


def test_correlator_adds_transitive_inter_module_call_edges():
    """Imported entry points should correlate to deeper helper scopes reached through target call graphs."""
    source = _make_finding(
        "source-transitive-call",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={
            "enclosing_scope": "function:loadUsers",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "fetchUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:loadUsers": ["fetchUsers"],
            },
        },
    )
    target_entry = _make_finding(
        "target-entry",
        "file:///src/api.js",
        Category.ENDPOINT,
        "/api/entry",
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
            "call_graph": {
                "function:fetchUsers": ["function:buildAuth"],
            },
        },
    )
    target_helper = _make_finding(
        "target-helper",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "exports": ["fetchUsers"],
            "call_graph": {
                "function:fetchUsers": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([source, target_entry, target_helper])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-helper"
        and edge.metadata.get("chain") == [
            "function:loadUsers",
            "./api:fetchUsers",
            "function:buildAuth",
        ]
        for edge in graph.edges
    )


def test_correlator_preserves_multiple_source_scope_paths_to_same_imported_target():
    """Distinct practical source-side call-graph routes to the same imported call should be preserved."""
    source = _make_finding(
        "source-transitive-call-source-multi",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "fetchUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:dispatchA": ["fetchUsers"],
                "function:dispatchB": ["fetchUsers"],
            },
            "call_graph": {
                "function:boot": ["function:dispatchA", "function:dispatchB"],
            },
        },
    )
    target = _make_finding(
        "target-transitive-call-source-multi",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-transitive-call-source-multi"
        and edge.metadata.get("chain") == [
            "function:boot",
            "function:dispatchA",
            "./api:fetchUsers",
        ]
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-transitive-call-source-multi"
        and edge.metadata.get("chain") == [
            "function:boot",
            "function:dispatchB",
            "./api:fetchUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_preserves_multiple_target_scope_paths_to_same_imported_target():
    """Distinct practical target-side call-graph routes to the same helper should be preserved."""
    source = _make_finding(
        "source-transitive-call-target-multi",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/users",
        metadata={
            "enclosing_scope": "function:loadUsers",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "fetchUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:loadUsers": ["fetchUsers"],
            },
        },
    )
    target_entry = _make_finding(
        "target-entry-target-multi",
        "file:///src/api.js",
        Category.ENDPOINT,
        "/api/entry",
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
            "call_graph": {
                "function:fetchUsers": ["function:buildAuthA", "function:buildAuthB"],
                "function:buildAuthA": ["function:buildAuth"],
                "function:buildAuthB": ["function:buildAuth"],
            },
        },
    )
    target_helper = _make_finding(
        "target-helper-target-multi",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "exports": ["fetchUsers"],
            "call_graph": {
                "function:fetchUsers": ["function:buildAuthA", "function:buildAuthB"],
                "function:buildAuthA": ["function:buildAuth"],
                "function:buildAuthB": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([source, target_entry, target_helper])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-helper-target-multi"
        and edge.metadata.get("chain") == [
            "function:loadUsers",
            "./api:fetchUsers",
            "function:buildAuthA",
            "function:buildAuth",
        ]
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-helper-target-multi"
        and edge.metadata.get("chain") == [
            "function:loadUsers",
            "./api:fetchUsers",
            "function:buildAuthB",
            "function:buildAuth",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_default_export_scope_call_edges():
    """Default imports should reach the exported function scope and its deeper helper scopes."""
    source = _make_finding(
        "source-default-export",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/default",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "apiClient",
                    "kind": "default",
                }
            ],
            "scoped_calls": {
                "function:boot": ["apiClient"],
            },
        },
    )
    target_entry = _make_finding(
        "target-default-entry",
        "file:///src/api.js",
        Category.ENDPOINT,
        "/api/entry",
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["function:fetchUsers"],
            },
            "call_graph": {
                "function:fetchUsers": ["function:buildAuth"],
            },
        },
    )
    target_helper = _make_finding(
        "target-default-helper",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "exports": ["default"],
            "export_scopes": {
                "default": ["function:fetchUsers"],
            },
            "call_graph": {
                "function:fetchUsers": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([source, target_entry, target_helper])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-default-entry"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:default",
        ]
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.target_id == "target-default-helper"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:default",
            "function:buildAuth",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_transitive_runtime_edges_for_nested_initiator_chain():
    """Nested initiator chains should correlate the root initiator to transitively loaded chunks."""
    root = _make_finding(
        "root-runtime",
        "https://example.com/static/main.js",
        Category.ENDPOINT,
        "/api/main",
    )
    middle = _make_finding(
        "middle-runtime",
        "https://example.com/static/vendor.js",
        Category.DEBUG,
        "/debug/vendor",
        metadata={"initiator": "https://example.com/static/main.js"},
    )
    leaf = _make_finding(
        "leaf-runtime",
        "https://example.com/static/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "https://example.com/static/vendor.js"},
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-runtime"
        and edge.target_id == "leaf-runtime"
        and edge.metadata.get("context")
        == "initiator_chain:https://example.com/static/main.js -> https://example.com/static/vendor.js"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_chain_edges_for_nested_initiator_chain():
    """Root load contexts should propagate through nested initiator chains to deeper chunks."""
    root = _make_finding(
        "root-load-context-runtime",
        "https://example.com/static/main.js",
        Category.ENDPOINT,
        "/api/main",
        metadata={"load_context": "/dashboard"},
    )
    middle = _make_finding(
        "middle-load-context-runtime",
        "https://example.com/static/vendor.js",
        Category.DEBUG,
        "/debug/vendor",
        metadata={"initiator": "https://example.com/static/main.js"},
    )
    leaf = _make_finding(
        "leaf-load-context-runtime",
        "https://example.com/static/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "https://example.com/static/vendor.js"},
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-runtime"
        and edge.target_id == "leaf-load-context-runtime"
        and edge.metadata.get("context")
        == "load_context_chain:/dashboard -> https://example.com/static/main.js -> https://example.com/static/vendor.js"
        for edge in graph.edges
    )


def test_correlator_adds_initiator_execution_call_chain_edges_for_downstream_module_calls():
    """Initiator-rooted runtime paths should propagate into downstream imported call chains."""
    root = _make_finding(
        "root-initiator-execution-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
    )
    chunk = _make_finding(
        "chunk-initiator-execution-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-initiator-execution-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, chunk, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-initiator-execution-call-chain"
        and edge.target_id == "target-initiator-execution-call-chain"
        and edge.metadata.get("context")
        == "initiator_execution_call_chain:file:///src/app.js -> initiator:file:///src/chunk.js -> function:loadChunk -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_does_not_add_initiator_execution_call_chain_without_downstream_invocation():
    """Initiator-rooted downstream call-chain runtime edges should require an actual descendant invocation."""
    root = _make_finding(
        "root-no-initiator-execution-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
    )
    chunk = _make_finding(
        "chunk-no-initiator-execution-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["console.log"],
            },
        },
    )
    target = _make_finding(
        "target-no-initiator-execution-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, chunk, target])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("initiator_execution_call_chain:")
        for edge in graph.edges
    )


def test_correlator_adds_load_context_initiator_call_chain_edges_for_downstream_module_calls():
    """Load-context roots should propagate through pure initiator paths into downstream imported call chains."""
    root = _make_finding(
        "root-load-context-initiator-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"load_context": "/dashboard"},
    )
    chunk = _make_finding(
        "chunk-load-context-initiator-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-load-context-initiator-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, chunk, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-initiator-call-chain"
        and edge.target_id == "target-load-context-initiator-call-chain"
        and edge.metadata.get("context")
        == "load_context_initiator_call_chain:/dashboard -> initiator:file:///src/chunk.js -> function:loadChunk -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_execution_chain_edges_for_import_then_initiator_flow():
    """Mixed import/initiator runtime paths should correlate even without load-context metadata."""
    root = _make_finding(
        "root-execution-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-execution-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    leaf = _make_finding(
        "leaf-execution-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/client.js"},
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-execution-chain"
        and edge.target_id == "leaf-execution-chain"
        and edge.metadata.get("context")
        == "execution_chain:file:///src/app.js -> ./client -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )


def test_correlator_adds_execution_call_chain_edges_for_mixed_runtime_paths():
    """Mixed runtime paths should propagate into downstream imported call chains without load-context metadata."""
    root = _make_finding(
        "root-execution-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-execution-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    chunk = _make_finding(
        "chunk-execution-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-execution-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, chunk, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-execution-call-chain"
        and edge.target_id == "target-execution-call-chain"
        and edge.metadata.get("context")
        == "execution_call_chain:file:///src/app.js -> ./client -> initiator:file:///src/chunk.js -> function:loadChunk -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_execution_scope_call_chain_edges_for_runtime_loaded_module_calls():
    """Mixed runtime paths should preserve same-file transitive call chains inside runtime-loaded modules."""
    root = _make_finding(
        "root-execution-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-execution-scope-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    chunk_entry = _make_finding(
        "chunk-entry-execution-scope-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:loadChunk",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )
    chunk_target = _make_finding(
        "chunk-target-execution-scope-call-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, middle, chunk_entry, chunk_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-execution-scope-call-chain"
        and edge.target_id == "chunk-target-execution-scope-call-chain"
        and edge.metadata.get("context")
        == "execution_scope_call_chain:file:///src/app.js -> ./client -> initiator:file:///src/chunk.js -> function:loadChunk -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_initiator_execution_scope_call_chain_edges_for_runtime_loaded_module_calls():
    """Pure initiator runtime paths should preserve same-file transitive call chains inside descendant modules."""
    root = _make_finding(
        "root-initiator-execution-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
    )
    chunk_entry = _make_finding(
        "chunk-entry-initiator-execution-scope-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:loadChunk",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )
    chunk_target = _make_finding(
        "chunk-target-initiator-execution-scope-call-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, chunk_entry, chunk_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-initiator-execution-scope-call-chain"
        and edge.target_id == "chunk-target-initiator-execution-scope-call-chain"
        and edge.metadata.get("context")
        == "initiator_execution_scope_call_chain:file:///src/app.js -> initiator:file:///src/chunk.js -> function:loadChunk -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_does_not_add_execution_call_chain_without_mixed_runtime_path():
    """Execution call-chain edges should require a mixed import/initiator runtime path."""
    root = _make_finding(
        "root-no-execution-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
    )
    chunk = _make_finding(
        "chunk-no-execution-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-no-execution-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, chunk, target])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("execution_call_chain:")
        for edge in graph.edges
    )


def test_correlator_does_not_add_load_context_chain_without_root_context():
    """Load-context chain edges should only appear when the root initiator file has a load context."""
    root = _make_finding(
        "root-no-load-context-runtime",
        "https://example.com/static/main.js",
        Category.ENDPOINT,
        "/api/main",
    )
    middle = _make_finding(
        "middle-no-load-context-runtime",
        "https://example.com/static/vendor.js",
        Category.DEBUG,
        "/debug/vendor",
        metadata={"initiator": "https://example.com/static/main.js"},
    )
    leaf = _make_finding(
        "leaf-no-load-context-runtime",
        "https://example.com/static/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "https://example.com/static/vendor.js"},
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("load_context_chain:")
        for edge in graph.edges
    )


def test_correlator_adds_import_chain_edges_for_transitive_imports():
    """Pure transitive import graphs should produce runtime import-chain edges without load contexts."""
    root = _make_finding(
        "root-import-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-import-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "dynamic_imports": ["./chunk"],
        },
    )
    leaf = _make_finding(
        "leaf-import-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-chain"
        and edge.target_id == "leaf-import-chain"
        and edge.metadata.get("context")
        == "import_chain:file:///src/app.js -> ./client -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_import_chain_edges_from_binding_metadata_through_reexport():
    """Pure import runtime edges should recover transitive chains from structured re-export bindings."""
    root = _make_finding(
        "root-import-chain-reexport-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "import_bindings": [
                {
                    "source": "./index",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                }
            ],
        },
    )
    barrel = _make_finding(
        "barrel-import-chain-reexport-binding",
        "file:///src/index.js",
        Category.DEBUG,
        "/debug/index",
        metadata={
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    leaf = _make_finding(
        "leaf-import-chain-reexport-binding",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, barrel, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-chain-reexport-binding"
        and edge.target_id == "leaf-import-chain-reexport-binding"
        and edge.metadata.get("context")
        == "import_chain:file:///src/app.js -> ./index -> ./api"
        for edge in graph.edges
    )


def test_correlator_adds_import_chain_edges_from_dynamic_binding_metadata():
    """Pure import runtime edges should recover dynamic-import legs from structured binding metadata."""
    root = _make_finding(
        "root-import-chain-dynamic-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
        },
    )
    leaf = _make_finding(
        "leaf-import-chain-dynamic-binding",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-chain-dynamic-binding"
        and edge.target_id == "leaf-import-chain-dynamic-binding"
        and edge.metadata.get("context")
        == "import_chain:file:///src/app.js -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_multiple_import_chains_for_same_target():
    """Pure import runtime edges should preserve distinct transitive import chains to the same target."""
    root = _make_finding(
        "root-import-chain-multi",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "imports": ["./clientA", "./clientB"],
        },
    )
    middle_a = _make_finding(
        "middle-import-chain-a",
        "file:///src/clientA.js",
        Category.DEBUG,
        "/debug/client-a",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    middle_b = _make_finding(
        "middle-import-chain-b",
        "file:///src/clientB.js",
        Category.DEBUG,
        "/debug/client-b",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    leaf = _make_finding(
        "leaf-import-chain-multi",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle_a, middle_b, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-chain-multi"
        and edge.target_id == "leaf-import-chain-multi"
        and edge.metadata.get("context")
        == "import_chain:file:///src/app.js -> ./clientA -> dynamic:./chunk"
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-chain-multi"
        and edge.target_id == "leaf-import-chain-multi"
        and edge.metadata.get("context")
        == "import_chain:file:///src/app.js -> ./clientB -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_import_chain_edges_for_transitive_imports():
    """Root load contexts should propagate through transitive import graphs even without initiator metadata."""
    root = _make_finding(
        "root-load-context-import",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-import",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "dynamic_imports": ["./chunk"],
        },
    )
    leaf = _make_finding(
        "leaf-load-context-import",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import"
        and edge.target_id == "leaf-load-context-import"
        and edge.metadata.get("context")
        == "load_context_import_chain:/dashboard -> ./client -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_import_chain_edges_from_binding_metadata_through_reexport():
    """Load-context import runtime edges should recover transitive chains from structured re-export bindings."""
    root = _make_finding(
        "root-load-context-import-reexport-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "import_bindings": [
                {
                    "source": "./index",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                }
            ],
        },
    )
    barrel = _make_finding(
        "barrel-load-context-import-reexport-binding",
        "file:///src/index.js",
        Category.DEBUG,
        "/debug/index",
        metadata={
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    leaf = _make_finding(
        "leaf-load-context-import-reexport-binding",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, barrel, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-reexport-binding"
        and edge.target_id == "leaf-load-context-import-reexport-binding"
        and edge.metadata.get("context")
        == "load_context_import_chain:/dashboard -> ./index -> ./api"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_import_chain_edges_from_dynamic_binding_metadata():
    """Load-context import runtime edges should recover dynamic-import legs from binding metadata."""
    root = _make_finding(
        "root-load-context-import-dynamic-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
        },
    )
    leaf = _make_finding(
        "leaf-load-context-import-dynamic-binding",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-dynamic-binding"
        and edge.target_id == "leaf-load-context-import-dynamic-binding"
        and edge.metadata.get("context")
        == "load_context_import_chain:/dashboard -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_does_not_add_load_context_import_chain_without_root_context():
    """Load-context import-chain edges should only appear when the root importer has a load context."""
    root = _make_finding(
        "root-no-load-context-import",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-no-load-context-import",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    leaf = _make_finding(
        "leaf-no-load-context-import",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("load_context_import_chain:")
        for edge in graph.edges
    )


def test_correlator_adds_multiple_load_context_import_chains_for_same_target():
    """Root load contexts should preserve distinct transitive import chains to the same target."""
    root = _make_finding(
        "root-load-context-import-multi",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./clientA", "./clientB"],
        },
    )
    middle_a = _make_finding(
        "middle-load-context-import-a",
        "file:///src/clientA.js",
        Category.DEBUG,
        "/debug/client-a",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    middle_b = _make_finding(
        "middle-load-context-import-b",
        "file:///src/clientB.js",
        Category.DEBUG,
        "/debug/client-b",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    leaf = _make_finding(
        "leaf-load-context-import-multi",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle_a, middle_b, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-multi"
        and edge.target_id == "leaf-load-context-import-multi"
        and edge.metadata.get("context")
        == "load_context_import_chain:/dashboard -> ./clientA -> dynamic:./chunk"
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-multi"
        and edge.target_id == "leaf-load-context-import-multi"
        and edge.metadata.get("context")
        == "load_context_import_chain:/dashboard -> ./clientB -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_execution_chain_edges_for_import_then_initiator_flow():
    """Root load contexts should propagate through mixed import then initiator execution paths."""
    root = _make_finding(
        "root-load-context-mixed-import",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-mixed-import",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    leaf = _make_finding(
        "leaf-load-context-mixed-import",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/client.js"},
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-mixed-import"
        and edge.target_id == "leaf-load-context-mixed-import"
        and edge.metadata.get("context")
        == "load_context_execution_chain:/dashboard -> ./client -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )


def test_correlator_adds_execution_chain_edges_from_binding_metadata_through_reexport():
    """Mixed execution runtime edges should recover import legs from structured re-export bindings."""
    root = _make_finding(
        "root-execution-chain-reexport-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "import_bindings": [
                {
                    "source": "./index",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                }
            ],
        },
    )
    barrel = _make_finding(
        "barrel-execution-chain-reexport-binding",
        "file:///src/index.js",
        Category.DEBUG,
        "/debug/index",
        metadata={
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    leaf = _make_finding(
        "leaf-execution-chain-reexport-binding",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/api.js"},
    )
    api = _make_finding(
        "api-execution-chain-reexport-binding",
        "file:///src/api.js",
        Category.DEBUG,
        "/debug/api",
    )

    graph = Correlator().correlate([root, barrel, api, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-execution-chain-reexport-binding"
        and edge.target_id == "leaf-execution-chain-reexport-binding"
        and edge.metadata.get("context")
        == "execution_chain:file:///src/app.js -> ./index -> ./api -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )


def test_correlator_adds_execution_chain_edges_from_dynamic_binding_metadata():
    """Mixed execution runtime edges should recover dynamic-import legs from binding metadata."""
    root = _make_finding(
        "root-execution-chain-dynamic-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
        },
    )
    chunk = _make_finding(
        "chunk-execution-chain-dynamic-binding",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
    )
    leaf = _make_finding(
        "leaf-execution-chain-dynamic-binding",
        "file:///src/worker.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/chunk.js"},
    )

    graph = Correlator().correlate([root, chunk, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-execution-chain-dynamic-binding"
        and edge.target_id == "leaf-execution-chain-dynamic-binding"
        and edge.metadata.get("context")
        == "execution_chain:file:///src/app.js -> dynamic:./chunk -> initiator:file:///src/worker.js"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_execution_chain_edges_for_initiator_then_import_flow():
    """Root load contexts should propagate through mixed initiator then import execution paths."""
    root = _make_finding(
        "root-load-context-mixed-initiator",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"load_context": "/dashboard"},
    )
    middle = _make_finding(
        "middle-load-context-mixed-initiator",
        "file:///src/vendor.js",
        Category.DEBUG,
        "/debug/vendor",
        metadata={
            "initiator": "file:///src/app.js",
            "dynamic_imports": ["./chunk"],
        },
    )
    leaf = _make_finding(
        "leaf-load-context-mixed-initiator",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-mixed-initiator"
        and edge.target_id == "leaf-load-context-mixed-initiator"
        and edge.metadata.get("context")
        == "load_context_execution_chain:/dashboard -> initiator:file:///src/vendor.js -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_does_not_add_load_context_execution_chain_without_root_context():
    """Mixed execution-chain edges should only appear when the root file has a load context."""
    root = _make_finding(
        "root-no-load-context-mixed-execution",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-no-load-context-mixed-execution",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    leaf = _make_finding(
        "leaf-no-load-context-mixed-execution",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/client.js"},
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("load_context_execution_chain:")
        for edge in graph.edges
    )


def test_correlator_adds_multiple_load_context_execution_chains_for_same_target():
    """Mixed execution-chain runtime edges should preserve distinct practical paths to the same target."""
    root = _make_finding(
        "root-load-context-multi-execution",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client", "./vendor"],
        },
    )
    client = _make_finding(
        "client-load-context-multi-execution",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    vendor = _make_finding(
        "vendor-load-context-multi-execution",
        "file:///src/vendor.js",
        Category.DEBUG,
        "/debug/vendor",
    )
    leaf_from_client = _make_finding(
        "leaf-load-context-multi-execution-client",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/client.js"},
    )
    leaf_from_vendor = _make_finding(
        "leaf-load-context-multi-execution-vendor",
        "file:///src/chunk.js",
        Category.FLAG,
        "feature_enabled",
        metadata={"initiator": "file:///src/vendor.js"},
    )

    graph = Correlator().correlate([
        root,
        client,
        vendor,
        leaf_from_client,
        leaf_from_vendor,
    ])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-multi-execution"
        and edge.target_id in {
            "leaf-load-context-multi-execution-client",
            "leaf-load-context-multi-execution-vendor",
        }
        and edge.metadata.get("context")
        == "load_context_execution_chain:/dashboard -> ./client -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-multi-execution"
        and edge.target_id in {
            "leaf-load-context-multi-execution-client",
            "leaf-load-context-multi-execution-vendor",
        }
        and edge.metadata.get("context")
        == "load_context_execution_chain:/dashboard -> ./vendor -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_call_chain_edges_for_imported_symbol_calls():
    """Root load contexts should propagate through imported call-chain correlation."""
    root = _make_finding(
        "root-load-context-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-load-context-call-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([root, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-call-chain"
        and edge.target_id == "target-load-context-call-chain"
        and edge.metadata.get("context")
        == "load_context_call_chain:/dashboard -> function:boot -> ./chunk:loadUsers"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_scope_call_chain_edges_for_same_file_calls():
    """Load-context root files should preserve same-file transitive call chains as runtime edges."""
    source = _make_finding(
        "source-load-context-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "enclosing_scope": "function:boot",
            "call_graph": {
                "function:boot": ["function:buildAuth"],
            },
        },
    )
    target = _make_finding(
        "target-load-context-scope-call-chain",
        "file:///src/app.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "load_context": "/dashboard",
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:boot": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "source-load-context-scope-call-chain"
        and edge.target_id == "target-load-context-scope-call-chain"
        and edge.metadata.get("context")
        == "load_context_scope_call_chain:/dashboard -> function:boot -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_initiator_scope_call_chain_edges_for_same_file_calls():
    """Load-context roots should propagate through pure initiator paths into same-file transitive call chains."""
    root = _make_finding(
        "root-load-context-initiator-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"load_context": "/dashboard"},
    )
    chunk_entry = _make_finding(
        "chunk-entry-load-context-initiator-scope-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:loadChunk",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )
    chunk_target = _make_finding(
        "chunk-target-load-context-initiator-scope-call-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "initiator": "file:///src/app.js",
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, chunk_entry, chunk_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-initiator-scope-call-chain"
        and edge.target_id == "chunk-target-load-context-initiator-scope-call-chain"
        and edge.metadata.get("context")
        == "load_context_initiator_scope_call_chain:/dashboard -> initiator:file:///src/chunk.js -> function:loadChunk -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_does_not_add_load_context_call_chain_without_root_context():
    """Load-context call-chain runtime edges should only appear when the source file has a load context."""
    root = _make_finding(
        "root-no-load-context-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-no-load-context-call-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([root, target])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("load_context_call_chain:")
        for edge in graph.edges
    )


def test_correlator_adds_import_call_chain_edges_for_downstream_module_calls():
    """Pure import paths should propagate into downstream imported call chains."""
    root = _make_finding(
        "root-import-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-import-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadClient",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-import-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-call-chain"
        and edge.target_id == "target-import-call-chain"
        and edge.metadata.get("context")
        == "import_call_chain:file:///src/app.js -> ./client -> function:loadClient -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_import_scope_call_chain_edges_for_same_module_calls():
    """Pure import paths should preserve same-file transitive call chains inside imported modules."""
    root = _make_finding(
        "root-import-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "imports": ["./client"],
        },
    )
    client_entry = _make_finding(
        "client-entry-import-scope-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )
    client_target = _make_finding(
        "client-target-import-scope-call-chain",
        "file:///src/client.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, client_entry, client_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-scope-call-chain"
        and edge.target_id == "client-target-import-scope-call-chain"
        and edge.metadata.get("context")
        == "import_scope_call_chain:file:///src/app.js -> ./client -> function:loadClient -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_import_scope_call_chain_edges_from_dynamic_binding_metadata():
    """Pure import scope-call edges should recover dynamic-import legs from structured binding metadata."""
    root = _make_finding(
        "root-import-scope-call-chain-dynamic-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
        },
    )
    chunk_entry = _make_finding(
        "chunk-entry-import-scope-call-chain-dynamic-binding",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "enclosing_scope": "function:loadChunk",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )
    chunk_target = _make_finding(
        "chunk-target-import-scope-call-chain-dynamic-binding",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, chunk_entry, chunk_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-import-scope-call-chain-dynamic-binding"
        and edge.target_id == "chunk-target-import-scope-call-chain-dynamic-binding"
        and edge.metadata.get("context")
        == "import_scope_call_chain:file:///src/app.js -> dynamic:./chunk -> function:loadChunk -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_import_call_chain_edges_for_downstream_module_calls():
    """Root load contexts should propagate through import paths into downstream imported call chains."""
    root = _make_finding(
        "root-load-context-import-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-import-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadClient",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-load-context-import-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-call-chain"
        and edge.target_id == "target-load-context-import-call-chain"
        and edge.metadata.get("context")
        == "load_context_import_call_chain:/dashboard -> ./client -> function:loadClient -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_import_scope_call_chain_edges_for_same_module_calls():
    """Load-context import paths should preserve same-file transitive call chains inside imported modules."""
    root = _make_finding(
        "root-load-context-import-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    client_entry = _make_finding(
        "client-entry-load-context-import-scope-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )
    client_target = _make_finding(
        "client-target-load-context-import-scope-call-chain",
        "file:///src/client.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, client_entry, client_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-scope-call-chain"
        and edge.target_id == "client-target-load-context-import-scope-call-chain"
        and edge.metadata.get("context")
        == "load_context_import_scope_call_chain:/dashboard -> ./client -> function:loadClient -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_import_scope_call_chain_edges_from_dynamic_binding_metadata():
    """Load-context import scope-call edges should recover dynamic-import legs from structured binding metadata."""
    root = _make_finding(
        "root-load-context-import-scope-call-chain-dynamic-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
        },
    )
    chunk_entry = _make_finding(
        "chunk-entry-load-context-import-scope-call-chain-dynamic-binding",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "enclosing_scope": "function:loadChunk",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )
    chunk_target = _make_finding(
        "chunk-target-load-context-import-scope-call-chain-dynamic-binding",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, chunk_entry, chunk_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-import-scope-call-chain-dynamic-binding"
        and edge.target_id == "chunk-target-load-context-import-scope-call-chain-dynamic-binding"
        and edge.metadata.get("context")
        == "load_context_import_scope_call_chain:/dashboard -> dynamic:./chunk -> function:loadChunk -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_execution_call_chain_edges_for_downstream_module_calls():
    """Root load contexts should propagate through mixed execution paths into downstream imported call chains."""
    root = _make_finding(
        "root-load-context-execution-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-execution-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    chunk = _make_finding(
        "chunk-load-context-execution-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-load-context-execution-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, chunk, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-execution-call-chain"
        and edge.target_id == "target-load-context-execution-call-chain"
        and edge.metadata.get("context")
        == "load_context_execution_call_chain:/dashboard -> ./client -> initiator:file:///src/chunk.js -> function:loadChunk -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_execution_scope_call_chain_edges_for_runtime_loaded_module_calls():
    """Load-context mixed execution paths should preserve same-file transitive call chains inside runtime-loaded modules."""
    root = _make_finding(
        "root-load-context-execution-scope-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-execution-scope-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    chunk_entry = _make_finding(
        "chunk-entry-load-context-execution-scope-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:loadChunk",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )
    chunk_target = _make_finding(
        "chunk-target-load-context-execution-scope-call-chain",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadChunk": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, middle, chunk_entry, chunk_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-execution-scope-call-chain"
        and edge.target_id == "chunk-target-load-context-execution-scope-call-chain"
        and edge.metadata.get("context")
        == "load_context_execution_scope_call_chain:/dashboard -> ./client -> initiator:file:///src/chunk.js -> function:loadChunk -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_does_not_add_downstream_load_context_call_chain_without_root_context():
    """Downstream load-context import/execution call-chain edges should require a root load context."""
    root = _make_finding(
        "root-no-load-context-downstream-call-chain",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-no-load-context-downstream-call-chain",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadClient",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["fetchToken"],
            },
        },
    )
    chunk = _make_finding(
        "chunk-no-load-context-downstream-call-chain",
        "file:///src/chunk.js",
        Category.DEBUG,
        "/debug/chunk",
        metadata={
            "initiator": "file:///src/client.js",
            "enclosing_scope": "function:loadChunk",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadChunk",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadChunk": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-no-load-context-downstream-call-chain",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, chunk, target])

    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("load_context_import_call_chain:")
        for edge in graph.edges
    )
    assert not any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.metadata.get("context", "").startswith("load_context_execution_call_chain:")
        for edge in graph.edges
    )


def test_correlator_adds_runtime_execution_graph_edges_for_any_practical_path():
    """Unified runtime execution graph edges should preserve transitive import and initiator paths together."""
    root = _make_finding(
        "root-runtime-execution-graph",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-runtime-execution-graph",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    target = _make_finding(
        "target-runtime-execution-graph",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/client.js"},
    )

    graph = Correlator().correlate([root, middle, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-runtime-execution-graph"
        and edge.target_id == "target-runtime-execution-graph"
        and edge.metadata.get("context")
        == "runtime_execution_graph:file:///src/app.js -> ./client -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_runtime_execution_graph_edges():
    """Load contexts should propagate across the unified runtime execution graph."""
    root = _make_finding(
        "root-load-context-runtime-execution-graph",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-runtime-execution-graph",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
    )
    target = _make_finding(
        "target-load-context-runtime-execution-graph",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={"initiator": "file:///src/client.js"},
    )

    graph = Correlator().correlate([root, middle, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-runtime-execution-graph"
        and edge.target_id == "target-load-context-runtime-execution-graph"
        and edge.metadata.get("context")
        == "load_context_runtime_execution_graph:/dashboard -> ./client -> initiator:file:///src/chunk.js"
        for edge in graph.edges
    )


def test_correlator_adds_runtime_execution_call_graph_edges():
    """Unified runtime execution graph should propagate into downstream imported call graphs."""
    root = _make_finding(
        "root-runtime-execution-call-graph",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-runtime-execution-call-graph",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadClient",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-runtime-execution-call-graph",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-runtime-execution-call-graph"
        and edge.target_id == "target-runtime-execution-call-graph"
        and edge.metadata.get("context")
        == "runtime_execution_call_graph:file:///src/app.js -> ./client -> function:loadClient -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_runtime_execution_scope_call_graph_edges():
    """Unified runtime execution graph should preserve same-file transitive call chains inside reached modules."""
    root = _make_finding(
        "root-runtime-execution-scope-graph",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle_entry = _make_finding(
        "middle-entry-runtime-execution-scope-graph",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )
    middle_target = _make_finding(
        "middle-target-runtime-execution-scope-graph",
        "file:///src/client.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, middle_entry, middle_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-runtime-execution-scope-graph"
        and edge.target_id == "middle-target-runtime-execution-scope-graph"
        and edge.metadata.get("context")
        == "runtime_execution_scope_call_graph:file:///src/app.js -> ./client -> function:loadClient -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_runtime_execution_call_graph_edges():
    """Load contexts should propagate through the unified runtime execution call graph."""
    root = _make_finding(
        "root-load-context-runtime-execution-call-graph",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle = _make_finding(
        "middle-load-context-runtime-execution-call-graph",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                    "scope": "function:loadClient",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-load-context-runtime-execution-call-graph",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([root, middle, target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-runtime-execution-call-graph"
        and edge.target_id == "target-load-context-runtime-execution-call-graph"
        and edge.metadata.get("context")
        == "load_context_runtime_execution_call_graph:/dashboard -> ./client -> function:loadClient -> ./auth:fetchToken"
        for edge in graph.edges
    )


def test_correlator_adds_load_context_runtime_execution_scope_call_graph_edges():
    """Load contexts should propagate through unified runtime same-file scope-call graphs."""
    root = _make_finding(
        "root-load-context-runtime-execution-scope-graph",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={
            "load_context": "/dashboard",
            "imports": ["./client"],
        },
    )
    middle_entry = _make_finding(
        "middle-entry-load-context-runtime-execution-scope-graph",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )
    middle_target = _make_finding(
        "middle-target-load-context-runtime-execution-scope-graph",
        "file:///src/client.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:loadClient": ["function:buildAuth"],
            },
        },
    )

    graph = Correlator().correlate([root, middle_entry, middle_target])

    assert any(
        edge.edge_type == EdgeType.RUNTIME
        and edge.source_id == "root-load-context-runtime-execution-scope-graph"
        and edge.target_id == "middle-target-load-context-runtime-execution-scope-graph"
        and edge.metadata.get("context")
        == "load_context_runtime_execution_scope_call_graph:/dashboard -> ./client -> function:loadClient -> function:buildAuth"
        for edge in graph.edges
    )


def test_correlator_adds_transitive_import_edges_for_multi_hop_modules():
    """Multi-hop import chains should correlate the root importing file to deeply imported modules."""
    root = _make_finding(
        "root-import",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./client"]},
    )
    middle = _make_finding(
        "middle-import",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={"imports": ["./auth"]},
    )
    leaf = _make_finding(
        "leaf-import",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle, leaf])

    assert any(
        edge.edge_type == EdgeType.IMPORT
        and edge.source_id == "root-import"
        and edge.target_id == "leaf-import"
        and edge.metadata.get("import_source") == "transitive:./client -> ./auth"
        for edge in graph.edges
    )


def test_correlator_adds_multiple_transitive_import_edges_for_same_target():
    """Distinct practical transitive import chains to the same target should be preserved."""
    root = _make_finding(
        "root-import-multi",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/root",
        metadata={"imports": ["./clientA", "./clientB"]},
    )
    middle_a = _make_finding(
        "middle-import-a",
        "file:///src/clientA.js",
        Category.DEBUG,
        "/debug/client-a",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    middle_b = _make_finding(
        "middle-import-b",
        "file:///src/clientB.js",
        Category.DEBUG,
        "/debug/client-b",
        metadata={"dynamic_imports": ["./chunk"]},
    )
    leaf = _make_finding(
        "leaf-import-multi",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )

    graph = Correlator().correlate([root, middle_a, middle_b, leaf])

    assert any(
        edge.edge_type == EdgeType.IMPORT
        and edge.source_id == "root-import-multi"
        and edge.target_id == "leaf-import-multi"
        and edge.metadata.get("import_source") == "transitive:./clientA -> dynamic:./chunk"
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.IMPORT
        and edge.source_id == "root-import-multi"
        and edge.target_id == "leaf-import-multi"
        and edge.metadata.get("import_source") == "transitive:./clientB -> dynamic:./chunk"
        for edge in graph.edges
    )


def test_correlator_adds_multi_hop_inter_module_call_edges():
    """Cross-module imported call chains should propagate through multiple imported modules."""
    source = _make_finding(
        "source-multi-hop",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:start",
            "import_bindings": [
                {
                    "source": "./client",
                    "imported": "loadClient",
                    "local": "loadClient",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:start": ["loadClient"],
            },
        },
    )
    middle = _make_finding(
        "middle-multi-hop",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "exports": ["loadClient"],
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["fetchToken"],
            },
        },
    )
    target = _make_finding(
        "target-multi-hop",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([source, middle, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-multi-hop"
        and edge.target_id == "target-multi-hop"
        and edge.metadata.get("chain") == [
            "function:start",
            "./client:loadClient",
            "./auth:fetchToken",
        ]
        for edge in graph.edges
    )


def test_correlator_does_not_add_multi_hop_inter_module_call_edge_without_downstream_invocation():
    """A transitive module import should not correlate unless the intermediate module actually invokes it."""
    source = _make_finding(
        "source-multi-hop-negative",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:start",
            "import_bindings": [
                {
                    "source": "./client",
                    "imported": "loadClient",
                    "local": "loadClient",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:start": ["loadClient"],
            },
        },
    )
    middle = _make_finding(
        "middle-multi-hop-negative",
        "file:///src/client.js",
        Category.DEBUG,
        "/debug/client",
        metadata={
            "enclosing_scope": "function:loadClient",
            "exports": ["loadClient"],
            "import_bindings": [
                {
                    "source": "./auth",
                    "imported": "fetchToken",
                    "local": "fetchToken",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:loadClient": ["console.log"],
            },
        },
    )
    target = _make_finding(
        "target-multi-hop-negative",
        "file:///src/auth.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchToken",
            "exports": ["fetchToken"],
        },
    )

    graph = Correlator().correlate([source, middle, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-multi-hop-negative"
        and edge.target_id == "target-multi-hop-negative"
        for edge in graph.edges
    )


def test_correlator_adds_dynamic_import_call_edges_from_namespace_binding():
    """Dynamic import namespace bindings should participate in call-chain correlation."""
    source = _make_finding(
        "source-dynamic-call",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "*",
                    "local": "chunkApi",
                    "kind": "namespace",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
            "scoped_calls": {
                "function:boot": ["chunkApi.loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-dynamic-call",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-dynamic-call"
        and edge.target_id == "target-dynamic-call"
        and edge.metadata.get("chain") == [
            "function:boot",
            "dynamic:./chunk:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_dynamic_import_call_edges_from_default_binding():
    """Dynamic-import destructured default bindings should correlate as default-export calls."""
    source = _make_finding(
        "source-dynamic-default-call",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
            "scoped_calls": {
                "function:boot": ["chunkApi"],
            },
        },
    )
    target = _make_finding(
        "target-dynamic-default-call",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["function:loadUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-dynamic-default-call"
        and edge.target_id == "target-dynamic-default-call"
        and edge.metadata.get("chain") == [
            "function:boot",
            "dynamic:./chunk:default",
        ]
        for edge in graph.edges
    )


def test_correlator_allows_outer_scope_import_binding_in_inner_scope_calls():
    """Lexically outer import bindings should stay visible inside nested inner scopes."""
    source = _make_finding(
        "source-outer-scope-binding",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:inner",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
            "scoped_calls": {
                "function:inner": ["loadUsers"],
            },
            "scope_parents": {
                "function:inner": ["function:boot"],
            },
        },
    )
    target = _make_finding(
        "target-outer-scope-binding",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-outer-scope-binding"
        and edge.target_id == "target-outer-scope-binding"
        and edge.metadata.get("chain") == [
            "function:inner",
            "dynamic:./chunk:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_call_edges_from_import_member_alias_binding():
    """Local aliases of namespace-import members should correlate as named imported calls."""
    source = _make_finding(
        "source-import-member-alias",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "*",
                    "local": "api",
                    "kind": "namespace",
                    "scope": "global",
                    "is_dynamic": False,
                },
                {
                    "source": "./chunk",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_member_alias": True,
                },
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-import-member-alias",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-import-member-alias"
        and edge.target_id == "target-import-member-alias"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./chunk:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_reexport_forwarded_call_edges():
    """Imported calls should forward through practical barrel re-export bindings."""
    source = _make_finding(
        "source-reexport",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./index",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-reexport",
        "file:///src/index.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "exports": ["loadUsers"],
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-reexport",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-reexport"
        and edge.target_id == "target-reexport"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./index:loadUsers",
            "./api:fetchUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_preserves_multiple_reexport_call_chains_to_same_target():
    """Distinct practical re-export paths to the same target finding should be preserved."""
    source = _make_finding(
        "source-reexport-multi",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./indexA",
                    "imported": "loadUsersA",
                    "local": "loadUsersA",
                    "kind": "named",
                },
                {
                    "source": "./indexB",
                    "imported": "loadUsersB",
                    "local": "loadUsersB",
                    "kind": "named",
                },
            ],
            "scoped_calls": {
                "function:boot": ["loadUsersA", "loadUsersB"],
            },
        },
    )
    barrel_a = _make_finding(
        "barrel-reexport-a",
        "file:///src/indexA.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "exports": ["loadUsersA"],
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsersA",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    barrel_b = _make_finding(
        "barrel-reexport-b",
        "file:///src/indexB.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "exports": ["loadUsersB"],
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsersB",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-reexport-multi",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
        },
    )

    graph = Correlator().correlate([source, barrel_a, barrel_b, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-reexport-multi"
        and edge.target_id == "target-reexport-multi"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./indexA:loadUsersA",
            "./api:fetchUsers",
        ]
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-reexport-multi"
        and edge.target_id == "target-reexport-multi"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./indexB:loadUsersB",
            "./api:fetchUsers",
        ]
        for edge in graph.edges
    )



def test_correlator_adds_call_edges_from_named_import_alias_binding():
    """Direct aliases of named imports should still correlate as imported calls."""
    source = _make_finding(
        "source-import-alias",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                },
                {
                    "source": "./api",
                    "imported": "loadUsers",
                    "local": "run",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_alias": True,
                },
            ],
            "scoped_calls": {
                "function:boot": ["run"],
            },
        },
    )
    target = _make_finding(
        "target-import-alias",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-import-alias"
        and edge.target_id == "target-import-alias"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_call_edges_from_namespace_alias_destructured_binding():
    """Destructured aliases from namespace-import aliases should correlate transitively."""
    source = _make_finding(
        "source-import-destructure-alias",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "*",
                    "local": "api",
                    "kind": "namespace",
                    "scope": "global",
                    "is_dynamic": False,
                },
                {
                    "source": "./chunk",
                    "imported": "*",
                    "local": "client",
                    "kind": "namespace",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_alias": True,
                },
                {
                    "source": "./chunk",
                    "imported": "loadUsers",
                    "local": "run",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_alias": True,
                    "is_destructured_alias": True,
                },
            ],
            "scoped_calls": {
                "function:boot": ["run"],
            },
        },
    )
    target = _make_finding(
        "target-import-destructure-alias",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-import-destructure-alias"
        and edge.target_id == "target-import-destructure-alias"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./chunk:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_commonjs_destructured_alias_call_edges():
    """Destructured aliases from CommonJS default objects should correlate as named exports."""
    source = _make_finding(
        "source-commonjs-destructure-alias",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_commonjs": True,
                },
                {
                    "source": "./api",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_commonjs": True,
                    "is_alias": True,
                    "is_destructured_alias": True,
                },
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-commonjs-destructure-alias",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["loadUsers"],
            "export_scopes": {
                "loadUsers": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-commonjs-destructure-alias"
        and edge.target_id == "target-commonjs-destructure-alias"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_export_all_forwarded_call_edges():
    """Export-all barrels should forward same-name imported calls to downstream modules."""
    source = _make_finding(
        "source-reexport-all",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./index",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-reexport-all",
        "file:///src/index.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "*",
                    "local": "*",
                    "kind": "namespace",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                    "is_reexport_all": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-reexport-all",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-reexport-all"
        and edge.target_id == "target-reexport-all"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./index:loadUsers",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_commonjs_default_call_edges():
    """CommonJS require default calls should correlate to module.exports default scopes."""
    source = _make_finding(
        "source-commonjs-default",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_commonjs": True,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api"],
            },
        },
    )
    target = _make_finding(
        "target-commonjs-default",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-commonjs-default"
        and edge.target_id == "target-commonjs-default"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:default",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_commonjs_named_call_edges():
    """CommonJS require member calls should correlate to named exports."""
    source = _make_finding(
        "source-commonjs-named",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_commonjs": True,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api.loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-commonjs-named",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["loadUsers"],
            "export_scopes": {
                "loadUsers": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-commonjs-named"
        and edge.target_id == "target-commonjs-named"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_default_object_member_call_edges():
    """Default-imported object member calls should correlate through export-member scopes."""
    source = _make_finding(
        "source-default-object-member",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api.loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-default-object-member",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["global"],
                "loadUsers": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-default-object-member"
        and edge.target_id == "target-default-object-member"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_commonjs_reexport_forwarded_call_edges():
    """CommonJS barrel re-exports should forward imported calls to downstream modules."""
    source = _make_finding(
        "source-commonjs-reexport",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_commonjs": True,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-commonjs-reexport",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "default",
                    "kind": "default",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                    "is_commonjs_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-commonjs-reexport",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-commonjs-reexport"
        and edge.target_id == "target-commonjs-reexport"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./barrel:default",
            "./api:default",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_default_object_member_reexport_forwarded_call_edges():
    """Default barrel re-exports should forward member calls into downstream default-object exports."""
    source = _make_finding(
        "source-default-object-reexport",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api.loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-default-object-reexport",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "default",
                    "kind": "default",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-default-object-reexport",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["global"],
                "loadUsers": ["function:fetchUsers"],
            },
            "default_object_exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-default-object-reexport"
        and edge.target_id == "target-default-object-reexport"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./barrel:loadUsers",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_does_not_forward_default_reexport_member_without_default_object_metadata():
    """Default barrel forwarding should not guess member exports without default-object metadata."""
    source = _make_finding(
        "source-default-object-reexport-negative",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api.loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-default-object-reexport-negative",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "default",
                    "kind": "default",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-default-object-reexport-negative",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default", "loadUsers"],
            "export_scopes": {
                "default": ["function:fetchUsers"],
                "loadUsers": ["function:loadUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-default-object-reexport-negative"
        and edge.target_id == "target-default-object-reexport-negative"
        for edge in graph.edges
    )


def test_correlator_adds_named_object_reexport_forwarded_call_edges():
    """Named object re-exports should forward member calls when downstream metadata proves the object shape."""
    source = _make_finding(
        "source-named-object-reexport",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "sdk",
                    "local": "sdk",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["sdk.loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-named-object-reexport",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "client",
                    "local": "sdk",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-named-object-reexport",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["client"],
            "export_scopes": {
                "client": ["global"],
                "loadUsers": ["function:fetchUsers"],
            },
            "named_object_exports": {
                "client": ["loadUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-named-object-reexport"
        and edge.target_id == "target-named-object-reexport"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./barrel:loadUsers",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_adds_named_class_member_call_edges():
    """Named class exports should forward member calls through named-object metadata."""
    source = _make_finding(
        "source-named-class-member",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./sdk",
                    "imported": "Api",
                    "local": "api",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api.loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-named-class-member",
        "file:///src/sdk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["Api"],
            "export_scopes": {
                "Api": ["global"],
                "loadUsers": ["function:loadUsers"],
            },
            "named_object_exports": {
                "Api": ["loadUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-named-class-member"
        and edge.target_id == "target-named-class-member"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./sdk:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_does_not_forward_named_object_reexport_without_named_object_metadata():
    """Named object re-exports should not guess member forwarding without downstream object-member metadata."""
    source = _make_finding(
        "source-named-object-reexport-negative",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "sdk",
                    "local": "sdk",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["sdk.loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-named-object-reexport-negative",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "client",
                    "local": "sdk",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-named-object-reexport-negative",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["client", "loadUsers"],
            "export_scopes": {
                "client": ["global"],
                "loadUsers": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-named-object-reexport-negative"
        and edge.target_id == "target-named-object-reexport-negative"
        for edge in graph.edges
    )


def test_correlator_does_not_forward_named_object_reexport_for_direct_named_call():
    """Named object re-export forwarding should only apply to object-member access, not direct named calls."""
    source = _make_finding(
        "source-named-object-direct-call-negative",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-named-object-direct-call-negative",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "client",
                    "local": "sdk",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-named-object-direct-call-negative",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["client", "loadUsers"],
            "export_scopes": {
                "client": ["global"],
                "loadUsers": ["function:fetchUsers"],
            },
            "named_object_exports": {
                "client": ["loadUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-named-object-direct-call-negative"
        and edge.target_id == "target-named-object-direct-call-negative"
        for edge in graph.edges
    )


def test_correlator_does_not_forward_default_object_reexport_for_direct_named_call():
    """Default-object re-export forwarding should only apply to member access on the default object."""
    source = _make_finding(
        "source-default-object-direct-call-negative",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-default-object-direct-call-negative",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "default",
                    "local": "default",
                    "kind": "default",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-default-object-direct-call-negative",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["default", "loadUsers"],
            "export_scopes": {
                "default": ["global"],
                "loadUsers": ["function:fetchUsers"],
            },
            "default_object_exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-default-object-direct-call-negative"
        and edge.target_id == "target-default-object-direct-call-negative"
        for edge in graph.edges
    )


def test_correlator_adds_commonjs_object_barrel_forwarded_call_edges():
    """Object-style CommonJS barrels should forward namespace-member calls downstream."""
    source = _make_finding(
        "source-commonjs-object-reexport",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "import_bindings": [
                {
                    "source": "./barrel",
                    "imported": "default",
                    "local": "api",
                    "kind": "default",
                    "scope": "function:boot",
                    "is_dynamic": False,
                    "is_commonjs": True,
                }
            ],
            "scoped_calls": {
                "function:boot": ["api.loadUsers"],
            },
        },
    )
    barrel = _make_finding(
        "barrel-commonjs-object-reexport",
        "file:///src/barrel.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                    "is_commonjs_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-commonjs-object-reexport",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["loadUsers"],
            "export_scopes": {
                "loadUsers": ["function:fetchUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, barrel, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-commonjs-object-reexport"
        and edge.target_id == "target-commonjs-object-reexport"
        and edge.metadata.get("chain") == [
            "function:boot",
            "./barrel:loadUsers",
            "./api:loadUsers",
        ]
        for edge in graph.edges
    )


def test_correlator_does_not_forward_reexport_without_requested_symbol():
    """Barrel files should not forward re-exported symbols for unrelated in-module findings."""
    barrel = _make_finding(
        "barrel-reexport-no-forward",
        "file:///src/index.js",
        Category.DEBUG,
        "debug",
        metadata={
            "enclosing_scope": "global",
            "exports": ["loadUsers"],
            "re_export_bindings": [
                {
                    "source": "./api",
                    "imported": "fetchUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "global",
                    "is_dynamic": False,
                    "is_reexport": True,
                }
            ],
        },
    )
    target = _make_finding(
        "target-reexport-no-forward",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:fetchUsers",
            "exports": ["fetchUsers"],
        },
    )

    graph = Correlator().correlate([barrel, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "barrel-reexport-no-forward"
        and edge.target_id == "target-reexport-no-forward"
        for edge in graph.edges
    )


def test_correlator_adds_dynamic_import_then_call_edges_from_default_binding():
    """Dynamic-import `.then()` default bindings should correlate through callback scope."""
    source = _make_finding(
        "source-dynamic-then-default-call",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:arrow@1",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "default",
                    "local": "chunkApi",
                    "kind": "default",
                    "scope": "function:arrow@1",
                    "is_dynamic": True,
                }
            ],
            "scoped_calls": {
                "function:arrow@1": ["chunkApi"],
            },
        },
    )
    target = _make_finding(
        "target-dynamic-then-default-call",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["default"],
            "export_scopes": {
                "default": ["function:loadUsers"],
            },
        },
    )

    graph = Correlator().correlate([source, target])

    assert any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-dynamic-then-default-call"
        and edge.target_id == "target-dynamic-then-default-call"
        and edge.metadata.get("chain") == [
            "function:arrow@1",
            "dynamic:./chunk:default",
        ]
        for edge in graph.edges
    )


def test_correlator_does_not_add_dynamic_import_call_edge_outside_binding_scope():
    """Dynamic import bindings should not correlate calls from unrelated scopes."""
    source = _make_finding(
        "source-dynamic-scope",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:other",
            "import_bindings": [
                {
                    "source": "./chunk",
                    "imported": "*",
                    "local": "chunkApi",
                    "kind": "namespace",
                    "scope": "function:boot",
                    "is_dynamic": True,
                }
            ],
            "scoped_calls": {
                "function:other": ["chunkApi.loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-dynamic-scope",
        "file:///src/chunk.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )

    graph = Correlator().correlate([source, target])

    assert not any(
        edge.edge_type == EdgeType.CALL_CHAIN
        and edge.source_id == "source-dynamic-scope"
        and edge.target_id == "target-dynamic-scope"
        for edge in graph.edges
    )


def test_correlator_caches_direct_dependency_edges_within_correlation_pass(monkeypatch):
    """Repeated dependency-edge requests in one pass should reuse the cached structure."""
    correlator = Correlator()
    source = _make_finding(
        "source-cache-direct",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={"imports": ["./api"]},
    )
    target = _make_finding(
        "target-cache-direct",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
    )
    by_file = correlator._group_by_file([source, target])
    correlator._correlation_cache = {}

    call_count = 0
    original = correlator._normalize_import_source

    def counted(import_source: str):
        nonlocal call_count
        call_count += 1
        return original(import_source)

    monkeypatch.setattr(correlator, "_normalize_import_source", counted)

    first = correlator._build_direct_dependency_edges(by_file)
    calls_after_first = call_count
    second = correlator._build_direct_dependency_edges(by_file)
    correlator._correlation_cache = None

    assert first is second
    assert call_count == calls_after_first


def test_correlator_caches_runtime_execution_paths_within_correlation_pass(monkeypatch):
    """Repeated runtime path expansion in one pass should reuse the cached path map."""
    correlator = Correlator()
    correlator._correlation_cache = {}
    direct_dependency_edges = {
        "file:///src/app.js": [
            ("file:///src/client.js", "./client"),
        ],
        "file:///src/client.js": [
            ("file:///src/chunk.js", "dynamic:./chunk"),
        ],
    }
    initiator_children = {
        "file:///src/chunk.js": {"file:///src/runtime.js"},
    }

    call_count = 0
    original = correlator._store_shortest_path_group

    def counted(paths, target, chain, max_chains=3):
        nonlocal call_count
        call_count += 1
        return original(paths, target, chain, max_chains=max_chains)

    monkeypatch.setattr(correlator, "_store_shortest_path_group", counted)

    first = correlator._collect_runtime_execution_paths(
        "file:///src/app.js",
        direct_dependency_edges,
        initiator_children,
    )
    calls_after_first = call_count
    second = correlator._collect_runtime_execution_paths(
        "file:///src/app.js",
        direct_dependency_edges,
        initiator_children,
    )
    correlator._correlation_cache = None

    assert first is second
    assert call_count == calls_after_first


def test_correlator_caches_inter_module_target_resolution_within_correlation_pass(monkeypatch):
    """Repeated inter-module target resolution in one pass should reuse cached targets."""
    correlator = Correlator()
    correlator._correlation_cache = {}
    source = _make_finding(
        "source-cache-inter-module",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "imports": ["./api"],
            "import_bindings": [
                {
                    "source": "./api",
                    "imported": "loadUsers",
                    "local": "loadUsers",
                    "kind": "named",
                    "scope": "function:boot",
                    "is_dynamic": False,
                }
            ],
            "scoped_calls": {
                "function:boot": ["loadUsers"],
            },
        },
    )
    target = _make_finding(
        "target-cache-inter-module",
        "file:///src/api.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:loadUsers",
            "exports": ["loadUsers"],
        },
    )
    by_file = correlator._group_by_file([source, target])
    file_aliases = {file_url: correlator._build_file_aliases(file_url) for file_url in by_file}

    call_count = 0
    original = correlator._collect_import_bindings

    def counted(findings):
        nonlocal call_count
        call_count += 1
        return original(findings)

    monkeypatch.setattr(correlator, "_collect_import_bindings", counted)

    first = correlator._resolve_inter_module_call_targets(
        "file:///src/app.js",
        "function:boot",
        by_file,
        file_aliases,
    )
    calls_after_first = call_count
    second = correlator._resolve_inter_module_call_targets(
        "file:///src/app.js",
        "function:boot",
        by_file,
        file_aliases,
    )
    correlator._correlation_cache = None

    assert first == second
    assert call_count == calls_after_first


def test_correlator_caches_intra_module_target_resolution_within_correlation_pass(monkeypatch):
    """Repeated intra-module target resolution in one pass should reuse cached targets."""
    correlator = Correlator()
    correlator._correlation_cache = {}
    source = _make_finding(
        "source-cache-intra-module",
        "file:///src/app.js",
        Category.ENDPOINT,
        "/api/start",
        metadata={
            "enclosing_scope": "function:boot",
            "call_graph": {
                "function:boot": ["function:buildAuth"],
            },
        },
    )
    target = _make_finding(
        "target-cache-intra-module",
        "file:///src/app.js",
        Category.SECRET,
        FAKE_STRIPE_LIVE,
        metadata={
            "enclosing_scope": "function:buildAuth",
            "call_graph": {
                "function:boot": ["function:buildAuth"],
            },
        },
    )
    findings = [source, target]

    call_count = 0
    original = correlator._collect_call_graph

    def counted(items):
        nonlocal call_count
        call_count += 1
        return original(items)

    monkeypatch.setattr(correlator, "_collect_call_graph", counted)

    first = correlator._resolve_intra_module_call_targets(findings, "function:boot")
    calls_after_first = call_count
    second = correlator._resolve_intra_module_call_targets(findings, "function:boot")
    correlator._correlation_cache = None

    assert first == second
    assert call_count == calls_after_first

