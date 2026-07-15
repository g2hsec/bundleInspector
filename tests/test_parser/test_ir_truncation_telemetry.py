"""DQ-C04: hard analysis caps must not truncate the IR silently.

A cap that drops detection-relevant nodes (AST visit depth, unique-identifier budget) must mark
`ir.partial` and record a note, so an INCOMPLETE analysis is distinguishable from a clean
0-finding result. The per-identifier occurrence sample is a benign memory bound and must NOT flip
the whole IR to partial -- real minified bundles exceed it constantly (common short names like
`e`/`t`/`n` appear thousands of times), and doing so would make the taint engine abstain from
`confirmed` on nearly every real bundle.
"""

from bundleInspector.parser.ir_builder import IRBuilder


def _loc(line: int = 1, col: int = 0) -> dict:
    return {"start": {"line": line, "column": col}, "end": {"line": line, "column": col}}


def _fetch_stmt(url: str) -> dict:
    return {
        "type": "ExpressionStatement", "loc": _loc(),
        "expression": {
            "type": "CallExpression", "loc": _loc(),
            "callee": {"type": "Identifier", "name": "fetch", "loc": _loc()},
            "arguments": [{"type": "Literal", "value": url, "loc": _loc()}],
        },
    }


def _nested_blocks(depth: int, leaf: dict) -> dict:
    node = leaf
    for _ in range(depth):
        node = {"type": "BlockStatement", "loc": _loc(), "body": [node]}
    return {"type": "Program", "loc": _loc(), "body": [node]}


def test_ast_depth_cap_marks_partial_not_silent():
    """A clean AST nested past MAX_VISIT_DEPTH drops the subtree below the cap (incl. the
    fetch call) -- but the loss must now be RECORDED (partial + note), not silent."""
    ir = IRBuilder().build(
        _nested_blocks(IRBuilder.MAX_VISIT_DEPTH + 20, _fetch_stmt("/api/deep")), "f.js", "h"
    )
    assert ir.partial is True
    assert any("depth" in e for e in ir.errors)
    assert len(ir.function_calls) == 0  # dropped, but no longer silent


def test_shallow_ast_is_not_marked_partial():
    """A normal-depth AST must not be flagged partial and must keep its findings."""
    ir = IRBuilder().build(_nested_blocks(50, _fetch_stmt("/api/deep")), "f.js", "h")
    assert ir.partial is False
    assert len(ir.function_calls) == 1


def test_unique_identifier_cap_marks_partial():
    """Exceeding the unique-identifier budget drops NEW names (losing their def-use), which is a
    detection-relevant truncation -> partial + note."""
    body = [
        {
            "type": "VariableDeclaration", "kind": "var", "loc": _loc(),
            "declarations": [{
                "type": "VariableDeclarator", "loc": _loc(),
                "id": {"type": "Identifier", "name": f"v{i}", "loc": _loc()}, "init": None,
            }],
        }
        for i in range(IRBuilder.MAX_UNIQUE_IDENTIFIERS + 100)
    ]
    ir = IRBuilder().build({"type": "Program", "loc": _loc(), "body": body}, "f.js", "h")
    assert ir.partial is True
    assert any("identifier" in e for e in ir.errors)
    assert len(ir.identifiers) == IRBuilder.MAX_UNIQUE_IDENTIFIERS


def test_occurrence_cap_does_not_mark_partial():
    """A single identifier exceeding the per-name occurrence sample is a benign bound and must
    NOT flip the whole IR to partial (else nearly every real minified bundle becomes partial)."""
    ref = {
        "type": "ExpressionStatement", "loc": _loc(),
        "expression": {"type": "Identifier", "name": "foo", "loc": _loc()},
    }
    body = [ref for _ in range(IRBuilder.MAX_OCCURRENCES_PER_IDENTIFIER + 50)]
    ir = IRBuilder().build({"type": "Program", "loc": _loc(), "body": body}, "f.js", "h")
    assert ir.partial is False
    assert len(ir.identifiers["foo"]) == IRBuilder.MAX_OCCURRENCES_PER_IDENTIFIER


def test_truncation_note_is_deduped():
    """The per-node cap must not spam the errors list -- one note per distinct cap."""
    ir = IRBuilder().build(
        _nested_blocks(IRBuilder.MAX_VISIT_DEPTH + 40, _fetch_stmt("/api/deep")), "f.js", "h"
    )
    depth_notes = [e for e in ir.errors if "depth" in e]
    assert len(depth_notes) == 1
