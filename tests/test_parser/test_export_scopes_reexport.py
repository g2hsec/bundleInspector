"""Export-scope regression coverage for ESM and adversarial CommonJS ASTs."""

import bundleInspector.parser.export_scopes as export_scopes
from bundleInspector.parser.export_scopes import (
    build_commonjs_default_object_export_members,
    build_commonjs_export_metadata,
    build_commonjs_named_object_export_members,
    build_commonjs_re_export_bindings,
    build_commonjs_require_bindings,
    build_default_object_export_members,
    build_export_scope_map,
    build_named_object_export_members,
    build_re_export_bindings,
)
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js

_COMMONJS_SOURCE = """
function loadUsers() {}
const sdk = {loadUsers};
const api = require("./api");
exports.forwarded = require("./api").loadUsers;
module.exports = {local: loadUsers};
exports.sdk = sdk;
"""


def _commonjs_ir():
    return build_ir(parse_js(_COMMONJS_SOURCE).ast, "commonjs.js", "hash")


def _wrap_ast(root, depth: int):
    for _ in range(depth):
        root = {"type": "DeepWrapper", "child": root}
    return root


def _run_commonjs_builders(ir):
    return (
        build_commonjs_require_bindings(ir),
        build_commonjs_re_export_bindings(ir),
        build_commonjs_export_metadata(ir),
        build_commonjs_default_object_export_members(ir),
        build_commonjs_named_object_export_members(ir),
    )


def test_reexport_from_not_bound_to_local_same_named_symbol():
    # `parse` is BOTH a local function and re-exported from './vendor'. The re-export must not be
    # wrongly bound to the local function:parse scope.
    src = "function parse(){ return doLocalThing(); }\nexport { parse } from './vendor';"
    scopes = build_export_scope_map(build_ir(parse_js(src).ast, "f.js", "h"))
    assert scopes.get("parse") != ["function:parse"]


def test_direct_export_still_resolves_local_scope():
    """A DIRECT export (no `from`) of a local symbol is still resolved normally."""
    src = "function parse(){ return doLocalThing(); }\nexport { parse };"
    scopes = build_export_scope_map(build_ir(parse_js(src).ast, "f.js", "h"))
    assert "function:parse" in (scopes.get("parse") or [])


def test_commonjs_builders_complete_on_ast_deeper_than_python_recursion_limit():
    ir = _commonjs_ir()
    ir.raw_ast = _wrap_ast(ir.raw_ast, 3_200)

    require_bindings, reexports, metadata, default_members, named_members = (
        _run_commonjs_builders(ir)
    )

    assert require_bindings == [{
        "source": "./api",
        "imported": "default",
        "local": "api",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_commonjs": True,
    }]
    assert reexports == [{
        "source": "./api",
        "imported": "loadUsers",
        "local": "forwarded",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    }]
    assert metadata == (
        ["forwarded", "local", "sdk"],
        {
            "forwarded": ["global"],
            "loadUsers": ["function:loadUsers"],
            "local": ["function:loadUsers"],
            "sdk": ["global"],
        },
    )
    assert default_members == ["local"]
    assert named_members == {"sdk": ["loadUsers"]}
    assert ir.partial is False
    assert ir.errors == []


def test_commonjs_ast_node_cap_marks_partial_once(monkeypatch):
    monkeypatch.setattr(export_scopes, "_MAX_EXPORT_AST_NODES", 8)
    ir = _commonjs_ir()
    ir.raw_ast = _wrap_ast(ir.raw_ast, 20)

    _run_commonjs_builders(ir)
    _run_commonjs_builders(ir)

    assert ir.partial is True
    assert ir.errors == ["export scope analysis incomplete (ast node cap=8)"]


def test_commonjs_cyclic_ast_terminates_at_shared_node_cap(monkeypatch):
    monkeypatch.setattr(export_scopes, "_MAX_EXPORT_AST_NODES", 8)
    ir = _commonjs_ir()
    cyclic = {"type": "Program", "body": []}
    cyclic["cycle"] = cyclic
    ir.raw_ast = cyclic

    _run_commonjs_builders(ir)

    assert ir.partial is True
    assert ir.errors == ["export scope analysis incomplete (ast cycle detected)"]


def test_commonjs_deep_member_expression_is_bounded_and_deduplicated():
    ir = _commonjs_ir()
    member = {"type": "Identifier", "name": "exports"}
    for _ in range(3_200):
        member = {
            "type": "MemberExpression",
            "computed": False,
            "object": member,
            "property": {"type": "Identifier", "name": "nested"},
        }
    ir.raw_ast = {
        "type": "Program",
        "body": [{
            "type": "ExpressionStatement",
            "expression": {
                "type": "AssignmentExpression",
                "operator": "=",
                "left": member,
                "right": {"type": "Identifier", "name": "value"},
            },
        }],
    }

    _run_commonjs_builders(ir)
    _run_commonjs_builders(ir)

    assert ir.partial is True
    assert ir.errors == [
        "export scope analysis incomplete (expression recursion limit)",
    ]


def test_esm_export_walkers_are_cycle_safe_and_mark_partial_once():
    ir = _commonjs_ir()
    cyclic = {"type": "Program", "body": []}
    cyclic["cycle"] = cyclic
    ir.raw_ast = cyclic

    assert build_export_scope_map(ir) == {}
    assert build_default_object_export_members(ir) == []
    assert build_named_object_export_members(ir) == {}
    assert ir.errors == ["export scope analysis incomplete (ast cycle detected)"]


def test_esm_reexport_body_obeys_shared_node_budget(monkeypatch):
    monkeypatch.setattr(export_scopes, "_MAX_EXPORT_AST_NODES", 2)
    ir = _commonjs_ir()
    ir.raw_ast = {
        "type": "Program",
        "body": [
            {
                "type": "ExportAllDeclaration",
                "source": {"type": "Literal", "value": f"./m{index}"},
            }
            for index in range(3)
        ],
    }

    bindings = build_re_export_bindings(ir)

    assert [binding["source"] for binding in bindings] == ["./m0", "./m1"]
    assert ir.errors == ["export scope analysis incomplete (ast node cap=2)"]


def test_commonjs_static_computed_exports_are_preserved():
    source = """
    exports["foo"] = require("./api").foo;
    module["exports"]["bar"] = require("./api").bar;
    module["exports"] = require("./default");
    """
    ir = build_ir(parse_js(source).ast, "commonjs.js", "hash")

    assert build_commonjs_re_export_bindings(ir) == [
        {
            "source": "./api",
            "imported": "foo",
            "local": "foo",
            "kind": "named",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
        {
            "source": "./api",
            "imported": "bar",
            "local": "bar",
            "kind": "named",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
        {
            "source": "./default",
            "imported": "default",
            "local": "default",
            "kind": "default",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
    ]
    assert build_commonjs_export_metadata(ir)[0] == ["bar", "default", "foo"]


def test_shadowed_commonjs_sentinels_do_not_create_runtime_edges():
    sources = [
        'function f(require){ const api=require("./fake"); }',
        'function f(exports){ exports.fake=require("./fake").thing; }',
        'const exports={}; exports.fake=require("./fake").thing;',
        'function f(module){ module.exports=require("./fake"); }',
        (
            'function f(kind){ switch(kind){ case 1: const exports={}; '
            'exports.fake=require("./fake").thing; } }'
        ),
        '(function(require){ require("./fake"); })(fakeRequire);',
        (
            'const require=fakeRequire; '
            '(function(require){ require("./fake"); })(require);'
        ),
        (
            '(function(require,module){ require("./fake"); '
            'module.exports=require("./fake"); })(module,require);'
        ),
        (
            '(function(require){ var require=fakeRequire; '
            'require("./fake"); })(require);'
        ),
        '(function require(require){ require("./fake"); })(require);',
        (
            '(function(require,require){ require("./fake"); })'
            '(require,fakeRequire);'
        ),
    ]

    for source in sources:
        ir = build_ir(parse_js(source).ast, "commonjs.js", "hash")
        assert build_commonjs_require_bindings(ir) == []
        assert build_commonjs_re_export_bindings(ir) == []
        assert build_commonjs_export_metadata(ir) == ([], {})


def test_iife_local_require_alias_can_forward_to_real_module_exports():
    source = (
        '(function(){ const api=require("./api"); '
        'module.exports=api; module.exports.load=api.load; })();'
    )
    ir = build_ir(parse_js(source).ast, "commonjs.js", "hash")

    require_bindings = build_commonjs_require_bindings(ir)
    assert require_bindings[0]["scope"] == "function:function_expr@1"
    assert build_commonjs_re_export_bindings(ir) == [
        {
            "source": "./api",
            "imported": "default",
            "local": "default",
            "kind": "default",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
        {
            "source": "./api",
            "imported": "load",
            "local": "load",
            "kind": "named",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
    ]
    assert build_commonjs_export_metadata(ir) == (
        ["default", "load"],
        {"default": ["global"], "load": ["global"]},
    )


def test_commonjs_sentinel_injected_into_direct_arrow_iife_remains_runtime_edge():
    source = '(require => { const api=require("./api"); })(require);'
    ir = build_ir(parse_js(source).ast, "commonjs.js", "hash")

    assert build_commonjs_require_bindings(ir) == [
        {
            "source": "./api",
            "imported": "default",
            "local": "api",
            "kind": "default",
            "scope": "function:arrow@1",
            "is_dynamic": False,
            "is_commonjs": True,
        }
    ]


def test_commonjs_sentinels_injected_into_direct_iife_remain_runtime_edges():
    source = (
        '(function(require,module,exports){ const api=require("./api"); '
        'module.exports=api; exports.load=api.load; })(require,module,exports);'
    )
    ir = build_ir(parse_js(source).ast, "commonjs.js", "hash")

    assert build_commonjs_require_bindings(ir) == [
        {
            "source": "./api",
            "imported": "default",
            "local": "api",
            "kind": "default",
            "scope": "function:function_expr@1",
            "is_dynamic": False,
            "is_commonjs": True,
        }
    ]
    assert build_commonjs_re_export_bindings(ir) == [
        {
            "source": "./api",
            "imported": "default",
            "local": "default",
            "kind": "default",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
        {
            "source": "./api",
            "imported": "load",
            "local": "load",
            "kind": "named",
            "scope": "global",
            "is_dynamic": False,
            "is_reexport": True,
            "is_commonjs_reexport": True,
        },
    ]
    assert build_commonjs_export_metadata(ir) == (
        ["default", "load"],
        {"default": ["global"], "load": ["global"]},
    )
