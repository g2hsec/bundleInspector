"""Structural JS/JSX/TypeScript/TSX parser and ESTree projection regressions."""

from __future__ import annotations

import inspect
from typing import Any, cast

import pytest

from bundleInspector.config import Config
from bundleInspector.parser import tree_sitter_backend
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import JSParser, parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine


def _iter_nodes(ast: dict[str, Any]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    stack = [ast]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        nodes.append(node)
        for value in node.values():
            if isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                stack.extend(item for item in value if isinstance(item, dict))
    return nodes


def _node_types(ast: dict[str, Any]) -> set[str]:
    return {str(node.get("type")) for node in _iter_nodes(ast)}


def _first_node(ast: dict[str, Any], node_type: str) -> dict[str, Any]:
    return next(node for node in _iter_nodes(ast) if node.get("type") == node_type)


def test_official_tree_sitter_wheels_are_truthfully_available() -> None:
    assert tree_sitter_backend.tree_sitter_available() is True
    assert tree_sitter_backend.tree_sitter_availability_reason() == "available"


def test_unavailable_binding_is_not_advertised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tree_sitter_backend, "_tree_sitter", None)

    assert tree_sitter_backend.tree_sitter_available() is False
    assert (
        tree_sitter_backend.tree_sitter_availability_reason()
        == "tree_sitter_binding_unavailable"
    )


def test_parser_api_preserves_positional_compatibility_and_adds_keyword_hint() -> None:
    signature = inspect.signature(parse_js)
    assert signature.parameters["language_hint"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parse_js("const x = 1;", True, True).success is True

    result = JSParser().parse("const x: number = 1;", language_hint="typescript")
    assert result.parser_used == "tree-sitter-typescript"
    assert result.completeness == "complete"


@pytest.mark.parametrize(
    "hint,source,required_types",
    [
        (
            "javascript",
            '@sealed class C { #x = "/private"; static { log("/static") } } '
            'const data = await import("./lazy.js");',
            {"Decorator", "PrivateIdentifier", "PropertyDefinition", "StaticBlock", "AwaitExpression"},
        ),
        (
            "jsx",
            'const C = ({q, ...rest}) => <><div data-url="/api/jsx" {...rest} />'
            '<button onClick={() => eval(q)}>Go</button></>;',
            {"JSXFragment", "JSXElement", "JSXSpreadAttribute", "ArrowFunctionExpression"},
        ),
        (
            "typescript",
            '@sealed export class C<T> { #x!: string; m(v: unknown) { '
            'const q = v as string; if (q satisfies string) this.#x = q!; } } '
            'interface I { x: string }; enum E { A = "/enum" }; '
            'namespace N { export const p = "/ns" }',
            {
                "Decorator",
                "PrivateIdentifier",
                "AssignmentExpression",
                "IfStatement",
                "TSEnumDeclaration",
                "TSModuleDeclaration",
            },
        ),
        (
            "tsx",
            'interface P { q: string }; const C: React.FC<P> = ({q}) => '
            '<div dangerouslySetInnerHTML={{__html:q}} />;',
            {"TSTypeMetadata", "JSXElement", "JSXAttribute", "AssignmentExpression"},
        ),
    ],
)
def test_modern_syntax_matrix_is_complete(
    hint: tree_sitter_backend.LanguageHint,
    source: str,
    required_types: set[str],
) -> None:
    result = parse_js(source, language_hint=hint)

    assert result.success is True
    assert result.partial is False
    assert result.completeness == "complete"
    assert result.parser_used == f"tree-sitter-{hint}"
    assert result.ast is not None
    assert required_types <= _node_types(result.ast)
    assert result.ast["parse_completeness"]["unsupported_runtime_nodes"] == []


def test_unhinted_valid_tsx_auto_selects_complete_structural_backend() -> None:
    source = (
        'interface P { q: string }; const C = ({q}: P) => '
        '<div data-url="/api/auto" dangerouslySetInnerHTML={{__html:q}} />;'
    )

    result = parse_js(source)

    assert result.parser_used == "tree-sitter-tsx"
    assert result.partial is False
    assert result.ast is not None


def test_import_assertions_attributes_namespace_export_and_dynamic_import_are_preserved() -> None:
    source = (
        'import data from "./api.json" assert { type: "json" }; '
        'export * as ns from "./module.js"; '
        'const lazy = await import("./lazy.js", {with: {type: "json"}});'
    )
    result = parse_js(source, language_hint="javascript")

    assert result.partial is False
    assert result.ast is not None
    declaration = _first_node(result.ast, "ImportDeclaration")
    assert declaration["source"]["value"] == "./api.json"
    assert declaration["attributes"][0]["key"]["name"] == "type"
    assert declaration["attributes"][0]["value"]["value"] == "json"
    assert source[declaration["range"][0]:declaration["range"][1]].startswith("import data")

    export_all = _first_node(result.ast, "ExportAllDeclaration")
    assert export_all["source"]["value"] == "./module.js"
    assert export_all["exported"]["name"] == "ns"

    dynamic_import = next(
        node
        for node in _iter_nodes(result.ast)
        if node.get("type") == "CallExpression"
        and (node.get("callee") or {}).get("type") == "Import"
    )
    assert dynamic_import["arguments"][0]["value"] == "./lazy.js"


def test_unicode_ranges_and_columns_use_python_characters_not_utf8_bytes() -> None:
    source = 'const 이름 = "값"; fetch("/api/사용자");'
    result = parse_js(source, language_hint="javascript")
    assert result.ast is not None
    call = next(
        node for node in _iter_nodes(result.ast)
        if node.get("type") == "CallExpression"
    )
    literal = call["arguments"][0]
    start, end = literal["range"]

    assert source[start:end] == '"/api/사용자"'
    assert literal["loc"]["start"] == {
        "line": 1,
        "column": source.index('"/api/사용자"'),
    }
    assert call["loc"]["start"]["column"] == source.index("fetch")


@pytest.mark.parametrize(
    ("source", "byte_offsets", "char_offsets", "positions"),
    [
        (
            "alpha\nbeta",
            [0, 5, 6, 10],
            [0, 5, 6, 10],
            [
                {"line": 1, "column": 0},
                {"line": 1, "column": 5},
                {"line": 2, "column": 0},
                {"line": 2, "column": 4},
            ],
        ),
        (
            "a\uD55C\n\U0001F642b",
            [0, 1, 4, 5, 9, 10],
            [0, 1, 2, 3, 4, 5],
            [
                {"line": 1, "column": 0},
                {"line": 1, "column": 1},
                {"line": 1, "column": 2},
                {"line": 2, "column": 0},
                {"line": 2, "column": 1},
                {"line": 2, "column": 2},
            ],
        ),
    ],
)
def test_estree_converter_preserves_ascii_and_utf8_character_positions(
    source: str,
    byte_offsets: list[int],
    char_offsets: list[int],
    positions: list[dict[str, int]],
) -> None:
    converter = tree_sitter_backend._ESTreeConverter(source)

    assert [converter._char_offset(offset) for offset in byte_offsets] == char_offsets
    assert [converter._position_at_byte(offset) for offset in byte_offsets] == positions


def test_cr_only_locations_follow_javascript_line_terminators() -> None:
    source = 'const x = 1;\r\rfetch("/api/cr");'
    result = parse_js(source, language_hint="javascript")
    assert result.ast is not None
    call = _first_node(result.ast, "CallExpression")
    assert call["loc"]["start"] == {"line": 3, "column": 0}


def test_estree_reserved_fields_and_hashbang_are_projected_without_false_partial() -> None:
    source = (
        "#!/usr/bin/env node\n"
        "async function f(xs) { for await (const x of xs) { await consume(x); } }"
    )
    result = parse_js(source, language_hint="javascript")

    assert result.partial is False
    assert result.ast is not None
    function = _first_node(result.ast, "FunctionDeclaration")
    loop = _first_node(result.ast, "ForOfStatement")
    assert function["async"] is True
    assert "async_" not in function
    assert loop["await"] is True
    assert "await_" not in loop
    assert "TreeSitterUnknownNode" not in _node_types(result.ast)


def test_string_decoder_combines_surrogates_and_never_raises_for_invalid_codepoints() -> None:
    converter = tree_sitter_backend._ESTreeConverter("")

    assert converter._decode_string(r'"\uD83D\uDE00"') == "😀"
    assert converter._decode_string(r'"\u{110000}"') == "u{110000}"
    assert converter._decode_string(r'"\uD800"') == r"\uD800"


@pytest.mark.parametrize(
    "source,expected_gap",
    [
        ('const x = ; fetch("/api/recovered")', "syntax_error_nodes"),
        ("function f(a { return a; }", "syntax_missing_nodes"),
    ],
)
def test_recovery_error_and_missing_nodes_are_explicitly_partial(
    source: str,
    expected_gap: str,
) -> None:
    result = parse_js(source, language_hint="javascript")

    assert result.success is True
    assert result.partial is True
    assert result.completeness == "partial"
    assert expected_gap in result.capability_gaps
    assert result.ast is not None
    assert result.ast["partial"] is True
    assert result.ast["parse_completeness"]["status"] == "partial"
    assert result.errors


def test_partial_on_error_false_rejects_tree_sitter_recovery() -> None:
    result = parse_js(
        'const x = ; fetch("/api/recovered")',
        partial_on_error=False,
        language_hint="javascript",
    )

    assert result.success is False
    assert result.ast is None
    assert result.partial is False
    assert result.completeness == "failed"
    assert "syntax_error_nodes" in result.capability_gaps


@pytest.mark.parametrize(
    "constant,limit,expected",
    [
        ("MAX_CST_SCAN_NODES", 2, "CST scan node cap"),
        ("MAX_CONVERTED_NODES", 3, "converted-node cap"),
        ("MAX_CONVERSION_DEPTH", 1, "conversion depth cap"),
    ],
)
def test_parser_caps_force_explicit_truncation(
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    limit: int,
    expected: str,
) -> None:
    monkeypatch.setattr(tree_sitter_backend, constant, limit)
    result = parse_js(
        'function f(a) { if (a) { fetch("/api/capped"); } }',
        language_hint="javascript",
    )

    assert result.success is True
    assert result.partial is True
    assert result.truncation_reasons
    assert any(expected in reason for reason in result.truncation_reasons)
    assert result.ast is not None
    assert result.ast["parse_completeness"]["truncation_reasons"] == list(
        result.truncation_reasons
    )


def test_unknown_runtime_node_is_retained_and_never_claims_complete() -> None:
    class FutureNode:
        type = "future_runtime_expression"
        start_byte = 0
        end_byte = 1
        start_point = (0, 0)
        end_point = (0, 1)
        is_error = False
        is_missing = False
        children: list[Any] = []
        named_children: list[Any] = []

    converter = tree_sitter_backend._ESTreeConverter("x")
    converted = converter.convert(FutureNode())

    assert converted is not None
    assert converted["type"] == "TreeSitterUnknownNode"
    assert converted["originalType"] == "future_runtime_expression"
    assert converter.partial is True
    assert converter.unsupported_types == {"future_runtime_expression"}


def test_plain_js_tree_sitter_differential_preserves_ir_evidence() -> None:
    source = (
        'import d, {x as y} from "pkg"; export function f(a) { '
        'if (a && y) { const o = {url:"/api/x", run(v) { return fetch(v) }}; '
        'return o.run(`/v1/${a}`); } } const g = q => eval(q);'
    )
    legacy = parse_js(source)
    structural = parse_js(source, language_hint="javascript")
    assert legacy.ast is not None and structural.ast is not None
    legacy_ir = build_ir(legacy.ast, "f.js", "h")
    structural_ir = build_ir(structural.ast, "f.js", "h")

    assert [literal.value for literal in structural_ir.string_literals] == [
        literal.value for literal in legacy_ir.string_literals
    ]
    assert [call.full_name for call in structural_ir.function_calls] == [
        call.full_name for call in legacy_ir.function_calls
    ]
    assert [
        (item.source, item.specifiers, item.is_dynamic) for item in structural_ir.imports
    ] == [
        (item.source, item.specifiers, item.is_dynamic) for item in legacy_ir.imports
    ]
    assert [(guard.node_kind, guard.tokens) for guard in structural_ir.guard_conditions] == [
        (guard.node_kind, guard.tokens) for guard in legacy_ir.guard_conditions
    ]


@pytest.mark.parametrize(
    ("source", "expected_flows"),
    [
        ("let a=[,location.hash]; el.innerHTML=a[0];", 0),
        ("let a=[,location.hash]; el.innerHTML=a[1];", 1),
        ('let a=["safe",location.hash]; let [,x]=a; el.innerHTML=x;', 1),
        ('let a=[location.hash,"safe"]; let [,x]=a; el.innerHTML=x;', 0),
    ],
)
def test_array_elisions_preserve_taint_indices_across_backends(
    source: str,
    expected_flows: int,
) -> None:
    engine = RuleEngine(Config().rules)
    engine.register_defaults()

    def flow_count(hint: tree_sitter_backend.LanguageHint | None) -> int:
        parsed = parse_js(source, language_hint=hint)
        assert parsed.ast is not None
        ir = build_ir(parsed.ast, "f.js", "h")
        findings = engine.analyze(
            ir,
            AnalysisContext(file_url="f.js", file_hash="h", source_content=source),
        )
        return sum(finding.value_type == "taint_flow" for finding in findings)

    assert flow_count(None) == expected_flows
    assert flow_count("javascript") == expected_flows


def test_legacy_octal_literals_match_classic_javascript_semantics() -> None:
    source = r'const values=[010,077,08]; fetch("\057api\057users");'
    parsed = parse_js(source, language_hint="javascript")

    assert parsed.partial is False
    assert parsed.ast is not None
    literal_by_raw = {
        str(node.get("raw")): node.get("value")
        for node in _iter_nodes(parsed.ast)
        if node.get("type") == "Literal"
    }
    assert literal_by_raw["010"] == 8
    assert literal_by_raw["077"] == 63
    assert literal_by_raw["08"] == 8
    assert literal_by_raw[r'"\057api\057users"'] == "/api/users"


def test_html_comment_is_inert_without_losing_following_flow() -> None:
    source = "<!-- deployment banner\nconst q=location.hash; el.innerHTML=q;"
    parsed = parse_js(source, language_hint="javascript")
    assert parsed.partial is False
    assert parsed.ast is not None

    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    findings = engine.analyze(
        build_ir(parsed.ast, "f.js", "h"),
        AnalysisContext(file_url="f.js", file_hash="h", source_content=source),
    )
    assert sum(finding.value_type == "taint_flow" for finding in findings) == 1


def test_import_assertion_rewrite_stops_at_asi_boundary() -> None:
    source = 'import "./x"\nassert\n{}'

    assert tree_sitter_backend._normalize_import_assertions(source) == source
    parsed = parse_js(source, language_hint="javascript")
    assert parsed.partial is False
    assert parsed.ast is not None
    assert [node.get("type") for node in parsed.ast["body"]] == [
        "ImportDeclaration",
        "ExpressionStatement",
        "BlockStatement",
    ]


def test_import_assertion_rewrite_respects_regex_templates_and_comment_line_breaks() -> None:
    inert = (
        'const a=/import "x" assert {}/; '
        'if(ok) /export "y" assert {}/.test(s); '
        'if(ok) {}\n/import "block" assert {}/.test(s); '
        'try {} finally {}\n/export "finally" assert {}/.test(s); '
        'function f() {}\n/import "function" assert {}/.test(s); '
        'class C {}\n/export "class" assert {}/.test(s); '
        '{}\n/import "bare" assert {}/.test(s); '
        'const t=`outer ${`import "z" assert {}`}`;'
    )
    block_asi = 'import "./x" /* line one\nline two */ assert\n{}'
    unicode_asi = 'import "./x"\u2028assert\n{}'
    same_line = 'import data from "./x" /* metadata */ assert {type:"json"};'

    assert tree_sitter_backend._normalize_import_assertions(inert) == inert
    assert tree_sitter_backend._normalize_import_assertions(block_asi) == block_asi
    assert tree_sitter_backend._normalize_import_assertions(unicode_asi) == unicode_asi
    normalized = tree_sitter_backend._normalize_import_assertions(same_line)
    assert normalized == same_line.replace("assert", "with  ")


def test_import_assertion_rewrite_resumes_after_all_javascript_line_terminators() -> None:
    for separator in ("\r", "\n", "\r\n", "\u2028", "\u2029"):
        source = (
            f'// import "comment" assert {{}}{separator}'
            'import data from "./real.json" assert {type:"json"};'
        )
        expected = source.replace(
            'import data from "./real.json" assert',
            'import data from "./real.json" with  ',
        )
        assert tree_sitter_backend._normalize_import_assertions(source) == expected

        unterminated_regex = (
            f'if(ok) /unterminated{separator}'
            'import data from "./real.json" assert {type:"json"};'
        )
        assert tree_sitter_backend._normalize_import_assertions(
            unterminated_regex
        ) == unterminated_regex.replace(
            'import data from "./real.json" assert',
            'import data from "./real.json" with  ',
        )

        escaped_terminator = (
            f'if(ok) /unterminated\\{separator}'
            'import data from "./real.json" assert {type:"json"};'
        )
        assert tree_sitter_backend._normalize_import_assertions(
            escaped_terminator
        ) == escaped_terminator.replace(
            'import data from "./real.json" assert',
            'import data from "./real.json" with  ',
        )


def test_import_assertion_rewrite_uses_only_declaration_level_module_source() -> None:
    sources = [
        'import {"a-b" as imported} from "./m.json" assert {type:"json"};',
        'import from from "./m.json" assert {type:"json"};',
        (
            'export {from as x, "a-b" as y} from "./m.json" '
            'assert {type:"json"};'
        ),
    ]

    for source in sources:
        normalized = tree_sitter_backend._normalize_import_assertions(source)
        assert normalized.count("with  ") == 1
        assert normalized == source.rsplit("assert", 1)[0] + "with  " + source.rsplit(
            "assert",
            1,
        )[1]


def test_static_modifier_ignores_comment_text() -> None:
    source = (
        "class A { m /* static marker */(){} static n(){}; "
        "x /* static marker */=1; static y=2; static get z(){return 1} }"
    )
    parsed = parse_js(source, language_hint="javascript")
    assert parsed.ast is not None
    methods = {
        (node.get("key") or {}).get("name"): node.get("static")
        for node in _iter_nodes(parsed.ast)
        if node.get("type") in {"MethodDefinition", "PropertyDefinition"}
    }
    assert methods == {"m": False, "n": True, "x": False, "y": True, "z": True}
    getter = next(
        node
        for node in _iter_nodes(parsed.ast)
        if node.get("type") == "MethodDefinition"
        and (node.get("key") or {}).get("name") == "z"
    )
    assert getter["kind"] == "get"


def test_custom_jsx_components_do_not_become_intrinsic_dom_sinks() -> None:
    custom_source = (
        "const q=location.hash; const C=()=>"
        "<Safe dangerouslySetInnerHTML={{__html:q}}/>;"
    )
    intrinsic_source = custom_source.replace("<Safe", "<div")
    engine = RuleEngine(Config().rules)
    engine.register_defaults()

    def flow_count(source: str) -> int:
        parsed = parse_js(source, language_hint="tsx")
        assert parsed.ast is not None and parsed.partial is False
        findings = engine.analyze(
            build_ir(parsed.ast, "f.tsx", "h"),
            AnalysisContext(file_url="f.tsx", file_hash="h", source_content=source),
        )
        return sum(finding.value_type == "taint_flow" for finding in findings)

    assert flow_count(custom_source) == 0
    assert flow_count(intrinsic_source) == 1


def test_tsx_endpoint_dom_sink_and_confirmed_taint_survive_end_to_end() -> None:
    source = (
        'interface P { q: string }; const q: string = location.hash; '
        'const C = () => <div data-api="/api/tsx-modern" '
        'dangerouslySetInnerHTML={{__html:q}} />;'
    )
    parsed = parse_js(source, language_hint="tsx")
    assert parsed.ast is not None
    assert parsed.partial is False
    ir = build_ir(parsed.ast, "f.tsx", "h")
    assert ir.partial is False

    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    findings = engine.analyze(
        ir,
        AnalysisContext(
            file_url="f.tsx",
            file_hash="h",
            source_content=source,
        ),
    )

    assert any(
        finding.category.value == "endpoint"
        and finding.extracted_value == "/api/tsx-modern"
        for finding in findings
    )
    assert any(
        finding.category.value == "sink"
        and finding.value_type == "dom_html_sink"
        and finding.extracted_value == "innerHTML="
        for finding in findings
    )
    taint = next(
        finding for finding in findings
        if finding.category.value == "sink" and finding.value_type == "taint_flow"
    )
    assert taint.metadata["confirmed"] is True
    assert taint.metadata["source_kind"] == "location"
    assert taint.metadata["sink"] == "innerhtml="


def test_invalid_language_hint_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported JavaScript language hint"):
        tree_sitter_backend.parse_tree_sitter(
            "const x = 1;",
            language_hint=cast(Any, "python"),
        )
