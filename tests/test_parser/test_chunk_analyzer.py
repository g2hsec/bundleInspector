"""Guards against mojibake (encoding-corrupted glyphs) leaking into chunk_analyzer -- especially
the arrow characters that surface in user-facing RuleResult title/description text."""

from bundleInspector.parser import chunk_analyzer
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext


def test_chunk_analyzer_source_is_ascii_clean():
    """The module source must contain no non-ASCII bytes, so a corrupted multibyte glyph can never
    silently reappear in user-facing detector output again."""
    raw = open(chunk_analyzer.__file__, "rb").read()
    non_ascii = [(i, b) for i, b in enumerate(raw) if b > 127]
    assert non_ascii == [], f"non-ASCII bytes in chunk_analyzer.py: {non_ascii[:5]}"


def test_chunk_analyzer_uses_ascii_arrow_not_mojibake():
    """The route/import display strings must render an ASCII '->' arrow, never the corrupted '??'."""
    src = open(chunk_analyzer.__file__, encoding="utf-8").read()
    assert "??" not in src                      # the corrupted-arrow marker is gone
    assert "{chunk_name} -> {import_path}" in src
    assert "Route inferred from chunk: {value} -> {route}" in src


def test_dynamic_import_scan_keeps_magic_comment_but_masks_ordinary_block_comment():
    source = (
        '/* import("./fake.js") */\n'
        'import(/* webpackChunkName: "real" */ "./real.js");'
    )
    parsed = parse_js(source)
    assert parsed.ast is not None
    ir = build_ir(parsed.ast, "f.js", "h")
    context = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)

    findings = list(chunk_analyzer.ChunkAnalyzer().match(ir, context))
    values = {finding.extracted_value for finding in findings}

    assert "./fake.js" not in values
    assert "real -> ./real.js" in values


def test_dynamic_import_scan_masks_code_looking_control_header_regex():
    source = (
        'if (\n// misleading )\nok\n) '
        r'/import\(".\/fake.js"\)/.test(value); '
        'import("./real.js");'
    )
    parsed = parse_js(source)
    assert parsed.ast is not None
    ir = build_ir(parsed.ast, "f.js", "h")
    context = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)

    findings = list(chunk_analyzer.ChunkAnalyzer().match(ir, context))
    import_paths = {
        finding.metadata.get("import_path")
        for finding in findings
        if finding.value_type in {"dynamic_import", "webpack_named_chunk"}
    }

    assert import_paths == {"./real.js"}


def test_dynamic_import_scan_masks_control_block_regex_but_keeps_division_operand():
    source = (
        'if(ok) {}\n/import("fake")/.test(value); '
        'function declared() {}\n/import("function-fake")/.test(value); '
        'class Declared {}\n/import("class-fake")/.test(value); '
        'const ratio={} / import("./real.js") / divisor; '
        'const fn=function(){} / import("./real-function.js") / divisor; '
        'const cls=class{} / import("./real-class.js") / divisor;'
    )
    parsed = parse_js(source)
    assert parsed.ast is not None
    ir = build_ir(parsed.ast, "f.js", "h")
    context = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)

    findings = list(chunk_analyzer.ChunkAnalyzer().match(ir, context))
    import_paths = {
        finding.metadata.get("import_path")
        for finding in findings
        if finding.value_type in {"dynamic_import", "webpack_named_chunk"}
    }

    assert import_paths == {
        "./real.js",
        "./real-function.js",
        "./real-class.js",
    }


def test_comment_mask_preserves_every_javascript_line_terminator():
    for separator in ("\r", "\n", "\r\n", "\u2028", "\u2029"):
        source = f'// import("./fake.js"){separator}import("./real.js")'
        masked = chunk_analyzer.ChunkAnalyzer._mask_comments(source, mask_block=False)
        assert separator in masked
        assert "./fake.js" not in masked
        assert 'import("./real.js")' in masked
        line_index = chunk_analyzer.ChunkAnalyzer._build_line_index(source)
        assert chunk_analyzer.ChunkAnalyzer._offset_to_line(
            line_index,
            source.index('import("./real.js")'),
        ) == 2

        unterminated_regex = (
            f'if(ok) /unterminated\\{separator}import("./recovered.js")'
        )
        recovered = chunk_analyzer.ChunkAnalyzer._mask_comments(
            unterminated_regex,
            mask_block=False,
        )
        assert 'import("./recovered.js")' in recovered
