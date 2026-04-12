"""JS parsing module - AST parsing and IR building."""

from bundleInspector.parser.js_parser import JSParser, ParseResult
from bundleInspector.parser.ir_builder import IRBuilder, IntermediateRepresentation
from bundleInspector.parser.string_table import StringTable, StringLiteral

__all__ = [
    "JSParser",
    "ParseResult",
    "IRBuilder",
    "IntermediateRepresentation",
    "StringTable",
    "StringLiteral",
]

