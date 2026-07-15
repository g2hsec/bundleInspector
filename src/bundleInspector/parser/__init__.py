"""JS parsing module - AST parsing and IR building."""

from bundleInspector.parser.ir_builder import IntermediateRepresentation, IRBuilder
from bundleInspector.parser.js_parser import JSParser, ParseResult
from bundleInspector.parser.string_table import StringLiteral, StringTable

__all__ = [
    "JSParser",
    "ParseResult",
    "IRBuilder",
    "IntermediateRepresentation",
    "StringTable",
    "StringLiteral",
]
