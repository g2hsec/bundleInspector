"""
File-upload surface detector.

Surfaces client-side file-upload logic:
- `new FormData()` / multipart usage (programmatic upload surface),
- `<input type="file">` markup built in JS,
- **client-side-only file-type/size validation** (an allow-list of extensions checked in JS),
  which is trivially bypassable and, if the server does not re-validate, enables unrestricted
  file upload.

Like the sink detector this reports an INDICATOR to review, not a proven vulnerability: the
server-side control cannot be seen from the bundle.
"""

from __future__ import annotations

import re
from typing import Iterator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

# Identifier / property names that gate uploads by file extension or type on the CLIENT.
_CLIENT_VALIDATION_KEYS = frozenset({
    "allowedext", "allowext", "allowedextension", "allowedextensions", "acceptext",
    "allowedtype", "allowedtypes", "allowedfiletype", "allowedfiletypes",
    "allowedmimetype", "allowedmimetypes", "validextensions", "fileext",
})

_RE_FILE_INPUT = re.compile(r"""type\s*=\s*['"]?file['"]?""", re.IGNORECASE)
_RE_MULTIPART = re.compile(r"multipart/form-data", re.IGNORECASE)


class FileUploadDetector(BaseRule):
    """Detect file-upload surfaces and bypassable client-side upload validation."""

    id = "upload-detector"
    name = "File Upload Surface Detector"
    description = "Detects file-upload surfaces and client-side-only upload validation"
    category = Category.UPLOAD
    severity = Severity.LOW

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        seen: set[tuple[str, int]] = set()

        # String-literal surfaces: <input type="file">, multipart content-type.
        for lit in ir.string_literals:
            value = lit.value or ""
            if _RE_FILE_INPUT.search(value):
                key = ("file_input", lit.line)
                if key not in seen:
                    seen.add(key)
                    yield self._result('input type="file"', "file_input", Severity.INFO,
                                       Confidence.MEDIUM, lit.line, lit.column,
                                       "File-upload input built in JS (upload surface)")
            if _RE_MULTIPART.search(value):
                key = ("multipart", lit.line)
                if key not in seen:
                    seen.add(key)
                    yield self._result("multipart/form-data", "file_upload", Severity.INFO,
                                       Confidence.MEDIUM, lit.line, lit.column,
                                       "multipart/form-data upload surface")

        # AST walk: new FormData(), and client-side extension/type allow-lists.
        yield from self._walk(ir.raw_ast or {}, seen)

    def _walk(self, raw_ast: dict, seen: set) -> Iterator[RuleResult]:
        if not isinstance(raw_ast, dict):
            return
        stack = [raw_ast]
        seen_nodes = 0
        while stack:
            node = stack.pop()
            seen_nodes += 1
            if seen_nodes > 200000 or not isinstance(node, dict):
                continue
            ntype = node.get("type")

            if ntype == "NewExpression":
                callee = node.get("callee", {})
                if isinstance(callee, dict) and callee.get("name") == "FormData":
                    loc = (node.get("loc") or {}).get("start", {})
                    line = loc.get("line", 0)
                    if ("formdata", line) not in seen:
                        seen.add(("formdata", line))
                        yield self._result("new FormData()", "file_upload", Severity.LOW,
                                           Confidence.MEDIUM, line, loc.get("column", 0),
                                           "FormData upload surface (programmatic multipart upload)")

            elif ntype in ("Property", "Identifier"):
                # a key/identifier that names a client-side extension/type allow-list
                name = None
                if ntype == "Property":
                    keyn = node.get("key", {})
                    name = keyn.get("name") or (keyn.get("value") if isinstance(keyn.get("value"), str) else None)
                else:
                    name = node.get("name")
                if isinstance(name, str) and name.lower() in _CLIENT_VALIDATION_KEYS:
                    loc = (node.get("loc") or {}).get("start", {})
                    line = loc.get("line", 0)
                    if ("clientval", line) not in seen:
                        seen.add(("clientval", line))
                        yield self._result(
                            name, "client_side_file_validation", Severity.MEDIUM, Confidence.MEDIUM,
                            line, loc.get("column", 0),
                            f"Client-side file-type allow-list ('{name}') -- bypassable; verify the "
                            f"server re-validates the file type/extension (unrestricted-upload risk)")

            for k, v in node.items():
                if k in ("loc", "range", "raw"):
                    continue
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            stack.append(item)

    def _result(self, value: str, value_type: str, severity: Severity, confidence: Confidence,
                line: int, column: int, description: str) -> RuleResult:
        return RuleResult(
            rule_id=self.id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            title=f"Upload: {value}",
            description=description,
            extracted_value=value,
            value_type=value_type,
            line=line,
            column=column,
            ast_node_type="",
            tags=["file_upload", value_type],
        )
