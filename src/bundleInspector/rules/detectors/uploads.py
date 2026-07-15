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
from bisect import bisect_right
from collections.abc import Iterator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

# Extension/MIME-specific names: unambiguously about file uploads -> emitted unconditionally.
_UPLOAD_EXT_KEYS = frozenset(
    {
        "allowedext",
        "allowext",
        "allowedextension",
        "allowedextensions",
        "acceptext",
        "allowedfiletype",
        "allowedfiletypes",
        "allowedmimetype",
        "allowedmimetypes",
        "validextensions",
        "fileext",
    }
)
# DQ-D02: generic names that ALSO name non-upload allow-lists (e.g. a role list
# `allowedTypes=["admin","editor"]`). These require corroboration: an upload surface in the same
# file, or a value that actually looks like file extensions / MIME types.
_UPLOAD_GENERIC_KEYS = frozenset({"allowedtype", "allowedtypes"})
_CLIENT_VALIDATION_KEYS = _UPLOAD_EXT_KEYS | _UPLOAD_GENERIC_KEYS

# Common file extensions (bare, without a leading dot) used to tell an upload allow-list from a
# role/enum list when corroborating a generic key.
_COMMON_UPLOAD_EXTS = frozenset(
    {
        "jpg",
        "jpeg",
        "png",
        "gif",
        "webp",
        "svg",
        "bmp",
        "ico",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "csv",
        "txt",
        "rtf",
        "zip",
        "rar",
        "7z",
        "gz",
        "tar",
        "mp4",
        "mov",
        "avi",
        "mkv",
        "webm",
        "mp3",
        "wav",
        "ogg",
        "json",
        "xml",
        "heic",
        "tiff",
    }
)
_RE_UPLOAD_MIME = re.compile(r"^[a-z]+/[a-z0-9.+*-]+$", re.IGNORECASE)
_RE_UPLOAD_DOTEXT = re.compile(r"^\.[a-z0-9]{1,5}$", re.IGNORECASE)

_RE_FILE_INPUT = re.compile(r"""type\s*=\s*['"]?file['"]?""", re.IGNORECASE)
_RE_MULTIPART = re.compile(r"multipart/form-data", re.IGNORECASE)
_MAX_WALK_NODES = 2_000_000  # DQ-D02: DoS guard far above any real bundle (~0.1s at 560k nodes)

# DQ-D02: attributes specific to an HTML file input, used to confirm a compiled/JSX
# `{type:"file", ...}` object props form (the dominant shape in minified bundles) is really a file
# input and not, say, a filesystem tree node `{type:"file", path:...}`.
_FILE_INPUT_ATTRS = frozenset(
    {
        "accept",
        "multiple",
        "capture",
        "webkitdirectory",
        "onchange",
        "onchangecapture",
    }
)


def _mask_comments(source: str) -> str:
    """Replace JavaScript comments with spaces while preserving offsets and newlines."""
    chars = list(source)
    state = "code"
    quote = ""
    escaped = False
    index = 0
    while index < len(chars):
        ch = chars[index]
        nxt = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "string":
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                state = "code"
            index += 1
            continue
        if state == "line":
            if ch in "\r\n":
                state = "code"
            else:
                chars[index] = " "
            index += 1
            continue
        if state == "block":
            if ch == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "code"
            else:
                if ch not in "\r\n":
                    chars[index] = " "
                index += 1
            continue
        if ch in "'\"`":
            state = "string"
            quote = ch
            index += 1
        elif ch == "/" and nxt == "/":
            chars[index] = chars[index + 1] = " "
            index += 2
            state = "line"
        elif ch == "/" and nxt == "*":
            chars[index] = chars[index + 1] = " "
            index += 2
            state = "block"
        else:
            index += 1
    return "".join(chars)


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
        seen: set[tuple[str, int, int]] = set()
        source = context.source_content or ""
        scan_source = _mask_comments(source)
        line_starts = [0]
        line_starts.extend(index + 1 for index, char in enumerate(source) if char == "\n")
        literal_spans: dict[tuple[str, int], list[tuple[int, int]]] = {}

        # String-literal surfaces: <input type="file">, multipart content-type.
        for lit in ir.string_literals:
            value = lit.value or ""
            if _RE_FILE_INPUT.search(value):
                key = ("file_input", lit.line, lit.column)
                if key not in seen:
                    seen.add(key)
                    literal_spans.setdefault(("file_input", lit.line), []).append(
                        (lit.column, lit.end_column or lit.column + len(value) + 2),
                    )
                    yield self._result(
                        'input type="file"',
                        "file_input",
                        Severity.INFO,
                        Confidence.MEDIUM,
                        lit.line,
                        lit.column,
                        "File-upload input built in JS (upload surface)",
                    )
            if _RE_MULTIPART.search(value):
                key = ("multipart", lit.line, lit.column)
                if key not in seen:
                    seen.add(key)
                    literal_spans.setdefault(("multipart", lit.line), []).append(
                        (lit.column, lit.end_column or lit.column + len(value) + 2),
                    )
                    yield self._result(
                        "multipart/form-data",
                        "file_upload",
                        Severity.INFO,
                        Confidence.MEDIUM,
                        lit.line,
                        lit.column,
                        "multipart/form-data upload surface",
                    )

        # DQ-D02: also scan the raw source so a React JSX / HTML-in-JS `type="file"` -- which esprima
        # cannot parse as JSX, so it never survives as a single string literal -- is still surfaced.
        # Deduped against the literal pass by (kind, line).
        for kind, pat, desc in (
            ("file_input", _RE_FILE_INPUT, "File-upload input built in JS (upload surface)"),
            ("multipart", _RE_MULTIPART, "multipart/form-data upload surface"),
        ):
            for m in pat.finditer(scan_source):
                line_index = bisect_right(line_starts, m.start()) - 1
                line = line_index + 1
                column = m.start() - line_starts[line_index]
                if any(start <= column < end for start, end in literal_spans.get((kind, line), [])):
                    continue
                key = (kind, line, column)
                if key not in seen:
                    seen.add(key)
                    val = 'input type="file"' if kind == "file_input" else "multipart/form-data"
                    vt = "file_input" if kind == "file_input" else "file_upload"
                    yield self._result(
                        val, vt, Severity.INFO, Confidence.MEDIUM, line, column, desc
                    )

        # An upload surface anywhere in the file corroborates an otherwise-ambiguous generic
        # allowedType(s) allow-list (vs a same-named role list).
        has_surface = bool(
            _RE_FILE_INPUT.search(scan_source)
            or _RE_MULTIPART.search(scan_source)
            or self._ast_has_formdata(ir.raw_ast or {})
            or any(
                _RE_FILE_INPUT.search(literal.value or "")
                or _RE_MULTIPART.search(literal.value or "")
                for literal in ir.string_literals
            )
        )

        # AST walk: new FormData(), and client-side extension/type allow-lists.
        yield from self._walk(ir.raw_ast or {}, seen, has_surface, context)

    @staticmethod
    def _ast_has_formdata(raw_ast: dict) -> bool:
        if not isinstance(raw_ast, dict):
            return False
        stack = [raw_ast]
        visited = 0
        while stack and visited < _MAX_WALK_NODES:
            node = stack.pop()
            visited += 1
            if not isinstance(node, dict):
                continue
            if node.get("type") == "NewExpression":
                callee = node.get("callee") or {}
                if isinstance(callee, dict) and callee.get("name") == "FormData":
                    return True
            for value in node.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(item for item in value if isinstance(item, dict))
        return False

    @staticmethod
    def _values_look_upload(value_node: object) -> bool:
        """True if a value (a string, or an array of strings) looks like file extensions or MIME
        types -- used to tell an upload allow-list from a role/enum list for a generic key."""
        strs: list[str] = []
        if isinstance(value_node, dict):
            if value_node.get("type") == "ArrayExpression":
                for el in value_node.get("elements", []) or []:
                    if (
                        isinstance(el, dict)
                        and el.get("type") == "Literal"
                        and isinstance(el.get("value"), str)
                    ):
                        strs.append(el["value"])
            elif value_node.get("type") == "Literal" and isinstance(value_node.get("value"), str):
                strs.append(value_node["value"])
        if not strs:
            return False
        # DQ-D05/D02: a dotted extension (".jpg") or a MIME type ("image/png") is an unambiguous
        # upload signal on its own. A bare word that merely coincides with an extension ("zip" a ZIP
        # code, "doc" a content kind) is not -- require a MAJORITY of bare values to be extension-like
        # so a single collision does not flip a role/enum list into an upload allow-list.
        strong = any(
            _RE_UPLOAD_MIME.match(s.strip()) or _RE_UPLOAD_DOTEXT.match(s.strip()) for s in strs
        )
        if strong:
            return True
        # A 2-element list may tie (["jpg","image"] = 1 ext + 1 category word is still an upload
        # allow-list); a longer list needs a STRICT majority so a format/negotiation enum with a
        # couple of ext-colliding words (["json","xml","yaml","toml"]) does not flip.
        ext_like = sum(1 for s in strs if s.strip().lower().lstrip(".") in _COMMON_UPLOAD_EXTS)
        return ext_like * 2 > len(strs) if len(strs) > 2 else ext_like * 2 >= len(strs)

    @staticmethod
    def _file_input_object(obj: dict) -> int | None:
        """DQ-D02: return the line of a compiled/JSX file input -- an object with a `type:"file"`
        property AND a file-input-SPECIFIC attribute (accept/multiple/capture/webkitdirectory/
        onChange). Requiring a specific attribute (rather than a file-global upload surface) keeps a
        bare filesystem/config `{type:"file", path:...}` from being mis-reported as an input, even in
        a bundle that also uses FormData elsewhere."""
        has_type_file = False
        has_attr = False
        line = 0
        for p in obj.get("properties") or []:
            if not isinstance(p, dict) or p.get("type") != "Property":
                continue
            k = p.get("key", {})
            kn = (
                k.get("name") or (k.get("value") if isinstance(k.get("value"), str) else "") or ""
            ).lower()
            if kn == "type":
                v = p.get("value", {})
                if (
                    isinstance(v, dict)
                    and v.get("type") == "Literal"
                    and str(v.get("value")).lower() == "file"
                ):
                    has_type_file = True
                    line = (p.get("loc") or {}).get("start", {}).get("line", 0)
            elif kn in _FILE_INPUT_ATTRS:
                has_attr = True
        return line if (has_type_file and has_attr) else None

    def _walk(
        self,
        raw_ast: dict,
        seen: set[tuple[str, int, int]],
        has_surface: bool,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        if not isinstance(raw_ast, dict):
            return
        stack = [raw_ast]
        seen_nodes = 0
        while stack:
            node = stack.pop()
            seen_nodes += 1
            if seen_nodes > _MAX_WALK_NODES:
                context.metadata.setdefault("analysis_incomplete", []).append(
                    {
                        "component": self.id,
                        "reason": "ast_node_cap",
                        "processed": _MAX_WALK_NODES,
                        "limit": _MAX_WALK_NODES,
                    }
                )
                break
            if not isinstance(node, dict):
                continue
            ntype = node.get("type")

            if ntype == "NewExpression":
                callee = node.get("callee", {})
                if isinstance(callee, dict) and callee.get("name") == "FormData":
                    loc = (node.get("loc") or {}).get("start", {})
                    line = loc.get("line", 0)
                    column = loc.get("column", 0)
                    if ("formdata", line, column) not in seen:
                        seen.add(("formdata", line, column))
                        yield self._result(
                            "new FormData()",
                            "file_upload",
                            Severity.LOW,
                            Confidence.MEDIUM,
                            line,
                            column,
                            "FormData upload surface (programmatic multipart upload)",
                        )

            elif ntype == "ObjectExpression":
                # compiled/JSX file input: jsx("input", {type:"file", accept:..., onChange:...})
                fline = self._file_input_object(node)
                fcol = (node.get("loc") or {}).get("start", {}).get("column", 0)
                if fline is not None and ("file_input", fline, fcol) not in seen:
                    seen.add(("file_input", fline, fcol))
                    yield self._result(
                        'type: "file"',
                        "file_input",
                        Severity.INFO,
                        Confidence.MEDIUM,
                        fline,
                        0,
                        "File-upload input (compiled JSX / element props) -- upload surface",
                    )

            elif ntype == "VariableDeclarator":
                # DQ-D02: a generic `const/let/var allowedType(s) = [...]` carries its allow-list on
                # the declarator's init, not on the Identifier node, so corroborate it here by value.
                idn = node.get("id", {})
                if isinstance(idn, dict) and idn.get("type") == "Identifier":
                    nlow = (idn.get("name") or "").lower()
                    if nlow in _UPLOAD_GENERIC_KEYS and self._values_look_upload(node.get("init")):
                        loc = (idn.get("loc") or {}).get("start", {})
                        line = loc.get("line", 0)
                        column = loc.get("column", 0)
                        if ("clientval", line, column) not in seen:
                            seen.add(("clientval", line, column))
                            yield self._result(
                                str(idn.get("name") or ""),
                                "client_side_file_validation",
                                Severity.MEDIUM,
                                Confidence.MEDIUM,
                                line,
                                column,
                                f"Client-side file-type allow-list ('{idn.get('name')}') -- bypassable; "
                                f"verify the server re-validates the file type/extension (unrestricted-upload risk)",
                            )

            elif ntype in ("Property", "Identifier"):
                # a key/identifier that names a client-side extension/type allow-list
                name = None
                if ntype == "Property":
                    keyn = node.get("key", {})
                    name = keyn.get("name") or (
                        keyn.get("value") if isinstance(keyn.get("value"), str) else None
                    )
                else:
                    name = node.get("name")
                nlow = name.lower() if isinstance(name, str) else None
                emit = False
                if nlow in _UPLOAD_EXT_KEYS:
                    emit = True  # extension-specific name -> unambiguous
                elif nlow in _UPLOAD_GENERIC_KEYS:
                    # DQ-D02: a generic allowedType(s) is an upload allow-list only when corroborated
                    # by an upload surface in the file or by extension/MIME-like values -- otherwise
                    # it is likely a role/enum list (allowedTypes=["admin","editor"]).
                    emit = has_surface or (
                        ntype == "Property" and self._values_look_upload(node.get("value"))
                    )
                if emit:
                    loc = (node.get("loc") or {}).get("start", {})
                    line = loc.get("line", 0)
                    column = loc.get("column", 0)
                    if ("clientval", line, column) not in seen:
                        seen.add(("clientval", line, column))
                        yield self._result(
                            str(name or ""),
                            "client_side_file_validation",
                            Severity.MEDIUM,
                            Confidence.MEDIUM,
                            line,
                            column,
                            f"Client-side file-type allow-list ('{name}') -- bypassable; verify the "
                            f"server re-validates the file type/extension (unrestricted-upload risk)",
                        )

            for k, v in node.items():
                if k in ("loc", "range", "raw"):
                    continue
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            stack.append(item)

    def _result(
        self,
        value: str,
        value_type: str,
        severity: Severity,
        confidence: Confidence,
        line: int,
        column: int,
        description: str,
    ) -> RuleResult:
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
