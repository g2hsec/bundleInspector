"""
Webpack/Vite chunk analyzer.

Analyzes JavaScript bundles to extract chunk manifests,
lazy-loaded routes, and code-split boundaries.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from bundleInspector.parser.lexical_context import LexicalGoal, is_line_terminator
from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
)

# DQ-D08: a bare `path: "..."` match yields many values that are NOT app routes -- asset/code
# file paths, URLs (the endpoint detector's territory), and SVG path data / free text. Gating
# these removes the dominant route_path false positives without dropping real routes (which are
# extensionless tokens like "/admin" or nested "users/edit").
_NON_ROUTE_EXT_RE = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|tsx|vue|svelte|css|scss|sass|less|json|map|png|jpe?g|gif|svg|"
    r"webp|avif|woff2?|ttf|otf|eot|ico|wasm|txt|md|html?|xml|csv|pdf)$",
    re.IGNORECASE,
)

@dataclass
class ChunkInfo:
    """Information about a code-split chunk."""
    chunk_id: str
    chunk_name: str = ""
    route: str = ""
    source_file: str = ""
    dependencies: list[str] = field(default_factory=list)
    is_lazy: bool = False
    is_entry: bool = False


@dataclass
class ChunkManifest:
    """Parsed chunk manifest."""
    bundler: str = ""  # webpack, vite, rollup, parcel
    chunks: list[ChunkInfo] = field(default_factory=list)
    routes: dict[str, str] = field(default_factory=dict)  # route -> chunk
    entrypoints: list[str] = field(default_factory=list)


class ChunkAnalyzer(BaseRule):
    """
    Detect and analyze Webpack/Vite code-split chunks.

    Finds:
    - Chunk manifest data (webpackJsonp, __webpack_require__)
    - Dynamic imports with route mappings
    - Lazy-loaded component paths
    - Route-to-chunk mappings
    - Hidden routes not linked in navigation
    """

    id = "chunk-analyzer"
    name = "Chunk Analyzer"
    description = "Analyzes code-split chunks to discover hidden routes and lazy-loaded components"
    category = Category.ENDPOINT
    severity = Severity.INFO
    enabled = True

    # Webpack patterns
    WEBPACK_PATTERNS = [
        # webpackJsonp / webpackChunk push
        (r'(?:webpackJsonp|webpackChunk\w*)\s*(?:\.\s*push|=)', "webpack_chunk_push"),
        # __webpack_require__.e(chunkId) -> dynamic chunk loading
        (r'__webpack_require__\.e\s*\(\s*["\']?(\w+)["\']?\s*\)', "webpack_require_ensure"),
        # webpack chunk loading: __webpack_require__.f.j
        (r'__webpack_require__\.f\.j\s*=', "webpack_chunk_loader"),
        # Webpack public path
        (r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']', "webpack_public_path"),
    ]

    # Vite patterns
    VITE_PATTERNS = [
        # Vite dynamic import
        (r'__vite__mapDeps\s*\(', "vite_map_deps"),
        # Vite preload
        (r'__vitePreload\s*\(', "vite_preload"),
    ]

    # Route configuration patterns
    ROUTE_PATTERNS = [
        # React Router style: { path: "/foo", component: lazy(() => import("./Foo")) }
        (r'path\s*:\s*["\']([^"\']+)["\']', "route_path"),
        # Vue Router style: { path: "/foo", component: () => import("./Foo.vue") }
        (r'component\s*:\s*\(\)\s*=>\s*import\s*\(\s*["\']([^"\']+)["\']', "lazy_component"),
        # Next.js page paths. Bounded ({1,200}): the lazy unbounded ([^"\']+?) before the required
        # extension suffix scanned to EOF from every `page/` start -> O(n^2) on a long `page/`-repeated
        # string literal (reached on the DEFAULT pipeline via ChunkAnalyzer.match). A real page path
        # is short, so the match set is unchanged.
        (r'pages?[/\\]([^"\']{1,200}?)(?:\.tsx?|\.jsx?|\.vue)', "nextjs_page"),
    ]

    # Dynamic import patterns
    IMPORT_PATTERNS = [
        # import(/* webpackChunkName: "foo" */ "./bar")
        (r'import\s*\(\s*/\*\s*webpackChunkName\s*:\s*["\']([^"\']+)["\']\s*\*/\s*["\']([^"\']+)["\']', "webpack_named_chunk"),
        # import("./path")
        (r'import\s*\(\s*["\']([^"\']+)["\']', "dynamic_import"),
        # React.lazy(() => import("./path"))
        (r'lazy\s*\(\s*\(\)\s*=>\s*import\s*\(\s*["\']([^"\']+)["\']', "react_lazy"),
        # loadable(() => import("./path"))
        (r'loadable\s*\(\s*\(\)\s*=>\s*import\s*\(\s*["\']([^"\']+)["\']', "loadable_import"),
    ]

    # Chunk-to-route mapping patterns (common in build outputs)
    CHUNK_ROUTE_PATTERNS = [
        # { "chunkId": "src_pages_Dashboard" } or similar manifest entries
        (r'["\']?(src[_/](?:pages|views|routes|screens)[_/][^"\'}\s,]+)["\']?', "chunk_page_path"),
    ]

    @staticmethod
    def _mask_comments(source: str, mask_block: bool = True) -> str:
        """Return `source` with comment bytes replaced by spaces, preserving length and newlines
        (so precomputed offset-to-line lookups stay correct) so commented-out config is not
        mis-reported as live routes. String, template, and regex literals are skipped -- a URL like
        "https://x" inside a string, or the escaped slashes in a regex like /\\/\\//g, are never
        treated as a `//` comment. Template interpolations `${ ... }` (including nested template
        literals) are tracked with a brace stack so their code is scanned normally and an inner
        template's backtick is never mistaken for the outer template's terminator.

        When `mask_block` is False, only a syntactically recognized webpack chunk-name comment is
        retained; every ordinary block comment remains inert. The dynamic-import scan needs that
        one metadata form (`/* webpackChunkName: "x" */`) but must never execute arbitrary comment
        text as a dependency."""
        out = list(source)
        i, n = 0, len(source)
        ctx = "code"          # "code" | "sq" (') | "dq" (") | "tpl" (` template string)
        interp = []           # brace-depth counter per active ${ ... } interpolation (a stack)
        lexical_goal = LexicalGoal()
        while i < n:
            ch = source[i]
            nxt = source[i + 1] if i + 1 < n else ""
            if ctx in ("sq", "dq"):
                if ch == "\\":
                    i += 2                       # skip escaped char inside the string
                    continue
                if ch == ("'" if ctx == "sq" else '"'):
                    ctx = "code"
                    lexical_goal.note_operand()
                i += 1
                continue
            if ctx == "tpl":
                if ch == "\\":
                    i += 2                       # skip escaped char inside the template
                    continue
                if ch == "`":
                    ctx = "code"
                    lexical_goal.note_operand()
                    i += 1
                    continue
                if ch == "$" and nxt == "{":
                    interp.append(0)             # enter interpolation code; } at depth 0 exits it
                    ctx = "code"
                    lexical_goal.enter_template_expression()
                    i += 2
                    continue
                i += 1                           # ordinary template character
                continue
            # ctx == "code"
            if ch == "'":
                ctx = "sq"
                i += 1
                continue
            if ch == '"':
                ctx = "dq"
                i += 1
                continue
            if ch == "`":
                ctx = "tpl"
                i += 1
                continue
            if ch == "/" and nxt == "/":
                # line comment: always a comment in any context; never carries magic info.
                out[i] = out[i + 1] = " "
                i += 2
                while i < n and not is_line_terminator(source[i]):
                    out[i] = " "
                    i += 1
                # A comment is whitespace-equivalent: keep the lexical goal so a following `/`
                # after an operand (a / b) remains division, not a regex start.
                continue
            if ch == "/" and nxt == "*":
                # Block comments are always inert. The dynamic-import view retains only the exact
                # webpack chunk-name metadata grammar consumed by IMPORT_PATTERNS.
                start = i
                i += 2
                while i < n and not (source[i] == "*" and (source[i + 1] if i + 1 < n else "") == "/"):
                    i += 1
                i = min(i + 2, n)                # consume the closing */ (or run to EOF)
                comment_text = source[start:i]
                keep_magic = not mask_block and re.fullmatch(
                    r"/\*\s*webpackChunkName\s*:\s*[\"'][^\"']+[\"']\s*\*/",
                    comment_text,
                )
                if not keep_magic:
                    for k in range(start, i):
                        if source[k] != "\n":
                            out[k] = " "
                # Keep the lexical goal so an inline block comment between an operand and `/`
                # (a /* c */ / b) does not turn division into a regex and swallow later code.
                continue
            if ch == "/" and lexical_goal.can_start_regex(source, i):
                # Regex bodies are data, not executable bundle syntax. Consume them as one token
                # and blank their bytes so code-looking import/route text cannot be detected.
                start = i
                i += 1
                in_class = False
                while i < n:
                    c = source[i]
                    if (
                        c == "\\"
                        and i + 1 < n
                        and not is_line_terminator(source[i + 1])
                    ):
                        i += 2
                        continue
                    if is_line_terminator(c):
                        lexical_goal.note_operand()
                        break                    # unterminated regex; stop to avoid runaway
                    if c == "[":
                        in_class = True
                    elif c == "]":
                        in_class = False
                    elif c == "/" and not in_class:
                        i += 1
                        lexical_goal.note_operand()
                        break
                    i += 1
                for k in range(start, i):
                    if not is_line_terminator(source[k]):
                        out[k] = " "
                continue
            if interp:
                # inside a ${ ... } interpolation: balance braces so the matching } returns to the
                # enclosing template (an object literal's own braces stay inside the interpolation).
                if ch == "{":
                    interp[-1] += 1
                elif ch == "}":
                    if interp[-1] == 0:
                        interp.pop()
                        ctx = "tpl"
                        lexical_goal.note_operand()
                        i += 1
                        continue
                    interp[-1] -= 1
            # ordinary code char (includes a division `/`)
            lexical_goal.observe_code_char(source, i)
            i += 1
        return "".join(out)

    @staticmethod
    def _looks_like_route(value: str) -> bool:
        """True if `value` is plausibly an app route -- not a file path, URL, or SVG/free text."""
        v = value.strip()
        if not v or " " in v or "\t" in v or "\\" in v:
            return False
        if "://" in v or v.startswith("//"):
            return False                          # absolute/protocol-relative URL, not a route
        if _NON_ROUTE_EXT_RE.search(v):
            return False                          # a file path, not a route
        return True

    @staticmethod
    def _build_line_index(source: str) -> list[int]:
        """Build offset-to-line lookup table. line_index[i] = line number at offset i (approx via newline positions)."""
        # Store the last code-point offset of each ECMAScript line terminator. CRLF contributes one
        # entry at LF, so bisect-based lookup counts the sequence exactly once.
        return [
            match.end() - 1
            for match in re.finditer(r"\r\n|\r|\n|\u2028|\u2029", source)
        ]

    @staticmethod
    def _offset_to_line(newline_offsets: list[int], offset: int) -> int:
        """Convert character offset to 1-based line number using binary search."""
        import bisect
        return bisect.bisect_right(newline_offsets, offset - 1) + 1

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Analyze chunks in IR."""
        source = context.source_content

        # Build line index once for all pattern searches
        newline_offsets = self._build_line_index(source)

        # DQ-D08: scan comment-masked source so commented-out config is not mis-detected. Same
        # length + newlines as the original, so `newline_offsets` still maps offsets to lines.
        # Dynamic imports use the selective mask, which retains only the exact
        # `/* webpackChunkName */` metadata grammar that scan depends on.
        masked = self._mask_comments(source, mask_block=True)
        masked_line = self._mask_comments(source, mask_block=False)

        # Find chunk patterns (bundler detection is implicit via pattern matching)
        yield from self._find_webpack_patterns(masked, context, newline_offsets)
        yield from self._find_vite_patterns(masked, context, newline_offsets)
        yield from self._find_route_patterns(masked, context, newline_offsets)
        yield from self._find_dynamic_imports(masked_line, context, ir, newline_offsets)
        yield from self._find_chunk_route_mappings(masked, context, newline_offsets)

    def _find_webpack_patterns(
        self, source: str, context: AnalysisContext, newline_offsets: list[int]
    ) -> Iterator[RuleResult]:
        """Find Webpack-specific chunk patterns."""
        for pattern, pattern_type in self.WEBPACK_PATTERNS:
            for match in re.finditer(pattern, source):
                line = self._offset_to_line(newline_offsets, match.start())
                value = match.group(1) if match.lastindex else match.group(0)

                # For public path, this reveals asset hosting location
                severity = Severity.INFO
                if pattern_type == "webpack_public_path":
                    severity = Severity.LOW

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    title=f"Webpack: {pattern_type.replace('_', ' ').title()}",
                    description=f"Webpack chunk infrastructure detected: {value[:80]}",
                    extracted_value=value[:200],
                    value_type=pattern_type,
                    line=line,
                    column=0,
                    ast_node_type="Expression",
                    tags=["chunk", "webpack", pattern_type],
                )

    def _find_vite_patterns(
        self, source: str, context: AnalysisContext, newline_offsets: list[int]
    ) -> Iterator[RuleResult]:
        """Find Vite-specific patterns."""
        for pattern, pattern_type in self.VITE_PATTERNS:
            for match in re.finditer(pattern, source):
                line = self._offset_to_line(newline_offsets, match.start())

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    title=f"Vite: {pattern_type.replace('_', ' ').title()}",
                    description="Vite chunk infrastructure detected",
                    extracted_value=match.group(0)[:200],
                    value_type=pattern_type,
                    line=line,
                    column=0,
                    ast_node_type="Expression",
                    tags=["chunk", "vite", pattern_type],
                )

    def _find_route_patterns(
        self, source: str, context: AnalysisContext, newline_offsets: list[int]
    ) -> Iterator[RuleResult]:
        """Find route configuration patterns."""
        for pattern, pattern_type in self.ROUTE_PATTERNS:
            for match in re.finditer(pattern, source):
                value = match.group(1)

                # DQ-D08: the generic `path: "..."` matcher fires on any config path. Keep only
                # values that actually look like routes so file paths / URLs / SVG data drop out.
                if pattern_type == "route_path" and not self._looks_like_route(value):
                    continue

                line = self._offset_to_line(newline_offsets, match.start())

                # Route paths are interesting for endpoint discovery
                severity = Severity.LOW
                if any(kw in value.lower() for kw in (
                    "admin", "internal", "debug", "dashboard", "settings",
                    "config", "manage", "panel"
                )):
                    severity = Severity.MEDIUM

                # Determine if this is a page/route path
                title_prefix = "Route" if pattern_type in ("route_path", "nextjs_page") else "Lazy Component"

                # DQ-D08: a bare `path:` string is weaker evidence than an explicit import()/lazy
                # target, so it is reported at MEDIUM; the specific patterns stay HIGH.
                confidence = Confidence.MEDIUM if pattern_type == "route_path" else Confidence.HIGH

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=severity,
                    confidence=confidence,
                    title=f"{title_prefix}: {value[:50]}",
                    description=f"Found {pattern_type.replace('_', ' ')}: {value}",
                    extracted_value=value,
                    value_type=pattern_type,
                    line=line,
                    column=0,
                    ast_node_type="Literal",
                    tags=["chunk", "route", pattern_type],
                    metadata={"route": value},
                )

    def _find_dynamic_imports(
        self,
        source: str,
        context: AnalysisContext,
        ir: IntermediateRepresentation,
        newline_offsets: list[int] | None = None,
    ) -> Iterator[RuleResult]:
        """Find dynamic import() patterns with chunk info."""
        if newline_offsets is None:
            newline_offsets = self._build_line_index(source)
        for pattern, pattern_type in self.IMPORT_PATTERNS:
            for match in re.finditer(pattern, source):
                line = self._offset_to_line(newline_offsets, match.start())

                if pattern_type == "webpack_named_chunk":
                    chunk_name = match.group(1)
                    import_path = match.group(2)
                    value = f"{chunk_name} -> {import_path}"
                else:
                    import_path = match.group(1)
                    chunk_name = ""
                    value = import_path

                # Extract potential route from import path
                route = self._path_to_route(import_path)

                severity = Severity.INFO
                if route and any(kw in route.lower() for kw in (
                    "admin", "internal", "debug", "hidden", "secret"
                )):
                    severity = Severity.MEDIUM

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    title=f"Dynamic Import: {value[:50]}",
                    description=f"Lazy-loaded module: {value}",
                    extracted_value=value,
                    value_type=pattern_type,
                    line=line,
                    column=0,
                    ast_node_type="ImportExpression",
                    tags=["chunk", "lazy", pattern_type],
                    metadata={
                        "chunk_name": chunk_name,
                        "import_path": import_path,
                        "inferred_route": route,
                    },
                )

    def _find_chunk_route_mappings(
        self, source: str, context: AnalysisContext, newline_offsets: list[int] | None = None
    ) -> Iterator[RuleResult]:
        """Find chunk-to-route mappings in bundle manifests."""
        if newline_offsets is None:
            newline_offsets = self._build_line_index(source)
        for pattern, _pattern_type in self.CHUNK_ROUTE_PATTERNS:
            for match in re.finditer(pattern, source):
                value = match.group(1)
                line = self._offset_to_line(newline_offsets, match.start())

                # Convert chunk path to route: src_pages_Dashboard -> /dashboard
                route = self._chunk_id_to_route(value)

                if route:
                    severity = Severity.LOW
                    if any(kw in route.lower() for kw in (
                        "admin", "internal", "debug", "hidden"
                    )):
                        severity = Severity.MEDIUM

                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        title=f"Chunk Route: {route}",
                        description=f"Route inferred from chunk: {value} -> {route}",
                        extracted_value=route,
                        value_type="chunk_route",
                        line=line,
                        column=0,
                        ast_node_type="Literal",
                        tags=["chunk", "route", "inferred"],
                        metadata={
                            "chunk_id": value,
                            "inferred_route": route,
                        },
                    )

    def _path_to_route(self, import_path: str) -> str:
        """Infer route from import path."""
        # ./pages/Dashboard -> /dashboard
        # ./views/admin/Users -> /admin/users
        # ../components/Settings -> /settings

        # Remove relative prefix
        path = re.sub(r'^(?:\.\.?/)+', '', import_path)

        # Remove file extension
        path = re.sub(r'\.(tsx?|jsx?|vue|svelte)$', '', path)

        # Remove common prefixes (may be stacked, e.g. src/pages/...)
        changed = True
        while changed:
            changed = False
            for prefix in ("pages/", "views/", "routes/", "screens/", "components/", "src/"):
                if path.startswith(prefix):
                    path = path[len(prefix):]
                    changed = True
                    break

        if not path:
            return ""

        # Convert to route: PascalCase -> kebab-case (per segment)
        segments = path.split("/")
        segments = [re.sub(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', '-', seg).lower().replace("_", "-") for seg in segments]
        route = "/".join(segments).replace("\\", "/")

        # index -> /
        if route.endswith("/index"):
            route = route[:-6] or "/"
        elif route == "index":
            route = "/"

        return f"/{route}" if not route.startswith("/") else route

    def _chunk_id_to_route(self, chunk_id: str) -> str:
        """Convert webpack chunk ID to route path."""
        # src_pages_Dashboard -> /dashboard
        # src_views_admin_Users -> /admin/users

        # Split on underscores and slashes (chunk IDs use either separator)
        parts = re.split(r'[_/]', chunk_id)

        # Find the page/view starting point
        start_idx = 0
        for i, part in enumerate(parts):
            if part.lower() in ("pages", "views", "routes", "screens"):
                start_idx = i + 1
                break
        else:
            return ""

        if start_idx >= len(parts):
            return ""

        route_parts = parts[start_idx:]
        # Convert PascalCase parts to kebab-case (consistent with _path_to_route)
        route = "/".join(
            re.sub(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', '-', p).lower()
            for p in route_parts if p
        )

        return f"/{route}" if route else ""
