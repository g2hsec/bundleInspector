"""
Webpack/Vite chunk analyzer.

Analyzes JavaScript bundles to extract chunk manifests,
lazy-loaded routes, and code-split boundaries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    IntermediateRepresentation,
    Severity,
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
    routes: dict[str, str] = field(default_factory=dict)  # route ??chunk
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
        # __webpack_require__.e(chunkId) ??dynamic chunk loading
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
        # Next.js page paths
        (r'pages?[/\\]([^"\']+?)(?:\.tsx?|\.jsx?|\.vue)', "nextjs_page"),
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
    def _build_line_index(source: str) -> list[int]:
        """Build offset?뭠ine lookup table. line_index[i] = line number at offset i (approx via newline positions)."""
        # Store newline offsets for bisect-based line lookup
        offsets = []
        for i, ch in enumerate(source):
            if ch == '\n':
                offsets.append(i)
        return offsets

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

        # Find chunk patterns (bundler detection is implicit via pattern matching)
        yield from self._find_webpack_patterns(source, context, newline_offsets)
        yield from self._find_vite_patterns(source, context, newline_offsets)
        yield from self._find_route_patterns(source, context, newline_offsets)
        yield from self._find_dynamic_imports(source, context, ir, newline_offsets)
        yield from self._find_chunk_route_mappings(source, context, newline_offsets)

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
                    description=f"Vite chunk infrastructure detected",
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

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=severity,
                    confidence=Confidence.HIGH,
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
        newline_offsets: list[int] = None,
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
                    value = f"{chunk_name} ??{import_path}"
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
        self, source: str, context: AnalysisContext, newline_offsets: list[int] = None
    ) -> Iterator[RuleResult]:
        """Find chunk-to-route mappings in bundle manifests."""
        if newline_offsets is None:
            newline_offsets = self._build_line_index(source)
        for pattern, pattern_type in self.CHUNK_ROUTE_PATTERNS:
            for match in re.finditer(pattern, source):
                value = match.group(1)
                line = self._offset_to_line(newline_offsets, match.start())

                # Convert chunk path to route: src_pages_Dashboard ??/dashboard
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
                        description=f"Route inferred from chunk: {value} ??{route}",
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
        # ./pages/Dashboard ??/dashboard
        # ./views/admin/Users ??/admin/users
        # ../components/Settings ??/settings

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

        # Convert to route: PascalCase ??kebab-case (per segment)
        segments = path.split("/")
        segments = [re.sub(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', '-', seg).lower().replace("_", "-") for seg in segments]
        route = "/".join(segments).replace("\\", "/")

        # index ??/
        if route.endswith("/index"):
            route = route[:-6] or "/"
        elif route == "index":
            route = "/"

        return f"/{route}" if not route.startswith("/") else route

    def _chunk_id_to_route(self, chunk_id: str) -> str:
        """Convert webpack chunk ID to route path."""
        # src_pages_Dashboard ??/dashboard
        # src_views_admin_Users ??/admin/users

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

