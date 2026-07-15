"""
Light per-asset analysis module (enh: light-module split).

Holds the pure parse -> IR -> rules -> annotate -> map logic for a SINGLE asset, extracted
verbatim from Orchestrator so parallel workers can import it WITHOUT dragging in the browser
(playwright) / network (httpx) stack. Windows uses spawn: every worker re-imports its module
graph, so keeping this module free of collector/httpx imports is what makes
BUNDLEINSPECTOR_PARALLEL fan-out cheap. Findings are byte-identical to the serial path
because these method bodies are unchanged.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

import structlog

from bundleInspector.core.text_decode import decode_js_bytes
from bundleInspector.normalizer.sourcemap import SourceMapResolver
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
from bundleInspector.parser.language import language_hint_from_path
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.storage.models import Finding, JSAsset

if TYPE_CHECKING:
    from bundleInspector.core.dedup import DedupCache
    from bundleInspector.normalizer.line_mapping import LineMapper
    from bundleInspector.normalizer.sourcemap import SourceMapInfo
    from bundleInspector.parser.ir_builder import IRBuilder
    from bundleInspector.parser.js_parser import JSParser
    from bundleInspector.rules.engine import RuleEngine
    from bundleInspector.storage.models import FunctionDef, IntermediateRepresentation

logger = structlog.get_logger(__name__)

_MAX_VIRTUAL_SOURCE_EVENTS = 256
_MAX_SOURCE_OCCURRENCES = 256
_MAX_EVENT_DETAILS = 32
_MAX_VIRTUAL_SOURCES = 512
_MAX_VIRTUAL_SOURCE_BYTES = 20 * 1024 * 1024
_ASSET_ENRICHMENT_SUMMARY = (
    "asset analysis incomplete (component=asset_enrichment; reason=failed)"
)


def _asset_enrichment_event() -> dict[str, Any]:
    """Return the stable, secret-free enrichment completeness event."""
    return {
        "component": "asset_enrichment",
        "reason": "failed",
        "partial_results": True,
    }


def _ir_incomplete_event() -> dict[str, Any]:
    """Return the stable final-IR completeness event shared by every analysis path."""
    return {
        "component": "intermediate_representation",
        "reason": "truncated",
        "partial_results": True,
    }


def _append_unique_analysis_event(
    events: list[dict[str, Any]],
    event: dict[str, Any],
) -> None:
    if event not in events:
        events.append(event)


def _virtual_source_hash(source_path: str, content: str) -> str:
    """Bind virtual evidence identity to both its logical path and exact source content."""
    digest = hashlib.sha256()
    digest.update(source_path.encode("utf-8", "surrogatepass"))
    digest.update(b"\0")
    digest.update(content.encode("utf-8", "surrogatepass"))
    return digest.hexdigest()[:16]


def _append_virtual_source_event(
    events: list[dict[str, Any]] | None,
    event: dict[str, Any],
) -> None:
    """Append one bounded, unique event without suppressing a diagnostic-cap disclosure."""
    if events is None or event in events:
        return
    virtual_count = sum(
        1
        for existing in events
        if isinstance(existing, dict)
        and (
            str(existing.get("component", "")).startswith("virtual_source")
            or existing.get("virtual_source") is True
        )
        and existing.get("reason") != "diagnostic_cap"
    )
    if virtual_count < _MAX_VIRTUAL_SOURCE_EVENTS:
        events.append(event)
        return
    capped = {
        "component": "virtual_source",
        "reason": "diagnostic_cap",
        "partial_results": True,
        "event_cap": _MAX_VIRTUAL_SOURCE_EVENTS,
    }
    if capped not in events:
        events.append(capped)


def _virtual_event_summary(event: dict[str, Any]) -> str | None:
    component = str(event.get("component", ""))
    if component == "asset_enrichment" and event.get("reason") == "failed":
        return _ASSET_ENRICHMENT_SUMMARY
    if not component.startswith("virtual_source"):
        return None
    parts = [
        f"component={component}",
        f"reason={event.get('reason', 'incomplete')}",
    ]
    for key in ("source_hash", "backend", "error_count", "event_cap"):
        if key in event:
            parts.append(f"{key}={event[key]}")
    return "virtual source analysis incomplete (" + "; ".join(parts) + ")"


class AssetAnalyzer:
    """Stateless per-asset analyzer carrying only the collaborators the moved logic uses."""

    def __init__(
        self,
        parser: JSParser,
        ir_builder: IRBuilder,
        rule_engine: RuleEngine,
        dedup: DedupCache,
    ) -> None:
        self.parser = parser
        self.ir_builder = ir_builder
        self.rule_engine = rule_engine
        self.dedup = dedup

    def _apply_mappings(
        self,
        findings: list[Finding],
        line_mapper: LineMapper | None,
        sourcemap: SourceMapInfo | None,
    ) -> None:
        """Apply position mappings using an explicit line_mapper/sourcemap (no self state),
        so per-asset analysis can run in a worker process without the orchestrator's maps."""
        resolver = SourceMapResolver()
        original_sources = resolver.get_original_sources(sourcemap) if sourcemap else {}

        for finding in findings:
            # DQ-P07: the sourcemap's mappings describe the GENERATED (minified) coordinate space.
            # The parser runs on the beautified/normalized asset, so finding.evidence.line/column are
            # normalized coords; the LineMapper reconstructs the generated coords from them. Use those
            # for the sourcemap lookup -- passing the raw normalized coords mis-resolves any beautified
            # asset. For an identity mapper the generated coords equal the finding coords.
            gen_line, gen_col = finding.evidence.line, finding.evidence.column
            if line_mapper and finding.evidence.line > 0:
                gen_line, gen_col = line_mapper.get_original(
                    finding.evidence.line,
                    finding.evidence.column,
                )
                finding.evidence.original_line = gen_line
                finding.evidence.original_column = gen_col

            if not sourcemap or finding.evidence.line <= 0:
                continue

            position = resolver.get_original_position(
                sourcemap,
                gen_line,
                gen_col,
            )
            if not position:
                continue

            finding.evidence.original_file_url = position.source
            finding.evidence.original_line = position.line
            finding.evidence.original_column = position.column

            source_content = original_sources.get(position.source)
            if source_content:
                snippet, snippet_lines = self._build_snippet(
                    source_content,
                    position.line,
                )
                finding.metadata["original_snippet"] = snippet
                finding.metadata["original_snippet_lines"] = list(snippet_lines)

    def _analyze_one_virtual_source(
        self,
        source_path: str,
        content: str,
        is_first_party: bool,
        *,
        incomplete_events: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """Parse + analyze a single original (pre-minification) source as its own virtual asset."""
        file_hash = _virtual_source_hash(source_path, content)
        result = self.parser.parse(
            content,
            language_hint=language_hint_from_path(source_path),
        )
        if getattr(result, "partial", False):
            _append_virtual_source_event(
                incomplete_events,
                {
                    "component": "virtual_source_parser",
                    "reason": "partial",
                    "partial_results": True,
                    "source_hash": file_hash,
                    "backend": str(getattr(result, "parser_used", "unknown")),
                    "error_count": len(getattr(result, "errors", ()) or ()),
                    "capability_gaps": sorted(
                        str(item) for item in (getattr(result, "capability_gaps", ()) or ())
                    )[:_MAX_EVENT_DETAILS],
                    "truncation_reasons": sorted(
                        str(item) for item in (getattr(result, "truncation_reasons", ()) or ())
                    )[:_MAX_EVENT_DETAILS],
                },
            )
        if not (result.success and result.ast):
            _append_virtual_source_event(
                incomplete_events,
                {
                    "component": "virtual_source_parser",
                    "reason": "failed",
                    "partial_results": True,
                    "source_hash": file_hash,
                    "backend": str(getattr(result, "parser_used", "unknown")),
                    "error_count": len(getattr(result, "errors", ()) or ()),
                    "capability_gaps": sorted(
                        str(item) for item in (getattr(result, "capability_gaps", ()) or ())
                    )[:_MAX_EVENT_DETAILS],
                },
            )
            return []
        ir = self.ir_builder.build(result.ast, source_path, file_hash)
        if getattr(ir, "partial", False):
            _append_virtual_source_event(
                incomplete_events,
                {
                    "component": "virtual_source_ir",
                    "reason": "partial",
                    "partial_results": True,
                    "source_hash": file_hash,
                    "error_count": len(getattr(ir, "errors", ()) or ()),
                    "errors": sorted(
                        str(item) for item in (getattr(ir, "errors", ()) or ())
                    )[:_MAX_EVENT_DETAILS],
                },
            )
        context = AnalysisContext(
            file_url=source_path,
            file_hash=file_hash,
            source_content=content,
            is_first_party=is_first_party,
        )
        findings = self.rule_engine.analyze(ir, context)
        events = context.metadata.get("analysis_incomplete", [])
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, dict):
                    continue
                virtual_event = dict(event)
                virtual_event.setdefault("source_hash", file_hash)
                virtual_event["virtual_source"] = True
                _append_virtual_source_event(incomplete_events, virtual_event)
        try:
            self._annotate_finding_metadata(None, ir, findings)
        except Exception as e:  # metadata is best-effort; never drop the findings
            logger.warning("virtual_source_annotate_error", source=source_path[:120], error=str(e))
            _append_virtual_source_event(
                incomplete_events,
                {
                    "component": "virtual_source_enrichment",
                    "reason": "failed",
                    "partial_results": True,
                    "source_hash": file_hash,
                    "exception_type": type(e).__name__,
                },
            )
        for f in findings:
            # Already in ORIGINAL coordinates -> do NOT run _apply_mappings on these.
            f.evidence.original_file_url = source_path
            f.metadata["virtual_source"] = True
        return findings

    def _analyze_virtual_sources(
        self,
        sourcemap: SourceMapInfo | None,
        is_first_party: bool,
        parent_findings: list[Finding] | None = None,
        *,
        incomplete_events: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """DQ-P08: analyze each `sourcesContent` entry of a sourcemap as its OWN virtual source, so
        endpoints/secrets/sinks present only in the pre-minification original (tree-shaken/DCE'd
        code, unminified-only literals) are recovered instead of missed. Strictly additive and
        fail-safe: a virtual-source failure never loses the parent asset's real findings and emits
        structured incompleteness telemetry (INV-01/INV-02). Semantically identical findings retain
        one canonical result while generated and original locations are unioned in deterministic
        ``source_occurrences`` metadata."""
        if not sourcemap:
            return []
        try:
            sources = SourceMapResolver().get_original_sources(sourcemap)
        except Exception as e:
            logger.warning("virtual_source_extract_error", error=str(e))
            _append_virtual_source_event(
                incomplete_events,
                {
                    "component": "virtual_source_sourcemap",
                    "reason": "source_extraction_failed",
                    "partial_results": True,
                    "exception_type": type(e).__name__,
                },
            )
            return []
        if not sources:
            return []

        def _key(f: Finding) -> tuple:
            # Include the HTTP method so a source-only hidden verb (e.g. a tree-shaken DELETE on a
            # path that also has a GET) is recovered, matching the endpoint detector's (method,url)
            # preservation, while identical string-literal secrets/urls still dedupe vs the bundle.
            return (f.rule_id, f.value_type, f.extracted_value, f.metadata.get("method"))

        def _occurrence(f: Finding) -> dict[str, Any]:
            evidence = f.evidence
            return {
                "kind": "virtual_source" if f.metadata.get("virtual_source") else "generated",
                "file_url": evidence.file_url,
                "file_hash": evidence.file_hash,
                "line": evidence.line,
                "column": evidence.column,
                "end_line": evidence.end_line,
                "end_column": evidence.end_column,
                "original_file_url": evidence.original_file_url,
                "original_line": evidence.original_line,
                "original_column": evidence.original_column,
            }

        def _occurrence_key(item: dict[str, Any]) -> str:
            return json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)

        def _merge_occurrence(canonical: Finding, duplicate: Finding) -> None:
            candidates: list[dict[str, Any]] = []
            existing = canonical.metadata.get("source_occurrences", [])
            if isinstance(existing, list):
                candidates.extend(dict(item) for item in existing if isinstance(item, dict))
            if not candidates:
                candidates.append(_occurrence(canonical))
            candidates.append(_occurrence(duplicate))
            unique = {_occurrence_key(item): item for item in candidates}
            ordered = [unique[key] for key in sorted(unique)]
            canonical.metadata["source_occurrences_total"] = len(ordered)
            canonical.metadata["source_occurrences"] = ordered[:_MAX_SOURCE_OCCURRENCES]
            if len(ordered) > _MAX_SOURCE_OCCURRENCES:
                canonical.metadata["source_occurrences_truncated"] = True
                _append_virtual_source_event(
                    incomplete_events,
                    {
                        "component": "virtual_source_provenance",
                        "reason": "occurrence_cap",
                        "partial_results": True,
                        "source_hash": canonical.evidence.file_hash,
                        "occurrence_count": len(ordered),
                        "occurrence_cap": _MAX_SOURCE_OCCURRENCES,
                    },
                )

        canonical_by_key: dict[tuple, Finding] = {}
        for f in parent_findings or []:
            canonical_by_key.setdefault(_key(f), f)
        out: list[Finding] = []
        eligible = sorted(
            (
                (str(source_path), content)
                for source_path, content in sources.items()
                if isinstance(content, str) and content.strip()
            ),
            key=lambda item: (
                item[0],
                hashlib.sha256(item[1].encode("utf-8", "surrogatepass")).hexdigest(),
            ),
        )
        analyzed_count = 0
        analyzed_bytes = 0
        skipped_count = 0
        for source_path, content in eligible:
            content_bytes = len(content.encode("utf-8", "surrogatepass"))
            if (
                analyzed_count >= _MAX_VIRTUAL_SOURCES
                or analyzed_bytes + content_bytes > _MAX_VIRTUAL_SOURCE_BYTES
            ):
                skipped_count += 1
                continue
            source_path = str(source_path)
            analyzed_count += 1
            analyzed_bytes += content_bytes
            try:
                found = self._analyze_one_virtual_source(
                    source_path,
                    content,
                    is_first_party,
                    incomplete_events=incomplete_events,
                )
            except Exception as e:
                logger.warning(
                    "virtual_source_analyze_error", source=source_path[:120], error=str(e)
                )
                _append_virtual_source_event(
                    incomplete_events,
                    {
                        "component": "virtual_source_analysis",
                        "reason": "failed",
                        "partial_results": True,
                        "source_hash": _virtual_source_hash(source_path, content),
                        "exception_type": type(e).__name__,
                    },
                )
                continue
            for f in found:
                key = _key(f)
                canonical = canonical_by_key.get(key)
                if canonical is not None:
                    _merge_occurrence(canonical, f)
                    continue
                canonical_by_key[key] = f
                _merge_occurrence(f, f)
                out.append(f)
        if skipped_count:
            _append_virtual_source_event(
                incomplete_events,
                {
                    "component": "virtual_source_analysis",
                    "reason": "budget_exceeded",
                    "partial_results": True,
                    "source_count": len(eligible),
                    "analyzed_count": analyzed_count,
                    "skipped_count": skipped_count,
                    "source_cap": _MAX_VIRTUAL_SOURCES,
                    "byte_cap": _MAX_VIRTUAL_SOURCE_BYTES,
                    "analyzed_bytes": analyzed_bytes,
                },
            )
        return out

    def analyze_asset_standalone(
        self,
        asset: JSAsset,
        line_mapper: LineMapper | None,
        sourcemap: SourceMapInfo | None,
        incomplete_events: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """Full per-asset analysis (parse -> IR -> rules -> annotate -> map) with no I/O.

        Used by parallel workers: the worker parses the asset's content locally so only the
        small findings list crosses the process boundary (never the large AST). Reuses the
        exact serial engine + annotation logic, so findings are byte-identical. Sets
        asset.parse_success / parse_errors / ast_hash (read back by the caller).
        """
        content = decode_js_bytes(asset.content)
        result = self.parser.parse(content, language_hint=asset.language_hint)
        asset.parse_success = result.success
        asset.parse_errors = list(result.errors)
        virtual_events = incomplete_events if incomplete_events is not None else []
        initial_event_count = len(virtual_events)
        if not (result.success and result.ast):
            findings = self._analyze_virtual_sources(
                sourcemap,
                asset.is_first_party,
                incomplete_events=virtual_events,
            )
            for event in virtual_events[initial_event_count:]:
                summary = _virtual_event_summary(event)
                if summary and summary not in asset.parse_errors:
                    asset.parse_errors.append(summary)
            return findings
        asset.ast_hash = self.dedup.compute_hash(
            json.dumps(result.ast, separators=(",", ":"), sort_keys=True).encode()
        )[:16]
        ir = self.ir_builder.build(result.ast, asset.url, asset.content_hash)
        # Surface IR-level truncation (AST depth / unique-identifier caps) so an INCOMPLETE
        # analysis is not reported as a clean parse with 0 findings (DQ-C04). Parse itself
        # succeeded, so parse_success stays True; the cap note rides the existing parse_errors
        # plumbing into the report.
        if getattr(ir, "partial", False) and ir.errors:
            asset.parse_errors = list(asset.parse_errors or []) + list(ir.errors)
        context = AnalysisContext(
            file_url=asset.url,
            file_hash=asset.content_hash,
            source_content=content,
            is_first_party=asset.is_first_party,
        )
        findings = self.rule_engine.analyze(ir, context)
        events = context.metadata.get("analysis_incomplete", [])
        if incomplete_events is not None and isinstance(events, list):
            incomplete_events.extend(dict(event) for event in events if isinstance(event, dict))
        # Secure findings BEFORE enrichment: a failure annotating metadata or
        # applying line maps must degrade metadata, never discard the findings
        # already extracted for this asset (previously it dropped all of them).
        try:
            self._annotate_finding_metadata(asset, ir, findings)
            self._apply_mappings(findings, line_mapper, sourcemap)
        except Exception as e:
            logger.warning(
                "finding_enrichment_error",
                url=asset.url[:120],
                exception_type=type(e).__name__,
            )
            _append_unique_analysis_event(virtual_events, _asset_enrichment_event())
        # DQ-P08: also analyze the sourcemap's sourcesContent as virtual sources (appended AFTER
        # mapping the real findings, since these are already in original coords). Deduped vs the
        # bundle findings above so shared string literals are not double-reported.
        findings.extend(
            self._analyze_virtual_sources(
                sourcemap,
                asset.is_first_party,
                findings,
                incomplete_events=virtual_events,
            )
        )
        if getattr(ir, "partial", False):
            _append_unique_analysis_event(virtual_events, _ir_incomplete_event())
        for event in virtual_events[initial_event_count:]:
            summary = _virtual_event_summary(event)
            if summary and summary not in asset.parse_errors:
                asset.parse_errors.append(summary)
        for error in getattr(ir, "errors", ()) or ():
            if error not in asset.parse_errors:
                asset.parse_errors.append(error)
        return findings

    def analyze_prebuilt_ir(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
        line_mapper: LineMapper | None = None,
        sourcemap: SourceMapInfo | None = None,
    ) -> list[Finding]:
        """Run rules + annotation + line/source mapping on an ALREADY-parsed IR.

        The local `analyze` command parses in a separate stage and then analyzes the
        resulting IRs; this is the shared analysis body it delegates to, so local, serial,
        and parallel paths all use one implementation (no drift). asset is None because
        local files carry no network load-context. Enrichment failures degrade metadata
        but never discard findings.
        """
        findings = self.rule_engine.analyze(ir, context)
        try:
            self._annotate_finding_metadata(None, ir, findings)
            self._apply_mappings(findings, line_mapper, sourcemap)
        except Exception as e:
            logger.warning(
                "finding_enrichment_error",
                url=context.file_url[:120],
                exception_type=type(e).__name__,
            )
            events = context.metadata.get("analysis_incomplete")
            if not isinstance(events, list):
                events = []
                context.metadata["analysis_incomplete"] = events
            _append_unique_analysis_event(events, _asset_enrichment_event())
        # DQ-P08: analyze sourcesContent virtual sources (no-op for local files, which carry no
        # sourcemap). Deduped vs the findings above.
        virtual_events: list[dict[str, Any]] = []
        findings.extend(
            self._analyze_virtual_sources(
                sourcemap,
                context.is_first_party,
                findings,
                incomplete_events=virtual_events,
            )
        )
        if virtual_events:
            events = context.metadata.setdefault("analysis_incomplete", [])
            if isinstance(events, list):
                for event in virtual_events:
                    _append_unique_analysis_event(events, event)
        if getattr(ir, "partial", False):
            events = context.metadata.get("analysis_incomplete")
            if not isinstance(events, list):
                events = []
                context.metadata["analysis_incomplete"] = events
            _append_unique_analysis_event(events, _ir_incomplete_event())
        return findings

    def _annotate_finding_metadata(
        self,
        asset: JSAsset | None,
        ir: IntermediateRepresentation,
        findings: list[Finding],
    ) -> None:
        """Attach IR and runtime context metadata used by correlators/reporters."""
        # Initialize every projection before building it, but never publish these defaults as if
        # enrichment completed. A RecursionError is re-raised to the shared analysis boundary,
        # which preserves findings and emits the explicit `asset_enrichment` incomplete event.
        imports = []
        dynamic_imports = []
        import_bindings = []
        re_export_bindings = []
        exports = []
        export_scopes = {}
        default_object_exports = []
        named_object_exports = {}
        call_names = []
        scoped_calls = {}
        scope_parents = {}
        function_defs = ir.function_defs
        call_graph = ir.call_graph
        try:
            commonjs_require_bindings = build_commonjs_require_bindings(ir)
            commonjs_require_sources = [
                str(binding.get("source") or "").strip()
                for binding in commonjs_require_bindings
                if str(binding.get("source") or "").strip()
            ]
            commonjs_re_export_bindings = build_commonjs_re_export_bindings(ir)
            re_export_bindings = [
                *build_re_export_bindings(ir),
                *commonjs_re_export_bindings,
            ]
            re_export_sources = [
                str(binding.get("source") or "").strip()
                for binding in re_export_bindings
                if str(binding.get("source") or "").strip()
            ]
            imports = list(
                dict.fromkeys(
                    [
                        *[imp.source for imp in ir.imports if imp.source],
                        *commonjs_require_sources,
                        *re_export_sources,
                    ]
                )
            )
            dynamic_imports = [imp.source for imp in ir.imports if imp.is_dynamic and imp.source]
            import_bindings = [
                *self._build_import_bindings(ir),
                *commonjs_require_bindings,
            ]
            function_defs = ir.function_defs
            scope_parents = self._build_scope_parent_map(function_defs)
            if ir.raw_ast:
                seen_binding_keys = {
                    self._import_binding_key(binding) for binding in import_bindings
                }
                for _ in range(4):
                    alias_bindings = self._collect_import_alias_bindings(
                        ir.raw_ast,
                        import_bindings,
                        scope_parents,
                    )
                    fresh_bindings = [
                        binding
                        for binding in alias_bindings
                        if self._import_binding_key(binding) not in seen_binding_keys
                    ]
                    if not fresh_bindings:
                        break
                    import_bindings.extend(fresh_bindings)
                    seen_binding_keys.update(
                        self._import_binding_key(binding) for binding in fresh_bindings
                    )
            commonjs_exports, commonjs_export_scopes = build_commonjs_export_metadata(ir)
            default_object_exports = list(
                dict.fromkeys(
                    [
                        *build_default_object_export_members(ir),
                        *build_commonjs_default_object_export_members(ir),
                    ]
                )
            )
            named_object_exports = self._merge_named_object_exports(
                build_named_object_export_members(ir),
                build_commonjs_named_object_export_members(ir),
            )
            exports = list(
                dict.fromkeys(
                    [
                        *[exp.name for exp in ir.exports if exp.name],
                        *commonjs_exports,
                    ]
                )
            )
            export_scopes = self._merge_export_scopes(
                build_export_scope_map(ir),
                commonjs_export_scopes,
            )
            call_names = [
                call.full_name or call.name
                for call in ir.function_calls
                if (call.full_name or call.name)
            ]
            scoped_calls = self._build_scoped_calls(ir)
            call_graph = ir.call_graph
        except RecursionError:
            logger.debug(
                "annotation_recursion_degraded", url=(getattr(asset, "url", "") or "")[:120]
            )
            raise

        for finding in findings:
            finding.metadata.setdefault("imports", imports)
            finding.metadata.setdefault("dynamic_imports", dynamic_imports)
            finding.metadata.setdefault("import_bindings", import_bindings)
            finding.metadata.setdefault("re_export_bindings", re_export_bindings)
            finding.metadata.setdefault("exports", exports)
            finding.metadata.setdefault("export_scopes", export_scopes)
            finding.metadata.setdefault("default_object_exports", default_object_exports)
            finding.metadata.setdefault("named_object_exports", named_object_exports)
            finding.metadata.setdefault("call_names", call_names[:50])
            finding.metadata.setdefault("scoped_calls", scoped_calls)
            finding.metadata.setdefault("call_graph", call_graph)
            finding.metadata.setdefault("scope_parents", scope_parents)
            finding.metadata.setdefault(
                "enclosing_scope",
                self._find_enclosing_scope(finding.evidence.line, function_defs),
            )
            if asset is not None and asset.load_context:
                finding.metadata.setdefault("load_context", asset.load_context)
            if asset is not None and asset.initiator:
                finding.metadata.setdefault("initiator", asset.initiator)

    def _merge_export_scopes(
        self,
        *scope_maps: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """Merge multiple export-scope maps without duplicates."""
        merged: dict[str, set[str]] = {}
        for scope_map in scope_maps:
            if not isinstance(scope_map, dict):
                continue
            for export_name, scopes in scope_map.items():
                if not isinstance(export_name, str):
                    continue
                merged.setdefault(export_name, set()).update(
                    scope for scope in scopes or [] if isinstance(scope, str) and scope
                )
        return {export_name: sorted(scopes) for export_name, scopes in merged.items() if scopes}

    def _merge_named_object_exports(
        self,
        *member_maps: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """Merge named object export member maps without duplicates."""
        merged: dict[str, set[str]] = {}
        for member_map in member_maps:
            if not isinstance(member_map, dict):
                continue
            for export_name, members in member_map.items():
                if not isinstance(export_name, str):
                    continue
                merged.setdefault(export_name, set()).update(
                    member for member in members or [] if isinstance(member, str) and member
                )
        return {export_name: sorted(members) for export_name, members in merged.items() if members}

    def _build_import_bindings(
        self,
        ir: IntermediateRepresentation,
    ) -> list[dict[str, Any]]:
        """Expand IR import declarations into structured import bindings."""
        bindings: list[dict[str, Any]] = []
        for import_decl in ir.imports:
            if not import_decl.source:
                continue
            for specifier in import_decl.specifiers:
                binding = self._parse_import_specifier(import_decl.source, specifier)
                if binding:
                    bindings.append(binding)
        if ir.raw_ast:
            bindings.extend(self._collect_dynamic_import_bindings(ir.raw_ast))
        return bindings

    def _parse_import_specifier(self, source: str, specifier: str) -> dict[str, Any] | None:
        """Parse a serialized import specifier into a structured binding."""
        value = (specifier or "").strip()
        if not value:
            return None
        if value.startswith("default as "):
            return {
                "source": source,
                "imported": "default",
                "local": value[len("default as ") :],
                "kind": "default",
                "scope": "global",
                "is_dynamic": False,
            }
        if value.startswith("* as "):
            return {
                "source": source,
                "imported": "*",
                "local": value[len("* as ") :],
                "kind": "namespace",
                "scope": "global",
                "is_dynamic": False,
            }
        if " as " in value:
            imported, local = value.split(" as ", 1)
            return {
                "source": source,
                "imported": imported.strip(),
                "local": local.strip(),
                "kind": "named",
                "scope": "global",
                "is_dynamic": False,
            }
        return {
            "source": source,
            "imported": value,
            "local": value,
            "kind": "named",
            "scope": "global",
            "is_dynamic": False,
        }

    def _collect_dynamic_import_bindings(
        self,
        node: Any,
        scope: str = "global",
    ) -> list[dict[str, Any]]:
        """Extract practical dynamic-import bindings from raw AST."""
        bindings: list[dict[str, Any]] = []
        if not isinstance(node, dict):
            return bindings

        node_type = node.get("type", "")
        if node_type in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            function_scope = self._derive_dynamic_scope_name(node)
            for param in node.get("params", []):
                bindings.extend(self._collect_dynamic_import_bindings(param, function_scope))
            body = node.get("body")
            if body:
                bindings.extend(self._collect_dynamic_import_bindings(body, function_scope))
            return bindings

        if node_type == "VariableDeclarator":
            bindings.extend(
                self._extract_dynamic_import_binding_targets(
                    node.get("id"),
                    node.get("init"),
                    scope,
                )
            )
        elif node_type == "AssignmentExpression" and node.get("operator") == "=":
            bindings.extend(
                self._extract_dynamic_import_binding_targets(
                    node.get("left"),
                    node.get("right"),
                    scope,
                )
            )
        elif node_type == "CallExpression":
            bindings.extend(self._extract_dynamic_import_then_bindings(node))

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                bindings.extend(self._collect_dynamic_import_bindings(value, scope))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        bindings.extend(self._collect_dynamic_import_bindings(item, scope))

        return bindings

    def _collect_import_alias_bindings(
        self,
        node: Any,
        existing_bindings: list[dict[str, Any]],
        scope_parents: dict[str, list[str]],
        scope: str = "global",
    ) -> list[dict[str, Any]]:
        """Extract practical local aliases of existing import bindings."""
        bindings: list[dict[str, Any]] = []
        if not isinstance(node, dict):
            return bindings

        node_type = node.get("type", "")
        if node_type in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            function_scope = self._derive_dynamic_scope_name(node)
            for param in node.get("params", []):
                bindings.extend(
                    self._collect_import_alias_bindings(
                        param,
                        existing_bindings,
                        scope_parents,
                        function_scope,
                    )
                )
            body = node.get("body")
            if body:
                bindings.extend(
                    self._collect_import_alias_bindings(
                        body,
                        existing_bindings,
                        scope_parents,
                        function_scope,
                    )
                )
            return bindings

        if node_type == "VariableDeclarator":
            bindings.extend(
                self._extract_import_alias_bindings(
                    node.get("id"),
                    node.get("init"),
                    existing_bindings,
                    scope_parents,
                    scope,
                )
            )
        elif node_type == "AssignmentExpression" and node.get("operator") == "=":
            bindings.extend(
                self._extract_import_alias_bindings(
                    node.get("left"),
                    node.get("right"),
                    existing_bindings,
                    scope_parents,
                    scope,
                )
            )

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                bindings.extend(
                    self._collect_import_alias_bindings(
                        value,
                        existing_bindings,
                        scope_parents,
                        scope,
                    )
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        bindings.extend(
                            self._collect_import_alias_bindings(
                                item,
                                existing_bindings,
                                scope_parents,
                                scope,
                            )
                        )

        return bindings

    def _extract_import_alias_bindings(
        self,
        target: Any,
        value: Any,
        existing_bindings: list[dict[str, Any]],
        scope_parents: dict[str, list[str]],
        scope: str,
    ) -> list[dict[str, Any]]:
        """Extract alias bindings produced by assignment or destructuring."""
        alias_bindings: list[dict[str, Any]] = []
        direct_alias = self._extract_identifier_import_alias_binding(
            target,
            value,
            existing_bindings,
            scope_parents,
            scope,
        )
        if direct_alias:
            alias_bindings.append(direct_alias)

        member_alias = self._extract_import_member_alias_binding(
            target,
            value,
            existing_bindings,
            scope_parents,
            scope,
        )
        if member_alias:
            alias_bindings.append(member_alias)

        alias_bindings.extend(
            self._extract_object_pattern_import_alias_bindings(
                target,
                value,
                existing_bindings,
                scope_parents,
                scope,
            )
        )
        return alias_bindings

    def _extract_identifier_import_alias_binding(
        self,
        target: Any,
        value: Any,
        existing_bindings: list[dict[str, Any]],
        scope_parents: dict[str, list[str]],
        scope: str,
    ) -> dict[str, Any] | None:
        """Convert `const alias = importedBinding` back into an import-like binding."""
        local = self._extract_pattern_target_name(target)
        if not local or not isinstance(value, dict) or value.get("type") != "Identifier":
            return None

        value_name = str(value.get("name") or "").strip()
        if not value_name or value_name == local:
            return None

        for binding in existing_bindings:
            if not self._binding_matches_local(binding, value_name, scope_parents, scope):
                continue
            return self._clone_import_binding(
                binding,
                local=local,
                scope=scope,
                is_alias=True,
            )
        return None

    def _extract_object_pattern_import_alias_bindings(
        self,
        target: Any,
        value: Any,
        existing_bindings: list[dict[str, Any]],
        scope_parents: dict[str, list[str]],
        scope: str,
    ) -> list[dict[str, Any]]:
        """Convert `const { foo } = importedObject` back into practical bindings."""
        if not isinstance(target, dict) or target.get("type") != "ObjectPattern":
            return []
        if not isinstance(value, dict) or value.get("type") != "Identifier":
            return []

        value_name = str(value.get("name") or "").strip()
        if not value_name:
            return []

        bindings: list[dict[str, Any]] = []
        source_bindings = [
            binding
            for binding in existing_bindings
            if self._binding_matches_local(binding, value_name, scope_parents, scope)
        ]
        if not source_bindings:
            return bindings

        for source_binding in source_bindings:
            binding_kind = str(source_binding.get("kind") or "").strip()
            if binding_kind not in {"namespace", "default"}:
                continue
            for prop in target.get("properties", []):
                if not isinstance(prop, dict) or prop.get("type") != "Property":
                    continue
                imported = self._extract_pattern_name(prop.get("key"))
                local = self._extract_pattern_target_name(prop.get("value"))
                if not imported or not local:
                    continue
                kind = "default" if imported == "default" else "named"
                bindings.append(
                    self._clone_import_binding(
                        source_binding,
                        imported=imported,
                        local=local,
                        kind=kind,
                        scope=scope,
                        is_alias=True,
                        is_destructured_alias=True,
                    )
                )

        return bindings

    def _binding_matches_local(
        self,
        binding: dict[str, Any],
        local_name: str,
        scope_parents: dict[str, list[str]],
        scope: str,
    ) -> bool:
        """Return True when an existing binding is visible under the given local name."""
        binding_local = str(binding.get("local") or "").strip()
        binding_scope = str(binding.get("scope") or "global").strip() or "global"
        if binding_local != local_name:
            return False
        if binding_scope == "global":
            return True
        if binding_scope == scope:
            return True
        return binding_scope in scope_parents.get(scope, [])

    def _clone_import_binding(
        self,
        binding: dict[str, Any],
        *,
        local: str,
        scope: str,
        imported: str | None = None,
        kind: str | None = None,
        is_alias: bool = False,
        is_destructured_alias: bool = False,
    ) -> dict[str, Any]:
        """Clone an existing import binding while preserving correlation metadata."""
        cloned = dict(binding)
        cloned["local"] = local
        cloned["scope"] = scope
        if imported is not None:
            cloned["imported"] = imported
        if kind is not None:
            cloned["kind"] = kind
        if is_alias:
            cloned["is_alias"] = True
        if is_destructured_alias:
            cloned["is_destructured_alias"] = True
        return cloned

    def _import_binding_key(self, binding: dict[str, Any]) -> tuple[Any, ...]:
        """Create a stable deduplication key for practical import bindings."""
        return (
            binding.get("source"),
            binding.get("imported"),
            binding.get("local"),
            binding.get("kind"),
            binding.get("scope"),
            bool(binding.get("is_dynamic")),
            bool(binding.get("is_reexport")),
            bool(binding.get("is_reexport_all")),
            bool(binding.get("is_commonjs")),
            bool(binding.get("is_commonjs_reexport")),
            bool(binding.get("is_member_alias")),
            bool(binding.get("is_alias")),
            bool(binding.get("is_destructured_alias")),
        )

    def _extract_import_member_alias_binding(
        self,
        target: Any,
        value: Any,
        existing_bindings: list[dict[str, Any]],
        scope_parents: dict[str, list[str]],
        scope: str,
    ) -> dict[str, Any] | None:
        """Convert `const fn = ns.member` aliases back into import-like bindings."""
        local = self._extract_pattern_target_name(target)
        if not local or not isinstance(value, dict) or value.get("type") != "MemberExpression":
            return None

        object_node = value.get("object")
        property_name = self._extract_pattern_name(value.get("property"))
        if (
            not property_name
            or not isinstance(object_node, dict)
            or object_node.get("type") != "Identifier"
        ):
            return None

        object_name = str(object_node.get("name") or "").strip()
        if not object_name:
            return None

        for binding in existing_bindings:
            binding_local = str(binding.get("local") or "").strip()
            binding_scope = str(binding.get("scope") or "global").strip() or "global"
            binding_kind = str(binding.get("kind") or "").strip()
            if binding_local != object_name:
                continue
            if binding_kind != "namespace":
                continue
            if (
                binding_scope != "global"
                and binding_scope != scope
                and binding_scope not in scope_parents.get(scope, [])
            ):
                continue
            return self._clone_import_binding(
                binding,
                imported=property_name,
                local=local,
                kind="named",
                scope=scope,
                is_alias=True,
                is_destructured_alias=False,
            ) | {"is_member_alias": True}
        return None

    def _extract_dynamic_import_then_bindings(
        self,
        node: Any,
    ) -> list[dict[str, Any]]:
        """Extract simple `.then(param => ...)` bindings fed by dynamic imports."""
        if not isinstance(node, dict):
            return []
        callee = node.get("callee") or {}
        if callee.get("type") != "MemberExpression":
            return []
        property_name = self._extract_pattern_name(callee.get("property"))
        if property_name != "then":
            return []
        source_object = callee.get("object")
        source = self._extract_dynamic_import_source(source_object)
        if not source:
            return []

        for arg in node.get("arguments", []):
            if not isinstance(arg, dict):
                continue
            if arg.get("type") not in {
                "FunctionDeclaration",
                "FunctionExpression",
                "ArrowFunctionExpression",
            }:
                continue
            params = arg.get("params") or []
            if not params:
                return []
            callback_scope = self._derive_dynamic_scope_name(arg)
            return self._extract_dynamic_import_binding_targets(
                params[0],
                source_object,
                callback_scope,
            )
        return []

    def _extract_dynamic_import_binding_targets(
        self,
        target: Any,
        value: Any,
        scope: str,
    ) -> list[dict[str, Any]]:
        """Extract binding targets from a dynamic import assignment/declaration."""
        source = self._extract_dynamic_import_source(value)
        if not source or not isinstance(target, dict):
            return []

        if target.get("type") == "Identifier":
            local = str(target.get("name") or "").strip()
            if not local:
                return []
            return [
                {
                    "source": source,
                    "imported": "*",
                    "local": local,
                    "kind": "namespace",
                    "scope": scope,
                    "is_dynamic": True,
                }
            ]

        if target.get("type") != "ObjectPattern":
            return []

        bindings: list[dict[str, Any]] = []
        for prop in target.get("properties", []):
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                continue
            imported = self._extract_pattern_name(prop.get("key"))
            local = self._extract_pattern_target_name(prop.get("value"))
            if not imported or not local:
                continue
            kind = "default" if imported == "default" else "named"
            bindings.append(
                {
                    "source": source,
                    "imported": imported,
                    "local": local,
                    "kind": kind,
                    "scope": scope,
                    "is_dynamic": True,
                }
            )
        return bindings

    def _extract_dynamic_import_source(self, node: Any) -> str:
        """Extract a literal-like source string from a dynamic import expression."""
        if not isinstance(node, dict):
            return ""

        node_type = node.get("type", "")
        if node_type == "AwaitExpression":
            return self._extract_dynamic_import_source(node.get("argument"))
        if node_type == "CallExpression" and (node.get("callee") or {}).get("type") == "Import":
            source_node = (node.get("arguments") or [{}])[0]
        elif node_type == "ImportExpression":
            source_node = node.get("source", {})
        else:
            return ""

        if source_node.get("type") == "Literal":
            value = source_node.get("value")
            return value if isinstance(value, str) else ""
        if source_node.get("type") == "TemplateLiteral":
            quasis = source_node.get("quasis", [])
            expressions = source_node.get("expressions", [])
            if quasis and not expressions:
                return str(quasis[0].get("value", {}).get("cooked") or "")
        return ""

    def _extract_pattern_name(self, node: Any) -> str:
        """Extract an imported property name from an object pattern key."""
        if not isinstance(node, dict):
            return ""
        node_type = node.get("type", "")
        if node_type == "Identifier":
            return str(node.get("name") or "").strip()
        if node_type == "Literal":
            value = node.get("value")
            return value.strip() if isinstance(value, str) else ""
        return ""

    def _extract_pattern_target_name(self, node: Any) -> str:
        """Extract a local binding target name from an object pattern value."""
        if not isinstance(node, dict):
            return ""
        node_type = node.get("type", "")
        if node_type == "Identifier":
            return str(node.get("name") or "").strip()
        if node_type == "AssignmentPattern":
            return self._extract_pattern_target_name(node.get("left"))
        return ""

    def _derive_dynamic_scope_name(self, node: dict[str, Any]) -> str:
        """Derive a function scope name matching the IR builder's naming scheme."""
        node_type = node.get("type", "")
        prefix_map = {
            "FunctionDeclaration": "function",
            "FunctionExpression": "function_expr",
            "ArrowFunctionExpression": "arrow",
        }
        identifier = (node.get("id") or {}).get("name")
        if identifier:
            return f"function:{identifier}"

        loc = node.get("loc", {})
        start = loc.get("start", {})
        line = start.get("line", 0)
        prefix = prefix_map.get(node_type, "function")
        return f"function:{prefix}@{line}"

    def _build_scoped_calls(
        self,
        ir: IntermediateRepresentation,
    ) -> dict[str, list[str]]:
        """Group function calls by lexical scope for correlation."""
        scoped_calls: dict[str, set[str]] = {}
        for call in ir.function_calls:
            scope = (call.scope or "global").strip() or "global"
            name = (call.full_name or call.name or "").strip()
            if not name:
                continue
            scoped_calls.setdefault(scope, set()).add(name)
        return {scope: sorted(call_names) for scope, call_names in scoped_calls.items()}

    def _find_enclosing_scope(self, line: int, function_defs: list[FunctionDef]) -> str:
        """Find the innermost function scope containing a finding line."""
        if line <= 0:
            return "global"

        matching = [
            func_def
            for func_def in function_defs
            if func_def.line <= line <= max(func_def.end_line, func_def.line)
        ]
        if not matching:
            return "global"

        matching.sort(key=lambda func_def: (func_def.end_line - func_def.line, func_def.line))
        return matching[0].scope

    def _build_scope_parent_map(
        self,
        function_defs: list[FunctionDef],
    ) -> dict[str, list[str]]:
        """Build lexical parent-scope chains from nested function ranges."""
        normalized_defs = [
            func_def
            for func_def in function_defs
            if getattr(func_def, "scope", "") and getattr(func_def, "line", 0) > 0
        ]
        if not normalized_defs:
            return {}

        parent_map: dict[str, str] = {}
        for func_def in normalized_defs:
            candidates = [
                candidate
                for candidate in normalized_defs
                if candidate.scope != func_def.scope
                and candidate.line <= func_def.line
                and candidate.end_line >= func_def.end_line
            ]
            if not candidates:
                continue
            candidates.sort(
                key=lambda candidate: (
                    candidate.end_line - candidate.line,
                    candidate.line,
                )
            )
            parent_map[func_def.scope] = candidates[0].scope

        scope_parents: dict[str, list[str]] = {}
        for scope in parent_map:
            ancestors: list[str] = []
            seen: set[str] = set()
            current = parent_map.get(scope)
            while current and current not in seen:
                ancestors.append(current)
                seen.add(current)
                current = parent_map.get(current)
            if ancestors:
                scope_parents[scope] = ancestors
        return scope_parents

    def _build_snippet(
        self,
        source_content: str,
        line: int,
        context_lines: int = 3,
    ) -> tuple[str, tuple[int, int]]:
        """Build a code snippet around a 1-indexed line."""
        lines = source_content.split("\n")
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        snippet = "\n".join(lines[start:end])
        return snippet, (start + 1, end)
