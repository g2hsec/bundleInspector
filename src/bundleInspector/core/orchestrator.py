"""
Pipeline orchestrator - main entry point.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from collections.abc import Callable, Coroutine
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, TypeVar
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from bundleInspector.classifier.risk_model import RiskClassifier
from bundleInspector.collector.headless import HeadlessCollector, HeadlessMultiPageCollector
from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.static import MultiPageStaticCollector, StaticCollector
from bundleInspector.config import Config
from bundleInspector.core.asset_analysis import analyze_asset_task_with_telemetry, init_worker
from bundleInspector.core.asset_analyzer import (
    AssetAnalyzer,
    _asset_enrichment_event,
    _ir_incomplete_event,
    _virtual_event_summary,
)
from bundleInspector.core.dedup import DedupCache
from bundleInspector.core.progress import PipelineStage, ProgressTracker, StageProgress
from bundleInspector.core.rate_limiter import AdaptiveRateLimiter
from bundleInspector.core.resume_policy import (
    build_remote_resume_signature,
    build_stage_state_with_resume_signature,
    checkpoint_matches_resume_signature,
    embed_report_resume_signature,
    report_matches_resume_signature,
)
from bundleInspector.core.safe_http import (
    build_pinned_transport,
    normalized_origin,
    origin_bound_auth_headers,
)
from bundleInspector.core.security import is_url_safe, ssrf_block_hint
from bundleInspector.core.text_decode import decode_js_bytes
from bundleInspector.correlator.graph import CorrelationGraph, Correlator
from bundleInspector.normalizer.beautify import Beautifier, NormalizationResult
from bundleInspector.normalizer.line_mapping import LineMapper
from bundleInspector.normalizer.sourcemap import SourceMapInfo, SourceMapResolver
from bundleInspector.parser.ir_builder import IRBuilder
from bundleInspector.parser.js_parser import JSParser, ParseResult
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.atomic import AtomicCommitError, UnsafePathError
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.job_repository import JobAccessError, JobRepository
from bundleInspector.storage.models import (
    AnalysisCompleteness,
    AssetProvenance,
    CompletenessIssue,
    CompletenessStatus,
    Finding,
    IntermediateRepresentation,
    JSAsset,
    JSReference,
    LoadMethod,
    PipelineCheckpoint,
    Report,
)

logger = structlog.get_logger()

_T = TypeVar("_T")
_AssetAnalysisResult = tuple[
    int,
    bool,
    list[str],
    str | None,
    list[Finding],
    list[dict[str, Any]],
]


def _terminate_process_pool(pool: ProcessPoolExecutor) -> None:
    """Terminate active workers before non-waiting shutdown after a bounded timeout."""
    processes = list((getattr(pool, "_processes", None) or {}).values())
    for process in processes:
        if process.is_alive():
            process.terminate()
    for process in processes:
        process.join(timeout=1)
    for process in processes:
        if process.is_alive():
            process.kill()
            process.join(timeout=1)
    pool.shutdown(wait=False, cancel_futures=True)


def _parallel_workers() -> int:
    """Worker count from BUNDLEINSPECTOR_PARALLEL (unset/1 = serial; 'auto' = cpu count)."""
    raw = os.environ.get("BUNDLEINSPECTOR_PARALLEL", "").strip().lower()
    if not raw or raw in ("0", "1"):
        return 1
    if raw == "auto":
        return max(1, os.cpu_count() or 1)
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


_STAGE_ORDER = [
    PipelineStage.CRAWL,
    PipelineStage.DOWNLOAD,
    PipelineStage.NORMALIZE,
    PipelineStage.PARSE,
    PipelineStage.ANALYZE,
    PipelineStage.CORRELATE,
    PipelineStage.CLASSIFY,
    PipelineStage.REPORT,
]
_MAX_SOURCEMAP_PROVENANCE_BASES = 64
_MAX_SUPPLEMENTAL_SOURCE_BYTES = 20 * 1024 * 1024


class Orchestrator:
    """
    Pipeline orchestrator.

    Coordinates all stages of JS analysis:
    1. Crawl - Discover JS URLs
    2. Download - Fetch JS content
    3. Normalize - Beautify and resolve sourcemaps
    4. Parse - Build AST and IR
    5. Analyze - Run detection rules
    6. Correlate - Build relationship graph
    7. Classify - Assign risk scores
    8. Report - Generate output
    """

    def __init__(self, config: Config):
        self.config = config
        self.progress = ProgressTracker()
        self.dedup = DedupCache()

        # Initialize components
        self.scope = ScopePolicy(config.scope)
        self.beautifier = Beautifier()
        self.parser = JSParser.from_parser_config(config.parser, temp_dir=config.temp_dir)
        self.ir_builder = IRBuilder.from_parser_config(config.parser)
        self.rule_engine = RuleEngine(config.rules)
        self.correlator = Correlator()
        self.classifier = RiskClassifier()
        # Light per-asset analyzer (parse->IR->rules->annotate->map). Same 4 collaborators;
        # workers import it directly (asset_analysis) to avoid the playwright/httpx stack.
        self._analyzer = AssetAnalyzer(
            self.parser, self.ir_builder, self.rule_engine, self.dedup
        )

        # Initialize rate limiter
        self.rate_limiter = AdaptiveRateLimiter(
            base_interval=config.crawler.rate_limit,
            max_concurrent=config.crawler.max_concurrent,
            per_domain=True,
        )

        # Runtime storage
        self.job_id = config.job_id or str(uuid.uuid4())
        self.config.job_id = self.job_id
        self._artifact_store: ArtifactStore | None = None
        self._finding_store: FindingStore | None = None
        self._init_storage()

        # State
        self._seed_urls: list[str] = []
        self._assets: list[JSAsset] = []
        self._findings: list[Finding] = []
        self._parse_results: dict[str, Any] = {}  # content_hash -> parse result
        self._download_client: httpx.AsyncClient | None = None
        self._line_mappers: dict[str, LineMapper] = {}
        self._sourcemaps: dict[str, SourceMapInfo] = {}
        self._normalize_heartbeat_seconds: float = 5.0
        self._resume_signature = build_remote_resume_signature(config)
        # enh2: xhr/fetch URLs the app actually called at runtime -- baseline for
        # dormant/hidden endpoint detection (declared in JS but never exercised).
        self._observed_requests: set[tuple[str, str]] = set()
        # enh7: WebSocket URLs opened at runtime -- baseline for runtime endpoint surfacing.
        self._observed_websockets: set[str] = set()
        # DQ-C06: transient (retryable) crawl-phase failures that must NOT be frozen as a complete
        # checkpoint; surfaced as report warnings so lost coverage is visible instead of a silent 0.
        self._crawl_warnings: list[str] = []
        # DQ-C06: seed URL -> phases left incomplete by a transient failure this run. A seed with any
        # incomplete phase is kept PARTIAL (not marked complete) so --resume actually re-runs only the
        # failed phase instead of skipping the seed wholesale.
        self._incomplete_crawl_phases: dict[str, set[str]] = {}
        self._checkpoint_snapshot: PipelineCheckpoint | None = None
        # Each value is the latest stage that is safe to claim complete while a retryable failure
        # remains. An empty string means crawl itself is incomplete; "crawl" means download is.
        self._retry_barriers: set[str] = set()
        self._completeness_issues: list[CompletenessIssue] = []
        self._crawl_stage_state: dict[str, Any] = {}
        self._download_stage_state: dict[str, Any] = {}
        self._checkpoint_lock = asyncio.Lock()

    def _init_storage(self) -> None:
        """Initialize persistent stores for the current job."""
        try:
            repository = JobRepository(self.config.cache_dir)
            job_root, owned = repository.prepare_job(
                self.job_id,
                "local",
                create=True,
                allow_legacy=True,
            )
            if job_root is None:
                raise JobAccessError("job storage is unavailable")
        except (AtomicCommitError, JobAccessError, UnsafePathError, ValueError):
            raise
        except Exception as e:
            logger.warning("storage_init_error", error=str(e))
            return

        if not owned:
            logger.warning("legacy_job_owner_missing", job_id=self.job_id)
        try:
            self._artifact_store = ArtifactStore(job_root / "artifacts")
            self._finding_store = FindingStore(job_root)
        except (AtomicCommitError, UnsafePathError, ValueError):
            raise
        except OSError as e:
            logger.warning("storage_init_error", error=str(e))
            self._artifact_store = None
            self._finding_store = None
        except Exception as e:
            logger.warning("storage_init_error", error=str(e))
            self._artifact_store = None
            self._finding_store = None

    async def run(self, seed_urls: list[str]) -> Report:
        """
        Run the full analysis pipeline.

        Args:
            seed_urls: URLs to analyze

        Returns:
            Report with all findings
        """
        self.progress.started_at = datetime.now(timezone.utc)
        self._seed_urls = list(seed_urls)

        # Initialize scope from seed URLs
        for url in seed_urls:
            self.scope.config.add_seed_domain(url)
        # Recompile scope patterns after adding seed domains
        self.scope.recompile()

        try:
            checkpoint = await self._load_checkpoint(seed_urls)

            # Stage 1: Crawl
            if checkpoint and self._stage_at_least(checkpoint.stage, PipelineStage.CRAWL):
                js_refs = checkpoint.js_refs
            else:
                partial_crawl_refs = list(checkpoint.js_refs) if checkpoint else []
                crawl_complete_seeds = set((checkpoint.stage_state or {}).get("crawl_complete_seeds", [])) if checkpoint else set()
                crawl_complete_seed_phases = (
                    {
                        url: set(phases)
                        for url, phases in ((checkpoint.stage_state or {}).get("crawl_complete_seed_phases", {}) or {}).items()
                        if isinstance(url, str) and isinstance(phases, list)
                    }
                    if checkpoint else {}
                )
                crawl_seed_phase_states = (
                    self._parse_crawl_phase_states((checkpoint.stage_state or {}).get("crawl_seed_phase_states", {}))
                    if checkpoint else {}
                )
                js_refs = await self._stage_crawl(
                    seed_urls,
                    partial_crawl_refs,
                    crawl_complete_seeds,
                    crawl_complete_seed_phases,
                    crawl_seed_phase_states,
                )
                crawl_stage = PipelineStage.CRAWL if "" not in self._retry_barriers else ""
                await self._store_checkpoint(
                    crawl_stage,
                    seed_urls,
                    js_refs=js_refs,
                    stage_state=self._crawl_stage_state,
                )

            # Stage 2: Download
            if checkpoint and self._stage_at_least(checkpoint.stage, PipelineStage.DOWNLOAD):
                assets = await self._restore_assets(checkpoint.asset_hashes)
            else:
                partial_assets = await self._restore_assets(checkpoint.asset_hashes) if checkpoint else []
                downloaded_urls = set((checkpoint.stage_state or {}).get("download_complete_urls", [])) if checkpoint else set()
                assets = await self._stage_download(js_refs, partial_assets, downloaded_urls)
                download_stage = (
                    PipelineStage.DOWNLOAD
                    if "crawl" not in self._retry_barriers
                    else PipelineStage.CRAWL
                )
                await self._store_checkpoint(
                    download_stage,
                    seed_urls,
                    js_refs=js_refs,
                    assets=assets,
                    stage_state=self._download_stage_state,
                )

            # Stage 3: Normalize
            if checkpoint and self._stage_at_least(checkpoint.stage, PipelineStage.NORMALIZE):
                self._restore_checkpoint_mappings(checkpoint)
            else:
                partial_normalized_hashes = set((checkpoint.stage_state or {}).get("normalize_complete_hashes", [])) if checkpoint else set()
                if checkpoint and partial_normalized_hashes:
                    self._restore_checkpoint_mappings(checkpoint)
                await self._stage_normalize(assets, partial_normalized_hashes)
                await self._store_checkpoint(PipelineStage.NORMALIZE, seed_urls, js_refs=js_refs, assets=assets)

            # Stage 4: Parse
            if checkpoint and self._stage_at_least(checkpoint.stage, PipelineStage.PARSE):
                await self._restore_parse_results(assets)
            else:
                partial_parse_hashes = set((checkpoint.stage_state or {}).get("parse_complete_hashes", [])) if checkpoint else set()
                if partial_parse_hashes:
                    await self._restore_parse_results(assets, partial_parse_hashes)
                await self._stage_parse(assets, partial_parse_hashes)
                await self._store_checkpoint(PipelineStage.PARSE, seed_urls, js_refs=js_refs, assets=assets)

            # Parsed static/dynamic imports can reveal modules absent from the page/manifest crawl.
            # Expand download -> normalize -> parse to a deterministic fixed point before analysis.
            js_refs, assets = await self._expand_dependency_frontier(js_refs, assets)

            # Stage 5: Analyze
            if checkpoint and self._stage_at_least(checkpoint.stage, PipelineStage.ANALYZE):
                findings = checkpoint.findings
                self._findings = findings
            else:
                partial_findings = list(checkpoint.findings) if checkpoint else []
                analyzed_hashes = set((checkpoint.stage_state or {}).get("analyze_complete_hashes", [])) if checkpoint else set()
                findings = await self._stage_analyze(assets, partial_findings, analyzed_hashes)
                await self._store_checkpoint(
                    PipelineStage.ANALYZE,
                    seed_urls,
                    js_refs=js_refs,
                    assets=assets,
                    findings=findings,
                )

            # Stage 6: Correlate
            graph = await self._stage_correlate(findings)

            # Stage 7: Classify
            await self._stage_classify(findings, graph)

            # Stage 8: Report
            report = await self._stage_report(
                seed_urls, assets, findings, graph
            )

            self.progress.complete()
            return report

        except Exception as e:
            logger.error("pipeline_error", error=str(e))
            raise

    async def _load_checkpoint(self, seed_urls: list[str]) -> PipelineCheckpoint | None:
        """Load a pipeline checkpoint for the current job when resuming."""
        if not self.config.resume or not self._finding_store:
            return None

        try:
            checkpoint = await self._finding_store.get_checkpoint()
        except (AtomicCommitError, UnsafePathError):
            raise
        except Exception as e:
            logger.warning("checkpoint_load_error", job_id=self.job_id, error=str(e))
            return None

        if checkpoint is not None and checkpoint_matches_resume_signature(
            checkpoint,
            expected_job_id=self.job_id,
            seed_urls=seed_urls,
            expected_signature=self._resume_signature,
        ):
            for issue in checkpoint.completeness.issues:
                self._add_completeness_issue(
                    code=issue.code,
                    stage=issue.stage,
                    message=issue.message,
                    retryable=issue.retryable,
                    affected_count=issue.affected_count,
                    details=dict(issue.details),
                )
            self._checkpoint_snapshot = checkpoint
            return checkpoint
        return None

    async def _store_checkpoint(
        self,
        stage: PipelineStage | str,
        seed_urls: list[str],
        js_refs: list[JSReference] | None = None,
        assets: list[JSAsset] | None = None,
        findings: list[Finding] | None = None,
        stage_state: dict[str, Any] | None = None,
    ) -> None:
        """Atomically merge and persist checkpoint state from concurrent callbacks."""
        if not self._finding_store:
            return
        async with self._checkpoint_lock:
            await self._store_checkpoint_unlocked(
                stage,
                seed_urls,
                js_refs=js_refs,
                assets=assets,
                findings=findings,
                stage_state=stage_state,
            )

    async def _store_checkpoint_unlocked(
        self,
        stage: PipelineStage | str,
        seed_urls: list[str],
        js_refs: list[JSReference] | None = None,
        assets: list[JSAsset] | None = None,
        findings: list[Finding] | None = None,
        stage_state: dict[str, Any] | None = None,
    ) -> None:
        """Persist a stage checkpoint for later resume."""
        if not self._finding_store:
            return

        requested_stage = stage.value if isinstance(stage, PipelineStage) else str(stage)
        stage_value = self._effective_checkpoint_stage(requested_stage)
        previous = self._checkpoint_snapshot
        if previous:
            previous_stage = self._effective_checkpoint_stage(previous.stage)
            if self._stage_index(previous_stage) > self._stage_index(stage_value):
                stage_value = previous_stage

        merged_state = dict(previous.stage_state if previous else {})
        merged_state.pop("_resume_signature", None)
        if stage_state:
            # Top-level keys are independently owned by stages. Replace the supplied value in full
            # (including an empty mapping, which intentionally clears stale nested resume state),
            # while retaining progress keys from every other stage.
            merged_state.update(stage_state)

        checkpoint = PipelineCheckpoint(
            job_id=self.job_id,
            seed_urls=seed_urls,
            stage=stage_value,
            js_refs=(list(js_refs) if js_refs is not None
                     else list(previous.js_refs) if previous else []),
            asset_hashes=(
                [asset.content_hash for asset in assets if asset.content_hash]
                if assets is not None
                else list(previous.asset_hashes) if previous else []
            ),
            line_mappers={
                content_hash: mapper.to_dict()
                for content_hash, mapper in self._line_mappers.items()
            },
            sourcemaps={
                content_hash: sourcemap.to_dict()
                for content_hash, sourcemap in self._sourcemaps.items()
            },
            findings=(list(findings) if findings is not None
                      else list(previous.findings) if previous else []),
            stage_state=build_stage_state_with_resume_signature(
                merged_state,
                self._resume_signature,
            ),
            completeness=self._build_completeness(),
        )

        try:
            await self._finding_store.store_checkpoint(checkpoint)
            self._checkpoint_snapshot = checkpoint
        except (AtomicCommitError, UnsafePathError):
            raise
        except Exception as e:
            logger.warning("checkpoint_store_error", stage=stage_value, error=str(e))

    @staticmethod
    def _stage_index(stage: str) -> int:
        lookup = {item.value: index for index, item in enumerate(_STAGE_ORDER)}
        return lookup.get(stage, -1)

    def _effective_checkpoint_stage(self, requested_stage: str) -> str:
        if not self._retry_barriers:
            return requested_stage
        barrier = min(self._retry_barriers, key=self._stage_index)
        if self._stage_index(requested_stage) > self._stage_index(barrier):
            return barrier
        return requested_stage

    def _add_completeness_issue(
        self,
        *,
        code: str,
        stage: str,
        message: str,
        retryable: bool = False,
        affected_count: int = 0,
        details: dict[str, Any] | None = None,
    ) -> None:
        issue = CompletenessIssue(
            code=code,
            stage=stage,
            message=message,
            retryable=retryable,
            affected_count=affected_count,
            details=details or {},
        )
        key = (issue.code, issue.stage, issue.message)
        if all((item.code, item.stage, item.message) != key for item in self._completeness_issues):
            self._completeness_issues.append(issue)

    def _build_completeness(self) -> AnalysisCompleteness:
        issues = list(self._completeness_issues)
        return AnalysisCompleteness(
            status=(CompletenessStatus.PARTIAL if issues else CompletenessStatus.COMPLETE),
            issues=issues,
        )

    def _promote_analysis_events(self, events: object) -> None:
        """Promote bounded rule-engine telemetry into the report completeness contract."""
        if not isinstance(events, list):
            return
        normalized = [dict(event) for event in events if isinstance(event, dict)]
        normalized.sort(
            key=lambda event: json.dumps(event, sort_keys=True, default=str, separators=(",", ":"))
        )
        for event in normalized:
            component = str(event.get("component", "rule"))
            reason = str(event.get("reason", "analysis_cap"))
            if component == "asset_enrichment":
                code = "finding_enrichment_failed"
                message = "Finding source metadata could not be fully enriched"
            elif component == "intermediate_representation":
                code = "ir_truncated"
                message = "Intermediate representation was truncated by an analysis cap"
            elif component.startswith("custom_rule"):
                code = "custom_rule_analysis_incomplete"
                message = f"Rule analysis was incomplete ({component}: {reason})"
            elif component.startswith("virtual_source"):
                code = "virtual_source_analysis_incomplete"
                message = f"Rule analysis was incomplete ({component}: {reason})"
            else:
                code = "rule_analysis_incomplete"
                message = f"Rule analysis was incomplete ({component}: {reason})"
            self._add_completeness_issue(
                code=code,
                stage=PipelineStage.ANALYZE.value,
                message=message,
                affected_count=1,
                details=event,
            )

    def _restore_checkpoint_mappings(self, checkpoint: PipelineCheckpoint) -> None:
        """Restore line mappers and source maps from a checkpoint."""
        self._line_mappers = {
            content_hash: LineMapper.from_dict(data)
            for content_hash, data in checkpoint.line_mappers.items()
        }
        self._sourcemaps = {
            content_hash: SourceMapInfo.from_dict(data)
            for content_hash, data in checkpoint.sourcemaps.items()
        }

    async def _restore_assets(self, asset_hashes: list[str]) -> list[JSAsset]:
        """Restore stored assets for resume."""
        assets: list[JSAsset] = []
        if not self._artifact_store:
            return assets

        for content_hash in asset_hashes:
            asset = await self._artifact_store.get_asset_meta(content_hash)
            if not asset:
                continue
            # Restore the NORMALIZED (beautified) content, not the raw download: the stored
            # AST, line_mappers and sourcemaps were all built against the beautified source,
            # so analyze must re-run against the same content or evidence positions and
            # context-filter indexing go wrong (mis-scored / dropped findings on --resume).
            content = None
            if asset.normalized_hash and asset.normalized_hash != content_hash:
                content = await self._artifact_store.get_js(asset.normalized_hash)
            if content is None:
                content = await self._artifact_store.get_js(content_hash)
            if content is not None:
                asset.content = content
            if asset.sourcemap_hash:
                sourcemap_content = await self._artifact_store.get_sourcemap(
                    content_hash,
                    asset.sourcemap_hash,
                )
                if sourcemap_content is not None:
                    asset.sourcemap_content = sourcemap_content
            assets.append(asset)

        self._assets = assets
        return assets

    async def _restore_parse_results(
        self,
        assets: list[JSAsset],
        allowed_hashes: set[str] | None = None,
    ) -> None:
        """Restore cached AST parse results for resumed assets."""
        if not self._artifact_store:
            return

        for asset in assets:
            if allowed_hashes is not None and asset.content_hash not in allowed_hashes:
                continue
            if not asset.ast_hash:
                continue
            ast = await self._artifact_store.get_ast(asset.content_hash, asset.ast_hash)
            if not ast:
                continue
            self._parse_results[asset.content_hash] = ParseResult(
                success=True,
                ast=ast,
                errors=list(asset.parse_errors),
                partial=bool(ast.get("partial") or ast.get("regex_fallback")),
                parser_used="cache",
            )

    def _stage_at_least(self, checkpoint_stage: str, target_stage: PipelineStage) -> bool:
        """Check whether a checkpoint has reached at least a target stage."""
        stage_lookup = {stage.value: index for index, stage in enumerate(_STAGE_ORDER)}
        return stage_lookup.get(checkpoint_stage, -1) >= stage_lookup[target_stage.value]

    async def _stage_crawl(
        self,
        seed_urls: list[str],
        existing_refs: list[JSReference] | None = None,
        completed_seeds: set[str] | None = None,
        completed_seed_phases: dict[str, set[str]] | None = None,
        partial_seed_phase_states: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> list[JSReference]:
        """Crawl for JS references."""
        self.progress.start_stage(PipelineStage.CRAWL, len(seed_urls))

        js_refs: list[JSReference] = list(existing_refs or [])
        completed = set(completed_seeds or [])
        partial_seed_phases = {
            url: set(phases)
            for url, phases in (completed_seed_phases or {}).items()
            if url not in completed and phases
        }
        phase_states = {
            url: {
                phase: dict(state)
                for phase, state in phases.items()
                if isinstance(phase, str) and isinstance(state, dict)
            }
            for url, phases in (partial_seed_phase_states or {}).items()
            if url not in completed and isinstance(phases, dict)
        }

        for ref in js_refs:
            self.dedup.add_url(ref.url)

        for url in seed_urls:
            if url in completed:
                self.progress.update(1)
                continue

            async def _phase_callback(
                phase_name: str,
                accumulated_refs: list[JSReference],
                phase_state: set[str],
                target_url: str = url,
            ) -> None:
                partial_seed_phases[target_url] = set(phase_state)
                phase_states.setdefault(target_url, {}).pop(phase_name, None)
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=[*js_refs, *accumulated_refs],
                    stage_state=self._build_crawl_stage_state(
                        completed,
                        partial_seed_phases,
                        phase_states,
                    ),
                )

            async def _ref_callback(
                phase_name: str,
                accumulated_refs: list[JSReference],
                phase_state: set[str],
                target_url: str = url,
            ) -> None:
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=[*js_refs, *accumulated_refs],
                    stage_state=self._build_crawl_stage_state(
                        completed,
                        partial_seed_phases,
                        phase_states,
                        in_progress_seed=target_url,
                        in_progress_phase=phase_name,
                        in_progress_ref_count=len(accumulated_refs),
                    ),
                )

            async def _page_callback(
                phase_name: str,
                accumulated_refs: list[JSReference],
                phase_progress_state: set[str],
                collector_state: dict[str, Any],
                target_url: str = url,
            ) -> None:
                partial_seed_phases[target_url] = set(phase_progress_state)
                phase_states.setdefault(target_url, {})[phase_name] = dict(
                    collector_state or {}
                )
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=[*js_refs, *accumulated_refs],
                    stage_state=self._build_crawl_stage_state(
                        completed,
                        partial_seed_phases,
                        phase_states,
                        in_progress_seed=target_url,
                        in_progress_phase=phase_name,
                        in_progress_ref_count=len(accumulated_refs),
                    ),
                )

            refs = await self._crawl_url(
                url,
                completed_phases=partial_seed_phases.get(url, set()),
                phase_states=phase_states.get(url, {}),
                on_phase_complete=_phase_callback,
                on_ref_discovered=_ref_callback,
                on_page_complete=_page_callback,
            )
            js_refs.extend(refs)
            if self._incomplete_crawl_phases.pop(url, None):
                # DQ-C06: a phase had a transient failure -> keep the seed PARTIAL so --resume re-runs
                # ONLY the failed phase. partial_seed_phases[url] already records the phases that DID
                # complete (set by their _phase_callback), so completed phases are not re-run.
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=js_refs,
                    stage_state=self._build_crawl_stage_state(
                        completed, partial_seed_phases, phase_states,
                    ),
                )
            else:
                completed.add(url)
                partial_seed_phases.pop(url, None)
                phase_states.pop(url, None)
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=js_refs,
                    stage_state=self._build_crawl_stage_state(completed, partial_seed_phases),
                )
            self.progress.update(1)

        self.progress.complete_stage()
        self._crawl_stage_state = self._build_crawl_stage_state(
            completed,
            partial_seed_phases,
            phase_states,
        )
        if len(completed) == len(set(seed_urls)):
            self._retry_barriers.discard("")
        else:
            self._retry_barriers.add("")
        logger.info("crawl_complete", js_refs=len(js_refs))

        return js_refs

    def _build_crawl_stage_state(
        self,
        completed_seeds: set[str],
        partial_seed_phases: dict[str, set[str]],
        partial_seed_phase_states: dict[str, dict[str, dict[str, Any]]] | None = None,
        in_progress_seed: str = "",
        in_progress_phase: str = "",
        in_progress_ref_count: int = 0,
    ) -> dict[str, Any]:
        """Serialize crawl-progress state for partial resume."""
        state: dict[str, Any] = {
            "crawl_complete_seeds": sorted(completed_seeds),
            "crawl_complete_seed_phases": {
                url: sorted(phases)
                for url, phases in partial_seed_phases.items()
                if phases and url not in completed_seeds
            },
        }
        if partial_seed_phase_states:
            state["crawl_seed_phase_states"] = {
                seed_url: {
                    phase_name: dict(phase_state)
                    for phase_name, phase_state in phases.items()
                    if phase_state and seed_url not in completed_seeds
                }
                for seed_url, phases in partial_seed_phase_states.items()
                if phases and seed_url not in completed_seeds
            }
        if in_progress_seed:
            state["crawl_in_progress_seed"] = in_progress_seed
            state["crawl_in_progress_phase"] = in_progress_phase
            state["crawl_in_progress_ref_count"] = in_progress_ref_count
        return state

    def _parse_crawl_phase_states(
        self,
        raw_state: Any,
    ) -> dict[str, dict[str, dict[str, Any]]]:
        """Validate serialized crawl phase resume state from checkpoints."""
        parsed: dict[str, dict[str, dict[str, Any]]] = {}
        if not isinstance(raw_state, dict):
            return parsed

        for seed_url, phase_map in raw_state.items():
            if not isinstance(seed_url, str) or not isinstance(phase_map, dict):
                continue
            parsed_phase_map: dict[str, dict[str, Any]] = {}
            for phase_name, phase_state in phase_map.items():
                if not isinstance(phase_name, str) or not isinstance(phase_state, dict):
                    continue
                parsed_phase_map[phase_name] = dict(phase_state)
            if parsed_phase_map:
                parsed[seed_url] = parsed_phase_map
        return parsed

    async def _crawl_url(
        self,
        url: str,
        completed_phases: set[str] | None = None,
        phase_states: dict[str, dict[str, Any]] | None = None,
        on_phase_complete: Callable[[str, list[JSReference], set[str]], Any] | None = None,
        on_ref_discovered: Callable[[str, list[JSReference], set[str]], Any] | None = None,
        on_page_complete: Callable[[str, list[JSReference], set[str], dict[str, Any]], Any] | None = None,
    ) -> list[JSReference]:
        """Crawl a single URL for JS references."""
        refs: list[JSReference] = []
        completed = set(completed_phases or [])
        self._incomplete_crawl_phases.pop(url, None)  # DQ-C06: fresh incomplete-phase tracking per run
        phase_state_map = {
            phase_name: dict(state)
            for phase_name, state in (phase_states or {}).items()
            if isinstance(phase_name, str) and isinstance(state, dict)
        }

        is_safe, reason = await asyncio.to_thread(
            is_url_safe, url, True, self.config.scope.allow_private_ips
        )
        if not is_safe:
            logger.warning("seed_url_blocked", url=url[:100], reason=reason,
                           hint=ssrf_block_hint(reason))
            self._add_completeness_issue(
                code="crawl_url_blocked",
                stage=PipelineStage.CRAWL.value,
                message=f"Seed URL was not crawled: {reason}",
                affected_count=1,
            )
            return refs

        static_cls = (
            MultiPageStaticCollector
            if self.config.crawler.max_depth > 0
            else StaticCollector
        )
        headless_cls = (
            HeadlessMultiPageCollector
            if self.config.crawler.max_depth > 0
            else HeadlessCollector
        )

        async def _run_phase(
            phase_name: str,
            collector_factory: Callable[[], Any],
        ) -> None:
            if phase_name in completed:
                return
            collector = collector_factory()
            if phase_state_map.get(phase_name) and hasattr(collector, "load_resume_state"):
                collector.load_resume_state(phase_state_map[phase_name])
            if on_page_complete and hasattr(collector, "on_page_complete"):
                async def _collector_page_callback(collector_state: dict[str, Any]) -> None:
                    await on_page_complete(
                        phase_name,
                        list(refs),
                        set(completed),
                        dict(collector_state or {}),
                    )
                collector.on_page_complete = _collector_page_callback
            async with collector:
                async for ref in collector.collect(url, self.scope):
                    if self.dedup.add_url(ref.url):
                        refs.append(ref)
                        if on_ref_discovered:
                            await on_ref_discovered(
                                phase_name,
                                list(refs),
                                set(completed),
                            )
            # enh2: harvest runtime-observed API calls (headless network capture) for the
            # dormant-endpoint baseline. Best-effort; only the headless collector exposes it.
            observed = getattr(collector, "observed_requests", None)
            if observed:
                self._observed_requests.update(observed)
            # enh7: also harvest runtime WebSocket URLs for runtime endpoint surfacing.
            observed_ws = getattr(collector, "observed_websockets", None)
            if observed_ws:
                self._observed_websockets.update(observed_ws)
            phase_state_map.pop(phase_name, None)
            # DQ-C06: if a transient failure (429/5xx/timeout/navigation) was swallowed during this
            # phase, do NOT mark it complete (so --resume re-runs it) and surface the lost coverage.
            # Gate on the explicit failure record, NOT on "0 refs" -- a legitimately empty page must
            # still checkpoint as complete. Refs already collected are kept.
            retryable = list(getattr(collector, "retryable_failures", None) or [])
            nested = getattr(collector, "_collector", None)
            if nested is not None:
                retryable.extend(list(getattr(nested, "retryable_failures", None) or []))
            if retryable:
                self._incomplete_crawl_phases.setdefault(url, set()).add(phase_name)
                for f in retryable:
                    status = f.get("status")
                    self._crawl_warnings.append(
                        f"crawl phase '{phase_name}' incomplete: transient failure fetching "
                        f"{f.get('url', '?')} ({f.get('reason', 'error')})"
                        + (f" [HTTP {status}]" if status else "")
                        + " -- coverage may be incomplete; re-scan to recover it"
                    )
                    self._add_completeness_issue(
                        code="crawl_transient_failure",
                        stage=PipelineStage.CRAWL.value,
                        message=(
                            f"Crawl phase {phase_name!r} did not finish after a transient failure"
                        ),
                        retryable=True,
                        affected_count=1,
                        details={"phase": phase_name, "status": status or 0},
                    )
                return
            terminal = list(getattr(collector, "terminal_failures", None) or [])
            if nested is not None:
                terminal.extend(list(getattr(nested, "terminal_failures", None) or []))
            for failure in terminal:
                self._add_completeness_issue(
                    code=str(failure.get("code") or "crawl_terminal_failure"),
                    stage=PipelineStage.CRAWL.value,
                    message=(
                        f"Crawl phase {phase_name!r} lost coverage because a request was "
                        "terminally rejected"
                    ),
                    affected_count=1,
                    details={"phase": phase_name, "reason": str(failure.get("reason", ""))[:160]},
                )
            completed.add(phase_name)
            if on_phase_complete:
                await on_phase_complete(phase_name, list(refs), set(completed))

        await _run_phase(
            "static",
            lambda: static_cls(
                self.config.crawler,
                self.config.auth,
                allow_private_ips=self.config.scope.allow_private_ips,
                rate_limiter=self.rate_limiter,
            ),
        )

        if self.config.crawler.use_headless:
            try:
                await _run_phase(
                    "headless",
                    lambda: headless_cls(
                        self.config.crawler,
                        self.config.auth,
                        allow_private_ips=self.config.scope.allow_private_ips,
                        rate_limiter=self.rate_limiter,
                    ),
                )
            except Exception as e:
                msg = str(e)
                self._incomplete_crawl_phases.setdefault(url, set()).add("headless")
                retryable = not (
                    "Executable doesn't exist" in msg or "playwright install" in msg
                )
                self._add_completeness_issue(
                    code="headless_crawl_failed",
                    stage=PipelineStage.CRAWL.value,
                    message="Headless crawl phase did not complete",
                    retryable=retryable,
                    affected_count=1,
                )
                if "Executable doesn't exist" in msg or "playwright install" in msg:
                    logger.warning(
                        "headless_browser_not_installed",
                        hint="run 'playwright install chromium' (see docs if behind a "
                             "TLS-intercepting proxy), or re-run with --no-headless",
                    )
                else:
                    logger.warning("headless_error", error=msg)

        await _run_phase(
            "manifest",
            lambda: ManifestCollector(
                self.config.crawler,
                self.config.auth,
                allow_private_ips=self.config.scope.allow_private_ips,
                rate_limiter=self.rate_limiter,
            ),
        )

        return refs

    async def _stage_download(
        self,
        js_refs: list[JSReference],
        existing_assets: list[JSAsset] | None = None,
        completed_urls: set[str] | None = None,
    ) -> list[JSAsset]:
        """Download JS files with rate limiting and concurrency control."""
        # A URL consumes the global budget once. Discovery paths remain attached as provenance,
        # and a browser-captured body wins as the canonical fetch source for duplicate refs.
        js_refs[:] = self._coalesce_js_refs(js_refs)
        # Enforce max_js_files limit
        max_files = self.config.crawler.max_js_files
        if len(js_refs) > max_files:
            # DQ-I01: when the cap truncates, keep every fetched external/network ref ahead of the
            # extra in-page inline (#__bi_inline) refs, so inline capture can never DISPLACE a
            # previously-kept external asset (INV-01). Stable sort preserves order within each group.
            ordered_refs = sorted(
                js_refs,
                key=lambda r: (
                    r.inline_content is not None,
                    r.url,
                    r.initiator,
                    r.load_context,
                    r.method.value,
                ),
            )
            logger.warning(
                "js_refs_limited",
                total=len(ordered_refs),
                limit=max_files,
            )
            self._add_completeness_issue(
                code="max_js_files_reached",
                stage=PipelineStage.DOWNLOAD.value,
                message=f"JavaScript reference limit ({max_files}) truncated the download set",
                affected_count=len(ordered_refs) - max_files,
                details={"limit": max_files, "discovered": len(ordered_refs)},
            )
            js_refs[:] = ordered_refs[:max_files]

        self.progress.start_stage(PipelineStage.DOWNLOAD, len(js_refs))

        assets: list[JSAsset] = list(existing_assets or [])
        completed = set(completed_urls or {asset.url for asset in assets})
        for asset in assets:
            if asset.content_hash:
                self.dedup.add_content(asset.content_hash, asset.url)
            matching_refs = [
                ref
                for ref in js_refs
                if ref.url == asset.url or any(item.url == ref.url for item in asset.provenance)
            ]
            for ref in matching_refs:
                self._merge_asset_provenance(
                    asset,
                    JSAsset(
                        url=ref.url,
                        provenance=self._provenance_entries_from_ref(ref),
                    ),
                )

        # Create shared HTTP client for all downloads
        self._download_client = httpx.AsyncClient(
            headers={"User-Agent": self.config.crawler.user_agent},
            timeout=self.config.crawler.request_timeout,
            follow_redirects=False,
            max_redirects=self.config.crawler.max_redirects,
            transport=build_pinned_transport(
                allow_private_ips=self.config.scope.allow_private_ips,
                max_connections=self.config.crawler.max_concurrent,
            ),
            trust_env=False,
        )

        tasks: list[asyncio.Task] = []
        try:
            # Semaphore to limit concurrent downloads (prevents task flooding)
            # max(1, ...): max_concurrent=0 would make Semaphore(0) block every download
            # forever (silent whole-scan hang, zero findings).
            download_semaphore = asyncio.Semaphore(max(1, self.config.crawler.max_concurrent))

            async def download_one(ref: JSReference) -> tuple[JSReference, JSAsset | None, bool]:
                # Returns (ref, asset, terminal). `terminal` marks whether this URL is DONE for
                # resume: True on success or a PERMANENT skip (SSRF / too-large), False on a
                # TRANSIENT failure (5xx / 429 / network) so --resume retries it instead of silently
                # dropping the asset and every finding it would have produced.
                # DQ-I01: inline <script> content is already in-page first-party JS -- there is no URL
                # to fetch, so synthesize the asset directly, bypassing the SSRF check, HTTP GET,
                # rate limiter and download semaphore. Terminal (never needs a resume retry).
                if ref.inline_content is not None:
                    try:
                        asset = self._build_inline_asset(ref)
                        self.progress.update(1)
                        return ref, asset, True
                    except Exception as exc:
                        logger.warning("inline_asset_build_failed", url=ref.url[:100], error=str(exc))
                        self.progress.update(0, failed=1)
                        return ref, None, True
                if ref.captured_content is not None:
                    try:
                        asset = await self._build_captured_asset(ref)
                        self.progress.update(1)
                        return ref, asset, True
                    except Exception as exc:
                        logger.warning("captured_asset_build_failed", url=ref.url[:100], error=str(exc))
                        self.progress.update(0, failed=1)
                        return ref, None, True
                async with download_semaphore:
                    attempts = max(0, self.config.crawler.max_retries) + 1
                    for attempt in range(attempts):
                        try:
                            await self.rate_limiter.acquire(ref.url)
                            downloaded_asset = await self._download_js(ref)
                            if downloaded_asset:
                                await self.rate_limiter.record_success(ref.url)
                                self.progress.update(1)
                            else:
                                self.progress.update(0, failed=1)
                                self._add_completeness_issue(
                                    code="download_policy_skip",
                                    stage=PipelineStage.DOWNLOAD.value,
                                    message="A JavaScript asset was skipped by download policy",
                                    affected_count=1,
                                )
                            return ref, downloaded_asset, True
                        except httpx.HTTPStatusError as exc:
                            status = exc.response.status_code
                            transient = status >= 500 or status == 429
                            await self.rate_limiter.record_error(ref.url, status)
                            if not transient:
                                self.progress.update(0, failed=1)
                                self._add_completeness_issue(
                                    code="download_http_rejected",
                                    stage=PipelineStage.DOWNLOAD.value,
                                    message=f"JavaScript asset returned HTTP {status}",
                                    affected_count=1,
                                    details={"status": status},
                                )
                                return ref, None, True
                            if attempt + 1 < attempts:
                                await asyncio.sleep(self.config.crawler.retry_delay)
                                continue
                            self.progress.update(0, failed=1)
                            self._add_completeness_issue(
                                code="download_transient_failure",
                                stage=PipelineStage.DOWNLOAD.value,
                                message=f"JavaScript asset remained unavailable after {attempts} attempts",
                                retryable=True,
                                affected_count=1,
                                details={"status": status, "attempts": attempts},
                            )
                            return ref, None, False
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            if attempt + 1 < attempts:
                                await asyncio.sleep(self.config.crawler.retry_delay)
                                continue
                            self.progress.update(0, failed=1)
                            self._add_completeness_issue(
                                code="download_transient_failure",
                                stage=PipelineStage.DOWNLOAD.value,
                                message=f"JavaScript asset remained unavailable after {attempts} attempts",
                                retryable=True,
                                affected_count=1,
                                details={"attempts": attempts},
                            )
                            return ref, None, False

                    return ref, None, False

            refs_to_download = [ref for ref in js_refs if ref.url not in completed]
            if completed:
                self.progress.update(sum(1 for ref in js_refs if ref.url in completed))

            tasks = [asyncio.create_task(download_one(ref)) for ref in refs_to_download]

            for task in asyncio.as_completed(tasks):
                completed_ref: JSReference | None = None
                terminal = False
                try:
                    completed_ref, result, terminal = await task
                    if isinstance(result, JSAsset):
                        # Check for content dedup
                        if self.dedup.add_content(result.content_hash, result.url):
                            assets.append(result)
                            await self._persist_asset(result)
                        else:
                            existing = next(
                                (asset for asset in assets if asset.content_hash == result.content_hash),
                                None,
                            )
                            if existing is not None:
                                self._merge_asset_provenance(existing, result)
                                await self._persist_asset(existing)
                except asyncio.CancelledError:
                    raise
                except (KeyboardInterrupt, SystemExit):
                    # BaseException below would otherwise swallow Ctrl+C, leaving
                    # the download loop running instead of aborting.
                    raise
                except BaseException as exc:
                    logger.warning("download_task_exception", error=str(exc))
                finally:
                    # Only mark a URL complete when it is DONE (success or a permanent skip); a
                    # transient failure stays incomplete so --resume re-downloads it (else the asset
                    # and every finding it would produce are silently lost on resume).
                    if completed_ref and terminal:
                        completed.add(completed_ref.url)
                    await self._store_checkpoint(
                        PipelineStage.CRAWL,
                        self._seed_urls,
                        js_refs=js_refs,
                        assets=assets,
                        stage_state={"download_complete_urls": sorted(completed)},
                    )

        except BaseException:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            raise
        finally:
            # A normal exit also awaits every owned child. This prevents an early iterator error or
            # cancellation from leaving network tasks alive against a closing client.
            pending = [task for task in tasks if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            await self._download_client.aclose()
            self._download_client = None

        self._download_stage_state = {"download_complete_urls": sorted(completed)}
        expected_urls = {ref.url for ref in js_refs}
        if expected_urls.issubset(completed):
            self._retry_barriers.discard(PipelineStage.CRAWL.value)
        else:
            self._retry_barriers.add(PipelineStage.CRAWL.value)
        self.progress.complete_stage()
        assets.sort(key=lambda asset: (asset.url, asset.content_hash, asset.id))
        self._assets = assets
        logger.info("download_complete", assets=len(assets))

        return assets

    def _build_inline_asset(self, ref: JSReference) -> JSAsset:
        """Synthesize a JSAsset from an inline <script> body (DQ-I01). No network: the content is
        already in-page first-party JS, so SSRF/HTTP/rate-limit are correctly bypassed."""
        content = (ref.inline_content or "").encode("utf-8")
        asset = JSAsset(
            url=ref.url,
            content=content,
            size=len(content),
            initiator=ref.initiator,
            load_context=ref.load_context,
            load_method=ref.method,
            is_first_party=self.scope.is_first_party(ref.url),
            status_code=200,
            provenance=self._provenance_entries_from_ref(ref),
        )
        asset.compute_hash()
        return asset

    async def _build_captured_asset(self, ref: JSReference) -> JSAsset:
        """Build an asset from the browser response body without credential-unsafe refetching."""
        content = ref.captured_content or b""
        if len(content) > self.config.crawler.max_file_size:
            raise ValueError("captured JavaScript body exceeds max_file_size")
        safe_headers = {
            name.lower(): value
            for name, value in ref.headers.items()
            if name.lower() in {"content-type", "content-length", "cache-control", "etag", "last-modified"}
        }
        content = await asyncio.to_thread(
            self._sanitize_html_document_for_analysis,
            content,
            safe_headers.get("content-type", ""),
        )
        asset = JSAsset(
            url=ref.url,
            content=content,
            size=len(content),
            initiator=ref.initiator,
            load_context=ref.load_context,
            load_method=ref.method,
            is_first_party=self.scope.is_first_party(ref.url),
            headers=safe_headers,
            status_code=ref.captured_status_code,
            etag=safe_headers.get("etag"),
            last_modified=safe_headers.get("last-modified"),
            provenance=self._provenance_entries_from_ref(ref),
        )
        asset.compute_hash()
        return asset

    @staticmethod
    def _provenance_from_ref(ref: JSReference) -> AssetProvenance:
        return AssetProvenance(
            url=ref.url,
            initiator=ref.initiator,
            load_context=ref.load_context,
            method=ref.method,
        )

    def _provenance_entries_from_ref(self, ref: JSReference) -> list[AssetProvenance]:
        entries = list(ref.provenance) + [self._provenance_from_ref(ref)]
        unique = {
            (item.url, item.initiator, item.load_context, item.method.value): item
            for item in entries
        }
        return [unique[key] for key in sorted(unique)]

    def _coalesce_js_refs(self, refs: list[JSReference]) -> list[JSReference]:
        grouped: dict[str, list[JSReference]] = {}
        for ref in refs:
            grouped.setdefault(ref.url, []).append(ref)

        coalesced: list[JSReference] = []
        for url in sorted(grouped):
            group = grouped[url]
            canonical = min(
                group,
                key=lambda ref: (
                    ref.captured_content is None,
                    ref.inline_content is None,
                    ref.initiator,
                    ref.load_context,
                    ref.method.value,
                ),
            ).model_copy(deep=True)
            paths: list[AssetProvenance] = []
            for ref in group:
                paths.extend(self._provenance_entries_from_ref(ref))
            unique = {
                (item.url, item.initiator, item.load_context, item.method.value): item
                for item in paths
            }
            canonical.provenance = [unique[key] for key in sorted(unique)]
            primary = canonical.provenance[0]
            canonical.initiator = primary.initiator
            canonical.load_context = primary.load_context
            canonical.method = primary.method
            coalesced.append(canonical)
        return coalesced

    def _merge_asset_provenance(self, existing: JSAsset, incoming: JSAsset) -> None:
        provenance = list(existing.provenance)
        provenance.append(AssetProvenance(
            url=existing.url,
            initiator=existing.initiator,
            load_context=existing.load_context,
            method=existing.load_method,
        ))
        provenance.extend(incoming.provenance)
        provenance.append(AssetProvenance(
            url=incoming.url,
            initiator=incoming.initiator,
            load_context=incoming.load_context,
            method=incoming.load_method,
        ))
        unique = {
            (item.url, item.initiator, item.load_context, item.method.value): item
            for item in provenance
        }
        existing.provenance = [unique[key] for key in sorted(unique)]
        # Both asset URLs are post-redirect response URLs. Keep a deterministic final URL as the
        # parsing base; discovery aliases remain provenance and must never overwrite it.
        existing.url = min(existing.url, incoming.url)
        canonical = min(
            (item for item in existing.provenance if item.url == existing.url),
            key=lambda item: (item.initiator, item.load_context, item.method.value),
            default=existing.provenance[0],
        )
        existing.initiator = canonical.initiator
        existing.load_context = canonical.load_context
        existing.load_method = canonical.method
        existing.is_first_party = self.scope.is_first_party(existing.url)

    # Markup attributes that hold a URL/path and, when a JS-ref URL mistakenly returns an HTML
    # document, get mis-detected as API endpoints. They carry URLs/paths, NEVER secrets, so stripping
    # only these removes the endpoint FP without dropping any known-provider secret (INV-02).
    _HTML_URL_ATTRS = ("href", "action", "src", "formaction")

    @staticmethod
    def _url_value_bears_secret(value: str) -> bool:
        """True if a markup URL-attribute value itself carries a known-provider or generic secret --
        e.g. a Google key in `<script src="...?key=AIza...">`, or a Slack/Discord webhook URL in an
        href/action/src. Such an attribute must NOT be stripped by the HTML sanitizer, because doing
        so would hard-drop a secret the pre-batch wholesale scan reported (INV-02). Reuses the
        SecretDetector's own compiled patterns (single source of truth), so the guard tracks exactly
        what the detector would report."""
        if not value:
            return False
        from bundleInspector.rules.detectors.secrets import SecretDetector
        for pattern, _type, _sev, required in SecretDetector._COMPILED_SECRET_PATTERNS:
            # Keep the detector's required-literal prefilter (do NOT discard it) -- a cheap `in` skip
            # that avoids running a regex whose mandatory literal is absent. Every provider pattern's
            # quantifiers are upper-bounded (the formerly-unbounded firebase/auth0/telegram/google-
            # oauth patterns were bounded at the source), so this scan is linear -- no length gate is
            # needed and none is applied (an earlier len>512 gate wrongly dropped a >512-char
            # amqp/rabbitmq database_url secret, which is anchorless yet length-bounded).
            if required is not None and required not in value:
                continue
            if pattern.search(value):
                return True
        for pattern, *_ in SecretDetector._COMPILED_GENERIC_PATTERNS:
            if pattern.search(value):
                return True
        return False

    @staticmethod
    def _sanitize_html_document_for_analysis(content: bytes, content_type: str) -> bytes:
        """DQ-I05: a <script src>/JS-ref URL that returns an HTML document (auth wall / login / error
        page served 200) must not have its markup URL attributes (href/action/src/formaction) analyzed
        as API endpoints. Sniff the BODY (never the content-type: JS mislabeled text/html/text/plain
        must NOT be touched -- real JS never leads with an HTML document marker) and, when it IS an
        HTML document, strip only those URL-bearing attributes, KEEPING every other byte -- inline
        <script> JS, <script type=application/json> hydration islands (__NEXT_DATA__), meta/data
        attributes and text -- so any embedded known-provider secret is still scanned (INV-02) and
        real inline-script endpoints survive (INV-01). A URL attribute whose VALUE itself bears a
        secret (a Google key `...?key=AIza...`, a Slack/Discord webhook) is KEPT (INV-02 > the
        endpoint FP for that rare secret-bearing URL). Only benign endpoint-FP URL values go."""
        try:
            prefix = content[:512].decode("utf-8", errors="replace").lstrip("\ufeff \t\r\n").lower()
        except Exception:
            return content
        if not prefix.startswith(("<!doctype html", "<html", "<head", "<body")):
            return content
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, "lxml")
            stripped = False
            for tag in soup.find_all(True):
                for attr in Orchestrator._HTML_URL_ATTRS:
                    if not tag.has_attr(attr):
                        continue
                    raw = tag.get(attr)
                    val = " ".join(raw) if isinstance(raw, list) else (raw or "")
                    if Orchestrator._url_value_bears_secret(val):
                        continue  # keep a secret-bearing URL attribute (INV-02)
                    del tag[attr]
                    stripped = True
            if not stripped:
                return content
            return str(soup).encode("utf-8")
        except Exception:
            return content

    async def _download_js(self, ref: JSReference) -> JSAsset | None:
        """Download a JS file with per-hop SSRF validation and origin-bound credentials."""
        try:
            client = self._download_client
            if not client:
                raise RuntimeError("Download client not initialized")
            current_url = ref.url
            redirect_count = 0
            response_headers: dict[str, str] = {}
            response_status = 0

            while True:
                if not self.scope.is_allowed(current_url):
                    logger.warning(
                        "scope_blocked",
                        url=current_url[:100],
                        reason="redirect target is outside scope",
                    )
                    return None
                is_safe, reason = is_url_safe(
                    current_url,
                    False,
                    self.config.scope.allow_private_ips,
                )
                if not is_safe:
                    logger.warning(
                        "ssrf_blocked",
                        url=current_url[:100],
                        reason=reason,
                        hint=ssrf_block_hint(reason),
                    )
                    return None

                if redirect_count:
                    await self.rate_limiter.acquire(current_url)
                request_headers = self._origin_bound_auth_headers(current_url)
                stream_context = (
                    client.stream("GET", current_url, headers=request_headers)
                    if request_headers
                    else client.stream("GET", current_url)
                )
                async with stream_context as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not self.config.crawler.follow_redirects or not location:
                            logger.warning("redirect_not_followed", url=current_url[:100])
                            return None
                        if redirect_count >= self.config.crawler.max_redirects:
                            logger.warning("redirect_limit_reached", url=current_url[:100])
                            return None
                        try:
                            current_url = urljoin(current_url, location)
                        except (TypeError, ValueError):
                            logger.warning("redirect_malformed", url=current_url[:100])
                            return None
                        redirect_count += 1
                        continue

                    response.raise_for_status()
                    content_length = response.headers.get("content-length")
                    if content_length:
                        try:
                            if int(content_length) > self.config.crawler.max_file_size:
                                logger.warning(
                                    "file_too_large",
                                    url=current_url[:100],
                                    limit_bytes=self.config.crawler.max_file_size,
                                    hint="raise crawler.max_file_size in --config to scan this asset",
                                )
                                return None
                        except ValueError:
                            pass

                    chunks: list[bytes] = []
                    downloaded = 0
                    if hasattr(response, "aiter_bytes"):
                        async for chunk in response.aiter_bytes():
                            downloaded += len(chunk)
                            if downloaded > self.config.crawler.max_file_size:
                                logger.warning(
                                    "file_too_large",
                                    url=current_url[:100],
                                    limit_bytes=self.config.crawler.max_file_size,
                                    hint="raise crawler.max_file_size in --config to scan this asset",
                                )
                                return None
                            chunks.append(chunk)
                    else:
                        chunk = await response.aread()
                        if len(chunk) > self.config.crawler.max_file_size:
                            return None
                        chunks.append(chunk)
                    content = b"".join(chunks)
                    response_status = response.status_code
                    # Persist only analysis-relevant, non-credential response headers.
                    safe_header_names = {
                        "content-type",
                        "content-length",
                        "cache-control",
                        "etag",
                        "last-modified",
                    }
                    response_headers = {
                        name.lower(): value
                        for name, value in response.headers.items()
                        if name.lower() in safe_header_names
                    }
                    break

            # DQ-I05: if a JS-reference URL actually returned an HTML document (auth wall / login /
            # error page served with 200), strip its URL-bearing markup attributes (href/action/src)
            # before analysis so they are not mis-detected as API endpoints -- while KEEPING all
            # other content so embedded secrets (inline JS, __NEXT_DATA__ JSON, meta/data attrs) are
            # still scanned (INV-02). The helper body-sniffs and no-ops on real JS (even when
            # mislabeled text/html). The size LIMIT above applies to the full downloaded bytes.
            # Run off the event loop (like the SSRF check / beautify): BeautifulSoup parsing of a
            # large HTML body + the secret-guard regex scan must not block the whole crawl.
            content = await asyncio.to_thread(
                self._sanitize_html_document_for_analysis,
                content, response_headers.get("content-type", ""),
            )

            asset = JSAsset(
                url=current_url,
                content=content,
                size=len(content),
                initiator=ref.initiator,
                load_context=ref.load_context,
                load_method=ref.method,
                is_first_party=self.scope.is_first_party(current_url),
                headers=response_headers,
                status_code=response_status,
                etag=response_headers.get("etag"),
                last_modified=response_headers.get("last-modified"),
                provenance=self._provenance_entries_from_ref(ref),
            )
            asset.compute_hash()

            return asset

        except httpx.HTTPStatusError:
            raise  # Let download_one handle rate-limit logic
        except Exception as e:
            # A network error (timeout / connection reset / DNS blip) is TRANSIENT -- re-raise so
            # download_one marks the URL non-terminal and --resume retries it, rather than treating
            # None (a permanent policy skip) and this case identically and permanently skipping it.
            logger.debug("download_error", url=ref.url[:100], error=str(e))
            raise

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int] | None:
        return normalized_origin(url)

    def _origin_bound_auth_headers(self, request_url: str) -> dict[str, str]:
        """Return credentials only for an exact configured seed origin.

        Every custom auth header is treated as sensitive. A redirect to another host, scheme, or
        port therefore receives neither custom headers nor the configured cookie jar.
        """
        allowed_origins = {item for item in (self._origin(url) for url in self._seed_urls) if item}
        return origin_bound_auth_headers(
            request_url,
            allowed_origins,
            self.config.auth.get_auth_headers(),
            self.config.auth.cookies,
        )

    async def _stage_normalize(
        self,
        assets: list[JSAsset],
        processed_hashes: set[str] | None = None,
    ) -> None:
        """Normalize JS content."""
        self.progress.start_stage(PipelineStage.NORMALIZE, len(assets))
        processed = set(processed_hashes or [])

        sourcemap_resolver = SourceMapResolver(
            timeout=self.config.crawler.request_timeout,
            allow_private_ips=self.config.scope.allow_private_ips,
            rate_limiter=self.rate_limiter,
            headers_for_url=self._origin_bound_auth_headers,
            is_allowed=self.scope.is_allowed,
            max_retries=self.config.crawler.max_retries,
            retry_delay=self.config.crawler.retry_delay,
        )
        await sourcemap_resolver.setup()

        try:
            total_assets = len(assets)
            for index, asset in enumerate(assets, 1):
                if asset.content_hash in processed:
                    self.progress.set_detail(
                        self._format_normalize_detail(index, total_assets, asset.url, "skipped")
                    )
                    self.progress.update(1)
                    continue
                # Beautify
                original_hash = asset.content_hash or self.dedup.compute_hash(asset.content)
                content = decode_js_bytes(asset.content)
                skip_reason = self._beautify_skip_reason(asset.content)
                if skip_reason:
                    skip_detail = self._format_normalize_detail(
                        index,
                        total_assets,
                        asset.url,
                        f"beautify skipped ({skip_reason})",
                    )
                    self.progress.set_detail(skip_detail)
                    logger.info(
                        "beautify_skipped",
                        url=asset.url[:160],
                        size_bytes=len(asset.content),
                        max_bytes=self.config.parser.beautify_max_bytes,
                        reason=skip_reason,
                    )
                    result = self._identity_normalization_result(content)
                else:
                    beautify_detail = self._format_normalize_detail(
                        index,
                        total_assets,
                        asset.url,
                        "beautify",
                    )
                    self.progress.set_detail(beautify_detail)
                    result = await self._await_with_stage_heartbeat(
                        asyncio.to_thread(self.beautifier.beautify, content),
                        stage=PipelineStage.NORMALIZE,
                        detail=beautify_detail,
                        heartbeat_event="normalize_heartbeat",
                        log_fields={
                            "url": asset.url[:160],
                            "operation": "beautify",
                        },
                    )

                if result.success:
                    # Store beautified content for use in parse/analyze stages
                    normalized_content = result.content.encode("utf-8")
                    asset.content = normalized_content
                    content = result.content
                    asset.size = len(normalized_content)
                    asset.content_hash = original_hash
                    asset.normalized_hash = self.dedup.compute_hash(
                        normalized_content
                    )

                self._line_mappers[original_hash] = result.line_mapper

                # Resolve sourcemap
                if self.config.parser.resolve_sourcemaps:
                    sourcemap_detail = self._format_normalize_detail(
                        index,
                        total_assets,
                        asset.url,
                        "sourcemap check",
                    )
                    self.progress.set_detail(sourcemap_detail)
                    resolution_bases = sorted({
                        asset.url,
                        *(entry.url for entry in asset.provenance if entry.url),
                    })
                    if len(resolution_bases) > _MAX_SOURCEMAP_PROVENANCE_BASES:
                        self._add_completeness_issue(
                            code="sourcemap_provenance_bases_truncated",
                            stage=PipelineStage.NORMALIZE.value,
                            message="Source-map resolution exceeded its provenance-base budget",
                            affected_count=(
                                len(resolution_bases) - _MAX_SOURCEMAP_PROVENANCE_BASES
                            ),
                            details={
                                "base_count": len(resolution_bases),
                                "base_cap": _MAX_SOURCEMAP_PROVENANCE_BASES,
                            },
                        )
                        resolution_bases = resolution_bases[:_MAX_SOURCEMAP_PROVENANCE_BASES]
                    resolved_maps: list[SourceMapInfo] = []
                    resolution_failures = []
                    for resolution_base in resolution_bases:
                        candidate_map = await self._await_with_stage_heartbeat(
                            sourcemap_resolver.resolve(content, resolution_base),
                            stage=PipelineStage.NORMALIZE,
                            detail=sourcemap_detail,
                            heartbeat_event="normalize_heartbeat",
                            log_fields={
                                "url": resolution_base[:160],
                                "operation": "sourcemap_check",
                            },
                        )
                        if candidate_map is not None:
                            resolved_maps.append(candidate_map)
                        elif sourcemap_resolver.last_diagnostic.status == "failed":
                            resolution_failures.append(sourcemap_resolver.last_diagnostic)
                    sourcemap = min(
                        resolved_maps,
                        key=lambda item: (
                            item.url or "",
                            hashlib.sha256((item.content or "").encode()).hexdigest(),
                        ),
                        default=None,
                    )
                    if sourcemap is not None:
                        supplemental: dict[str, str] = {}
                        supplemental_bytes = 0
                        supplemental_skipped = 0
                        for candidate_map in resolved_maps:
                            if candidate_map is sourcemap:
                                continue
                            for source_path, source_content in sourcemap_resolver.get_original_sources(
                                candidate_map
                            ).items():
                                key = source_path
                                existing_content = supplemental.get(key)
                                if existing_content is not None and existing_content != source_content:
                                    digest = hashlib.sha256(
                                        source_content.encode("utf-8", "surrogatepass")
                                    ).hexdigest()[:16]
                                    key = f"{source_path}#bundleinspector-source={digest}"
                                if supplemental.get(key) == source_content:
                                    continue
                                source_bytes = len(source_content.encode("utf-8", "surrogatepass"))
                                if (
                                    supplemental_bytes + source_bytes
                                    > _MAX_SUPPLEMENTAL_SOURCE_BYTES
                                ):
                                    supplemental_skipped += 1
                                    continue
                                supplemental[key] = source_content
                                supplemental_bytes += source_bytes
                        sourcemap.supplemental_sources.update(supplemental)
                        if supplemental_skipped:
                            self._add_completeness_issue(
                                code="sourcemap_supplemental_sources_truncated",
                                stage=PipelineStage.NORMALIZE.value,
                                message="Supplemental source-map content exceeded its byte budget",
                                affected_count=supplemental_skipped,
                                details={
                                    "byte_cap": _MAX_SUPPLEMENTAL_SOURCE_BYTES,
                                    "retained_bytes": supplemental_bytes,
                                },
                            )
                    if sourcemap:
                        self.progress.set_detail(
                            self._format_normalize_detail(
                                index,
                                total_assets,
                                asset.url,
                                "sourcemap found",
                            )
                        )
                        asset.has_sourcemap = True
                        asset.sourcemap_url = sourcemap.url
                        if sourcemap.content:
                            asset.sourcemap_content = sourcemap.content.encode("utf-8")
                            asset.sourcemap_hash = await self._artifact_store.store_sourcemap(
                                asset.sourcemap_content,
                                original_hash,
                            ) if self._artifact_store else None
                        self._sourcemaps[original_hash] = sourcemap
                        if sourcemap.diagnostics:
                            self._add_completeness_issue(
                                code="sourcemap_mapping_truncated",
                                stage=PipelineStage.NORMALIZE.value,
                                message="A source map contained mappings beyond the decode budget",
                                affected_count=1,
                                details={"diagnostics": sorted(set(sourcemap.diagnostics))},
                            )
                        for reason in sorted({
                            diagnostic.reason or "resolution_failed"
                            for diagnostic in resolution_failures
                        }):
                            failures = [
                                diagnostic
                                for diagnostic in resolution_failures
                                if (diagnostic.reason or "resolution_failed") == reason
                            ]
                            self._add_completeness_issue(
                                code="sourcemap_provenance_resolution_failed",
                                stage=PipelineStage.NORMALIZE.value,
                                message=(
                                    "A source map could not be resolved from every content "
                                    f"provenance base ({reason})"
                                ),
                                retryable=reason in {
                                    "client_unavailable", "fetch_error", "http_status"
                                },
                                affected_count=len(failures),
                                details={
                                    "reason": reason,
                                    "references": sorted({
                                        diagnostic.reference
                                        for diagnostic in failures
                                        if diagnostic.reference
                                    })[:8],
                                },
                            )
                    else:
                        diagnostic = (
                            resolution_failures[0]
                            if resolution_failures
                            else sourcemap_resolver.last_diagnostic
                        )
                        if diagnostic.status == "failed":
                            reason = diagnostic.reason or "resolution_failed"
                            details: dict[str, Any] = {
                                "reason": reason,
                                "discovered": diagnostic.discovered,
                            }
                            if diagnostic.reference:
                                details["reference"] = diagnostic.reference
                            if diagnostic.http_status is not None:
                                details["http_status"] = diagnostic.http_status
                            self._add_completeness_issue(
                                code="sourcemap_resolution_failed",
                                stage=PipelineStage.NORMALIZE.value,
                                message=(
                                    "A source map was discovered but could not be resolved "
                                    f"({reason})"
                                ),
                                retryable=reason
                                in {"client_unavailable", "fetch_error", "http_status"},
                                affected_count=1,
                                details=details,
                            )
                        self.progress.set_detail(
                            self._format_normalize_detail(
                                index,
                                total_assets,
                                asset.url,
                                (
                                    "sourcemap unresolved"
                                    if diagnostic.status == "failed"
                                    else "no sourcemap"
                                ),
                            )
                        )

                await self._persist_asset(asset)
                self.progress.set_detail(
                    self._format_normalize_detail(index, total_assets, asset.url, "saved")
                )

                processed.add(original_hash)
                await self._store_checkpoint(
                    PipelineStage.DOWNLOAD,
                    self._seed_urls,
                    assets=assets,
                    stage_state={
                        "normalize_complete_hashes": sorted(processed),
                    },
                )
                self.progress.update(1)

        finally:
            await sourcemap_resolver.teardown()

        self.progress.complete_stage()
        logger.info("normalize_complete")

    def _summarize_asset_url(self, asset_url: str) -> str:
        """Return a compact host/path label for progress output."""
        parsed = urlparse(asset_url)
        host = parsed.netloc
        path = parsed.path or ""
        if host and path:
            label = f"{host}{path}"
        elif host:
            label = host
        elif path:
            label = path
        else:
            label = asset_url

        if len(label) > 90:
            return f"...{label[-87:]}"
        return label

    def _format_normalize_detail(
        self,
        index: int,
        total: int,
        asset_url: str,
        operation: str,
    ) -> str:
        """Build a concise progress detail for normalize-stage asset work."""
        label = self._summarize_asset_url(asset_url)
        return f"{index}/{max(total, 1)} {label} · {operation}"

    def _beautify_skip_reason(self, content: bytes) -> str:
        """Return the configured reason to use identity normalization, if any."""
        if not self.config.parser.beautify:
            return "disabled"
        limit = max(int(self.config.parser.beautify_max_bytes), 0)
        return "size limit" if limit > 0 and len(content) > limit else ""

    def _should_skip_beautify(self, content: bytes) -> bool:
        """Compatibility predicate retained for callers/tests."""
        return bool(self._beautify_skip_reason(content))

    def _identity_normalization_result(self, content: str) -> NormalizationResult:
        """Return a no-op normalization result for already-usable source."""
        from bundleInspector.normalizer.beautify import NormalizationLevel

        return NormalizationResult(
            content=content,
            original_content=content,
            level=NormalizationLevel.NONE,
            line_mapper=LineMapper.identity(content),
            success=True,
            errors=[],
        )

    async def _await_with_stage_heartbeat(
        self,
        awaitable: Coroutine[Any, Any, _T],
        *,
        stage: PipelineStage,
        detail: str,
        heartbeat_event: str,
        log_fields: dict[str, Any] | None = None,
    ) -> _T:
        """Await work while periodically refreshing progress detail for long-running operations."""
        task = asyncio.create_task(awaitable)
        heartbeat_seconds = max(self._normalize_heartbeat_seconds, 0.1)
        started = perf_counter()

        try:
            while True:
                try:
                    return await asyncio.wait_for(asyncio.shield(task), timeout=heartbeat_seconds)
                except asyncio.TimeoutError:
                    elapsed = perf_counter() - started
                    heartbeat_detail = f"{detail} ({elapsed:.0f}s elapsed)"
                    self.progress.set_detail(heartbeat_detail)
                    logger.debug(
                        heartbeat_event,
                        stage=stage.value,
                        elapsed_seconds=round(elapsed, 2),
                        **(log_fields or {}),
                    )
        except BaseException:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            raise

    async def _stage_parse(
        self,
        assets: list[JSAsset],
        processed_hashes: set[str] | None = None,
    ) -> None:
        """Parse JS to AST."""
        self.progress.start_stage(PipelineStage.PARSE, len(assets))
        processed = set(processed_hashes or [])

        for asset in assets:
            if asset.content_hash in processed and asset.content_hash in self._parse_results:
                self.progress.update(1)
                continue
            content = decode_js_bytes(asset.content)
            result = self.parser.parse(content, language_hint=asset.language_hint)
            await self._store_parse_result(asset, result, assets, processed)

        self.progress.complete_stage()
        success_count = sum(1 for a in assets if a.parse_success)
        logger.info("parse_complete", success=success_count, total=len(assets))

    async def _expand_dependency_frontier(
        self,
        js_refs: list[JSReference],
        assets: list[JSAsset],
    ) -> tuple[list[JSReference], list[JSAsset]]:
        """Resolve parsed module imports until no new in-scope URL remains or the global cap fires."""
        known_urls = {ref.url for ref in js_refs}
        max_files = self.config.crawler.max_js_files
        iterations = 0

        while True:
            candidate_paths: dict[str, dict[tuple[str, str, str, str], AssetProvenance]] = {}
            for asset in sorted(assets, key=lambda item: (item.url, item.content_hash)):
                parse_result = self._parse_results.get(asset.content_hash)
                if not parse_result or not parse_result.ast:
                    continue
                try:
                    ir = self.ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
                except Exception as exc:
                    self._add_completeness_issue(
                        code="dependency_frontier_ir_failed",
                        stage=PipelineStage.PARSE.value,
                        message="An asset could not contribute imports to the dependency frontier",
                        affected_count=1,
                        details={"error": type(exc).__name__},
                    )
                    continue
                resolution_bases = sorted({
                    asset.url,
                    *(entry.url for entry in asset.provenance if entry.url),
                })
                for declaration in ir.imports:
                    source = declaration.source.strip()
                    if not source or source.startswith(("data:", "blob:", "node:")):
                        continue
                    if not source.startswith((".", "/", "http://", "https://")):
                        continue
                    for base_url in resolution_bases:
                        resolved = urljoin(base_url, source)
                        if resolved in known_urls or not self.scope.is_allowed(resolved):
                            continue
                        path = AssetProvenance(
                            url=resolved,
                            initiator=base_url,
                            load_context=asset.load_context or base_url,
                            method=LoadMethod.DYNAMIC_IMPORT,
                        )
                        key = (path.url, path.initiator, path.load_context, path.method.value)
                        candidate_paths.setdefault(resolved, {})[key] = path

            ordered: list[JSReference] = []
            for resolved in sorted(candidate_paths):
                provenance = [
                    candidate_paths[resolved][key]
                    for key in sorted(candidate_paths[resolved])
                ]
                primary = provenance[0]
                ordered.append(JSReference(
                    url=resolved,
                    initiator=primary.initiator,
                    load_context=primary.load_context,
                    method=primary.method,
                    provenance=provenance,
                ))
            if not ordered:
                break
            remaining = max(0, max_files - len(known_urls))
            if len(ordered) > remaining:
                self._add_completeness_issue(
                    code="dependency_frontier_truncated",
                    stage=PipelineStage.DOWNLOAD.value,
                    message="The global JavaScript cap truncated parsed dependency expansion",
                    affected_count=len(ordered) - remaining,
                    details={"limit": max_files, "discovered": len(known_urls) + len(ordered)},
                )
                ordered = ordered[:remaining]
            if not ordered:
                break

            js_refs.extend(ordered)
            known_urls.update(ref.url for ref in ordered)
            previous_hashes = {asset.content_hash for asset in assets}
            completed_urls = set(self._download_stage_state.get("download_complete_urls", []))
            assets = await self._stage_download(js_refs, assets, completed_urls)
            new_assets = [asset for asset in assets if asset.content_hash not in previous_hashes]
            if new_assets:
                await self._stage_normalize(new_assets)
                await self._stage_parse(new_assets)
            await self._store_checkpoint(
                PipelineStage.PARSE,
                self._seed_urls,
                js_refs=js_refs,
                assets=assets,
                stage_state={
                    "dependency_frontier_iterations": iterations + 1,
                    "dependency_frontier_urls": sorted(known_urls),
                },
            )
            iterations += 1
            if iterations > max_files:
                self._add_completeness_issue(
                    code="dependency_frontier_guard",
                    stage=PipelineStage.PARSE.value,
                    message="Dependency expansion stopped at its deterministic iteration guard",
                    affected_count=1,
                )
                break

        return js_refs, assets

    async def _store_parse_result(
        self,
        asset: JSAsset,
        result: ParseResult,
        assets: list[JSAsset],
        processed: set[str],
    ) -> None:
        """Record a parse result + persist AST + checkpoint (serial, order-preserving)."""
        asset.parse_success = result.success
        asset.parse_errors = result.errors
        if not result.success or result.partial:
            self._add_completeness_issue(
                code="parse_incomplete",
                stage=PipelineStage.PARSE.value,
                message="A JavaScript asset could not be fully parsed",
                affected_count=1,
                details={"partial": bool(result.partial)},
            )

        if result.success and result.ast:
            asset.ast_hash = self.dedup.compute_hash(
                json.dumps(result.ast, separators=(",", ":"), sort_keys=True).encode()
            )[:16]
            # Store parse result for reuse in analyze stage
            self._parse_results[asset.content_hash] = result
            await self._persist_ast(asset.content_hash, result.ast)

        if result.success and result.ast:
            processed.add(asset.content_hash)
        else:
            # A failed parse must never be checkpointed as completed. Resume from the normalized
            # source and retry it rather than reusing a false-complete empty analysis.
            self._retry_barriers.add(PipelineStage.NORMALIZE.value)
        await self._store_checkpoint(
            PipelineStage.NORMALIZE,
            self._seed_urls,
            assets=assets,
            stage_state={
                "parse_complete_hashes": sorted(processed),
            },
        )
        self.progress.update(1)

    async def _stage_analyze(
        self,
        assets: list[JSAsset],
        existing_findings: list[Finding] | None = None,
        processed_hashes: set[str] | None = None,
    ) -> list[Finding]:
        """Run detection rules."""
        self.progress.start_stage(PipelineStage.ANALYZE, len(assets))

        # Register default rules
        self.rule_engine.register_defaults()

        findings: list[Finding] = list(existing_findings or [])
        processed = set(processed_hashes or [])

        workers = _parallel_workers()
        to_analyze = [a for a in assets if a.content_hash not in processed]
        # >= 1 (not > 1): in parallel mode _stage_parse deferred parsing, so a lone asset
        # would fall into the serial loop below and be skipped (parse_success is False,
        # _parse_results empty) -- silently dropping all of its findings.
        if workers > 1 and len(to_analyze) >= 1:
            # Fused parallel parse+analyze: each worker parses its asset and runs the full
            # per-asset pipeline, returning only the small findings list (the AST stays inside
            # the worker). Results are reassembled in asset order, so the aggregate findings
            # list -- and therefore the correlation graph -- is byte-identical to serial.
            skipped = len(assets) - len(to_analyze)
            if skipped:
                self.progress.update(skipped)
            payloads = [
                (
                    idx,
                    asset,
                    self._line_mappers.get(asset.content_hash),
                    self._sourcemaps.get(asset.content_hash),
                    self.config,
                )
                for idx, asset in enumerate(to_analyze)
            ]
            loop = asyncio.get_running_loop()
            pool = ProcessPoolExecutor(
                max_workers=workers,
                initializer=init_worker,
                initargs=(self.config,),
            )
            futures = [
                    loop.run_in_executor(pool, analyze_asset_task_with_telemetry, payload)
                    for payload in payloads
                ]
            pool_completed = False
            try:
                timeout = self.config.parser.analysis_worker_timeout
                done, pending = await asyncio.wait(futures, timeout=timeout)
                results: list[_AssetAnalysisResult | BaseException] = []
                for future in futures:
                    if future in pending:
                        future.cancel()
                        results.append(TimeoutError(
                            f"parallel analysis exceeded {timeout:.3f}s"
                        ))
                        continue
                    try:
                        results.append(future.result())
                    except BaseException as exc:
                        results.append(exc)
                pool_completed = not pending
            finally:
                if pool_completed:
                    pool.shutdown(wait=True, cancel_futures=True)
                else:
                    await asyncio.to_thread(_terminate_process_pool, pool)
            # A worker that dies (OOM/segfault -> BrokenProcessPool) must not wipe the
            # whole batch's findings. Re-run any failed payload serially in-process so
            # its findings are still recovered; a genuine per-asset failure yields an
            # empty result and is logged -- never a silent whole-batch loss + crash.
            recovered: list[_AssetAnalysisResult] = []
            for payload, res in zip(payloads, results, strict=True):
                if isinstance(res, BaseException):
                    url = payload[1].url[:120]
                    logger.warning("parallel_worker_failed", url=url, error=str(res))
                    if isinstance(res, TimeoutError):
                        self._add_completeness_issue(
                            code="parallel_worker_timeout",
                            stage=PipelineStage.ANALYZE.value,
                            message="Parallel asset analysis exceeded its configured worker timeout",
                            affected_count=1,
                            details={
                                "timeout_seconds": self.config.parser.analysis_worker_timeout,
                            },
                        )
                    try:
                        res = analyze_asset_task_with_telemetry(payload)
                    except Exception as e:
                        logger.warning("serial_fallback_failed", url=url, error=str(e))
                        res = (payload[0], False, [f"analyze failed: {e}"], None, [], [])
                recovered.append(res)
            for (
                idx,
                parse_success,
                parse_errors,
                ast_hash,
                worker_findings,
                incomplete_events,
            ) in sorted(
                recovered, key=lambda item: item[0]
            ):
                asset = to_analyze[idx]
                asset.parse_success = parse_success
                asset.parse_errors = parse_errors
                if not parse_success or parse_errors:
                    self._add_completeness_issue(
                        code="asset_analysis_incomplete",
                        stage=PipelineStage.ANALYZE.value,
                        message="A JavaScript asset was not fully analyzed",
                        affected_count=1,
                    )
                if ast_hash:
                    asset.ast_hash = ast_hash
                findings.extend(worker_findings)
                self._promote_analysis_events(incomplete_events)
                processed.add(asset.content_hash)
                self.progress.update(1)
            await self._store_checkpoint(
                PipelineStage.PARSE,
                self._seed_urls,
                assets=assets,
                findings=findings,
                stage_state={
                    "analyze_complete_hashes": sorted(processed),
                },
            )
            self._parse_results.clear()
            self.progress.complete_stage()
            self._findings = findings
            logger.info("analyze_complete", findings=len(findings), parallel=workers)
            return findings

        for asset in assets:
            if asset.content_hash in processed:
                self.progress.update(1)
                continue
            if not asset.parse_success:
                processed.add(asset.content_hash)
                await self._store_checkpoint(
                    PipelineStage.PARSE,
                    self._seed_urls,
                    assets=assets,
                    findings=findings,
                    stage_state={
                        "analyze_complete_hashes": sorted(processed),
                    },
                )
                self.progress.update(1)
                continue

            # Reuse parse result from _stage_parse instead of re-parsing
            parse_result = self._parse_results.get(asset.content_hash)
            if not parse_result or not parse_result.ast:
                processed.add(asset.content_hash)
                await self._store_checkpoint(
                    PipelineStage.PARSE,
                    self._seed_urls,
                    assets=assets,
                    findings=findings,
                    stage_state={
                        "analyze_complete_hashes": sorted(processed),
                    },
                )
                self.progress.update(1)
                continue

            content = decode_js_bytes(asset.content)

            asset_findings: list[Finding] = []
            ir = None
            try:
                # Build IR + run rules. A failure here (e.g. a RecursionError from a deep
                # AST) must not abort the whole scan -- other assets' findings must survive.
                ir = self.ir_builder.build(
                    parse_result.ast,
                    asset.url,
                    asset.content_hash,
                )
                if getattr(ir, "partial", False) and ir.errors:
                    asset.parse_errors = list(asset.parse_errors or []) + [
                        error for error in ir.errors if error not in (asset.parse_errors or [])
                    ]
                    self._promote_analysis_events([_ir_incomplete_event()])
                context = AnalysisContext(
                    file_url=asset.url,
                    file_hash=asset.content_hash,
                    source_content=content,
                    is_first_party=asset.is_first_party,
                )
                asset_findings = self.rule_engine.analyze(ir, context)
                self._promote_analysis_events(context.metadata.get("analysis_incomplete", []))
            except Exception as e:
                logger.warning("asset_analyze_error", url=asset.url[:120], error=str(e))
                asset.parse_errors = list(asset.parse_errors or []) + [f"analyze failed: {e}"]
                self._add_completeness_issue(
                    code="asset_analysis_failed",
                    stage=PipelineStage.ANALYZE.value,
                    message="A JavaScript asset failed during rule analysis",
                    affected_count=1,
                )
            # Secure findings BEFORE enrichment (matches the parallel/local paths): an
            # annotate/line-map failure must degrade metadata, never discard the findings
            # already produced for this asset.
            findings.extend(asset_findings)
            if ir is not None:
                try:
                    self._annotate_finding_metadata(asset, ir, asset_findings)
                    self._apply_artifact_mappings(asset, asset_findings)
                except Exception as e:
                    logger.warning(
                        "finding_enrichment_error",
                        url=asset.url[:120],
                        exception_type=type(e).__name__,
                    )
                    enrichment_event = _asset_enrichment_event()
                    self._promote_analysis_events([enrichment_event])
                    summary = _virtual_event_summary(enrichment_event)
                    if summary and summary not in asset.parse_errors:
                        asset.parse_errors.append(summary)
            if ir is not None and getattr(ir, "partial", False):
                late_ir_errors = [
                    error
                    for error in (getattr(ir, "errors", ()) or ())
                    if error not in asset.parse_errors
                ]
                if late_ir_errors:
                    asset.parse_errors.extend(late_ir_errors)
                self._promote_analysis_events([_ir_incomplete_event()])
            # DQ-P08: the serial loop inlines analysis and does NOT call analyze_asset_standalone,
            # so it needs its own hook to analyze the sourcemap's sourcesContent as virtual sources
            # (the parallel path gets this inside analyze_asset_standalone). Deduped vs asset_findings.
            virtual_events: list[dict[str, Any]] = []
            virtual_findings = self._analyzer._analyze_virtual_sources(
                self._sourcemaps.get(asset.content_hash),
                asset.is_first_party,
                asset_findings,
                incomplete_events=virtual_events,
            )
            self._promote_analysis_events(virtual_events)
            for event in virtual_events:
                summary = _virtual_event_summary(event)
                if summary and summary not in asset.parse_errors:
                    asset.parse_errors.append(summary)
            if virtual_findings:
                findings.extend(virtual_findings)
            if not asset.parse_success or asset.parse_errors:
                self._add_completeness_issue(
                    code="asset_analysis_incomplete",
                    stage=PipelineStage.ANALYZE.value,
                    message="A JavaScript asset was not fully analyzed",
                    affected_count=1,
                )

            processed.add(asset.content_hash)
            await self._store_checkpoint(
                PipelineStage.PARSE,
                self._seed_urls,
                assets=assets,
                findings=findings,
                stage_state={
                    "analyze_complete_hashes": sorted(processed),
                },
            )
            self.progress.update(1)

        # Free parse results to release memory
        self._parse_results.clear()

        self.progress.complete_stage()
        self._findings = findings
        logger.info("analyze_complete", findings=len(findings))

        return findings

    def _apply_artifact_mappings(
        self,
        asset: JSAsset,
        findings: list[Finding],
    ) -> None:
        """Apply beautify and source map position data to findings."""
        self._apply_mappings(
            findings,
            self._line_mappers.get(asset.content_hash),
            self._sourcemaps.get(asset.content_hash),
        )

    def _apply_mappings(
        self,
        findings: list[Finding],
        line_mapper: LineMapper | None,
        sourcemap: SourceMapInfo | None,
    ) -> None:
        """Delegate to the light AssetAnalyzer (kept for serial path + test callers)."""
        return self._analyzer._apply_mappings(findings, line_mapper, sourcemap)

    def analyze_asset_standalone(
        self,
        asset: JSAsset,
        line_mapper: LineMapper | None,
        sourcemap: SourceMapInfo | None,
    ) -> list[Finding]:
        """Delegate full per-asset analysis to the light AssetAnalyzer."""
        return self._analyzer.analyze_asset_standalone(asset, line_mapper, sourcemap)

    def _annotate_finding_metadata(
        self,
        asset: JSAsset,
        ir: IntermediateRepresentation,
        findings: list[Finding],
    ) -> None:
        """Delegate IR/runtime metadata annotation to the light AssetAnalyzer."""
        return self._analyzer._annotate_finding_metadata(asset, ir, findings)

    async def _stage_correlate(self, findings: list[Finding]) -> CorrelationGraph:
        """Build correlation graph."""
        self.progress.start_stage(PipelineStage.CORRELATE, 1)

        # enh2: flag endpoints declared in JS but never called during the crawl (hidden
        # AJAX-reachable surface). Runs before classify so severity bumps are scored. No-op
        # when no runtime baseline was captured (headless off / nothing observed).
        try:
            from bundleInspector.correlator.dormant import annotate_dormant_endpoints

            # First-party origins: a *relative* declared endpoint resolves against the
            # app's own origin, so it is only "exercised" if that path was observed on a
            # first-party host -- not on some third-party/CDN host that happened to share
            # the path (which would wrongly hide a real same-origin dormant endpoint).
            primary_hosts = {
                urlparse(u).netloc.lower()
                for u in self._seed_urls
                if urlparse(u).netloc
            }
            dormant_n = annotate_dormant_endpoints(
                findings, self._observed_requests, self.config.rules,
                primary_hosts=primary_hosts,
            )
            if dormant_n:
                logger.info(
                    "dormant_endpoints_flagged",
                    count=dormant_n,
                    observed=len(self._observed_requests),
                )
        except Exception as e:
            logger.warning("dormant_endpoint_error", error=str(e))

        # enh7: surface endpoints the app CALLED at runtime but static analysis missed
        # (complement of dormant). Additive + first-party scoped; no-op without a baseline.
        try:
            from bundleInspector.correlator.runtime_surface import surface_runtime_endpoints

            primary_hosts = {
                urlparse(u).netloc.lower()
                for u in self._seed_urls
                if urlparse(u).netloc
            }
            surfaced_n = surface_runtime_endpoints(
                findings,
                self._observed_requests,
                self._observed_websockets,
                self.config.rules,
                primary_hosts=primary_hosts,
            )
            if surfaced_n:
                logger.info("runtime_endpoints_surfaced", count=surfaced_n)
        except Exception as e:
            logger.warning("runtime_surface_error", error=str(e))

        graph = self.correlator.correlate(findings)
        capped_passes = graph.telemetry.get("capped_passes", {})
        if isinstance(capped_passes, dict) and capped_passes:
            self._add_completeness_issue(
                code="correlation_graph_truncated",
                stage=PipelineStage.CORRELATE.value,
                message="Correlation analysis reached one or more deterministic graph caps",
                affected_count=int(graph.telemetry.get("truncated_candidates_lower_bound", 0)),
                details={
                    "capped_passes": dict(sorted(capped_passes.items())),
                    "truncated_candidates": int(
                        graph.telemetry.get("truncated_candidates", 0)
                    ),
                    "truncated_candidates_lower_bound": int(
                        graph.telemetry.get("truncated_candidates_lower_bound", 0)
                    ),
                    "truncated_candidates_unknown": int(
                        graph.telemetry.get("truncated_candidates_unknown", 0)
                    ),
                },
            )

        self.progress.update(1)
        self.progress.complete_stage()
        logger.info(
            "correlate_complete",
            edges=len(graph.edges),
            clusters=len(graph.clusters),
        )

        return graph

    async def _stage_classify(
        self,
        findings: list[Finding],
        graph: CorrelationGraph,
    ) -> None:
        """Classify risk levels."""
        self.progress.start_stage(PipelineStage.CLASSIFY, len(findings))

        for finding in findings:
            self.classifier.classify(finding, graph)
            self.progress.update(1)

        self.progress.complete_stage()
        logger.info("classify_complete")

    async def _stage_report(
        self,
        seed_urls: list[str],
        assets: list[JSAsset],
        findings: list[Finding],
        graph: CorrelationGraph,
    ) -> Report:
        """Generate report."""
        self.progress.start_stage(PipelineStage.REPORT, 1)
        completeness = self._build_completeness()
        issue_warnings = [issue.message for issue in completeness.issues]

        report = Report(
            job_id=self.job_id,
            seed_urls=seed_urls,
            config=embed_report_resume_signature(
                self.config.to_report_dict(),
                self._resume_signature,
            ),
            assets=assets,
            findings=findings,
            correlations=graph.to_correlations(),
            clusters=graph.clusters,
            completed_at=datetime.now(timezone.utc),
            duration_seconds=self.progress.duration,
            # DQ-C06: transient crawl-phase failures that were not frozen as complete -- surface the
            # lost coverage rather than reporting a silent, apparently-finished 0-result.
            warnings=list(dict.fromkeys([*self._crawl_warnings, *issue_warnings])),
            completeness=completeness,
        )

        report.compute_summary()
        await self._persist_report(report)

        self.progress.update(1)
        self.progress.complete_stage()

        return report

    async def _persist_asset(self, asset: JSAsset) -> None:
        """Persist normalized asset content and metadata when storage is enabled."""
        if not self._artifact_store:
            return

        try:
            await self._artifact_store.store_js(asset.content, asset.url)
            if asset.sourcemap_content:
                asset.sourcemap_hash = asset.sourcemap_hash or await self._artifact_store.store_sourcemap(
                    asset.sourcemap_content,
                    asset.content_hash,
                )
            await self._artifact_store.store_asset_meta(asset)
        except (AtomicCommitError, UnsafePathError):
            raise
        except Exception as e:
            logger.warning("asset_store_error", url=asset.url[:100], error=str(e))

    async def _persist_ast(self, content_hash: str, ast: dict[str, Any]) -> None:
        """Persist parsed AST when storage is enabled."""
        if not self._artifact_store:
            return

        try:
            await self._artifact_store.store_ast(ast, content_hash)
        except (AtomicCommitError, UnsafePathError):
            raise
        except Exception as e:
            logger.warning("ast_store_error", content_hash=content_hash[:16], error=str(e))

    async def _persist_report(self, report: Report) -> None:
        """Persist findings and final report when storage is enabled."""
        if not self._finding_store:
            return

        try:
            for finding in report.findings:
                await self._finding_store.store_finding(finding)
            await self._finding_store.store_report(report)
        except (AtomicCommitError, UnsafePathError):
            raise
        except Exception as e:
            logger.warning("report_store_error", report_id=report.id, error=str(e))


class BundleInspector:
    """
    Main BundleInspector class - high-level API.
    """

    def __init__(
        self,
        config: Config | None = None,
        on_stage_start: Callable[[PipelineStage], None] | None = None,
        on_stage_complete: Callable[[PipelineStage, StageProgress], None] | None = None,
        on_progress: Callable[[PipelineStage, int, int], None] | None = None,
        on_stage_detail: Callable[[PipelineStage, str], None] | None = None,
        on_resume: Callable[[Report], None] | None = None,
    ) -> None:
        self.config = config or Config()
        self._on_stage_start = on_stage_start
        self._on_stage_complete = on_stage_complete
        self._on_progress = on_progress
        self._on_stage_detail = on_stage_detail
        self._on_resume = on_resume

    async def scan(self, urls: list[str]) -> Report:
        """
        Scan URLs for JS security findings.

        Args:
            urls: URLs to scan

        Returns:
            Report with findings
        """
        # Ensure directories exist
        self.config.ensure_dirs()

        # Resume from the latest stored report when requested
        resumed_report = await self._try_resume_report(urls)
        if resumed_report is not None:
            if self._on_resume:
                self._on_resume(resumed_report)
            return resumed_report

        # Run orchestrator
        orchestrator = Orchestrator(self.config)

        # Attach progress callbacks
        if self._on_stage_start:
            orchestrator.progress.on_stage_start = self._on_stage_start
        if self._on_stage_complete:
            orchestrator.progress.on_stage_complete = self._on_stage_complete
        if self._on_progress:
            orchestrator.progress.on_progress = self._on_progress
        if self._on_stage_detail:
            orchestrator.progress.on_stage_detail = self._on_stage_detail

        return await orchestrator.run(urls)

    async def _try_resume_report(self, urls: list[str]) -> Report | None:
        """Load the latest stored report for the configured job when resuming."""
        job_id = self.config.job_id
        if not self.config.resume or not job_id:
            return None

        try:
            repository = JobRepository(self.config.cache_dir)
            job_root, owned = repository.prepare_job(
                job_id,
                "local",
                create=False,
                allow_legacy=True,
            )
            if job_root is None:
                return None
            if owned:
                report = await repository.get_report(job_id, "local")
            else:
                report = await FindingStore(job_root).get_latest_report()
            if report_matches_resume_signature(
                report,
                expected_job_id=job_id,
                seed_urls=urls,
                expected_signature=build_remote_resume_signature(self.config),
            ):
                return report
            return None
        except (AtomicCommitError, JobAccessError, UnsafePathError):
            raise
        except Exception as e:
            logger.warning(
                "resume_report_load_error",
                job_id=job_id,
                error=str(e),
            )
            return None

    @classmethod
    async def quick_scan(cls, url: str) -> Report:
        """
        Quick scan a single URL with default settings.

        Args:
            url: URL to scan

        Returns:
            Report with findings
        """
        finder = cls()
        return await finder.scan([url])
