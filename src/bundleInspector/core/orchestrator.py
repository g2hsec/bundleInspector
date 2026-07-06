"""
Pipeline orchestrator - main entry point.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx
import structlog

from bundleInspector.classifier.risk_model import RiskClassifier
from bundleInspector.collector.headless import HeadlessCollector, HeadlessMultiPageCollector
from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.static import StaticCollector, MultiPageStaticCollector
from bundleInspector.config import Config
from bundleInspector.core.asset_analysis import analyze_asset_task, init_worker
from bundleInspector.core.asset_analyzer import AssetAnalyzer
from bundleInspector.core.dedup import DedupCache
from bundleInspector.core.progress import PipelineStage, ProgressTracker
from bundleInspector.core.rate_limiter import AdaptiveRateLimiter
from bundleInspector.core.text_decode import decode_js_bytes
from bundleInspector.core.resume_policy import (
    build_remote_resume_signature,
    build_stage_state_with_resume_signature,
    checkpoint_matches_resume_signature,
    embed_report_resume_signature,
    report_matches_resume_signature,
)
from bundleInspector.core.security import is_url_safe
from bundleInspector.correlator.graph import Correlator
from bundleInspector.normalizer.beautify import Beautifier
from bundleInspector.normalizer.line_mapping import LineMapper
from bundleInspector.normalizer.sourcemap import SourceMapInfo, SourceMapResolver
from bundleInspector.parser.export_scopes import (
    build_commonjs_default_object_export_members,
    build_commonjs_export_metadata,
    build_commonjs_named_object_export_members,
    build_commonjs_require_bindings,
    build_commonjs_re_export_bindings,
    build_default_object_export_members,
    build_export_scope_map,
    build_named_object_export_members,
    build_re_export_bindings,
)
from bundleInspector.parser.ir_builder import IRBuilder
from bundleInspector.parser.js_parser import JSParser, ParseResult
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.artifact_store import ArtifactStore
from bundleInspector.storage.finding_store import FindingStore
from bundleInspector.storage.models import (
    Finding,
    JSAsset,
    JSReference,
    PipelineCheckpoint,
    Report,
)


logger = structlog.get_logger()


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
        self.parser = JSParser(tolerant=config.parser.tolerant)
        self.ir_builder = IRBuilder()
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

    def _init_storage(self) -> None:
        """Initialize persistent stores for the current job."""
        try:
            job_root = self.config.cache_dir / self.job_id
            self._artifact_store = ArtifactStore(job_root / "artifacts")
            self._finding_store = FindingStore(job_root)
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
                await self._store_checkpoint(PipelineStage.CRAWL, seed_urls, js_refs=js_refs)

            # Stage 2: Download
            if checkpoint and self._stage_at_least(checkpoint.stage, PipelineStage.DOWNLOAD):
                assets = await self._restore_assets(checkpoint.asset_hashes)
            else:
                partial_assets = await self._restore_assets(checkpoint.asset_hashes) if checkpoint else []
                downloaded_urls = set((checkpoint.stage_state or {}).get("download_complete_urls", [])) if checkpoint else set()
                assets = await self._stage_download(js_refs, partial_assets, downloaded_urls)
                await self._store_checkpoint(PipelineStage.DOWNLOAD, seed_urls, js_refs=js_refs, assets=assets)

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

    async def _load_checkpoint(self, seed_urls: list[str]) -> Optional[PipelineCheckpoint]:
        """Load a pipeline checkpoint for the current job when resuming."""
        if not self.config.resume or not self._finding_store:
            return None

        try:
            checkpoint = await self._finding_store.get_checkpoint()
        except Exception as e:
            logger.warning("checkpoint_load_error", job_id=self.job_id, error=str(e))
            return None

        if checkpoint_matches_resume_signature(
            checkpoint,
            seed_urls=seed_urls,
            expected_signature=self._resume_signature,
        ):
            return checkpoint
        return None

    async def _store_checkpoint(
        self,
        stage: PipelineStage | str,
        seed_urls: list[str],
        js_refs: Optional[list[JSReference]] = None,
        assets: Optional[list[JSAsset]] = None,
        findings: Optional[list[Finding]] = None,
        stage_state: Optional[dict[str, Any]] = None,
    ) -> None:
        """Persist a stage checkpoint for later resume."""
        if not self._finding_store:
            return

        stage_value = stage.value if isinstance(stage, PipelineStage) else str(stage)

        checkpoint = PipelineCheckpoint(
            job_id=self.job_id,
            seed_urls=seed_urls,
            stage=stage_value,
            js_refs=js_refs or [],
            asset_hashes=[asset.content_hash for asset in assets or [] if asset.content_hash],
            line_mappers={
                content_hash: mapper.to_dict()
                for content_hash, mapper in self._line_mappers.items()
            },
            sourcemaps={
                content_hash: {
                    "url": sourcemap.url,
                    "content": sourcemap.content,
                    "is_inline": sourcemap.is_inline,
                    "sources": sourcemap.sources,
                    "sources_content": sourcemap.sources_content,
                    "mappings": sourcemap.mappings,
                }
                for content_hash, sourcemap in self._sourcemaps.items()
            },
            findings=findings or [],
            stage_state=build_stage_state_with_resume_signature(
                stage_state,
                self._resume_signature,
            ),
        )

        try:
            await self._finding_store.store_checkpoint(checkpoint)
        except Exception as e:
            logger.warning("checkpoint_store_error", stage=stage_value, error=str(e))

    def _restore_checkpoint_mappings(self, checkpoint: PipelineCheckpoint) -> None:
        """Restore line mappers and source maps from a checkpoint."""
        self._line_mappers = {
            content_hash: LineMapper.from_dict(data)
            for content_hash, data in checkpoint.line_mappers.items()
        }
        self._sourcemaps = {
            content_hash: SourceMapInfo(
                url=data.get("url"),
                content=data.get("content"),
                is_inline=bool(data.get("is_inline")),
                sources=list(data.get("sources", [])),
                sources_content=list(data.get("sources_content", [])),
                mappings=data.get("mappings", ""),
            )
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
        allowed_hashes: Optional[set[str]] = None,
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
        existing_refs: Optional[list[JSReference]] = None,
        completed_seeds: Optional[set[str]] = None,
        completed_seed_phases: Optional[dict[str, set[str]]] = None,
        partial_seed_phase_states: Optional[dict[str, dict[str, dict[str, Any]]]] = None,
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
            ) -> None:
                partial_seed_phases[url] = set(phase_state)
                phase_states.setdefault(url, {}).pop(phase_name, None)
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
            ) -> None:
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=[*js_refs, *accumulated_refs],
                    stage_state=self._build_crawl_stage_state(
                        completed,
                        partial_seed_phases,
                        phase_states,
                        in_progress_seed=url,
                        in_progress_phase=phase_name,
                        in_progress_ref_count=len(accumulated_refs),
                    ),
                )

            async def _page_callback(
                phase_name: str,
                accumulated_refs: list[JSReference],
                phase_progress_state: set[str],
                collector_state: dict[str, Any],
            ) -> None:
                partial_seed_phases[url] = set(phase_progress_state)
                phase_states.setdefault(url, {})[phase_name] = dict(collector_state or {})
                await self._store_checkpoint(
                    "",
                    seed_urls,
                    js_refs=[*js_refs, *accumulated_refs],
                    stage_state=self._build_crawl_stage_state(
                        completed,
                        partial_seed_phases,
                        phase_states,
                        in_progress_seed=url,
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
        logger.info("crawl_complete", js_refs=len(js_refs))

        return js_refs

    def _build_crawl_stage_state(
        self,
        completed_seeds: set[str],
        partial_seed_phases: dict[str, set[str]],
        partial_seed_phase_states: Optional[dict[str, dict[str, dict[str, Any]]]] = None,
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
        completed_phases: Optional[set[str]] = None,
        phase_states: Optional[dict[str, dict[str, Any]]] = None,
        on_phase_complete: Optional[Callable[[str, list[JSReference], set[str]], Any]] = None,
        on_ref_discovered: Optional[Callable[[str, list[JSReference], set[str]], Any]] = None,
        on_page_complete: Optional[Callable[[str, list[JSReference], set[str], dict[str, Any]], Any]] = None,
    ) -> list[JSReference]:
        """Crawl a single URL for JS references."""
        refs: list[JSReference] = []
        completed = set(completed_phases or [])
        phase_state_map = {
            phase_name: dict(state)
            for phase_name, state in (phase_states or {}).items()
            if isinstance(phase_name, str) and isinstance(state, dict)
        }

        is_safe, reason = await asyncio.to_thread(is_url_safe, url, True)
        if not is_safe:
            logger.warning("seed_url_blocked", url=url[:100], reason=reason)
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

        async def _run_phase(phase_name: str, collector_factory) -> None:
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
            completed.add(phase_name)
            if on_phase_complete:
                await on_phase_complete(phase_name, list(refs), set(completed))

        await _run_phase(
            "static",
            lambda: static_cls(self.config.crawler, self.config.auth),
        )

        if self.config.crawler.use_headless:
            try:
                await _run_phase(
                    "headless",
                    lambda: headless_cls(self.config.crawler, self.config.auth),
                )
            except Exception as e:
                logger.warning("headless_error", error=str(e))

        await _run_phase(
            "manifest",
            lambda: ManifestCollector(self.config.crawler, self.config.auth),
        )

        return refs

    async def _stage_download(
        self,
        js_refs: list[JSReference],
        existing_assets: Optional[list[JSAsset]] = None,
        completed_urls: Optional[set[str]] = None,
    ) -> list[JSAsset]:
        """Download JS files with rate limiting and concurrency control."""
        # Enforce max_js_files limit
        max_files = self.config.crawler.max_js_files
        if len(js_refs) > max_files:
            logger.warning(
                "js_refs_limited",
                total=len(js_refs),
                limit=max_files,
            )
            js_refs = js_refs[:max_files]

        self.progress.start_stage(PipelineStage.DOWNLOAD, len(js_refs))

        assets: list[JSAsset] = list(existing_assets or [])
        completed = set(completed_urls or {asset.url for asset in assets})
        for asset in assets:
            if asset.content_hash:
                self.dedup.add_content(asset.content_hash, asset.url)

        # Create shared HTTP client for all downloads
        headers = {"User-Agent": self.config.crawler.user_agent}
        headers.update(self.config.auth.get_auth_headers())

        self._download_client = httpx.AsyncClient(
            headers=headers,
            cookies=self.config.auth.cookies or None,
            timeout=self.config.crawler.request_timeout,
            follow_redirects=self.config.crawler.follow_redirects,
            max_redirects=self.config.crawler.max_redirects,
        )

        try:
            # Semaphore to limit concurrent downloads (prevents task flooding)
            download_semaphore = asyncio.Semaphore(self.config.crawler.max_concurrent)

            async def download_one(ref: JSReference) -> tuple[JSReference, Optional[JSAsset]]:
                # Acquire semaphore slot to limit concurrency
                async with download_semaphore:
                    # Apply rate limiting before each request
                    await self.rate_limiter.acquire(ref.url)

                    try:
                        asset = await self._download_js(ref)
                        if asset:
                            await self.rate_limiter.record_success(ref.url)
                            self.progress.update(1)
                        else:
                            self.progress.update(0, failed=1)
                        return ref, asset
                    except httpx.HTTPStatusError as e:
                        await self.rate_limiter.record_error(ref.url, e.response.status_code)
                        self.progress.update(0, failed=1)
                        return ref, None
                    except Exception:
                        self.progress.update(0, failed=1)
                        return ref, None

            refs_to_download = [ref for ref in js_refs if ref.url not in completed]
            if completed:
                self.progress.update(len(completed))

            tasks = [asyncio.create_task(download_one(ref)) for ref in refs_to_download]

            for task in asyncio.as_completed(tasks):
                ref: Optional[JSReference] = None
                try:
                    ref, result = await task
                    if isinstance(result, JSAsset):
                        # Check for content dedup
                        if self.dedup.add_content(result.content_hash, result.url):
                            assets.append(result)
                            await self._persist_asset(result)
                except asyncio.CancelledError:
                    raise
                except (KeyboardInterrupt, SystemExit):
                    # BaseException below would otherwise swallow Ctrl+C, leaving
                    # the download loop running instead of aborting.
                    raise
                except BaseException as exc:
                    logger.warning("download_task_exception", error=str(exc))
                finally:
                    if ref:
                        completed.add(ref.url)
                    await self._store_checkpoint(
                        PipelineStage.CRAWL,
                        self._seed_urls,
                        js_refs=js_refs,
                        assets=assets,
                        stage_state={"download_complete_urls": sorted(completed)},
                    )

        finally:
            await self._download_client.aclose()
            self._download_client = None

        self.progress.complete_stage()
        self._assets = assets
        logger.info("download_complete", assets=len(assets))

        return assets

    async def _download_js(self, ref: JSReference) -> Optional[JSAsset]:
        """Download a single JS file with SSRF protection."""
        # SSRF Protection: Validate URL before making request
        # Run in thread to avoid blocking event loop with DNS resolution
        is_safe, reason = await asyncio.to_thread(is_url_safe, ref.url, True)
        if not is_safe:
            logger.warning(
                "ssrf_blocked",
                url=ref.url[:100],
                reason=reason,
            )
            return None

        try:
            client = self._download_client
            if not client:
                raise RuntimeError("Download client not initialized")

            # Stream response to check Content-Length before downloading body
            async with client.stream("GET", ref.url) as response:
                response.raise_for_status()

                # Check Content-Length if available (early rejection)
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > self.config.crawler.max_file_size:
                            logger.warning("file_too_large", url=ref.url)
                            return None
                    except ValueError:
                        pass

                # Read body
                content = await response.aread()

            # Check actual size limit
            if len(content) > self.config.crawler.max_file_size:
                logger.warning("file_too_large", url=ref.url)
                return None

            asset = JSAsset(
                url=ref.url,
                content=content,
                size=len(content),
                initiator=ref.initiator,
                load_context=ref.load_context,
                load_method=ref.method,
                is_first_party=self.scope.is_first_party(ref.url),
                headers=dict(response.headers),
                status_code=response.status_code,
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
            )
            asset.compute_hash()

            return asset

        except httpx.HTTPStatusError:
            raise  # Let download_one handle rate-limit logic
        except Exception as e:
            logger.debug("download_error", url=ref.url[:100], error=str(e))
            return None

    async def _stage_normalize(
        self,
        assets: list[JSAsset],
        processed_hashes: Optional[set[str]] = None,
    ) -> None:
        """Normalize JS content."""
        self.progress.start_stage(PipelineStage.NORMALIZE, len(assets))
        processed = set(processed_hashes or [])

        sourcemap_resolver = SourceMapResolver()
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
                if self._should_skip_beautify(asset.content):
                    skip_detail = self._format_normalize_detail(
                        index,
                        total_assets,
                        asset.url,
                        "beautify skipped (size limit)",
                    )
                    self.progress.set_detail(skip_detail)
                    logger.info(
                        "beautify_skipped_large_asset",
                        url=asset.url[:160],
                        size_bytes=len(asset.content),
                        max_bytes=self.config.parser.beautify_max_bytes,
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
                    sourcemap = await self._await_with_stage_heartbeat(
                        sourcemap_resolver.resolve(content, asset.url),
                        stage=PipelineStage.NORMALIZE,
                        detail=sourcemap_detail,
                        heartbeat_event="normalize_heartbeat",
                        log_fields={
                            "url": asset.url[:160],
                            "operation": "sourcemap_check",
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
                    else:
                        self.progress.set_detail(
                            self._format_normalize_detail(
                                index,
                                total_assets,
                                asset.url,
                                "no sourcemap",
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

    def _format_normalize_detail(
        self,
        index: int,
        total: int,
        asset_url: str,
        operation: str,
    ) -> str:
        """Build a concise progress detail for normalize-stage asset work."""
        return f"{index}/{max(total, 1)} {self._summarize_asset_url(asset_url)} · {operation}"

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

    def _should_skip_beautify(self, content: bytes) -> bool:
        """Return True when beautify should be skipped for oversized assets."""
        limit = max(int(self.config.parser.beautify_max_bytes), 0)
        return limit > 0 and len(content) > limit

    def _identity_normalization_result(self, content: str):
        """Return a no-op normalization result for already-usable source."""
        from bundleInspector.normalizer.beautify import NormalizationLevel, NormalizationResult

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
        awaitable,
        *,
        stage: PipelineStage,
        detail: str,
        heartbeat_event: str,
        log_fields: Optional[dict[str, Any]] = None,
    ):
        """Await work while periodically refreshing progress detail for long-running operations."""
        task = asyncio.create_task(awaitable)
        heartbeat_seconds = max(self._normalize_heartbeat_seconds, 0.1)
        started = perf_counter()

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

    async def _stage_parse(
        self,
        assets: list[JSAsset],
        processed_hashes: Optional[set[str]] = None,
    ) -> None:
        """Parse JS to AST."""
        self.progress.start_stage(PipelineStage.PARSE, len(assets))
        processed = set(processed_hashes or [])

        # In parallel mode, parsing is fused into the analyze stage: each worker parses its
        # asset locally, so the large AST never crosses a process boundary (the key to
        # multicore scaling). Nothing to parse here.
        if _parallel_workers() > 1:
            self.progress.update(len(assets))
            self.progress.complete_stage()
            logger.info("parse_deferred_to_parallel_analyze", total=len(assets))
            return

        for asset in assets:
            if asset.content_hash in processed and asset.content_hash in self._parse_results:
                self.progress.update(1)
                continue
            content = decode_js_bytes(asset.content)
            result = self.parser.parse(content)
            await self._store_parse_result(asset, result, assets, processed)

        self.progress.complete_stage()
        success_count = sum(1 for a in assets if a.parse_success)
        logger.info("parse_complete", success=success_count, total=len(assets))

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

        if result.success and result.ast:
            asset.ast_hash = self.dedup.compute_hash(
                json.dumps(result.ast, separators=(",", ":"), sort_keys=True).encode()
            )[:16]
            # Store parse result for reuse in analyze stage
            self._parse_results[asset.content_hash] = result
            await self._persist_ast(asset.content_hash, result.ast)

        processed.add(asset.content_hash)
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
        existing_findings: Optional[list[Finding]] = None,
        processed_hashes: Optional[set[str]] = None,
    ) -> list[Finding]:
        """Run detection rules."""
        self.progress.start_stage(PipelineStage.ANALYZE, len(assets))

        # Register default rules
        self.rule_engine.register_defaults()

        findings: list[Finding] = list(existing_findings or [])
        processed = set(processed_hashes or [])

        workers = _parallel_workers()
        to_analyze = [a for a in assets if a.content_hash not in processed]
        if workers > 1 and len(to_analyze) > 1:
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
            loop = asyncio.get_event_loop()
            with ProcessPoolExecutor(
                max_workers=workers,
                initializer=init_worker,
                initargs=(self.config,),
            ) as pool:
                results = await asyncio.gather(*[
                    loop.run_in_executor(pool, analyze_asset_task, payload)
                    for payload in payloads
                ], return_exceptions=True)
            # A worker that dies (OOM/segfault -> BrokenProcessPool) must not wipe the
            # whole batch's findings. Re-run any failed payload serially in-process so
            # its findings are still recovered; a genuine per-asset failure yields an
            # empty result and is logged -- never a silent whole-batch loss + crash.
            recovered = []
            for payload, res in zip(payloads, results):
                if isinstance(res, BaseException):
                    url = payload[1].url[:120]
                    logger.warning("parallel_worker_failed", url=url, error=str(res))
                    try:
                        res = analyze_asset_task(payload)
                    except Exception as e:
                        logger.warning("serial_fallback_failed", url=url, error=str(e))
                        res = (payload[0], False, [f"analyze failed: {e}"], None, [])
                recovered.append(res)
            for idx, parse_success, parse_errors, ast_hash, asset_findings in sorted(
                recovered, key=lambda item: item[0]
            ):
                asset = to_analyze[idx]
                asset.parse_success = parse_success
                asset.parse_errors = parse_errors
                if ast_hash:
                    asset.ast_hash = ast_hash
                findings.extend(asset_findings)
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

            # Build IR
            ir = self.ir_builder.build(
                parse_result.ast,
                asset.url,
                asset.content_hash,
            )

            # Create analysis context
            context = AnalysisContext(
                file_url=asset.url,
                file_hash=asset.content_hash,
                source_content=content,
                is_first_party=asset.is_first_party,
            )

            # Run rules
            asset_findings = self.rule_engine.analyze(ir, context)
            self._annotate_finding_metadata(asset, ir, asset_findings)
            self._apply_artifact_mappings(asset, asset_findings)
            findings.extend(asset_findings)

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
        findings,
        line_mapper,
        sourcemap,
    ) -> None:
        """Delegate to the light AssetAnalyzer (kept for serial path + test callers)."""
        return self._analyzer._apply_mappings(findings, line_mapper, sourcemap)

    def analyze_asset_standalone(
        self,
        asset: JSAsset,
        line_mapper,
        sourcemap,
    ) -> list[Finding]:
        """Delegate full per-asset analysis to the light AssetAnalyzer."""
        return self._analyzer.analyze_asset_standalone(asset, line_mapper, sourcemap)

    def _annotate_finding_metadata(
        self,
        asset: JSAsset,
        ir,
        findings: list[Finding],
    ) -> None:
        """Delegate IR/runtime metadata annotation to the light AssetAnalyzer."""
        return self._analyzer._annotate_finding_metadata(asset, ir, findings)

    async def _stage_correlate(self, findings: list[Finding]):
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

        self.progress.update(1)
        self.progress.complete_stage()
        logger.info(
            "correlate_complete",
            edges=len(graph.edges),
            clusters=len(graph.clusters),
        )

        return graph

    async def _stage_classify(self, findings: list[Finding], graph) -> None:
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
        graph,
    ) -> Report:
        """Generate report."""
        self.progress.start_stage(PipelineStage.REPORT, 1)

        report = Report(
            job_id=self.job_id,
            seed_urls=seed_urls,
            config=embed_report_resume_signature(
                self.config.to_dict(),
                self._resume_signature,
            ),
            assets=assets,
            findings=findings,
            correlations=graph.to_correlations(),
            clusters=graph.clusters,
            completed_at=datetime.now(timezone.utc),
            duration_seconds=self.progress.duration,
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
        except Exception as e:
            logger.warning("asset_store_error", url=asset.url[:100], error=str(e))

    async def _persist_ast(self, content_hash: str, ast: dict[str, Any]) -> None:
        """Persist parsed AST when storage is enabled."""
        if not self._artifact_store:
            return

        try:
            await self._artifact_store.store_ast(ast, content_hash)
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
        except Exception as e:
            logger.warning("report_store_error", report_id=report.id, error=str(e))


class BundleInspector:
    """
    Main BundleInspector class - high-level API.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        on_stage_start: Optional[callable] = None,
        on_stage_complete: Optional[callable] = None,
        on_progress: Optional[callable] = None,
        on_stage_detail: Optional[callable] = None,
        on_resume: Optional[callable] = None,
    ):
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

    async def _try_resume_report(self, urls: list[str]) -> Optional[Report]:
        """Load the latest stored report for the configured job when resuming."""
        if not self.config.resume or not self.config.job_id:
            return None

        try:
            store = FindingStore(self.config.cache_dir / self.config.job_id)
            report = await store.get_latest_report()
            if report_matches_resume_signature(
                report,
                seed_urls=urls,
                expected_signature=build_remote_resume_signature(self.config),
            ):
                return report
            return None
        except Exception as e:
            logger.warning(
                "resume_report_load_error",
                job_id=self.config.job_id,
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
