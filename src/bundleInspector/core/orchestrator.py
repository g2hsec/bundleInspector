"""
Pipeline orchestrator - main entry point.
"""

from __future__ import annotations

import asyncio
import json
import uuid
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
from bundleInspector.core.dedup import DedupCache
from bundleInspector.core.progress import PipelineStage, ProgressTracker
from bundleInspector.core.rate_limiter import AdaptiveRateLimiter
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

        if checkpoint and checkpoint.seed_urls == seed_urls:
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
            stage_state=stage_state or {},
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
                content = asset.content.decode("utf-8", errors="replace")
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

        for asset in assets:
            if asset.content_hash in processed and asset.content_hash in self._parse_results:
                self.progress.update(1)
                continue

            content = asset.content.decode("utf-8", errors="replace")
            result = self.parser.parse(content)

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

        self.progress.complete_stage()
        success_count = sum(1 for a in assets if a.parse_success)
        logger.info("parse_complete", success=success_count, total=len(assets))

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

            content = asset.content.decode("utf-8", errors="replace")

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
        line_mapper = self._line_mappers.get(asset.content_hash)
        sourcemap = self._sourcemaps.get(asset.content_hash)
        resolver = SourceMapResolver()
        original_sources = (
            resolver.get_original_sources(sourcemap) if sourcemap else {}
        )

        for finding in findings:
            if line_mapper and finding.evidence.line > 0:
                original_line, original_column = line_mapper.get_original(
                    finding.evidence.line,
                    finding.evidence.column,
                )
                finding.evidence.original_line = original_line
                finding.evidence.original_column = original_column

            if not sourcemap or finding.evidence.line <= 0:
                continue

            position = resolver.get_original_position(
                sourcemap,
                finding.evidence.line,
                finding.evidence.column,
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

    def _annotate_finding_metadata(
        self,
        asset: JSAsset,
        ir,
        findings: list[Finding],
    ) -> None:
        """Attach IR and runtime context metadata used by correlators/reporters."""
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
        imports = list(dict.fromkeys([
            *[imp.source for imp in ir.imports if imp.source],
            *commonjs_require_sources,
            *re_export_sources,
        ]))
        dynamic_imports = [imp.source for imp in ir.imports if imp.is_dynamic and imp.source]
        import_bindings = [
            *self._build_import_bindings(ir),
            *commonjs_require_bindings,
        ]
        function_defs = ir.function_defs
        scope_parents = self._build_scope_parent_map(function_defs)
        if ir.raw_ast:
            seen_binding_keys = {
                self._import_binding_key(binding)
                for binding in import_bindings
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
                    self._import_binding_key(binding)
                    for binding in fresh_bindings
                )
        commonjs_exports, commonjs_export_scopes = build_commonjs_export_metadata(ir)
        default_object_exports = list(dict.fromkeys([
            *build_default_object_export_members(ir),
            *build_commonjs_default_object_export_members(ir),
        ]))
        named_object_exports = self._merge_named_object_exports(
            build_named_object_export_members(ir),
            build_commonjs_named_object_export_members(ir),
        )
        exports = list(dict.fromkeys([
            *[exp.name for exp in ir.exports if exp.name],
            *commonjs_exports,
        ]))
        export_scopes = self._merge_export_scopes(
            build_export_scope_map(ir),
            commonjs_export_scopes,
        )
        call_names = [call.full_name or call.name for call in ir.function_calls if (call.full_name or call.name)]
        scoped_calls = self._build_scoped_calls(ir)
        call_graph = ir.call_graph

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
            if asset.load_context:
                finding.metadata.setdefault("load_context", asset.load_context)
            if asset.initiator:
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
                    scope for scope in scopes or []
                    if isinstance(scope, str) and scope
                )
        return {
            export_name: sorted(scopes)
            for export_name, scopes in merged.items()
            if scopes
        }

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
                    member for member in members or []
                    if isinstance(member, str) and member
                )
        return {
            export_name: sorted(members)
            for export_name, members in merged.items()
            if members
        }

    def _build_import_bindings(self, ir) -> list[dict[str, Any]]:
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

    def _parse_import_specifier(self, source: str, specifier: str) -> Optional[dict[str, Any]]:
        """Parse a serialized import specifier into a structured binding."""
        value = (specifier or "").strip()
        if not value:
            return None
        if value.startswith("default as "):
            return {
                "source": source,
                "imported": "default",
                "local": value[len("default as "):],
                "kind": "default",
                "scope": "global",
                "is_dynamic": False,
            }
        if value.startswith("* as "):
            return {
                "source": source,
                "imported": "*",
                "local": value[len("* as "):],
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
    ) -> Optional[dict[str, Any]]:
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
        imported: Optional[str] = None,
        kind: Optional[str] = None,
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
    ) -> Optional[dict[str, Any]]:
        """Convert `const fn = ns.member` aliases back into import-like bindings."""
        local = self._extract_pattern_target_name(target)
        if not local or not isinstance(value, dict) or value.get("type") != "MemberExpression":
            return None

        object_node = value.get("object")
        property_name = self._extract_pattern_name(value.get("property"))
        if not property_name or not isinstance(object_node, dict) or object_node.get("type") != "Identifier":
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
            return [{
                "source": source,
                "imported": "*",
                "local": local,
                "kind": "namespace",
                "scope": scope,
                "is_dynamic": True,
            }]

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
            bindings.append({
                "source": source,
                "imported": imported,
                "local": local,
                "kind": kind,
                "scope": scope,
                "is_dynamic": True,
            })
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
            if quasis:
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

    def _build_scoped_calls(self, ir) -> dict[str, list[str]]:
        """Group function calls by lexical scope for correlation."""
        scoped_calls: dict[str, set[str]] = {}
        for call in ir.function_calls:
            scope = (call.scope or "global").strip() or "global"
            name = (call.full_name or call.name or "").strip()
            if not name:
                continue
            scoped_calls.setdefault(scope, set()).add(name)
        return {
            scope: sorted(call_names)
            for scope, call_names in scoped_calls.items()
        }

    def _find_enclosing_scope(self, line: int, function_defs) -> str:
        """Find the innermost function scope containing a finding line."""
        if line <= 0:
            return "global"

        matching = [
            func_def for func_def in function_defs
            if func_def.line <= line <= max(func_def.end_line, func_def.line)
        ]
        if not matching:
            return "global"

        matching.sort(key=lambda func_def: (func_def.end_line - func_def.line, func_def.line))
        return matching[0].scope

    def _build_scope_parent_map(
        self,
        function_defs: list[Any],
    ) -> dict[str, list[str]]:
        """Build lexical parent-scope chains from nested function ranges."""
        normalized_defs = [
            func_def for func_def in function_defs
            if getattr(func_def, "scope", "") and getattr(func_def, "line", 0) > 0
        ]
        if not normalized_defs:
            return {}

        parent_map: dict[str, str] = {}
        for func_def in normalized_defs:
            candidates = [
                candidate for candidate in normalized_defs
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

    async def _stage_correlate(self, findings: list[Finding]):
        """Build correlation graph."""
        self.progress.start_stage(PipelineStage.CORRELATE, 1)

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
            config=self.config.to_dict(),
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
        resumed_report = await self._try_resume_report()
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

    async def _try_resume_report(self) -> Optional[Report]:
        """Load the latest stored report for the configured job when resuming."""
        if not self.config.resume or not self.config.job_id:
            return None

        try:
            store = FindingStore(self.config.cache_dir / self.config.job_id)
            return await store.get_latest_report()
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
