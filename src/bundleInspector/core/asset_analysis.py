"""
Parallel per-asset analysis worker.

Runs the FULL per-asset pipeline (parse -> IR -> rules -> annotate -> map) inside a worker
process and returns only the small findings list. The large AST is created and consumed
entirely inside the worker, so it never crosses the process boundary -- this is what lets
multicore analysis scale (a naive parse-only pool is bottlenecked pickling multi-MB ASTs back
to the main process).

Opt-in via BUNDLEINSPECTOR_PARALLEL; the serial default path is unchanged and uses the exact
same Orchestrator.analyze_asset_standalone logic, so findings are byte-identical.
"""

from __future__ import annotations

from typing import Any, Optional

from bundleInspector.config import Config
from bundleInspector.core.asset_analyzer import AssetAnalyzer
from bundleInspector.core.dedup import DedupCache
from bundleInspector.parser.ir_builder import IRBuilder
from bundleInspector.parser.js_parser import JSParser
from bundleInspector.rules.engine import RuleEngine

# Per-worker-process analyzer, built once by the pool initializer.
_ANALYZER: Optional[Any] = None


def _build_analyzer(config: Config) -> AssetAnalyzer:
    """Build the light per-asset analyzer from its 4 stateless collaborators.

    Imports only the analysis stack (parser/IR/rules) -- deliberately NOT the Orchestrator,
    so a spawned worker never re-imports the collector (playwright) / httpx stack it will
    never use. Findings stay byte-identical to the serial path (same AssetAnalyzer code)."""
    parser = JSParser(tolerant=config.parser.tolerant)
    ir_builder = IRBuilder()
    rule_engine = RuleEngine(config.rules)
    rule_engine.register_defaults()
    return AssetAnalyzer(parser, ir_builder, rule_engine, DedupCache())


def init_worker(config: Config) -> None:
    """ProcessPoolExecutor initializer: build the analyzer once per worker process."""
    global _ANALYZER
    _ANALYZER = _build_analyzer(config)


def analyze_asset_task(payload):
    """Worker task.

    payload = (index, asset, line_mapper, sourcemap, config)
    returns = (index, parse_success, parse_errors, ast_hash, findings)
    """
    global _ANALYZER
    index, asset, line_mapper, sourcemap, config = payload
    if _ANALYZER is None:  # defensive: build if the initializer did not run
        _ANALYZER = _build_analyzer(config)
    findings = _ANALYZER.analyze_asset_standalone(asset, line_mapper, sourcemap)
    return index, asset.parse_success, asset.parse_errors, asset.ast_hash, findings
