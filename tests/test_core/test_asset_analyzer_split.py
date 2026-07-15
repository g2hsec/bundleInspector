"""Light-module split: per-asset analysis is extracted from the Orchestrator into
core.asset_analyzer so spawned parallel workers do not re-import the browser (playwright) /
network (httpx) stack. These tests guard (a) the import graph stays light, (b) findings are
byte-identical to the serial path, and (c) the public API still resolves via lazy hooks.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys

import pytest

from bundleInspector.config import Config
from bundleInspector.core import asset_analysis
from bundleInspector.core.asset_analyzer import AssetAnalyzer
from bundleInspector.core.dedup import DedupCache
from bundleInspector.parser.ir_builder import IRBuilder
from bundleInspector.parser.js_parser import JSParser
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import JSAsset

_HEAVY_CHECK = (
    "import sys;"
    "heavy=[m for m in sys.modules if m=='httpx' or m.startswith('playwright')"
    " or m.startswith('bundleInspector.collector') or m=='bundleInspector.core.orchestrator'];"
    "print('HEAVY' if heavy else 'LIGHT', heavy[:3])"
)


def _run_fresh(code: str) -> str:
    """Run code in a fresh interpreter (spawn-equivalent) and return stdout."""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_asset_analyzer_import_graph_is_light():
    out = _run_fresh("import bundleInspector.core.asset_analyzer;" + _HEAVY_CHECK)
    assert out.startswith("LIGHT"), out


def test_asset_analysis_worker_import_is_light():
    # Mirrors the spawned worker: import the task module AND run init_worker.
    out = _run_fresh(
        "import bundleInspector.core.asset_analysis as a;"
        "from bundleInspector.config import Config;"
        "a.init_worker(Config());" + _HEAVY_CHECK
    )
    assert out.startswith("LIGHT"), out


def test_sourcemap_import_is_httpx_free():
    out = _run_fresh(
        "import sys, bundleInspector.normalizer.sourcemap as s;"
        "print('HTTPX' if 'httpx' in sys.modules else 'CLEAN');"
        # sanity: offline position mapping still works without httpx loaded
        "r=s.SourceMapResolver();"
        "print('RESOLVER_OK' if hasattr(r,'get_original_position') else 'BAD')"
    )
    assert "CLEAN" in out and "RESOLVER_OK" in out, out


def test_public_api_lazy_still_resolves():
    out = _run_fresh(
        "from bundleInspector import BundleInspector, Config;"
        "from bundleInspector.core import Orchestrator, PipelineStage, DedupCache;"
        "print(BundleInspector.__name__, Orchestrator.__name__, PipelineStage.__name__)"
    )
    assert "BundleInspector Orchestrator PipelineStage" in out, out


# --------------------------------------------------------------------------- parity

def _mkasset(name: str, src: str) -> JSAsset:
    b = src.encode("utf-8")
    return JSAsset(
        url=f"https://x/{name}.js", content=b,
        content_hash=hashlib.sha256(b).hexdigest()[:16], is_first_party=True,
    )


def _serial_analyzer() -> AssetAnalyzer:
    cfg = Config()
    parser = JSParser(tolerant=cfg.parser.tolerant)
    engine = RuleEngine(cfg.rules)
    engine.register_defaults()
    return AssetAnalyzer(parser, IRBuilder(), engine, DedupCache())


def _sig(findings):
    return sorted(
        (f.rule_id, str(f.category), str(f.severity), str(f.confidence), f.value_type,
         f.extracted_value, f.evidence.line,
         tuple(sorted((k, str(v)) for k, v in (f.metadata or {}).items())))
        for f in findings
    )


@pytest.mark.parametrize("src", [
    'const api = axios.create({baseURL:"https://api.x.com"}); api.get("/users"); axios.post("/api/v1/items/42",{});',
    'import("./mod").then(m => m.doThing()); const api = await import("./api"); api.get("/api/v1/hidden");',
    'import * as ns from "./ns"; const fn = ns.callEndpoint; fn("/api/admin/secret");',
    'const x = require("./x"); module.exports = require("./barrel"); fetch("/api/internal/reexport");',
    '(function(){function outer(){const c=window.axios;function inner(){const d=c;d.get("/api/nested/scope");}inner();}outer();})();',
    'function h(u){ if(u.isAdmin){ fetch("/api/v1/admin/users"); } }',
])
def test_serial_parallel_findings_identical(src):
    cfg = Config()
    asset_analysis.init_worker(cfg)
    a1, a2 = _mkasset("t", src), _mkasset("t", src)
    serial = _serial_analyzer().analyze_asset_standalone(a1, None, None)
    _, _, _, _, parallel = asset_analysis.analyze_asset_task((0, a2, None, None, cfg))
    assert _sig(serial) == _sig(parallel)
    assert a1.ast_hash == a2.ast_hash


def test_orchestrator_uses_asset_analyzer_and_delegates():
    from bundleInspector.core.orchestrator import Orchestrator

    orch = Orchestrator(Config())
    assert isinstance(orch._analyzer, AssetAnalyzer)
    # delegator forwards to the light analyzer
    src = 'fetch("/api/v1/thing");'
    asset = _mkasset("d", src)
    via_orch = orch.analyze_asset_standalone(asset, None, None)
    asset2 = _mkasset("d", src)
    via_analyzer = orch._analyzer.analyze_asset_standalone(asset2, None, None)
    assert _sig(via_orch) == _sig(via_analyzer)
