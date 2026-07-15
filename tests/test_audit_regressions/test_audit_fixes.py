"""Regression tests for the codebase-wide audit fixes.

Each test pins a specific defect found during the full-codebase sweep so it cannot
silently return. Grouped by finding id (F1, F2, F5, F6, F8, F9, F11/F12, F14, F16, F17).
The overriding invariant for this tool is that detection must never silently drop.
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
from pathlib import Path

import pytest

from bundleInspector.config import Config, CrawlerConfig, RuleConfig
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import (
    Category,
    Confidence,
    JSAsset,
    PipelineCheckpoint,
    Severity,
)

# --------------------------------------------------------------------------- helpers

def _ctx(source: str) -> AnalysisContext:
    return AnalysisContext(file_url="f.js", file_hash="h", source_content=source)


def _ir(source: str):
    result = parse_js(source)
    assert result.success
    return build_ir(result.ast, "f.js", "h")


def _mk_result(value: str) -> RuleResult:
    return RuleResult(
        rule_id="fake",
        category=Category.ENDPOINT,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        title="t",
        description="d",
        extracted_value=value,
        value_type="url",
        line=1,
        column=0,
    )


def _engine_with_rule(rule) -> RuleEngine:
    eng = RuleEngine(Config().rules)
    eng.rules = [rule]
    eng._context_filter = None  # isolate: don't let the FP filter drop test values
    return eng


# --------------------------------------------------------------------------- F1: per-result containment

class _PartlyBrokenRule(BaseRule):
    id = "partly_broken"
    category = Category.ENDPOINT
    enabled = True

    def __init__(self, values, bad):
        self._values = values
        self._bad = bad

    def match(self, ir, context):
        for v in self._values:
            yield _mk_result(v)

    def to_finding(self, result, context):
        if result.extracted_value == self._bad:
            raise ValueError("boom on one malformed node")
        return super().to_finding(result, context)


class _ExplodingRule(BaseRule):
    id = "exploding"
    category = Category.ENDPOINT
    enabled = True

    def match(self, ir, context):
        yield _mk_result("/before")
        raise RuntimeError("detector exploded mid-iteration")


def test_one_bad_result_does_not_zero_the_detector():
    src = "fetch('/a');fetch('/b');"
    findings = _engine_with_rule(
        _PartlyBrokenRule(["/good1", "/bad", "/good2"], bad="/bad")
    ).analyze(_ir(src), _ctx(src))
    vals = {f.extracted_value for f in findings}
    assert "/good1" in vals and "/good2" in vals  # survive despite the bad one
    assert "/bad" not in vals


def test_generator_raise_preserves_already_yielded_results():
    src = "fetch('/x');"
    findings = _engine_with_rule(_ExplodingRule()).analyze(_ir(src), _ctx(src))
    assert "/before" in {f.extracted_value for f in findings}


# --------------------------------------------------------------------------- F6: unknown category surfaced

def test_unknown_enabled_category_warns_but_keeps_valid(monkeypatch):
    with pytest.raises(ValueError, match="unknown enabled_categories"):
        RuleConfig(enabled_categories=["endpoint", "secretsTYPO"])
    legacy_config = RuleConfig.model_construct(
        enabled_categories=["endpoint", "secretsTYPO"],
    )
    eng = RuleEngine(legacy_config)
    eng.register_defaults()
    warned = []
    monkeypatch.setattr(
        "bundleInspector.rules.engine.logger.warning",
        lambda evt, **k: warned.append(evt),
    )
    src = "fetch('/api/thing');"
    findings = eng.analyze(_ir(src), _ctx(src))
    assert "unknown_enabled_categories" in warned
    # The valid 'endpoint' category is still active (typo didn't disable everything).
    assert any(f.category == Category.ENDPOINT for f in findings)


# --------------------------------------------------------------------------- F2: enrichment failure keeps findings

def test_enrichment_failure_preserves_findings(monkeypatch):
    from bundleInspector.core.asset_analysis import _build_analyzer

    analyzer = _build_analyzer(Config())

    def _boom(*a, **k):
        raise RuntimeError("line-mapping blew up")

    monkeypatch.setattr(analyzer, "_apply_mappings", _boom)
    asset = JSAsset(url="https://x/a.js", content=b"fetch('https://api.example.com/v1/users');")
    asset.compute_hash()
    findings = analyzer.analyze_asset_standalone(asset, None, None)
    assert findings, "findings must survive an enrichment failure, not be dropped"


# --------------------------------------------------------------------------- F5: in-process serial fallback works

def test_analyze_asset_task_runs_in_process():
    """The parallel path re-runs a failed worker payload in-process; that call path
    (which lazily builds the analyzer) must work outside a worker."""
    from bundleInspector.core.asset_analysis import analyze_asset_task

    asset = JSAsset(url="https://x/a.js", content=b"fetch('https://api.example.com/v1/users');")
    asset.compute_hash()
    idx, ok, errs, ast_hash, findings = analyze_asset_task((0, asset, None, None, Config()))
    assert idx == 0
    assert isinstance(findings, list) and findings


# --------------------------------------------------------------------------- F8: dormant first-party scoping

def _relative_endpoint_findings():
    src = "fetch('/api/v1/user');"
    ctx = _ctx(src)
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    return [f for f in eng.analyze(_ir(src), ctx) if f.category == Category.ENDPOINT]


def test_dormant_relative_not_credited_by_third_party_host():
    from bundleInspector.correlator.dormant import annotate_dormant_endpoints

    observed = ["https://cdn.thirdparty.com/api/v1/user"]  # only a third-party hit
    findings = _relative_endpoint_findings()
    assert findings
    annotate_dormant_endpoints(
        findings, observed, Config().rules, primary_hosts={"app.example.com"}
    )
    assert any("dormant_endpoint" in f.tags for f in findings)


def test_dormant_host_agnostic_backward_compatible():
    from bundleInspector.correlator.dormant import annotate_dormant_endpoints

    observed = ["https://cdn.thirdparty.com/api/v1/user"]
    findings = _relative_endpoint_findings()
    # No primary_hosts -> legacy host-agnostic behavior: the path counts as exercised.
    annotate_dormant_endpoints(findings, observed, Config().rules)
    assert not any("dormant_endpoint" in f.tags for f in findings)


# --------------------------------------------------------------------------- F9: atomic concurrent checkpoints

@pytest.mark.asyncio
async def test_concurrent_checkpoints_never_corrupt(tmp_path):
    from bundleInspector.storage.finding_store import FindingStore

    store = FindingStore(tmp_path)
    checkpoints = [
        PipelineCheckpoint(
            job_id="j",
            seed_urls=["u"],
            stage="analyze",
            stage_state={"n": i, "pad": "x" * 4000},
        )
        for i in range(40)
    ]
    await asyncio.gather(*[store.store_checkpoint(c) for c in checkpoints])
    loaded = await store.get_checkpoint()  # must be valid JSON, never torn
    assert loaded is not None
    assert not (tmp_path / "checkpoint.json.tmp").exists()  # temp cleaned up


# --------------------------------------------------------------------------- F16: BOM-aware decode

def test_decode_utf8_no_bom_is_identical():
    from bundleInspector.core.text_decode import decode_js_bytes

    raw = "const s='café résumé 한국어';".encode()
    assert decode_js_bytes(raw) == raw.decode("utf-8", errors="replace")


def test_decode_utf16_bom_not_mangled():
    from bundleInspector.core.text_decode import decode_js_bytes

    s = "const secret='AKIAIOSFODNN7EXAMPLE';"
    assert decode_js_bytes(s.encode("utf-16")) == s  # BOM detected & stripped


def test_decode_bomless_utf16_and_utf32_not_mangled():
    from bundleInspector.core.text_decode import decode_js_bytes

    source = 'const endpoint = "/api/admin"; fetch(endpoint);'
    for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        assert decode_js_bytes(source.encode(encoding)) == source


def test_decode_does_not_reclassify_binary_without_strong_unicode_lanes():
    from bundleInspector.core.text_decode import decode_js_bytes

    binary = b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03\xff\x00\xfe\x10"
    assert decode_js_bytes(binary) == binary.decode("utf-8", errors="replace")


def test_decode_utf8_sig_bom_stripped():
    from bundleInspector.core.text_decode import decode_js_bytes

    s = "const x = 1;"
    assert decode_js_bytes(b"\xef\xbb\xbf" + s.encode("utf-8")) == s


# --------------------------------------------------------------------------- F11/F12: cookie DB copy + sidecars

def test_firefox_cookies_read_via_copy(tmp_path):
    from bundleInspector.core.cookie_import import _read_firefox_cookies

    db = tmp_path / "cookies.sqlite"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT)")
    conn.execute("INSERT INTO moz_cookies VALUES ('sid', 'abc123', 'app.example.com')")
    conn.commit()
    conn.close()
    cookies = _read_firefox_cookies(db)
    assert cookies.get("sid") == "abc123"


def test_copy_db_with_sidecars_includes_wal(tmp_path):
    from bundleInspector.core.cookie_import import _copy_db_with_sidecars

    db = tmp_path / "Cookies"
    db.write_bytes(b"main-db")
    (tmp_path / "Cookies-wal").write_bytes(b"wal-rows")
    out = tmp_path / "out"
    out.mkdir()
    dst = _copy_db_with_sidecars(db, out)
    assert dst.read_bytes() == b"main-db"
    assert (out / "Cookies-wal").read_bytes() == b"wal-rows"  # recent rows not missed


# --------------------------------------------------------------------------- F14: teardown always stops driver

@pytest.mark.asyncio
async def test_teardown_stops_playwright_even_if_close_raises():
    from bundleInspector.collector.headless import HeadlessCollector

    collector = HeadlessCollector(CrawlerConfig())
    stopped = {"v": False}

    class _Browser:
        async def close(self):
            raise RuntimeError("browser already crashed")

    class _Playwright:
        async def stop(self):
            stopped["v"] = True

    collector._browser = _Browser()
    collector._playwright = _Playwright()
    with pytest.raises(RuntimeError):
        await collector.teardown()
    assert stopped["v"] is True  # driver stopped despite close() raising


# --------------------------------------------------------------------------- F17: case-insensitive containment (Windows)

@pytest.mark.skipif(sys.platform != "win32", reason="normcase only lowercases on Windows")
def test_is_path_safe_case_insensitive_on_windows(tmp_path):
    from bundleInspector.core.security import is_path_safe

    target = tmp_path / "App.js"
    target.write_text("x", encoding="utf-8")
    # Base given with different case than the actual path.
    ok, _ = is_path_safe(target, [Path(str(tmp_path).upper())], allow_symlinks=True)
    assert ok
