"""CLI UX and output regression tests."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path

from click.testing import CliRunner
from rich.console import Console

import bundleInspector.cli as cli_module
from bundleInspector.config import Config, LogLevel
from bundleInspector.core.progress import PipelineStage, StageProgress
from bundleInspector.storage.models import Report


def _build_report() -> Report:
    report = Report(seed_urls=["https://example.com"])
    report.compute_summary()
    return report


def test_scan_help_includes_debug_and_no_banner():
    runner = CliRunner()
    result = runner.invoke(cli_module.main, ["scan", "--help"])

    assert result.exit_code == 0, result.output
    assert "--debug" in result.output
    assert "--no-banner" in result.output


def test_analyze_help_includes_debug_and_no_banner():
    runner = CliRunner()
    result = runner.invoke(cli_module.main, ["analyze", "--help"])

    assert result.exit_code == 0, result.output
    assert "--debug" in result.output
    assert "--no-banner" in result.output


def test_analyze_no_banner_suppresses_ascii_banner(monkeypatch, tmp_path: Path):
    async def fake_local_analysis(*args, **kwargs):
        return _build_report()

    monkeypatch.setattr(cli_module, "_run_local_analysis", fake_local_analysis)

    target_dir = tmp_path / "bundle"
    target_dir.mkdir()
    output_path = tmp_path / "report.json"
    runner = CliRunner()

    default_result = runner.invoke(
        cli_module.main,
        ["analyze", str(target_dir), "--output", str(output_path)],
    )
    assert default_result.exit_code == 0, default_result.output
    assert "JavaScript Security Analyzer" in default_result.output

    no_banner_result = runner.invoke(
        cli_module.main,
        ["analyze", str(target_dir), "--output", str(output_path), "--no-banner"],
    )
    assert no_banner_result.exit_code == 0, no_banner_result.output
    assert "JavaScript Security Analyzer" not in no_banner_result.output
    assert "Local analysis" in no_banner_result.output


def test_scan_debug_enables_debug_logging_and_verbose(monkeypatch, tmp_path: Path):
    seen: dict[str, object] = {}

    async def fake_run_scan(urls, config, quiet, *, verbose=False, debug=False):
        seen["urls"] = list(urls)
        seen["quiet"] = quiet
        seen["verbose"] = verbose
        seen["debug"] = debug
        seen["log_level"] = config.log_level
        seen["config_verbose"] = config.verbose
        return _build_report()

    monkeypatch.setattr(cli_module, "_run_scan", fake_run_scan)

    output_path = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        cli_module.main,
        [
            "scan",
            "https://example.com",
            "--debug",
            "--no-banner",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["debug"] is True
    assert seen["verbose"] is True
    assert seen["log_level"] == LogLevel.DEBUG
    assert seen["config_verbose"] is True
    assert "Debug Runtime Context" in result.output


def test_run_scan_emits_stage_output_in_debug_mode(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(
        cli_module,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    class FakeFinder:
        def __init__(
            self,
            config=None,
            on_stage_start=None,
            on_stage_complete=None,
            on_progress=None,
            on_resume=None,
        ):
            self._on_stage_start = on_stage_start
            self._on_stage_complete = on_stage_complete
            self._on_progress = on_progress
            self._on_resume = on_resume

        async def scan(self, urls):
            if self._on_stage_start:
                self._on_stage_start(PipelineStage.CRAWL)
            if self._on_progress:
                self._on_progress(PipelineStage.CRAWL, 1, 2)
            if self._on_stage_complete:
                self._on_stage_complete(
                    PipelineStage.CRAWL,
                    StageProgress(
                        stage=PipelineStage.CRAWL,
                        total=2,
                        completed=1,
                        failed=0,
                    ),
                )
            return _build_report()

    monkeypatch.setattr(cli_module, "BundleInspector", FakeFinder)

    report = asyncio.run(
        cli_module._run_scan(
            ["https://example.com"],
            Config(),
            quiet=False,
            verbose=True,
            debug=True,
        )
    )

    rendered = output.getvalue()
    assert report.summary.total_findings == 0
    assert "Crawl" in rendered
    assert "1/2" in rendered
