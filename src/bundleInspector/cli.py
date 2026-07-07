"""
BundleInspector CLI interface.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import re
import sys
from time import perf_counter
from pathlib import Path
from typing import Optional

import click
import structlog
from click.core import ParameterSource
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from bundleInspector import __version__
from bundleInspector.config import (
    Config,
    ScopeConfig,
    AuthConfig,
    CrawlerConfig,
    OutputConfig,
    OutputFormat,
    LogLevel,
)
from bundleInspector.core.orchestrator import BundleInspector
from bundleInspector.core.asset_analysis import _build_analyzer
from bundleInspector.core.progress import PipelineStage
from bundleInspector.core.text_decode import decode_js_bytes
from bundleInspector.core.resume_policy import (
    build_local_resume_signature,
    build_stage_state_with_resume_signature,
    checkpoint_matches_resume_signature,
    embed_report_resume_signature,
    report_matches_resume_signature,
)
from bundleInspector.reporter.json_reporter import JSONReporter
from bundleInspector.reporter.html_reporter import HTMLReporter
from bundleInspector.reporter.sarif_reporter import SARIFReporter
from bundleInspector.storage.models import RiskTier, Severity
from bundleInspector.collector.local import LocalCollector, is_local_path


console = Console()
logger = structlog.get_logger()

# Severity ordering (ascending) for the --fail-on CI gate.
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _apply_fail_on_gate(report, fail_on: Optional[str]) -> None:
    """Exit with code 2 if any finding meets or exceeds the --fail-on severity.

    Distinct from exit 1 (tool error / interrupt): exit 2 means the scan ran fine and
    found something at or above the configured gate. Intended for CI. No-op when unset.
    The report is already written by the time this runs, so the artifact is preserved.
    """
    if not fail_on:
        return
    threshold = fail_on.lower()
    if threshold not in _SEVERITY_ORDER:
        return
    min_rank = _SEVERITY_ORDER.index(threshold)
    matched = [
        f for f in (report.findings or [])
        if f.severity.value.lower() in _SEVERITY_ORDER
        and _SEVERITY_ORDER.index(f.severity.value.lower()) >= min_rank
    ]
    if matched:
        console.print(
            f"[red]✗ fail-on gate: {len(matched)} finding(s) at severity "
            f">= {threshold} (exit 2)[/red]"
        )
        sys.exit(2)


STAGE_LABELS = {
    PipelineStage.CRAWL: "Crawl",
    PipelineStage.DOWNLOAD: "Download",
    PipelineStage.NORMALIZE: "Normalize",
    PipelineStage.PARSE: "Parse",
    PipelineStage.ANALYZE: "Analyze",
    PipelineStage.CORRELATE: "Correlate",
    PipelineStage.CLASSIFY: "Classify",
    PipelineStage.REPORT: "Report",
}


def print_banner():
    """Print the banner."""
    banner = r"""
 ____                  _ _      ___                           __                 _
| __ ) _   _ _ __   __| | | ___|_ _|_ __  ___ _ __   ___  ___/ _| ___  _ __   __| |
|  _ \| | | | '_ \ / _` | |/ _ \| || '_ \/ __| '_ \ / _ \/ __| |_ / _ \| '__| / _` |
| |_) | |_| | | | | (_| | |  __/| || | | \__ \ |_) |  __/ (__|  _| (_) | |   | (_| |
|____/ \__,_|_| |_|\__,_|_|\___|___|_| |_|___/ .__/ \___|\___|_|  \___/|_|    \__,_|
                                             |_|
"""
    subtitle = f"v{__version__}  JavaScript Security Analyzer"
    console.print(
        Panel(
            f"[bold blue]{banner}[/bold blue]\n[dim]{subtitle}[/dim]",
            border_style="blue",
        )
    )


def _stage_label(stage: PipelineStage) -> str:
    """Return a user-facing stage label."""
    return STAGE_LABELS.get(stage, stage.value.replace("_", " ").title())


def _configure_cli_logging(*, debug: bool, verbose: bool, quiet: bool) -> None:
    """Configure console logging for the current CLI invocation."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr,
        force=True,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _print_runtime_context(
    *,
    mode: str,
    target_count: int,
    config: Config,
    debug: bool,
    extra_fields: Optional[dict[str, str]] = None,
) -> None:
    """Print a concise runtime header and optional debug details."""
    summary_bits = [f"[bold cyan]{mode}[/bold cyan]", f"targets={target_count}"]

    if mode == "Remote scan":
        summary_bits.extend(
            [
                f"headless={'on' if config.crawler.use_headless else 'off'}",
                f"depth={config.crawler.max_depth}",
                f"rate={config.crawler.rate_limit}s",
            ]
        )

    if config.resume:
        summary_bits.append("resume=on")
    if config.job_id:
        summary_bits.append(f"job={config.job_id}")

    if extra_fields:
        summary_bits.extend(f"{key}={value}" for key, value in extra_fields.items())

    console.print(" | ".join(summary_bits))

    if not debug:
        console.print()
        return

    debug_table = Table(title="Debug Runtime Context", show_header=True)
    debug_table.add_column("Key", style="cyan")
    debug_table.add_column("Value", style="white")

    rows = {
        "log_level": config.log_level.value,
        "cache_dir": str(config.cache_dir),
        "output_format": config.output.format.value,
        "rules_file": str(config.rules.custom_rules_file) if config.rules.custom_rules_file else "-",
        "scope_patterns": str(len(config.scope.allowed_domains)),
    }
    if mode == "Remote scan":
        rows.update(
            {
                "max_pages": str(config.crawler.max_pages),
                "max_js_files": str(config.crawler.max_js_files),
                "explore_routes": str(config.crawler.explore_routes).lower(),
                "max_route_exploration": str(config.crawler.max_route_exploration),
            }
        )
    if extra_fields:
        rows.update(extra_fields)

    for key, value in rows.items():
        debug_table.add_row(key, value)

    console.print(debug_table)
    console.print()


def _force_utf8_console() -> None:
    """Make stdout/stderr use UTF-8 so non-ASCII findings/logs never crash on a
    legacy console codec (e.g. cp949 on Korean Windows). Without this the tool
    would depend on the user exporting PYTHONIOENCODING. Safe no-op when a stream
    doesn't support reconfiguration."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def _silence_proactor_shutdown_noise() -> None:
    """Windows only: the Proactor event loop GCs subprocess/pipe transports AFTER the loop
    is closed (e.g. after asyncio.run() returns). Their __del__ then builds an "unclosed
    transport" repr that calls fileno() on an already-closed pipe, printing harmless
    'Exception ignored in ... __del__ ... I/O operation on closed pipe' / 'Event loop is
    closed' noise -- Playwright's Node driver subprocess triggers this. Swallow ONLY those
    two benign messages in the transport __del__s; re-raise anything else."""
    if sys.platform != "win32":
        return
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport
        from asyncio.base_subprocess import BaseSubprocessTransport
    except Exception:
        return

    _benign = ("Event loop is closed", "I/O operation on closed pipe")

    def _wrap(cls) -> None:
        original = getattr(cls, "__del__", None)
        if original is None or getattr(original, "_bi_silenced", False):
            return

        @functools.wraps(original)
        def _quiet_del(self, *args, **kwargs):
            try:
                original(self, *args, **kwargs)
            except (RuntimeError, ValueError) as exc:
                if str(exc) not in _benign:
                    raise

        _quiet_del._bi_silenced = True
        cls.__del__ = _quiet_del

    _wrap(_ProactorBasePipeTransport)
    _wrap(BaseSubprocessTransport)


@click.group()
@click.version_option(version=__version__)
def main():
    """BundleInspector - JavaScript Security Analysis Tool.

    Analyze JavaScript files to find hidden APIs, secrets,
    internal domains, feature flags, and debug endpoints.
    """
    _force_utf8_console()
    _silence_proactor_shutdown_noise()


@main.command()
@click.pass_context
@click.argument("urls", nargs=-1, required=True)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True),
    help="Load YAML/JSON configuration file",
)
@click.option(
    "--scope", "-s",
    multiple=True,
    help="Allowed domain patterns (e.g., *.example.com)",
)
@click.option(
    "--cookie", "-c",
    multiple=True,
    help="Session cookies (name=value)",
)
@click.option(
    "--header", "-H",
    multiple=True,
    help="HTTP headers (name:value)",
)
@click.option(
    "--depth", "-d",
    default=3,
    help="Crawl depth (default: 3)",
)
@click.option(
    "--rate-limit", "-r",
    default=1.0,
    help="Rate limit in seconds (default: 1.0)",
)
@click.option(
    "--no-headless",
    is_flag=True,
    help="Disable headless browser",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html", "sarif"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Verbose output",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable detailed debug output and internal logging",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Quiet mode (minimal output)",
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Suppress the startup banner",
)
@click.option(
    "--wordlist", "-w",
    type=click.Choice(["all", "endpoints", "paths", "params", "domains", "dirs"]),
    help="Generate fuzzing wordlist (mode: all, endpoints, paths, params, domains, dirs)",
)
@click.option(
    "--api-map",
    is_flag=True,
    help="Generate API map reconstruction",
)
@click.option(
    "--headers-file",
    type=click.Path(exists=True),
    help="Load HTTP headers from file (txt 'Name: Value' or JSON)",
)
@click.option(
    "--bearer-token",
    help="Bearer token for Authorization header",
)
@click.option(
    "--basic-auth",
    help="Basic auth credentials (user:password)",
)
@click.option(
    "--user-agent",
    help="Custom User-Agent string",
)
@click.option(
    "--cookies-file",
    type=click.Path(exists=True),
    help="Import cookies from file (JSON, Netscape, header string)",
)
@click.option(
    "--cookies-from",
    type=click.Choice(["chrome", "firefox", "edge", "chromium"]),
    help="Import cookies from browser",
)
@click.option(
    "--resume",
    is_flag=True,
    help="Reuse the latest stored report for the selected job id when available",
)
@click.option(
    "--job-id",
    help="Explicit job id for cache persistence and resume",
)
@click.option(
    "--rules-file",
    type=click.Path(exists=True),
    help="Load custom regex rules from JSON/YAML",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with code 2 if any finding is at or above this severity (CI gate)",
)
def scan(
    ctx: click.Context,
    urls: tuple[str],
    config_file: Optional[str],
    scope: tuple[str],
    cookie: tuple[str],
    header: tuple[str],
    depth: int,
    rate_limit: float,
    no_headless: bool,
    output: Optional[str],
    format: str,
    verbose: bool,
    debug: bool,
    quiet: bool,
    no_banner: bool,
    wordlist: Optional[str],
    api_map: bool,
    headers_file: Optional[str],
    bearer_token: Optional[str],
    basic_auth: Optional[str],
    user_agent: Optional[str],
    cookies_file: Optional[str],
    cookies_from: Optional[str],
    resume: bool,
    job_id: Optional[str],
    rules_file: Optional[str],
    fail_on: Optional[str],
):
    """Scan URLs for JavaScript security findings.

    Examples:

        bundleInspector scan https://example.com

        bundleInspector scan https://example.com --scope "*.example.com"

        bundleInspector scan https://example.com -c "session=abc123" -o report.json
    """
    base_config = _load_cli_config(config_file)
    effective_quiet = _resolve_base_flag(ctx, base_config, "quiet", quiet)

    # Import cookies from file or browser
    imported_cookies = _import_cookies(cookies_file, cookies_from, effective_quiet, target_urls=list(urls))

    # Import headers from file
    imported_headers = _load_headers_file(headers_file) if headers_file else {}

    # Build config
    config = _build_config(
        ctx=ctx,
        urls=list(urls),
        scope_domains=list(scope),
        cookies=list(cookie),
        headers=list(header),
        depth=depth,
        rate_limit=rate_limit,
        headless=not no_headless,
        output_format=format,
        output_file=output,
        verbose=verbose,
        debug=debug,
        quiet=quiet,
        extra_cookies=imported_cookies,
        extra_headers=imported_headers,
        bearer_token=bearer_token,
        basic_auth=basic_auth,
        user_agent=user_agent,
        base_config=base_config,
        resume=resume,
        job_id=job_id,
        rules_file=rules_file,
    )

    quiet = config.quiet
    verbose = config.verbose
    debug = config.log_level == LogLevel.DEBUG
    format = config.output.format.value
    output = str(config.output.output_file) if config.output.output_file else None
    _configure_cli_logging(debug=debug, verbose=verbose, quiet=quiet)

    if not quiet and not no_banner:
        print_banner()
    if not quiet:
        _print_runtime_context(
            mode="Remote scan",
            target_count=len(urls),
            config=config,
            debug=debug,
        )

    # Display configured headers in verbose mode
    if (verbose or debug) and not quiet:
        _display_auth_info(config, console)

    # Run scan
    try:
        report = asyncio.run(_run_scan(list(urls), config, quiet, verbose=verbose, debug=debug))

        reporter = _build_reporter(config)
        output_path = _resolve_output_path(
            config=config,
            explicit_output=output,
            default_basename="bundleInspector_report",
        )

        content = reporter.generate(report)
        output_path.write_text(content, encoding="utf-8")

        if not quiet:
            _print_summary(report)
            console.print(f"\n[green]Report saved to: {output_path}[/green]")

        # Generate wordlist
        if wordlist:
            _generate_wordlist(report, wordlist, output_path, quiet)

        # Generate API map
        if api_map:
            _generate_api_map(report, output_path, quiet)

        # CI gate: exit non-zero if findings meet the severity threshold.
        _apply_fail_on_gate(report, fail_on)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if verbose:
            raise
        sys.exit(1)


async def _run_scan(
    urls: list[str],
    config: Config,
    quiet: bool,
    *,
    verbose: bool = False,
    debug: bool = False,
):
    """Run the scan with progress display."""
    if quiet:
        finder = BundleInspector(config)
        return await finder.scan(urls)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.fields[stage_label]}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.fields[detail]}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "scan",
            total=100,
            stage_label="Prepare",
            detail="queueing pipeline",
        )

        stage_weights = {
            PipelineStage.CRAWL: 10,
            PipelineStage.DOWNLOAD: 20,
            PipelineStage.NORMALIZE: 10,
            PipelineStage.PARSE: 15,
            PipelineStage.ANALYZE: 30,
            PipelineStage.CORRELATE: 5,
            PipelineStage.CLASSIFY: 5,
            PipelineStage.REPORT: 5,
        }
        stage_order = [
            PipelineStage.CRAWL,
            PipelineStage.DOWNLOAD,
            PipelineStage.NORMALIZE,
            PipelineStage.PARSE,
            PipelineStage.ANALYZE,
            PipelineStage.CORRELATE,
            PipelineStage.CLASSIFY,
            PipelineStage.REPORT,
        ]
        stage_started_at: dict[PipelineStage, float] = {}
        stage_runtime_detail: dict[PipelineStage, str] = {}
        stage_counts: dict[PipelineStage, tuple[int, int]] = {}
        last_debug_detail: dict[PipelineStage, str] = {}

        def _emit(message: str) -> None:
            progress.console.print(message)

        def _compose_detail(stage: PipelineStage, default: str = "starting") -> str:
            runtime_detail = stage_runtime_detail.get(stage, default)
            counts = stage_counts.get(stage)
            if not counts:
                return runtime_detail

            completed, total = counts
            count_detail = f"{completed}/{total}" if total else f"{completed} items"
            if runtime_detail and runtime_detail != "starting":
                return f"{count_detail} | {runtime_detail}"
            return count_detail

        def on_stage_start(stage: PipelineStage):
            label = _stage_label(stage)
            stage_started_at[stage] = perf_counter()
            stage_runtime_detail[stage] = "starting"
            stage_counts.pop(stage, None)
            progress.update(task, stage_label=label, detail=_compose_detail(stage))
            if verbose or debug:
                _emit(f"[cyan]→ {label}[/cyan]")

        def on_stage_complete(stage: PipelineStage, stage_progress):
            label = _stage_label(stage)
            duration = perf_counter() - stage_started_at.get(stage, perf_counter())
            completed = stage_progress.completed + stage_progress.failed
            stage_counts[stage] = (completed, stage_progress.total)
            stage_runtime_detail.pop(stage, None)
            last_debug_detail.pop(stage, None)
            detail = (
                f"{completed}/{stage_progress.total} complete"
                if stage_progress.total
                else "complete"
            )
            progress.update(task, stage_label=label, detail=detail)
            if debug:
                _emit(
                    f"[green]✓ {label}[/green] "
                    f"{completed}/{stage_progress.total or completed} "
                    f"(failed={stage_progress.failed}, {duration:.2f}s)"
                )
            elif verbose:
                _emit(f"[green]✓ {label}[/green] {detail}")

        def on_progress(stage: PipelineStage, completed: int, total: int):
            stage_counts[stage] = (completed, total)
            base = 0
            for ordered_stage in stage_order:
                if ordered_stage == stage:
                    break
                base += stage_weights.get(ordered_stage, 0)

            stage_progress = (completed / max(total, 1)) * stage_weights.get(stage, 0)
            detail = f"{completed}/{total}" if total else f"{completed} items"
            progress.update(
                task,
                completed=base + stage_progress,
                stage_label=_stage_label(stage),
                detail=_compose_detail(stage, default=detail),
            )

        def on_stage_detail(stage: PipelineStage, detail: str):
            stage_runtime_detail[stage] = detail
            progress.update(
                task,
                stage_label=_stage_label(stage),
                detail=_compose_detail(stage, default=detail),
            )
            if debug and last_debug_detail.get(stage) != detail:
                last_debug_detail[stage] = detail
                _emit(f"[dim]{_stage_label(stage)}[/dim] {detail}")

        def on_resume(report) -> None:
            progress.update(
                task,
                completed=100,
                stage_label="Resume",
                detail="reused stored report",
            )
            _emit(
                f"[yellow]Resumed stored report[/yellow] "
                f"(job={config.job_id or report.job_id or 'auto'})"
            )

        finder = BundleInspector(
            config=config,
            on_stage_start=on_stage_start,
            on_stage_complete=on_stage_complete,
            on_progress=on_progress,
            on_stage_detail=on_stage_detail,
            on_resume=on_resume,
        )
        report = await finder.scan(urls)
        progress.update(
            task,
            completed=100,
            stage_label="Complete",
            detail=f"{report.summary.total_findings} findings",
        )
        return report


def _build_config(
    ctx: click.Context,
    urls: list[str],
    scope_domains: list[str],
    cookies: list[str],
    headers: list[str],
    depth: int,
    rate_limit: float,
    headless: bool,
    output_format: str,
    output_file: Optional[str],
    verbose: bool,
    debug: bool,
    quiet: bool,
    extra_cookies: Optional[dict[str, str]] = None,
    extra_headers: Optional[dict[str, str]] = None,
    bearer_token: Optional[str] = None,
    basic_auth: Optional[str] = None,
    user_agent: Optional[str] = None,
    base_config: Optional[Config] = None,
    resume: bool = False,
    job_id: Optional[str] = None,
    rules_file: Optional[str] = None,
) -> Config:
    """Build configuration from CLI options."""
    config = base_config.model_copy(deep=True) if base_config else Config()

    # Parse cookies
    cookie_dict = dict(config.auth.cookies)
    for c in cookies:
        if "=" in c:
            name, value = c.split("=", 1)
            cookie_dict[name.strip()] = value.strip()

    # Merge imported cookies (CLI -c flags take priority)
    if extra_cookies:
        merged = dict(extra_cookies)
        merged.update(cookie_dict)
        cookie_dict = merged

    # Parse headers from -H flags
    header_dict = dict(config.auth.headers)
    for h in headers:
        if ":" in h:
            name, value = h.split(":", 1)
            header_dict[name.strip()] = value.strip()

    # Merge headers from --headers-file (CLI -H flags take priority)
    if extra_headers:
        merged = dict(extra_headers)
        merged.update(header_dict)
        header_dict = merged

    # Parse --basic-auth "user:password"
    basic_auth_tuple = None
    if basic_auth:
        if ":" in basic_auth:
            user, password = basic_auth.split(":", 1)
            basic_auth_tuple = (user, password)
        else:
            raise click.BadParameter(
                "Format must be 'user:password'",
                param_hint="'--basic-auth'",
            )

    if _param_supplied(ctx, "scope"):
        config.scope.allowed_domains = list(scope_domains)
    if _param_supplied(ctx, "cookie") or extra_cookies:
        config.auth.cookies = cookie_dict
    if _param_supplied(ctx, "header") or extra_headers:
        config.auth.headers = header_dict
    if _param_supplied(ctx, "depth"):
        config.crawler.max_depth = depth
    if _param_supplied(ctx, "rate_limit"):
        config.crawler.rate_limit = rate_limit
    if _param_supplied(ctx, "no_headless"):
        config.crawler.use_headless = headless
    if _param_supplied(ctx, "format"):
        config.output.format = OutputFormat(output_format)
    if _param_supplied(ctx, "output"):
        config.output.output_file = Path(output_file) if output_file else None
    if _param_supplied(ctx, "verbose"):
        config.verbose = verbose
    if _param_supplied(ctx, "debug") and debug:
        config.log_level = LogLevel.DEBUG
        config.verbose = True
        config.quiet = False
    if _param_supplied(ctx, "quiet"):
        config.quiet = quiet
    if _param_supplied(ctx, "bearer_token"):
        config.auth.bearer_token = bearer_token
    if _param_supplied(ctx, "basic_auth"):
        config.auth.basic_auth = basic_auth_tuple
    if _param_supplied(ctx, "user_agent") and user_agent:
        config.crawler.user_agent = user_agent
    if _param_supplied(ctx, "resume"):
        config.resume = resume
    if _param_supplied(ctx, "job_id"):
        config.job_id = job_id
    if _param_supplied(ctx, "rules_file") and rules_file:
        config.rules.custom_rules_file = Path(rules_file)

    # Add scope from URLs
    for url in urls:
        config.scope.add_seed_domain(url)

    return config


def _build_local_config(
    ctx: click.Context,
    recursive: bool,
    include_json: bool,
    output_format: str,
    output_file: Optional[str],
    verbose: bool,
    debug: bool,
    quiet: bool,
    base_config: Optional[Config] = None,
    resume: bool = False,
    job_id: Optional[str] = None,
    rules_file: Optional[str] = None,
) -> Config:
    """Build local-analysis configuration from CLI options."""
    config = base_config.model_copy(deep=True) if base_config else Config()

    if _param_supplied(ctx, "format"):
        config.output.format = OutputFormat(output_format)
    if _param_supplied(ctx, "output"):
        config.output.output_file = Path(output_file) if output_file else None
    if _param_supplied(ctx, "verbose"):
        config.verbose = verbose
    if _param_supplied(ctx, "debug") and debug:
        config.log_level = LogLevel.DEBUG
        config.verbose = True
        config.quiet = False
    if _param_supplied(ctx, "quiet"):
        config.quiet = quiet
    if _param_supplied(ctx, "resume"):
        config.resume = resume
    if _param_supplied(ctx, "job_id"):
        config.job_id = job_id
    if _param_supplied(ctx, "rules_file") and rules_file:
        config.rules.custom_rules_file = Path(rules_file)

    return config


def _param_supplied(ctx: click.Context, name: str) -> bool:
    """Check whether a click parameter was explicitly supplied on the CLI."""
    return ctx.get_parameter_source(name) == ParameterSource.COMMANDLINE


def _resolve_base_flag(
    ctx: click.Context,
    base_config: Optional[Config],
    name: str,
    value: bool,
) -> bool:
    """Resolve a boolean CLI flag against an optional base config."""
    if _param_supplied(ctx, name) or not base_config:
        return value
    return bool(getattr(base_config, name))


def _load_cli_config(config_file: Optional[str]) -> Optional[Config]:
    """Load a CLI configuration file when provided."""
    if not config_file:
        return None
    return Config.from_file(Path(config_file))


def _build_reporter(config: Config):
    """Build a reporter from the effective output configuration."""
    report_format = config.output.format.value
    if report_format == "html":
        return HTMLReporter(
            mask_secrets=config.rules.mask_secrets,
            secret_visible_chars=config.rules.secret_visible_chars,
        )
    if report_format == "sarif":
        return SARIFReporter(
            mask_secrets=config.rules.mask_secrets,
            secret_visible_chars=config.rules.secret_visible_chars,
        )
    return JSONReporter(
        include_raw=config.output.include_raw_content,
        mask_secrets=config.rules.mask_secrets,
    )


def _resolve_output_path(
    config: Config,
    explicit_output: Optional[str],
    default_basename: str,
) -> Path:
    """Resolve the final report output path from CLI/config defaults."""
    if explicit_output:
        return Path(explicit_output)

    if config.output.output_file:
        return Path(config.output.output_file)

    extension = "sarif" if config.output.format.value == "sarif" else config.output.format.value
    filename = f"{default_basename}.{extension}"
    if config.output.output_dir:
        return Path(config.output.output_dir) / filename
    return Path(filename)


def _print_summary(report):
    """Print scan summary."""
    console.print()

    # Summary table
    table = Table(title="Scan Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("JS Files Analyzed", str(report.summary.total_js_files))
    table.add_row("Total Findings", str(report.summary.total_findings))
    table.add_row("Duration", f"{report.duration_seconds:.2f}s")

    console.print(table)

    # Severity breakdown
    if report.summary.total_findings > 0:
        console.print()
        sev_table = Table(title="Findings by Severity", show_header=True)
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", style="green")

        severity_colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
            "info": "white",
        }

        for sev, count in report.summary.findings_by_severity.items():
            if count > 0:
                color = severity_colors.get(sev, "white")
                sev_table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    str(count),
                )

        console.print(sev_table)

    if report.findings:
        console.print()
        sorted_findings = sorted(
            report.findings,
            key=lambda f: f.risk_score or 0,
            reverse=True,
        )

        console.print("[bold]Findings:[/bold]")
        max_display = None if len(sorted_findings) <= 20 else 20

        for idx, finding in enumerate(sorted_findings):
            if max_display is not None and idx >= max_display:
                remaining = len(sorted_findings) - max_display
                console.print(f"  ... and {remaining} more findings")
                break
            console.print(f"  {_format_cli_finding_line(finding)}")


def _format_cli_finding_line(finding) -> str:
    """Render a concise one-line finding summary for terminal output."""
    tier = finding.risk_tier.value if finding.risk_tier else "?"
    sev = finding.severity.value.upper() if finding.severity else "?"
    cat = finding.category.value.upper() if finding.category else "?"
    location = finding.evidence.file_url.rsplit("/", 1)[-1] if finding.evidence and finding.evidence.file_url else "?"
    line = finding.evidence.line if finding.evidence else 0
    value = finding.masked_value or finding.extracted_value or ""
    if len(value) > 48:
        value = value[:45] + "..."
    summary = f"[{tier}] [{sev}] [{cat}] {finding.title}"
    if value:
        summary += f" :: {value}"
    summary += f" @ {location}:{line}"

    matched_text = ""
    if isinstance(finding.metadata, dict):
        matched_text = str(finding.metadata.get("matched_text") or "")
    if matched_text and matched_text != finding.extracted_value:
        compact = matched_text.strip().replace("\n", " ")
        if len(compact) > 36:
            compact = compact[:33] + "..."
        summary += f" (match: {compact})"
    return summary


@main.command()
@click.pass_context
@click.argument("paths", nargs=-1, required=True)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True),
    help="Load YAML/JSON configuration file",
)
@click.option(
    "--recursive/--no-recursive", "-r",
    default=True,
    help="Recursively scan directories (default: True)",
)
@click.option(
    "--include-json",
    is_flag=True,
    help="Include JSON files in analysis",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html", "sarif"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Verbose output",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable detailed debug output and internal logging",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Quiet mode (minimal output)",
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Suppress the startup banner",
)
@click.option(
    "--wordlist", "-w",
    type=click.Choice(["all", "endpoints", "paths", "params", "domains", "dirs"]),
    help="Generate fuzzing wordlist (mode: all, endpoints, paths, params, domains, dirs)",
)
@click.option(
    "--api-map",
    is_flag=True,
    help="Generate API map reconstruction",
)
@click.option(
    "--resume",
    is_flag=True,
    help="Reuse the latest stored report for the selected job id when available",
)
@click.option(
    "--job-id",
    help="Explicit job id for cache persistence and resume",
)
@click.option(
    "--rules-file",
    type=click.Path(exists=True),
    help="Load custom regex rules from JSON/YAML",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    help="Exit with code 2 if any finding is at or above this severity (CI gate)",
)
def analyze(
    ctx: click.Context,
    paths: tuple[str],
    config_file: Optional[str],
    recursive: bool,
    include_json: bool,
    output: Optional[str],
    format: str,
    verbose: bool,
    debug: bool,
    quiet: bool,
    no_banner: bool,
    wordlist: Optional[str],
    api_map: bool,
    resume: bool,
    job_id: Optional[str],
    rules_file: Optional[str],
    fail_on: Optional[str],
):
    """Analyze local JavaScript files (no network traffic).

    Supports files, directories, and glob patterns.

    Examples:

        bundleInspector analyze ./dist/bundle.js

        bundleInspector analyze ./src --recursive

        bundleInspector analyze ./dist/*.js ./vendor/*.js

        bundleInspector analyze C:/projects/myapp/static/js/
    """
    base_config = _load_cli_config(config_file)
    config = _build_local_config(
        ctx=ctx,
        recursive=recursive,
        include_json=include_json,
        output_format=format,
        output_file=output,
        verbose=verbose,
        debug=debug,
        quiet=quiet,
        base_config=base_config,
        resume=resume,
        job_id=job_id,
        rules_file=rules_file,
    )

    quiet = config.quiet
    verbose = config.verbose
    debug = config.log_level == LogLevel.DEBUG
    format = config.output.format.value
    output = str(config.output.output_file) if config.output.output_file else None
    _configure_cli_logging(debug=debug, verbose=verbose, quiet=quiet)

    if not quiet and not no_banner:
        print_banner()
    if not quiet:
        _print_runtime_context(
            mode="Local analysis",
            target_count=len(paths),
            config=config,
            debug=debug,
            extra_fields={
                "recursive": str(recursive).lower(),
                "include_json": str(include_json).lower(),
            },
        )

    try:
        report = asyncio.run(_run_local_analysis(
            paths=list(paths),
            recursive=recursive,
            include_json=include_json,
            verbose=verbose,
            debug=debug,
            quiet=quiet,
            config=config,
        ))

        reporter = _build_reporter(config)
        output_path = _resolve_output_path(
            config=config,
            explicit_output=output,
            default_basename="bundleInspector_local_report",
        )

        content = reporter.generate(report)
        output_path.write_text(content, encoding="utf-8")

        if not quiet:
            _print_summary(report)
            console.print(f"\n[green]Report saved to: {output_path}[/green]")

        # Generate wordlist
        if wordlist:
            _generate_wordlist(report, wordlist, output_path, quiet)

        # Generate API map
        if api_map:
            _generate_api_map(report, output_path, quiet)

        # CI gate: exit non-zero if findings meet the severity threshold.
        _apply_fail_on_gate(report, fail_on)

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis cancelled[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if verbose:
            raise
        sys.exit(1)


async def _run_local_analysis(
    paths: list[str],
    recursive: bool,
    include_json: bool,
    verbose: bool,
    quiet: bool,
    debug: bool = False,
    config: Optional[Config] = None,
):
    """Run local file analysis with progress tracking."""
    from datetime import datetime, timezone
    import uuid
    from bundleInspector.normalizer.beautify import Beautifier, NormalizationLevel
    from bundleInspector.normalizer.line_mapping import LineMapper
    from bundleInspector.parser.js_parser import JSParser
    from bundleInspector.parser.ir_builder import IRBuilder
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.correlator.graph import Correlator
    from bundleInspector.classifier.risk_model import RiskClassifier
    from bundleInspector.storage.models import PipelineCheckpoint, Report, ReportSummary
    from bundleInspector.storage.artifact_store import ArtifactStore
    from bundleInspector.storage.finding_store import FindingStore

    start_time = datetime.now(timezone.utc)
    analysis_config = config or Config()
    analysis_config.ensure_dirs()
    analysis_config.job_id = analysis_config.job_id or str(uuid.uuid4())
    resume_signature = build_local_resume_signature(
        analysis_config,
        recursive=recursive,
        include_json=include_json,
    )

    if analysis_config.resume and analysis_config.job_id:
        resumed = await _try_resume_local_report(
            analysis_config.cache_dir,
            analysis_config.job_id,
            paths=paths,
            config=analysis_config,
            recursive=recursive,
            include_json=include_json,
        )
        if resumed is not None:
            if not quiet:
                console.print(f"[yellow]Resumed stored report[/yellow] (job={analysis_config.job_id})")
            return resumed

    artifact_store = None
    finding_store = None
    try:
        job_root = analysis_config.cache_dir / analysis_config.job_id
        artifact_store = ArtifactStore(job_root / "artifacts")
        finding_store = FindingStore(job_root)
    except PermissionError:
        fallback_cache_dir = Path.cwd() / ".bundleInspector" / "cache"
        fallback_cache_dir.mkdir(parents=True, exist_ok=True)
        analysis_config.cache_dir = fallback_cache_dir
        try:
            job_root = analysis_config.cache_dir / analysis_config.job_id
            artifact_store = ArtifactStore(job_root / "artifacts")
            finding_store = FindingStore(job_root)
        except Exception as e:
            logger.warning("local_storage_init_error", error=str(e))
    except Exception as e:
        logger.warning("local_storage_init_error", error=str(e))

    local_stage_order = ["collect", "normalize", "parse", "analyze"]

    async def _store_asset(asset):
        if not artifact_store:
            return
        try:
            await artifact_store.store_js(asset.content, asset.url)
            await artifact_store.store_asset_meta(asset)
        except Exception as e:
            logger.warning("local_asset_store_error", url=asset.url[:100], error=str(e))

    async def _store_ast(asset, ast):
        if not artifact_store:
            return
        try:
            await artifact_store.store_ast(ast, asset.content_hash)
        except Exception as e:
            logger.warning("local_ast_store_error", url=asset.url[:100], error=str(e))

    async def _store_report(report):
        if not finding_store:
            return
        try:
            for finding in report.findings:
                await finding_store.store_finding(finding)
            await finding_store.store_report(report)
        except Exception as e:
            logger.warning("local_report_store_error", report_id=report.id, error=str(e))

    def _local_stage_at_least(stage: str, target: str) -> bool:
        try:
            return local_stage_order.index(stage) >= local_stage_order.index(target)
        except ValueError:
            return False

    async def _load_local_checkpoint():
        if not analysis_config.resume or not finding_store:
            return None
        try:
            checkpoint = await finding_store.get_checkpoint()
            if checkpoint_matches_resume_signature(
                checkpoint,
                seed_urls=paths,
                expected_signature=resume_signature,
            ):
                return checkpoint
            return None
        except Exception as e:
            logger.warning("local_checkpoint_load_error", job_id=analysis_config.job_id, error=str(e))
            return None

    async def _store_local_checkpoint(stage: str, assets=None, findings=None, line_mappers_map=None, stage_state=None):
        if not finding_store:
            return
        checkpoint = PipelineCheckpoint(
            job_id=analysis_config.job_id,
            seed_urls=paths,
            stage=stage,
            asset_hashes=[asset.content_hash for asset in assets or [] if asset.content_hash],
            line_mappers={
                content_hash: mapper.to_dict()
                for content_hash, mapper in (line_mappers_map or {}).items()
            },
            findings=findings or [],
            stage_state=build_stage_state_with_resume_signature(
                stage_state,
                resume_signature,
            ),
        )
        try:
            await finding_store.store_checkpoint(checkpoint)
        except Exception as e:
            logger.warning("local_checkpoint_store_error", stage=stage, error=str(e))

    async def _restore_assets_from_checkpoint(checkpoint):
        restored_assets = []
        if not artifact_store:
            return restored_assets
        for content_hash in checkpoint.asset_hashes:
            asset = await artifact_store.get_asset_meta(content_hash)
            if not asset:
                continue
            # Restore the NORMALIZED (beautified) content, matching the stored AST/line maps;
            # restoring the raw download would run analyze against mismatched source (wrong
            # evidence positions / dropped findings on --resume).
            content = None
            if asset.normalized_hash and asset.normalized_hash != content_hash:
                content = await artifact_store.get_js(asset.normalized_hash)
            if content is None:
                content = await artifact_store.get_js(content_hash)
            if content is not None:
                asset.content = content
            restored_assets.append(asset)
        return restored_assets

    async def _restore_irs_from_assets(assets, allowed_hashes=None):
        irs = []
        if not artifact_store:
            return irs
        for asset in assets:
            if allowed_hashes is not None and asset.content_hash not in allowed_hashes:
                continue
            if not asset.ast_hash:
                continue
            ast = await artifact_store.get_ast(asset.content_hash, asset.ast_hash)
            if not ast:
                continue
            irs.append(IRBuilder().build(ast, asset.url, asset.content_hash))
        return irs

    checkpoint = await _load_local_checkpoint()

    # Collect local files
    collector = LocalCollector(
        recursive=recursive,
        include_json=include_json,
    )

    line_mappers = {}
    if checkpoint and _local_stage_at_least(checkpoint.stage, "collect"):
        assets = await _restore_assets_from_checkpoint(checkpoint)
    else:
        assets = []
        async for asset in collector.collect(paths):
            assets.append(asset)
            if verbose and not quiet:
                console.print(f"  Found: {asset.url}")
            await _store_asset(asset)
        await _store_local_checkpoint("collect", assets=assets)

    if not assets:
        if not quiet:
            console.print("[yellow]No JavaScript files found[/yellow]")
        return Report(
            seed_urls=paths,
            summary=ReportSummary(total_js_files=0, total_findings=0),
        )

    if not quiet:
        console.print(f"[green]Found {len(assets)} JavaScript files[/green]")

    # Set up optional progress display
    progress_bar = None
    task = None
    if not quiet:
        progress_bar = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.fields[stage_label]}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.fields[detail]}"),
            TimeElapsedColumn(),
            console=console,
        )
        progress_bar.start()
        task = progress_bar.add_task(
            "local-analysis",
            total=100,
            stage_label="Collect",
            detail="discovered assets",
        )

    def _announce_stage(label: str, detail: str = "") -> None:
        if verbose or debug:
            suffix = f" {detail}" if detail else ""
            console.print(f"[cyan]→ {label}[/cyan]{suffix}")

    def _complete_stage(label: str, detail: str = "") -> None:
        if verbose or debug:
            suffix = f" {detail}" if detail else ""
            console.print(f"[green]✓ {label}[/green]{suffix}")

    def _update(completed, stage_label=None, detail=None):
        if progress_bar is not None and task is not None:
            kwargs = {"completed": completed}
            if stage_label:
                kwargs["stage_label"] = stage_label
            if detail:
                kwargs["detail"] = detail
            progress_bar.update(task, **kwargs)

    try:
        # Normalize
        _announce_stage("Normalize", f"({len(assets)} assets)")
        _update(0, "Normalize", f"0/{len(assets)} assets")
        beautifier = Beautifier(level=NormalizationLevel.BEAUTIFY)
        if checkpoint and _local_stage_at_least(checkpoint.stage, "normalize"):
            line_mappers = {
                content_hash: LineMapper.from_dict(data)
                for content_hash, data in checkpoint.line_mappers.items()
            }
            _complete_stage("Normalize", "(restored from checkpoint)")
        else:
            partial_normalized_hashes = set((checkpoint.stage_state or {}).get("normalize_complete_hashes", [])) if checkpoint else set()
            if checkpoint and partial_normalized_hashes:
                line_mappers = {
                    content_hash: LineMapper.from_dict(data)
                    for content_hash, data in checkpoint.line_mappers.items()
                }
            processed_normalized_hashes = set(partial_normalized_hashes)
            for i, asset in enumerate(assets):
                if asset.content_hash in processed_normalized_hashes:
                    _update(10 + (i + 1) / len(assets) * 15, "Normalize", f"{i + 1}/{len(assets)} assets")
                    continue
                try:
                    if analysis_config.parser.beautify:
                        original_hash = asset.content_hash or hashlib.sha256(asset.content).hexdigest()
                        content_str = decode_js_bytes(asset.content)
                        if (
                            analysis_config.parser.beautify_max_bytes > 0
                            and len(asset.content) > analysis_config.parser.beautify_max_bytes
                        ):
                            logger.info(
                                "beautify_skipped_large_asset",
                                url=asset.url[:160],
                                size_bytes=len(asset.content),
                                max_bytes=analysis_config.parser.beautify_max_bytes,
                            )
                            result = beautifier.beautify(content_str, level=NormalizationLevel.NONE)
                        else:
                            result = beautifier.beautify(content_str)
                        if result.success:
                            normalized_content = result.content.encode('utf-8')
                            asset.content = normalized_content
                            asset.size = len(normalized_content)
                            asset.content_hash = original_hash
                            asset.normalized_hash = hashlib.sha256(normalized_content).hexdigest()
                            line_mappers[original_hash] = result.line_mapper
                except Exception as e:
                    logger.warning("normalization_error", url=asset.url[:100], error=str(e))
                await _store_asset(asset)
                processed_normalized_hashes.add(asset.content_hash)
                await _store_local_checkpoint(
                    "collect",
                    assets=assets,
                    line_mappers_map=line_mappers,
                    stage_state={"normalize_complete_hashes": sorted(processed_normalized_hashes)},
                )
                _update(10 + (i + 1) / len(assets) * 15, "Normalize", f"{i + 1}/{len(assets)} assets")
            await _store_local_checkpoint("normalize", assets=assets, line_mappers_map=line_mappers)
            _complete_stage("Normalize", f"({len(assets)} assets)")

        # Parse
        _announce_stage("Parse", f"({len(assets)} assets)")
        _update(25, "Parse", f"0/{len(assets)} assets")
        parser = JSParser(tolerant=analysis_config.parser.tolerant)
        ir_builder = IRBuilder()
        if checkpoint and _local_stage_at_least(checkpoint.stage, "parse"):
            ir_list = await _restore_irs_from_assets(assets)
            _complete_stage("Parse", "(restored from checkpoint)")
        else:
            partial_parse_hashes = set((checkpoint.stage_state or {}).get("parse_complete_hashes", [])) if checkpoint else set()
            ir_list = await _restore_irs_from_assets(assets, partial_parse_hashes) if partial_parse_hashes else []
            processed_parse_hashes = set(partial_parse_hashes)
            for i, asset in enumerate(assets):
                if asset.content_hash in processed_parse_hashes and asset.ast_hash:
                    _update(25 + (i + 1) / len(assets) * 20, "Parse", f"{i + 1}/{len(assets)} assets")
                    continue
                try:
                    content_str = decode_js_bytes(asset.content)
                    parse_result = parser.parse(content_str)
                    if parse_result.success and parse_result.ast:
                        ir = ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
                        ir_list.append(ir)
                        asset.parse_success = True
                        # Must match ArtifactStore.store_ast's key (canonical json.dumps),
                        # otherwise get_ast() on --resume never finds the file and every
                        # restored IR is dropped -> resumed report has 0 findings.
                        asset.ast_hash = hashlib.sha256(
                            json.dumps(parse_result.ast, separators=(",", ":"), sort_keys=True).encode()
                        ).hexdigest()[:16]
                        await _store_ast(asset, parse_result.ast)
                        await _store_asset(asset)
                    else:
                        asset.parse_errors.extend(parse_result.errors)
                except Exception as e:
                    asset.parse_errors.append(str(e))
                processed_parse_hashes.add(asset.content_hash)
                await _store_local_checkpoint(
                    "normalize",
                    assets=assets,
                    line_mappers_map=line_mappers,
                    stage_state={"parse_complete_hashes": sorted(processed_parse_hashes)},
                )
                _update(25 + (i + 1) / len(assets) * 20, "Parse", f"{i + 1}/{len(assets)} assets")
            await _store_local_checkpoint("parse", assets=assets, line_mappers_map=line_mappers)
            _complete_stage("Parse", f"({len(ir_list)} IR objects)")

        # Analyze
        _announce_stage("Analyze", f"({len(ir_list)} IR objects)")
        _update(45, "Analyze", f"0/{max(len(ir_list), 1)} assets")
        analyzer = _build_analyzer(analysis_config)

        content_map = {}
        for asset in assets:
            content_map[asset.url] = decode_js_bytes(asset.content)

        if checkpoint and _local_stage_at_least(checkpoint.stage, "analyze"):
            findings = checkpoint.findings
            _complete_stage("Analyze", "(restored from checkpoint)")
        else:
            findings = list(checkpoint.findings) if checkpoint else []
            analyzed_hashes = set((checkpoint.stage_state or {}).get("analyze_complete_hashes", [])) if checkpoint else set()
            for i, ir in enumerate(ir_list):
                if ir.file_hash in analyzed_hashes:
                    _update(45 + (i + 1) / max(len(ir_list), 1) * 40, "Analyze", f"{i + 1}/{max(len(ir_list), 1)} assets")
                    continue
                file_findings = []
                try:
                    context = AnalysisContext(
                        file_url=ir.file_url,
                        file_hash=ir.file_hash,
                        source_content=content_map.get(ir.file_url, ""),
                        is_first_party=True,
                    )
                    # Unified analysis path: the SAME AssetAnalyzer the serial/parallel scan
                    # pipeline uses (analyze -> annotate -> line-map), so there is no
                    # local-vs-orchestrator drift. Enrichment failures degrade metadata but
                    # never drop findings (secured inside analyze_prebuilt_ir).
                    file_findings = analyzer.analyze_prebuilt_ir(
                        ir, context, line_mapper=line_mappers.get(ir.file_hash)
                    )
                except Exception as e:
                    if verbose and not quiet:
                        console.print(f"[yellow]Analysis error: {e}[/yellow]")
                    else:
                        logger.warning("analysis_error", error=str(e))
                findings.extend(file_findings)
                analyzed_hashes.add(ir.file_hash)
                await _store_local_checkpoint(
                    "parse",
                    assets=assets,
                    findings=findings,
                    line_mappers_map=line_mappers,
                    stage_state={"analyze_complete_hashes": sorted(analyzed_hashes)},
                )
                _update(45 + (i + 1) / max(len(ir_list), 1) * 40, "Analyze", f"{i + 1}/{max(len(ir_list), 1)} assets")
            await _store_local_checkpoint("analyze", assets=assets, findings=findings, line_mappers_map=line_mappers)
            _complete_stage("Analyze", f"({len(findings)} findings)")

        # Correlate
        _announce_stage("Correlate")
        _update(85, "Correlate", f"{len(findings)} findings")
        correlator = Correlator()
        correlation_graph = correlator.correlate(findings)
        correlations = correlation_graph.to_correlations()
        clusters = correlation_graph.clusters
        _complete_stage("Correlate", f"({len(correlations)} edges)")

        # Classify
        _announce_stage("Classify", f"({len(findings)} findings)")
        _update(90, "Classify", f"0/{max(len(findings), 1)} findings")
        classifier = RiskClassifier()
        for i, finding in enumerate(findings):
            classifier.classify(finding, correlation_graph)
            _update(90 + (i + 1) / max(len(findings), 1) * 8, "Classify", f"{i + 1}/{max(len(findings), 1)} findings")
        _complete_stage("Classify", f"({len(findings)} findings)")

        # Build report
        _announce_stage("Report")
        _update(98, "Report", "assembling output")
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        report = Report(
            job_id=analysis_config.job_id,
            seed_urls=paths,
            config=embed_report_resume_signature(
                {
                    **analysis_config.to_dict(),
                    "mode": "local_analysis",
                    "paths": paths,
                    "recursive": recursive,
                    "include_json": include_json,
                },
                resume_signature,
            ),
            assets=assets,
            findings=findings,
            correlations=correlations,
            clusters=clusters,
            duration_seconds=duration,
            completed_at=end_time,
        )
        report.compute_summary()
        await _store_report(report)

        _complete_stage("Report", f"({report.summary.total_findings} findings)")
        _update(100, "Complete", f"{report.summary.total_findings} findings")
        return report

    finally:
        if progress_bar is not None:
            progress_bar.stop()


async def _try_resume_local_report(
    cache_dir: Path,
    job_id: str,
    *,
    paths: list[str],
    config: Config,
    recursive: bool,
    include_json: bool,
):
    """Resume local analysis from the latest stored report when available."""
    from bundleInspector.storage.finding_store import FindingStore

    try:
        store = FindingStore(cache_dir / job_id)
        report = await store.get_latest_report()
        expected_signature = build_local_resume_signature(
            config,
            recursive=recursive,
            include_json=include_json,
        )
        if report_matches_resume_signature(
            report,
            seed_urls=paths,
            expected_signature=expected_signature,
        ):
            return report
        return None
    except Exception as e:
        logger.warning("local_resume_report_load_error", job_id=job_id, error=str(e))
        return None


@main.command()
@click.argument("report_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html"]),
    default="html",
    help="Output format",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path",
)
def convert(report_file: str, format: str, output: Optional[str]):
    """Convert report between formats.

    Example:

        bundleInspector convert report.json --format html -o report.html
    """
    report = _load_report_for_convert(report_file)

    # Generate output
    if format == "html":
        reporter = HTMLReporter()
    else:
        reporter = JSONReporter()

    output_path = Path(output) if output else Path(f"report.{format}")
    content = reporter.generate(report)
    output_path.write_text(content, encoding="utf-8")

    console.print(f"[green]Converted to: {output_path}[/green]")


@main.command()
def version():
    """Show version information."""
    console.print(f"BundleInspector version {__version__}")


def _load_report_for_convert(report_file: str):
    """Load a report from JSON or from BundleInspector-generated HTML."""
    content = Path(report_file).read_text(encoding="utf-8-sig")  # tolerate a BOM
    return _parse_report_content_for_convert(content)


def _parse_report_content_for_convert(content: str):
    """Parse report content from JSON or from embedded HTML report data."""
    import json
    import re
    from bundleInspector.storage.models import Report

    stripped = content.lstrip()

    if stripped.startswith("{"):
        data = json.loads(content)
        return Report.model_validate(data)

    html_match = re.search(
        r'<script id="bundleInspector-report-data" type="application/json">(.*?)</script>',
        content,
        re.DOTALL,
    )
    if not html_match:
        raise click.ClickException(
            "HTML report does not contain embedded report data. "
            "Only BundleInspector-generated HTML reports can be converted back to JSON."
        )

    try:
        data = json.loads(html_match.group(1))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Embedded report data is invalid JSON: {exc}") from exc

    return Report.model_validate(data)


def _load_headers_file(path: str) -> dict[str, str]:
    """Load HTTP headers from a file.

    Supports two formats:
    - JSON: {"Name": "Value", ...}
    - Text: One 'Name: Value' per line (# comments allowed)
    """
    import json as _json

    content = Path(path).read_text(encoding="utf-8-sig")  # tolerate a Windows-authored BOM

    # Try JSON first
    stripped = content.strip()
    if stripped.startswith("{"):
        try:
            data = _json.loads(stripped)
            if not isinstance(data, dict):
                raise click.BadParameter(
                    "JSON headers file must contain an object",
                    param_hint="'--headers-file'",
                )
            return {str(k): str(v) for k, v in data.items()}
        except _json.JSONDecodeError as e:
            raise click.BadParameter(
                f"Invalid JSON in headers file: {e}",
                param_hint="'--headers-file'",
            )

    # Parse as text: "Name: Value" per line
    headers: dict[str, str] = {}
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise click.BadParameter(
                f"Invalid header format at line {line_num}: {line!r} "
                "(expected 'Name: Value')",
                param_hint="'--headers-file'",
            )
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    return headers


def _display_auth_info(config: Config, con: Console) -> None:
    """Display configured authentication info in verbose mode."""
    auth = config.auth
    all_headers = auth.get_auth_headers()

    if not all_headers and not auth.cookies:
        return

    con.print("[cyan]Authentication Configuration:[/cyan]")

    if all_headers:
        con.print(f"  Custom headers: {len(all_headers)}")
        for name, value in all_headers.items():
            # Mask sensitive values
            if len(value) > 20:
                display = value[:8] + "..." + value[-4:]
            else:
                display = value
            # Extra masking for auth-related headers
            lower_name = name.lower()
            if lower_name in ("authorization", "x-api-key", "x-auth-token"):
                display = value[:8] + "****" if len(value) > 8 else "****"
            con.print(f"    {name}: {display}")

    if auth.cookies:
        con.print(f"  Cookies: {len(auth.cookies)} configured")

    if config.crawler.user_agent != CrawlerConfig().user_agent:
        con.print(f"  User-Agent: {config.crawler.user_agent[:60]}")

    con.print()


def _import_cookies(
    cookies_file: Optional[str],
    cookies_from: Optional[str],
    quiet: bool,
    target_urls: Optional[list[str]] = None,
) -> dict[str, str]:
    """Import cookies from file or browser."""
    cookies: dict[str, str] = {}

    if cookies_file and cookies_from:
        raise click.UsageError("Cannot specify both --cookies-file and --cookies-from")

    if cookies_file or cookies_from:
        from bundleInspector.core.cookie_import import import_cookies

        source = cookies_file or cookies_from

        # Extract domain from target URLs for browser cookie filtering
        domain = ""
        if cookies_from and target_urls:
            from urllib.parse import urlparse as _urlparse
            for url in target_urls:
                parsed = _urlparse(url)
                if parsed.hostname:
                    domain = parsed.hostname
                    break

        try:
            cookies = import_cookies(source, domain=domain)
            if not quiet:
                console.print(
                    f"[green]Imported {len(cookies)} cookies from "
                    f"{cookies_file or cookies_from}[/green]"
                )
        except Exception as e:
            console.print(f"[yellow]Cookie import warning: {e}[/yellow]")

    return cookies


def _generate_wordlist(
    report,
    mode: str,
    report_path: Path,
    quiet: bool,
) -> None:
    """Generate fuzzing wordlist from report findings."""
    from bundleInspector.reporter.wordlist_reporter import WordlistReporter, generate_wordlists

    if mode == "all":
        wordlists = generate_wordlists(report)
        for wl_mode, content in wordlists.items():
            wl_path = report_path.parent / f"wordlist_{wl_mode}.txt"
            wl_path.write_text(content, encoding="utf-8")
            lines = len(content.strip().split("\n")) if content.strip() else 0
            if not quiet:
                console.print(f"  [green]Wordlist ({wl_mode}): {wl_path} ({lines} entries)[/green]")
    else:
        reporter = WordlistReporter(mode=mode)
        content = reporter.generate(report)
        wl_path = report_path.parent / f"wordlist_{mode}.txt"
        wl_path.write_text(content, encoding="utf-8")
        lines = len(content.strip().split("\n")) if content.strip() else 0
        if not quiet:
            console.print(f"  [green]Wordlist ({mode}): {wl_path} ({lines} entries)[/green]")


def _generate_api_map(report, report_path: Path, quiet: bool) -> None:
    """Generate API map from report findings."""
    from bundleInspector.correlator.api_map import build_api_map

    builder = build_api_map(report)

    # Save JSON API map
    json_path = report_path.parent / "api_map.json"
    json_path.write_text(builder.to_json(), encoding="utf-8")

    # Save ASCII tree
    tree_path = report_path.parent / "api_map.txt"
    tree_content = builder.to_tree_string()
    tree_path.write_text(tree_content, encoding="utf-8")

    if not quiet:
        # Print tree summary to console
        total_domains = len(builder.domains)
        total_endpoints = sum(d.total_endpoints for d in builder.domains.values())
        console.print(f"\n[bold]API Map: {total_domains} domains, {total_endpoints} endpoints[/bold]")

        # Print truncated tree (first 30 lines)
        tree_lines = tree_content.split("\n")
        for line in tree_lines[:30]:
            console.print(f"  {line}")
        if len(tree_lines) > 30:
            console.print(f"  ... ({len(tree_lines) - 30} more lines)")

        console.print(f"  [green]API map saved to: {json_path}[/green]")
        console.print(f"  [green]API tree saved to: {tree_path}[/green]")


if __name__ == "__main__":
    main()
