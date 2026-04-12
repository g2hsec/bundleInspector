"""
BundleInspector CLI interface.
"""

from __future__ import annotations

import asyncio
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
from bundleInspector.core.progress import PipelineStage
from bundleInspector.reporter.json_reporter import JSONReporter
from bundleInspector.reporter.html_reporter import HTMLReporter
from bundleInspector.reporter.sarif_reporter import SARIFReporter
from bundleInspector.storage.models import RiskTier, Severity
from bundleInspector.collector.local import LocalCollector, is_local_path


console = Console()
logger = structlog.get_logger()


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


@click.group()
@click.version_option(version=__version__)
def main():
    """BundleInspector - JavaScript Security Analysis Tool.

    Analyze JavaScript files to find hidden APIs, secrets,
    internal domains, feature flags, and debug endpoints.
    """
    pass


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

        def _emit(message: str) -> None:
            progress.console.print(message)

        def on_stage_start(stage: PipelineStage):
            label = _stage_label(stage)
            stage_started_at[stage] = perf_counter()
            progress.update(task, stage_label=label, detail="starting")
            if verbose or debug:
                _emit(f"[cyan]→ {label}[/cyan]")

        def on_stage_complete(stage: PipelineStage, stage_progress):
            label = _stage_label(stage)
            duration = perf_counter() - stage_started_at.get(stage, perf_counter())
            completed = stage_progress.completed + stage_progress.failed
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
                detail=detail,
            )

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
        return HTMLReporter()
    if report_format == "sarif":
        return SARIFReporter()
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

    # Top findings
    if report.findings:
        console.print()
        console.print("[bold]Top Findings:[/bold]")

        # Sort by risk score
        sorted_findings = sorted(
            report.findings,
            key=lambda f: f.risk_score or 0,
            reverse=True,
        )[:5]

        for finding in sorted_findings:
            tier = finding.risk_tier.value if finding.risk_tier else "?"
            sev = finding.severity.value.upper() if finding.severity else "?"
            console.print(
                f"  [{tier}] [{sev}] {finding.title[:60]}"
            )


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
    from bundleInspector.parser.js_parser import JSParser
    from bundleInspector.parser.ir_builder import IRBuilder
    from bundleInspector.rules.engine import RuleEngine
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

    if analysis_config.resume and analysis_config.job_id:
        resumed = await _try_resume_local_report(
            analysis_config.cache_dir,
            analysis_config.job_id,
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

    def _annotate_finding_metadata(ir, findings):
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
            *_build_import_bindings(ir),
            *commonjs_require_bindings,
        ]
        function_defs = ir.function_defs
        scope_parents = _build_scope_parent_map(function_defs)
        if ir.raw_ast:
            seen_binding_keys = {
                _import_binding_key(binding)
                for binding in import_bindings
            }
            for _ in range(4):
                alias_bindings = _collect_import_alias_bindings(
                    ir.raw_ast,
                    import_bindings,
                    scope_parents,
                )
                fresh_bindings = [
                    binding
                    for binding in alias_bindings
                    if _import_binding_key(binding) not in seen_binding_keys
                ]
                if not fresh_bindings:
                    break
                import_bindings.extend(fresh_bindings)
                seen_binding_keys.update(
                    _import_binding_key(binding)
                    for binding in fresh_bindings
                )
        commonjs_exports, commonjs_export_scopes = build_commonjs_export_metadata(ir)
        default_object_exports = list(dict.fromkeys([
            *build_default_object_export_members(ir),
            *build_commonjs_default_object_export_members(ir),
        ]))
        named_object_exports = _merge_named_object_exports(
            build_named_object_export_members(ir),
            build_commonjs_named_object_export_members(ir),
        )
        exports = list(dict.fromkeys([
            *[exp.name for exp in ir.exports if exp.name],
            *commonjs_exports,
        ]))
        export_scopes = _merge_export_scopes(
            build_export_scope_map(ir),
            commonjs_export_scopes,
        )
        call_names = [call.full_name or call.name for call in ir.function_calls if (call.full_name or call.name)]
        scoped_calls = _build_scoped_calls(ir)
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
                _find_enclosing_scope(finding.evidence.line, function_defs),
            )

    def _merge_export_scopes(*scope_maps):
        merged = {}
        for scope_map in scope_maps:
            if not isinstance(scope_map, dict):
                continue
            for export_name, scopes in scope_map.items():
                if not isinstance(export_name, str):
                    continue
                merged.setdefault(export_name, set()).update(
                    scope for scope in (scopes or [])
                    if isinstance(scope, str) and scope
                )
        return {
            export_name: sorted(scopes)
            for export_name, scopes in merged.items()
            if scopes
        }

    def _merge_named_object_exports(*member_maps):
        merged = {}
        for member_map in member_maps:
            if not isinstance(member_map, dict):
                continue
            for export_name, members in member_map.items():
                if not isinstance(export_name, str):
                    continue
                merged.setdefault(export_name, set()).update(
                    member for member in (members or [])
                    if isinstance(member, str) and member
                )
        return {
            export_name: sorted(members)
            for export_name, members in merged.items()
            if members
        }

    def _build_import_bindings(ir):
        bindings = []
        for import_decl in ir.imports:
            if not import_decl.source:
                continue
            for specifier in import_decl.specifiers:
                binding = _parse_import_specifier(import_decl.source, specifier)
                if binding:
                    bindings.append(binding)
        if ir.raw_ast:
            bindings.extend(_collect_dynamic_import_bindings(ir.raw_ast))
        return bindings

    def _parse_import_specifier(source, specifier):
        value = (specifier or "").strip()
        if not value:
            return None
        if value.startswith("default as "):
            return {"source": source, "imported": "default", "local": value[len("default as "):], "kind": "default"}
        if value.startswith("* as "):
            return {"source": source, "imported": "*", "local": value[len("* as "):], "kind": "namespace"}
        if " as " in value:
            imported, local = value.split(" as ", 1)
            return {"source": source, "imported": imported.strip(), "local": local.strip(), "kind": "named"}
        return {"source": source, "imported": value, "local": value, "kind": "named"}

    def _collect_dynamic_import_bindings(node, scope="global"):
        bindings = []
        if not isinstance(node, dict):
            return bindings

        node_type = node.get("type", "")
        if node_type in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            function_scope = _derive_dynamic_scope_name(node)
            for param in node.get("params", []):
                bindings.extend(_collect_dynamic_import_bindings(param, function_scope))
            body = node.get("body")
            if body:
                bindings.extend(_collect_dynamic_import_bindings(body, function_scope))
            return bindings

        if node_type == "VariableDeclarator":
            bindings.extend(
                _extract_dynamic_import_binding_targets(
                    node.get("id"),
                    node.get("init"),
                    scope,
                )
            )
        elif node_type == "AssignmentExpression" and node.get("operator") == "=":
            bindings.extend(
                _extract_dynamic_import_binding_targets(
                    node.get("left"),
                    node.get("right"),
                    scope,
                )
            )
        elif node_type == "CallExpression":
            bindings.extend(_extract_dynamic_import_then_bindings(node))

        for key, value in node.items():
            if key in {"loc", "range", "raw"}:
                continue
            if isinstance(value, dict):
                bindings.extend(_collect_dynamic_import_bindings(value, scope))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        bindings.extend(_collect_dynamic_import_bindings(item, scope))

        return bindings

    def _extract_dynamic_import_then_bindings(node):
        if not isinstance(node, dict):
            return []
        callee = node.get("callee") or {}
        if callee.get("type") != "MemberExpression":
            return []
        property_name = _extract_pattern_name(callee.get("property"))
        if property_name != "then":
            return []
        source_object = callee.get("object")
        source = _extract_dynamic_import_source(source_object)
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
            callback_scope = _derive_dynamic_scope_name(arg)
            return _extract_dynamic_import_binding_targets(
                params[0],
                source_object,
                callback_scope,
            )
        return []

    def _extract_dynamic_import_binding_targets(target, value, scope):
        source = _extract_dynamic_import_source(value)
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

        bindings = []
        for prop in target.get("properties", []):
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                continue
            imported = _extract_pattern_name(prop.get("key"))
            local = _extract_pattern_target_name(prop.get("value"))
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

    def _extract_dynamic_import_source(node):
        if not isinstance(node, dict):
            return ""

        node_type = node.get("type", "")
        if node_type == "AwaitExpression":
            return _extract_dynamic_import_source(node.get("argument"))
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

    def _collect_import_alias_bindings(node, existing_bindings, scope_parents, scope="global"):
        bindings = []
        if not isinstance(node, dict):
            return bindings

        node_type = node.get("type", "")
        if node_type in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            function_scope = _derive_dynamic_scope_name(node)
            for param in node.get("params", []):
                bindings.extend(
                    _collect_import_alias_bindings(param, existing_bindings, scope_parents, function_scope)
                )
            body = node.get("body")
            if body:
                bindings.extend(
                    _collect_import_alias_bindings(body, existing_bindings, scope_parents, function_scope)
                )
            return bindings

        if node_type == "VariableDeclarator":
            bindings.extend(
                _extract_import_alias_bindings(
                    node.get("id"),
                    node.get("init"),
                    existing_bindings,
                    scope_parents,
                    scope,
                )
            )
        elif node_type == "AssignmentExpression" and node.get("operator") == "=":
            bindings.extend(
                _extract_import_alias_bindings(
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
                bindings.extend(_collect_import_alias_bindings(value, existing_bindings, scope_parents, scope))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        bindings.extend(_collect_import_alias_bindings(item, existing_bindings, scope_parents, scope))

        return bindings

    def _extract_import_alias_bindings(target, value, existing_bindings, scope_parents, scope):
        alias_bindings = []
        direct_alias = _extract_identifier_import_alias_binding(
            target,
            value,
            existing_bindings,
            scope_parents,
            scope,
        )
        if direct_alias:
            alias_bindings.append(direct_alias)

        member_alias = _extract_import_member_alias_binding(
            target,
            value,
            existing_bindings,
            scope_parents,
            scope,
        )
        if member_alias:
            alias_bindings.append(member_alias)

        alias_bindings.extend(
            _extract_object_pattern_import_alias_bindings(
                target,
                value,
                existing_bindings,
                scope_parents,
                scope,
            )
        )
        return alias_bindings

    def _extract_identifier_import_alias_binding(target, value, existing_bindings, scope_parents, scope):
        local = _extract_pattern_target_name(target)
        if not local or not isinstance(value, dict) or value.get("type") != "Identifier":
            return None

        value_name = str(value.get("name") or "").strip()
        if not value_name or value_name == local:
            return None

        for binding in existing_bindings:
            if not _binding_matches_local(binding, value_name, scope_parents, scope):
                continue
            return _clone_import_binding(
                binding,
                local=local,
                scope=scope,
                is_alias=True,
            )
        return None

    def _extract_object_pattern_import_alias_bindings(target, value, existing_bindings, scope_parents, scope):
        if not isinstance(target, dict) or target.get("type") != "ObjectPattern":
            return []
        if not isinstance(value, dict) or value.get("type") != "Identifier":
            return []

        value_name = str(value.get("name") or "").strip()
        if not value_name:
            return []

        bindings = []
        source_bindings = [
            binding
            for binding in existing_bindings
            if _binding_matches_local(binding, value_name, scope_parents, scope)
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
                imported = _extract_pattern_name(prop.get("key"))
                local = _extract_pattern_target_name(prop.get("value"))
                if not imported or not local:
                    continue
                kind = "default" if imported == "default" else "named"
                bindings.append(
                    _clone_import_binding(
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

    def _binding_matches_local(binding, local_name, scope_parents, scope):
        binding_local = str(binding.get("local") or "").strip()
        binding_scope = str(binding.get("scope") or "global").strip() or "global"
        if binding_local != local_name:
            return False
        if binding_scope == "global":
            return True
        if binding_scope == scope:
            return True
        return binding_scope in scope_parents.get(scope, [])

    def _clone_import_binding(binding, *, local, scope, imported=None, kind=None, is_alias=False, is_destructured_alias=False):
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

    def _import_binding_key(binding):
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

    def _extract_import_member_alias_binding(target, value, existing_bindings, scope_parents, scope):
        local = _extract_pattern_target_name(target)
        if not local or not isinstance(value, dict) or value.get("type") != "MemberExpression":
            return None

        object_node = value.get("object")
        property_name = _extract_pattern_name(value.get("property"))
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
            if binding_scope != "global" and binding_scope != scope and binding_scope not in scope_parents.get(scope, []):
                continue
            return _clone_import_binding(
                binding,
                imported=property_name,
                local=local,
                kind="named",
                scope=scope,
                is_alias=True,
                is_destructured_alias=False,
            ) | {"is_member_alias": True}
        return None

    def _extract_pattern_name(node):
        if not isinstance(node, dict):
            return ""
        node_type = node.get("type", "")
        if node_type == "Identifier":
            return str(node.get("name") or "").strip()
        if node_type == "Literal":
            value = node.get("value")
            return value.strip() if isinstance(value, str) else ""
        return ""

    def _extract_pattern_target_name(node):
        if not isinstance(node, dict):
            return ""
        node_type = node.get("type", "")
        if node_type == "Identifier":
            return str(node.get("name") or "").strip()
        if node_type == "AssignmentPattern":
            return _extract_pattern_target_name(node.get("left"))
        return ""

    def _derive_dynamic_scope_name(node):
        node_type = node.get("type", "")
        prefix_map = {
            "FunctionDeclaration": "function",
            "FunctionExpression": "function_expr",
            "ArrowFunctionExpression": "arrow",
        }
        prefix = prefix_map.get(node_type, "function")
        function_id = (node.get("id") or {}).get("name")
        if function_id:
            return f"function:{function_id}"
        line = ((node.get("loc") or {}).get("start") or {}).get("line", 0)
        return f"function:{prefix}@{line}" if line else "global"

    def _build_scoped_calls(ir):
        scoped_calls = {}
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

    def _find_enclosing_scope(line, function_defs):
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

    def _build_scope_parent_map(function_defs):
        normalized_defs = [
            func_def for func_def in function_defs
            if getattr(func_def, "scope", "") and getattr(func_def, "line", 0) > 0
        ]
        if not normalized_defs:
            return {}

        parent_map = {}
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

        scope_parents = {}
        for scope in parent_map:
            ancestors = []
            seen = set()
            current = parent_map.get(scope)
            while current and current not in seen:
                ancestors.append(current)
                seen.add(current)
                current = parent_map.get(current)
            if ancestors:
                scope_parents[scope] = ancestors
        return scope_parents

    def _local_stage_at_least(stage: str, target: str) -> bool:
        try:
            return local_stage_order.index(stage) >= local_stage_order.index(target)
        except ValueError:
            return False

    async def _load_local_checkpoint():
        if not analysis_config.resume or not finding_store:
            return None
        try:
            return await finding_store.get_checkpoint()
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
            stage_state=stage_state or {},
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
                        content_str = asset.content.decode('utf-8', errors='replace')
                        result = beautifier.beautify(content_str)
                        if result.success:
                            asset.content = result.content.encode('utf-8')
                            asset.size = len(asset.content)
                            asset.compute_hash()
                            asset.normalized_hash = hashlib.sha256(asset.content).hexdigest()
                            line_mappers[asset.content_hash] = result.line_mapper
                except Exception:
                    pass
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
                    content_str = asset.content.decode('utf-8', errors='replace')
                    parse_result = parser.parse(content_str)
                    if parse_result.success and parse_result.ast:
                        ir = ir_builder.build(parse_result.ast, asset.url, asset.content_hash)
                        ir_list.append(ir)
                        asset.parse_success = True
                        asset.ast_hash = hashlib.sha256(str(parse_result.ast).encode()).hexdigest()[:16]
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
        engine = RuleEngine(analysis_config.rules)
        engine.register_defaults()

        content_map = {}
        for asset in assets:
            content_map[asset.url] = asset.content.decode('utf-8', errors='replace')

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
                try:
                    source_content = content_map.get(ir.file_url, "")
                    context = AnalysisContext(
                        file_url=ir.file_url,
                        file_hash=ir.file_hash,
                        source_content=source_content,
                        is_first_party=True,
                    )
                    file_findings = engine.analyze(ir, context)
                    _annotate_finding_metadata(ir, file_findings)
                    line_mapper = line_mappers.get(ir.file_hash)
                    if line_mapper:
                        for finding in file_findings:
                            if finding.evidence.line > 0:
                                original_line, original_column = line_mapper.get_original(
                                    finding.evidence.line,
                                    finding.evidence.column,
                                )
                                finding.evidence.original_line = original_line
                                finding.evidence.original_column = original_column
                    findings.extend(file_findings)
                except Exception as e:
                    if verbose and not quiet:
                        console.print(f"[yellow]Analysis error: {e}[/yellow]")
                    else:
                        logger.warning("analysis_error", error=str(e))
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
            config={
                **analysis_config.to_dict(),
                "mode": "local_analysis",
                "paths": paths,
                "recursive": recursive,
                "include_json": include_json,
            },
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


async def _try_resume_local_report(cache_dir: Path, job_id: str):
    """Resume local analysis from the latest stored report when available."""
    from bundleInspector.storage.finding_store import FindingStore

    try:
        store = FindingStore(cache_dir / job_id)
        return await store.get_latest_report()
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
    content = Path(report_file).read_text(encoding="utf-8")
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

    content = Path(path).read_text(encoding="utf-8")

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

