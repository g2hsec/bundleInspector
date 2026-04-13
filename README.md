# BundleInspector

[Korean](README.ko.md)

BundleInspector is a Python-based JavaScript security analysis tool for:

- remote website scanning that collects JavaScript and analyzes it
- local JavaScript bundle analysis with no network traffic
- extracting endpoints, secrets, domains, feature flags, debug signals, and their correlations

Repository note: test fixtures and regression tests intentionally include fake
secret-like strings so detection, masking, and reporting behavior can be
verified. They are sample values only, not live credentials.

Current shipped implementation status: [docs/IMPLEMENTATION_CHECKLIST.md](docs/IMPLEMENTATION_CHECKLIST.md)  
Current config model: [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md)  
Custom rule reference: [docs/CUSTOM_RULES.md](docs/CUSTOM_RULES.md)  
Synthetic correlator benchmark: [scripts/benchmark_correlator.py](scripts/benchmark_correlator.py)
Remote scan profiles: [examples/scan-profiles/README.md](examples/scan-profiles/README.md)

## Recommended Remote Scan Profiles

- Ultra-safe: [examples/scan-profiles/ultra-safe.yml](examples/scan-profiles/ultra-safe.yml)
  - lowest practical traffic
  - no headless browser
  - best default when program rules are unclear

  Example command:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/ultra-safe.yml \
    --scope "target.example.com" \
    --job-id target-ultra-safe \
    --resume
  ```

- Conservative: [examples/scan-profiles/conservative.yml](examples/scan-profiles/conservative.yml)
  - first-pass triage
  - no headless browser
  - lowest traffic

  Example command:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/conservative.yml \
    --scope "*.example.com" \
    --job-id target-conservative \
    --resume
  ```

- Standard: [examples/scan-profiles/standard.yml](examples/scan-profiles/standard.yml)
  - normal website diagnosis
  - headless initial render enabled
  - no route walking or click exploration

  Example command:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/standard.yml \
    --scope "*.example.com" \
    --job-id target-standard \
    --resume \
    -f html -o report.html
  ```

- Deep: [examples/scan-profiles/deep.yml](examples/scan-profiles/deep.yml)
  - SPA-heavy targets
  - headless route exploration enabled
  - highest coverage and highest traffic of the three

  Example command:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/deep.yml \
    --scope "*.example.com" \
    --job-id target-deep \
    --resume \
    --api-map -w all
  ```

Profile usage guide: [examples/scan-profiles/README.md](examples/scan-profiles/README.md)

### Profile Comparison

These are practical traffic expectations, not hard guarantees. Actual request
volume depends on the target's frontend behavior, number of discovered assets,
and whether rendering triggers additional API calls.

| Profile | Key settings | Typical use | Realistic traffic expectation | Operational risk |
|---|---|---|---|---|
| `ultra-safe` | depth `0`, pages `1`, headless `off`, routes `off`, concurrency `1`, rate limit `5.0s` | unknown rules, strict programs, first contact | usually one entry page plus discovered JS and manifest requests; often tens of requests on a typical site | lowest |
| `conservative` | depth `1`, pages `10`, headless `off`, routes `off`, concurrency `2`, rate limit `2.5s` | first-pass triage | usually tens to low hundreds of requests on a typical site | low |
| `standard` | depth `2`, pages `30`, headless `on`, routes `off`, concurrency `4`, rate limit `1.25s` | normal authorized diagnosis | often low hundreds of requests and may trigger extra frontend/API traffic during render | medium |
| `deep` | depth `3`, pages `80`, headless `on`, routes `on`, concurrency `8`, rate limit `0.75s` | SPA-heavy authorized testing | often hundreds of requests and can rise further if the app lazily loads many chunks or API calls | high |

## Remote Traffic And Safety

- Remote `scan` is not a harmless single-page fetch. It can request HTML pages, probe build manifests, download JavaScript assets, and, when headless mode is enabled, render pages in a real browser context.
- `scan` can therefore create browser-like traffic that is visible in logs, WAFs, and monitoring systems.
- The default `scan` settings are not conservative. The shipped defaults enable headless collection and route exploration, so use an explicit profile instead of relying on defaults for production targets.
- `ultra-safe` is the best default when a program's automation allowance is unclear or when you want the lowest practical traffic.
- `conservative` is the safest starting point and is usually the right first choice for bug bounty or production triage.
- `standard` is often acceptable for authorized diagnosis, but it is still visible and can trigger additional frontend/API traffic during rendering.
- `deep` has the highest coverage and the highest risk of noticeable operational impact. On small services, brittle legacy apps, or heavy SPA targets, it can create enough traffic to be treated as unsafe.
- BundleInspector is not a DoS tool, but misconfigured remote scans can still be too aggressive for some programs. Always follow the target program's rules, traffic limits, and automation policy.
- If you do not have explicit permission for heavier testing, start with `ultra-safe` or `conservative`, narrow `--scope`, keep one target at a time, and stop immediately if latency or error rates increase.

## What It Does

BundleInspector analyzes JavaScript assets to find:

- hidden or undocumented API endpoints
- hard-coded secrets and secret-like tokens
- internal or non-public domains
- feature flags and rollout markers
- debug or administrative indicators

It supports both static and runtime-assisted collection, then normalizes, parses, analyzes, correlates, classifies, and reports the findings.

## Core Features

- Remote scanning with static HTML collection, headless browser collection, and build-manifest discovery
- Local analysis for files, directories, and glob patterns with no network access
- Output formats: JSON, HTML, SARIF
- Optional fuzzing wordlist generation
- Optional API map reconstruction
- Checkpointed `--resume` support with persistent job storage
- Source-map and normalized-to-original evidence mapping when available
- YAML/JSON config loading
- YAML/JSON custom rules, rule directories, and ruleset-style packs
- JSON masking for secrets and secret metadata
- Runtime and inter-module correlation across imports, re-exports, dynamic imports, and runtime execution paths
- Branded CLI banner, stage-aware progress output, and `--verbose` / `--debug` / `--no-banner` execution modes

## Feature Breakdown

### Static collector

- Parses HTML without rendering the page
- Extracts JavaScript from `<script src>`, preload, modulepreload, and inline dynamic-import patterns
- Lowest-impact collection mode

### Headless collector

- Uses Playwright to render the page in a real browser context
- Captures runtime-loaded scripts and chunks that static parsing can miss
- Can optionally explore routes and click common interactive elements to trigger lazy-loaded JavaScript
- This is the most coverage-rich remote collection mode, and also the mode most likely to produce visible browser-like traffic

### Manifest collector

- Probes common build-manifest paths such as webpack, Vite, CRA, and Next.js locations
- Extracts chunk URLs from manifest JSON or JS files
- Useful when the app exposes build metadata even if the page itself does not reference every chunk directly

### Multi-page crawl

- Follows in-scope internal links up to the configured depth
- Keeps page-level progress and supports resume from partial crawl state
- Best used with a narrow scope and conservative depth on production systems

### Download and normalization

- Downloads discovered JavaScript assets
- Beautifies bundles when enabled
- Resolves source maps when available
- Preserves original-source evidence when source-map resolution succeeds

### Parsing and analysis

- Parses JavaScript into AST/IR structures
- Detects endpoints, secrets, domains, feature flags, and debug indicators
- Supports built-in detectors and shipped custom rule formats

### Correlation and risk classification

- Connects findings through same-file, import, runtime, and execution-path relationships
- Reconstructs practical call chains across modules
- Assigns risk scores and tiers to help triage findings

### Resume and job persistence

- Stores assets, ASTs, findings, reports, and stage checkpoints under a persistent job id
- `--resume` can continue from stored work instead of starting over
- `--job-id` lets you keep repeated runs for the same target in a stable cache namespace

### Reporting and extra artifacts

- JSON, HTML, and SARIF reports
- Optional fuzzing wordlists
- Optional API map reconstruction
- HTML reports can be converted back to JSON if they were generated by BundleInspector

### CLI experience

- Shows a branded startup banner by default for `scan` and `analyze`
- Shows a stage-aware progress bar so long-running scans are easier to follow
- `--verbose` prints stage-level detail without flooding the terminal
- `--debug` enables internal logging and deeper execution detail
- `--no-banner` suppresses the startup art when you want cleaner CI or terminal output

## Installation

### Requirements

- Python 3.10+
- Playwright browser binaries for headless collection if you want runtime-assisted remote scans

### Install the package

```bash
git clone https://github.com/g2hsec/bundleInspector.git
cd bundleInspector
pip install -e .
```

### Install development dependencies

```bash
pip install -e ".[dev]"
```

### Install Playwright Chromium for headless scanning

```bash
playwright install chromium
```

## Quick Start

### Remote scan

```bash
bundleInspector scan https://example.com
```

### Local analysis

```bash
bundleInspector analyze ./dist
```

### Save HTML report

```bash
bundleInspector scan https://example.com -f html -o report.html
```

### Save SARIF report

```bash
bundleInspector analyze ./dist -f sarif -o report.sarif
```

### Resume a saved job

```bash
bundleInspector scan https://example.com --job-id example-scan --resume
bundleInspector analyze ./dist --job-id dist-scan --resume
```

## Command Overview

```bash
bundleInspector --help
bundleInspector --version
bundleInspector version
bundleInspector scan ...
bundleInspector analyze ...
bundleInspector convert ...
```

Commands:

- `scan`: scan remote URLs for JavaScript security findings
- `analyze`: analyze local files with no network traffic
- `convert`: convert saved reports between JSON and HTML
- `version`: print version information

## Complete CLI Reference

### Global

```bash
bundleInspector --version
bundleInspector --help
bundleInspector version
```

### `scan`

Syntax:

```bash
bundleInspector scan [OPTIONS] URLS...
```

Examples:

```bash
bundleInspector scan https://example.com
bundleInspector scan https://example.com --scope "*.example.com"
bundleInspector scan https://example.com -c "session=abc123" -o report.json
bundleInspector scan https://example.com --headers-file headers.txt --cookies-file cookies.json
bundleInspector scan https://example.com --bearer-token "$TOKEN" --api-map
bundleInspector scan https://example.com -f html -w all
bundleInspector scan https://example.com --job-id prod-app --resume
bundleInspector scan https://example.com --rules-file ./rules/
bundleInspector scan https://example.com --config config.yml
```

Options:

| Option | Type / Values | Default | Description |
|---|---|---:|---|
| `--config` | `PATH` |  | Load a YAML or JSON configuration file |
| `-s`, `--scope` | repeated `TEXT` |  | Add allowed domain patterns such as `*.example.com` |
| `-c`, `--cookie` | repeated `TEXT` |  | Add cookies as `name=value` |
| `-H`, `--header` | repeated `TEXT` |  | Add headers as `Name: Value` |
| `-d`, `--depth` | `INTEGER` | `3` | Crawl depth |
| `-r`, `--rate-limit` | `FLOAT` | `1.0` | Seconds between requests |
| `--no-headless` | flag | `false` | Disable headless browser collection |
| `-o`, `--output` | `PATH` |  | Explicit report output path |
| `-f`, `--format` | `json`, `html`, `sarif` | `json` | Report format |
| `-v`, `--verbose` | flag | `false` | Verbose output |
| `--debug` | flag | `false` | Enable detailed debug output and internal logging |
| `-q`, `--quiet` | flag | `false` | Minimal output |
| `--no-banner` | flag | `false` | Suppress the startup banner |
| `-w`, `--wordlist` | `all`, `endpoints`, `paths`, `params`, `domains`, `dirs` |  | Generate fuzzing wordlists |
| `--api-map` | flag | `false` | Generate API map files |
| `--headers-file` | `PATH` |  | Load headers from a text or JSON file |
| `--bearer-token` | `TEXT` |  | Set `Authorization: Bearer ...` |
| `--basic-auth` | `TEXT` |  | Set HTTP Basic auth as `user:password` |
| `--user-agent` | `TEXT` |  | Override the crawler user agent |
| `--cookies-file` | `PATH` |  | Import cookies from file |
| `--cookies-from` | `chrome`, `firefox`, `edge`, `chromium` |  | Import cookies from a local browser |
| `--resume` | flag | `false` | Resume from the latest report or stage checkpoints for the job |
| `--job-id` | `TEXT` |  | Explicit persistent job id |
| `--rules-file` | `PATH` |  | Load custom rules from JSON/YAML, a directory, or a ruleset pack |

Remote-scan behavior notes:

- Seed domains are added to scope automatically.
- `--scope` adds additional allowed domains.
- `--resume` reuses stored report/checkpoint state when possible instead of starting from scratch.
- Headless collection is enabled by default unless `--no-headless` is supplied.
- Normalize progress now includes the currently processed asset so long-running bundles are easier to identify.
- `--debug` also surfaces Normalize asset-level detail such as sourcemap checks and heartbeat updates for long-running work.
- `scan` may generate report output plus extra artifacts such as wordlists and API maps.
- Default output is concise: banner, runtime header, progress bar, and final summary.
- `--verbose` adds stage start and completion messages.
- `--debug` implies verbose behavior and also enables internal debug logging.
- `--no-banner` keeps the progress and summary but removes the startup banner.

### Remote authentication and session input

You can combine any of the following:

- `-c/--cookie` for direct `name=value` cookies
- `-H/--header` for direct `Name: Value` headers
- `--headers-file` for bulk headers
- `--bearer-token` for bearer auth
- `--basic-auth user:password` for basic auth
- `--cookies-file` for imported cookies
- `--cookies-from` for browser cookie import

Header file formats for `--headers-file`:

- JSON object:

```json
{
  "Authorization": "Bearer TOKEN",
  "X-API-Key": "abc123"
}
```

- Text file with one `Name: Value` per line:

```text
# comments are allowed
Authorization: Bearer TOKEN
X-API-Key: abc123
```

Cookie file formats for `--cookies-file`:

- JSON cookie arrays such as browser-extension exports
- JSON wrapper objects containing a cookie array
- Netscape/curl cookie files
- raw cookie header strings such as `name1=value1; name2=value2`

Browser import for `--cookies-from`:

- supported values: `chrome`, `firefox`, `edge`, `chromium`
- domain filtering uses the first target URL when available
- for Chromium-family encrypted cookies, exporting cookies to JSON from an extension can be more reliable than direct DB reads

Merge rules:

- CLI `-H/--header` values override duplicate names loaded from `--headers-file`
- CLI `-c/--cookie` values override duplicate names loaded from `--cookies-file` or `--cookies-from`
- `--cookies-file` and `--cookies-from` are mutually exclusive

### `analyze`

Syntax:

```bash
bundleInspector analyze [OPTIONS] PATHS...
```

Examples:

```bash
bundleInspector analyze ./dist/bundle.js
bundleInspector analyze ./src --recursive
bundleInspector analyze ./dist/*.js ./vendor/*.js
bundleInspector analyze C:/projects/myapp/static/js/
bundleInspector analyze ./dist --include-json -f html -o report.html
bundleInspector analyze ./dist --job-id dist-analysis --resume
bundleInspector analyze ./dist --rules-file ./ruleset/meta.yml
bundleInspector analyze ./dist --config config.yml
```

Options:

| Option | Type / Values | Default | Description |
|---|---|---:|---|
| `--config` | `PATH` |  | Load a YAML or JSON configuration file |
| `-r`, `--recursive / --no-recursive` | boolean switch | `recursive` | Recurse into directories |
| `--include-json` | flag | `false` | Include JSON files in local analysis |
| `-o`, `--output` | `PATH` |  | Explicit report output path |
| `-f`, `--format` | `json`, `html`, `sarif` | `json` | Report format |
| `-v`, `--verbose` | flag | `false` | Verbose output |
| `--debug` | flag | `false` | Enable detailed debug output and internal logging |
| `-q`, `--quiet` | flag | `false` | Minimal output |
| `--no-banner` | flag | `false` | Suppress the startup banner |
| `-w`, `--wordlist` | `all`, `endpoints`, `paths`, `params`, `domains`, `dirs` |  | Generate fuzzing wordlists |
| `--api-map` | flag | `false` | Generate API map files |
| `--resume` | flag | `false` | Resume from the latest report or stage checkpoints for the job |
| `--job-id` | `TEXT` |  | Explicit persistent job id |
| `--rules-file` | `PATH` |  | Load custom rules from JSON/YAML, a directory, or a ruleset pack |

Local-analysis behavior notes:

- `analyze` accepts files, directories, and glob patterns.
- Local analysis does not make network requests.
- By default it analyzes JavaScript-like files; use `--include-json` to include JSON assets too.
- `--resume` uses stored checkpoints for collect/normalize/parse/analyze stages when available.
- Default output is concise: banner, runtime header, progress bar, and final summary.
- `--verbose` adds stage start and completion messages.
- `--debug` implies verbose behavior and also enables internal debug logging.
- `--no-banner` keeps the progress and summary but removes the startup banner.

### `convert`

Syntax:

```bash
bundleInspector convert [OPTIONS] REPORT_FILE
```

Examples:

```bash
bundleInspector convert report.json -f html -o report.html
bundleInspector convert report.html -f json -o report.json
```

Options:

| Option | Type / Values | Default | Description |
|---|---|---:|---|
| `-f`, `--format` | `json`, `html` | `html` | Output format |
| `-o`, `--output` | `PATH` |  | Explicit output path |

Important note:

- HTML to JSON conversion works only for BundleInspector-generated HTML reports that contain embedded report data.

### `version`

Syntax:

```bash
bundleInspector version
```

This prints the BundleInspector version string.

## Output Files and Generated Artifacts

### Report formats

- `json`
- `html`
- `sarif`

### Default report filenames

When `-o/--output` is omitted:

- `scan` and `analyze` default to `bundleInspector_report.<format>`
- `convert` defaults to `report.<format>`
- if `output.output_dir` is set in config, the default report filename is written there

### Extra files generated by `--wordlist`

- `wordlist_endpoints.txt`
- `wordlist_paths.txt`
- `wordlist_params.txt`
- `wordlist_domains.txt`
- `wordlist_dirs.txt`

Notes:

- `-w all` generates all non-empty wordlists
- `-w endpoints|paths|params|domains|dirs` generates one wordlist file
- wordlists are written beside the main report

### Extra files generated by `--api-map`

- `api_map.json`
- `api_map.txt`

These are written beside the main report.

## Config Files

You can load a config file in both remote and local modes:

```bash
bundleInspector scan https://example.com --config config.yml
bundleInspector analyze ./dist --config config.json
```

Supported file types:

- `.json`
- `.yaml`
- `.yml`

The shipped YAML subset works even without `PyYAML`.

### Top-level config sections

- `scope`
- `auth`
- `crawler`
- `parser`
- `rules`
- `output`
- `log_level`
- `verbose`
- `quiet`
- `cache_dir`
- `temp_dir`
- `job_id`
- `resume`

### Config summary

#### `scope`

- `allowed_domains`
- `denied_domains`
- `include_subdomains`
- `allowed_paths`
- `denied_paths`
- `third_party_policy`
- `cdn_patterns`

#### `auth`

- `cookies`
- `headers`
- `bearer_token`
- `basic_auth`

#### `crawler`

- `max_depth`
- `max_pages`
- `max_js_files`
- `rate_limit`
- `max_concurrent`
- `request_timeout`
- `page_timeout`
- `max_redirects`
- `follow_redirects`
- `use_headless`
- `headless_wait_time`
- `explore_routes`
- `max_route_exploration`
- `max_retries`
- `retry_delay`
- `user_agent`
- `max_file_size`

#### `parser`

- `tolerant`
- `partial_on_error`
- `extract_strings`
- `extract_calls`
- `extract_imports`
- `build_call_graph`
- `beautify`
- `resolve_sourcemaps`

#### `rules`

- `enabled_categories`
- `custom_rules_file`
- `min_confidence`
- `mask_secrets`
- `secret_visible_chars`
- `entropy_threshold`
- `extract_headers`
- `extract_parameters`

#### `output`

- `format`
- `output_file`
- `output_dir`
- `include_raw_content`
- `include_ast`
- `include_snippets`
- `snippet_context_lines`
- `min_severity`
- `min_risk_tier`

For the current shipped semantics of each key, see [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md).

Important runtime notes:

- `rules.custom_rules_file` can be supplied inside the config file instead of using `--rules-file`
- `output.format`, `output.output_file`, and `output.output_dir` are honored by `scan` and `analyze`
- `output.include_raw_content` is honored by JSON output
- `rules.mask_secrets` is honored by the JSON reporter
- `cache_dir`, `job_id`, and `resume` control persistent job storage and resume behavior

## Custom Rules

Custom rules are supported in both scan and analyze mode:

```bash
bundleInspector scan https://example.com --rules-file custom-rules.json
bundleInspector analyze ./dist --rules-file custom-rules.yaml
bundleInspector scan https://example.com --rules-file ./rules/
bundleInspector analyze ./dist --rules-file ./ruleset/meta.yml
```

Supported `--rules-file` targets:

- a single JSON file
- a single YAML file
- a directory containing rule files
- a ruleset-style `meta.yml` whose sibling `rules/` directory contains the actual rules

You can also load the same rule source through config by setting `rules.custom_rules_file`.

Supported shipped matcher families:

- `regex`
- `ast_pattern`
- `semantic`

The full documented matcher surface is in [docs/CUSTOM_RULES.md](docs/CUSTOM_RULES.md).

## Detection Coverage

BundleInspector currently detects and correlates signals in these categories:

- `endpoint`
- `secret`
- `domain`
- `flag`
- `debug`

Feature coverage includes:

- static and runtime-assisted JS discovery
- endpoint extraction from common HTTP, request-config, helper-flow, `Request`, `URL`, `WebSocket`, and `XMLHttpRequest` patterns
- secret detection with context filtering to reduce example/mock/docs false positives
- source-map-backed original evidence when available
- inter-module and runtime execution correlation
- JSON/HTML/SARIF reporting

## Risk Tiers

Findings are also classified into practical triage tiers:

| Tier | Meaning | Typical examples |
|---|---|---|
| `P0` | Critical, immediate action needed | production cloud keys, live payment keys, private keys |
| `P1` | High, action needed | internal production domains, real personal access tokens |
| `P2` | Medium, investigate | hidden admin flows, staging URLs, sensitive debug surfaces |
| `P3` | Low, informational | health-check endpoints, public but useful API signals |

## Secret Family Examples

BundleInspector's shipped secret coverage spans many practical families, including:

- cloud credentials such as AWS, Azure, and Google Cloud
- AI and model-service tokens such as OpenAI and Anthropic
- source control and CI/CD credentials such as GitHub, GitLab, npm, and PyPI
- payment-service secrets such as Stripe webhook or live secret keys
- communication and notification credentials such as Slack, Discord, and Mailgun
- database connection strings and access tokens
- monitoring and telemetry credentials
- JWTs and private-key material

## Architecture Overview

High-level package layout:

```text
bundleInspector/
  collector/    remote and local asset collection
  normalizer/   beautify and source-map handling
  parser/       AST parsing and IR construction
  rules/        built-in and custom rule execution
  correlator/   inter-finding graph and clustering
  classifier/   risk scoring and tier assignment
  reporter/     JSON, HTML, and SARIF reporting
  core/         orchestration, progress, rate limiting, and security controls
  storage/      persistent artifacts, reports, and checkpoints
```

## Python API

Basic example:

```python
import asyncio
from bundleInspector import BundleInspector, Config


async def main():
    finder = BundleInspector(Config())
    report = await finder.scan(["https://example.com"])

    print(report.summary.total_js_files)
    print(report.summary.total_findings)

    for finding in report.findings[:5]:
        print(finding.category, finding.title, finding.extracted_value)


asyncio.run(main())
```

Local config example:

```python
from bundleInspector import BundleInspector, Config, ScopeConfig, AuthConfig

config = Config(
    scope=ScopeConfig(allowed_domains=["*.example.com"]),
    auth=AuthConfig(
        cookies={"session": "abc123"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    ),
)
```

Exports available from `bundleInspector`:

- `BundleInspector`
- `Config`
- `ScopeConfig`
- `AuthConfig`
- `JSAsset`
- `Finding`
- `Evidence`
- `Correlation`
- `Cluster`
- `Report`
- `Severity`
- `Confidence`
- `Category`
- `RiskTier`

## Operational Notes

- Local `analyze` mode does not generate network traffic.
- Remote `scan` mode can use both static and headless collection.
- Secret masking is enabled for JSON output by default.
- If the default cache directory is not writable, BundleInspector falls back to a workspace-local `.bundleInspector/cache`.
- Resume state includes reports and stage checkpoints so interrupted jobs can continue from stored progress.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src/bundleInspector
mypy src/bundleInspector
```

## Disclaimer

Use BundleInspector only on systems and targets you are authorized to assess. The user
is responsible for choosing safe scan depth, traffic profile, and credential
handling for the target environment.

## License

MIT

## Support

If BundleInspector is useful in your workflow, consider starring the repository on GitHub. It helps other people find the project and makes continued maintenance easier to justify.
