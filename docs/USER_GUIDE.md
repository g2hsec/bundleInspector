# 📖 BundleInspector — User Guide

Complete reference for installing, configuring, and running BundleInspector.
For a quick overview, see the [README](../README.md).

---

## Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [MCP Server](#mcp-server)
- [🧭 CLI Reference](#-cli-reference)
- [Configuration](#configuration)
- [Scan Profiles](#scan-profiles)
- [🛡️ Traffic & Safety](#-traffic--safety)
- [🔬 Detection Coverage](#-detection-coverage)
- [Output & Reports](#output--reports)
- [Performance](#performance)
- [Authentication & Sessions](#authentication--sessions)
- [Custom Rules](#custom-rules)
- [Python API](#python-api)
- [How It Works](#how-it-works)
- [Notes & Limitations](#notes--limitations)
- [Troubleshooting](#troubleshooting)

---

## Overview

BundleInspector is a Python security/recon scanner for JavaScript bundles. It works two ways:

- **`scan`** — crawls a live site (static HTML collector + optional headless Playwright render + build-manifest probing), downloads the discovered JavaScript, and analyzes it.
- **`analyze`** — runs the same analysis engine over local files, directories, or globs with **no network traffic**.

Downloaded bytes are retained under their content hash. Eligible plain JavaScript may use a
whitespace-reflowed derivative after a raw-literal preservation check; TS/JSX-shaped input and any
candidate that loses a literal stay byte-equivalent to the decoded source. The selected analysis
content is parsed into an AST and passed through rules for **endpoints, secrets, domains, flags,
debug surface, sinks/dataflow, and uploads**, then enriched with seven recon enhancements and
risk-tiered `P0–P3`. Source-map originals are analyzed as bounded virtual sources when available.

> **Version:** `0.1.0` · **Python:** `3.10-3.13` (`>=3.10,<3.14`) · **License:** MIT

---

## Installation

```bash
git clone https://github.com/g2hsec/bundleInspector.git
cd bundleInspector
python -m venv .venv
```

Activate the virtualenv (pick your shell), then install:

| Shell | Activate |
|---|---|
| macOS / Linux (bash/zsh) | `source .venv/bin/activate` |
| Windows PowerShell | `.venv\Scripts\Activate.ps1` |
| Windows cmd | `.venv\Scripts\activate.bat` |

```bash
python -m pip install -e .
python -m playwright install chromium          # required for headless scanning
```

On a clean Linux host or container, install Chromium and its OS libraries together:

```bash
python -m playwright install --with-deps chromium
```

> **Windows PowerShell 5.1** does not support `&&`, and `source` is a Unix-shell command. Run each command on its own line. If activation fails with *"running scripts is disabled on this system"*, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once in the session, then re-run `.venv\Scripts\Activate.ps1`.

Development install (tests, linting):

```bash
pip install -e ".[dev]"              # pytest, pytest-asyncio, pytest-cov, ruff, mypy, pre-commit
```

**Parser selection.** The required Tree-sitter backends handle structurally hinted JavaScript,
JSX, TypeScript, and TSX first. The caller's `language_hint` selects the matching grammar, so modern
syntax is not routed through a legacy parser first. Unhinted plain JavaScript uses a complete legacy
ESTree result when available; an incomplete legacy result is retried with Tree-sitter. An optional
[Acorn](https://github.com/acornjs/acorn) ESTree fast path can be enabled before the legacy Esprima
path; it needs Node.js on `PATH` and a resolvable `acorn` package:

```bash
npm install acorn                     # anywhere Node can resolve it (or on NODE_PATH)
export BUNDLEINSPECTOR_NATIVE_PARSER=1
```

If Node/Acorn is unavailable, parsing continues through Esprima and the structural recovery path.
Every parse result reports the selected backend, completeness, capability gaps, and truncation
reasons; partial or lexical recovery is never presented as a complete structural parse.

**Runtime dependencies** (installed automatically): `httpx`, `httpcore`, `playwright`,
`beautifulsoup4`, `lxml`, `esprima`, `jsbeautifier`, `pydantic`, `click`, `rich`, `structlog`,
`jinja2`, `aiofiles`, `regex`, `cryptography`, `PyYAML`, `tree-sitter`,
`tree-sitter-javascript`, and `tree-sitter-typescript`. Node.js/Acorn remains optional.

---

## Quick Start

```bash
# Remote scan, scoped to a domain and its subdomains
bundleInspector scan https://target.example.com --scope "*.example.com"

# Local, offline analysis of a build directory
bundleInspector analyze ./dist

# HTML report
bundleInspector scan https://target.example.com -f html -o report.html

# SARIF for GitHub Code Scanning / CI
bundleInspector analyze ./dist -f sarif -o findings.sarif

# Generate fuzzing wordlists + an API map alongside the report
bundleInspector scan https://target.example.com -w all --api-map

# Long scan you can stop and resume
bundleInspector scan https://target.example.com --job-id acme --resume
```

---

## MCP Server

The shipped MCP adapter is usable as a **local stdio, read-only public-report projection**. Install
the extra from this source checkout, create a persisted CLI report, and configure the MCP client to
launch the entry point:

```bash
python -m pip install -e ".[mcp]"
bundleInspector analyze ./dist --job-id mcp-example
bundleInspector-mcp
```

The default CLI and server both use `~/.bundleInspector/cache`, so omit `--cache-dir` to share it.
For a configured or workspace-fallback cache, pass the exact same root:

```bash
bundleInspector-mcp --cache-dir /absolute/path/to/.bundleInspector/cache
```

A generic client configuration looks like this. Use the absolute executable and cache paths for
the client's OS; remove `args` when using the default cache.

```json
{
  "mcpServers": {
    "bundleInspector": {
      "command": "/absolute/path/to/.venv/bin/bundleInspector-mcp",
      "args": ["--cache-dir", "/absolute/path/to/.bundleInspector/cache"]
    }
  }
}
```

| Capability | Contract |
|---|---|
| `list_jobs(limit=50, cursor=null)` | Lists accessible persisted jobs using opaque IDs |
| `get_job_status(job_id)` | Returns persisted-report-derived `completed`, `partial`, or `unknown` state and the latest opaque report ID |
| `get_report_page(...)` | Reads `findings`, `assets`, `correlations`, or `clusters`; default 50, maximum 100 items |
| `bundleinspector://jobs/{job_id}` | Status resource template, `application/json` MIME |

Follow `next_cursor` without changing the page kind or limit. Cursors are signed and bound to the
principal, request, and content revision; restart pagination after report/key changes. Raw job or
report IDs are rejected, and missing/malformed/unauthorized identifiers intentionally collapse to
`resource unavailable`.

Operational boundaries:

- The standalone server is not attached to an in-process `JobQueue`; it reports persisted state,
  not live scan progress. A stored report is required for report pages.
- Only current jobs with repository ownership for the built-in `local` principal are visible.
  Ownerless legacy jobs are not auto-adopted and have no supported adoption command; re-run the
  analysis into a fresh current-format job.
- Public DTOs omit raw artifacts, config, snippets, and arbitrary metadata. They use field
  allowlists, bounded pagination/completeness, opaque IDs, and secret/URI redaction.
- Read-only describes the MCP capabilities, not zero filesystem writes. First initialization may
  create the cache, `.public-view-key`, and a lock shard. Deleting/rotating the key changes opaque
  IDs and invalidates cursors.
- Transport is `stdio` only and has no protocol authentication. Keep it client-launched and local;
  do not expose it through a network bridge without separate authentication and isolation.
- Chromium is unnecessary for serving existing reports. It is needed only when producing a report
  through a headless scan.

---

## 🧭 CLI Reference

Invoke as the console command **`bundleInspector`** (or `python -m bundleInspector.cli`). Global options: `--version`, `--help`.

```
bundleInspector [scan | analyze | convert | version]
```

### `scan <urls…>` — remote

Crawl and analyze one or more live target URLs (at least one URL required).

| Flag | Default | Description |
|---|---|---|
| `--config PATH` | — | Load a YAML/JSON config file (merged; CLI flags win) |
| `-s, --scope PATTERN` | seed domains | Allowed domain pattern, e.g. `*.example.com` (repeatable) |
| `-c, --cookie name=value` | — | Session cookie (repeatable) |
| `-H, --header name:value` | — | HTTP header (repeatable) |
| `-d, --depth INT` | `3` | Crawl depth |
| `-r, --rate-limit FLOAT` | `1.0` | Seconds between requests (per domain) |
| `--no-headless` | headless on | Disable the headless browser collector |
| `-o, --output PATH` | `bundleInspector_report.<ext>` | Report output path |
| `-f, --format {json,html,sarif}` | `json` | Report format |
| `-w, --wordlist {all,endpoints,paths,params,domains,dirs}` | — | Also emit fuzzing wordlists |
| `--api-map` | off | Also emit `api_map.json` + `api_map.txt` |
| `--headers-file PATH` | — | Load headers from a `Name: Value` text or JSON file |
| `--bearer-token TOKEN` | — | Sets `Authorization: Bearer <token>` |
| `--basic-auth user:password` | — | HTTP Basic auth (must contain `:`) |
| `--user-agent STRING` | Chrome UA | Custom User-Agent |
| `--cookies-file PATH` | — | Import cookies (JSON / Netscape / header string) |
| `--cookies-from {chrome,firefox,edge,chromium}` | — | Import cookies from a local browser (mutually exclusive with `--cookies-file`) |
| `--rules-file PATH` | — | Load custom regex/AST/semantic rules |
| `--job-id ID` | auto-uuid | Persistent job id for cache/resume |
| `--resume` | off | Reuse the latest stored report/checkpoint for the job id |
| `--fail-on {info,low,medium,high,critical}` | — | Exit code **2** if any finding is at or above this severity (CI gate) |
| `--allow-private-ips` | off | Allow a target that resolves to a **private/internal** IP (RFC1918/CGNAT/ULA) for **authorized** internal/dev-server testing. Loopback, cloud-metadata (`169.254.169.254`), multicast & reserved ranges stay blocked. |
| `--chains` | off | After the findings, print unified **ATTACK CHAINS** — the sink indicator + the CONFIRMED dataflow (`taint_flow`) + the upload↔sink correlation grouped per sink, so the whole `source → flow → sink` path (plus linked upload surface and same-file endpoints for replay) reads as one chain. Confirmed vs name-heuristic **candidate** chains are labelled. |
| `--first-party-only` | off | **Noise reduction (non-destructive).** Vendor-file findings (`[3p:<lib>]`) **and** likely-false-positives (see [Noise reduction & triage](#noise-reduction--triage)) are always **labelled** and **sorted to the bottom**; this flag additionally **hides** them from the *console* for cleaner triage. Nothing is dropped from the saved report, and detection is unchanged. |
| `-v, --verbose` / `--debug` / `-q, --quiet` / `--no-banner` | — | Output verbosity controls |

### `analyze <paths…>` — local, no network

Analyze local files, directories, or glob patterns (at least one path required).

| Flag | Default | Description |
|---|---|---|
| `--config PATH` | — | Load a YAML/JSON config file |
| `-r, --recursive / --no-recursive` | recursive | Recurse into directories |
| `--include-json` | off | Also analyze `.json` files |
| `-o, --output PATH` | `bundleInspector_local_report.<ext>` | Report output path |
| `-f, --format {json,html,sarif}` | `json` | Report format |
| `-w, --wordlist {…}` / `--api-map` | — | Same as `scan` |
| `--rules-file PATH` | — | Custom rules |
| `--job-id ID` / `--resume` | — | Cache / resume |
| `--fail-on {info,low,medium,high,critical}` | — | Exit code **2** if any finding is at or above this severity (CI gate) |
| `--chains` / `--first-party-only` | off | Same as `scan` (attack-chain view / vendor + likely-FP hiding) |
| `-v, --verbose` / `--debug` / `-q, --quiet` / `--no-banner` | — | Verbosity |

> ⚠️ **`-r` differs per command:** in `scan` it is `--rate-limit`; in `analyze` it is `--recursive`.

### `convert <report>`

Convert an existing report between formats. Input is a BundleInspector JSON report, or a BundleInspector-generated HTML report (which embeds its JSON).

| Flag | Default | Description |
|---|---|---|
| `-f, --format {json,html}` | `html` | Target format (no SARIF here) |
| `-o, --output PATH` | `report.<format>` | Output path |

### `version`

Prints `BundleInspector version 0.1.0`.

---

## Configuration

Configuration comes from two sources that **merge** — CLI flags override values from a config file:

1. **A YAML or JSON file** via `--config` (on both `scan` and `analyze`). `.yaml`/`.yml` use the
   direct PyYAML dependency. A tested subset parser is used only if PyYAML cannot be imported (and
   for PyYAML's specific unknown-escape compatibility case); anything else is parsed as JSON.
2. **Direct CLI flags** (see above).

A config file mirrors the `Config` model. Example:

```yaml
scope:
  include_subdomains: true
  third_party_policy: tag_only        # analyze | skip | tag_only
crawler:
  max_depth: 2
  rate_limit: 1.25
  use_headless: true
  interactive_clicking: false          # OFF by default (see Safety)
  block_state_changing_requests: true  # ON by default (see Safety)
rules:
  min_confidence: low
  client_side_gating_enabled: true
  dormant_endpoint_detection_enabled: true
output:
  format: html
```

### Config reference

**`scope`** — first- vs third-party scoping

| Field | Default | Purpose |
|---|---|---|
| `allowed_domains` / `denied_domains` | `[]` | Allow / block domain patterns |
| `include_subdomains` | `true` | Seed domains also allow `*.domain` |
| `allowed_paths` / `denied_paths` | `[]` | Allow / deny path prefixes |
| `third_party_policy` | `tag_only` | `analyze` \| `skip` \| `tag_only` |
| `cdn_patterns` | 16 built-ins | Known CDNs for first/third-party heuristics |
| `allow_private_ips` | `false` | Permit authorized RFC1918/CGNAT/ULA targets; loopback/metadata/reserved remain blocked |

**`auth`** — credentials (cookie/header/bearer/basic names and values reject CR/LF/NUL;
transport-controlled headers are rejected)

| Field | Default | Purpose |
|---|---|---|
| `cookies` | `{}` | `{name: value}` map |
| `headers` | `{}` | Arbitrary HTTP headers |
| `bearer_token` | `null` | `Authorization: Bearer <token>` |
| `basic_auth` | `null` | `(user, password)` → Basic auth |

**`crawler`** — remote crawl/download behavior

| Field | Default | Purpose |
|---|---|---|
| `max_depth` | `3` | Recursive crawl depth |
| `max_pages` | `100` | Max pages for recursive collectors |
| `max_js_files` | `1000` | Cap on downloaded JS assets |
| `rate_limit` | `1.0` | Seconds between requests (per domain) |
| `max_concurrent` | `10` | Concurrent request cap |
| `request_timeout` / `page_timeout` | `30.0` / `60.0` | HTTP / browser-nav timeouts (s) |
| `max_redirects` / `follow_redirects` | `10` / `true` | Redirect handling |
| `use_headless` | `true` | Headless browser collector |
| `headless_wait_time` | `2.0` | Wait after page load (s) |
| `explore_routes` | `true` | Route-link exploration |
| `max_route_exploration` | `20` | Route/click exploration cap |
| **`interactive_clicking`** | **`false`** | Click buttons/tabs to trigger lazy JS — **off by default** (see Safety) |
| **`block_state_changing_requests`** | **`true`** | Block state-changing requests the UI driving induces — **on by default** |
| `max_retries` / `retry_delay` | `3` / `1.0` | Retry count / base delay |
| `max_file_size` | `10 MB` | Max downloaded JS size |
| `user_agent` | Chrome UA | Remote-scan User-Agent |

**`parser`**

| Field | Default | Purpose |
|---|---|---|
| `extract_strings` / `extract_calls` / `extract_imports` | `true` | Enable the corresponding IR features |
| `beautify` | `true` | Reflow eligible plain JS before parse; TS/JSX and literal-loss candidates remain raw-equivalent |
| `resolve_sourcemaps` | `true` | Resolve inline + external source maps |
| `beautify_max_bytes` | `1_000_000` | Skip beautify above this size |
| `tolerant` / `partial_on_error` | `true` / `true` | Tolerant / partial parsing |
| `build_call_graph` | `true` | Build call edges used by analysis/correlation; `false` skips them |
| `analysis_worker_timeout` | `30.0` | Per-asset process-worker deadline in seconds (`0.1` through `600`) |

**`rules`**

| Field | Default | Purpose |
|---|---|---|
| `enabled_categories` | `[endpoint, secret, domain, flag, debug, sink, upload]` | Active rule categories |
| `min_confidence` | `low` | `low` \| `medium` \| `high` |
| `mask_secrets` | `true` | Mask secret values in output |
| `secret_visible_chars` | `4` | Unmasked chars kept per side, capped to one quarter; `0` masks the full value |
| `entropy_threshold` | `3.5` | Generic-secret entropy threshold |
| `custom_rules_file` | `null` | Custom rules path |
| `extract_headers` / `extract_parameters` | `true` | Endpoint request-contract extraction |
| **`client_side_gating_enabled`** | **`true`** | enh1 — client-side access-control gating |
| **`client_side_gating_severity`** | **`medium`** | enh1 — severity floor; high-confidence role/permission/entitlement guards rise to at least `high` |
| **`dormant_endpoint_detection_enabled`** | **`true`** | enh2 — dormant/hidden endpoints |
| **`runtime_endpoint_surfacing_enabled`** | **`true`** | enh7 — first-party runtime-only HTTP/WS endpoints |

**`output`**

| Field | Default | Purpose |
|---|---|---|
| `format` | `json` | `json` \| `html` \| `sarif` |
| `output_file` / `output_dir` | `null` | Explicit file / default dir |
| `min_severity` | `info` | Minimum severity in the rendered report copy |
| `min_risk_tier` | `P3` | Minimum risk tier in the rendered report copy |
| `include_snippets` / `snippet_context_lines` | `true` / `3` | Keep/crop finding evidence snippets |
| `include_raw_content` | `false` | Include asset analysis-input byte payloads in JSON only; an eligible asset may hold its accepted normalized derivative |
| `include_ast` | `false` | Preserve finding `ast_node_type` and `metadata.ast_path`; not a full report AST |

Output filtering never mutates the persisted internal report. It does not weaken `--fail-on`, and
wordlists/API maps continue to see all findings.

**Top-level:** `log_level` (`info`), `verbose`, `quiet`, `cache_dir`
(`~/.bundleInspector/cache`, falls back to a workspace-local dir if unwritable), `temp_dir`
(native-parser handoff files, including worker processes), `job_id`, `resume`. A filesystem-backed
`job_id` is 1-128 characters, lowercase, and limited to `[a-z0-9._-]` with an alphanumeric first
character. Paths, trailing dots, aliases, and Windows device names such as `con` or `com1` are
rejected.

All config models reject unknown fields. Numeric resource limits reject negative/non-finite values;
`max_concurrent >= 1`, `analysis_worker_timeout` is `0.1..600`,
`secret_visible_chars` is `0..1024`, and `snippet_context_lines` is `0..50`.

See also [`docs/CONFIG_REFERENCE.md`](CONFIG_REFERENCE.md).

---

## Scan Profiles

Ready-made YAML presets live in [`examples/scan-profiles/`](../examples/scan-profiles/). These are practical traffic *expectations*, not hard guarantees — real volume depends on the target's frontend and how many assets/API calls rendering triggers.

| Profile | Depth | Pages | Headless | Routes | Concurrency | Rate limit | Traffic | Best for |
|---|---|---|---|---|---|---|---|---|
| `ultra-safe` | 0 | 1 | off | off | 1 | `5.0s` | lowest | unknown rules, strict programs, first contact |
| `conservative` | 1 | 10 | off | off | 2 | `2.5s` | low | first-pass triage, bug bounty |
| `standard` | 2 | 30 | on | off | 4 | `1.25s` | medium | authorized diagnosis |
| `deep` | 3 | 80 | on | **on** | 8 | `0.75s` | high | SPA-heavy targets |
| `fast` | 1 | 15 | off | off | 3 | `1.5s` | low | speed over fidelity — **beautify + source maps off** |

```bash
bundleInspector scan https://target.example.com \
  --config examples/scan-profiles/conservative.yml \
  --scope "*.example.com" \
  --job-id target-conservative --resume
```

**Guidance.** `ultra-safe` / `conservative` are the right first choices for bug-bounty or production triage. They keep the main detector set enabled, but deliberately reduce collection and source-map coverage along with traffic. `standard` is fine for authorized diagnosis. `deep` has the highest coverage and the highest chance of noticeable operational impact on small or brittle services. `fast` additionally trades normalization fidelity for turnaround; use it only when that tradeoff is acceptable.

---

## 🛡️ Traffic & Safety

A remote `scan` is **not** a single-page fetch. It can request HTML pages, probe build manifests, download JS assets, and — with headless enabled — render pages in a real browser. That traffic is visible to logs, WAFs, and monitoring.

### State-change guard (default ON)

The guard reduces mutation risk from the scanner's own route/click exploration:

- **`interactive_clicking = false`** — button/tab/role-element clicks are off by default. Route-link
  exploration remains enabled in the standard config.
- **`block_state_changing_requests = true`** — once exploration starts, induced
  `POST`/`PUT`/`PATCH`/`DELETE` requests are intercepted, recorded for endpoint discovery, and
  aborted unless the low-level collector's `on_state_change_attempt` callback explicitly approves.
- The guard remains armed for the rest of that page lifetime, including delayed requests. Service
  workers are always blocked in the headless context because Playwright routing cannot inspect
  requests they intercept, including when the method-based guard is disabled.
- Initial page-load requests occur before the guard is armed. A semantically mutating `GET` is
  outside the method list, and operators can disable the guard or attach an approving callback.

This is a bounded traffic safeguard, not an absolute non-mutation proof. Keep interactive clicking
off and prefer a profile with headless collection disabled when a target requires the narrowest
traffic surface.

### Throttling, scope & SSRF

- **Per-domain adaptive rate limiting** — `rate_limit` seconds between requests (default `1.0`), automatic backoff on `429`/`5xx` (×2, capped at 60s), recovery on success; concurrency capped by `max_concurrent`.
- **SSRF / scope guards** — every seed and every download is validated: localhost & cloud-metadata hosts, private/loopback/link-local/CGNAT IP ranges (incl. `169.254.169.254`), DNS-rebinding checks, and non-`http(s)` schemes are blocked; `ScopePolicy` enforces allow/deny domains.
  - **Authorized internal scanning** — pass `--allow-private-ips` (or `scope.allow_private_ips: true`) to permit targets that resolve to **private** ranges (RFC1918/CGNAT/ULA) for a dev/staging server on an internal network. This is a deliberate opt-in (default **off**); loopback, cloud-metadata (`169.254.169.254`), multicast and reserved ranges — and the blocked-hostname list (`localhost`, …) — stay blocked either way.
- **Secret masking** — secret findings are masked (`secret_visible_chars=4`); request-contract extraction redacts credential-shaped values to `<REDACTED_*>` before anything reaches disk.
- **Other hardening** — 10 MB download cap, 10-redirect cap, CR/LF/NUL validation on auth inputs, path-traversal protection for local analysis.

**How much load is this?** The download limiter targets about one request/second per domain by
default, while collector/navigation requests and target-generated browser traffic add workload that
cannot be reduced to a universal “one user” equivalent. Moving `rate_limit` toward `0` with high
`max_concurrent` can burst; keep the defaults or a conservative profile.

> **BundleInspector is not a DoS tool**, but a misconfigured aggressive scan can still be too noisy for some programs. Always follow the target's rules and rate limits.

### Common blocks & recommended options

When the scanner blocks or skips something for a fixable reason it prints a `hint=` right next to
the warning (and, when **0 JS files** were analyzed, a prominent remedy list at the summary):

| Situation (log event) | Why | Recommended option |
|---|---|---|
| `seed_url_blocked` / `ssrf_blocked` — *"Resolved IP is blocked"* | The target resolves to a **private/internal** IP | If it's an **authorized** internal/dev target: `--allow-private-ips` (or `scope.allow_private_ips: true`) |
| `seed_url_blocked` — *"Blocked host"* | `localhost` / cloud-metadata hostname | **Blocked by design** — cannot be scanned (not bypassable) |
| `seed_url_blocked` — *"Blocked/Unsupported scheme"* | non-`http(s)` URL (`javascript:`/`data:`/`file:`) | Use an `http://` or `https://` URL |
| `file_too_large` | JS asset exceeds `crawler.max_file_size` (10 MB) | Raise `crawler.max_file_size` in `--config` |
| `headless_error` | Playwright/Chromium missing or a TLS-intercepting proxy | `playwright install chromium`, or re-run with `--no-headless` (conservative profiles) |
| **0 JS files analyzed** | seed blocked / out of scope / JS injected at runtime | See the printed remedy list: `--allow-private-ips`, widen `--scope`, or use a headless profile |

---

## 🔬 Detection Coverage

### Core categories

| Category | Base severity | What it finds |
|---|---|---|
| **Endpoint** | INFO | `fetch`/`axios`/`request`/`ajax` calls, `obj.get/post/...`, `XMLHttpRequest.open`, `axios.create` baseURL/default headers, URL literals matching `/api/`, `/v\d+/`, `/graphql`, `/rest/`, `/rpc/`, `/ws/`, `/socket`, `/webhook`, and **server-side dynamic paths** (`.do`/`.jsp`/`.action`/`.php`/`.aspx`/`.ashx`/`.cgi`…) as bare/relative literals or `${base}/x.do` templates (Java/Spring/Struts, PHP, ASP.NET). Statically resolves URLs across template literals, concatenation, ternaries, constants, named objects, and `new URL()`/`new Request()`. |
| **Secret** | HIGH | ~100 precompiled key patterns (AWS, Azure, GCP, OpenAI, Anthropic, GitHub, GitLab, Stripe, Slack, Twilio, Firebase, Supabase, DB connection strings, JWT, PEM/SSH keys, …), generic assignment-context patterns (`api_key`, `access_token`, …), and Shannon-entropy analysis for random blobs (demoted to LOW without secret vocabulary). Obvious placeholders are excluded; provider-shaped credentials in demo/mock context are retained with low/context-suppressed evidence instead of hard-dropped. |
| **Domain** | MEDIUM | Internal/staging hosts (`dev`/`staging`/`qa`…, `.internal`/`.local`/`.corp`), Kubernetes (`.svc.cluster.local`), Docker/AWS-internal, private/loopback IPs, S3/GCS/Azure buckets, and **cloud-metadata / IMDS SSRF targets** — `169.254.169.254` and `metadata.google.internal` → **HIGH** (steals instance credentials), plus link-local `169.254.0.0/16`. |
| **Flag** | LOW | Feature-flag keywords, SDKs (LaunchDarkly, Optimizely, Split, ConfigCat, Unleash, …), flag-config endpoints, flag-check functions, and admin/debug identifiers. |
| **Debug** | per-path | Debug/admin paths with graded severity (`/shell`,`/eval` → CRITICAL; `/debug`,`/admin` → HIGH; `/actuator`,`/test` → MEDIUM; `/health`,`/swagger` → LOW), sensitive `console.*` logging, `debugger` statements, `alert()`, dev-only branches (`NODE_ENV`, `__DEV__`), and **source-map disclosure** (`//# sourceMappingURL=` — the map reconstructs the original pre-minification source). |
| **Sink** | per-sink | **DOM-XSS / code-injection / open-redirect sinks fed a DYNAMIC argument** (not a static literal): HTML injection (`innerHTML`/`outerHTML =`, `document.write`, `insertAdjacentHTML`, jQuery `.html()`/`.append()`…, and jQuery **HTML construction** `` $('<div>'+x) `` / `` $(`<a href="${u}">`) ``), attribute injection (`setAttribute`/jQuery `.attr()`/`.prop()` on `src`/`href`/`on*`…), **HTML-attribute injection** — a dynamic value interpolated into a dangerous attribute of an HTML string (`` `<img src="${item.image_url}">` ``, `onerror="${x}"`) → **HIGH**, **navigation / open-redirect** (`location.href =`, `location.assign`/`replace`, `window.open` fed a dynamic value — also catches `javascript:`-URL DOM-XSS; same-origin components like `location.pathname` are ignored), and code execution (`eval`, `new Function`, string `setTimeout`/`setInterval`). The finding **names the source expression** (`item.image_url`, `e.target.result`, `uploaded.path`…) so you see exactly what flows in. These are client-side **indicators**. On top of them a **flow-sensitive dataflow taint engine** emits a **CONFIRMED** `taint_flow` finding (with the reconstructed `source → … → sink` path) only when a real intra-file def-use chain connects an *enumerated* source — a FileReader result, an `$.ajax`/`fetch` response, or a DOM input (`.val()`/`.data()`/`location.*`/`window.location.*`) — to the sink. It is flow-sensitive (a clean reassignment kills taint; no impossible backward flows), context-sensitive (`f(userInput)` is tainted, `f("safe")` is not), closure- and scope-aware, and abstains on cross-file/unknown callees — so it prefers a missed flow over a wrong one. |
| **Upload** | per-signal | File-upload surface: `new FormData()`/`multipart`, `<input type="file">` built in JS, and **client-side-only file-type allow-lists** (`allowedExt`/`allowedTypes`… → MEDIUM) which are bypassable — verify the server re-validates (unrestricted-upload risk). |

The **Chunk Analyzer** additionally surfaces Webpack/Vite code-split infrastructure and lazy/hidden routes.

> The **Sink** and **Upload** detectors report client-side *indicators*, not proven vulnerabilities: a static bundle scan cannot see the server-side control (authorization, server file re-validation) or prove the source is attacker-controlled. They point you at the exact sinks/surfaces to confirm manually or with DAST — e.g. a `.html()`/`innerHTML=` fed a stored value is the client half of a **stored XSS**, and a client-side `allowedExt` check is the client half of an **unrestricted file upload**.

### The seven enhancements

| ID | Name | What it does |
|---|---|---|
| **enh1** | Client-side access-control gating | Flags endpoints reachable **only** behind a browser-side authz check (`if(user.isAdmin)`, `flags.canX && fetch(...)`, `if(!hasRole()) return`). Classifies the guard (role/permission/entitlement/feature/flag) and raises severity — a classic bypass surface. Offset-based matching works on minified single-line bundles. |
| **enh2** | Dormant / hidden endpoints | Cross-references endpoints **declared** in JS against endpoints the running app **actually called** during the headless crawl. Declared-but-never-called endpoints are AJAX-reachable bypass surface. FP-safe (no-op without a runtime baseline; leaves untouched hosts alone), sensitive paths raised to MEDIUM. |
| **enh3** | Replayable request contract + PoC | Assembles a per-call contract (method, url, headers, auth scheme, body shape, query params) into `request_contract` metadata, with credential-shaped values redacted at extraction. `reporter/poc.py` renders replayable **curl + fetch** snippets with `FUZZ` placeholders. |
| **enh4** | IDOR + HTTP method-flip | Detects IDOR/enumeration path parameters (`${…}`, `:id`, UUID, Mongo ObjectId, email, numeric) and tags `idor_candidate`; lists standard HTTP verbs **not yet seen** on each path as advisory fuzz hints. HTTP dedup keys on `(method, url)` so a hidden `DELETE` beside a benign `GET` survives. |
| **enh5** | Framework client route maps | Reconstructs recognized SPA routes — including admin/internal/feature-flagged pages **never linked in nav** — from React Router, Vue Router, Angular, compiled JSX, and Next.js file routes, joining parent/child paths and associating per-route lazy chunks. Emits `client_route` findings; sensitive routes flagged. Dynamic or unsupported route construction can remain unresolved. |
| **enh6** | GraphQL + WebSocket surface | Extracts GraphQL operations (query/mutation/subscription + fields) from `gql` tagged templates and query props, and the WebSocket **message surface** from `.send()`/`.emit()` on WS/Socket.IO clients. |
| **enh7** | Runtime-observed endpoints | The complement of enh2: HTTP/WebSocket endpoints the running app **actually called** during the crawl but static analysis never found (typically dynamically-assembled URLs). Surfaced as `runtime-observed` endpoint findings. Scan-only, first-party scoped, de-duplicated against static findings. |

### Download surfaces

File-serving endpoints (serve/stream a file to the client) are a high-value surface — path
traversal, file IDOR, SSRF, and forced browsing. A dedicated classifier tags discovered endpoints
that are **file** downloads and names the **specific parameter** and **risk** to test.

**Graded by how a file is *served*, not by the endpoint's name.** The question is "does it serve a
**file**", never "is it a coupon" — a coupon/report/gift *download* commonly serves a barcode
**PDF/image** (a real arbitrary-file-download / traversal / IDOR surface), so it is **not**
blanket-excluded. Two tiers:

- **CONFIRMED** — a file-download keyword (`fileDown`/`getFile`/`atchFileDown`/`excelDown`/
  `download.php`…), a strong file parameter, an office/archive extension, **or a file-response
  mechanism** near the call (`responseType:'blob'`, `createObjectURL`, `download` attribute,
  `saveAs`, `content-disposition`, `application/pdf`) — this catches a coupon endpoint that streams a
  PDF *regardless of its name*.
- **POSSIBLE (verify)** — a download/export keyword with no strong signal; surfaced at low confidence
  with a "verify the response is a file" note (data/action endpoints like `…Count`/`…Agree` opt out).

Keyword matching is word-boundary anchored (so `uploadFile`/`profileView`/`targetImage` are *not*
misread), upload endpoints are excluded, and a high-severity claim needs a strong keyword **and** a
strong parameter.

**Korean enterprise conventions (deep).** eGovFrame / Nexacro / XE·Rhymix / gnuboard parameter names:

| Parameter | Meaning | Risk |
|---|---|---|
| `atchFileId`, `fileSn`, `fileMngId`, `nttFileId`, `bsnsFileSn`, `file_srl` | attachment id / seq | **file-IDOR** |
| `fileNm`, `orgnlFileNm`, `streFileNm` (`Nm`=名) | file name | **path-traversal** |
| `fileStreCours` (`Cours`=경로), `filePath`, `savePath` | store path | **path-traversal** |
| `imageUrl`, `fileUrl`, `remoteUrl` | remote fetch | **SSRF** |
| `objectKey`, `s3Key` | cloud storage key | file-IDOR |

Shown as a **`▾ download: <risk>`** tag on the endpoint plus a dedicated **Download Surfaces** table
(console) / **`⬇ DOWNLOAD` badge + risk panel** (HTML) with the exact parameter and what to test
(`../../etc/passwd`, id enumeration, `169.254.169.254`, …). Non-destructive: tag only, detection
unchanged.

### Risk tiers

Every finding is scored and tiered:

| Tier | Meaning |
|---|---|
| **P0** | Critical — act immediately |
| **P1** | High |
| **P2** | Medium — investigate |
| **P3** | Low / informational |

---

## Noise reduction & triage

Static scanners over-report on third-party libraries and pattern-only matches. BundleInspector
reduces that noise **non-destructively** — likely false positives are **labelled and demoted, never
dropped**, so detection recall is unchanged (the detection-invariance gate stays byte-identical).

A presentation-layer pass tags a finding `likely_fp` (with a reason) when:

| Rule | What it demotes | Why it's a false positive | Safety |
|---|---|---|---|
| **A** | A "secret" inside a **third-party library file** (`jquery`/`swiper`/`jsencrypt`/…) | Library regex/CSS/base64-alphabet strings, not an app credential | Only `category == secret` in a vendor file |
| **C** | A `-----BEGIN … PRIVATE KEY-----` **marker with no base64 key body** nearby | PEM parsing/label code, not a leaked key | A real key is never demoted — a base64 body **or** PEM structure (`-----END`/`Proc-Type:`/`DEK-Info:`) in the snippet keeps it |

A **CONFIRMED** taint flow (proven `source → sink` dataflow) is **never** demoted.

**Where you see it**
- **Console** — likely-FP / vendor findings sort to the bottom, are tagged (`[3p:…]` / `[likely FP: …]`), and a count line points to `--first-party-only` to hide them.
- **HTML report** — noise findings are **hidden by default** (a banner states "showing N **first-party findings to review** · M vendor/likely-FP hidden"); a toggle reveals them, and they stay in the saved report. Note the N are **not all vulnerabilities** — they still include attack surface (endpoints/flags); they are sorted by severity so confirmed dataflows & injections rank first. Each sink shows a **DANGEROUS VALUE** line naming the exact value that reaches the sink, and the code snippet is anchored on that value (even when it sits deep inside a multi-line HTML template) so you can see it highlighted.

---

## Output & Reports

| Format | Flag | Notes |
|---|---|---|
| **JSON** | `-f json` (default) | Full structured report fields with redaction; asset analysis-input bytes require `include_raw_content` and may be an accepted normalized derivative; prefers source-map original positions and includes enhancement metadata |
| **HTML** | `-f html` | Self-contained report that embeds its own JSON (round-trippable with `convert`) |
| **SARIF 2.1.0** | `-f sarif` | GitHub Code Scanning / Azure DevOps; rules `JSFINDER001–007` (secret/endpoint/domain/flag/debug/sink/upload), CWE taxonomy, code flows for normalized vs. original positions |

Extra artifacts (written next to the main report):

- **Fuzzing wordlists** — `-w {all,endpoints,paths,params,domains,dirs}` → `wordlist_endpoints.txt`, `wordlist_paths.txt`, `wordlist_params.txt`, `wordlist_domains.txt`, `wordlist_dirs.txt` (`${…}` replaced with `FUZZ`; ffuf/dirsearch/feroxbuster-compatible).
- **API map** — `--api-map` → `api_map.json` + `api_map.txt` (an ASCII tree of domains → routes → params).

Default report names: `bundleInspector_report.<ext>` (scan), `bundleInspector_local_report.<ext>` (analyze), `report.<ext>` (convert).

### Analysis completeness

Every report carries `Report.completeness.status`: `complete`, `partial`, `failed`, or
`cancelled`. Issues include a stable code/stage, retryability, affected count, and internal
diagnostic details. Parser recovery, collection failures, source-map/virtual-source loss, caps,
custom-rule failures, and worker timeouts therefore cannot silently turn into a clean zero-finding
result. HTML renders incomplete banners/issues, SARIF writes completeness properties and
notifications, JSON retains the structured model subject to configured redaction/raw-content
policy, and MCP exposes only a bounded allowlisted summary.

---

## Performance

- **Remote-scan parallel analysis** — `BUNDLEINSPECTOR_PARALLEL` is read by the remote `scan`
  orchestrator: unset/`0`/`1` = serial; `auto` = one worker per CPU; integer `N` = `N`
  workers. Parse and analyze are fused inside each worker so large ASTs do not cross the process
  boundary. Local `analyze` is currently serial and does not read this variable.

  ```bash
  BUNDLEINSPECTOR_PARALLEL=auto bundleInspector scan https://target.example.com
  ```

- **Parser backends** — language-hinted JS/JSX/TS/TSX uses the required Tree-sitter grammar first.
  `BUNDLEINSPECTOR_NATIVE_PARSER=1` optionally tries Node.js/Acorn before the legacy Esprima path;
  incomplete legacy parsing is retried structurally.
- **Resume / checkpoints** — `--job-id <id> --resume` reuses the latest stored report or per-stage checkpoint. A **resume signature** invalidates stale state if the profile, parser, rules, auth, scope, depth, or headless setting changed under the same job id.
- **Resume correctness** — local input content, config, report schema, parser identity, and engine
  identity participate in the resume contract. Retryable/incomplete collection work remains a retry
  barrier rather than a false-complete checkpoint.
- **Under the hood** — content-hash dedup, linear beautify line mapping, per-pass dependency/runtime
  caches, call-target/AST memoization, and a sound required-literal secret prefilter bound repeated
  work. Custom regex execution and candidate recovery have explicit time/count caps.
- **Release benchmark gate** — committed baselines are Linux x86-64 CPython 3.13 measurements with
  exact dependency, origin, and CPU provenance. Same-CPU runs enforce point p95 +20% and RSS +25%.
  Cross-CPU runs still gate: the current p95 bootstrap lower bound is compared with the baseline
  upper bound +20%, and RSS +25% remains active. Cross-hardware results cannot attribute the cause
  to code versus hardware and report `applied_cross_hardware_attribution_unavailable`. Absolute,
  semantic, completeness, sample, bootstrap, and CV gates always remain active; baselines are never
  updated automatically.

### Current reference measurements

The committed reference was measured on WSL2 Linux x86-64, CPython 3.13.7, AMD Ryzen 9 9950X, with
2 warmups and 30 measured runs per scenario.

| Correlator fixture | p50 ms | p95 ms | p95 95% bootstrap CI | observed peak RSS | Edges |
|---:|---:|---:|---:|---:|---:|
| 80 modules / 160 findings | 311.577 | 330.026 | 320.358-342.076 | 72,667,136 B | 1,130 |
| 200 modules / 400 findings | 880.845 | 913.658 | 901.100-918.252 | 86,319,104 B | 1,250 |
| 500 modules / 1,000 findings | 4,062.641 | 4,131.418 | 4,103.741-4,173.599 | 116,260,864 B | 1,550 |

| Detection/resource scenario | Fixture size | p50 ms | p95 ms | p95 95% bootstrap CI | observed suite peak RSS |
|---|---:|---:|---:|---:|---:|
| Complete Tree-sitter TypeScript parse | 1,048,576 B | 613.226 | 639.054 | 632.591-643.679 | 404,127,744 B |
| Bounded custom regex timeout | 20,029 B | 50.179 | 50.234 | 50.210-50.253 | 404,127,744 B |
| Lexical candidate flood/recovery | 150,123 B | 20.178 | 20.593 | 20.378-20.729 | 404,127,744 B |

These are the first current-reference baselines recorded after remediation. No methodologically
comparable pre-change baseline exists, so they do **not** establish a speedup percentage. They are
synthetic stage gates, not end-to-end `scan`/`analyze`, crawler/browser/network throughput, or an
SLA. Peak RSS is a process-lifetime high-water observation; later rows and the identical detection
values are not isolated per-scenario allocations. Results on this high-end WSL host do not predict
other hardware.

### Validation snapshot and limits

- The public labeled corpus currently passes all 19 release gates over 45 cases and 1,916
  labels/predictions, with labeled FP/FN, parser, completeness, invariance, graph, and regression
  failure lists empty.
- The repository-visible frozen governance artifact passes the same 19-key profile over 11 cases
  and 2,193 labels/predictions.
- Those perfect in-corpus observations are not a general 100% accuracy claim. The frozen cases are
  visible, share one vendor-family identity, and are not unseen external independent samples.
- Exact import-edge precision, original source-map column accuracy, injected-cap attribution, and
  diagnostic recall do not each have an independent external labeled estimate.

---

## Authentication & Sessions

Provide credentials for authenticated scans several ways (CLI values override file values):

```bash
# Inline
bundleInspector scan https://app.example.com -c "session=abc123" -H "X-Env: staging"
bundleInspector scan https://app.example.com --bearer-token "$TOKEN"
bundleInspector scan https://app.example.com --basic-auth "user:pass"

# From files
bundleInspector scan https://app.example.com --headers-file headers.txt      # "Name: Value" lines or JSON
bundleInspector scan https://app.example.com --cookies-file cookies.json      # JSON / Netscape / header string

# From a local browser profile
bundleInspector scan https://app.example.com --cookies-from chrome
```

`--cookies-file` and `--cookies-from` are mutually exclusive. Cookie/header names and values,
bearer tokens, and both basic-auth components reject CR/LF/NUL injection.

### Reusing a full `Cookie:` header

The easiest way to reuse a big browser session is `--cookies-file`: copy the whole `Cookie: …` header from DevTools into a text file and point at it. `--cookies-file` accepts any of:

- a raw **cookie header string** — `Cookie: a=1; b=2; …` (the `Cookie:` prefix is optional),
- a **Netscape/curl** cookie file,
- a **JSON array** (browser-extension export) or **EditThisCookie** JSON.

```bash
# cookies.txt contains one line:  Cookie: WMONID=…; sso_key=…; JSESSIONID=…
bundleInspector scan https://app.example.com --cookies-file cookies.txt --scope "*.example.com"
```

This is preferred over `-c name=value` for long sessions: it needs no shell escaping (values may contain `$`, `%`, `:`, `=`, empty values) and injects real cookies into the headless browser's cookie jar. Treat the file as a secret — it holds a live session; don't commit it.

---

## Custom Rules

Bring your own detections with `--rules-file` (a single JSON/YAML file, a directory, or a ruleset `meta.yml` with a sibling `rules/` dir). Three matcher families are supported: **regex**, **ast_pattern**, and **semantic**. See [`docs/CUSTOM_RULES.md`](CUSTOM_RULES.md) for the full DSL and worked examples.

```bash
bundleInspector analyze ./dist --rules-file my-rules.yml
```

---

## Python API

BundleInspector can be driven programmatically:

```python
import asyncio
from bundleInspector import BundleInspector, Config

async def main():
    report = await BundleInspector(Config()).scan(["https://target.example.com"])
    for f in report.findings:
        print(f.risk_tier, f.category, f.extracted_value)

asyncio.run(main())
```

Public exports: `BundleInspector`, `Config`, `ScopeConfig`, `AuthConfig`, `JSAsset`, `Finding`, `Evidence`, `Correlation`, `Cluster`, `Report`, `Severity`, `Confidence`, `Category`, `RiskTier`.

---

## How It Works

The `scan` pipeline runs eight stages (the `analyze` command runs an equivalent local pipeline):

1. **Crawl** — discover JS (static HTML collector — external `<script src>` **and inline `<script>` bodies** — optional headless render, build-manifest probing); SSRF-checked seeds; headless network capture feeds enh2's observed-request baseline.
2. **Download** — fetch JS with per-domain rate limiting, a concurrency semaphore, SSRF revalidation, size caps, and content-hash dedup.
3. **Normalize** — retain the raw content-hash artifact; optionally beautify eligible plain JS
   after a raw-literal monotonicity check, build generated/original line mappings, and resolve
   bounded inline + external source maps. TS/JSX-shaped or literal-losing candidates stay
   raw-equivalent.
4. **Parse** — build the AST with the language-hinted Tree-sitter grammar first for
   JS/JSX/TypeScript/TSX, or the optional Acorn and legacy/recovery sequence for unhinted input.
5. **Analyze** — run the rule engine + context-filter FP reduction + enh1 gating annotation + metadata/position mapping. Original pre-minification sources embedded in source maps (`sourcesContent`) are also scanned as virtual sources, so secrets/endpoints present only in the original code are recovered.
6. **Correlate** — enh2 dormant-endpoint annotation, then build the correlation graph (edges + clusters). Edge types include same-file, import/call-chain, runtime, secret↔endpoint, and **taint** — a light dataflow link that auto-connects a **file-upload surface (or upload/file endpoint) → a DOM `src`/`href` sink fed a file/image/upload-looking value** in the same asset, surfacing the `upload → <img src>` stored/DOM-XSS chain (heuristic, MEDIUM confidence — a correlated sink is also risk-scored higher).
7. **Classify** — assign risk tier, risk score, impact & likelihood per finding.
8. **Report** — assemble, summarize, and persist findings/report/checkpoints.

---

## Notes & Limitations

- **No built-in proxy support.** There is no `--proxy` flag; traffic is not routed through an upstream proxy such as Burp or ZAP. Intercept at the OS/network layer if you need to.
- **Exit codes.** `0` = success (even **with** findings), `1` = error or interrupt, `2` = the `--fail-on` severity gate tripped. Without `--fail-on` there is no severity-based gate, so a clean-exit-with-findings stays `0` — either use `--fail-on`, or decide pass/fail from the report/SARIF. (A malformed CLI invocation also exits `2` at parse time, per Click — but *before* the scan runs and with no report written, so it is distinguishable from a gate trip.)
- **Config-only settings.** Examples include `interactive_clicking`,
  `block_state_changing_requests`, `min_severity`, and `min_risk_tier`; set them in a
  `--config` YAML/JSON file.
- **The `on_state_change_attempt` confirmation callback** is a low-level
  `HeadlessCollector` integration point, not a CLI option or a wired high-level
  `BundleInspector` API. Without a callback, guarded state-changing requests are blocked.
- **Duplicate cookie names** in a header string resolve last-wins.
- **Headless response memory bound.** A trustworthy `Content-Length` is rejected before capture,
  but Playwright's `response.body()` must materialize one response whose length is absent or false
  before the post-read `max_file_size` check. The capture semaphore bounds concurrency, not that
  single response's allocation.
- **Static-analysis boundary.** Dynamic code, unresolved cross-file/runtime values, server-side
  authorization/validation, and intentionally bounded caps can still produce false positives or
  false negatives. Check `Report.completeness` before interpreting a zero-finding result.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `playwright` / browser errors on `scan` (e.g. `headless_browser_not_installed`, `Executable doesn't exist`) | Run `playwright install chromium`, or add `--no-headless` (or use a profile with headless collection disabled). The scan still runs its static/manifest collectors, but an SPA may need the headless browser to yield JS. |
| `playwright install` fails with `SELF_SIGNED_CERT_IN_CHAIN` | A TLS-intercepting proxy (corporate MITM) is breaking Node's download. **Secure fix:** point Node at your proxy's root CA — `setx NODE_EXTRA_CA_CERTS C:\path\to\corp-root-ca.pem` then reopen the shell and re-run. **Quick (insecure) fix:** `$env:NODE_TLS_REJECT_UNAUTHORIZED=0; playwright install chromium` (one session only). If a proxy is required, also set `$env:HTTPS_PROXY`. |
| Scan feels too aggressive / noisy | Use `--config examples/scan-profiles/conservative.yml`, raise `--rate-limit`, lower `max_concurrent` |
| Acorn path not used | Acorn is optional. Ensure Node.js is on `PATH`, `acorn` is resolvable, and `BUNDLEINSPECTOR_NATIVE_PARSER=1`; language-hinted modern input intentionally uses Tree-sitter first. |
| Resume re-runs from scratch | The config changed under the same `--job-id` (profile/rules/scope/etc.), which invalidates stale state by design |
| Secrets appear masked | Expected — set `rules.mask_secrets: false` in a config file only for local, trusted analysis |
| Large local bundles are slow | Local `analyze` is serial. Use a config that disables beautify/source maps when that fidelity tradeoff is acceptable, or split independent input sets. |
| MCP starts but shows no jobs | Use the exact same `cache_dir` as `scan`/`analyze`; ownerless legacy jobs are intentionally invisible |
| Running `bundleInspector-mcp` appears to hang | Expected for stdio: configure the MCP client to launch it and exchange protocol messages over stdin/stdout |
| Non-ASCII (Korean, etc.) console output looks garbled on Windows | Handled automatically — the CLI forces UTF-8 on stdout/stderr, so no `PYTHONIOENCODING` is needed; just use a UTF-8-capable terminal (e.g. Windows Terminal) |
| `--cookies-from` returns no cookies | The DB (incl. `-wal`) is copied, so the browser may stay open. The required `cryptography` dependency decrypts supported Chrome/Edge/Chromium values on Windows. Still empty means the profile may use app-bound encryption (Chrome 127+); export via a cookie extension to JSON and use `--cookies-file`. |

---

Built for authorized security testing. Use responsibly. See the [README](../README.md) for the short version.
