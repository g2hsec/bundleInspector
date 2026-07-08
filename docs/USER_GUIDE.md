# 📖 BundleInspector — User Guide

Complete reference for installing, configuring, and running BundleInspector.
For a quick overview, see the [README](../README.md).

---

## Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
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

Each asset is normalized (beautified, source-map resolved), parsed into an AST, and passed through a rule engine that extracts **endpoints, secrets, internal domains, feature flags, and debug endpoints**, then enriched with six offensive-recon enhancements and risk-tiered `P0–P3`.

> **Version:** `0.1.0` · **Python:** `3.10+` · **License:** MIT

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
pip install -e .
playwright install chromium          # required for headless scanning
```

> **Windows PowerShell** does not support `&&` or `source` — run each command on its own line. If activation fails with *"running scripts is disabled on this system"*, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once in the session, then re-run `.venv\Scripts\Activate.ps1`.

Development install (tests, linting):

```bash
pip install -e ".[dev]"              # pytest, pytest-asyncio, pytest-cov, ruff, mypy, pre-commit
```

**Optional native parser.** BundleInspector uses `esprima` by default. For faster parsing and full modern-syntax support you can opt into an [acorn](https://github.com/acornjs/acorn)-based backend, which needs Node.js on `PATH` and the `acorn` package resolvable:

```bash
npm install acorn                     # anywhere Node can resolve it (or on NODE_PATH)
export BUNDLEINSPECTOR_NATIVE_PARSER=1
```

If Node/acorn is missing or anything fails, BundleInspector silently falls back to `esprima` — the native path can never reduce detection.

**Runtime dependencies** (installed automatically): `httpx`, `playwright`, `beautifulsoup4`, `lxml`, `esprima`, `jsbeautifier`, `pydantic>=2`, `click>=8.1`, `rich`, `structlog`, `jinja2`, `aiofiles`, `regex`.

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

1. **A YAML or JSON file** via `--config` (on both `scan` and `analyze`). `.yaml`/`.yml` use a bundled loader (no PyYAML needed); anything else is parsed as JSON.
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

**`auth`** — credentials (all CR/LF/NUL-injection validated)

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
| `max_file_size` | `10 MB` | Max downloaded JS size |
| `user_agent` | Chrome UA | Remote-scan User-Agent |

**`parser`**

| Field | Default | Purpose |
|---|---|---|
| `beautify` | `true` | Beautify JS before parse |
| `resolve_sourcemaps` | `true` | Resolve inline + external source maps |
| `beautify_max_bytes` | `1_000_000` | Skip beautify above this size |
| `tolerant` / `partial_on_error` | `true` / `true` | Tolerant / partial parsing |

**`rules`**

| Field | Default | Purpose |
|---|---|---|
| `enabled_categories` | `[endpoint, secret, domain, flag, debug]` | Active rule categories |
| `min_confidence` | `low` | `low` \| `medium` \| `high` |
| `mask_secrets` | `true` | Mask secret values in output |
| `secret_visible_chars` | `4` | Unmasked chars kept |
| `entropy_threshold` | `3.5` | Generic-secret entropy threshold |
| `custom_rules_file` | `null` | Custom rules path |
| **`client_side_gating_enabled`** | **`true`** | enh1 — client-side access-control gating |
| **`client_side_gating_severity`** | **`medium`** | enh1 — severity for gated endpoints |
| **`dormant_endpoint_detection_enabled`** | **`true`** | enh2 — dormant/hidden endpoints |

**`output`**

| Field | Default | Purpose |
|---|---|---|
| `format` | `json` | `json` \| `html` \| `sarif` |
| `output_file` / `output_dir` | `null` | Explicit file / default dir |
| `min_severity` | `info` | Minimum severity to include |
| `min_risk_tier` | `P3` | Minimum risk tier to include |
| `include_snippets` / `snippet_context_lines` | `true` / `3` | Code snippets |
| `include_raw_content` / `include_ast` | `false` | Heavy payloads |

**Top-level:** `log_level` (`info`), `verbose`, `quiet`, `cache_dir` (`~/.bundleInspector/cache`, falls back to a workspace-local dir if unwritable), `temp_dir`, `job_id`, `resume`.

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

**Guidance.** `ultra-safe` / `conservative` are the right first choices for bug-bounty or production triage — they stay low-traffic but keep full analysis precision. `standard` is fine for authorized diagnosis. `deep` has the highest coverage and the highest chance of noticeable operational impact on small or brittle services. `fast` trades normalization fidelity for turnaround; use it only when that tradeoff is acceptable.

---

## 🛡️ Traffic & Safety

A remote `scan` is **not** a single-page fetch. It can request HTML pages, probe build manifests, download JS assets, and — with headless enabled — render pages in a real browser. That traffic is visible to logs, WAFs, and monitoring.

### State-change guard (default ON)

BundleInspector will not mutate a target through its own UI driving:

- **`interactive_clicking = false`** — clicking buttons/tabs/role elements (the highest-risk way to submit forms or trigger deletes) is **off by default**. Route-link exploration stays on but is covered by the guard below.
- **`block_state_changing_requests = true`** — while the crawler drives the UI (route-link + interactive clicks), any non-idempotent request (`POST`/`PUT`/`PATCH`/`DELETE`) it induces is **intercepted at the network layer**: the endpoint is **recorded** (so discovery is preserved and it feeds dormant-endpoint detection), then **aborted** — unless a wired `on_state_change_attempt` handler approves it (pause-and-confirm).
- **Service workers are blocked** while the guard is on, so no request can bypass interception via a service-worker fetch.
- Requests the app fires **outside** the exploration phase (initial page load) are untouched, so normal rendering and detection are preserved.

> **Residual, stated honestly:** the guard is scoped to the exploration phase, so a mutation a click schedules *far* in the future (e.g. a debounced `setTimeout` beyond the settle window) can still fire after the guard disarms. Because interactive clicking is off by default and the confirm hook exists, this is a narrow edge — but if you need an absolute guarantee, keep `interactive_clicking` off and prefer the non-headless profiles.

### Throttling, scope & SSRF

- **Per-domain adaptive rate limiting** — `rate_limit` seconds between requests (default `1.0`), automatic backoff on `429`/`5xx` (×2, capped at 60s), recovery on success; concurrency capped by `max_concurrent`.
- **SSRF / scope guards** — every seed and every download is validated: localhost & cloud-metadata hosts, private/loopback/link-local/CGNAT IP ranges (incl. `169.254.169.254`), DNS-rebinding checks, and non-`http(s)` schemes are blocked; `ScopePolicy` enforces allow/deny domains.
  - **Authorized internal scanning** — pass `--allow-private-ips` (or `scope.allow_private_ips: true`) to permit targets that resolve to **private** ranges (RFC1918/CGNAT/ULA) for a dev/staging server on an internal network. This is a deliberate opt-in (default **off**); loopback, cloud-metadata (`169.254.169.254`), multicast and reserved ranges — and the blocked-hostname list (`localhost`, …) — stay blocked either way.
- **Secret masking** — secret findings are masked (`secret_visible_chars=4`); request-contract extraction redacts credential-shaped values to `<REDACTED_*>` before anything reaches disk.
- **Other hardening** — 10 MB download cap, 10-redirect cap, CR/LF/NUL validation on auth inputs, path-traversal protection for local analysis.

**How much load is this?** At default settings the download stage is ~1 request/second per domain and the headless stage renders one page at a time — comparable to a single active user. Cranking `rate_limit` toward `0` with a high `max_concurrent` can burst to dozens of concurrent requests; keep the defaults (or a conservative profile) to stay gentle.

> **BundleInspector is not a DoS tool**, but a misconfigured aggressive scan can still be too noisy for some programs. Always follow the target's rules and rate limits.

---

## 🔬 Detection Coverage

### Core categories

| Category | Base severity | What it finds |
|---|---|---|
| **Endpoint** | INFO | `fetch`/`axios`/`request`/`ajax` calls, `obj.get/post/...`, `XMLHttpRequest.open`, `axios.create` baseURL/default headers, URL literals matching `/api/`, `/v\d+/`, `/graphql`, `/rest/`, `/rpc/`, `/ws/`, `/socket`, `/webhook`, and **server-side dynamic paths** (`.do`/`.jsp`/`.action`/`.php`/`.aspx`/`.ashx`/`.cgi`…) as bare/relative literals or `${base}/x.do` templates (Java/Spring/Struts, PHP, ASP.NET). Statically resolves URLs across template literals, concatenation, ternaries, constants, named objects, and `new URL()`/`new Request()`. |
| **Secret** | HIGH | ~100 precompiled key patterns (AWS, Azure, GCP, OpenAI, Anthropic, GitHub, GitLab, Stripe, Slack, Twilio, Firebase, Supabase, DB connection strings, JWT, PEM/SSH keys, …), generic assignment-context patterns (`api_key`, `access_token`, …), and Shannon-entropy analysis for random blobs (demoted to LOW without secret vocabulary). Placeholder/test values excluded. |
| **Domain** | MEDIUM | Internal/staging hosts (`dev`/`staging`/`qa`…, `.internal`/`.local`/`.corp`), Kubernetes (`.svc.cluster.local`), Docker/AWS-internal, private/loopback IPs, and S3/GCS/Azure buckets. |
| **Flag** | LOW | Feature-flag keywords, SDKs (LaunchDarkly, Optimizely, Split, ConfigCat, Unleash, …), flag-config endpoints, flag-check functions, and admin/debug identifiers. |
| **Debug** | per-path | Debug/admin paths with graded severity (`/shell`,`/eval` → CRITICAL; `/debug`,`/admin` → HIGH; `/actuator`,`/test` → MEDIUM; `/health`,`/swagger` → LOW), sensitive `console.*` logging, `debugger` statements, `alert()`, and dev-only branches (`NODE_ENV`, `__DEV__`). |
| **Sink** | per-sink | **DOM-XSS / code-injection sinks fed a DYNAMIC argument** (not a static literal): HTML injection (`innerHTML`/`outerHTML =`, `document.write`, `insertAdjacentHTML`, jQuery `.html()`/`.append()`…), attribute injection (`setAttribute`/jQuery `.attr()`/`.prop()` on `src`/`href`/`on*`…), **HTML-attribute injection** — a dynamic value interpolated into a dangerous attribute of an HTML string (`` `<img src="${item.image_url}">` ``, `onerror="${x}"`) → **HIGH**, and code execution (`eval`, `new Function`, string `setTimeout`/`setInterval`). The finding **names the source expression** (`item.image_url`, `e.target.result`, `uploaded.path`…) so you see exactly what flows in. A client-side **indicator** (confirm the source is attacker-controlled via taint review/DAST); it pinpoints every injectable sink — e.g. an upload response's `image.path` reaching an `<img src>` is the client half of a **stored XSS**. |
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
| **enh5** | Framework client route maps | Reconstructs the SPA's full route table — including admin/internal/feature-flagged pages **never linked in nav** — from React Router, Vue Router, Angular, compiled JSX, and Next.js file routes, joining parent/child paths and associating per-route lazy chunks. Emits `client_route` findings; sensitive routes flagged. |
| **enh6** | GraphQL + WebSocket surface | Extracts GraphQL operations (query/mutation/subscription + fields) from `gql` tagged templates and query props, and the WebSocket **message surface** from `.send()`/`.emit()` on WS/Socket.IO clients. |
| **enh7** | Runtime-observed endpoints | The complement of enh2: HTTP/WebSocket endpoints the running app **actually called** during the crawl but static analysis never found (typically dynamically-assembled URLs). Surfaced as `runtime-observed` endpoint findings. Scan-only, first-party scoped, de-duplicated against static findings. |

### Risk tiers

Every finding is scored and tiered:

| Tier | Meaning |
|---|---|
| **P0** | Critical — act immediately |
| **P1** | High |
| **P2** | Medium — investigate |
| **P3** | Low / informational |

---

## Output & Reports

| Format | Flag | Notes |
|---|---|---|
| **JSON** | `-f json` (default) | Full report, secrets masked, prefers source-map original positions, includes `request_contract` + all enhancement metadata |
| **HTML** | `-f html` | Self-contained report that embeds its own JSON (round-trippable with `convert`) |
| **SARIF 2.1.0** | `-f sarif` | GitHub Code Scanning / Azure DevOps; rules `JSFINDER001–005`, CWE taxonomy, code flows for normalized vs. original positions |

Extra artifacts (written next to the main report):

- **Fuzzing wordlists** — `-w {all,endpoints,paths,params,domains,dirs}` → `wordlist_endpoints.txt`, `wordlist_paths.txt`, `wordlist_params.txt`, `wordlist_domains.txt`, `wordlist_dirs.txt` (`${…}` replaced with `FUZZ`; ffuf/dirsearch/feroxbuster-compatible).
- **API map** — `--api-map` → `api_map.json` + `api_map.txt` (an ASCII tree of domains → routes → params).

Default report names: `bundleInspector_report.<ext>` (scan), `bundleInspector_local_report.<ext>` (analyze), `report.<ext>` (convert).

---

## Performance

- **Parallel analysis** — set `BUNDLEINSPECTOR_PARALLEL`: unset/`0`/`1` = serial; `auto` = one worker per CPU; integer `N` = `N` workers. Parse **and** analyze are fused inside each worker so multi-MB ASTs never cross the process boundary — output is byte-identical to serial.

  ```bash
  BUNDLEINSPECTOR_PARALLEL=auto bundleInspector analyze ./big-bundle-dir
  ```

- **Native parser** — `BUNDLEINSPECTOR_NATIVE_PARSER=1` (needs Node.js + acorn) parses via a short-lived Node subprocess; any failure transparently falls back to `esprima`.
- **Resume / checkpoints** — `--job-id <id> --resume` reuses the latest stored report or per-stage checkpoint. A **resume signature** invalidates stale state if the profile, parser, rules, auth, scope, depth, or headless setting changed under the same job id.
- **Under the hood** — content-hash dedup avoids re-analyzing identical assets; a required-literal prefilter lets most non-secret strings skip the ~100 secret regexes; the endpoint detector memoizes AST walks.

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

`--cookies-file` and `--cookies-from` are mutually exclusive. Auth header values are validated against CR/LF/NUL injection.

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

1. **Crawl** — discover JS URLs (static HTML collector, optional headless render, build-manifest probing); SSRF-checked seeds; headless network capture feeds enh2's observed-request baseline.
2. **Download** — fetch JS with per-domain rate limiting, a concurrency semaphore, SSRF revalidation, size caps, and content-hash dedup.
3. **Normalize** — beautify, build line mappers, resolve inline + external source maps.
4. **Parse** — build the AST (esprima or optional acorn).
5. **Analyze** — run the rule engine + context-filter FP reduction + enh1 gating annotation + metadata/position mapping.
6. **Correlate** — enh2 dormant-endpoint annotation, then build the correlation graph (edges + clusters). Edge types include same-file, import/call-chain, runtime, secret↔endpoint, and **taint** — a light dataflow link that auto-connects a **file-upload surface (or upload/file endpoint) → a DOM `src`/`href` sink fed a file/image/upload-looking value** in the same asset, surfacing the `upload → <img src>` stored/DOM-XSS chain (heuristic, MEDIUM confidence — a correlated sink is also risk-scored higher).
7. **Classify** — assign risk tier, risk score, impact & likelihood per finding.
8. **Report** — assemble, summarize, and persist findings/report/checkpoints.

---

## Notes & Limitations

- **No built-in proxy support.** There is no `--proxy` flag; traffic is not routed through an upstream proxy such as Burp or ZAP. Intercept at the OS/network layer if you need to.
- **Exit codes.** `0` = success (even **with** findings), `1` = error or interrupt, `2` = the `--fail-on` severity gate tripped. Without `--fail-on` there is no severity-based gate, so a clean-exit-with-findings stays `0` — either use `--fail-on`, or decide pass/fail from the report/SARIF. (A malformed CLI invocation also exits `2` at parse time, per Click — but *before* the scan runs and with no report written, so it is distinguishable from a gate trip.)
- **Config-only settings.** `interactive_clicking`, `block_state_changing_requests`, `min_severity`, and `min_risk_tier` have **no CLI flag** — set them in a `--config` YAML/JSON file.
- **The `on_state_change_attempt` confirm hook** is a programmatic (Python API) hook, not a CLI option; without it, induced state-changing requests are simply blocked.
- **Duplicate cookie names** in a header string resolve last-wins.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `playwright` / browser errors on `scan` (e.g. `headless_browser_not_installed`, `Executable doesn't exist`) | Run `playwright install chromium`, or add `--no-headless` (or use a non-headless profile). The scan still runs its static/manifest collectors, but an SPA needs the headless browser to yield JS. |
| `playwright install` fails with `SELF_SIGNED_CERT_IN_CHAIN` | A TLS-intercepting proxy (corporate MITM) is breaking Node's download. **Secure fix:** point Node at your proxy's root CA — `setx NODE_EXTRA_CA_CERTS C:\path\to\corp-root-ca.pem` then reopen the shell and re-run. **Quick (insecure) fix:** `$env:NODE_TLS_REJECT_UNAUTHORIZED=0; playwright install chromium` (one session only). If a proxy is required, also set `$env:HTTPS_PROXY`. |
| Scan feels too aggressive / noisy | Use `--config examples/scan-profiles/conservative.yml`, raise `--rate-limit`, lower `max_concurrent` |
| Native parser not used | Ensure Node.js is on `PATH`, `acorn` is resolvable, and `BUNDLEINSPECTOR_NATIVE_PARSER=1` — otherwise it silently uses esprima |
| Resume re-runs from scratch | The config changed under the same `--job-id` (profile/rules/scope/etc.), which invalidates stale state by design |
| Secrets appear masked | Expected — set `rules.mask_secrets: false` in a config file only for local, trusted analysis |
| Large local bundles are slow | Try `BUNDLEINSPECTOR_PARALLEL=auto`, or the `fast` profile (beautify off) |
| Non-ASCII (Korean, etc.) console output looks garbled on Windows | Handled automatically — the CLI forces UTF-8 on stdout/stderr, so no `PYTHONIOENCODING` is needed; just use a UTF-8-capable terminal (e.g. Windows Terminal) |
| `--cookies-from` returns no cookies | The DB (incl. `-wal`) is copied, so the browser may stay open. Chrome/Edge/Chromium encrypted values are decrypted automatically on Windows when the optional `cryptography` package is installed (`pip install cryptography`). Still empty → the profile likely uses app-bound encryption (Chrome 127+); export via a cookie extension to JSON and use `--cookies-file` |

---

Built for authorized security testing. Use responsibly. See the [README](../README.md) for the short version.
