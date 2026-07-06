<div align="center">

# 🔎 BundleInspector

### Surface the attack surface hiding in JavaScript.

A static **+** dynamic security scanner that pulls hidden API endpoints, hardcoded secrets,
internal domains, and client-side bypass surface out of JavaScript bundles —
for pentesters, bug-bounty hunters, and AppSec teams.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-brightgreen.svg)](#)
[![Headless: Playwright](https://img.shields.io/badge/headless-Playwright-2ea44f.svg)](https://playwright.dev/)
[![Output: SARIF](https://img.shields.io/badge/output-JSON%20%C2%B7%20HTML%20%C2%B7%20SARIF-orange.svg)](#-what-it-finds)

**English** · [한국어](README.ko.md) · [📖 User Guide](docs/USER_GUIDE.md)

</div>

---

## ✨ Highlights

- **Two modes** — `scan` a live site (crawl → render → download → analyze) or `analyze` local bundles with **zero network traffic**.
- **Deep static extraction** — hidden REST / GraphQL / WebSocket endpoints, ~100 secret types, internal & staging domains, feature flags, and debug endpoints — resolved through template literals, string concatenation, ternaries, and constants.
- **Offensive recon built in** — six enhancements: client-side access-control gating, **dormant/hidden endpoints**, replayable curl/fetch PoCs, IDOR + HTTP method-flip hints, full SPA route maps, and GraphQL/WebSocket surface.
- **Safe by default** — state-changing requests (`POST`/`PUT`/`DELETE`) the crawler induces are **blocked and confirmed, not sent**; per-domain rate limiting with adaptive backoff; SSRF & scope guards; secret masking.
- **Fast** — file-level multiprocessing, an optional native (acorn) parser, content-hash dedup, and resumable checkpoints.
- **Reports that fit your workflow** — JSON, a self-contained HTML report, and **SARIF** for GitHub Code Scanning — plus fuzzing wordlists and a reconstructed API map.

## 🚀 Install

Requires **Python 3.10+**. Headless scanning needs the Playwright Chromium binary.

```bash
git clone https://github.com/g2hsec/bundleInspector.git
cd bundleInspector
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -e .
playwright install chromium
```

## ⚡ Quick Start

```bash
# Scan a live target — always stay in scope
bundleInspector scan https://target.example.com --scope "*.example.com"

# Analyze a local bundle — no network traffic at all
bundleInspector analyze ./dist

# Write a shareable HTML report
bundleInspector scan https://target.example.com -f html -o report.html

# Emit SARIF for CI / GitHub Code Scanning
bundleInspector scan https://target.example.com -f sarif -o findings.sarif

# Resume a long scan by job id
bundleInspector scan https://target.example.com --job-id acme --resume
```

## 🛡️ Safety First

BundleInspector is a recon tool, not a DoS tool — and the defaults reflect that:

- **Interactive clicking is OFF by default.** The crawler won't click buttons/tabs that could submit forms or trigger deletes.
- **State-changing requests are blocked by default.** Any `POST`/`PUT`/`PATCH`/`DELETE` the crawl induces is intercepted, **recorded** (so you still discover the endpoint), and **not sent** — unless a wired confirm handler approves it.
- **Throttled & scoped.** Per-domain rate limiting (default `1 req/s`) with `429`/`5xx` backoff, SSRF protection, and strict scope patterns.

> **New to a target?** Start with the **`ultra-safe`** or **`conservative`** profile.
> Full details in the [Traffic & Safety guide »](docs/USER_GUIDE.md#-traffic--safety)

## 🎚️ Scan Profiles

Presets in [`examples/scan-profiles/`](examples/scan-profiles/) trade coverage for traffic:

| Profile | Crawl | Headless | Traffic | Use it for |
|---|---|---|---|---|
| `ultra-safe` | 1 page | off | lowest | unknown rules, first contact |
| `conservative` | shallow | off | low | bug-bounty / prod triage |
| `standard` | medium | on | medium | authorized diagnosis |
| `deep` | broad | on + routes | high | SPA-heavy targets |
| `fast` | shallow | off | low | speed over fidelity (beautify off) |

```bash
bundleInspector scan https://target.example.com --config examples/scan-profiles/conservative.yml
```

## 🧭 Commands

| Command | What it does |
|---|---|
| `scan <urls…>` | Crawl + analyze one or more **live** targets |
| `analyze <paths…>` | Analyze local files / dirs / globs — **no network** |
| `convert <report>` | Convert a report between JSON ⇄ HTML |
| `version` | Print the version |

Most-used flags: `-s/--scope`, `-c/--cookie`, `-H/--header`, `-o/--output`, `-f/--format {json,html,sarif}`, `-w/--wordlist`, `--api-map`, `--no-headless`, `--job-id` / `--resume`.
Full reference → [CLI section of the User Guide »](docs/USER_GUIDE.md#-cli-reference)

## 🔬 What It Finds

| Category | Examples |
|---|---|
| **Endpoints** | `fetch`/`axios`/XHR calls, REST · `/graphql` · WebSocket URLs, resolved from templates & constants |
| **Secrets** | ~100 key types (AWS, GCP, Stripe, GitHub, Slack, JWT, private keys) + entropy analysis |
| **Domains** | internal/staging hosts, `.internal`/`.local`, private IPs, S3/GCS/Azure buckets |
| **Feature flags** | LaunchDarkly/Optimizely/Split keywords, `isFeatureEnabled`, admin/debug toggles |
| **Debug** | `/debug` `/admin` `/actuator`, `console.log` of sensitive data, `debugger`, dev-only branches |

Findings are risk-tiered **P0 → P3** (critical → informational) with impact/likelihood scoring, and enriched with the six recon enhancements — see the [Detection Coverage guide »](docs/USER_GUIDE.md#-detection-coverage).

## 📚 Documentation

- **[User Guide](docs/USER_GUIDE.md)** — full CLI, configuration, detections, safety deep-dive, performance
- **[Config Reference](docs/CONFIG_REFERENCE.md)** — every configuration field
- **[Custom Rules](docs/CUSTOM_RULES.md)** — write your own regex / AST / semantic rules

## ⚖️ License & Disclaimer

Released under the **MIT License** — see [LICENSE](LICENSE).

> Only scan systems you **own** or are **explicitly authorized** to test. You are responsible for staying within a target's rules, rate limits, and automation policy. Test fixtures in this repo intentionally contain **fake** secret-like strings so detection and masking can be verified — they are not live credentials.
