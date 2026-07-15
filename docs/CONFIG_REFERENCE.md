# Config Reference

This document describes the shipped `Config` model in
`src/bundleInspector/config.py` and the CLI behavior in
`src/bundleInspector/cli.py`. Configuration files are UTF-8/UTF-8-SIG JSON,
YAML, or YML. PyYAML is the normal YAML backend; the bounded built-in parser
only covers the shipped subset when PyYAML cannot be imported and for
PyYAML's specific unknown-escape compatibility case.

Every config model rejects unknown fields and validates assignments. A typo
therefore fails closed instead of being silently ignored.

## Top Level

| Field | Default | Meaning and validation |
|---|---|---|
| `scope` | `ScopeConfig()` | First/third-party and SSRF scope policy |
| `auth` | `AuthConfig()` | Credentials used by remote collectors |
| `crawler` | `CrawlerConfig()` | Remote collection limits and behavior |
| `parser` | `ParserConfig()` | Normalization, parsing, and IR extraction |
| `rules` | `RuleConfig()` | Built-in and custom detection behavior |
| `output` | `OutputConfig()` | CLI report rendering and destination |
| `log_level` | `info` | `debug`, `info`, `warning`, or `error` |
| `verbose` | `false` | Verbose CLI output |
| `quiet` | `false` | Minimal CLI output |
| `cache_dir` | `~/.bundleInspector/cache` | Persistent jobs, checkpoints, reports, ownership, and MCP projection metadata |
| `temp_dir` | `null` | Optional native-parser handoff directory, including process workers |
| `job_id` | `null` | Optional portable persistent job identifier |
| `resume` | `false` | Reuse compatible report/checkpoint state |

A filesystem-backed `job_id` is 1-128 lowercase characters matching
`[a-z0-9][a-z0-9._-]{0,127}`. It must not end in a dot, contain a path or
alias spelling, or have a Windows device stem such as `con`, `nul`, `com1`,
or `lpt1`.

`Config.ensure_dirs()` falls back to `.bundleInspector/cache` under the
current workspace only when creating the configured cache directory raises
`PermissionError`. Use the resulting effective path, not an assumed default,
when attaching MCP to that run.

## Scope

| Field | Default | Meaning and validation |
|---|---|---|
| `allowed_domains` | `[]` | Allowed domain patterns |
| `denied_domains` | `[]` | Denied domain patterns |
| `include_subdomains` | `true` | Add `*.domain` when a seed domain is registered |
| `allowed_paths` | `[]` | Allowed path patterns |
| `denied_paths` | `[]` | Denied path patterns |
| `third_party_policy` | `tag_only` | `analyze`, `skip`, or `tag_only` |
| `allow_private_ips` | `false` | Permit RFC1918/CGNAT/ULA destinations for authorized internal testing |
| `cdn_patterns` | 16 built-ins | Known CDN patterns used by first/third-party classification |

Each of `allowed_domains`, `denied_domains`, and `cdn_patterns` accepts at
most 100 entries. Every entry must be a non-empty string of at most 256
characters and may contain at most two `*` characters.

`allow_private_ips` is a narrow SSRF opt-in. Loopback, cloud metadata
(`169.254.169.254`), multicast/reserved ranges, and blocked hostnames such as
`localhost` remain blocked. The CLI equivalent is `--allow-private-ips`.

## Auth

| Field | Default | Meaning and validation |
|---|---|---|
| `cookies` | `{}` | Cookie `{name: value}` map; names must be non-empty |
| `headers` | `{}` | Additional request headers |
| `bearer_token` | `null` | Emits `Authorization: Bearer ...` |
| `basic_auth` | `null` | `(user, password)` tuple used for HTTP Basic auth |

Cookie and header names must be non-empty. Cookie/header names and values,
bearer tokens, and both basic-auth components reject CR, LF, and NUL. `Host`,
`Content-Length`, and `Transfer-Encoding` are transport-controlled and cannot
be configured as headers.

CLI cookie/header flags and imported credentials merge into this section.
Serialized reports contain only the configured auth kinds, not live auth
values. Construction and whole-field assignment validate immediately; the
shared transport-preparation path revalidates mutable cookie/header maps for
control-character injection. Origin-bound transport filtering separately
removes `Host`, `Content-Length`, and `Transfer-Encoding` if an unsafe object or
in-place mutation bypasses the normal assignment boundary.

## Crawler

| Field | Default | Meaning and validation |
|---|---|---|
| `max_depth` | `3` | Recursive crawl depth, integer >= 0 |
| `max_pages` | `100` | Recursive page cap, integer >= 0 |
| `max_js_files` | `1000` | Downloaded-JS cap, integer >= 0 |
| `rate_limit` | `1.0` | Seconds between requests, finite and >= 0 |
| `max_concurrent` | `10` | Concurrent request cap, integer >= 1 |
| `request_timeout` | `30.0` | HTTP timeout seconds, finite and >= 0 |
| `page_timeout` | `60.0` | Browser navigation timeout seconds, finite and >= 0 |
| `max_redirects` | `10` | Redirect cap, integer >= 0 |
| `follow_redirects` | `true` | Follow redirects within the policy limits |
| `use_headless` | `true` | Enable the Playwright collector |
| `headless_wait_time` | `2.0` | Post-load wait seconds, finite and >= 0 |
| `explore_routes` | `true` | Explore route links to discover lazy assets |
| `max_route_exploration` | `20` | Route/click exploration cap, integer >= 0 |
| `interactive_clicking` | `false` | Click button/tab/role elements; highest-risk UI driving and off by default |
| `block_state_changing_requests` | `true` | Once route/click exploration begins, record then block induced `POST`/`PUT`/`PATCH`/`DELETE` for the remaining page lifetime unless a low-level confirmation handler approves |
| `max_retries` | `3` | Retry count for retryable collection failures, integer >= 0 |
| `retry_delay` | `1.0` | Retry delay seconds, finite and >= 0 |
| `user_agent` | Chrome-compatible UA | Remote-scan User-Agent |
| `max_file_size` | `10485760` | Maximum downloaded JS bytes, integer >= 0 |

The state-change guard is not a guarantee that a target cannot mutate.
Initial page-load traffic is intentionally untouched, a configured low-level
handler may approve a request, the guard can be disabled, and a target may
attach state changes to an idempotent-looking method. Service workers are
always blocked in the headless browser context because Playwright routing
cannot inspect requests intercepted by them, even when the method-based
mutation guard is disabled. The public high-level `BundleInspector`
constructor and CLI do not expose the low-level confirmation handler.

## Parser

| Field | Default | Meaning and validation |
|---|---|---|
| `tolerant` | `true` | Permit tolerant/recovery parsing |
| `partial_on_error` | `true` | Return an explicitly incomplete recovery result when possible |
| `extract_strings` | `true` | Populate IR string literals |
| `extract_calls` | `true` | Populate IR call sites |
| `extract_imports` | `true` | Populate IR imports/dynamic imports |
| `build_call_graph` | `true` | Build call edges used by detection and correlation |
| `beautify` | `true` | Attempt safe JS beautification before parsing |
| `resolve_sourcemaps` | `true` | Resolve available inline/external source maps |
| `beautify_max_bytes` | `1000000` | For a positive value, use identity normalization above this byte count; `0` disables the size cap; integer >= 0 |
| `analysis_worker_timeout` | `30.0` | Per-asset process-worker deadline; finite and in `[0.1, 600]` |

All four IR extraction flags are active. Disabling one removes that data from
the IR and can reduce detector/correlator coverage.

Normalization is conditional, not a promise that every asset is rewritten.
It retains the raw content-hash artifact and uses identity normalization when beautifying
is disabled, the size cap is exceeded, TypeScript/JSX markers make
`jsbeautifier` unsafe, beautification fails, or normalized output does not
preserve the raw static-literal multiset. Accepted beautification carries a
line mapping back to raw evidence. Source-map resolution enriches original
locations separately and can itself be incomplete.

An explicit JavaScript/JSX/TypeScript/TSX `language_hint` selects the matching
required Tree-sitter grammar first. Optional Node.js/Acorn is an opt-in ESTree
path for unhinted input; Esprima and lexical parsing are legacy/recovery
paths. Parser backend, completeness, capability gaps, and truncation reasons
are recorded instead of presenting recovery as a complete structural parse.

## Rules

| Field | Default | Meaning and validation |
|---|---|---|
| `enabled_categories` | all 7 categories | `endpoint`, `secret`, `domain`, `flag`, `debug`, `sink`, `upload`; normalized, deduplicated, unknown values rejected |
| `custom_rules_file` | `null` | JSON/YAML file, rule directory, or ruleset `meta.yml` path |
| `min_confidence` | `low` | `low`, `medium`, or `high`; normalized and validated |
| `mask_secrets` | `true` | Build masked secret values and sanitize report output |
| `secret_visible_chars` | `4` | Requested visible characters per side, integer in `[0, 1024]`; actual masking also caps each side to 25% of value length, and `0` masks the full value |
| `entropy_threshold` | `3.5` | Generic-secret entropy threshold, finite and >= 0 |
| `extract_headers` | `true` | Extract request headers in endpoint detection |
| `extract_parameters` | `true` | Extract request parameters in endpoint detection |
| `client_side_gating_enabled` | `true` | Detect client-side access-control gating |
| `client_side_gating_severity` | `medium` | Severity floor for gated endpoints; `info`, `low`, `medium`, `high`, or `critical`, normalized and validated. High-confidence role/permission/entitlement guards are promoted to at least `high` |
| `dormant_endpoint_detection_enabled` | `true` | Mark static endpoints not observed at runtime |
| `runtime_endpoint_surfacing_enabled` | `true` | Surface first-party HTTP/WebSocket calls seen only at runtime; scan-only |

`mask_secrets` is honored by JSON, HTML, and SARIF CLI reporters, and all three
receive the same configured `secret_visible_chars` value for canonical
redaction. A normal engine-produced secret finding already carries the
configured `masked_value`; reporters additionally sanitize snippets and
metadata. Cache contents remain a private trust boundary and must not be
treated as a public redacted export.

See [Custom Rules](CUSTOM_RULES.md) for the supported DSL, loader failure
semantics, and regex resource limits.

## Output

| Field | Default | Meaning and validation |
|---|---|---|
| `format` | `json` | `json`, `html`, or `sarif` |
| `output_file` | `null` | Configured output path |
| `output_dir` | `null` | Default directory when no explicit output file is selected |
| `include_raw_content` | `false` | Include report asset byte payloads in JSON output only; an eligible asset may contain its accepted normalized derivative |
| `include_ast` | `false` | Preserve finding `evidence.ast_node_type` and `metadata.ast_path` in the rendered copy |
| `include_snippets` | `true` | Preserve evidence snippets in the rendered copy |
| `snippet_context_lines` | `3` | Lines around evidence, integer in `[0, 50]` |
| `min_severity` | `info` | `info`, `low`, `medium`, `high`, or `critical`; normalized and validated |
| `min_risk_tier` | `P3` | `P0`, `P1`, `P2`, or `P3`; normalized and validated |

These content and threshold settings are applied by the CLI to a deep report
copy immediately before JSON/HTML/SARIF rendering. A finding must meet both
thresholds; a finding with no `risk_tier` bypasses only the tier test.
`include_snippets: false` also removes snippet-derived metadata. Changing
`snippet_context_lines` crops normalized and available original snippets.
`include_ast` does not serialize a full AST.

Output filtering does not mutate the analyzed or persisted report. Console
triage, `--fail-on`, wordlists, and API maps continue to use the full finding
set. HTML and SARIF use their fixed schemas; asset analysis-input bytes, which
may be an accepted normalized derivative, are available only through JSON with
`include_raw_content: true`.

An explicit CLI `-o/--output` path wins over `output_file`; `output_dir` is
used for the generated default name when neither explicit path is present.

## Persistent Storage and MCP Contract

- Current `scan` and `analyze` jobs are registered to the fixed local MCP
  principal through a per-job `.owner` record. MCP lists only jobs owned by
  that principal.
- Recognized ownerless legacy caches remain usable only through the private
  compatibility path. They are never adopted automatically and are not
  enumerable through MCP. Re-run the analysis into a fresh current-format job
  rather than manufacturing an ownership file.
- The project exposes the `bundleInspector-mcp` entry point; the optional
  `[mcp]` extra supplies its runtime dependency. From a source checkout install
  it with `python -m pip install -e ".[mcp]"`. Only `--transport stdio` is accepted. There is no
  HTTP/SSE listener, remote authentication layer, or scan/write/cancel tool.
- Omit `--cache-dir` to use the same `~/.bundleInspector/cache` default as the
  analyzer, or pass the exact same configured cache path. Pointing the server
  at a different directory yields a different job view.
- The public surface contains `list_jobs`, `get_job_status`, and
  `get_report_page`, plus the `application/json`
  `bundleinspector://jobs/{job_id}` resource template. It exposes bounded,
  allowlisted, redacted DTOs and opaque public identifiers, not raw cache IDs,
  local paths, ASTs, source payloads, credentials, or private diagnostics.
- `get_report_page` accepts only `findings`, `assets`, `correlations`, or
  `clusters` as its page kind. Call `list_jobs` first and use the returned
  opaque job identifier; a raw filesystem job id is deliberately rejected.
- Constructing the MCP service loads or creates `cache_dir/.public-view-key`
  and may create its shared lock shard. The tools are semantically read-only,
  but first startup is therefore not a zero-filesystem-write operation. The
  key signs cursors and derives opaque IDs; keep it private and stable. Offline
  key replacement invalidates existing cursors and public IDs.
- Public cursors are signed and bound to the page kind, limit, report/job
  context, and current content revision. Limits are 1-100. Stale, malformed,
  or context-mismatched cursors are rejected.
- `cache_dir` and every ancestor are a local service-account trust boundary.
  Do not allow untrusted principals to replace or write those directories.

Filesystem-backed job, report, and finding identifiers use the same portable
component rule. Final symlink/reparse, nonregular, and multi-link entries are
rejected, but the runtime does not claim to defeat an attacker who can
concurrently replace a writable ancestor.

Atomic persistent-file operations map names onto exactly 64 sibling
`.bundleinspector-lock-00` through `.bundleinspector-lock-3f` shards. Never
delete lock files while a process may be running. Legacy per-payload lock files
are not removed automatically.

Before an offline cache upgrade, stop every BundleInspector/MCP process, back
up the cache, and inventory immediate job names plus report/finding stems by
`casefold()`. Resolve case-only collisions before renaming entries to portable
lowercase form. Only after confirming no old process remains may reviewed
legacy lock cleanup occur; the runtime never guesses which colliding entry
should win.
