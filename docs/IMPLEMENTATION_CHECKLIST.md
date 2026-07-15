# BundleInspector Current Implementation Checklist

This is a current-state checklist for version `0.1.0`, not a historical changelog. The repository
has no Git metadata from which to reconstruct a controlled before/after comparison. A checked item
means that the capability exists in the current implementation and is covered by an executable
contract; it does not mean that static analysis is complete for every JavaScript program.

## Runtime and Entry Points

- [x] Package metadata supports CPython 3.10 through 3.13 (`>=3.10,<3.14`).
- [x] `bundleInspector scan` performs scoped remote collection and analysis.
- [x] `bundleInspector analyze` performs local file/directory/glob analysis without target-network
  traffic.
- [x] `bundleInspector convert` converts BundleInspector JSON/HTML reports, and `version` reports the
  package version.
- [x] JSON, self-contained HTML, and SARIF reports are supported; wordlist, attack-chain, and API-map
  views are available from the CLI.
- [x] Playwright is a runtime dependency, while the Chromium binary and host libraries are separate
  prerequisites for headless collection.
- [x] PyYAML and the JavaScript/TypeScript Tree-sitter grammars are direct runtime dependencies.
  Node.js/Acorn remains an optional parser path.

## Analysis Pipeline

| Area | Current implemented contract | Status |
|---|---|---|
| Collection | Static HTML, optional headless rendering, build-manifest probing, multipage discovery, bounded fixed-point asset expansion, source maps, and virtual/inline sources | Implemented |
| Network boundary | Seed, redirect, manifest, asset, and source-map requests are scope/SSRF checked; redirects and response sizes are bounded; credentials are origin-bound | Implemented |
| Evidence | The raw content-hash artifact is retained; eligible plain JS may use a literal-preserving beautified derivative as the parse/analyze input, while TS/JSX-shaped or literal-losing candidates stay raw-equivalent; findings preserve normalized and available original source locations | Implemented |
| Parser | Language hints route JS/JSX/TS/TSX to the matching structural backend; incomplete parsing is retried or explicitly reported as partial/degraded | Implemented |
| Completeness | Collection, parser, rule, cap, graph, and lifecycle loss is represented by `AnalysisCompleteness` issues instead of being silently reported as zero findings | Implemented |
| Detectors | Endpoints/request contracts, secrets, domains, flags, debug surface, routes/chunks, DOM/code sinks, uploads, GraphQL/WebSocket, and runtime/dormant surface | Implemented |
| Flow | Reachability-aware, binding/member/alias-aware, context-sensitive taint distinguishes confirmed, probable, and unavailable evidence; unreachable paths do not become confirmed flows | Implemented |
| Correlation | Canonical import/re-export/dynamic/runtime identities, directional edges, deterministic clustering, partition-fair caps, and cap telemetry | Implemented |
| Risk and triage | Evidence-sensitive risk tiers, download-surface annotation, third-party labeling, and non-destructive likely-false-positive annotation | Implemented |
| Resume | Per-stage and per-work-item checkpoints cover remote and local work; a content/config signature invalidates stale incompatible state | Implemented |
| Custom rules | Strict YAML/JSON regex, AST-pattern, and semantic matchers with bounded regex execution, captures, scopes, inheritance, and shipped pack support | Implemented |

## Security, Persistence, and Output

- [x] State-changing requests induced by headless exploration are blocked unless an explicit
  confirmation handler approves them; the guard remains armed for the page lifetime.
- [x] Authentication inputs reject control-character injection at construction, assignment, and
  transport preparation after mutable-map changes; persisted configuration, checkpoints, reports,
  logs, and public projections use credential-aware redaction.
- [x] Secret masking is applied across JSON, HTML, SARIF, snippets, and metadata. A visible-character
  count of zero produces no secret suffix.
- [x] Job/report/finding identities use portable path components. Storage rejects linked, reparse,
  non-regular, and multi-link payloads where the platform exposes those properties.
- [x] Persistent writes use atomic publication, bounded 64-shard sibling locks, ownership records,
  and terminal unsafe-path/commit errors rather than silently continuing.
- [x] Reporter input models are treated as immutable projections; one-shot user outputs use atomic
  replacement.
- [x] Strict configuration rejects unknown fields and propagates parser, rule, output, timeout,
  scope, and storage settings through the actual pipeline. Remote-scan asset parallelism is a
  separate opt-in `BUNDLEINSPECTOR_PARALLEL` environment control; local `analyze` remains serial.

## MCP Public Projection

The project exposes the `bundleInspector-mcp` entry point, and the optional `[mcp]` extra supplies
its runtime dependency. The standalone server is intentionally limited to local stdio and the
`local` repository principal.

| MCP surface | Current contract |
|---|---|
| Transport | `stdio` only; no HTTP/SSE listener and no protocol authentication |
| Tools | `list_jobs`, `get_job_status`, `get_report_page` |
| Resource template | `bundleinspector://jobs/{job_id}` with `application/json` MIME |
| Report page kinds | `findings`, `assets`, `correlations`, `clusters` |
| Pagination | Default 50, maximum 100; signed cursors bind request context, principal, and content revision |
| Identifiers | Repository-keyed opaque public IDs; raw filesystem IDs are rejected |
| Data boundary | Explicit immutable DTO allowlist with bounded values, secret/URI redaction, and bounded completeness summaries |
| Mutation boundary | No scan start/control, cache write tool, raw artifact retrieval, arbitrary local path, or internal exception/queue exposure |

- [x] Current jobs written with an ownership record for `local` are visible through the matching
  cache directory; ownerless legacy and foreign-principal jobs remain private.
- [x] Missing, malformed, and unauthorized public IDs collapse to the same public error.
- [x] Source and installed-wheel tests verify tool/resource enumeration, redaction, raw-ID rejection,
  revision-bound pagination, and no job/report mutation during reads.
- [x] First startup may create the cache directory, `.public-view-key`, and a lock shard. The tools
  are read-only, but provisioning is not a zero-write operation. Deleting or rotating the key
  changes opaque IDs and invalidates cursors.

The cache and all writable ancestors are an operating-system trust boundary. Do not expose the
stdio server through a network bridge without a separate authentication, authorization, quota,
approval, cancellation, and audit design.

## Detection Quality Evidence

| Gate | Current committed fixture | Current result | Scope limit |
|---|---|---|---|
| Public metrics | 45 cases, 1,916 labels/predictions, 19 release keys | 19/19 PASS; no FP/FN, parser, completeness, invariance, graph, or regression failure | Repository-visible synthetic/manual corpus |
| Frozen governance | 11 cases, 2,193 labels/predictions, 19 release keys | 19/19 PASS | Visible; all 11 share one frozen vendor family |
| Branch coverage | Full source line+branch instrumentation | CI requires at least 80% | Coverage is not proof of detector completeness |
| Full regression | Ubuntu Python 3.10/3.11/3.12/3.13 and Windows Python 3.13 | Required by CI | Platform-specific skips remain capability checks, not silent passes |

The public metric job runs on every configured workflow trigger. The frozen gate runs only for
`v*` tags, the weekly schedule, `release: published`, or an explicitly enabled manual dispatch; see
[Frozen Detection Governance](HELDOUT_GOVERNANCE.md). Corpus precision/recall of 1.0 is evidence for
these labels only and must not be presented as universal accuracy.

## Exact Synthetic Performance Gates

The first committed reference was measured on WSL2 Linux x86-64, CPython 3.13.7, and an AMD Ryzen 9
9950X with exact pinned dependencies. Every release scenario uses two warm-ups and 30 measured
runs, preserves one semantic signature, recomputes sample statistics/bootstrap intervals, and
requires timing CV no greater than 0.25.

### Correlator Reference

Each fixture uses import fanout 3 and four load contexts.

| Modules / findings | p50 ms | p95 ms | p95 bootstrap 95% CI ms | CV | Observed process peak RSS | Semantic output | Absolute p95 gate |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 80 / 160 | 311.577 | 330.026 | 320.358-342.076 | 0.034117 | 69.3 MiB | 1,130 edges / 1 cluster | 1,000 ms |
| 200 / 400 | 880.845 | 913.658 | 901.100-918.252 | 0.022666 | 82.3 MiB | 1,250 edges / 1 cluster | 2,500 ms |
| 500 / 1,000 | 4,062.641 | 4,131.418 | 4,103.741-4,173.599 | 0.015093 | 110.9 MiB | 1,550 edges / 1 cluster | 8,000 ms |

Only the 500-module scenario has a fixed 1 GiB absolute RSS ceiling; all three also participate in
the relative RSS gate.

### Detection Resource Reference

| Scenario / fixed input | p50 ms | p95 ms | p95 bootstrap 95% CI ms | CV | Observed suite-process peak RSS | Absolute gate |
|---|---:|---:|---:|---:|---:|---|
| Structural TypeScript parse / 1,048,576 B | 613.226 | 639.054 | 632.591-643.679 | 0.074678 | 385.4 MiB | p95 <=2,000 ms; RSS <=1 GiB |
| Bounded custom regex / 20,029 B | 50.179 | 50.234 | 50.210-50.253 | 0.000527 | 385.4 MiB | maximum wall time <=750 ms |
| Lexical candidate recovery / 150,123 B | 20.178 | 20.593 | 20.378-20.729 | 0.022348 | 385.4 MiB | p95 <=2,000 ms; RSS <=1 GiB |

The structural fixture must remain complete on the TypeScript Tree-sitter backend and preserve its
known endpoint. All 30 custom-regex runs must disclose the configured 50 ms timeout while preserving
the result found before timeout. All 30 lexical runs must retain the expected 10,002 candidates,
preserve single/template quote sentinels, and disclose cap truncation.

Same-CPU comparisons fail when point p95 regresses by more than 20% or process peak RSS by more than
25%. On a different CPU, the current p95 bootstrap lower bound is compared with the committed upper
bound times 1.20; RSS +25% still applies and the result is marked
`applied_cross_hardware_attribution_unavailable`.

These are the first current-reference baselines recorded after remediation. No comparable
pre-change baseline exists, so they do not establish a speedup percentage. They are synthetic stage
gates, not end-to-end `scan`/`analyze`, crawler, browser, network, or parallel-throughput SLAs.
Peak RSS is a process-lifetime high-water observation: later correlator rows and the equal detection
values are cumulative suite observations, not isolated per-scenario or incremental allocations.
Correlator timings also run with `tracemalloc` instrumentation active.

## Build and Release Verification

- [x] CI runs the complete test suite on supported Ubuntu Python minors and a Windows filesystem/full
  regression job.
- [x] Ruff, production mypy, branch coverage, public metrics, and exact synthetic performance gates
  fail closed.
- [x] Wheel and sdist paths are checked against `packaging/distribution-manifest.json`; archive
  structure, traversal/collision/link/device/bomb constraints, metadata, Twine, and wheel contents
  are checked before release.
- [x] Clean installed artifacts are smoke-tested for CLI entry points, packaged resources, TSX
  structural parsing, MCP stdio projection, and a headless Chromium launch with page rendering
  (`set_content` + `title` readback).
- [x] Baselines and frozen governance artifacts change only through explicit reviewed updater
  commands; CI never rewrites them.
- [x] A `v*` frozen-governance run is the documented pre-publication gate. The repository has no
  automated publisher, and `release: published` is necessarily a post-publication recheck.

## Remaining Limits

| Area | Explicit current limit |
|---|---|
| Static analysis | Dynamic code generation, opaque runtime state, server-side enforcement, and future syntax cannot be fully inferred. Partial/recovery modes report reduced completeness instead of claiming full coverage. |
| Statistical evidence | Public and frozen corpora are visible and template-related; the frozen cases share one vendor family. Current corpus scores do not estimate an independent external population. |
| Performance | Results are hardware- and fixture-specific synthetic stage gates. Cross-hardware failures cannot distinguish code from runner effects, and process high-water RSS is not per-operation allocation. |
| Headless memory | A response with false/missing `Content-Length` may be materialized by Playwright before the post-read byte cap; declared-size and concurrency caps limit other fan-out. |
| Browser setup | Clean Linux hosts need Chromium system libraries, normally installed with `playwright install --with-deps chromium`. |
| Filesystem | Sudden-power-loss durability for Windows namespace deletion is not guaranteed; some NFS implementations reject the required exclusive sidecar lock and therefore fail closed. |
| Cache trust | An attacker able to replace a writable cache ancestor is outside the supported service-account trust boundary. Legacy per-payload-lock writers require an offline upgrade. |
| MCP | Local read-only stdio projection only. There is no remote transport, protocol authentication, live standalone queue progress, write operation, or scan-control capability. |
| Release automation | Local workflow-contract verification does not substitute for an actual remote GitHub Actions run, and no workflow prevents a human from publishing before the tag gate finishes. |

The validation above is bounded by its explicit contracts and is not a claim of mathematical
perfection, zero future defects, or complete analysis of every JavaScript program.
