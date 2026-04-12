# Config Reference

This document describes the current shipped `Config` model used by BundleInspector.
It reflects the runtime behavior in `src/bundleInspector/config.py` and the current
CLI wiring in `src/bundleInspector/cli.py`.

## Top Level

- `scope`: scope policy and first/third-party rules
- `auth`: cookies and headers used for remote scans
- `crawler`: remote crawling/downloading behavior
- `parser`: parse/beautify/source-map behavior
- `rules`: detection-engine behavior
- `output`: report-output behavior
- `log_level`: `debug`, `info`, `warning`, `error`
- `verbose`: verbose CLI mode
- `quiet`: quiet CLI mode
- `cache_dir`: persistent job storage root
- `temp_dir`: optional temp directory
- `job_id`: explicit persistent job id
- `resume`: reuse report/checkpoint state when possible

## Scope

- `allowed_domains`: allowed domain patterns
- `denied_domains`: blocked domain patterns
- `include_subdomains`: seed domains also allow `*.domain`
- `allowed_paths`: allowed path prefixes/patterns
- `denied_paths`: denied path prefixes/patterns
- `third_party_policy`: `analyze`, `skip`, `tag_only`
- `cdn_patterns`: known CDN patterns used for first/third-party heuristics

## Auth

- `cookies`: `{name: value}` cookie map
- `headers`: arbitrary HTTP headers
- `bearer_token`: emits `Authorization: Bearer ...`
- `basic_auth`: tuple of `(user, password)`

Runtime notes:

- header, bearer-token, and basic-auth values are validated against CR/LF injection
- CLI auth flags and imported cookies/headers merge into this section

## Crawler

- `max_depth`: recursive crawl depth
- `max_pages`: max pages for recursive collectors
- `max_js_files`: cap on downloaded JS refs
- `rate_limit`: seconds between requests
- `max_concurrent`: concurrent request cap
- `request_timeout`: HTTP timeout seconds
- `page_timeout`: browser navigation timeout seconds
- `max_redirects`: redirect cap
- `follow_redirects`: enable redirects
- `use_headless`: enable headless collector
- `headless_wait_time`: post-load wait
- `explore_routes`: allow route exploration
- `max_route_exploration`: route/click exploration cap
- `max_retries`: HTTP retry count
- `retry_delay`: retry delay seconds
- `user_agent`: remote-scan user agent
- `max_file_size`: max downloaded JS size in bytes

## Parser

- `tolerant`: tolerant parser mode
- `partial_on_error`: allow partial/fallback parse
- `extract_strings`: parser-model field
- `extract_calls`: parser-model field
- `extract_imports`: parser-model field
- `build_call_graph`: parser-model field
- `beautify`: normalize/beautify JS before parse
- `resolve_sourcemaps`: resolve source maps when available

Runtime notes:

- the current runtime always builds the shipped IR structures it needs
- `beautify` and `resolve_sourcemaps` are actively honored

## Rules

- `enabled_categories`: enabled rule categories
- `custom_rules_file`: JSON/YAML custom rule file
- `min_confidence`: minimum confidence threshold setting
- `mask_secrets`: whether JSON output masks secret values
- `secret_visible_chars`: secret masking helper setting
- `entropy_threshold`: entropy threshold for generic secret detection
- `extract_headers`: endpoint-rule setting
- `extract_parameters`: endpoint-rule setting

Runtime notes:

- `custom_rules_file` is honored by `scan` and `analyze`
- `mask_secrets` is honored by the JSON reporter path in the CLI

## Output

- `format`: `json`, `html`, `sarif`
- `output_file`: explicit output file path
- `output_dir`: default directory used when no explicit output file is given
- `include_raw_content`: keep raw asset payloads in JSON output
- `include_ast`: output-model field
- `include_snippets`: output-model field
- `snippet_context_lines`: output-model field
- `min_severity`: output-model field
- `min_risk_tier`: output-model field

Runtime notes:

- `format`, `output_file`, and `output_dir` are honored by `scan` and `analyze`
- `include_raw_content` is honored by JSON output
- HTML and SARIF use their shipped fixed output schema

## File Formats

`Config.from_file()` supports:

- `.json`
- `.yaml`
- `.yml`

YAML uses the bundled fallback loader, so `PyYAML` is not required for the
shipped subset.

