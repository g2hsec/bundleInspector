# Remote Scan Profiles

These are ready-to-use runtime config files for real website diagnosis.
They use the current shipped `Config` model and can be passed directly to:

```bash
bundleInspector scan https://target.example.com --config examples/scan-profiles/ultra-safe.yml --job-id target
bundleInspector scan https://target.example.com --config examples/scan-profiles/conservative.yml --job-id target
bundleInspector scan https://target.example.com --config examples/scan-profiles/standard.yml --job-id target
bundleInspector scan https://target.example.com --config examples/scan-profiles/deep.yml --job-id target
```

Recommended usage:

- `ultra-safe.yml`
  - use when automation rules are unclear or unusually strict
  - no headless browser
  - no route exploration
  - single-page, lowest practical traffic

- `conservative.yml`
  - use for first-pass triage
  - no headless browser
  - no route exploration
  - lowest traffic

- `standard.yml`
  - use for most production website diagnosis
  - headless initial render enabled
  - no route walking or click exploration
  - balanced coverage vs traffic

- `deep.yml`
  - use for SPA-heavy targets when lazy-loaded chunks matter
  - headless route exploration enabled
  - highest coverage and highest traffic of the three profiles

## Profile Comparison

These are practical traffic expectations, not hard guarantees. Actual request
volume depends on the target's frontend behavior, number of discovered assets,
and whether rendering triggers additional API calls.

| Profile | Key settings | Typical use | Realistic traffic expectation | Operational risk |
|---|---|---|---|---|
| `ultra-safe` | depth `0`, pages `1`, headless `off`, routes `off`, concurrency `1`, rate limit `5.0s` | unknown rules, strict programs, first contact | usually one entry page plus discovered JS and manifest requests; often tens of requests on a typical site | lowest |
| `conservative` | depth `1`, pages `10`, headless `off`, routes `off`, concurrency `2`, rate limit `2.5s` | first-pass triage | usually tens to low hundreds of requests on a typical site | low |
| `standard` | depth `2`, pages `30`, headless `on`, routes `off`, concurrency `4`, rate limit `1.25s` | normal authorized diagnosis | often low hundreds of requests and may trigger extra frontend/API traffic during render | medium |
| `deep` | depth `3`, pages `80`, headless `on`, routes `on`, concurrency `8`, rate limit `0.75s` | SPA-heavy authorized testing | often hundreds of requests and can rise further if the app lazily loads many chunks or API calls | high |

Typical invocation:

```bash
bundleInspector scan https://target.example.com \
  --config examples/scan-profiles/ultra-safe.yml \
  --scope "target.example.com" \
  --job-id example-ultra-safe \
  --resume
```

Typical standard invocation:

```bash
bundleInspector scan https://target.example.com \
  --config examples/scan-profiles/standard.yml \
  --scope "*.example.com" \
  --job-id example-prod \
  --resume \
  -o report.html
```

If authentication is required, combine the profile with one of:

- `--cookies-file cookies.json`
- `--cookies-from chrome`
- `--headers-file headers.txt`
- `--bearer-token ...`
- `--basic-auth user:password`

Notes:

- `resume: true` is set in these profiles, but you still need `--job-id` if you
  want stable per-target persistence across runs.
- CLI flags override config values when supplied explicitly.
- `output.output_dir` is pre-filled so repeated runs have a predictable default
  report location unless `-o/--output` overrides it.
- These profiles still create real remote traffic. They are not equivalent to a single harmless page fetch.
- `ultra-safe` is the lowest-impact profile and the safest choice when you are not sure what a program allows.
- `conservative` is the safest profile here. `standard` is clearly visible in logs. `deep` can be operationally unsafe on small services, brittle legacy apps, or heavy SPA targets.
- The default `bundleInspector scan ...` behavior is more aggressive than `conservative`, so do not rely on defaults for production systems or bug bounty targets.
- Always follow program-specific traffic limits, automation policy, and safe-harbor rules. If you do not have explicit permission for heavier testing, start with `ultra-safe` or `conservative`.

