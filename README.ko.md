# BundleInspector

[English](README.md)

BundleInspector는 Python 기반 JavaScript 보안 분석 도구입니다.

- 웹사이트 원격 스캔으로 JavaScript를 수집하고 분석합니다.
- 로컬 JavaScript 번들을 네트워크 없이 분석할 수 있습니다.
- endpoint, secret, domain, feature flag, debug 신호와 상관관계를 추출합니다.

저장소 안내:
테스트 fixture와 회귀 테스트에는 탐지, 마스킹, 리포트 동작 검증을 위해 fake secret 문자열이 포함되어 있습니다. 전부 샘플 값이며 실제 자격증명은 아닙니다.

현재 구현 상태: [docs/IMPLEMENTATION_CHECKLIST.md](docs/IMPLEMENTATION_CHECKLIST.md)  
현재 config 모델: [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md)  
custom rule 문서: [docs/CUSTOM_RULES.md](docs/CUSTOM_RULES.md)  
correlator 벤치마크: [scripts/benchmark_correlator.py](scripts/benchmark_correlator.py)  
원격 스캔 프로필: [examples/scan-profiles/README.md](examples/scan-profiles/README.md)

## 권장 원격 스캔 프로필

- ultra-safe: [examples/scan-profiles/ultra-safe.yml](examples/scan-profiles/ultra-safe.yml)
  - 실질적으로 가장 낮은 트래픽
  - headless 비활성화
  - 프로그램 규정이 불명확할 때 가장 먼저 써야 하는 기본 선택

  예시 명령:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/ultra-safe.yml \
    --scope "target.example.com" \
    --job-id target-ultra-safe \
    --resume
  ```

- 보수적: [examples/scan-profiles/conservative.yml](examples/scan-profiles/conservative.yml)
  - 1차 확인용
  - headless 비활성화
  - 트래픽 최소화

  예시 명령:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/conservative.yml \
    --scope "*.example.com" \
    --job-id target-conservative \
    --resume
  ```

- 표준: [examples/scan-profiles/standard.yml](examples/scan-profiles/standard.yml)
  - 일반적인 웹 진단용
  - headless 초기 렌더링 사용
  - route walk나 click exploration 없음

  예시 명령:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/standard.yml \
    --scope "*.example.com" \
    --job-id target-standard \
    --resume \
    -f html -o report.html
  ```

- 심화: [examples/scan-profiles/deep.yml](examples/scan-profiles/deep.yml)
  - SPA 비중이 큰 대상용
  - headless route exploration 사용
  - 트래픽 계층 프로필 중 커버리지가 가장 높고 트래픽도 가장 큼

  예시 명령:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/deep.yml \
    --scope "*.example.com" \
    --job-id target-deep \
    --resume \
    --api-map -w all
  ```

- `fast.yml`
  - 대형 번들에서 로컬 normalize 시간이 주된 병목일 때 사용
  - headless 브라우저 없음
  - route exploration 없음
  - 속도를 위해 beautify/source-map 정밀도를 명시적으로 일부 포기하는 프로필

  예시 명령:

  ```bash
  bundleInspector scan https://target.example.com \
    --config examples/scan-profiles/fast.yml \
    --scope "*.example.com" \
    --job-id target-fast \
    --resume
  ```

프로필 사용 안내: [examples/scan-profiles/README.md](examples/scan-profiles/README.md)

### 프로필 비교표

아래 표는 실무적인 트래픽 감각을 정리한 것이며, 절대적인 보장은 아닙니다.
실제 요청량은 대상 프론트엔드의 동작, 발견되는 자산 수, 렌더링 과정에서 추가 API가 호출되는지에 따라 달라집니다.

`fast`는 트래픽 계층 프로필이 아니라 속도/정밀도 tradeoff 프로필이므로, 아래 표에서는 의도적으로 제외했습니다.

| 프로필 | 핵심 설정 | 권장 용도 | 현실적인 트래픽 감각 | 운영 위험도 |
|---|---|---|---|---|
| `ultra-safe` | depth `0`, pages `1`, headless `off`, routes `off`, concurrency `1`, rate limit `5.0s` | 규정이 불명확한 대상, 엄격한 프로그램, 첫 접촉 | 보통 시작 페이지 1개와 발견된 JS/manifest 요청 정도로 끝나며, 일반적인 사이트에서는 수십 요청 수준인 경우가 많음 | 가장 낮음 |
| `conservative` | depth `1`, pages `10`, headless `off`, routes `off`, concurrency `2`, rate limit `2.5s` | 1차 확인, 초기 triage | 일반적인 사이트에서는 수십에서 낮은 수백 요청 수준으로 끝나는 경우가 많음 | 낮음 |
| `standard` | depth `2`, pages `30`, headless `on`, routes `off`, concurrency `4`, rate limit `1.25s` | 허가된 일반 진단 | 보통 낮은 수백 요청 수준까지 갈 수 있고, 렌더링 중 추가 프론트엔드/API 트래픽이 발생할 수 있음 | 중간 |
| `deep` | depth `3`, pages `80`, headless `on`, routes `on`, concurrency `8`, rate limit `0.75s` | SPA 비중이 큰 대상의 허가된 심화 진단 | 보통 수백 요청 수준이며, lazy-loaded chunk나 추가 API 호출이 많으면 더 커질 수 있음 | 높음 |

## 원격 트래픽과 안전성

- 원격 `scan`은 무해한 단일 페이지 접속이 아닙니다. HTML 페이지 요청, build manifest 탐색, JavaScript 자산 다운로드를 수행하고, headless 모드가 켜져 있으면 실제 브라우저 컨텍스트에서 페이지를 렌더링합니다.
- 따라서 `scan`은 서버 로그, WAF, 관제 시스템에서 보이는 브라우저형 트래픽을 만들 수 있습니다.
- 기본 `scan` 설정은 보수적이지 않습니다. shipped 기본값은 headless 수집과 route exploration을 켜므로, 운영 대상에는 기본값보다 명시적인 프로필 사용이 맞습니다.
- `ultra-safe`는 프로그램의 자동화 허용 범위가 불명확하거나, 가능한 한 낮은 트래픽으로 시작해야 할 때 가장 적절한 기본 선택입니다.
- `conservative`는 가장 안전한 시작점이며, 버그바운티나 운영계 1차 확인에서는 보통 이 프로필이 맞습니다.
- `ultra-safe`와 `conservative`는 기본 beautify 경로를 유지합니다. 이 둘은 저트래픽 프로필이지, 저정밀 프로필이 아닙니다.
- `fast`는 속도 전용 프로필입니다. beautify와 sourcemap 해석을 끄므로, 그 정밀도 tradeoff를 받아들일 수 있을 때만 써야 합니다.
- `standard`는 허가된 일반 진단에서는 쓸 수 있는 편이지만, 렌더링 과정에서 추가적인 프론트엔드/API 트래픽을 만들 수 있어 충분히 눈에 띕니다.
- `deep`는 커버리지가 가장 높은 대신 운영 영향 위험도 가장 큽니다. 작은 서비스, 취약한 레거시 앱, 무거운 SPA 대상에서는 안전하지 않을 정도의 트래픽을 만들 수 있습니다.
- BundleInspector는 DoS 도구는 아니지만, 원격 스캔을 잘못 설정하면 일부 프로그램 기준으로는 과도할 수 있습니다. 항상 대상 프로그램의 자동화 정책, 트래픽 제한, 테스트 규칙을 따라야 합니다.
- 무거운 테스트에 대한 명시적 허가가 없다면 `ultra-safe` 또는 `conservative`부터 시작하고, `--scope`를 좁히고, 한 번에 한 대상만 다루고, 지연이나 오류율이 증가하면 즉시 중단하는 것이 맞습니다.

## 프로그램이 하는 일

BundleInspector는 JavaScript 자산을 분석해 다음을 찾습니다.

- 숨겨진 또는 문서화되지 않은 API endpoint
- 하드코딩된 secret과 secret 유사 토큰
- 내부 도메인 또는 비공개 도메인
- feature flag와 rollout marker
- debug 또는 administrative indicator

정적 수집과 runtime 보조 수집을 모두 지원하며, 이후 normalize, parse, analyze, correlate, classify, report 단계를 거칩니다.

## 핵심 기능

- 정적 HTML 수집, headless 브라우저 수집, build-manifest 탐색을 포함한 원격 스캔
- 파일, 디렉터리, glob 패턴 대상 로컬 분석
- JSON, HTML, SARIF 출력
- 선택적 fuzzing wordlist 생성
- 선택적 API map 재구성
- persistent job 저장소 기반 `--resume`
- 가능할 경우 source-map과 normalized-to-original evidence 매핑
- YAML/JSON config 로딩
- YAML/JSON custom rules, rule directory, ruleset-style pack 지원
- secret 및 secret metadata의 JSON masking
- import, re-export, dynamic import, runtime execution path를 넘는 상관분석
- 브랜드형 CLI 배너, 단계 기반 진행 표시, `--verbose` / `--debug` / `--no-banner` 실행 모드

## 기능별 설명

### Static collector

- 페이지 렌더링 없이 HTML만 파싱합니다.
- `<script src>`, preload, modulepreload, inline dynamic-import 패턴을 추출합니다.
- 가장 보수적인 원격 수집 모드입니다.

### Headless collector

- Playwright로 실제 브라우저 컨텍스트에서 페이지를 렌더링합니다.
- 정적 파싱으로 놓칠 수 있는 runtime-loaded script와 chunk를 수집합니다.
- 옵션에 따라 route 탐색과 일반적인 상호작용 요소 클릭으로 lazy-loaded JavaScript를 유도할 수 있습니다.
- 가장 높은 커버리지를 제공하지만, 서버 측에는 가장 눈에 띄는 브라우저형 트래픽이 발생합니다.

### Manifest collector

- webpack, Vite, CRA, Next.js 등에서 자주 쓰이는 build-manifest 경로를 탐색합니다.
- manifest JSON/JS에서 chunk URL을 추출합니다.
- 페이지에 모든 chunk가 직접 노출되지 않아도 build metadata가 남아 있으면 유효합니다.

### Multi-page crawl

- 설정된 depth까지 in-scope 내부 링크를 따라갑니다.
- 페이지 단위 진행 상태를 저장하고 partial crawl state에서 resume할 수 있습니다.
- 운영계에서는 scope를 좁히고 depth를 보수적으로 두는 것이 맞습니다.

### Download and normalization

- 발견된 JavaScript 자산을 다운로드합니다.
- 설정 시 beautify를 수행합니다.
- 가능하면 source map을 해결합니다.
- source-map 해결 시 원본 위치 기준 evidence를 유지합니다.

### Parsing and analysis

- JavaScript를 AST/IR 구조로 파싱합니다.
- endpoint, secret, domain, feature flag, debug indicator를 탐지합니다.
- built-in detector와 shipped custom rule 형식을 지원합니다.

### Correlation and risk classification

- finding을 same-file, import, runtime, execution-path 관계로 연결합니다.
- practical call chain을 재구성합니다.
- triage를 돕기 위해 risk score와 tier를 부여합니다.

### Resume and job persistence

- asset, AST, finding, report, stage checkpoint를 persistent job id 아래 저장합니다.
- `--resume`는 저장된 작업을 재사용합니다.
- `--job-id`를 사용하면 같은 대상 반복 분석을 안정적인 캐시 namespace로 유지할 수 있습니다.

### Reporting and extra artifacts

- JSON, HTML, SARIF 리포트
- 선택적 fuzzing wordlist
- 선택적 API map 재구성
- BundleInspector가 생성한 HTML 리포트는 다시 JSON으로 변환할 수 있습니다.

### CLI 경험

- `scan`과 `analyze`는 기본적으로 브랜드 배너를 표시합니다.
- 긴 실행 동안 현재 stage를 보여주는 진행 표시를 제공합니다.
- `--verbose`는 터미널을 과하게 어지럽히지 않는 수준에서 stage 시작과 완료를 보여줍니다.
- `--debug`는 내부 로그와 더 자세한 실행 과정을 보여줍니다.
- `--no-banner`는 CI나 깔끔한 터미널 출력을 원할 때 시작 배너를 숨깁니다.

## 설치

### 요구사항

- Python 3.10+
- headless 원격 스캔을 쓰려면 Playwright 브라우저 바이너리 필요

### 패키지 설치

```bash
git clone https://github.com/g2hsec/bundleInspector.git
cd bundleInspector
pip install -e .
```

### 개발 의존성 설치

```bash
pip install -e ".[dev]"
```

### Headless 스캔용 Playwright Chromium 설치

```bash
playwright install chromium
```

## 빠른 시작

### 원격 스캔

```bash
bundleInspector scan https://example.com
```

### 로컬 분석

```bash
bundleInspector analyze ./dist
```

### HTML 리포트 저장

```bash
bundleInspector scan https://example.com -f html -o report.html
```

### SARIF 리포트 저장

```bash
bundleInspector analyze ./dist -f sarif -o report.sarif
```

### 저장된 job 이어서 실행

```bash
bundleInspector scan https://example.com --job-id example-scan --resume
bundleInspector analyze ./dist --job-id dist-scan --resume
```

## 명령 개요

```bash
bundleInspector --help
bundleInspector --version
bundleInspector version
bundleInspector scan ...
bundleInspector analyze ...
bundleInspector convert ...
```

- `scan`: 원격 URL을 스캔해 JavaScript 보안 finding을 수집
- `analyze`: 로컬 파일을 네트워크 없이 분석
- `convert`: 저장된 리포트를 JSON과 HTML 사이에서 변환
- `version`: 버전 문자열 출력

## 전체 CLI 참고서

### Global

```bash
bundleInspector --version
bundleInspector --help
bundleInspector version
```

### `scan`

구문:

```bash
bundleInspector scan [OPTIONS] URLS...
```

예시:

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

옵션:

| 옵션 | 타입 / 값 | 기본값 | 설명 |
|---|---|---:|---|
| `--config` | `PATH` |  | YAML 또는 JSON config 파일 로드 |
| `-s`, `--scope` | 반복 `TEXT` |  | `*.example.com` 같은 허용 도메인 패턴 추가 |
| `-c`, `--cookie` | 반복 `TEXT` |  | `name=value` 형식 쿠키 추가 |
| `-H`, `--header` | 반복 `TEXT` |  | `Name: Value` 형식 헤더 추가 |
| `-d`, `--depth` | `INTEGER` | `3` | crawl depth |
| `-r`, `--rate-limit` | `FLOAT` | `1.0` | 요청 간 대기 초 |
| `--no-headless` | 플래그 | `false` | headless 브라우저 수집 비활성화 |
| `-o`, `--output` | `PATH` |  | 리포트 출력 경로 지정 |
| `-f`, `--format` | `json`, `html`, `sarif` | `json` | 리포트 형식 |
| `-v`, `--verbose` | 플래그 | `false` | 상세 출력 |
| `--debug` | 플래그 | `false` | 내부 로그와 자세한 실행 과정을 포함한 debug 출력 활성화 |
| `-q`, `--quiet` | 플래그 | `false` | 최소 출력 |
| `--no-banner` | 플래그 | `false` | 시작 배너 숨김 |
| `-w`, `--wordlist` | `all`, `endpoints`, `paths`, `params`, `domains`, `dirs` |  | fuzzing wordlist 생성 |
| `--api-map` | 플래그 | `false` | API map 파일 생성 |
| `--headers-file` | `PATH` |  | 텍스트 또는 JSON 파일에서 헤더 로드 |
| `--bearer-token` | `TEXT` |  | `Authorization: Bearer ...` 설정 |
| `--basic-auth` | `TEXT` |  | `user:password` 형식 Basic auth |
| `--user-agent` | `TEXT` |  | crawler user agent 덮어쓰기 |
| `--cookies-file` | `PATH` |  | 파일에서 쿠키 로드 |
| `--cookies-from` | `chrome`, `firefox`, `edge`, `chromium` |  | 로컬 브라우저에서 쿠키 가져오기 |
| `--resume` | 플래그 | `false` | 해당 job의 최신 리포트 또는 checkpoint에서 재개 |
| `--job-id` | `TEXT` |  | persistent job id 지정 |
| `--rules-file` | `PATH` |  | JSON/YAML, 디렉터리, ruleset pack에서 custom rules 로드 |

원격 스캔 출력 메모:

- 기본 출력은 배너, runtime header, 진행 표시, 최종 summary 중심입니다.
- Normalize 단계는 현재 처리 중인 asset을 detail에 같이 보여줘서 큰 번들 때문에 오래 걸리는 구간을 식별하기 쉽습니다.
- `--verbose`는 stage 시작과 완료를 더 보여줍니다.
- `--debug`는 `--verbose` 성격을 포함하고 내부 debug logging을 활성화하며, Normalize 단계의 sourcemap 확인과 장시간 작업 heartbeat도 함께 보여줍니다.
- `--no-banner`는 배너만 숨기고 진행 표시와 summary는 유지합니다.

### `analyze`

구문:

```bash
bundleInspector analyze [OPTIONS] PATHS...
```

예시:

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

옵션:

| 옵션 | 타입 / 값 | 기본값 | 설명 |
|---|---|---:|---|
| `--config` | `PATH` |  | YAML 또는 JSON config 파일 로드 |
| `-r`, `--recursive / --no-recursive` | boolean switch | `recursive` | 디렉터리 재귀 탐색 |
| `--include-json` | 플래그 | `false` | 로컬 분석에 JSON 파일 포함 |
| `-o`, `--output` | `PATH` |  | 리포트 출력 경로 지정 |
| `-f`, `--format` | `json`, `html`, `sarif` | `json` | 리포트 형식 |
| `-v`, `--verbose` | 플래그 | `false` | 상세 출력 |
| `--debug` | 플래그 | `false` | 내부 로그와 자세한 실행 과정을 포함한 debug 출력 활성화 |
| `-q`, `--quiet` | 플래그 | `false` | 최소 출력 |
| `--no-banner` | 플래그 | `false` | 시작 배너 숨김 |
| `-w`, `--wordlist` | `all`, `endpoints`, `paths`, `params`, `domains`, `dirs` |  | fuzzing wordlist 생성 |
| `--api-map` | 플래그 | `false` | API map 파일 생성 |
| `--resume` | 플래그 | `false` | 해당 job의 최신 리포트 또는 checkpoint에서 재개 |
| `--job-id` | `TEXT` |  | persistent job id 지정 |
| `--rules-file` | `PATH` |  | JSON/YAML, 디렉터리, ruleset pack에서 custom rules 로드 |

로컬 분석 출력 메모:

- 기본 출력은 배너, runtime header, 진행 표시, 최종 summary 중심입니다.
- `--verbose`는 stage 시작과 완료를 더 보여줍니다.
- `--debug`는 `--verbose` 성격을 포함하고 내부 debug logging도 활성화합니다.
- `--no-banner`는 배너만 숨기고 진행 표시와 summary는 유지합니다.

### `convert`

구문:

```bash
bundleInspector convert [OPTIONS] REPORT_FILE
```

예시:

```bash
bundleInspector convert report.json -f html -o report.html
bundleInspector convert report.html -f json -o report.json
```

옵션:

| 옵션 | 타입 / 값 | 기본값 | 설명 |
|---|---|---:|---|
| `-f`, `--format` | `json`, `html` | `html` | 출력 형식 |
| `-o`, `--output` | `PATH` |  | 출력 경로 |

### `version`

```bash
bundleInspector version
```

## 출력 파일과 산출물

- 리포트 형식: `json`, `html`, `sarif`
- 기본 리포트 파일명:
  - `scan`, `analyze`: `bundleInspector_report.<format>`
  - `convert`: `report.<format>`
- `--wordlist` 추가 파일:
  - `wordlist_endpoints.txt`
  - `wordlist_paths.txt`
  - `wordlist_params.txt`
  - `wordlist_domains.txt`
  - `wordlist_dirs.txt`
- `--api-map` 추가 파일:
  - `api_map.json`
  - `api_map.txt`

## Config 파일

지원 형식:

- `.json`
- `.yaml`
- `.yml`

최상위 section:

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

핵심 section:

- `scope`: allowed/denied domain, path, subdomain, third-party policy
- `auth`: cookies, headers, bearer token, basic auth
- `crawler`: depth, pages, JS file 수, rate limit, headless, timeouts, retries
- `parser`: tolerant, partial_on_error, extract/build toggles, beautify, beautify_max_bytes, sourcemap
- `rules`: enabled category, custom rules, masking, confidence, entropy
- `output`: format, file, dir, raw content, snippet, severity, risk tier

세부 semantics는 [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md)를 기준으로 봐야 합니다.

## Custom Rules

사용 예시:

```bash
bundleInspector scan https://example.com --rules-file custom-rules.json
bundleInspector analyze ./dist --rules-file custom-rules.yaml
bundleInspector scan https://example.com --rules-file ./rules/
bundleInspector analyze ./dist --rules-file ./ruleset/meta.yml
```

지원 matcher family:

- `regex`
- `ast_pattern`
- `semantic`

전체 문서는 [docs/CUSTOM_RULES.md](docs/CUSTOM_RULES.md)를 보십시오.

## Detection Coverage

기본 카테고리:

- endpoint
- secret
- domain
- feature flag
- debug indicator

## Risk Tiers

- `critical`
- `high`
- `medium`
- `low`
- `info`

## Architecture Overview

주요 파이프라인:

1. collect
2. download
3. normalize
4. parse
5. analyze
6. correlate
7. classify
8. report

## Python API

```python
from bundleInspector.cli import main

main()
```

현재는 CLI가 가장 안정적인 공개 인터페이스입니다.

## 운영 메모

- 원격 `scan`은 단순 1회 페이지 접속 수준이 아닙니다.
- headless와 route exploration은 서버 로그, 관제, WAF에 보일 수 있습니다.
- 운영계에서는 보수적 profile부터 시작하는 것이 맞습니다.
- `--job-id`를 안정적으로 쓰면 `--resume` 효율이 좋아집니다.

## 개발

```bash
pytest -p no:cacheprovider
ruff check .
```

## 면책

이 도구는 합법적이고 승인된 환경에서만 사용해야 합니다. 원격 스캔은 실제 서비스에 부하를 만들 수 있습니다.

## 라이선스

MIT

## 지원

이슈나 개선 제안은 GitHub Issues를 사용하십시오.

프로젝트가 도움이 됐다면 GitHub에서 star를 눌러 두는 것이 가장 직접적인 지원입니다.
