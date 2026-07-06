# 📖 BundleInspector — 사용설명서

BundleInspector 설치·설정·실행에 대한 완전한 레퍼런스입니다.
간단한 개요는 [README](../README.ko.md)를 참고하세요.

---

## 목차

- [개요](#개요)
- [설치](#설치)
- [빠른 시작](#빠른-시작)
- [🧭 CLI 레퍼런스](#-cli-레퍼런스)
- [설정](#설정)
- [스캔 프로파일](#스캔-프로파일)
- [🛡️ 트래픽 & 안전](#-트래픽--안전)
- [🔬 탐지 커버리지](#-탐지-커버리지)
- [출력 & 리포트](#출력--리포트)
- [성능](#성능)
- [인증 & 세션](#인증--세션)
- [커스텀 룰](#커스텀-룰)
- [Python API](#python-api)
- [동작 원리](#동작-원리)
- [참고 & 제약](#참고--제약)
- [문제 해결](#문제-해결)

---

## 개요

BundleInspector는 자바스크립트 번들을 위한 Python 보안/정찰 스캐너입니다. 두 가지 방식으로 동작합니다:

- **`scan`** — 라이브 사이트를 크롤(정적 HTML 수집기 + 선택적 헤드리스 Playwright 렌더링 + 빌드 매니페스트 프로빙)하고, 발견한 자바스크립트를 다운로드해 분석합니다.
- **`analyze`** — 동일한 분석 엔진을 로컬 파일/디렉터리/글롭에 대해 **네트워크 트래픽 없이** 실행합니다.

각 자산은 정규화(beautify, 소스맵 해석)되고 AST로 파싱된 뒤, **엔드포인트·시크릿·내부 도메인·피처 플래그·디버그 엔드포인트**를 추출하는 룰 엔진을 거치며, 7가지 공격 정찰 고도화로 보강되고 `P0–P3` 위험 등급이 매겨집니다.

> **버전:** `0.1.0` · **Python:** `3.10+` · **라이선스:** MIT

---

## 설치

```bash
git clone https://github.com/g2hsec/bundleInspector.git
cd bundleInspector
python -m venv .venv
```

셸에 맞게 가상환경을 활성화한 뒤 설치:

| 셸 | 활성화 |
|---|---|
| macOS / Linux (bash/zsh) | `source .venv/bin/activate` |
| Windows PowerShell | `.venv\Scripts\Activate.ps1` |
| Windows cmd | `.venv\Scripts\activate.bat` |

```bash
pip install -e .
playwright install chromium          # 헤드리스 스캔에 필요
```

> **Windows PowerShell은 `&&`·`source`를 지원하지 않습니다** — 각 명령을 한 줄씩 실행하세요. 활성화 시 *"이 시스템에서 스크립트를 실행할 수 없습니다"* 오류가 나면, 세션에서 한 번 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` 를 실행한 뒤 `.venv\Scripts\Activate.ps1` 를 다시 실행하세요.

개발용 설치(테스트·린팅):

```bash
pip install -e ".[dev]"              # pytest, pytest-asyncio, pytest-cov, ruff, mypy, pre-commit
```

**선택적 네이티브 파서.** 기본 파서는 `esprima`입니다. 더 빠른 파싱과 최신 문법 완전 지원이 필요하면 [acorn](https://github.com/acornjs/acorn) 백엔드를 옵트인할 수 있으며, Node.js가 `PATH`에 있고 `acorn` 패키지를 찾을 수 있어야 합니다:

```bash
npm install acorn                     # Node가 찾을 수 있는 위치(또는 NODE_PATH)
export BUNDLEINSPECTOR_NATIVE_PARSER=1
```

Node/acorn이 없거나 실패하면 BundleInspector는 조용히 `esprima`로 폴백합니다 — 네이티브 경로가 탐지율을 떨어뜨릴 일은 없습니다.

**런타임 의존성**(자동 설치): `httpx`, `playwright`, `beautifulsoup4`, `lxml`, `esprima`, `jsbeautifier`, `pydantic>=2`, `click>=8.1`, `rich`, `structlog`, `jinja2`, `aiofiles`, `regex`.

---

## 빠른 시작

```bash
# 도메인과 서브도메인으로 스코프를 제한한 원격 스캔
bundleInspector scan https://target.example.com --scope "*.example.com"

# 빌드 디렉터리 오프라인 분석
bundleInspector analyze ./dist

# HTML 리포트
bundleInspector scan https://target.example.com -f html -o report.html

# GitHub Code Scanning / CI 용 SARIF
bundleInspector analyze ./dist -f sarif -o findings.sarif

# 리포트와 함께 퍼징 워드리스트 + API 맵 생성
bundleInspector scan https://target.example.com -w all --api-map

# 멈췄다 재개할 수 있는 긴 스캔
bundleInspector scan https://target.example.com --job-id acme --resume
```

---

## 🧭 CLI 레퍼런스

콘솔 명령 **`bundleInspector`**(또는 `python -m bundleInspector.cli`)로 실행합니다. 전역 옵션: `--version`, `--help`.

```
bundleInspector [scan | analyze | convert | version]
```

### `scan <urls…>` — 원격

하나 이상의 라이브 타겟 URL을 크롤·분석합니다(URL 최소 1개 필수).

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `--config PATH` | — | YAML/JSON 설정 파일 로드(병합; CLI 플래그 우선) |
| `-s, --scope PATTERN` | 시드 도메인 | 허용 도메인 패턴 예: `*.example.com` (반복 가능) |
| `-c, --cookie name=value` | — | 세션 쿠키(반복 가능) |
| `-H, --header name:value` | — | HTTP 헤더(반복 가능) |
| `-d, --depth INT` | `3` | 크롤 깊이 |
| `-r, --rate-limit FLOAT` | `1.0` | 요청 간 간격(초, 도메인별) |
| `--no-headless` | 헤드리스 on | 헤드리스 브라우저 수집기 비활성화 |
| `-o, --output PATH` | `bundleInspector_report.<ext>` | 리포트 경로 |
| `-f, --format {json,html,sarif}` | `json` | 리포트 형식 |
| `-w, --wordlist {all,endpoints,paths,params,domains,dirs}` | — | 퍼징 워드리스트 추가 생성 |
| `--api-map` | off | `api_map.json` + `api_map.txt` 추가 생성 |
| `--headers-file PATH` | — | `Name: Value` 텍스트 또는 JSON 파일에서 헤더 로드 |
| `--bearer-token TOKEN` | — | `Authorization: Bearer <token>` 설정 |
| `--basic-auth user:password` | — | HTTP Basic 인증(`:` 필수) |
| `--user-agent STRING` | Chrome UA | 커스텀 User-Agent |
| `--cookies-file PATH` | — | 쿠키 임포트(JSON / Netscape / 헤더 문자열) |
| `--cookies-from {chrome,firefox,edge,chromium}` | — | 로컬 브라우저에서 쿠키 임포트(`--cookies-file`과 배타) |
| `--rules-file PATH` | — | 커스텀 regex/AST/semantic 룰 로드 |
| `--job-id ID` | 자동 uuid | 캐시/재개용 영속 job id |
| `--resume` | off | 해당 job id의 최신 저장 리포트/체크포인트 재사용 |
| `--fail-on {info,low,medium,high,critical}` | — | 이 심각도 이상 발견 시 종료 코드 **2** (CI 게이트) |
| `-v, --verbose` / `--debug` / `-q, --quiet` / `--no-banner` | — | 출력 상세도 제어 |

### `analyze <paths…>` — 로컬, 네트워크 없음

로컬 파일/디렉터리/글롭을 분석합니다(경로 최소 1개 필수).

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `--config PATH` | — | YAML/JSON 설정 파일 로드 |
| `-r, --recursive / --no-recursive` | recursive | 디렉터리 재귀 |
| `--include-json` | off | `.json` 파일도 분석 |
| `-o, --output PATH` | `bundleInspector_local_report.<ext>` | 리포트 경로 |
| `-f, --format {json,html,sarif}` | `json` | 리포트 형식 |
| `-w, --wordlist {…}` / `--api-map` | — | `scan`과 동일 |
| `--rules-file PATH` | — | 커스텀 룰 |
| `--job-id ID` / `--resume` | — | 캐시 / 재개 |
| `--fail-on {info,low,medium,high,critical}` | — | 이 심각도 이상 발견 시 종료 코드 **2** (CI 게이트) |
| `-v, --verbose` / `--debug` / `-q, --quiet` / `--no-banner` | — | 상세도 |

> ⚠️ **`-r`은 명령마다 다릅니다:** `scan`에서는 `--rate-limit`, `analyze`에서는 `--recursive`입니다.

### `convert <report>`

기존 리포트를 형식 간 변환합니다. 입력은 BundleInspector JSON 리포트 또는 (JSON을 내장한) BundleInspector HTML 리포트입니다.

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `-f, --format {json,html}` | `html` | 대상 형식(여기선 SARIF 없음) |
| `-o, --output PATH` | `report.<format>` | 출력 경로 |

### `version`

`BundleInspector version 0.1.0`을 출력합니다.

---

## 설정

설정은 **병합**되는 두 소스에서 옵니다 — CLI 플래그가 설정 파일 값을 덮어씁니다:

1. **YAML 또는 JSON 파일** (`--config`, `scan`/`analyze` 모두). `.yaml`/`.yml`은 내장 로더 사용(PyYAML 불필요), 그 외는 JSON으로 파싱.
2. **직접 CLI 플래그**(위 표 참고).

설정 파일은 `Config` 모델을 그대로 반영합니다. 예:

```yaml
scope:
  include_subdomains: true
  third_party_policy: tag_only        # analyze | skip | tag_only
crawler:
  max_depth: 2
  rate_limit: 1.25
  use_headless: true
  interactive_clicking: false          # 기본 OFF (안전 섹션 참고)
  block_state_changing_requests: true  # 기본 ON (안전 섹션 참고)
rules:
  min_confidence: low
  client_side_gating_enabled: true
  dormant_endpoint_detection_enabled: true
output:
  format: html
```

### 설정 레퍼런스

**`scope`** — 1st/3rd-party 스코프

| 필드 | 기본값 | 용도 |
|---|---|---|
| `allowed_domains` / `denied_domains` | `[]` | 허용/차단 도메인 패턴 |
| `include_subdomains` | `true` | 시드 도메인이 `*.domain`도 허용 |
| `allowed_paths` / `denied_paths` | `[]` | 허용/차단 경로 프리픽스 |
| `third_party_policy` | `tag_only` | `analyze` \| `skip` \| `tag_only` |
| `cdn_patterns` | 내장 16개 | 1st/3rd-party 판별용 CDN 패턴 |

**`auth`** — 자격증명 (모두 CR/LF/NUL 인젝션 검증)

| 필드 | 기본값 | 용도 |
|---|---|---|
| `cookies` | `{}` | `{name: value}` 맵 |
| `headers` | `{}` | 임의 HTTP 헤더 |
| `bearer_token` | `null` | `Authorization: Bearer <token>` |
| `basic_auth` | `null` | `(user, password)` → Basic 인증 |

**`crawler`** — 원격 크롤/다운로드 동작

| 필드 | 기본값 | 용도 |
|---|---|---|
| `max_depth` | `3` | 재귀 크롤 깊이 |
| `max_pages` | `100` | 재귀 수집기 최대 페이지 |
| `max_js_files` | `1000` | 다운로드 JS 자산 상한 |
| `rate_limit` | `1.0` | 요청 간 간격(초, 도메인별) |
| `max_concurrent` | `10` | 동시 요청 상한 |
| `request_timeout` / `page_timeout` | `30.0` / `60.0` | HTTP / 브라우저 네비게이션 타임아웃(초) |
| `max_redirects` / `follow_redirects` | `10` / `true` | 리다이렉트 처리 |
| `use_headless` | `true` | 헤드리스 브라우저 수집기 |
| `headless_wait_time` | `2.0` | 페이지 로드 후 대기(초) |
| `explore_routes` | `true` | 라우트-링크 탐색 |
| `max_route_exploration` | `20` | 라우트/클릭 탐색 상한 |
| **`interactive_clicking`** | **`false`** | 버튼/탭 클릭으로 지연 JS 유도 — **기본 off**(안전 참고) |
| **`block_state_changing_requests`** | **`true`** | UI 조작이 유발하는 상태변경 요청 차단 — **기본 on** |
| `max_file_size` | `10 MB` | 다운로드 JS 최대 크기 |
| `user_agent` | Chrome UA | 원격 스캔 User-Agent |

**`parser`**

| 필드 | 기본값 | 용도 |
|---|---|---|
| `beautify` | `true` | 파싱 전 JS beautify |
| `resolve_sourcemaps` | `true` | 인라인 + 외부 소스맵 해석 |
| `beautify_max_bytes` | `1_000_000` | 이 크기 초과 시 beautify 생략 |
| `tolerant` / `partial_on_error` | `true` / `true` | 관대한/부분 파싱 |

**`rules`**

| 필드 | 기본값 | 용도 |
|---|---|---|
| `enabled_categories` | `[endpoint, secret, domain, flag, debug]` | 활성 룰 카테고리 |
| `min_confidence` | `low` | `low` \| `medium` \| `high` |
| `mask_secrets` | `true` | 출력에서 시크릿 값 마스킹 |
| `secret_visible_chars` | `4` | 마스킹 시 노출 문자 수 |
| `entropy_threshold` | `3.5` | 제네릭 시크릿 엔트로피 임계값 |
| `custom_rules_file` | `null` | 커스텀 룰 경로 |
| **`client_side_gating_enabled`** | **`true`** | enh1 — 클라이언트 사이드 접근제어 게이팅 |
| **`client_side_gating_severity`** | **`medium`** | enh1 — 게이팅 엔드포인트 심각도 |
| **`dormant_endpoint_detection_enabled`** | **`true`** | enh2 — 휴면/은닉 엔드포인트 |

**`output`**

| 필드 | 기본값 | 용도 |
|---|---|---|
| `format` | `json` | `json` \| `html` \| `sarif` |
| `output_file` / `output_dir` | `null` | 명시 파일 / 기본 디렉터리 |
| `min_severity` | `info` | 포함 최소 심각도 |
| `min_risk_tier` | `P3` | 포함 최소 위험 등급 |
| `include_snippets` / `snippet_context_lines` | `true` / `3` | 코드 스니펫 |
| `include_raw_content` / `include_ast` | `false` | 무거운 페이로드 |

**최상위:** `log_level`(`info`), `verbose`, `quiet`, `cache_dir`(`~/.bundleInspector/cache`, 쓰기 불가 시 워크스페이스 로컬로 폴백), `temp_dir`, `job_id`, `resume`.

자세한 내용은 [`docs/CONFIG_REFERENCE.md`](CONFIG_REFERENCE.md).

---

## 스캔 프로파일

바로 쓰는 YAML 프리셋이 [`examples/scan-profiles/`](../examples/scan-profiles/)에 있습니다. 아래 트래픽은 실제 보장이 아니라 실무적 *기대치*이며, 실제 양은 타겟 프론트엔드와 렌더링이 유발하는 자산/API 호출 수에 따라 달라집니다.

| 프로파일 | 깊이 | 페이지 | 헤드리스 | 라우트 | 동시성 | 레이트리밋 | 트래픽 | 용도 |
|---|---|---|---|---|---|---|---|---|
| `ultra-safe` | 0 | 1 | off | off | 1 | `5.0s` | 최저 | 규칙 불명, 엄격한 프로그램, 첫 접촉 |
| `conservative` | 1 | 10 | off | off | 2 | `2.5s` | 낮음 | 1차 트리아지, 버그바운티 |
| `standard` | 2 | 30 | on | off | 4 | `1.25s` | 중간 | 인가된 진단 |
| `deep` | 3 | 80 | on | **on** | 8 | `0.75s` | 높음 | SPA 위주 타겟 |
| `fast` | 1 | 15 | off | off | 3 | `1.5s` | 낮음 | 정밀도보다 속도 — **beautify + 소스맵 off** |

```bash
bundleInspector scan https://target.example.com \
  --config examples/scan-profiles/conservative.yml \
  --scope "*.example.com" \
  --job-id target-conservative --resume
```

**가이드.** 버그바운티/운영 트리아지의 첫 선택은 `ultra-safe` / `conservative`입니다 — 트래픽은 낮지만 분석 정밀도는 그대로입니다. `standard`는 인가된 진단에 적합합니다. `deep`은 커버리지가 가장 높고, 작거나 취약한 서비스에서 눈에 띄는 부하를 줄 가능성도 가장 큽니다. `fast`는 정규화 정밀도를 속도와 맞바꾸므로, 그 트레이드오프가 허용될 때만 쓰세요.

---

## 🛡️ 트래픽 & 안전

원격 `scan`은 단일 페이지 fetch가 **아닙니다**. HTML 페이지 요청, 빌드 매니페스트 프로빙, JS 자산 다운로드, 그리고 헤드리스 활성 시 실제 브라우저 렌더링까지 발생합니다. 이 트래픽은 로그·WAF·모니터링에 보입니다.

### 상태변경 가드 (기본 ON)

BundleInspector는 자신의 UI 조작으로 타겟을 변경하지 않습니다:

- **`interactive_clicking = false`** — 버튼/탭/role 요소 클릭(폼 제출·삭제 유발 가능성이 가장 큰 경로)은 **기본 off**입니다. 라우트-링크 탐색은 켜져 있지만 아래 가드가 커버합니다.
- **`block_state_changing_requests = true`** — 크롤러가 UI를 조작하는 동안(라우트-링크 + 인터랙티브 클릭) 유발되는 비멱등 요청(`POST`/`PUT`/`PATCH`/`DELETE`)은 **네트워크 계층에서 가로챕니다**: 엔드포인트는 **기록**(발견 유지 + 휴면 엔드포인트 탐지에 활용)한 뒤 **abort**합니다 — 연결된 `on_state_change_attempt` 핸들러가 승인한 경우에만 진행(멈춰서 확인).
- 가드가 켜져 있는 동안 **서비스워커가 차단**되어, SW fetch로 가로채기를 우회할 수 없습니다.
- 탐색 단계 **밖**에서 앱이 보내는 요청(초기 페이지 로드)은 건드리지 않으므로, 정상 렌더링과 탐지가 보존됩니다.

> **잔여 한계(정직하게):** 가드는 탐색 단계로 스코프가 잡혀 있어, 클릭이 아주 먼 미래에 예약한 변경(예: 세틀 창을 넘긴 디바운스 `setTimeout`)은 가드 해제 후 발생할 수 있습니다. 인터랙티브 클릭이 기본 off이고 확인 훅이 있으므로 좁은 엣지 케이스지만, 절대 보장이 필요하면 `interactive_clicking`을 끈 채 비헤드리스 프로파일을 쓰세요.

### 스로틀링, 스코프 & SSRF

- **도메인별 적응형 레이트리밋** — 요청 간 `rate_limit`초(기본 `1.0`), `429`/`5xx`에 자동 백오프(×2, 최대 60s), 성공 시 회복. 동시성은 `max_concurrent`로 제한.
- **SSRF / 스코프 가드** — 모든 시드와 다운로드를 검증: localhost·클라우드 메타데이터 호스트, 사설/루프백/링크로컬/CGNAT IP(`169.254.169.254` 포함), DNS 리바인딩 체크, non-`http(s)` 스킴 차단. `ScopePolicy`가 허용/차단 도메인 강제.
- **시크릿 마스킹** — 시크릿 발견은 마스킹(`secret_visible_chars=4`), 요청 컨트랙트 추출 시 자격증명 형태 값은 디스크에 닿기 전에 `<REDACTED_*>`로 리댁션.
- **기타 하드닝** — 10 MB 다운로드 상한, 10 리다이렉트 상한, 인증 입력 CR/LF/NUL 검증, 로컬 분석 경로 순회 방지.

**부하는 어느 정도?** 기본 설정에서 다운로드 단계는 도메인당 초당 ~1요청, 헤드리스 단계는 한 번에 한 페이지 렌더 — 활성 사용자 한 명 수준입니다. `rate_limit`을 `0`에 가깝게 낮추고 `max_concurrent`를 크게 올리면 동시 수십 요청까지 튈 수 있으니, 기본값(또는 conservative 프로파일)을 유지해 온순하게 두세요.

> **BundleInspector는 DoS 도구가 아닙니다.** 다만 잘못 설정한 공격적 스캔은 일부 프로그램에 과할 수 있습니다. 항상 타겟 규칙과 트래픽 제한을 준수하세요.

---

## 🔬 탐지 커버리지

### 핵심 카테고리

| 카테고리 | 기본 심각도 | 무엇을 찾나 |
|---|---|---|
| **Endpoint** | INFO | `fetch`/`axios`/`request`/`ajax` 호출, `obj.get/post/...`, `XMLHttpRequest.open`, `axios.create` baseURL/기본 헤더, `/api/`·`/v\d+/`·`/graphql`·`/rest/`·`/rpc/`·`/ws/`·`/socket`·`/webhook` 리터럴. 템플릿 리터럴·결합·삼항·상수·명명 객체·`new URL()`/`new Request()`까지 정적 해석. |
| **Secret** | HIGH | ~100개 사전 컴파일 키 패턴(AWS, Azure, GCP, OpenAI, Anthropic, GitHub, GitLab, Stripe, Slack, Twilio, Firebase, Supabase, DB 접속 문자열, JWT, PEM/SSH 키 …), 대입 컨텍스트 패턴(`api_key`, `access_token` …), 랜덤 블롭용 섀넌 엔트로피 분석(시크릿 어휘 없으면 LOW로 강등). 플레이스홀더/테스트 값 제외. |
| **Domain** | MEDIUM | 내부/스테이징 호스트(`dev`/`staging`/`qa`…, `.internal`/`.local`/`.corp`), Kubernetes(`.svc.cluster.local`), Docker/AWS-internal, 사설/루프백 IP, S3/GCS/Azure 버킷. |
| **Flag** | LOW | 피처 플래그 키워드, SDK(LaunchDarkly, Optimizely, Split, ConfigCat, Unleash …), 플래그 설정 엔드포인트, 플래그 체크 함수, admin/debug 식별자. |
| **Debug** | 경로별 | 디버그/관리 경로 등급별(`/shell`,`/eval` → CRITICAL; `/debug`,`/admin` → HIGH; `/actuator`,`/test` → MEDIUM; `/health`,`/swagger` → LOW), 민감 `console.*`, `debugger`, `alert()`, dev 전용 분기(`NODE_ENV`, `__DEV__`). |

**Chunk Analyzer**가 Webpack/Vite 코드 스플릿 인프라와 지연/은닉 라우트를 추가로 드러냅니다.

### 7가지 고도화

| ID | 이름 | 내용 |
|---|---|---|
| **enh1** | 클라이언트 사이드 접근제어 게이팅 | 브라우저 측 authz 체크 **뒤에서만** 도달 가능한 엔드포인트(`if(user.isAdmin)`, `flags.canX && fetch(...)`, `if(!hasRole()) return`)를 표시. 가드를 분류(role/permission/entitlement/feature/flag)하고 심각도 상향 — 전형적 우회 표면. 오프셋 매칭으로 minified 단일 라인도 지원. |
| **enh2** | 휴면/은닉 엔드포인트 | JS에 **선언된** 엔드포인트와 헤드리스 크롤 중 앱이 **실제 호출한** 엔드포인트를 대조. 선언됐지만 호출된 적 없는 것은 AJAX로 도달 가능한 우회 표면. FP 안전(런타임 기준선 없으면 no-op, 미접촉 호스트 제외), 민감 경로는 MEDIUM으로. |
| **enh3** | 재현 가능한 요청 컨트랙트 + PoC | 호출별 컨트랙트(method, url, headers, auth scheme, body shape, query params)를 `request_contract` 메타데이터로 조립, 자격증명 형태 값은 추출 시 리댁션. `reporter/poc.py`가 `FUZZ` 플레이스홀더로 **curl + fetch** 스니펫 렌더. |
| **enh4** | IDOR + HTTP 메서드-플립 | IDOR/열거 경로 파라미터(`${…}`, `:id`, UUID, Mongo ObjectId, email, numeric)를 탐지해 `idor_candidate` 태그; 각 경로에서 **아직 안 본** 표준 HTTP 메서드를 퍼징 힌트로 나열. HTTP 중복 제거를 `(method, url)`로 키잉해 정상 `GET` 옆의 은닉 `DELETE`도 보존. |
| **enh5** | 프레임워크 클라이언트 라우트 맵 | React Router / Vue Router / Angular / 컴파일된 JSX / Next.js 파일 라우트에서 SPA 라우트 테이블 전체를 복원 — 내비에 **없는** admin/internal/피처플래그 페이지 포함. 부모/자식 경로 결합 + 라우트별 지연 청크 연결. `client_route` 발견 생성, 민감 라우트 표시. |
| **enh6** | GraphQL + WebSocket 표면 | `gql` 태그드 템플릿·쿼리 프로퍼티에서 GraphQL 오퍼레이션(query/mutation/subscription + 필드) 추출, WS/Socket.IO 클라이언트의 `.send()`/`.emit()`에서 WebSocket **메시지 표면** 추출. |
| **enh7** | 런타임 관측 엔드포인트 | enh2의 짝: 크롤 중 앱이 **실제 호출**했지만 정적 분석이 못 찾은 HTTP/WebSocket 엔드포인트(주로 동적 조립 URL)를 `runtime-observed` 발견으로 노출. 스캔 전용, first-party 스코프, 정적 발견과 중복 제거. |

### 위험 등급

모든 발견은 점수화·등급화됩니다:

| 등급 | 의미 |
|---|---|
| **P0** | 치명적 — 즉시 대응 |
| **P1** | 높음 |
| **P2** | 중간 — 조사 필요 |
| **P3** | 낮음 / 정보성 |

---

## 출력 & 리포트

| 형식 | 플래그 | 비고 |
|---|---|---|
| **JSON** | `-f json` (기본) | 전체 리포트, 시크릿 마스킹, 소스맵 원본 위치 우선, `request_contract` + 모든 고도화 메타데이터 포함 |
| **HTML** | `-f html` | 자체 JSON을 내장한 단일 파일 리포트(`convert`로 왕복 가능) |
| **SARIF 2.1.0** | `-f sarif` | GitHub Code Scanning / Azure DevOps용; 룰 `JSFINDER001–005`, CWE 분류, 정규화 vs 원본 위치 코드 플로우 |

부가 산출물(메인 리포트 옆에 생성):

- **퍼징 워드리스트** — `-w {all,endpoints,paths,params,domains,dirs}` → `wordlist_endpoints.txt`, `wordlist_paths.txt`, `wordlist_params.txt`, `wordlist_domains.txt`, `wordlist_dirs.txt` (`${…}` → `FUZZ`; ffuf/dirsearch/feroxbuster 호환).
- **API 맵** — `--api-map` → `api_map.json` + `api_map.txt` (도메인 → 라우트 → 파라미터 ASCII 트리).

기본 리포트 파일명: `bundleInspector_report.<ext>`(scan), `bundleInspector_local_report.<ext>`(analyze), `report.<ext>`(convert).

---

## 성능

- **병렬 분석** — `BUNDLEINSPECTOR_PARALLEL` 설정: 미설정/`0`/`1` = 직렬; `auto` = CPU당 워커 1개; 정수 `N` = 워커 `N`개. 파싱과 분석이 각 워커 안에서 융합되어 멀티 MB AST가 프로세스 경계를 넘지 않으며, 출력은 직렬과 바이트 동일합니다.

  ```bash
  BUNDLEINSPECTOR_PARALLEL=auto bundleInspector analyze ./big-bundle-dir
  ```

- **네이티브 파서** — `BUNDLEINSPECTOR_NATIVE_PARSER=1`(Node.js + acorn 필요)이 짧은 Node 서브프로세스로 파싱하며, 실패 시 투명하게 `esprima`로 폴백.
- **재개 / 체크포인트** — `--job-id <id> --resume`이 최신 저장 리포트 또는 단계별 체크포인트를 재사용. **resume 시그니처**가 동일 job id에서 프로파일·파서·룰·인증·스코프·깊이·헤드리스 설정이 바뀌면 오래된 상태를 무효화.
- **내부 최적화** — 콘텐츠 해시 중복 제거로 동일 자산 재분석 회피; 필수 리터럴 프리필터로 대부분의 비시크릿 문자열이 ~100개 시크릿 regex를 건너뜀; 엔드포인트 디텍터가 AST 순회를 메모이제이션.

---

## 인증 & 세션

인증 스캔용 자격증명을 여러 방식으로 제공합니다(CLI 값이 파일 값을 덮어씀):

```bash
# 인라인
bundleInspector scan https://app.example.com -c "session=abc123" -H "X-Env: staging"
bundleInspector scan https://app.example.com --bearer-token "$TOKEN"
bundleInspector scan https://app.example.com --basic-auth "user:pass"

# 파일에서
bundleInspector scan https://app.example.com --headers-file headers.txt      # "Name: Value" 라인 또는 JSON
bundleInspector scan https://app.example.com --cookies-file cookies.json      # JSON / Netscape / 헤더 문자열

# 로컬 브라우저 프로필에서
bundleInspector scan https://app.example.com --cookies-from chrome
```

`--cookies-file`과 `--cookies-from`은 배타적입니다. 인증 헤더 값은 CR/LF/NUL 인젝션에 대해 검증됩니다.

### 전체 `Cookie:` 헤더 재사용

큰 브라우저 세션을 재사용하는 가장 쉬운 방법은 `--cookies-file`입니다: DevTools의 `Cookie: …` 헤더 전체를 텍스트 파일에 붙여넣고 지정하면 됩니다. `--cookies-file`은 다음을 모두 받습니다:

- **쿠키 헤더 문자열** — `Cookie: a=1; b=2; …` (`Cookie:` 접두사는 선택),
- **Netscape/curl** 쿠키 파일,
- **JSON 배열**(브라우저 확장 익스포트) 또는 **EditThisCookie** JSON.

```bash
# cookies.txt 에 한 줄:  Cookie: WMONID=…; sso_key=…; JSESSIONID=…
bundleInspector scan https://app.example.com --cookies-file cookies.txt --scope "*.example.com"
```

긴 세션에는 `-c name=value` 보다 이 방식을 권장합니다: 셸 이스케이프가 전혀 필요 없고(값에 `$`, `%`, `:`, `=`, 빈 값이 있어도 됨) 헤드리스 브라우저의 쿠키 잼에 실제 쿠키로 주입됩니다. 파일은 라이브 세션이므로 **비밀로 취급**하고 커밋하지 마세요.

---

## 커스텀 룰

`--rules-file`로 나만의 탐지를 추가합니다(단일 JSON/YAML 파일, 디렉터리, 또는 `rules/` 형제 디렉터리를 둔 `meta.yml`). 세 가지 매처 계열을 지원합니다: **regex**, **ast_pattern**, **semantic**. 전체 DSL과 예제는 [`docs/CUSTOM_RULES.md`](CUSTOM_RULES.md) 참고.

```bash
bundleInspector analyze ./dist --rules-file my-rules.yml
```

---

## Python API

프로그램적으로도 구동할 수 있습니다:

```python
import asyncio
from bundleInspector import BundleInspector, Config

async def main():
    report = await BundleInspector(Config()).scan(["https://target.example.com"])
    for f in report.findings:
        print(f.risk_tier, f.category, f.extracted_value)

asyncio.run(main())
```

공개 심볼: `BundleInspector`, `Config`, `ScopeConfig`, `AuthConfig`, `JSAsset`, `Finding`, `Evidence`, `Correlation`, `Cluster`, `Report`, `Severity`, `Confidence`, `Category`, `RiskTier`.

---

## 동작 원리

`scan` 파이프라인은 8단계로 실행됩니다(`analyze`는 동등한 로컬 파이프라인 실행):

1. **Crawl** — JS URL 발견(정적 HTML 수집기, 선택적 헤드리스 렌더, 빌드 매니페스트 프로빙); SSRF 검증 시드; 헤드리스 네트워크 캡처가 enh2 관측 기준선을 공급.
2. **Download** — 도메인별 레이트리밋·동시성 세마포어·SSRF 재검증·크기 상한·콘텐츠 해시 중복 제거로 JS 다운로드.
3. **Normalize** — beautify, 라인 매퍼 생성, 인라인 + 외부 소스맵 해석.
4. **Parse** — AST 생성(esprima 또는 선택적 acorn).
5. **Analyze** — 룰 엔진 + 컨텍스트 필터 FP 감소 + enh1 게이팅 주석 + 메타데이터/위치 매핑.
6. **Correlate** — enh2 휴면 엔드포인트 주석 후 상관 그래프(엣지 + 클러스터) 구축.
7. **Classify** — 발견별 위험 등급·점수·영향·가능성 부여.
8. **Report** — 조립·요약·발견/리포트/체크포인트 영속화.

---

## 참고 & 제약

- **내장 프록시 미지원.** `--proxy` 플래그가 없어 트래픽을 Burp/ZAP 같은 상위 프록시로 라우팅하지 않습니다. 필요하면 OS/네트워크 레벨에서 가로채세요.
- **종료 코드.** `0` = 성공(발견이 **있어도**), `1` = 오류/중단, `2` = `--fail-on` 심각도 게이트 발동. `--fail-on` 없이는 심각도 기반 게이트가 없어 발견이 있어도 `0`으로 종료됩니다 — `--fail-on`을 쓰거나 리포트/SARIF로 판정하세요. (잘못된 CLI 인자도 Click에 의해 파싱 단계에서 `2`로 종료되지만, 스캔 전·리포트 미생성 시점이라 게이트 발동과 구분됩니다.)
- **설정 파일 전용 항목.** `interactive_clicking`, `block_state_changing_requests`, `min_severity`, `min_risk_tier` 는 **CLI 플래그가 없습니다** — `--config` YAML/JSON 파일로 지정하세요.
- **`on_state_change_attempt` 확인 훅**은 CLI 옵션이 아니라 프로그램(Python API) 훅입니다. 없으면 유발된 상태변경 요청은 그냥 차단됩니다.
- **중복 쿠키 이름**은 헤더 문자열에서 뒤 값이 채택됩니다(last-wins).

---

## 문제 해결

| 증상 | 해결 |
|---|---|
| `scan`에서 `playwright`/브라우저 오류(`headless_browser_not_installed`, `Executable doesn't exist` 등) | `playwright install chromium` 실행, 또는 `--no-headless`(혹은 비헤드리스 프로파일) 사용. 정적/매니페스트 수집은 계속 돌지만 SPA는 헤드리스 브라우저가 있어야 JS를 얻습니다. |
| `playwright install`이 `SELF_SIGNED_CERT_IN_CHAIN`으로 실패 | TLS를 가로채는 프록시(사내 MITM)가 Node 다운로드를 깨뜨리는 경우. **안전한 해결:** 프록시 루트 CA를 지정 — `setx NODE_EXTRA_CA_CERTS C:\경로\corp-root-ca.pem` 후 셸 재시작하고 재실행. **빠른(비보안) 해결:** `$env:NODE_TLS_REJECT_UNAUTHORIZED=0; playwright install chromium` (해당 세션만). 프록시가 필요하면 `$env:HTTPS_PROXY`도 설정. |
| 스캔이 너무 공격적/시끄러움 | `--config examples/scan-profiles/conservative.yml` 사용, `--rate-limit` 상향, `max_concurrent` 하향 |
| 네이티브 파서가 안 쓰임 | Node.js가 `PATH`에 있고 `acorn`을 찾을 수 있으며 `BUNDLEINSPECTOR_NATIVE_PARSER=1`인지 확인 — 아니면 조용히 esprima 사용 |
| 재개가 처음부터 다시 돎 | 동일 `--job-id`에서 설정(프로파일/룰/스코프 등)이 바뀌어 오래된 상태가 의도적으로 무효화됨 |
| 시크릿이 마스킹됨 | 정상 — 로컬·신뢰 분석에서만 설정 파일에 `rules.mask_secrets: false` 지정 |
| 큰 로컬 번들이 느림 | `BUNDLEINSPECTOR_PARALLEL=auto` 또는 `fast` 프로파일(beautify off) 시도 |
| Windows에서 한글 등 비ASCII 콘솔 출력이 깨짐 | 자동 처리됨 — CLI가 stdout/stderr를 UTF-8로 강제하므로 `PYTHONIOENCODING` 설정 불필요. UTF-8 지원 터미널(예: Windows Terminal) 사용 |
| `--cookies-from`이 쿠키를 못 가져옴 | DB(및 `-wal`)를 복사하므로 브라우저를 켜둔 채로 가능. Chrome/Edge/Chromium 암호화 값은 선택 패키지 `cryptography` 설치 시 Windows에서 자동 복호화(`pip install cryptography`). 그래도 비면 app-bound 암호화(Chrome 127+) 프로파일 — 쿠키 확장으로 JSON 내보내 `--cookies-file` 사용 |

---

인가된 보안 테스트를 위해 만들어졌습니다. 책임감 있게 사용하세요. 짧은 버전은 [README](../README.ko.md)를 참고하세요.
