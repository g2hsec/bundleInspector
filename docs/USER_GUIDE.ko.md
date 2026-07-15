# 📖 BundleInspector — 사용설명서

BundleInspector 설치·설정·실행에 대한 완전한 레퍼런스입니다.
간단한 개요는 [README](../README.ko.md)를 참고하세요.

---

## 목차

- [개요](#개요)
- [설치](#설치)
- [빠른 시작](#빠른-시작)
- [MCP 서버](#mcp-서버)
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

다운로드한 byte는 content hash 아래 보존합니다. 조건에 맞는 일반 JavaScript는 raw literal
보존 검사를 통과한 whitespace-reflow 파생물을 사용할 수 있고, TS/JSX 형태 또는 literal을
잃는 후보는 decoded source와 byte-equivalent한 상태로 유지합니다. 선택된 분석 content를
AST로 파싱한 뒤 **endpoint, secret, domain, flag, debug surface, sink/dataflow, upload** rule을
실행하고, 7가지 recon 고도화와 `P0–P3` 위험 등급을 적용합니다. source-map 원본은 가능한
경우 bounded virtual source로 분석합니다.

> **버전:** `0.1.0` · **Python:** `3.10-3.13` (`>=3.10,<3.14`) · **라이선스:** MIT

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
python -m pip install -e .
python -m playwright install chromium          # 헤드리스 스캔에 필요
```

clean Linux host/container에서는 Chromium과 OS library를 함께 설치하세요.

```bash
python -m playwright install --with-deps chromium
```

> **Windows PowerShell 5.1**은 `&&`를 지원하지 않고 `source`는 Unix shell 명령입니다. 각 명령을 한 줄씩 실행하세요. 활성화 시 *"이 시스템에서 스크립트를 실행할 수 없습니다"* 오류가 나면, 세션에서 한 번 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`를 실행한 뒤 `.venv\Scripts\Activate.ps1`을 다시 실행하세요.

개발용 설치(테스트·린팅):

```bash
pip install -e ".[dev]"              # pytest, pytest-asyncio, pytest-cov, ruff, mypy, pre-commit
```

**파서 선택.** 명시적인 `language_hint`가 있는 JavaScript, JSX, TypeScript, TSX는 필수
Tree-sitter 백엔드의 해당 문법으로 먼저 구조 파싱합니다. 힌트가 없는 일반 JavaScript는
완전한 legacy ESTree 결과를 사용할 수 있고, legacy 결과가 불완전하면 Tree-sitter로 다시
시도합니다. 선택적인 [Acorn](https://github.com/acornjs/acorn) ESTree 경로는 legacy Esprima
경로보다 먼저 켤 수 있으며, Node.js가 `PATH`에 있고 `acorn` 패키지를 찾을 수 있어야 합니다:

```bash
npm install acorn                     # Node가 찾을 수 있는 위치(또는 NODE_PATH)
export BUNDLEINSPECTOR_NATIVE_PARSER=1
```

Node/Acorn을 사용할 수 없으면 Esprima 및 구조 복구 경로로 계속 진행합니다. 모든 파싱
결과는 실제 선택된 backend, completeness, capability gap, truncation reason을 보고하며,
부분 또는 lexical 복구를 완전한 구조 파싱으로 표시하지 않습니다.

**런타임 의존성**(자동 설치): `httpx`, `httpcore`, `playwright`, `beautifulsoup4`, `lxml`,
`esprima`, `jsbeautifier`, `pydantic`, `click`, `rich`, `structlog`, `jinja2`, `aiofiles`,
`regex`, `cryptography`, `PyYAML`, `tree-sitter`, `tree-sitter-javascript`,
`tree-sitter-typescript`. Node.js/Acorn만 선택 사항입니다.

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

## MCP 서버

shipped MCP adapter는 **로컬 stdio 기반 read-only public report projection**으로 사용할 수
있습니다. 이 source checkout에서 extra를 설치하고 persisted CLI report를 만든 뒤 MCP client가
entry point를 실행하도록 설정합니다.

```bash
python -m pip install -e ".[mcp]"
bundleInspector analyze ./dist --job-id mcp-example
bundleInspector-mcp
```

CLI와 server 기본값은 모두 `~/.bundleInspector/cache`이므로 이를 공유할 때는
`--cache-dir`를 생략합니다. custom 또는 workspace fallback cache라면 정확히 같은 root를
전달하세요.

```bash
bundleInspector-mcp --cache-dir /absolute/path/to/.bundleInspector/cache
```

다음은 일반적인 client 설정입니다. client OS의 absolute executable/cache path를 사용하고
기본 cache를 쓸 때는 `args`를 제거하세요.

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

| Capability | 계약 |
|---|---|
| `list_jobs(limit=50, cursor=null)` | 접근 가능한 persisted job을 opaque ID로 열거 |
| `get_job_status(job_id)` | persisted report 기반 `completed`, `partial`, `unknown` 상태와 최신 opaque report ID 반환 |
| `get_report_page(...)` | `findings`, `assets`, `correlations`, `clusters` 조회; 기본 50개, 최대 100개 |
| `bundleinspector://jobs/{job_id}` | `application/json` MIME의 상태 resource template |

`next_cursor`를 따라갈 때 page kind와 limit를 바꾸지 마세요. cursor는 서명되며 principal,
request, content revision에 결합됩니다. report/key 변경 뒤에는 pagination을 처음부터 다시
시작해야 합니다. raw job/report ID는 거부하며 missing/malformed/unauthorized ID는 의도적으로
`resource unavailable` 한 종류로 처리합니다.

운영 경계:

- standalone server는 in-process `JobQueue`에 연결되지 않으므로 live scan 진행률이 아니라
  persisted 상태를 보여 줍니다. report page에는 저장된 report가 필요합니다.
- built-in `local` principal의 repository ownership이 있는 current job만 보입니다. ownerless
  legacy job은 자동 채택되지 않고 지원되는 adoption command도 없습니다. fresh current-format
  job으로 분석을 다시 실행해야 합니다.
- public DTO는 raw artifact, config, snippet, 임의 metadata를 제외합니다. field allowlist,
  bounded pagination/completeness, opaque ID, secret/URI redaction을 사용합니다.
- read-only는 MCP capability를 뜻하며 filesystem 무쓰기를 뜻하지 않습니다. 최초 초기화 시
  cache, `.public-view-key`, lock shard를 만들 수 있습니다. key 삭제/교체는 opaque ID를 바꾸고
  cursor를 무효화합니다.
- transport는 `stdio`만 지원하고 protocol authentication은 없습니다. client가 실행하는 로컬
  process로 유지하고 별도 인증/격리 없이 network bridge로 노출하지 마세요.
- 기존 report를 제공하는 데 Chromium은 필요 없습니다. headless scan으로 report를 만들 때만
  필요합니다.

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
| `--allow-private-ips` | off | **인가된** 내부/개발 서버 테스트용 — 대상이 **사설/내부** IP(RFC1918/CGNAT/ULA)로 resolve돼도 허용. 루프백·클라우드 메타데이터(`169.254.169.254`)·멀티캐스트·예약 대역은 계속 차단. |
| `--chains` | off | 발견 목록 뒤에 통합 **ATTACK CHAINS**를 출력 — sink 지표 + 확정 데이터플로우(`taint_flow`) + 업로드↔sink 상관관계를 sink별로 묶어 `source → flow → sink` 전체 경로(연결된 업로드 표면·재요청용 동일-파일 엔드포인트 포함)를 한 체인으로 보여줌. 확정 vs 휴리스틱 **후보(candidate)** 체인을 구분 표기. |
| `--first-party-only` | off | **노이즈 감소(비파괴적).** 벤더 파일 발견(`[3p:<lib>]`) **및** 오탐 가능(likely-FP, [노이즈 감소 & 트리아지](#노이즈-감소--트리아지) 참고)은 항상 **라벨링**되고 **맨 아래로 정렬**됨. 이 플래그는 추가로 *콘솔*에서 **숨김**. 저장 리포트에선 안 지워지고 탐지도 불변. |
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
| `--chains` / `--first-party-only` | off | `scan`과 동일 (어택 체인 뷰 / 벤더·오탐 숨김) |
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

1. **YAML 또는 JSON 파일** (`--config`, `scan`/`analyze` 모두). `.yaml`/`.yml`은 직접
   의존성인 PyYAML을 사용합니다. PyYAML을 import할 수 없는 경우와 PyYAML의 특정
   unknown-escape 호환 사례에만 검증된 subset parser를 사용하며, 그 외는 JSON으로 파싱합니다.
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
| `allow_private_ips` | `false` | 인가된 RFC1918/CGNAT/ULA 대상 허용; loopback/metadata/reserved는 계속 차단 |

**`auth`** — 자격증명(cookie/header/bearer/basic 이름과 값의 CR/LF/NUL 거부,
transport-controlled header 거부)

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
| `max_retries` / `retry_delay` | `3` / `1.0` | 재시도 횟수 / 기본 지연 |
| `max_file_size` | `10 MB` | 다운로드 JS 최대 크기 |
| `user_agent` | Chrome UA | 원격 스캔 User-Agent |

**`parser`**

| 필드 | 기본값 | 용도 |
|---|---|---|
| `extract_strings` / `extract_calls` / `extract_imports` | `true` | 해당 IR 기능 활성화 |
| `beautify` | `true` | 조건에 맞는 일반 JS reflow; TS/JSX 및 literal-loss 후보는 raw-equivalent 유지 |
| `resolve_sourcemaps` | `true` | 인라인 + 외부 소스맵 해석 |
| `beautify_max_bytes` | `1_000_000` | 이 크기 초과 시 beautify 생략 |
| `tolerant` / `partial_on_error` | `true` / `true` | 관대한/부분 파싱 |
| `build_call_graph` | `true` | 분석/상관관계용 호출 엣지 구축; `false`면 생략 |
| `analysis_worker_timeout` | `30.0` | 자산별 프로세스 워커 제한 시간(초, `0.1`-`600`) |

**`rules`**

| 필드 | 기본값 | 용도 |
|---|---|---|
| `enabled_categories` | `[endpoint, secret, domain, flag, debug, sink, upload]` | 활성 룰 카테고리 |
| `min_confidence` | `low` | `low` \| `medium` \| `high` |
| `mask_secrets` | `true` | 출력에서 시크릿 값 마스킹 |
| `secret_visible_chars` | `4` | 앞/뒤 노출 문자 수(각 측 최대 전체의 1/4); `0`이면 전체 마스킹 |
| `entropy_threshold` | `3.5` | 제네릭 시크릿 엔트로피 임계값 |
| `custom_rules_file` | `null` | 커스텀 룰 경로 |
| `extract_headers` / `extract_parameters` | `true` | endpoint request contract 추출 |
| **`client_side_gating_enabled`** | **`true`** | enh1 — 클라이언트 사이드 접근제어 게이팅 |
| **`client_side_gating_severity`** | **`medium`** | enh1 — 심각도 하한; high-confidence role/permission/entitlement guard는 최소 `high`로 승격 |
| **`dormant_endpoint_detection_enabled`** | **`true`** | enh2 — 휴면/은닉 엔드포인트 |
| **`runtime_endpoint_surfacing_enabled`** | **`true`** | enh7 — first-party runtime-only HTTP/WS endpoint |

**`output`**

| 필드 | 기본값 | 용도 |
|---|---|---|
| `format` | `json` | `json` \| `html` \| `sarif` |
| `output_file` / `output_dir` | `null` | 명시 파일 / 기본 디렉터리 |
| `min_severity` | `info` | rendered report copy의 최소 심각도 |
| `min_risk_tier` | `P3` | rendered report copy의 최소 위험 등급 |
| `include_snippets` / `snippet_context_lines` | `true` / `3` | finding evidence snippet 보존/자르기 |
| `include_raw_content` | `false` | JSON에만 asset 분석 입력 byte payload 포함; eligible asset에는 승인된 normalized derivative가 들어갈 수 있음 |
| `include_ast` | `false` | finding `ast_node_type`과 `metadata.ast_path` 보존; full report AST가 아님 |

output filtering은 persisted internal report를 변경하지 않습니다. `--fail-on`을 약화하지 않으며
wordlist/API map은 계속 모든 finding을 봅니다.

**최상위:** `log_level`(`info`), `verbose`, `quiet`, `cache_dir`
(`~/.bundleInspector/cache`, 쓰기 불가 시 워크스페이스 로컬로 폴백), `temp_dir`(병렬
워커를 포함한 네이티브 파서 전달 파일), `job_id`, `resume`. 파일시스템 `job_id`는
1-128자의 소문자 portable 식별자이며 첫 문자는 영숫자, 나머지는 `[a-z0-9._-]`만
허용합니다. 경로, 후행 점, alias, `con`/`com1` 같은 Windows 장치 이름은 거부합니다.

모든 config model은 unknown field를 거부합니다. 숫자 resource limit은 음수/비유한 값을
거부하고, `max_concurrent >= 1`, `analysis_worker_timeout=0.1..600`,
`secret_visible_chars=0..1024`, `snippet_context_lines=0..50`을 강제합니다.

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

**가이드.** 버그바운티/운영 트리아지의 첫 선택은 `ultra-safe` / `conservative`입니다. 주요 탐지기 세트는 유지하지만 트래픽과 함께 수집·source-map 커버리지를 의도적으로 줄입니다. `standard`는 인가된 진단에 적합합니다. `deep`은 커버리지가 가장 높고, 작거나 취약한 서비스에서 눈에 띄는 부하를 줄 가능성도 가장 큽니다. `fast`는 여기에 정규화 정밀도까지 속도와 맞바꾸므로, 그 트레이드오프가 허용될 때만 쓰세요.

---

## 🛡️ 트래픽 & 안전

원격 `scan`은 단일 페이지 fetch가 **아닙니다**. HTML 페이지 요청, 빌드 매니페스트 프로빙, JS 자산 다운로드, 그리고 헤드리스 활성 시 실제 브라우저 렌더링까지 발생합니다. 이 트래픽은 로그·WAF·모니터링에 보입니다.

### 상태변경 가드 (기본 ON)

가드는 scanner 자체의 route/click 탐색이 만드는 mutation 위험을 줄입니다.

- **`interactive_clicking = false`** — button/tab/role element click은 기본 off입니다.
  standard config의 route-link 탐색은 계속 활성화됩니다.
- **`block_state_changing_requests = true`** — 탐색이 시작된 뒤 유발된
  `POST`/`PUT`/`PATCH`/`DELETE`는 가로채어 endpoint discovery용으로 기록한 뒤 abort합니다.
  저수준 collector의 `on_state_change_attempt` callback이 명시적으로 승인하면 예외입니다.
- guard는 delayed request를 포함해 해당 page lifetime의 나머지 동안 유지됩니다. Playwright
  routing은 service worker가 가로챈 request를 검사할 수 없으므로 method 기반 guard를 꺼도
  headless context에서는 service worker를 항상 차단합니다.
- 초기 page-load request는 guard가 armed되기 전에 발생합니다. 의미상 상태를 바꾸는 `GET`은
  method list 밖이며, operator가 guard를 끄거나 승인 callback을 연결할 수도 있습니다.

이는 bounded traffic safeguard이지 절대적인 non-mutation 증명이 아닙니다. 가장 좁은 traffic
surface가 필요하면 interactive clicking을 끄고 headless 수집을 비활성화한 profile을
사용하세요.

### 스로틀링, 스코프 & SSRF

- **도메인별 적응형 레이트리밋** — 요청 간 `rate_limit`초(기본 `1.0`), `429`/`5xx`에 자동 백오프(×2, 최대 60s), 성공 시 회복. 동시성은 `max_concurrent`로 제한.
- **SSRF / 스코프 가드** — 모든 시드와 다운로드를 검증: localhost·클라우드 메타데이터 호스트, 사설/루프백/링크로컬/CGNAT IP(`169.254.169.254` 포함), DNS 리바인딩 체크, non-`http(s)` 스킴 차단. `ScopePolicy`가 허용/차단 도메인 강제.
  - **인가된 내부 스캔** — 내부망의 dev/staging 서버처럼 대상이 **사설**(RFC1918/CGNAT/ULA) 대역으로 resolve되는 경우 `--allow-private-ips`(또는 `scope.allow_private_ips: true`)로 허용. 기본 **off**의 명시적 옵트인이며, 루프백·클라우드 메타데이터(`169.254.169.254`)·멀티캐스트·예약 대역과 차단 호스트명(`localhost` 등)은 플래그와 무관하게 계속 차단됩니다.
- **시크릿 마스킹** — 시크릿 발견은 마스킹(`secret_visible_chars=4`), 요청 컨트랙트 추출 시 자격증명 형태 값은 디스크에 닿기 전에 `<REDACTED_*>`로 리댁션.
- **기타 하드닝** — 10 MB 다운로드 상한, 10 리다이렉트 상한, 인증 입력 CR/LF/NUL 검증, 로컬 분석 경로 순회 방지.

**부하는 어느 정도?** download limiter 기본 목표는 도메인당 약 초당 1요청이지만
collector/navigation request와 target이 생성하는 browser traffic이 더해지므로 보편적인 “사용자
한 명” 부하로 환산할 수 없습니다. `rate_limit`을 `0`에 가깝게 낮추고
`max_concurrent`를 올리면 burst가 발생할 수 있으므로 기본값 또는 conservative profile을
유지하세요.

> **BundleInspector는 DoS 도구가 아닙니다.** 다만 잘못 설정한 공격적 스캔은 일부 프로그램에 과할 수 있습니다. 항상 타겟 규칙과 트래픽 제한을 준수하세요.

### 자주 겪는 차단 & 권장 옵션

수정 가능한 이유로 차단/스킵될 때 경고 **바로 옆에 `hint=`**가 출력되고, **JS 0개 분석** 시에는 요약에 권장 조치 목록이 눈에 띄게 나옵니다:

| 상황 (로그 이벤트) | 이유 | 권장 옵션 |
|---|---|---|
| `seed_url_blocked` / `ssrf_blocked` — *"Resolved IP is blocked"* | 대상이 **사설/내부** IP로 resolve됨 | **인가된** 내부/개발 대상이면: `--allow-private-ips` (또는 `scope.allow_private_ips: true`) |
| `seed_url_blocked` — *"Blocked host"* | `localhost` / 클라우드 메타데이터 호스트명 | **설계상 차단** — 스캔 불가(우회 불가) |
| `seed_url_blocked` — *"Blocked/Unsupported scheme"* | non-`http(s)` URL(`javascript:`/`data:`/`file:`) | `http://` 또는 `https://` URL 사용 |
| `file_too_large` | JS가 `crawler.max_file_size`(10 MB) 초과 | `--config`에서 `crawler.max_file_size` 상향 |
| `headless_error` | Playwright/Chromium 미설치 또는 TLS 가로채기 프록시 | `playwright install chromium`, 또는 `--no-headless`(conservative 프로파일) |
| **JS 0개 분석** | 시드 차단 / 스코프 밖 / 런타임 주입 JS | 출력된 권장 목록 참고: `--allow-private-ips`, `--scope` 확대, 또는 헤드리스 프로파일 |

---

## 🔬 탐지 커버리지

### 핵심 카테고리

| 카테고리 | 기본 심각도 | 무엇을 찾나 |
|---|---|---|
| **Endpoint** | INFO | `fetch`/`axios`/`request`/`ajax` 호출, `obj.get/post/...`, `XMLHttpRequest.open`, `axios.create` baseURL/기본 헤더, `/api/`·`/v\d+/`·`/graphql`·`/rest/`·`/rpc/`·`/ws/`·`/socket`·`/webhook` 리터럴, 그리고 **서버사이드 동적 경로**(`.do`/`.jsp`/`.action`/`.php`/`.aspx`/`.ashx`/`.cgi`…) — 절대/상대 리터럴 또는 `${base}/x.do` 템플릿(Java/Spring/Struts, PHP, ASP.NET). 템플릿 리터럴·결합·삼항·상수·명명 객체·`new URL()`/`new Request()`까지 정적 해석. |
| **Secret** | HIGH | ~100개 사전 컴파일 키 패턴(AWS, Azure, GCP, OpenAI, Anthropic, GitHub, GitLab, Stripe, Slack, Twilio, Firebase, Supabase, DB 접속 문자열, JWT, PEM/SSH 키 …), 대입 컨텍스트 패턴(`api_key`, `access_token` …), 랜덤 블롭용 섀넌 엔트로피 분석(시크릿 어휘 없으면 LOW로 강등). 명백한 placeholder는 제외하지만 demo/mock 문맥의 provider 형태 credential은 hard-drop하지 않고 low/context-suppressed evidence로 보존. |
| **Domain** | MEDIUM | 내부/스테이징 호스트(`dev`/`staging`/`qa`…, `.internal`/`.local`/`.corp`), Kubernetes(`.svc.cluster.local`), Docker/AWS-internal, 사설/루프백 IP, S3/GCS/Azure 버킷, **클라우드 메타데이터/IMDS SSRF 타깃** — `169.254.169.254`·`metadata.google.internal` → **HIGH**(인스턴스 자격증명 탈취), 링크로컬 `169.254.0.0/16`. |
| **Flag** | LOW | 피처 플래그 키워드, SDK(LaunchDarkly, Optimizely, Split, ConfigCat, Unleash …), 플래그 설정 엔드포인트, 플래그 체크 함수, admin/debug 식별자. |
| **Debug** | 경로별 | 디버그/관리 경로 등급별(`/shell`,`/eval` → CRITICAL; `/debug`,`/admin` → HIGH; `/actuator`,`/test` → MEDIUM; `/health`,`/swagger` → LOW), 민감 `console.*`, `debugger`, `alert()`, dev 전용 분기(`NODE_ENV`, `__DEV__`), **소스맵 노출**(`//# sourceMappingURL=` — 맵은 난독화 이전 원본 소스를 복원). |
| **Sink** | sink별 | **동적 인자가 흘러드는 DOM-XSS/코드인젝션/오픈리다이렉트 sink**(정적 리터럴 제외): HTML 주입(`innerHTML`/`outerHTML =`, `document.write`, `insertAdjacentHTML`, jQuery `.html()`/`.append()`…, jQuery **HTML 생성** `` $('<div>'+x) ``/`` $(`<a href="${u}">`) ``), 속성 주입(`setAttribute`/jQuery `.attr()`/`.prop()`의 `src`/`href`/`on*`…), **HTML 속성 주입** — 동적 값이 HTML 문자열의 위험 속성에 삽입되는 경우(`` `<img src="${item.image_url}">` ``, `onerror="${x}"`) → **HIGH**, **내비게이션/오픈리다이렉트**(`location.href =`, `location.assign`/`replace`, `window.open`에 동적 값 — `javascript:` URL DOM-XSS도 포착, `location.pathname` 같은 동일 출처 컴포넌트는 제외), 코드 실행(`eval`, `new Function`, 문자열 `setTimeout`/`setInterval`). 발견 시 **소스 표현식**(`item.image_url`, `e.target.result`, `uploaded.path`…)을 함께 표기해 무엇이 흘러드는지 보여줌. 이는 클라이언트측 **지표**임. 그 위에 **흐름 민감 데이터플로우 taint 엔진**이, 열거된 *실제 소스*(FileReader 결과, `$.ajax`/`fetch` 응답, DOM 입력 `.val()`/`.data()`/`location.*`/`window.location.*`)가 실제 def-use 체인으로 sink에 닿을 때만 **CONFIRMED** `taint_flow` 발견(재구성된 `source → … → sink` 경로 포함)을 냄. 흐름 민감(clean 재대입은 taint를 kill, 역방향 불가능 흐름 없음)·문맥 민감(`f(사용자입력)`은 taint, `f("safe")`는 아님)·클로저/스코프 인식이며 파일 외부/미해결 호출은 abstain — 잘못된 흐름보다 미탐을 선호. |
| **Upload** | 신호별 | 파일 업로드 표면: `new FormData()`/`multipart`, JS로 만든 `<input type="file">`, 그리고 **클라이언트측 전용 확장자 허용목록**(`allowedExt`/`allowedTypes`… → MEDIUM) — 우회 가능하므로 서버 재검증 여부 확인(무제한 업로드 위험). |

**Chunk Analyzer**가 Webpack/Vite 코드 스플릿 인프라와 지연/은닉 라우트를 추가로 드러냅니다.

> **Sink**·**Upload** 탐지기는 *지표*이지 확정 취약점이 아닙니다: 정적 번들 스캔은 서버측 통제(인가, 서버 파일 재검증)나 입력의 공격자 제어 여부를 볼 수 없습니다. 수동/DAST로 확인할 sink·표면을 정확히 안내합니다 — 저장값이 흘러드는 `.html()`/`innerHTML=`는 **저장형 XSS**의 클라이언트 절반, 클라이언트측 `allowedExt` 검사는 **무제한 파일 업로드**의 클라이언트 절반입니다.

### 7가지 고도화

| ID | 이름 | 내용 |
|---|---|---|
| **enh1** | 클라이언트 사이드 접근제어 게이팅 | 브라우저 측 authz 체크 **뒤에서만** 도달 가능한 엔드포인트(`if(user.isAdmin)`, `flags.canX && fetch(...)`, `if(!hasRole()) return`)를 표시. 가드를 분류(role/permission/entitlement/feature/flag)하고 심각도 상향 — 전형적 우회 표면. 오프셋 매칭으로 minified 단일 라인도 지원. |
| **enh2** | 휴면/은닉 엔드포인트 | JS에 **선언된** 엔드포인트와 헤드리스 크롤 중 앱이 **실제 호출한** 엔드포인트를 대조. 선언됐지만 호출된 적 없는 것은 AJAX로 도달 가능한 우회 표면. FP 안전(런타임 기준선 없으면 no-op, 미접촉 호스트 제외), 민감 경로는 MEDIUM으로. |
| **enh3** | 재현 가능한 요청 컨트랙트 + PoC | 호출별 컨트랙트(method, url, headers, auth scheme, body shape, query params)를 `request_contract` 메타데이터로 조립, 자격증명 형태 값은 추출 시 리댁션. `reporter/poc.py`가 `FUZZ` 플레이스홀더로 **curl + fetch** 스니펫 렌더. |
| **enh4** | IDOR + HTTP 메서드-플립 | IDOR/열거 경로 파라미터(`${…}`, `:id`, UUID, Mongo ObjectId, email, numeric)를 탐지해 `idor_candidate` 태그; 각 경로에서 **아직 안 본** 표준 HTTP 메서드를 퍼징 힌트로 나열. HTTP 중복 제거를 `(method, url)`로 키잉해 정상 `GET` 옆의 은닉 `DELETE`도 보존. |
| **enh5** | 프레임워크 클라이언트 라우트 맵 | React Router / Vue Router / Angular / 컴파일된 JSX / Next.js 파일 라우트에서 인식 가능한 SPA 라우트를 복원하며, 내비에 **없는** admin/internal/피처플래그 페이지도 포함합니다. 부모/자식 경로 결합 + 라우트별 지연 청크 연결. `client_route` 발견 생성, 민감 라우트 표시. 동적이거나 미지원인 라우트 구성은 해석되지 않을 수 있습니다. |
| **enh6** | GraphQL + WebSocket 표면 | `gql` 태그드 템플릿·쿼리 프로퍼티에서 GraphQL 오퍼레이션(query/mutation/subscription + 필드) 추출, WS/Socket.IO 클라이언트의 `.send()`/`.emit()`에서 WebSocket **메시지 표면** 추출. |
| **enh7** | 런타임 관측 엔드포인트 | enh2의 짝: 크롤 중 앱이 **실제 호출**했지만 정적 분석이 못 찾은 HTTP/WebSocket 엔드포인트(주로 동적 조립 URL)를 `runtime-observed` 발견으로 노출. 스캔 전용, first-party 스코프, 정적 발견과 중복 제거. |

### 다운로드 표면 (Download surfaces)

파일을 클라이언트로 서빙하는 엔드포인트는 고가치 표면입니다 — path traversal, 파일 IDOR, SSRF,
forced browsing. 전용 분류기가 **파일** 다운로드 엔드포인트를 태깅하고 **어떤 파라미터**가 **어떤 위험**인지
지목합니다.

**엔드포인트 이름이 아니라 "파일을 서빙하느냐"로 등급 판정.** 판단 기준은 "쿠폰이냐"가 아니라 **"파일을
서빙하느냐"** — 쿠폰/리포트/기프트 "다운로드"는 바코드 **PDF/이미지**를 서빙하는 경우가 많고(임의파일다운로드/
traversal/IDOR 취약점), 그래서 **일괄 제외하지 않습니다.** 2단계:

- **CONFIRMED** — 파일-다운로드 키워드(`fileDown`/`getFile`/`atchFileDown`/`excelDown`/`download.php`…),
  강한 파일 파라미터, office/archive 확장자, **또는 호출부 근처의 파일-응답 메커니즘**(`responseType:'blob'`,
  `createObjectURL`, `download` 속성, `saveAs`, `content-disposition`, `application/pdf`) — 이름과 무관하게
  PDF를 스트리밍하는 쿠폰 엔드포인트도 잡습니다.
- **POSSIBLE(검증)** — 강한 신호 없는 download/export 키워드; 낮은 신뢰도로 "응답이 파일인지 검증하라" 노트와 함께
  표기(`…Count`/`…Agree` 같은 데이터/액션 엔드포인트는 제외).

키워드는 **단어 경계** 매칭(→ `uploadFile`/`profileView`/`targetImage` 오탐 없음), 업로드 엔드포인트 제외,
고위험 판정은 강키워드 **AND** 강파라미터 필요.

**한국 엔터프라이즈 관례(깊이).** eGovFrame / Nexacro / XE·Rhymix / 그누보드 파라미터명:

| 파라미터 | 의미 | 위험 |
|---|---|---|
| `atchFileId`, `fileSn`, `fileMngId`, `nttFileId`, `bsnsFileSn`, `file_srl` | 첨부파일ID/순번 | **file-IDOR** |
| `fileNm`, `orgnlFileNm`, `streFileNm` (`Nm`=名) | 파일명 | **path-traversal** |
| `fileStreCours` (`Cours`=경로), `filePath`, `savePath` | 저장경로 | **path-traversal** |
| `imageUrl`, `fileUrl`, `remoteUrl` | 원격 fetch | **SSRF** |
| `objectKey`, `s3Key` | 클라우드 스토리지 키 | file-IDOR |

엔드포인트에 **`▾ download: <위험>`** 태그 + 전용 **Download Surfaces 표**(콘솔) / **`⬇ DOWNLOAD` 배지 + 위험
패널**(HTML)로, 정확한 파라미터와 테스트 방법(`../../etc/passwd`, id 열거, `169.254.169.254` …)을 표기.
비파괴 — 태깅만, 탐지 불변.

### 위험 등급

모든 발견은 점수화·등급화됩니다:

| 등급 | 의미 |
|---|---|
| **P0** | 치명적 — 즉시 대응 |
| **P1** | 높음 |
| **P2** | 중간 — 조사 필요 |
| **P3** | 낮음 / 정보성 |

---

## 노이즈 감소 & 트리아지

정적 스캐너는 서드파티 라이브러리와 패턴-only 매치에서 과탐이 많습니다. BundleInspector는 이를
**비파괴적으로** 줄입니다 — 오탐 가능 항목은 **라벨링 + 하위 정렬(demote)일 뿐 절대 삭제하지 않음** →
탐지율 불변(탐지 불변성 게이트 바이트 동일 유지).

프레젠테이션 레이어 패스가 다음일 때 `likely_fp`(사유 포함)로 태깅합니다:

| 규칙 | 무엇을 강등 | 왜 오탐인가 | 안전장치 |
|---|---|---|---|
| **A** | **서드파티 라이브러리 파일**(`jquery`/`swiper`/`jsencrypt`/…) 안의 "시크릿" | 라이브러리 정규식/CSS/base64 알파벳 문자열, 앱 크리덴셜 아님 | `category == secret` + 벤더 파일일 때만 |
| **C** | base64 키 본문 없는 `-----BEGIN … PRIVATE KEY-----` **마커만** | PEM 파싱/라벨 코드, 유출된 키 아님 | 실제 키는 절대 강등 안 함 — 스니펫에 base64 본문 **또는** PEM 구조(`-----END`/`Proc-Type:`/`DEK-Info:`)가 있으면 유지 |

**CONFIRMED** taint flow(입증된 `source → sink`)는 **절대** 강등되지 않습니다.

**어디서 보이나**
- **콘솔** — likely-FP/벤더 발견은 맨 아래로 정렬 + 태깅(`[3p:…]` / `[likely FP: …]`), 카운트 라인이 `--first-party-only`로 숨기라고 안내.
- **HTML 리포트** — 노이즈는 **기본적으로 숨김**(배너에 "검토할 first-party N개 · 벤더/오탐 M개 숨김" 표기), 토글로 펼침(리포트엔 그대로 유지). N은 **전부 취약점이 아님** — 엔드포인트/플래그 같은 공격표면 포함, 심각도순 정렬이라 확정 dataflow·injection이 먼저 옴. 각 sink는 **DANGEROUS VALUE** 라인으로 sink에 도달하는 정확한 값을 표기하고, **코드 스니펫이 그 값 기준으로 앵커**되어(여러 줄 HTML 템플릿 깊숙이 있어도) 하이라이트로 보이게 함.

---

## 출력 & 리포트

| 형식 | 플래그 | 비고 |
|---|---|---|
| **JSON** | `-f json` (기본) | redaction을 적용한 전체 구조 필드. asset 분석 입력 byte는 `include_raw_content`를 켜야 포함하며 승인된 normalized derivative일 수 있음; source-map 원본 위치와 고도화 metadata를 보존 |
| **HTML** | `-f html` | 자체 JSON을 내장한 단일 파일 리포트(`convert`로 왕복 가능) |
| **SARIF 2.1.0** | `-f sarif` | GitHub Code Scanning / Azure DevOps용; 룰 `JSFINDER001–007`(secret/endpoint/domain/flag/debug/sink/upload), CWE 분류, 정규화 vs 원본 위치 코드 플로우 |

부가 산출물(메인 리포트 옆에 생성):

- **퍼징 워드리스트** — `-w {all,endpoints,paths,params,domains,dirs}` → `wordlist_endpoints.txt`, `wordlist_paths.txt`, `wordlist_params.txt`, `wordlist_domains.txt`, `wordlist_dirs.txt` (`${…}` → `FUZZ`; ffuf/dirsearch/feroxbuster 호환).
- **API 맵** — `--api-map` → `api_map.json` + `api_map.txt` (도메인 → 라우트 → 파라미터 ASCII 트리).

기본 리포트 파일명: `bundleInspector_report.<ext>`(scan), `bundleInspector_local_report.<ext>`(analyze), `report.<ext>`(convert).

### 분석 completeness

모든 report는 `Report.completeness.status`로 `complete`, `partial`, `failed`,
`cancelled` 중 하나를 가집니다. issue는 stable code/stage, retryable 여부, affected count,
internal diagnostic detail을 포함합니다. 따라서 parser recovery, collection failure,
source-map/virtual-source 손실, cap, custom-rule failure, worker timeout이 clean한 0-finding
결과로 숨지 않습니다. HTML은 incomplete banner/issue를, SARIF는 completeness
property/notification을, JSON은 설정된 redaction/raw-content 정책 범위에서 structured model을
보존하고, MCP는 bounded allowlisted summary만 공개합니다.

---

## 성능

- **원격 scan 병렬 분석** — 원격 `scan` orchestrator가 `BUNDLEINSPECTOR_PARALLEL`을
  읽습니다. 미설정/`0`/`1` = serial, `auto` = CPU당 worker 1개, 정수 `N` = worker
  `N`개입니다. parse/analyze는 각 worker 안에서 합쳐져 큰 AST가 process 경계를 넘지
  않습니다. 로컬 `analyze`는 현재 serial이며 이 변수를 읽지 않습니다.

  ```bash
  BUNDLEINSPECTOR_PARALLEL=auto bundleInspector scan https://target.example.com
  ```

- **파서 백엔드** — language hint가 있는 JS/JSX/TS/TSX는 필수 Tree-sitter 문법을 먼저
  사용합니다. `BUNDLEINSPECTOR_NATIVE_PARSER=1`은 선택적으로 Node.js/Acorn을 legacy
  Esprima보다 먼저 시도하며, 불완전한 legacy 파싱은 구조 backend로 다시 시도합니다.
- **재개 / 체크포인트** — `--job-id <id> --resume`이 최신 저장 리포트 또는 단계별 체크포인트를 재사용. **resume 시그니처**가 동일 job id에서 프로파일·파서·룰·인증·스코프·깊이·헤드리스 설정이 바뀌면 오래된 상태를 무효화.
- **재개 정확성** — local input content, config, report schema, parser identity, engine identity가
  resume contract에 들어갑니다. retryable/incomplete collection work는 false-complete
  checkpoint가 아니라 retry barrier로 유지됩니다.
- **내부 최적화** — content-hash dedup, linear beautify line mapping, pass별
  dependency/runtime cache, call-target/AST memoization, sound required-literal secret prefilter로
  반복 작업을 제한합니다. custom regex와 candidate recovery에는 time/count cap이 있습니다.
- **릴리스 benchmark gate** — 커밋된 baseline은 정확한 의존성, 측정 origin, CPU provenance를
  가진 Linux x86-64 CPython 3.13 측정입니다. 동일 CPU에서는 point p95 +20%와 RSS +25%를
  적용합니다. CPU가 달라도 gate를 생략하지 않고 current p95 bootstrap 하한을 baseline
  상한 +20%와 비교하며 RSS +25%도 유지합니다. 다만 cross-hardware 결과는 원인을 코드와
  하드웨어 중 하나로 귀속할 수 없으며
  `applied_cross_hardware_attribution_unavailable` 상태를 기록합니다. 절대 상한, 의미,
  completeness, sample, bootstrap, CV gate는 항상 유지되며 baseline은 자동 갱신되지 않습니다.

### 현재 기준 측정

committed reference는 WSL2 Linux x86-64, CPython 3.13.7, AMD Ryzen 9 9950X에서 scenario별
warmup 2회와 measured run 30회로 측정했습니다.

| Correlator fixture | p50 ms | p95 ms | p95 95% bootstrap CI | observed peak RSS | Edge |
|---:|---:|---:|---:|---:|---:|
| 80 module / 160 finding | 311.577 | 330.026 | 320.358-342.076 | 72,667,136 B | 1,130 |
| 200 module / 400 finding | 880.845 | 913.658 | 901.100-918.252 | 86,319,104 B | 1,250 |
| 500 module / 1,000 finding | 4,062.641 | 4,131.418 | 4,103.741-4,173.599 | 116,260,864 B | 1,550 |

| Detection/resource scenario | Fixture size | p50 ms | p95 ms | p95 95% bootstrap CI | observed suite peak RSS |
|---|---:|---:|---:|---:|---:|
| complete Tree-sitter TypeScript parse | 1,048,576 B | 613.226 | 639.054 | 632.591-643.679 | 404,127,744 B |
| bounded custom regex timeout | 20,029 B | 50.179 | 50.234 | 50.210-50.253 | 404,127,744 B |
| lexical candidate flood/recovery | 150,123 B | 20.178 | 20.593 | 20.378-20.729 | 404,127,744 B |

이는 remediation 뒤 처음 기록한 current-reference baseline입니다. 동일 방법의 수정 전 baseline이
없으므로 **속도 개선률을 증명하지 않습니다**. synthetic stage gate이지 end-to-end
`scan`/`analyze`, crawler/browser/network throughput 또는 SLA가 아닙니다. peak RSS는 process
lifetime high-water 관측값이므로 뒤 row와 같은 detection 값은 scenario별 독립 allocation이
아닙니다. 이 고성능 WSL host의 결과를 다른 hardware 성능으로 일반화할 수 없습니다.

### 검증 snapshot과 한계

- public labeled corpus는 45 case와 1,916 label/prediction에서 19개 release gate를 모두
  통과하며 labeled FP/FN, parser, completeness, invariance, graph, regression failure list가
  비어 있습니다.
- repository-visible frozen governance artifact도 11 case와 2,193 label/prediction에서 같은
  19-key profile을 통과합니다.
- 이 완벽한 in-corpus 관측은 일반적인 100% 정확도 주장이 아닙니다. frozen case는 공개되어
  있고 하나의 vendor-family identity를 공유하며 unseen external independent sample이 아닙니다.
- exact import-edge precision, original source-map column 정확도, injected-cap attribution,
  diagnostic recall에는 각각 독립적인 external labeled estimate가 없습니다.

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

`--cookies-file`과 `--cookies-from`은 배타적입니다. cookie/header 이름과 값, bearer token,
basic-auth의 두 구성요소는 CR/LF/NUL control character를 거부합니다.

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

1. **Crawl** — JS 발견(정적 HTML 수집기 — 외부 `<script src>` **및 인라인 `<script>` 본문** — 선택적 헤드리스 렌더, 빌드 매니페스트 프로빙); SSRF 검증 시드; 헤드리스 네트워크 캡처가 enh2 관측 기준선을 공급.
2. **Download** — 도메인별 레이트리밋·동시성 세마포어·SSRF 재검증·크기 상한·콘텐츠 해시 중복 제거로 JS 다운로드.
3. **Normalize** — raw content-hash artifact를 유지하고, raw-literal monotonicity 검사를 통과한
   일반 JS만 선택적으로 beautify하며, generated/original line mapping과 bounded inline/external
   source map을 해석. TS/JSX 형태 또는 literal을 잃는 후보는 raw-equivalent 유지.
4. **Parse** — JS/JSX/TypeScript/TSX language hint가 있으면 해당 Tree-sitter 문법을 먼저
   사용하고, 힌트가 없는 입력은 선택적 Acorn 및 legacy/recovery 순서로 AST 생성.
5. **Analyze** — 룰 엔진 + 컨텍스트 필터 FP 감소 + enh1 게이팅 주석 + 메타데이터/위치 매핑. 소스맵에 내장된 원본(minify 이전) 소스(`sourcesContent`)도 가상 소스로 스캔해, 원본 코드에만 있는 시크릿/엔드포인트를 복구합니다.
6. **Correlate** — enh2 휴면 엔드포인트 주석 후 상관 그래프(엣지 + 클러스터) 구축. 엣지 유형에 same-file·import/call-chain·runtime·secret↔endpoint 및 **taint**가 있습니다 — 같은 자산 안에서 **파일 업로드 표면(또는 업로드/파일 엔드포인트) → 파일/이미지/업로드로 보이는 값이 흘러드는 DOM `src`/`href` sink**를 자동 연결해 `업로드 → <img src>` 저장형/DOM XSS 체인을 드러냅니다(휴리스틱, MEDIUM 신뢰도 — 연결된 sink는 위험 점수도 상향).
7. **Classify** — 발견별 위험 등급·점수·영향·가능성 부여.
8. **Report** — 조립·요약·발견/리포트/체크포인트 영속화.

---

## 참고 & 제약

- **내장 프록시 미지원.** `--proxy` 플래그가 없어 트래픽을 Burp/ZAP 같은 상위 프록시로 라우팅하지 않습니다. 필요하면 OS/네트워크 레벨에서 가로채세요.
- **종료 코드.** `0` = 성공(발견이 **있어도**), `1` = 오류/중단, `2` = `--fail-on` 심각도 게이트 발동. `--fail-on` 없이는 심각도 기반 게이트가 없어 발견이 있어도 `0`으로 종료됩니다 — `--fail-on`을 쓰거나 리포트/SARIF로 판정하세요. (잘못된 CLI 인자도 Click에 의해 파싱 단계에서 `2`로 종료되지만, 스캔 전·리포트 미생성 시점이라 게이트 발동과 구분됩니다.)
- **설정 파일 전용 항목.** 주요 예로 `interactive_clicking`,
  `block_state_changing_requests`, `min_severity`, `min_risk_tier`가 있으며
  `--config` YAML/JSON 파일로 지정합니다.
- **`on_state_change_attempt` 승인 callback**은 저수준 `HeadlessCollector` integration
  point이며 CLI option이나 wiring된 high-level `BundleInspector` API가 아닙니다. callback이
  없으면 guarded state-changing request를 차단합니다.
- **중복 쿠키 이름**은 헤더 문자열에서 뒤 값이 채택됩니다(last-wins).
- **Headless response memory bound.** 신뢰할 수 있는 `Content-Length`는 capture 전에
  거부하지만, length가 없거나 거짓인 한 response는 Playwright `response.body()`가 materialize한
  뒤에야 `max_file_size`를 검사할 수 있습니다. capture semaphore는 동시성만 제한하고 이 한
  response allocation을 제한하지 않습니다.
- **정적 분석 경계.** dynamic code, unresolved cross-file/runtime value, server-side
  authorization/validation, 의도적으로 bounded cap은 여전히 FP/FN을 만들 수 있습니다.
  0-finding 결과를 해석하기 전에 `Report.completeness`를 확인하세요.

---

## 문제 해결

| 증상 | 해결 |
|---|---|
| `scan`에서 `playwright`/브라우저 오류(`headless_browser_not_installed`, `Executable doesn't exist` 등) | `playwright install chromium` 실행, 또는 `--no-headless`(headless 수집 비활성화 profile) 사용. 정적/매니페스트 수집은 계속 돌지만 SPA는 headless browser가 있어야 JS를 얻을 수 있습니다. |
| `playwright install`이 `SELF_SIGNED_CERT_IN_CHAIN`으로 실패 | TLS를 가로채는 프록시(사내 MITM)가 Node 다운로드를 깨뜨리는 경우. **안전한 해결:** 프록시 루트 CA를 지정 — `setx NODE_EXTRA_CA_CERTS C:\경로\corp-root-ca.pem` 후 셸 재시작하고 재실행. **빠른(비보안) 해결:** `$env:NODE_TLS_REJECT_UNAUTHORIZED=0; playwright install chromium` (해당 세션만). 프록시가 필요하면 `$env:HTTPS_PROXY`도 설정. |
| 스캔이 너무 공격적/시끄러움 | `--config examples/scan-profiles/conservative.yml` 사용, `--rate-limit` 상향, `max_concurrent` 하향 |
| Acorn 경로가 안 쓰임 | Acorn은 선택 사항입니다. Node.js가 `PATH`에 있고 `acorn`을 찾을 수 있으며 `BUNDLEINSPECTOR_NATIVE_PARSER=1`인지 확인하세요. language hint가 있는 최신 입력은 의도적으로 Tree-sitter를 먼저 사용합니다. |
| 재개가 처음부터 다시 돎 | 동일 `--job-id`에서 설정(프로파일/룰/스코프 등)이 바뀌어 오래된 상태가 의도적으로 무효화됨 |
| 시크릿이 마스킹됨 | 정상 — 로컬·신뢰 분석에서만 설정 파일에 `rules.mask_secrets: false` 지정 |
| 큰 로컬 번들이 느림 | 로컬 `analyze`는 serial입니다. fidelity tradeoff가 허용되면 config에서 beautify/source map을 끄거나 독립 input set을 나누세요. |
| MCP가 시작되지만 job이 없음 | `scan`/`analyze`와 정확히 같은 `cache_dir`를 사용하세요. ownerless legacy job은 의도적으로 보이지 않습니다. |
| `bundleInspector-mcp` 실행이 멈춘 것처럼 보임 | stdio에서는 정상입니다. MCP client가 process를 실행하고 stdin/stdout으로 protocol message를 교환하도록 설정하세요. |
| Windows에서 한글 등 비ASCII 콘솔 출력이 깨짐 | 자동 처리됨 — CLI가 stdout/stderr를 UTF-8로 강제하므로 `PYTHONIOENCODING` 설정 불필요. UTF-8 지원 터미널(예: Windows Terminal) 사용 |
| `--cookies-from`이 쿠키를 못 가져옴 | DB(및 `-wal`)를 복사하므로 브라우저를 켜둔 채로 가능합니다. 필수 `cryptography` 의존성이 지원되는 Chrome/Edge/Chromium 값을 Windows에서 복호화합니다. 그래도 비면 app-bound 암호화(Chrome 127+)일 수 있으므로 쿠키 확장으로 JSON을 내보내 `--cookies-file`을 사용하세요. |

---

인가된 보안 테스트를 위해 만들어졌습니다. 책임감 있게 사용하세요. 짧은 버전은 [README](../README.ko.md)를 참고하세요.
