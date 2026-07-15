<div align="center">

<img src="images/main_banner.png" alt="BundleInspector" width="100%">

# 🔎 BundleInspector

### 자바스크립트 속에 숨은 공격 표면을 드러냅니다.

정적 **+** 동적 분석으로 자바스크립트 번들에서 숨겨진 API 엔드포인트, 하드코딩된 시크릿,
내부 도메인, 클라이언트 사이드 우회 지점을 뽑아내는 보안 스캐너 —
모의해커, 버그바운티 헌터, AppSec 엔지니어를 위한 도구입니다.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10-3.13](https://img.shields.io/badge/Python-3.10--3.13-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-brightgreen.svg)](#)
[![Headless: Playwright](https://img.shields.io/badge/headless-Playwright-2ea44f.svg)](https://playwright.dev/)
[![Output: SARIF](https://img.shields.io/badge/output-JSON%20%C2%B7%20HTML%20%C2%B7%20SARIF-orange.svg)](#-무엇을-찾나요)

[English](README.md) · **한국어** · [📖 사용설명서](docs/USER_GUIDE.ko.md)

</div>

---

## ✨ 핵심 기능

- **두 가지 모드** — 라이브 사이트를 `scan`(크롤 → 렌더 → 다운로드 → 분석)하거나, 로컬 번들을 **네트워크 트래픽 없이** `analyze`.
- **깊이 있는 정적 추출** — 숨겨진 REST / GraphQL / WebSocket 엔드포인트(서버사이드 `.do`/`.jsp`/`.php`/`.aspx` 경로 포함), ~100종의 시크릿, 내부·스테이징 도메인, 피처 플래그, 디버그 엔드포인트, **DOM-XSS/코드인젝션 sink**(동적 값이 흘러드는 `innerHTML`/`.html()`/`eval`/`document.write`), 도달 가능성을 구분하는 **confirmed/probable 데이터플로우**, **파일 업로드 표면**(우회 가능한 클라이언트측 검증 포함)을 템플릿 리터럴·문자열 결합·분기·상수·alias·실용적 호출 흐름까지 따라가며 해석.
- **공격 정찰 기능 내장** — 7가지 고도화: 클라이언트 사이드 접근제어 게이팅, **휴면/은닉 엔드포인트**, 재현 가능한 curl/fetch PoC, IDOR + HTTP 메서드-플립 힌트, SPA 라우트 맵 복원, GraphQL/WebSocket 표면, **런타임 관측 엔드포인트**(정적으론 못 찾았지만 실행 중 호출됨).
- **기본이 안전** — route/click 탐색이 활성화된 동안 유발된 상태변경 요청은 기본적으로 가로채어 기록하고 차단합니다. 도메인별 레이트리밋 + 적응형 백오프, SSRF·스코프 가드, 시크릿 마스킹도 적용합니다.
- **자원 경계와 회귀 gate** — 필수 Tree-sitter JS/TS/TSX 백엔드, 선택적 Acorn,
  콘텐츠 해시 중복 제거, 재개 가능한 체크포인트, 원격 `scan` 자산 분석의 opt-in
  멀티프로세싱을 제공합니다. 기본값과 로컬 `analyze` 경로는 serial입니다.
- **워크플로에 맞는 리포트** — JSON, 단일 파일 HTML 리포트, **SARIF**(GitHub Code Scanning) — 여기에 퍼징 워드리스트와 복원된 API 맵까지.

## 🚀 설치

**Python 3.10-3.13** 필요. 헤드리스 스캔에는 Playwright Chromium 바이너리가 필요합니다.

```bash
git clone https://github.com/g2hsec/bundleInspector.git
cd bundleInspector
python -m venv .venv
```

가상환경 활성화 후 설치:

| 셸 | 활성화 |
|---|---|
| **macOS / Linux (bash/zsh)** | `source .venv/bin/activate` |
| **Windows PowerShell** | `.venv\Scripts\Activate.ps1` |
| **Windows cmd** | `.venv\Scripts\activate.bat` |

```bash
python -m pip install -e .
python -m playwright install chromium
```

clean Linux host/container에서는 Chromium OS 의존성도 함께 설치하세요.

```bash
python -m playwright install --with-deps chromium
```

> **Windows PowerShell 5.1**은 `&&`를 지원하지 않으며 `source`는 Unix shell 명령입니다. 각 줄을 따로 실행하세요. `Activate.ps1`이 차단되면("스크립트 실행이 사용 안 함") 세션에서 한 번 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`를 먼저 실행하세요.

## ⚡ 빠른 시작

```bash
# 라이브 타겟 스캔 — 반드시 스코프 안에서
bundleInspector scan https://target.example.com --scope "*.example.com"

# 로컬 번들 분석 — 네트워크 트래픽 전혀 없음
bundleInspector analyze ./dist

# 공유용 HTML 리포트 생성
bundleInspector scan https://target.example.com -f html -o report.html

# CI / GitHub Code Scanning 용 SARIF 출력
bundleInspector scan https://target.example.com -f sarif -o findings.sarif

# job id 로 긴 스캔 재개
bundleInspector scan https://target.example.com --job-id acme --resume
```

## MCP 서버

source checkout에서 선택 의존성을 설치합니다. 먼저 persisted report를 만든 뒤 MCP client가
stdio 서버를 실행하도록 설정합니다.

```bash
python -m pip install -e ".[mcp]"
bundleInspector analyze ./dist --job-id mcp-example
bundleInspector-mcp
```

`--cache-dir`를 생략하면 CLI 기본값인 `~/.bundleInspector/cache`를 공유합니다. scan이 custom
또는 fallback cache를 사용했다면 그 **정확히 같은 cache root**를 서버에 전달해야 합니다.
경로가 다르면 서버가 다른 위치를 검색하지 않고 빈 job 목록을 반환합니다.

로컬 stdio 전용 서버는 읽기 전용 도구 `list_jobs`, `get_job_status`,
`get_report_page` 세 개를 공개합니다. report page는 `findings`, `assets`,
`correlations`, `clusters` 중 하나입니다. 또한 `application/json` MIME의
`bundleinspector://jobs/{job_id}` 상태 resource template을 제공합니다. 서버가 반환한 opaque
ID만 허용합니다. scan 시작·취소, report 쓰기, network 제어, raw artifact/config/snippet 반환은
지원하지 않습니다. standalone status는 live in-process queue가 아니라 persisted report에서
계산합니다.

내장 local principal 소유 job만 보이며 ownerless legacy cache entry는 자동 채택하지 않습니다.
read-only는 MCP capability를 뜻하며 filesystem 무쓰기를 뜻하지 않습니다. 최초 초기화 시
cache, `.public-view-key`, lock shard를 만들 수 있습니다.

이 transport에는 protocol 인증이 없으며 client가 실행하는 로컬 process 용도입니다. 별도 인증과
격리 없이 network bridge로 공개하면 안 됩니다. 공개 page가 field allowlist, revision-bound
pagination, 시크릿·URI redaction을 사용해도 cache는 OS 수준의 비공개 신뢰 경계입니다.
[MCP 운영 가이드](docs/USER_GUIDE.ko.md#mcp-서버)와
[저장소 계약](docs/CONFIG_REFERENCE.md#persistent-storage-and-mcp-contract)을 참고하세요.

## 현재 검증 상태

| 계약 | 현재 근거 |
|---|---|
| Runtime | Python 3.10-3.13, 현재 source 및 installed artifact 검사가 Windows/Linux에서 통과 |
| 탐지 | public corpus 45 case / 1,916 label, visible frozen governance 11 case / 2,193 label이 모두 19개 release gate를 통과했고 labeled FP/FN은 0 |
| Coverage | line + branch 결합 coverage 81.72%, 강제 gate 80% |
| MCP | 최종 wheel의 실제 stdio smoke가 Windows/Linux에서 3-tool read-only projection으로 통과 |
| 성능 | parser, regex, lexical recovery, correlator에 대해 deterministic 30-run p95/RSS/semantic 회귀 gate 고정 |

frozen governance set은 저장소에 공개되어 있고 같은 vendor family를 공유하므로 unseen/external
독립 표본이 아닙니다. 성능 snapshot도 수정 후 처음 고정한 current-reference baseline이므로
재현성과 향후 회귀 한계는 보여 주지만 **전후 속도 개선률을 증명하지 않습니다**.
[성능](docs/USER_GUIDE.ko.md#성능)과
[Frozen Detection Governance](docs/HELDOUT_GOVERNANCE.md)를 참고하세요.

## 🛡️ 안전이 먼저

BundleInspector는 DoS 도구가 아니라 정찰 도구이며, 기본값이 이를 반영합니다:

- **인터랙티브 클릭 기본 OFF.** 폼 제출·삭제를 유발할 수 있는 버튼/탭을 크롤러가 클릭하지 않습니다.
- **탐색 유발 상태변경 기본 차단.** route/click 탐색이 활성화된 동안 `POST`/`PUT`/`PATCH`/`DELETE`를 가로채어 **기록**한 뒤 **전송하지 않습니다**. 명시적으로 설정한 저수준 collector callback이 승인하면 예외입니다.
- **속도 제한 + 스코프.** 도메인별 레이트리밋(기본 `1 req/s`) + `429`/`5xx` 백오프, SSRF 방어, 엄격한 스코프 패턴.

초기 page-load 요청은 탐색 guard 대상이 아니며 method 기반 차단은 의미상 상태를 바꾸는 `GET`을
판별하지 못합니다. 설정으로 guard를 끄거나 저수준 callback으로 승인할 수도 있습니다. 가장 좁은
traffic surface가 필요하면 interactive clicking을 끄고 headless 수집을 비활성화한 profile을
사용하세요.

> **타겟이 처음이라면** **`ultra-safe`** 또는 **`conservative`** 프로파일로 시작하세요.
> 자세한 내용은 [트래픽 & 안전 가이드 »](docs/USER_GUIDE.ko.md#-트래픽--안전)

## 🎚️ 스캔 프로파일

[`examples/scan-profiles/`](examples/scan-profiles/) 의 프리셋은 커버리지와 트래픽을 절충합니다:

| 프로파일 | 크롤 | 헤드리스 | 트래픽 | 용도 |
|---|---|---|---|---|
| `ultra-safe` | 1 페이지 | off | 최저 | 규칙 불명, 첫 접촉 |
| `conservative` | 얕게 | off | 낮음 | 버그바운티 / 운영 트리아지 |
| `standard` | 중간 | on | 중간 | 인가된 진단 |
| `deep` | 넓게 | on + 라우트 | 높음 | SPA 위주 타겟 |
| `fast` | 얕게 | off | 낮음 | 로컬 normalization/source-map 작업 축소 |

```bash
bundleInspector scan https://target.example.com --config examples/scan-profiles/conservative.yml
```

## 🧭 명령어

| 명령 | 설명 |
|---|---|
| `scan <urls…>` | **라이브** 타겟 크롤 + 분석 |
| `analyze <paths…>` | 로컬 파일/디렉터리/글롭 분석 — **네트워크 없음** |
| `convert <report>` | 리포트를 JSON ⇄ HTML 로 변환 |
| `version` | 버전 출력 |

자주 쓰는 플래그: `--config`, `--rules-file`, `-s/--scope`, `-c/--cookie`,
`-H/--header`, `-o/--output`, `-f/--format {json,html,sarif}`, `-w/--wordlist`,
`--api-map`, `--no-headless`, `--job-id` / `--resume`, `--fail-on {심각도}`,
`--allow-private-ips`, `--chains`, `--first-party-only`.
전체 레퍼런스 → [사용설명서 CLI 섹션 »](docs/USER_GUIDE.ko.md#-cli-레퍼런스)

## 🔬 무엇을 찾나요

| 카테고리 | 예시 |
|---|---|
| **엔드포인트** | `fetch`/`axios`/XHR 호출, REST · `/graphql` · WebSocket URL, 템플릿·상수에서 해석 |
| **시크릿** | ~100종 키(AWS, GCP, Stripe, GitHub, Slack, JWT, 개인키) + 엔트로피 분석 |
| **도메인** | 내부/스테이징 호스트, `.internal`/`.local`, 사설 IP, S3/GCS/Azure 버킷 |
| **피처 플래그** | LaunchDarkly/Optimizely/Split 키워드, `isFeatureEnabled`, admin/debug 토글 |
| **디버그** | `/debug` `/admin` `/actuator`, 민감정보 `console.log`, `debugger`, dev 전용 분기 |
| **Sink & flow** | 동적 DOM/code/navigation sink와 confirmed/probable source-to-sink 경로 |
| **업로드** | FormData/multipart, JS로 만든 file input, client-only 파일 유형 검증 |
| **Route & runtime** | 복원된 client route, named chunk, dormant 및 runtime-only endpoint |

모든 발견은 **P0 → P3**(치명적 → 정보성) 위험 등급과 영향/가능성 점수를 가집니다. report는
`complete`, `partial`, `failed`, `cancelled` analysis completeness와 machine-readable
coverage-loss issue도 보존합니다.
[탐지 커버리지 가이드 »](docs/USER_GUIDE.ko.md#-탐지-커버리지)를 참고하세요.

## 📚 문서

- **[사용설명서](docs/USER_GUIDE.ko.md)** — 전체 CLI, 설정, 탐지, 안전 심층 설명, 성능
- **[설정 레퍼런스](docs/CONFIG_REFERENCE.md)** — 모든 설정 필드
- **[커스텀 룰](docs/CUSTOM_RULES.md)** — 나만의 regex / AST / semantic 룰 작성
- **[Frozen Detection Governance](docs/HELDOUT_GOVERNANCE.md)** — release gate 절차와 통계 한계
- **[구현 상태](docs/IMPLEMENTATION_CHECKLIST.md)** — 현재 기능, 검증, 명시적 제약

## ⚖️ 라이선스 & 고지

**MIT License** 로 배포됩니다 — [LICENSE](LICENSE) 참고.

> **본인이 소유했거나 명시적으로 테스트를 허가받은** 시스템만 스캔하세요. 타겟의 규칙·트래픽 제한·자동화 정책을 준수할 책임은 사용자에게 있습니다. 이 저장소의 테스트 픽스처에는 탐지·마스킹 검증을 위한 **가짜** 시크릿 문자열이 의도적으로 포함되어 있으며, 실제 자격증명이 아닙니다.
