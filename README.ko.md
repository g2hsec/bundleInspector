<div align="center">

# 🔎 BundleInspector

### 자바스크립트 속에 숨은 공격 표면을 드러냅니다.

정적 **+** 동적 분석으로 자바스크립트 번들에서 숨겨진 API 엔드포인트, 하드코딩된 시크릿,
내부 도메인, 클라이언트 사이드 우회 지점을 뽑아내는 보안 스캐너 —
모의해커, 버그바운티 헌터, AppSec 엔지니어를 위한 도구입니다.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-brightgreen.svg)](#)
[![Headless: Playwright](https://img.shields.io/badge/headless-Playwright-2ea44f.svg)](https://playwright.dev/)
[![Output: SARIF](https://img.shields.io/badge/output-JSON%20%C2%B7%20HTML%20%C2%B7%20SARIF-orange.svg)](#-무엇을-찾나요)

[English](README.md) · **한국어** · [📖 사용설명서](docs/USER_GUIDE.ko.md)

</div>

---

## ✨ 핵심 기능

- **두 가지 모드** — 라이브 사이트를 `scan`(크롤 → 렌더 → 다운로드 → 분석)하거나, 로컬 번들을 **네트워크 트래픽 없이** `analyze`.
- **깊이 있는 정적 추출** — 숨겨진 REST / GraphQL / WebSocket 엔드포인트, ~100종의 시크릿, 내부·스테이징 도메인, 피처 플래그, 디버그 엔드포인트를 템플릿 리터럴·문자열 결합·삼항식·상수까지 따라가며 해석.
- **공격 정찰 기능 내장** — 7가지 고도화: 클라이언트 사이드 접근제어 게이팅, **휴면/은닉 엔드포인트**, 재현 가능한 curl/fetch PoC, IDOR + HTTP 메서드-플립 힌트, SPA 라우트 맵 전체 복원, GraphQL/WebSocket 표면, **런타임 관측 엔드포인트**(정적으론 못 찾았지만 실행 중 호출됨).
- **기본이 안전** — 크롤러가 유발하는 상태변경 요청(`POST`/`PUT`/`DELETE`)은 **차단·확인하며 전송하지 않음**. 도메인별 레이트리밋 + 적응형 백오프, SSRF·스코프 가드, 시크릿 마스킹.
- **빠름** — 파일 단위 멀티프로세싱, 선택적 네이티브(acorn) 파서, 콘텐츠 해시 중복 제거, 재개 가능한 체크포인트.
- **워크플로에 맞는 리포트** — JSON, 단일 파일 HTML 리포트, **SARIF**(GitHub Code Scanning) — 여기에 퍼징 워드리스트와 복원된 API 맵까지.

## 🚀 설치

**Python 3.10+** 필요. 헤드리스 스캔에는 Playwright Chromium 바이너리가 필요합니다.

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
pip install -e .
playwright install chromium
```

> **PowerShell에는 `&&`·`source`가 없습니다** — 각 줄을 따로 실행하세요. `Activate.ps1`이 차단되면("스크립트 실행이 사용 안 함") 세션에서 한 번 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` 를 먼저 실행하세요.

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

## 🛡️ 안전이 먼저

BundleInspector는 DoS 도구가 아니라 정찰 도구이며, 기본값이 이를 반영합니다:

- **인터랙티브 클릭 기본 OFF.** 폼 제출·삭제를 유발할 수 있는 버튼/탭을 크롤러가 클릭하지 않습니다.
- **상태변경 요청 기본 차단.** 크롤이 유발한 `POST`/`PUT`/`PATCH`/`DELETE`는 가로채어 **기록**(엔드포인트는 여전히 발견됨)한 뒤 **전송하지 않습니다** — 확인 핸들러가 승인한 경우에만 진행.
- **속도 제한 + 스코프.** 도메인별 레이트리밋(기본 `1 req/s`) + `429`/`5xx` 백오프, SSRF 방어, 엄격한 스코프 패턴.

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
| `fast` | 얕게 | off | 낮음 | 정밀도보다 속도(beautify off) |

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

자주 쓰는 플래그: `-s/--scope`, `-c/--cookie`, `-H/--header`, `-o/--output`, `-f/--format {json,html,sarif}`, `-w/--wordlist`, `--api-map`, `--no-headless`, `--job-id` / `--resume`, `--fail-on {심각도}`.
전체 레퍼런스 → [사용설명서 CLI 섹션 »](docs/USER_GUIDE.ko.md#-cli-레퍼런스)

## 🔬 무엇을 찾나요

| 카테고리 | 예시 |
|---|---|
| **엔드포인트** | `fetch`/`axios`/XHR 호출, REST · `/graphql` · WebSocket URL, 템플릿·상수에서 해석 |
| **시크릿** | ~100종 키(AWS, GCP, Stripe, GitHub, Slack, JWT, 개인키) + 엔트로피 분석 |
| **도메인** | 내부/스테이징 호스트, `.internal`/`.local`, 사설 IP, S3/GCS/Azure 버킷 |
| **피처 플래그** | LaunchDarkly/Optimizely/Split 키워드, `isFeatureEnabled`, admin/debug 토글 |
| **디버그** | `/debug` `/admin` `/actuator`, 민감정보 `console.log`, `debugger`, dev 전용 분기 |

모든 발견은 **P0 → P3**(치명적 → 정보성) 위험 등급 + 영향/가능성 점수가 매겨지고, 7가지 정찰 고도화로 보강됩니다 — [탐지 커버리지 가이드 »](docs/USER_GUIDE.ko.md#-탐지-커버리지) 참고.

## 📚 문서

- **[사용설명서](docs/USER_GUIDE.ko.md)** — 전체 CLI, 설정, 탐지, 안전 심층 설명, 성능
- **[설정 레퍼런스](docs/CONFIG_REFERENCE.md)** — 모든 설정 필드
- **[커스텀 룰](docs/CUSTOM_RULES.md)** — 나만의 regex / AST / semantic 룰 작성

## ⚖️ 라이선스 & 고지

**MIT License** 로 배포됩니다 — [LICENSE](LICENSE) 참고.

> **본인이 소유했거나 명시적으로 테스트를 허가받은** 시스템만 스캔하세요. 타겟의 규칙·트래픽 제한·자동화 정책을 준수할 책임은 사용자에게 있습니다. 이 저장소의 테스트 픽스처에는 탐지·마스킹 검증을 위한 **가짜** 시크릿 문자열이 의도적으로 포함되어 있으며, 실제 자격증명이 아닙니다.
