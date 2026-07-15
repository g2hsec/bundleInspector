"""Release documentation must describe executable runtime and governance contracts."""

import json
import re
from pathlib import Path

from bundleInspector.config import (
    AuthConfig,
    Config,
    CrawlerConfig,
    OutputConfig,
    ParserConfig,
    RuleConfig,
    ScopeConfig,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_MODELS = (
    Config,
    ScopeConfig,
    AuthConfig,
    CrawlerConfig,
    ParserConfig,
    RuleConfig,
    OutputConfig,
)
MCP_TOOLS = {"list_jobs", "get_job_status", "get_report_page"}
MCP_PAGE_KINDS = {"findings", "assets", "correlations", "clusters"}


def _read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def _read_bytes(relative: str) -> bytes:
    return (REPO_ROOT / relative).read_bytes()


def _squash(value: str) -> str:
    return " ".join(value.split())


def _between(document: str, start: str, end: str) -> str:
    assert start in document
    section = document.split(start, maxsplit=1)[1]
    assert end in section
    return section.split(end, maxsplit=1)[0]


def _window(document: str, marker: str, radius: int = 350) -> str:
    position = document.find(marker)
    assert position >= 0, marker
    return document[max(0, position - radius) : position + len(marker) + radius]


def _display_int(value: int) -> str:
    return f"{value:,}"


def _display_ms(value: float) -> str:
    return f"{value:,.3f}"


def test_en_ko_guides_match_parser_dependency_and_config_contracts() -> None:
    guides = (_read("docs/USER_GUIDE.md"), _read("docs/USER_GUIDE.ko.md"))
    for guide in guides:
        lowered = guide.casefold()
        for required in (
            "tree-sitter",
            "tree-sitter-javascript",
            "tree-sitter-typescript",
            "language_hint",
            "acorn",
            "esprima",
            "httpcore",
            "cryptography",
            "pyyaml",
            "build_call_graph",
            "analysis_worker_timeout",
            "applied_cross_hardware",
        ):
            assert required.casefold() in lowered, (required, guide[:80])
    forbidden = (
        "uses `esprima` by default",
        "기본 파서는 `esprima`",
        "no pyyaml needed",
        "pyyaml 불필요",
        "optional `cryptography`",
        "선택 패키지 `cryptography`",
        "not_applicable_cross_hardware",
    )
    combined = "\n".join(guides).casefold()
    assert not [phrase for phrase in forbidden if phrase.casefold() in combined]


def test_readme_alias_and_en_ko_docs_pin_the_mcp_contract() -> None:
    assert _read_bytes("README.md") == _read_bytes("README.en.md")

    english_readme = _squash(_read("README.en.md"))
    korean_readme = _squash(_read("README.ko.md"))
    for readme in (english_readme, korean_readme):
        for required in (
            "Python 3.10-3.13",
            "~/.bundleInspector/cache",
            "bundleinspector://jobs/{job_id}",
            "application/json",
            "opaque",
            *MCP_TOOLS,
            *MCP_PAGE_KINDS,
        ):
            assert required in readme
        assert "Python 3.10+" not in readme
    assert "three read-only tools" in english_readme
    assert "읽기 전용 도구" in korean_readme and "세 개" in korean_readme

    guide_specs = (
        (
            _read("docs/USER_GUIDE.md"),
            "## MCP Server",
            "## 🧭 CLI Reference",
            "exact same root",
            "no supported adoption command",
            "Transport is `stdio` only",
        ),
        (
            _read("docs/USER_GUIDE.ko.md"),
            "## MCP 서버",
            "## 🧭 CLI 레퍼런스",
            "정확히 같은 root",
            "지원되는 adoption command도 없습니다",
            "transport는 `stdio`만 지원",
        ),
    )
    for guide, start, end, cache_contract, owner_contract, transport_contract in guide_specs:
        section = _between(guide, start, end)
        normalized = _squash(section)
        folded = normalized.casefold()
        for required in (
            "~/.bundleInspector/cache",
            ".public-view-key",
            "built-in `local` principal",
            cache_contract,
            owner_contract,
            transport_contract,
        ):
            assert required.casefold() in folded

        documented_tools = set(
            re.findall(r"(?m)^\| `([a-z_]+)(?:\([^`]*\))?` \|", section)
        )
        assert documented_tools == MCP_TOOLS
        page_row = next(line for line in section.splitlines() if "`get_report_page(" in line)
        assert set(re.findall(r"`([a-z]+)`", page_row)) == MCP_PAGE_KINDS


def test_docs_reject_stale_mcp_parallel_and_browser_guard_guidance() -> None:
    paths = ["README.md", "README.en.md", "README.ko.md"]
    paths.extend(
        str(path.relative_to(REPO_ROOT)) for path in sorted((REPO_ROOT / "docs").glob("*.md"))
    )
    combined = "\n".join(_read(path) for path in paths)
    folded = combined.casefold()

    assert not re.search(
        r"(?im)^\s*bundleinspector-mcp --cache-dir \.bundleinspector\s*$",
        combined,
    )
    assert not re.search(
        r"(?i)bundleinspector_parallel=(?:auto|[2-9][0-9]*)\s+bundleinspector analyze",
        combined,
    )
    for forbidden in (
        "after the guard disarms",
        "guard is scoped to the exploration phase",
        "guard disarms after exploration",
        "가드 해제 후",
        "가드가 해제된 후",
        "탐색 단계에만 적용",
    ):
        assert forbidden.casefold() not in folded

    english_guide = _squash(_read("docs/USER_GUIDE.md"))
    korean_guide = _squash(_read("docs/USER_GUIDE.ko.md"))
    assert "Local `analyze` is currently serial and does not read this variable" in english_guide
    assert "guard remains armed for the rest of that page lifetime" in english_guide
    assert "workers are always blocked in the headless context" in english_guide
    assert "로컬 `analyze`는 현재 serial이며 이 변수를 읽지 않습니다" in korean_guide
    assert "page lifetime의 나머지 동안 유지됩니다" in korean_guide
    assert "service worker를 항상 차단합니다" in korean_guide
    assert "raw asset bytes require `include_raw_content`" not in english_guide
    assert "raw asset byte는 `include_raw_content`" not in korean_guide


def test_config_reference_covers_every_runtime_field_and_storage_contract() -> None:
    reference = _read("docs/CONFIG_REFERENCE.md")
    normalized_reference = _squash(reference)
    missing_fields = [
        f"{model.__name__}.{field_name}"
        for model in CONFIG_MODELS
        for field_name in model.model_fields
        if f"`{field_name}`" not in reference
    ]
    assert not missing_fields

    for required in (
        "Every config model rejects unknown fields",
        "PyYAML is the normal YAML backend",
        "All four IR extraction flags are active",
        "analysis_worker_timeout",
        "casefold()",
        "exactly 64 sibling",
        ".bundleinspector-lock-00",
        ".bundleinspector-lock-3f",
        "Legacy per-payload lock files are not removed automatically",
        "concurrently replace a writable ancestor",
        'python -m pip install -e ".[mcp]"',
        "Severity floor for gated endpoints",
        "asset analysis-input bytes",
    ):
        assert required in normalized_reference
    assert "does not apply the same CR/LF/NUL validator to the cookie map" not in reference
    auth_section = _between(reference, "## Auth", "## Crawler")
    for required in ("cookie", "CR", "LF", "NUL"):
        assert required in auth_section
    example = _read("examples/yaml-configs/default.yml")
    assert "Unknown or legacy fields are rejected" in example
    assert "analysis_worker_timeout: 30.0" in example
    assert "build_call_graph: true" in example


def test_custom_rule_docs_disclose_limits_and_reserved_noop_fields() -> None:
    custom_rules = _read("docs/CUSTOM_RULES.md")
    folded = custom_rules.casefold()
    assert "256" in custom_rules and "character" in folded
    assert "50,000" in custom_rules
    assert "50 ms" in folded or "0.05 second" in folded
    for disclosure in ("analysis_incomplete", "custom_rule_analysis_incomplete", "`partial`"):
        assert disclosure in custom_rules

    for marker in ("matcher.language", "evidence.snippet_from"):
        context = _window(custom_rules, marker).casefold()
        assert "reserved" in context
        assert any(
            wording in context
            for wording in (
                "no-op",
                "no runtime effect",
                "not currently enforced",
                "does not currently change",
                "currently ignored",
            )
        )


def test_en_ko_guides_pin_completeness_and_committed_benchmarks() -> None:
    guides = (_read("docs/USER_GUIDE.md"), _read("docs/USER_GUIDE.ko.md"))
    correlator = json.loads(_read("benchmarks/baselines/correlator.json"))
    detection = json.loads(_read("benchmarks/baselines/detection.json"))

    expected_measurements: set[str] = set()
    for scenario in correlator["scenarios"]:
        timings = scenario["timings_ms"]
        expected_measurements.update(
            {
                _display_int(scenario["modules"]),
                _display_int(scenario["findings"]),
                _display_int(scenario["edges"]),
                _display_int(scenario["peak_rss_bytes"]),
                _display_ms(timings["p50"]),
                _display_ms(timings["p95"]),
                *(_display_ms(value) for value in timings["p95_bootstrap_95_ci"]),
            }
        )
    for scenario in detection["scenarios"].values():
        timings = scenario["timings_ms"]
        expected_measurements.update(
            {
                _display_int(scenario["source_bytes"]),
                _display_int(scenario["peak_rss_bytes"]),
                _display_ms(timings["p50"]),
                _display_ms(timings["p95"]),
                *(_display_ms(value) for value in timings["p95_bootstrap_95_ci"]),
            }
        )

    for guide in guides:
        for required in (
            "Report.completeness.status",
            "`complete`",
            "`partial`",
            "`failed`",
            "`cancelled`",
            "source-map",
            "custom-rule",
            "worker timeout",
            "p95 +20%",
            "RSS +25%",
            "applied_cross_hardware_attribution_unavailable",
            "WSL2",
            "CPython 3.13.7",
            "AMD Ryzen 9 9950X",
            "end-to-end",
            "SLA",
            "peak RSS",
            "45",
            "1,916",
            "11",
            "2,193",
            "19",
            *expected_measurements,
        ):
            assert required in guide, required

    english = _squash(guides[0])
    korean = _squash(guides[1])
    assert "clean zero-finding result" in english
    assert "2 warmups and 30 measured runs per scenario" in english
    assert "No methodologically comparable pre-change baseline exists" in english
    assert "do **not** establish a speedup percentage" in english
    assert "not unseen external independent samples" in english
    assert "clean한 0-finding 결과" in korean
    assert "warmup 2회와 measured run 30회" in korean
    assert "속도 개선률을 증명하지 않습니다" in korean
    assert "unseen external independent sample이 아닙니다" in korean


def test_frozen_governance_doc_discloses_limits_and_exact_trigger_semantics() -> None:
    governance = _squash(_read("docs/HELDOUT_GOVERNANCE.md"))
    for required in (
        "frozen and independently partitioned",
        "It is not secret, unseen",
        "not group-aware or vendor-family-aware",
        "must not be presented as 11 independent vendor samples",
        "There is no URL/digest secret override",
        "Pull request | Always | No",
        "Push to `main` | Always | No",
        "Push of a `v*` tag | Always | Yes | Pre-publication governance run",
        "Weekly schedule (`17 3 * * 1`) | Always | Yes",
        "`release: published` | Always | Yes | Post-publication recheck only",
        "Manual dispatch, input false | Always | No",
        "Manual dispatch, `run_heldout_governance=true` | Always | Yes",
        "Publish a release only after that tag run passes",
        "cannot retroactively serve as the publication blocker",
        "scripts/build_heldout_governance_corpus.py",
        "scripts/update_detection_baseline.py",
        "scripts/update_heldout_governance_artifact.py --replace",
        "CI never updates these files automatically",
    ):
        assert required in governance
    corpus_readme = _squash(_read("tests/corpus/README.md"))
    assert "HELDOUT_GOVERNANCE.md" in corpus_readme
    assert "must not be described as an unseen statistical test set" in corpus_readme
