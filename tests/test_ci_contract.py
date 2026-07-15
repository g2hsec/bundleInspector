"""The repository quality gates must remain executable CI contracts."""

import ast
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "quality.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"
CONSTRAINTS = REPO_ROOT / "benchmarks" / "performance-constraints.txt"
PACKAGING_CONSTRAINTS = REPO_ROOT / "benchmarks" / "packaging-constraints.txt"


def _parse_exact_constraints(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        assert line.count("==") == 1
        name, pinned = line.split("==", 1)
        assert name not in parsed and name and pinned
        parsed[name] = pinned
    return parsed


def _literal_assignment(path: Path, name: str) -> object:
    module = ast.parse(path.read_text(encoding="utf-8"))
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in statement.targets):
            return ast.literal_eval(statement.value)
    raise AssertionError(f"missing literal assignment {name} in {path}")


def test_quality_workflow_enforces_every_release_gate() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    required_fragments = (
        "permissions:\n  contents: read",
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0",
        'python-version: ["3.10", "3.11", "3.12", "3.13"]',
        "windows-tests:\n    name: Windows filesystem and full regression suite",
        "runs-on: windows-latest",
        'python-version: "3.13"',
        "Run Windows full test suite",
        'python -m pip install --upgrade "pip==26.1.2"',
        'python -m pip install -c benchmarks/packaging-constraints.txt -e ".[dev,mcp]"',
        "python -m ruff check --no-cache src tests scripts",
        "python -m mypy --no-incremental src/bundleInspector",
        "python scripts/run_detection_metrics.py --corpus tests/corpus\n          --fail-on-regression",
        "--cov-fail-under=80",
        "python -m build",
        "Verify distribution metadata and exact contents",
        "python scripts/update_distribution_manifest.py --check",
        "python scripts/verify_distribution_contents.py",
        "--manifest packaging/distribution-manifest.json",
        'python -m twine check dist/*',
        'check-wheel-contents dist/*.whl',
        "Build and smoke-test the installed Windows wheel",
        'Scripts/bundleInspector.exe',
        'Scripts/bundleInspector-mcp.exe',
        '$wheelSpec = "$($wheel.FullName)[mcp]"',
        'bin/bundleInspector" version',
        'python" -m pip install "${wheel}[mcp]"',
        'MCP_ENTRYPOINT="$RUNNER_TEMP/bundleinspector-wheel/bin/bundleInspector-mcp"',
        "from mcp import ClientSession",
        "await client.initialize()",
        "await client.list_tools()",
        "await client.list_resource_templates()",
        "await client.read_resource(",
        'template.mimeType == "application/json"',
        'assert "wheel-job-1" not in encoded',
        'assert "wheel-report-1" not in encoded',
        'assert "WHEEL_PRIVATE_" not in encoded',
        'assert "wheel-job-1" not in stderr',
        'assert "wheel-report-1" not in stderr',
        'assert "WHEEL_PRIVATE_" not in stderr',
        "assert tree_hash(cache_path) == before",
        "await asyncio.wait_for(smoke(), timeout=30)",
        'python" -m playwright install --with-deps chromium',
        "await playwright.chromium.launch(headless=True)",
        'r.parser_used == "tree-sitter-tsx"',
        'schedule:\n    - cron: "17 3 * * 1"',
        'tags: ["v*"]',
        "release:\n    types: [published]",
        "heldout-governance:\n    name: Frozen held-out governance release gate",
        "Run committed frozen governance artifact",
        "run: python scripts/run_heldout_detection_gate.py run",
        "-c benchmarks/packaging-constraints.txt",
        "-c benchmarks/performance-constraints.txt",
        "BUNDLEINSPECTOR_BENCHMARK_ORIGIN: github-hosted",
        "python -m pip check",
        "--suite --runs 30 --warmups 2 --assert-gates",
        "--baseline benchmarks/baselines/correlator.json",
        "python scripts/benchmark_detection.py\n          --runs 30 --warmups 2 --assert-gates",
        "--baseline benchmarks/baselines/detection.json",
    )
    missing = [fragment for fragment in required_fragments if fragment not in content]
    assert not missing, f"quality workflow lost mandatory gates: {missing}"
    forbidden_fragments = (
        "DETECTION_HELDOUT_ARCHIVE_URL",
        "DETECTION_HELDOUT_ARCHIVE_SHA256",
        "HELDOUT_ARCHIVE_URL",
        "HELDOUT_ARCHIVE_SHA256",
        "secret-override",
        "import tarfile",
        "import zipfile",
        "pip install --upgrade pip",
    )
    present = [fragment for fragment in forbidden_fragments if fragment in content]
    assert not present, f"quality workflow retained forbidden release paths: {present}"
    assert "continue-on-error:" not in content
    assert "|| true" not in content


def test_quality_workflow_preserves_governance_runs_and_browser_dependencies() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["push"] == {"branches": ["main"], "tags": ["v*"]}
    concurrency = workflow["concurrency"]

    assert concurrency == {
        "group": "quality-${{ github.event_name }}-${{ github.ref }}",
        "cancel-in-progress": (
            "${{ github.event_name == 'push' || "
            "github.event_name == 'pull_request' }}"
        ),
    }
    wheel_smoke = next(
        step["run"]
        for step in workflow["jobs"]["quality"]["steps"]
        if step.get("name") == "Verify wheel in an isolated environment"
    )
    assert "python\" -m playwright install --with-deps chromium" in wheel_smoke
    assert "await playwright.chromium.launch(headless=True)" in wheel_smoke
    assert 'stderr_path.read_text(encoding="utf-8")' in wheel_smoke
    assert wheel_smoke.index("errlog.close()") < wheel_smoke.index("stderr_path.read_text")
    windows_wheel_smoke = next(
        step["run"]
        for step in workflow["jobs"]["windows-tests"]["steps"]
        if step.get("name") == "Build and smoke-test the installed Windows wheel"
    )
    assert "python -m build --wheel" in windows_wheel_smoke
    assert "Scripts/bundleInspector.exe" in windows_wheel_smoke
    assert "Scripts/bundleInspector-mcp.exe" in windows_wheel_smoke
    assert 'await client.list_resource_templates()' in windows_wheel_smoke
    assert 'await client.read_resource(' in windows_wheel_smoke
    assert 'stderr_path.read_text(encoding="utf-8")' in windows_wheel_smoke
    assert "asyncio.wait_for(smoke(), timeout=30)" in windows_wheel_smoke
    heldout_condition = workflow["jobs"]["heldout-governance"]["if"]
    assert "github.event_name == 'push'" in heldout_condition
    assert "startsWith(github.ref, 'refs/tags/v')" in heldout_condition
    assert "github.event_name == 'release'" in heldout_condition


def test_distribution_metadata_keeps_runtime_and_artifact_contracts() -> None:
    content = PYPROJECT.read_text(encoding="utf-8")

    required_fragments = (
        'requires-python = ">=3.10,<3.14"',
        '"Programming Language :: Python :: 3.10"',
        '"Programming Language :: Python :: 3.11"',
        '"Programming Language :: Python :: 3.12"',
        '"Programming Language :: Python :: 3.13"',
        'bundleInspector = "bundleInspector.cli:main"',
        'bundleInspector-mcp = "bundleInspector.mcp_server.server:main"',
        'mcp = [\n    "mcp>=1.28.1,<2"',
        '"PyYAML>=6.0,<7"',
        'requires = ["hatchling==1.31.0"]',
        '"build==1.5.0"',
        '"twine==6.2.0"',
        '"check-wheel-contents==0.6.3"',
        '[tool.hatch.build.targets.wheel]\npackages = ["src/bundleInspector"]',
        '[tool.hatch.build.targets.sdist]\ninclude = [',
        '    "/src",',
        '    "/tests",',
        '    "/scripts",',
        '    "/benchmarks",',
        '    "/packaging",',
    )
    missing = [fragment for fragment in required_fragments if fragment not in content]
    assert not missing, f"distribution metadata lost mandatory contracts: {missing}"
    assert (REPO_ROOT / "src" / "bundleInspector" / "py.typed").is_file()
    assert (REPO_ROOT / "src" / "bundleInspector" / "parser" / "acorn_parse.js").is_file()


def test_performance_constraints_match_benchmark_dependency_contracts() -> None:
    parsed = _parse_exact_constraints(CONSTRAINTS)

    detection = _literal_assignment(
        REPO_ROOT / "scripts" / "benchmark_detection.py",
        "DETECTION_DEPENDENCY_VERSIONS",
    )
    correlator = _literal_assignment(
        REPO_ROOT / "scripts" / "benchmark_correlator.py",
        "CORRELATOR_DEPENDENCY_NAMES",
    )
    assert isinstance(detection, dict)
    assert isinstance(correlator, tuple)
    assert parsed == detection
    assert set(correlator) <= set(parsed)


def test_packaging_constraints_pin_the_reviewed_release_toolchain() -> None:
    assert _parse_exact_constraints(PACKAGING_CONSTRAINTS) == {
        "pip": "26.1.2",
        "hatchling": "1.31.0",
        "build": "1.5.0",
        "twine": "6.2.0",
        "check-wheel-contents": "0.6.3",
    }
    rationale = PACKAGING_CONSTRAINTS.read_text(encoding="utf-8").casefold()
    assert "does not claim cross-os" in rationale
    assert "timestamp-stable bytes" in rationale
