"""Tests for the benchmark script interface."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_benchmark_script_rejects_zero_rounds_without_traceback():
    result = subprocess.run(
        [sys.executable, "scripts/benchmark_correlator.py", "--rounds", "0"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    combined = f"{result.stdout}\n{result.stderr}"
    assert result.returncode != 0
    assert "--rounds must be at least 1" in combined
    assert "Traceback" not in combined
