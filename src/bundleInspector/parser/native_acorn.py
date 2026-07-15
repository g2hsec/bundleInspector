"""
Optional native (acorn) parser backend.

This is an OPT-IN accelerator: it is used only when the environment variable
``BUNDLEINSPECTOR_NATIVE_PARSER`` is set to a truthy value AND Node.js + acorn are
available. It parses JavaScript with acorn (which emits the same ESTree shape esprima
does, but far faster and with full modern-syntax support) via a short-lived Node
subprocess and returns the AST as a plain dict.

Design guarantee: every failure path (env off, Node missing, acorn missing, parse
error, timeout, malformed output) returns ``None``, so the caller transparently falls
back to the existing esprima chain. The native path therefore can never *reduce*
detection relative to the default parser -- on files esprima can parse it produces an
equivalent AST (verified byte-identical on the detection-invariance corpus), and on
modern syntax that esprima can only regex-fallback it produces a *more* complete AST.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_SCRIPT = Path(__file__).with_name("acorn_parse.js")
_TIMEOUT_SECONDS = 30
_PROBE_TIMEOUT_SECONDS = 5

# Cached availability probe (None = not yet probed).
_available: bool | None = None
_availability_reason = "not_probed"
_node_executable: str | None = None


def native_parser_enabled() -> bool:
    """True when the opt-in env flag is set to a truthy value."""
    return os.environ.get("BUNDLEINSPECTOR_NATIVE_PARSER", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def native_parser_available() -> bool:
    """True only when the opt-in backend can actually resolve its Acorn dependency."""
    global _available, _availability_reason, _node_executable
    if not native_parser_enabled():
        _availability_reason = "disabled"
        return False
    if _available is not None:
        return _available

    if not _SCRIPT.is_file():
        _available = False
        _availability_reason = "sidecar_missing"
        return False
    _node_executable = shutil.which("node")
    if not _node_executable:
        _available = False
        _availability_reason = "node_missing"
        return False

    # The sidecar's existence does not prove `require("acorn")` can resolve. Probe using the
    # sidecar directory as the Node resolution root, matching how the real script is loaded.
    try:
        probe = subprocess.run(
            [
                _node_executable,
                "-e",
                "require.resolve('acorn', {paths: [process.argv[1]]})",
                str(_SCRIPT.parent),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        _available = False
        _availability_reason = f"probe_failed:{type(exc).__name__}"
        return False
    _available = probe.returncode == 0
    _availability_reason = "available" if _available else "acorn_unavailable"
    return _available


def native_parser_availability_reason() -> str:
    """Return a stable, non-secret reason for backend availability telemetry."""
    native_parser_available()
    return _availability_reason


def parse_source(source: str, *, temp_dir: Path | None = None) -> dict[str, Any] | None:
    """
    Parse ``source`` with acorn and return an ESTree dict, or None on any failure
    (caller must fall back to the default parser).
    """
    if not native_parser_available():
        return None

    tmp_path = None
    try:
        if temp_dir is not None:
            temp_dir.mkdir(parents=True, exist_ok=True)
        # newline="" preserves the source byte-for-byte (no "\n" -> "\r\n" translation on
        # Windows). This keeps acorn's absolute char offsets (node.range) aligned with the
        # in-memory `source` string that downstream consumers index into -- enh1's
        # access-control gating matches endpoint findings against guard `range` offsets, so
        # any newline-induced shift would misattribute guards.
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".js",
            encoding="utf-8",
            newline="",
            delete=False,
            dir=temp_dir,
        ) as tmp:
            # Capture the name BEFORE writing: with delete=False, a failing
            # write (e.g. disk full) would otherwise orphan the temp file
            # because `finally` cleanup keys off tmp_path.
            tmp_path = tmp.name
            tmp.write(source)

        proc = subprocess.run(
            [_node_executable or "node", str(_SCRIPT), tmp_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0 or not proc.stdout:
            return None
        ast = json.loads(proc.stdout)
        return ast if isinstance(ast, dict) else None
    except Exception:
        # Any failure (missing node/acorn, parse error, timeout, bad JSON) -> fall back.
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
