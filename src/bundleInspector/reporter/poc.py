"""
Render a replayable PoC (curl + fetch) from an endpoint's `request_contract` metadata (enh3).

Sensitive header/param values are already redacted at extraction time, so PoC output never
carries live credentials -- it emits placeholders (<REDACTED_*>, FUZZ, <string>) for the tester
to fill in.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

_SKELETON = {"string": "<string>", "number": 0, "boolean": False, "null": None,
             "array": [], "object": {}}


def _shell_q(s: Any) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


def _fuzz_url(url: str) -> str:
    return re.sub(r"\$\{[^}]*\}", "FUZZ", url or "")


def _skeleton(shape: dict) -> str:
    obj = {k: _SKELETON.get(t, "<value>") for k, t in (shape or {}).items() if k != "__truncated__"}
    return json.dumps(obj)


def build_curl(contract: dict) -> str:
    method = contract.get("method", "GET")
    parts = ["curl"]
    if method != "GET":
        parts += ["-X", method]
    headers = contract.get("headers") or {}
    for name, value in headers.items():
        parts += ["-H", _shell_q(f"{name}: {value}")]
    body = contract.get("body") or {}
    kind = body.get("kind")
    if kind == "json":
        if not any(k.lower() == "content-type" for k in headers):
            parts += ["-H", _shell_q("Content-Type: application/json")]
        parts += ["--data", _shell_q(_skeleton(body.get("shape") or {}))]
    elif kind == "urlencoded":
        pairs = "&".join(f"{k}=<{t}>" for k, t in (body.get("shape") or {}).items() if k != "__truncated__")
        parts += ["--data", _shell_q(pairs or body.get("raw_preview") or "")]
    elif kind == "form":
        for key in (body.get("shape") or {}):
            if key != "__truncated__":
                parts += ["-F", _shell_q(f"{key}=<value>")]
    elif kind == "raw":
        parts += ["--data", _shell_q(body.get("raw_preview") or "<body>")]
    parts += [_shell_q(_fuzz_url(contract.get("url", "")))]
    return " ".join(parts)


def build_fetch(contract: dict) -> str:
    method = contract.get("method", "GET")
    url = _fuzz_url(contract.get("url", ""))
    headers = contract.get("headers") or {}
    body = contract.get("body") or {}
    fields = []
    if method != "GET":
        fields.append(f'method: "{method}"')
    if headers:
        fields.append("headers: " + json.dumps(headers))
    if body.get("kind") == "json":
        fields.append(f"body: JSON.stringify({_skeleton(body.get('shape') or {})})")
    elif body.get("kind") in ("urlencoded", "raw") and body.get("raw_preview"):
        fields.append("body: " + json.dumps(body["raw_preview"]))
    if fields:
        return f'fetch("{url}", {{ {", ".join(fields)} }})'
    return f'fetch("{url}")'


def build_poc(contract: dict) -> dict:
    return {"curl": build_curl(contract), "fetch": build_fetch(contract)}


def iter_endpoint_contracts(report) -> Iterator:
    for finding in getattr(report, "findings", []):
        contract = (getattr(finding, "metadata", None) or {}).get("request_contract")
        if contract:
            yield finding, contract
