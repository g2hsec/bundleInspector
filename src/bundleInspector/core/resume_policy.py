"""
Resume compatibility helpers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from bundleInspector.config import Config
from bundleInspector.storage.models import CompletenessStatus, PipelineCheckpoint, Report

RESUME_SIGNATURE_KEY = "_resume_signature"
RESUME_SIGNATURE_SCHEMA = 3

_ENGINE_FINGERPRINT_PATHS = (
    "parser",
    "rules",
    "correlator",
    "classifier",
    "collector",
    "normalizer",
    "core",
    "storage/models.py",
    "cli.py",
)


def _canonicalize_resume_payload(value: Any) -> Any:
    """Return a JSON-stable structure for signature hashing."""
    if isinstance(value, dict):
        return {
            str(key): _canonicalize_resume_payload(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_canonicalize_resume_payload(item) for item in value]
    return value


def _hash_resume_payload(payload: dict[str, Any]) -> str:
    normalized = _canonicalize_resume_payload(payload)
    return hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _custom_rules_fingerprint(config: Config) -> str | None:
    """Content fingerprint of the custom rules referenced by config, so an IN-PLACE edit of a rule
    file (path unchanged) invalidates a stored checkpoint/report on --resume -- config records only
    the PATH, so without this an edited ruleset would silently reuse a stale report. Covers a single
    file, a directory of rules, and a meta-pack file with a sibling `rules/` dir. Returns None when
    no custom rules are set; a sentinel when the path is missing/unreadable (signature still changes)."""
    path = getattr(config.rules, "custom_rules_file", None)
    if not path:
        return None
    p = Path(path)
    exts = (".json", ".yml", ".yaml")
    try:
        if p.is_dir():
            targets = sorted((f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in exts),
                             key=lambda f: str(f).lower())
        elif p.is_file():
            targets = [p]
            sibling = p.parent / "rules"  # meta-pack: the rules live in a sibling dir
            if sibling.is_dir():
                targets += sorted((f for f in sibling.rglob("*")
                                   if f.is_file() and f.suffix.lower() in exts),
                                  key=lambda f: str(f).lower())
        else:
            return "missing"
        h = hashlib.sha256()
        for f in targets:
            h.update(f.name.encode("utf-8") + b"\0" + f.read_bytes() + b"\0")
        return h.hexdigest()
    except OSError:
        return "unreadable"


def _analysis_engine_fingerprint() -> str:
    """Fingerprint shipped parser/rule/analysis code so upgrades cannot reuse stale results.

    Package versions are not sufficient during editable installs and downstream rebuilds. Hashing
    the analysis-bearing modules makes the resume contract change whenever their behavior can
    change, without including CLI/report-only files that do not affect findings.
    """
    package_root = Path(__file__).resolve().parents[1]
    targets: list[Path] = []
    try:
        for relative in _ENGINE_FINGERPRINT_PATHS:
            path = package_root / relative
            if path.is_dir():
                targets.extend(sorted(path.rglob("*.py"), key=lambda item: item.as_posix()))
            elif path.is_file():
                targets.append(path)
        digest = hashlib.sha256()
        for path in sorted(set(targets), key=lambda item: item.as_posix()):
            digest.update(path.relative_to(package_root).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()
    except OSError:
        # Fail closed: an unreadable installation never matches a previously readable one.
        return "unreadable-engine"


def build_remote_resume_signature(config: Config) -> str:
    """Build a resume signature for remote scans."""
    config_dict = config.to_dict()
    payload = {
        "schema": RESUME_SIGNATURE_SCHEMA,
        "mode": "remote_scan",
        "config": {
            "scope": config_dict.get("scope", {}),
            "auth": config_dict.get("auth", {}),
            "crawler": config_dict.get("crawler", {}),
            "parser": config_dict.get("parser", {}),
            "rules": config_dict.get("rules", {}),
        },
        "analysis_engine_fingerprint": _analysis_engine_fingerprint(),
        "custom_rules_fingerprint": _custom_rules_fingerprint(config),
    }
    return _hash_resume_payload(payload)


def _local_input_inventory(
    input_paths: list[str] | None,
    *,
    recursive: bool,
    include_json: bool,
) -> dict[str, str]:
    """Content inventory of the local inputs a run would analyze, keyed by resolved path with a
    `sha256:size:mtime_ns` value each. A CHANGE to any input file (content edit, size, mtime, or an
    added/removed file inside a scanned directory) yields a different signature and forces
    re-analysis instead of returning a stale report (DQ-C05). Mirrors the LocalCollector selection
    (JS/source-map/optional-json extensions, recursive dir walk, glob expansion). Missing/unreadable
    inputs get a stable sentinel so their disappearance also changes the signature."""
    from bundleInspector.collector.local import LocalCollector

    exts = {
        extension.lower()
        for extension in (*LocalCollector.JS_EXTENSIONS, *LocalCollector.COMPONENT_EXTENSIONS)
    }
    exts.add(".map")  # source maps are collected by default
    if include_json:
        exts.add(".json")

    inventory: dict[str, str] = {}

    def _record(fp: Path) -> None:
        try:
            if not fp.is_file() or fp.suffix.lower() not in exts:
                return
            st = fp.stat()
            digest = hashlib.sha256(fp.read_bytes()).hexdigest()
            key = str(fp.resolve()).replace("\\", "/")
            inventory[key] = f"{digest}:{st.st_size}:{st.st_mtime_ns}"
        except OSError:
            inventory[str(fp).replace("\\", "/")] = "unreadable"

    for raw in input_paths or []:
        p = Path(raw)
        try:
            if p.is_file():
                _record(p)
            elif p.is_dir():
                for fp in p.glob("**/*" if recursive else "*"):
                    _record(fp)
            elif "*" in str(raw):
                s = str(raw)
                prefix = s.split("*")[0]
                sep = max(prefix.rfind("/"), prefix.rfind("\\"))
                base = Path(prefix[:sep] or s[0]) if sep >= 0 else Path(".")
                pattern = s[sep + 1:] if sep >= 0 else s
                if base.exists():
                    for fp in base.glob(pattern):
                        _record(fp)
            else:
                inventory[str(raw).replace("\\", "/")] = "missing"
        except OSError:
            inventory[str(raw).replace("\\", "/")] = "unreadable"

    return dict(sorted(inventory.items()))


def build_local_resume_signature(
    config: Config,
    *,
    recursive: bool,
    include_json: bool,
    input_paths: list[str] | None = None,
) -> str:
    """Build a resume signature for local analysis.

    When `input_paths` is provided, a content inventory of the analyzed files is folded into the
    signature so an in-place edit of an input file invalidates the stored report (DQ-C05). When it
    is None (unit callers), the payload is unchanged so existing signatures stay byte-stable."""
    config_dict = config.to_dict()
    input_payload: dict[str, Any] = {
        "recursive": recursive,
        "include_json": include_json,
    }
    if input_paths is not None:
        input_payload["inventory"] = _local_input_inventory(
            input_paths, recursive=recursive, include_json=include_json
        )
    payload = {
        "schema": RESUME_SIGNATURE_SCHEMA,
        "mode": "local_analysis",
        "config": {
            "crawler": {
                "max_file_size": config_dict.get("crawler", {}).get("max_file_size"),
            },
            "parser": config_dict.get("parser", {}),
            "rules": config_dict.get("rules", {}),
        },
        "input": input_payload,
        "analysis_engine_fingerprint": _analysis_engine_fingerprint(),
        "custom_rules_fingerprint": _custom_rules_fingerprint(config),
    }
    return _hash_resume_payload(payload)


def embed_report_resume_signature(report_config: dict[str, Any], signature: str) -> dict[str, Any]:
    """Embed the current resume signature into stored report config."""
    config = dict(report_config)
    config[RESUME_SIGNATURE_KEY] = signature
    return config


def build_stage_state_with_resume_signature(
    stage_state: dict[str, Any] | None,
    signature: str,
) -> dict[str, Any]:
    """Embed the current resume signature into checkpoint stage state."""
    state = dict(stage_state or {})
    state[RESUME_SIGNATURE_KEY] = signature
    return state


def report_matches_resume_signature(
    report: Report | None,
    *,
    expected_job_id: str,
    seed_urls: list[str],
    expected_signature: str,
) -> bool:
    """Return True only for a compatible, terminally complete stored report."""
    if (
        report is None
        or report.job_id != expected_job_id
        or report.seed_urls != seed_urls
    ):
        return False
    if report.config.get(RESUME_SIGNATURE_KEY) != expected_signature:
        return False
    completeness = getattr(report, "completeness", None)
    return (
        completeness is None
        or (
            completeness.status == CompletenessStatus.COMPLETE
            and not completeness.issues
        )
    )


def checkpoint_matches_resume_signature(
    checkpoint: PipelineCheckpoint | None,
    *,
    expected_job_id: str,
    seed_urls: list[str],
    expected_signature: str,
) -> bool:
    """Return True when a stored checkpoint is compatible with the current run."""
    if (
        checkpoint is None
        or checkpoint.job_id != expected_job_id
        or checkpoint.seed_urls != seed_urls
    ):
        return False
    return checkpoint.stage_state.get(RESUME_SIGNATURE_KEY) == expected_signature
