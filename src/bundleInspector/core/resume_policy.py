"""
Resume compatibility helpers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from bundleInspector.config import Config
from bundleInspector.storage.models import PipelineCheckpoint, Report


RESUME_SIGNATURE_KEY = "_resume_signature"
RESUME_SIGNATURE_SCHEMA = 1


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
    }
    return _hash_resume_payload(payload)


def build_local_resume_signature(
    config: Config,
    *,
    recursive: bool,
    include_json: bool,
) -> str:
    """Build a resume signature for local analysis."""
    config_dict = config.to_dict()
    payload = {
        "schema": RESUME_SIGNATURE_SCHEMA,
        "mode": "local_analysis",
        "config": {
            "parser": config_dict.get("parser", {}),
            "rules": config_dict.get("rules", {}),
        },
        "input": {
            "recursive": recursive,
            "include_json": include_json,
        },
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
    seed_urls: list[str],
    expected_signature: str,
) -> bool:
    """Return True when a stored report is compatible with the current run."""
    if report is None or report.seed_urls != seed_urls:
        return False
    return report.config.get(RESUME_SIGNATURE_KEY) == expected_signature


def checkpoint_matches_resume_signature(
    checkpoint: PipelineCheckpoint | None,
    *,
    seed_urls: list[str],
    expected_signature: str,
) -> bool:
    """Return True when a stored checkpoint is compatible with the current run."""
    if checkpoint is None or checkpoint.seed_urls != seed_urls:
        return False
    return checkpoint.stage_state.get(RESUME_SIGNATURE_KEY) == expected_signature
