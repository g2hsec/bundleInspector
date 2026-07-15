"""Canonical, fail-closed redaction used by persistence, reporters, and public views."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel

from bundleInspector.core.security import mask_sensitive_value
from bundleInspector.storage.models import Category, Finding, PipelineCheckpoint, Report

REDACTED = "***redacted***"
_SENSITIVE_KEY = re.compile(
    r"(?:auth|authorization|cookie|credential|password|passwd|secret|session|token|api[-_]?key|"
    r"private[-_]?key|client[-_]?secret|signature|storage_state|localstorage|sessionstorage)",
    re.IGNORECASE,
)
_SAFE_RESPONSE_HEADERS = {
    "cache-control",
    "content-length",
    "content-type",
    "etag",
    "last-modified",
}
_TOKEN_PATTERNS = (
    re.compile(
        r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+(?=$|[\s'\"<>,;)])",
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
)


def _valid_unicode(value: str) -> str:
    """Return UTF-8-serializable text without throwing on unpaired surrogate code points."""
    return value.encode("utf-8", "replace").decode("utf-8")


def sanitize_uri(value: str, *, public: bool = False) -> str:
    """Remove userinfo, fragment, and query values from an HTTP(S) URI."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[invalid-uri]" if public else value
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        if public:
            fingerprint = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
            return f"[local-resource:{fingerprint}]"
        return value
    host = parsed.hostname.lower()
    if public:
        for pattern in _TOKEN_PATTERNS:
            host = pattern.sub(REDACTED, host)
        normalized_host = _public_hostname(host)
        if normalized_host is None:
            return "[invalid-uri]"
        host = normalized_host
    try:
        port = parsed.port
    except ValueError:
        return "[invalid-uri]" if public else value
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc_host = f"[{host}]" if ":" in host else host
    netloc = (
        netloc_host
        if not port or port == default_port
        else f"{netloc_host}:{port}"
    )
    if public:
        query = ""
    else:
        query = urlencode([
            (key.encode("utf-8", "replace").decode("utf-8"), REDACTED)
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ])
    path = parsed.path or ("/" if public else "")
    if public and path not in {"", "/"}:
        path_fingerprint = hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:16]
        path = f"/[resource:{path_fingerprint}]"
    return _valid_unicode(urlunsplit((parsed.scheme.lower(), netloc, path, query, "")))


def _public_hostname(host: str) -> str | None:
    """Canonicalize a public host while rejecting encoded or malformed host material."""
    if not host or "%" in host or any(ord(character) < 33 for character in host):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not ascii_host or len(ascii_host) > 253:
            return None
        labels = ascii_host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ):
            return None
        return ascii_host
    return address.compressed.lower()


def redact_text(
    value: str,
    replacements: Iterable[tuple[str, str]] = (),
    *,
    public: bool = False,
    max_length: int | None = None,
) -> str:
    """Redact exact discovered secrets, common credential forms, and embedded URL values."""
    result = value.replace("\x00", "")
    for raw, masked in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if raw:
            result = result.replace(raw, masked)
    result = _valid_unicode(result)
    for pattern in _TOKEN_PATTERNS:
        result = pattern.sub(REDACTED, result)

    # Sanitize standalone URLs and URLs embedded in prose/snippets.
    if re.match(r"(?i)^https?://", result):
        result = sanitize_uri(result, public=public)
    else:
        result = re.sub(
            r"(?i)https?://[^\s'\"<>]+",
            lambda match: sanitize_uri(match.group(0), public=public),
            result,
        )
    if max_length is not None and len(result) > max_length:
        result = result[:max_length] + "..."
    return result


def _secret_replacements(
    findings: Iterable[Finding],
    visible_chars: int,
    *,
    honor_existing_mask: bool,
) -> list[tuple[str, str]]:
    replacements: list[tuple[str, str]] = []
    for finding in findings:
        if finding.category != Category.SECRET or not finding.extracted_value:
            continue
        raw = finding.extracted_value
        existing = finding.masked_value
        masked = (
            existing
            if honor_existing_mask and existing and existing != raw and raw not in existing
            else mask_sensitive_value(
                raw,
                visible_start=visible_chars,
                visible_end=visible_chars,
            )
        )
        if raw != masked:
            replacements.append((raw, masked))
    return replacements


def _restore_explicit_masks(
    finding_data: dict[str, Any],
    replacements: Iterable[tuple[str, str]],
    *,
    visible_chars: int,
) -> None:
    """Use detector-provided masked metadata instead of replacing it with a generic marker."""
    metadata = finding_data.get("metadata")
    if not isinstance(metadata, dict):
        return
    extracted = metadata.get("extracted_fields")
    masked = metadata.get("masked_fields")
    if not isinstance(extracted, dict) or not isinstance(masked, dict):
        return
    for key, masked_value in masked.items():
        if key in extracted and isinstance(masked_value, str):
            if visible_chars <= 0:
                masked_value = "*" * len(masked_value)
                masked[key] = masked_value
            extracted[key] = redact_text(masked_value, replacements)


def redact_tree(
    value: Any,
    replacements: Iterable[tuple[str, str]] = (),
    *,
    public: bool = False,
    key_path: tuple[str, ...] = (),
    max_depth: int = 12,
) -> Any:
    """Return a redacted deep copy of a JSON/Pydantic-compatible tree."""
    if max_depth < 0:
        return REDACTED
    if isinstance(value, str):
        return redact_text(value, replacements, public=public)
    if isinstance(value, bytes):
        if public:
            return b""
        try:
            return redact_text(value.decode("utf-8"), replacements).encode("utf-8")
        except UnicodeDecodeError:
            result = value
            for raw, masked in replacements:
                if raw:
                    result = result.replace(raw.encode("utf-8"), masked.encode("utf-8"))
            return result
    if isinstance(value, BaseModel):
        data = value.model_dump(mode="python")
        redacted = redact_tree(
            data,
            replacements,
            public=public,
            key_path=key_path,
            max_depth=max_depth - 1,
        )
        return type(value).model_validate(redacted)
    if isinstance(value, dict):
        output: dict[Any, Any] = {}
        parent = key_path[-1].lower() if key_path else ""
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            path = (*key_path, key_text)
            if (
                lowered == "_resume_signature"
                and isinstance(item, str)
                and re.fullmatch(r"[0-9a-f]{64}", item)
            ):
                output[key] = item
                continue
            if parent == "masked_fields" and isinstance(item, str):
                output[key] = redact_text(item, replacements, public=public)
                continue
            if _SENSITIVE_KEY.search(lowered):
                if item is None or isinstance(item, (bool, int, float)):
                    output[key] = item
                elif isinstance(item, str):
                    sanitized = redact_text(item, replacements, public=public)
                    output[key] = sanitized if sanitized != item else REDACTED
                else:
                    output[key] = REDACTED
                continue
            if parent == "headers" and lowered not in _SAFE_RESPONSE_HEADERS:
                output[key] = REDACTED
                continue
            output[key] = redact_tree(
                item,
                replacements,
                public=public,
                key_path=path,
                max_depth=max_depth - 1,
            )
        return output
    if isinstance(value, list):
        return [
            redact_tree(
                item,
                replacements,
                public=public,
                key_path=key_path,
                max_depth=max_depth - 1,
            )
            for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            redact_tree(
                item,
                replacements,
                public=public,
                key_path=key_path,
                max_depth=max_depth - 1,
            )
            for item in value
        )
    return copy.deepcopy(value)


def sanitize_finding_copy(
    finding: Finding,
    *,
    visible_chars: int = 4,
    honor_existing_mask: bool = True,
) -> Finding:
    replacements = _secret_replacements(
        [finding],
        visible_chars,
        honor_existing_mask=honor_existing_mask,
    )
    data = redact_tree(finding.model_dump(mode="python"), replacements)
    _restore_explicit_masks(data, replacements, visible_chars=visible_chars)
    if finding.category == Category.SECRET:
        raw = finding.extracted_value
        masked = next((masked for candidate, masked in replacements if candidate == raw), REDACTED)
        data["extracted_value"] = masked
        data["masked_value"] = masked
    return Finding.model_validate(data)


def sanitize_report_copy(
    report: Report,
    *,
    visible_chars: int = 4,
    public: bool = False,
    include_raw_assets: bool = False,
    honor_existing_mask: bool = True,
) -> Report:
    replacements = _secret_replacements(
        report.findings,
        visible_chars,
        honor_existing_mask=honor_existing_mask,
    )
    data = redact_tree(report.model_dump(mode="python"), replacements, public=public)
    for finding in data.get("findings", []):
        _restore_explicit_masks(finding, replacements, visible_chars=visible_chars)
        if finding.get("category") == Category.SECRET.value:
            raw = next(
                (
                    original.extracted_value
                    for original in report.findings
                    if original.id == finding.get("id") and original.category == Category.SECRET
                ),
                "",
            )
            masked = next((masked for candidate, masked in replacements if candidate == raw), REDACTED)
            finding["extracted_value"] = masked
            finding["masked_value"] = masked
    if not include_raw_assets:
        for asset in data.get("assets", []):
            asset["content"] = b""
            asset["sourcemap_content"] = None
    return Report.model_validate(data)


def sanitize_checkpoint_copy(
    checkpoint: PipelineCheckpoint,
    *,
    visible_chars: int = 4,
    honor_existing_mask: bool = True,
) -> PipelineCheckpoint:
    replacements = _secret_replacements(
        checkpoint.findings,
        visible_chars,
        honor_existing_mask=honor_existing_mask,
    )
    data = redact_tree(checkpoint.model_dump(mode="python"), replacements)
    for finding in data.get("findings", []):
        _restore_explicit_masks(finding, replacements, visible_chars=visible_chars)
        if finding.get("category") == Category.SECRET.value:
            raw = next(
                (
                    original.extracted_value
                    for original in checkpoint.findings
                    if original.id == finding.get("id") and original.category == Category.SECRET
                ),
                "",
            )
            masked = next((masked for candidate, masked in replacements if candidate == raw), REDACTED)
            finding["extracted_value"] = masked
            finding["masked_value"] = masked
    return PipelineCheckpoint.model_validate(data)
