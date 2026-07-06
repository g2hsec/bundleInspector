"""enh7: runtime endpoint surfacing.

The complement of dormant detection ([[dormant]]): endpoints the running app ACTUALLY
called at runtime (xhr/fetch/WebSocket, captured by the headless collector) but that the
static EndpointDetector never found -- typically because the URL was assembled dynamically
in a way static evaluation can't resolve. These are real, reachable endpoints that would
otherwise be missed entirely, so we surface them as first-class findings.

Design guarantees:
  * PURELY ADDITIVE -- only appends new findings; never modifies or drops existing ones.
  * FALSE-POSITIVE SAFE -- scoped to first-party origins (third-party/analytics/CDN calls
    are ignored) and de-duplicated against the static endpoint findings, so it never
    re-reports something already found.
  * SCAN-ONLY / GATE-NEUTRAL -- with no runtime observations (local `analyze`, or the
    static detection-invariance gate) it is a NO-OP, so it cannot perturb static detection.
"""

from __future__ import annotations

from bundleInspector.correlator.dormant import _SENSITIVE_RE, _split
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)


def surface_runtime_endpoints(
    findings,
    observed,
    observed_websockets=None,
    config=None,
    primary_hosts=None,
) -> int:
    """Append endpoint findings for first-party HTTP/WS URLs observed at runtime that are
    not already present as static endpoint findings.

    Returns the number of findings added. No-op (returns 0) when disabled or when there is
    no runtime observation baseline.
    """
    enabled = (
        getattr(config, "runtime_endpoint_surfacing_enabled", True)
        if config is not None else True
    )
    if not enabled:
        return 0
    if not observed and not observed_websockets:
        return 0

    primary = {h.lower() for h in primary_hosts} if primary_hosts else None

    # Normalized paths already covered by static endpoint findings, so we never duplicate.
    known_paths: set[str] = set()
    for f in findings:
        if f.category == Category.ENDPOINT and f.extracted_value:
            try:
                known_paths.add(_split(f.extracted_value)[1])
            except Exception:
                continue

    def _in_scope(host: str) -> bool:
        # Relative (host-less) or first-party only; when no primary set is known, keep the
        # relative ones and skip absolute third-party hosts to stay FP-safe.
        if not host:
            return True
        if primary is None:
            return False
        return host in primary

    added = 0
    seen_new: set[str] = set()

    def _emit(url: str, method: str, transport: str) -> None:
        nonlocal added
        try:
            host, path = _split(url)
        except Exception:
            return
        if path in ("", "/") or not _in_scope(host):
            return
        if path in known_paths or path in seen_new:
            return
        seen_new.add(path)

        sensitive = bool(_SENSITIVE_RE.search(path))
        severity = Severity.MEDIUM if sensitive else Severity.LOW
        label = "WebSocket" if transport == "websocket" else method
        findings.append(Finding(
            rule_id="runtime_observed_endpoint",
            category=Category.ENDPOINT,
            severity=severity,
            confidence=Confidence.HIGH,  # we literally observed the call happen
            title=f"Runtime-observed endpoint: {label} {path}",
            description=(
                "Endpoint the running application called at runtime but which static "
                "analysis did not surface (likely a dynamically-assembled URL). Reachable "
                "and replayable by hand."
            ),
            evidence=Evidence(file_url=url, file_hash="", line=0),
            extracted_value=url,
            value_type="websocket_url" if transport == "websocket" else "api_endpoint",
            tags=["runtime-observed", "dynamically-discovered"],
            metadata={
                "observed_at_runtime": True,
                "method": method,
                "transport": transport,
                "runtime_sensitive": sensitive,
                "is_first_party": True,
            },
        ))
        added += 1

    for item in observed or []:
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            method, url = str(item[0] or "GET").upper(), item[1]
        else:
            method, url = "GET", item
        if isinstance(url, str) and url.strip():
            _emit(url, method, "http")

    for url in observed_websockets or []:
        if isinstance(url, str) and url.strip():
            _emit(url, "WS", "websocket")

    return added
