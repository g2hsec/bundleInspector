"""
enh2: dormant / hidden endpoint detection.

Cross-references endpoints DECLARED in the JS bundle (static EndpointDetector findings)
against endpoints the running app ACTUALLY called during the headless crawl (network
capture). An endpoint present in the code but never exercised by normal UI flow is a
*dormant* / *hidden* endpoint -- classic bypass surface: the request can still be replayed
by hand (crafted AJAX) even though nothing in the rendered UI triggers it. Admin, internal,
debug and legacy routes commonly hide here.

Design guarantees:
  * PURELY ADDITIVE -- only tags + (for sensitive paths) raises severity; never drops a
    finding, never lowers severity.
  * FALSE-POSITIVE SAFE -- if there is no observation baseline (headless disabled, crawl
    captured nothing) it is a NO-OP, because "never observed" is meaningless without a
    crawl. Endpoints on hosts the crawl never contacted are left alone (could be a legit
    third-party API we simply did not trigger), not flagged as hidden.
  * ORCHESTRATOR-LEVEL / GATE-NEUTRAL -- runs after the rule engine using runtime data, so
    it does not perturb the static detection-invariance gate.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from bundleInspector.storage.models import Category, Severity

_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}

# Endpoint value_types that represent a replayable HTTP request (dormancy applies). GraphQL
# operations, WebSocket messages and client routes are handled by their own enhancements.
_HTTP_VALUE_TYPES = {"api_endpoint", "api_path", "url", "endpoint", "relative_url"}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXID_RE = re.compile(r"^[0-9a-f]{24,}$", re.I)
_NUMERIC_RE = re.compile(r"^\d+$")

# Paths whose exposure is inherently higher value when hidden from the UI.
_SENSITIVE_RE = re.compile(
    r"(admin|internal|debug|superuser|root|manage|console|priv|secret|"
    r"delete|remove|drop|purge|export|import|config|setting|token|key|"
    r"impersonat|sudo|backend|ops|dashboard)",
    re.I,
)


def _norm_segment(seg: str) -> str:
    if not seg:
        return seg
    if seg.startswith("$") or seg.startswith("{") or seg == "FUZZ":
        return "{id}"
    if _NUMERIC_RE.match(seg) or _UUID_RE.match(seg) or _HEXID_RE.match(seg):
        return "{id}"
    return seg


def _split(value: str) -> tuple[str, str]:
    """Return (host, normalized_path) for an endpoint value or observed URL; host='' if relative."""
    value = (value or "").strip()
    # Collapse template expressions so ${id} and {param} match a concrete observed id.
    value = re.sub(r"\$\{[^}]*\}", "/{id}/", value)
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        parts = urlsplit(value)
        host = parts.netloc.lower()
        path = parts.path or "/"
    elif value.startswith("//"):
        parts = urlsplit("https:" + value)
        host = parts.netloc.lower()
        path = parts.path or "/"
    else:
        host = ""
        path = value.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("/"):
            path = "/" + path
    norm = "/" + "/".join(_norm_segment(s) for s in path.split("/") if s)
    return host, norm


def build_observed_index(observed) -> dict:
    """
    Build a lookup index from raw observations.

    ``observed`` is an iterable of either ``url`` strings or ``(method, url)`` tuples
    (method is recorded but path-level matching is used -- a path the app fetched is not
    hidden regardless of verb).
    """
    hosts: set[str] = set()
    rel_paths: set[str] = set()
    host_paths: set[tuple[str, str]] = set()
    for item in observed or []:
        url = item[1] if isinstance(item, (tuple, list)) and len(item) >= 2 else item
        if not isinstance(url, str) or not url.strip():
            continue
        host, path = _split(url)
        if host:
            hosts.add(host)
            host_paths.add((host, path))
        # Every observed request also contributes a host-agnostic path (same-origin relative
        # declarations resolve against whatever host actually served them).
        rel_paths.add(path)
    return {"hosts": hosts, "rel_paths": rel_paths, "host_paths": host_paths}


def _is_exercised(host: str, path: str, index: dict) -> tuple[bool, bool]:
    """
    Returns (exercised, in_scope).

    * relative endpoint  -> in scope whenever any request was observed; exercised if the
      normalized path was requested against any host.
    * absolute endpoint  -> in scope only if its host was contacted at all (otherwise we have
      no baseline and must not guess); exercised if (host, path) was requested.
    """
    if not host:
        return (path in index["rel_paths"], True)
    if host not in index["hosts"]:
        return (True, False)  # no baseline for this host -> treat as "not hidden"
    return ((host, path) in index["host_paths"], True)


def annotate_dormant_endpoints(findings, observed, config=None) -> int:
    """
    Tag endpoint findings that were declared in JS but never called during the crawl.

    Returns the number of findings newly tagged as dormant. No-op (returns 0) when the
    feature is disabled or there is no observation baseline.
    """
    enabled = getattr(config, "dormant_endpoint_detection_enabled", True) if config is not None else True
    if not enabled or not findings:
        return 0
    index = build_observed_index(observed)
    if not index["rel_paths"] and not index["host_paths"]:
        return 0  # no crawl baseline -> cannot distinguish hidden from un-crawled

    tagged = 0
    for finding in findings:
        if finding.category != Category.ENDPOINT:
            continue
        if "dormant_endpoint" in finding.tags:
            continue
        md = finding.metadata or {}
        # Only replayable HTTP endpoints; skip graphql/ws/route surfaces (own enhancements).
        if md.get("transport") in ("graphql", "websocket") or md.get("operation_type"):
            continue
        if finding.value_type not in _HTTP_VALUE_TYPES:
            continue
        value = finding.extracted_value or ""
        if not value or value.startswith(("ws://", "wss://")):
            continue

        host, path = _split(value)
        if path in ("", "/"):
            continue
        exercised, in_scope = _is_exercised(host, path, index)
        if exercised or not in_scope:
            continue

        finding.tags.append("dormant_endpoint")
        if "hidden-candidate" not in finding.tags:
            finding.tags.append("hidden-candidate")
        finding.metadata["dormant"] = True
        finding.metadata["observed_at_runtime"] = False
        finding.metadata["dormancy_reason"] = "declared_in_js_never_called"
        tagged += 1

        # Sensitive hidden endpoints are the high-value bypass targets -> raise to at least
        # MEDIUM (never lower an already-higher severity, e.g. an enh1-gated HIGH).
        if _SENSITIVE_RE.search(path):
            finding.metadata["dormant_sensitive"] = True
            if _SEVERITY_RANK.get(finding.severity, 0) < _SEVERITY_RANK[Severity.MEDIUM]:
                finding.severity = Severity.MEDIUM

    return tagged
