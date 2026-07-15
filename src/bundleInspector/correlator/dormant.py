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
from collections.abc import Iterable
from typing import Any

from bundleInspector.core.url_utils import safe_urlsplit as urlsplit
from bundleInspector.storage.models import Category, Finding, Severity

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
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
    # Collapse a template expression to a NON-slash placeholder so it stays within its path segment.
    # A slash-wrapped `/{id}/` would split a PARTIAL-segment template (`${API_BASE}/x` -> `/{id}//x`,
    # or `v${version}` -> `v/{id}/`), keying the declared path differently from the concrete observed
    # one -- which falsely tagged a LIVE endpoint dormant AND re-surfaced it as a duplicate runtime
    # finding. `{id}` keeps the segment whole (matches api_map's `{param}`); a whole-segment
    # `/x/${id}` -> `/x/{id}` still matches a concrete id.
    value = re.sub(r"\$\{[^}]{0,1024}\}", "{id}", value)
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


def build_observed_index(
    observed: Iterable[Any] | None,
    primary_hosts: Iterable[str] | None = None,
) -> dict[str, Any]:
    """
    Build a lookup index from raw observations.

    ``observed`` is an iterable of either ``url`` strings or ``(method, url)`` tuples
    (method is recorded but path-level matching is used -- a path the app fetched is not
    hidden regardless of verb).

    ``primary_hosts`` (optional) is the set of first-party origin hosts. When given, only
    requests to those hosts (or host-less/relative observations) contribute to the
    host-agnostic ``rel_paths`` set, so a relative declared endpoint is not falsely marked
    exercised just because an unrelated third-party host hit the same path. When omitted,
    every observed path contributes (backward-compatible, host-agnostic).
    """
    primary = {h.lower() for h in primary_hosts} if primary_hosts else None
    hosts: set[str] = set()
    rel_paths: set[str] = set()
    host_paths: set[tuple[str, str]] = set()
    # DQ-H01: method-aware sets so an observed GET does not mark a declared DELETE on the same path
    # exercised. A verbless observation (bare-string, method unknown) can be any verb, so it credits
    # every method (kept separately and OR'd in).
    rel_method_paths: set[tuple[str, str]] = set()  # (METHOD, path)
    host_method_paths: set[tuple[str, str, str]] = set()  # (host, METHOD, path)
    verbless_rel_paths: set[str] = set()
    verbless_host_paths: set[tuple[str, str]] = set()
    for item in observed or []:
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            method = str(item[0]).upper() if item[0] else ""
            url = item[1]
        else:
            method = ""
            url = item
        if not isinstance(url, str) or not url.strip():
            continue
        host, path = _split(url)
        first_party = primary is None or not host or host in primary
        if host:
            hosts.add(host)
            host_paths.add((host, path))
            if method:
                host_method_paths.add((host, method, path))
            else:
                verbless_host_paths.add((host, path))
        # A relative declaration resolves against the app's own origin, so only credit
        # the host-agnostic path when the request was first-party (or host-less).
        if first_party:
            rel_paths.add(path)
            if method:
                rel_method_paths.add((method, path))
            else:
                verbless_rel_paths.add(path)
    return {
        "hosts": hosts,
        "rel_paths": rel_paths,
        "host_paths": host_paths,
        "rel_method_paths": rel_method_paths,
        "host_method_paths": host_method_paths,
        "verbless_rel_paths": verbless_rel_paths,
        "verbless_host_paths": verbless_host_paths,
    }


def _is_exercised(
    host: str,
    path: str,
    index: dict[str, Any],
    method: str = "",
) -> tuple[bool, bool]:
    """
    Returns (exercised, in_scope).

    * relative endpoint  -> in scope whenever any request was observed; exercised if the
      normalized path was requested against any host.
    * absolute endpoint  -> in scope only if its host was contacted at all (otherwise we have
      no baseline and must not guess); exercised if (host, path) was requested.

    DQ-H01: when the declared endpoint carries a CONFIDENT HTTP verb, exercised requires the SAME verb
    was observed (or a verbless observation, whose method is unknown). Only a NON-GET verb is
    confident: EndpointDetector defaults an unresolvable verb to 'GET', so a declared 'GET' may
    actually be POST/PUT/DELETE at runtime -- matching it method-exact would falsely mark a live
    endpoint dormant, so 'GET' (and a verbless declaration) fall back to path-only matching.
    """
    confident = method if method and method != "GET" else ""
    if not host:
        if not confident:
            return (path in index["rel_paths"], True)
        exercised = (confident, path) in index["rel_method_paths"] or path in index[
            "verbless_rel_paths"
        ]
        return (exercised, True)
    if host not in index["hosts"]:
        return (True, False)  # no baseline for this host -> treat as "not hidden"
    if not confident:
        return ((host, path) in index["host_paths"], True)
    exercised = (host, confident, path) in index["host_method_paths"] or (host, path) in index[
        "verbless_host_paths"
    ]
    return (exercised, True)


def annotate_dormant_endpoints(
    findings: list[Finding],
    observed: Iterable[Any] | None,
    config: Any | None = None,
    primary_hosts: Iterable[str] | None = None,
) -> int:
    """
    Tag endpoint findings that were declared in JS but never called during the crawl.

    Returns the number of findings newly tagged as dormant. No-op (returns 0) when the
    feature is disabled or there is no observation baseline. ``primary_hosts`` (the app's
    first-party origins) scopes relative-path matching -- see ``build_observed_index``.
    """
    enabled = (
        getattr(config, "dormant_endpoint_detection_enabled", True) if config is not None else True
    )
    if not enabled or not findings:
        return 0
    index = build_observed_index(observed, primary_hosts=primary_hosts)
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
        # DQ-H01: match on the declared HTTP verb when known, so a runtime GET does not clear a
        # declared DELETE on the same path.
        method = str(md.get("method") or "").upper()
        exercised, in_scope = _is_exercised(host, path, index, method)
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
