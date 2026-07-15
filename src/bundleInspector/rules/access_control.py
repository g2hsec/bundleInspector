"""
enh1: client-side access-control gating detection.

Flags endpoint findings whose HTTP/WebSocket call is reachable ONLY behind a browser-side
authorization check (if(user.isAdmin), flags.canX && fetch(...), if(!hasRole(...)) return;).
These are the classic bypass surface -- replay the request with a normal session. Purely
additive: it tags + raises severity of gated endpoints and never drops any finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from bundleInspector.storage.models import (
    Category,
    Finding,
    GuardCondition,
    IntermediateRepresentation,
    Severity,
)

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _subtokens(tokens: Iterable[object] | None) -> set[str]:
    subs: set[str] = set()
    for tok in tokens or []:
        for part in re.split(r"[._]|(?<=[a-z0-9])(?=[A-Z])", str(tok)):
            if part:
                subs.add(part.lower())
        subs.add(str(tok).lower())
    return subs


def classify_guard(tokens: Iterable[object] | None) -> str | None:
    """Classify a guard's tokens into an access-control kind, or None (FP gate)."""
    subs = _subtokens(tokens)
    if subs & {"entitlement", "entitlements", "hasentitlement", "isentitled"}:
        return "entitlement"
    if subs & {
        "permission",
        "permissions",
        "haspermission",
        "checkpermission",
        "perm",
        "perms",
        "acl",
        "grant",
        "grants",
    }:
        return "permission"
    if subs & {
        "admin",
        "isadmin",
        "hasadmin",
        "administrator",
        "superadmin",
        "sysadmin",
        "superuser",
        "issuperuser",
        "root",
    }:
        return "role"
    if subs & {"role", "roles", "hasrole", "checkrole", "inrole"}:
        return "role"
    if subs & {
        "authorize",
        "authorized",
        "authorization",
        "isauthorized",
        "hasauthorization",
        "access",
        "hasaccess",
        "checkaccess",
        "accesscontrol",
        "canaccess",
        "isallowed",
        "allowed",
    }:
        return "generic-authz"
    if subs & {"can", "cant"}:
        return "generic-authz"
    return None


def _slice_source(source: str, guard: GuardCondition) -> str:
    if not source or guard.test_start <= 0:
        return ""
    lines = source.split("\n")
    seg = lines[guard.test_start - 1 : (guard.test_end or guard.test_start)]
    return re.sub(r"\s+", " ", " ".join(s.strip() for s in seg)).strip()[:120]


def _line_start_offsets(source: str) -> list[int]:
    """Absolute char offset at which each 1-based line begins (index 0 => line 1)."""
    offsets = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _finding_offset(finding: Finding, line_starts: list[int]) -> int:
    """Absolute char offset of a finding's evidence anchor, or -1 if not derivable."""
    ev = getattr(finding, "evidence", None)
    if ev is None:
        return -1
    line = ev.line or 0
    if line <= 0 or line > len(line_starts):
        return -1
    col = ev.column or 0
    return line_starts[line - 1] + col


def _guard_has_offsets(guard: GuardCondition) -> bool:
    # Both bounds must be real. A guard with only an end offset (start == -1
    # sentinel) would otherwise gate everything from file start (off < -1 is
    # never true), mis-tagging endpoints that precede the guard.
    return (
        guard.guarded_end_off is not None
        and guard.guarded_end_off >= 0
        and guard.guarded_start_off is not None
        and guard.guarded_start_off >= 0
    )


def _guard_contains_offset(guard: GuardCondition, off: int) -> bool:
    """True if `off` lies in the guarded body but NOT inside the test expression."""
    if off < guard.guarded_start_off or off >= guard.guarded_end_off:
        return False
    if (
        guard.test_end_off is not None
        and guard.test_end_off >= 0
        and guard.test_start_off <= off < guard.test_end_off
    ):
        return False
    return True


def _guard_contains_line(guard: GuardCondition, line: int) -> bool:
    """Line-based fallback containment (used only when offsets are unavailable)."""
    if not (guard.guarded_start <= line <= guard.guarded_end):
        return False
    if guard.test_start <= line <= guard.test_end:
        return False
    return True


def _severity_from_str(name: str) -> Severity:
    try:
        return Severity(str(name).lower())
    except ValueError:
        return Severity.MEDIUM


def annotate_client_side_gating(
    findings: list[Finding],
    ir: IntermediateRepresentation | None,
    source_content: str = "",
    config: Any | None = None,
) -> None:
    """Tag + raise severity of endpoint findings sitting inside a client-side authz guard."""
    enabled = getattr(config, "client_side_gating_enabled", True) if config is not None else True
    if not enabled or ir is None or not getattr(ir, "guard_conditions", None):
        return

    guards = []
    for g in ir.guard_conditions:
        if g.guarded_start <= 0:
            continue
        kind = classify_guard(g.tokens)
        if kind is None:
            continue
        g.kind = kind
        guards.append(g)
    if not guards:
        return

    target = _severity_from_str(
        getattr(config, "client_side_gating_severity", "medium") if config is not None else "medium"
    )

    line_starts = _line_start_offsets(source_content or "")
    # Precompute each guard's source-expr ONCE (there are few guards). _slice_source splits the whole
    # source, and it was called per guarded finding -> O(guarded_findings x source_len), quadratic on a
    # single-line minified bundle with many endpoints inside one guard. Keyed by guard identity.
    guard_exprs = {
        id(g): (_slice_source(source_content, g) or " ".join(sorted(g.tokens))) for g in guards
    }

    for finding in findings:
        if finding.category != Category.ENDPOINT:
            continue
        if "client_side_gated_endpoint" in finding.tags:
            continue
        line = finding.evidence.line if finding.evidence else 0
        raw_sites = (finding.metadata or {}).get("call_sites") or [
            (line, finding.evidence.column if finding.evidence else 0)
        ]
        sites = [
            (int(site[0]), int(site[1]))
            for site in raw_sites
            if isinstance(site, (tuple, list)) and len(site) >= 2 and int(site[0]) > 0
        ]
        if not sites:
            continue
        candidates_by_site = []
        for site_line, site_column in sites:
            # Preserve the finding object while computing the precise callsite offset.
            off = (
                line_starts[site_line - 1] + site_column
                if 0 < site_line <= len(line_starts)
                else -1
            )
            candidates = []
            for g in guards:
                if _guard_has_offsets(g) and off >= 0:
                    if _guard_contains_offset(g, off):
                        candidates.append(g)
                elif _guard_contains_line(g, site_line):
                    candidates.append(g)
            candidates_by_site.append(candidates)
        # The merged endpoint is guard-only only when EVERY observed callsite is guarded.
        if not candidates_by_site or any(not candidates for candidates in candidates_by_site):
            continue
        candidates = [candidate for group in candidates_by_site for candidate in group]
        off = -1
        inner = min(
            candidates,
            key=lambda g: (
                (g.guarded_end_off - g.guarded_start_off)
                if (_guard_has_offsets(g) and off >= 0)
                else (g.guarded_end - g.guarded_start) * 10_000,
                g.guarded_start_off if _guard_has_offsets(g) else g.guarded_start,
            ),
        )
        guard_expr = guard_exprs[id(inner)]

        finding.tags.append("client_side_gated_endpoint")
        finding.tags.append("access-control")
        finding.metadata["client_side_gated"] = True
        finding.metadata["guard_kind"] = inner.kind
        finding.metadata["guard_expr"] = guard_expr
        finding.metadata["guard_source"] = inner.node_kind
        finding.metadata["guard_polarity"] = inner.polarity
        finding.metadata["guard_scope"] = inner.scope
        finding.metadata["guard_line"] = inner.test_start_line

        tgt = target
        conf = getattr(finding.confidence, "value", finding.confidence)
        if inner.kind in ("role", "permission", "entitlement") and str(conf).lower() == "high":
            tgt = Severity.HIGH
        if _SEVERITY_RANK.get(finding.severity, 0) < _SEVERITY_RANK.get(tgt, 2):
            finding.severity = tgt
