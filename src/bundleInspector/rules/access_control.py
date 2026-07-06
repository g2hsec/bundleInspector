"""
enh1: client-side access-control gating detection.

Flags endpoint findings whose HTTP/WebSocket call is reachable ONLY behind a browser-side
authorization check (if(user.isAdmin), flags.canX && fetch(...), if(!hasRole(...)) return;).
These are the classic bypass surface -- replay the request with a normal session. Purely
additive: it tags + raises severity of gated endpoints and never drops any finding.
"""

from __future__ import annotations

import re
from typing import Optional

from bundleInspector.storage.models import Category, Severity

_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}


def _subtokens(tokens) -> set:
    subs = set()
    for tok in tokens or []:
        for part in re.split(r"[._]|(?<=[a-z0-9])(?=[A-Z])", str(tok)):
            if part:
                subs.add(part.lower())
        subs.add(str(tok).lower())
    return subs


def classify_guard(tokens) -> Optional[str]:
    """Classify a guard's tokens into an access-control kind, or None (FP gate)."""
    subs = _subtokens(tokens)
    if any("entitlement" in s for s in subs):
        return "entitlement"
    if any("permission" in s or s in ("perm", "perms", "acl", "grant", "grants") for s in subs):
        return "permission"
    if any("admin" in s or s in ("superuser", "issuperuser", "root") for s in subs):
        return "role"
    if any(s in ("role", "roles", "hasrole") for s in subs):
        return "role"
    if any("feature" in s for s in subs):
        return "feature"
    if any(s in ("flag", "flags", "toggle") for s in subs):
        return "flag"
    if any("authoriz" in s or s in ("isallowed", "allowed", "canaccess") for s in subs):
        return "generic-authz"
    if any(s in ("can", "cant") for s in subs):
        return "generic-authz"
    return None


def _slice_source(source: str, guard) -> str:
    if not source or guard.test_start <= 0:
        return ""
    lines = source.split("\n")
    seg = lines[guard.test_start - 1: (guard.test_end or guard.test_start)]
    return re.sub(r"\s+", " ", " ".join(s.strip() for s in seg)).strip()[:120]


def _line_start_offsets(source: str) -> list:
    """Absolute char offset at which each 1-based line begins (index 0 => line 1)."""
    offsets = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _finding_offset(finding, line_starts: list) -> int:
    """Absolute char offset of a finding's evidence anchor, or -1 if not derivable."""
    ev = getattr(finding, "evidence", None)
    if ev is None:
        return -1
    line = ev.line or 0
    if line <= 0 or line > len(line_starts):
        return -1
    col = ev.column or 0
    return line_starts[line - 1] + col


def _guard_has_offsets(guard) -> bool:
    return guard.guarded_end_off is not None and guard.guarded_end_off >= 0


def _guard_contains_offset(guard, off: int) -> bool:
    """True if `off` lies in the guarded body but NOT inside the test expression."""
    if off < guard.guarded_start_off or off >= guard.guarded_end_off:
        return False
    if (guard.test_end_off is not None and guard.test_end_off >= 0
            and guard.test_start_off <= off < guard.test_end_off):
        return False
    return True


def _guard_contains_line(guard, line: int) -> bool:
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


def annotate_client_side_gating(findings, ir, source_content: str = "", config=None) -> None:
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

    target = _severity_from_str(getattr(config, "client_side_gating_severity", "medium") if config is not None else "medium")

    line_starts = _line_start_offsets(source_content or "")

    for finding in findings:
        if finding.category != Category.ENDPOINT:
            continue
        if "client_side_gated_endpoint" in finding.tags:
            continue
        line = finding.evidence.line if finding.evidence else 0
        if line <= 0:
            continue
        off = _finding_offset(finding, line_starts)
        # Prefer precise absolute-offset containment (correct even for minified single-line
        # bundles, where line ranges collapse); fall back to line ranges when a parser
        # omits `range` metadata.
        candidates = []
        for g in guards:
            if _guard_has_offsets(g) and off >= 0:
                if _guard_contains_offset(g, off):
                    candidates.append(g)
            elif _guard_contains_line(g, line):
                candidates.append(g)
        if not candidates:
            continue
        inner = min(
            candidates,
            key=lambda g: (
                (g.guarded_end_off - g.guarded_start_off)
                if (_guard_has_offsets(g) and off >= 0)
                else (g.guarded_end - g.guarded_start) * 10_000,
                g.guarded_start_off if _guard_has_offsets(g) else g.guarded_start,
            ),
        )
        guard_expr = _slice_source(source_content, inner) or " ".join(sorted(inner.tokens))

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
