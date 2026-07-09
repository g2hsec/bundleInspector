"""
Attack-chain view: unify the three related XSS signals into one coherent chain per sink.

A DOM/stored-XSS finding is spread across three producers:
- a SINK indicator (`dom_html_sink` / `dom_attr_sink` / `dom_attr_injection` / `code_eval_sink`),
- a CONFIRMED dataflow finding (`taint_flow`) with the reconstructed source->...->sink path,
- an upload->sink TAINT correlation edge.

This module groups them into `chains` so a reviewer sees the whole path at once -- a CONFIRMED
chain (backed by a proven def-use flow) or a CANDIDATE chain (name-heuristic correlation only).
It is a pure presentation layer over an existing Report; it never changes detection.
"""

from __future__ import annotations

from typing import Any

_SINK_INDICATOR_TYPES = {"dom_html_sink", "dom_attr_sink", "dom_attr_injection", "code_eval_sink"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _file(f: Any) -> str:
    ev = getattr(f, "evidence", None)
    return (getattr(ev, "file_url", "") or "") if ev else ""


def _line(f: Any) -> int:
    ev = getattr(f, "evidence", None)
    return (getattr(ev, "line", 0) or 0) if ev else 0


def _cat(f: Any) -> str:
    c = getattr(f, "category", None)
    return getattr(c, "value", "") if c is not None else ""


def _vendor_of(url: str) -> Any:
    try:
        from bundleInspector.core.vendor import classify_vendor_file
        return classify_vendor_file(url)
    except Exception:
        return None


def build_chains(report: Any, first_party_only: bool = False) -> list[dict]:
    """Group a Report's findings/correlations into attack chains (confirmed first).
    Each chain is tagged with `third_party` (the library name, or None); when first_party_only
    is set, chains in third-party library files are omitted (they are noise, not app vulns)."""
    findings = list(getattr(report, "findings", []) or [])
    correlations = list(getattr(report, "correlations", []) or [])
    by_id = {getattr(f, "id", None): f for f in findings}
    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(_file(f), []).append(f)

    chains: list[dict] = []
    confirmed_sinks: set[tuple[str, int]] = set()

    # --- CONFIRMED chains: one per taint_flow finding ---
    for f in findings:
        if getattr(f, "value_type", "") != "taint_flow":
            continue
        md = getattr(f, "metadata", None) or {}
        fu = _file(f)
        sink_line = md.get("sink_line") or _line(f)
        confirmed_sinks.add((fu, sink_line))
        siblings = by_file.get(fu, [])
        indicator = next(
            (s for s in siblings
             if getattr(s, "value_type", "") in _SINK_INDICATOR_TYPES and _line(s) == sink_line),
            None,
        )
        uploads = [(getattr(s, "value_type", ""), getattr(s, "extracted_value", ""), _line(s))
                   for s in siblings if _cat(s) == "upload"]
        endpoints = [getattr(s, "extracted_value", "") for s in siblings if _cat(s) == "endpoint"]
        chains.append({
            "kind": "confirmed",
            "file": fu,
            "third_party": _vendor_of(fu),
            "severity": getattr(getattr(f, "severity", None), "value", "medium"),
            "confidence": getattr(getattr(f, "confidence", None), "value", "medium"),
            "source_kind": md.get("source_kind", ""),
            "source_line": md.get("source_line", 0),
            "sink": md.get("sink", ""),
            "sink_line": sink_line,
            "sink_attr": md.get("sink_attr", ""),
            "sink_source": md.get("sink_source", ""),
            "flow_path": list(md.get("flow_path", []) or []),
            "indicator": getattr(indicator, "value_type", None) if indicator else None,
            "uploads": uploads,
            "endpoints": endpoints,
        })

    # --- CANDIDATE chains: TAINT correlations not covered by a confirmed flow ---
    for c in correlations:
        et = getattr(getattr(c, "edge_type", None), "value", None)
        if et != "taint":
            continue
        src = by_id.get(getattr(c, "source_finding_id", None))
        tgt = by_id.get(getattr(c, "target_finding_id", None))
        if src is None or tgt is None:
            continue
        sink_f = tgt if _cat(tgt) == "sink" else (src if _cat(src) == "sink" else None)
        up_f = src if _cat(src) == "upload" else (tgt if _cat(tgt) == "upload" else None)
        if sink_f is None:
            continue
        fu, sl = _file(sink_f), _line(sink_f)
        if (fu, sl) in confirmed_sinks:
            continue  # a proven flow already covers this sink
        chains.append({
            "kind": "candidate",
            "file": fu,
            "third_party": _vendor_of(fu),
            "severity": getattr(getattr(sink_f, "severity", None), "value", "medium"),
            "confidence": "medium",
            "sink": getattr(sink_f, "value_type", ""),
            "sink_line": sl,
            "sink_source": (getattr(sink_f, "metadata", None) or {}).get("sink_source", ""),
            "upload": getattr(up_f, "extracted_value", "") if up_f else "",
            "upload_line": _line(up_f) if up_f else 0,
            "reasoning": getattr(c, "reasoning", ""),
        })

    if first_party_only:
        chains = [c for c in chains if not c.get("third_party")]
    # confirmed first; within that, first-party before third-party library files; then severity.
    chains.sort(key=lambda ch: (0 if ch["kind"] == "confirmed" else 1,
                                1 if ch.get("third_party") else 0,
                                _SEV_RANK.get(ch["severity"], 5), ch["file"], ch["sink_line"]))
    return chains


def _short_ep(ep: Any) -> str:
    """Trim an endpoint to its last path segment (drop `${...}/` prefixes) for a compact list."""
    s = str(ep).strip()
    return s.rsplit("/", 1)[-1] if "/" in s else s


def _row(label: str, value: str) -> str:
    """One aligned detail row inside a chain block."""
    return f"        {label:<9} {value}"


def render_chains(chains: list[dict]) -> str:
    """Render chains as plain text (no rich markup -- print with markup=False)."""
    if not chains:
        return ""
    confirmed = sum(1 for c in chains if c["kind"] == "confirmed")
    candidate = len(chains) - confirmed
    bar = "═" * 72
    out: list[str] = [
        "", bar,
        f"  ATTACK CHAINS  —  {confirmed} confirmed · {candidate} candidate", bar,
        "  ● confirmed (proven source→sink dataflow)   "
        "○ candidate (name-heuristic, verify manually)",
    ]
    for i, c in enumerate(chains, 1):
        fn = (c["file"].rsplit("/", 1)[-1] or c["file"])[:60]
        vendor = f"   [3p:{c['third_party']} · likely library noise]" if c.get("third_party") else ""
        out.append("")
        if c["kind"] == "confirmed":
            out.append(f"  ● [{i}] CONFIRMED  DOM/stored-XSS dataflow"
                       f"   —   {c['severity'].upper()} / {c['confidence']}{vendor}")
            out.append(_row("file", fn))
            out.append(_row("source", f"{c['source_kind']} @L{c['source_line']}"))
            attr = f" ['{c['sink_attr']}' attr]" if c["sink_attr"] else ""
            out.append(_row("sink", f"{c['sink']}{attr} @L{c['sink_line']}"
                                    f"   ←  tainted value: {c['sink_source']}"))
            out.append(_row("flow", f"{c['source_kind']} @L{c['source_line']}  →  "
                                    f"`{c['sink_source']}`  →  {c['sink']} @L{c['sink_line']}"))
            if c["indicator"]:
                out.append(_row("indicator", f"{c['indicator']} flagged at the same sink"))
            if c["uploads"]:
                vt = c["uploads"][0][0]
                val = c["uploads"][0][1]
                at = ", ".join(f"@L{ln}" for _, _, ln in c["uploads"])
                out.append(_row("upload", f"{vt} `{val}` {at}  → stored-XSS via <img src>"))
            if c["endpoints"]:
                eps = ", ".join(_short_ep(e) for e in c["endpoints"][:3])
                extra = "" if len(c["endpoints"]) <= 3 else f"  (+{len(c['endpoints']) - 3} more)"
                out.append(_row("replay", f"{eps}{extra}"))
        else:
            out.append(f"  ○ [{i}] CANDIDATE  name-heuristic, UNCONFIRMED"
                       f"   —   {c['severity'].upper()}{vendor}")
            out.append(_row("file", fn))
            out.append(_row("link", f"upload `{c['upload']}` @L{c['upload_line']}  ↔  "
                                    f"{c['sink']} @L{c['sink_line']}   (value: {c['sink_source']})"))
            out.append(_row("note", "dataflow not proven — verify manually"))
    out.append("")
    return "\n".join(out)
