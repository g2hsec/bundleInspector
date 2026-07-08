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


def build_chains(report: Any) -> list[dict]:
    """Group a Report's findings/correlations into attack chains (confirmed first)."""
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
            "severity": getattr(getattr(sink_f, "severity", None), "value", "medium"),
            "confidence": "medium",
            "sink": getattr(sink_f, "value_type", ""),
            "sink_line": sl,
            "sink_source": (getattr(sink_f, "metadata", None) or {}).get("sink_source", ""),
            "upload": getattr(up_f, "extracted_value", "") if up_f else "",
            "upload_line": _line(up_f) if up_f else 0,
            "reasoning": getattr(c, "reasoning", ""),
        })

    chains.sort(key=lambda ch: (0 if ch["kind"] == "confirmed" else 1,
                                _SEV_RANK.get(ch["severity"], 5), ch["file"], ch["sink_line"]))
    return chains


def render_chains(chains: list[dict]) -> str:
    """Render chains as plain text (no rich markup -- print with markup=False)."""
    if not chains:
        return ""
    confirmed = sum(1 for c in chains if c["kind"] == "confirmed")
    candidate = len(chains) - confirmed
    out: list[str] = ["", "=" * 74,
                      f"  ATTACK CHAINS  ({confirmed} confirmed, {candidate} candidate)", "=" * 74]
    for i, c in enumerate(chains, 1):
        fn = (c["file"].rsplit("/", 1)[-1] or c["file"])[:60]
        out.append("")
        if c["kind"] == "confirmed":
            out.append(f"[{i}] CONFIRMED dataflow XSS chain            {c['severity'].upper()}/{c['confidence']}")
            out.append(f"    file    : {fn}")
            out.append(f"    SOURCE  : {c['source_kind']}  @L{c['source_line']}")
            attr = f" ['{c['sink_attr']}' attr]" if c["sink_attr"] else ""
            out.append(f"    SINK    : {c['sink']}{attr}  @L{c['sink_line']}   (value: {c['sink_source']})")
            if c["flow_path"]:
                out.append(f"    FLOW    : {'  ->  '.join(str(s) for s in c['flow_path'])}")
            if c["indicator"]:
                out.append(f"    indicator: {c['indicator']} flagged at the same sink")
            for vt, val, ln in c["uploads"]:
                out.append(f"    +-> linked upload surface: {vt} `{val}` @L{ln}  (upload -> <img src> stored-XSS)")
            if c["endpoints"]:
                eps = ", ".join(str(e)[:38] for e in c["endpoints"][:4])
                extra = "" if len(c["endpoints"]) <= 4 else f" (+{len(c['endpoints']) - 4} more)"
                out.append(f"    context : same-file endpoints for replay: {eps}{extra}")
        else:
            out.append(f"[{i}] CANDIDATE chain (name-heuristic, UNCONFIRMED)   {c['severity'].upper()}")
            out.append(f"    file    : {fn}")
            out.append(f"    upload `{c['upload']}` @L{c['upload_line']}  <->  sink {c['sink']} @L{c['sink_line']}"
                       f"  (value: {c['sink_source']})")
            out.append(f"    note    : dataflow not proven -- verify manually")
    out.append("")
    return "\n".join(out)
