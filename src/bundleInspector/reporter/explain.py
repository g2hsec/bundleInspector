"""Human-readable 'why is this a risk' + source->sink flow + highlighted code snippet.

Pure presentation over a Finding, used by the HTML reporter to make each result legible at a glance:
- explain_finding()  -> {why, impact, fix} plain-language risk explanation (keyed by value_type,
                        category fallback) so the reader sees WHY it was flagged, not just a label.
- flow_steps()       -> structured SOURCE -> tainted value -> SINK steps for a taint_flow, so the
                        connection between the code and the finding is explicit.
- highlight_snippet()-> the code snippet with real line numbers, the offending line marked, and the
                        matched token(s) wrapped in <mark> -- so the snippet visibly ties to the finding.

Everything is defensive: rendering a report must never raise on odd/missing data.
"""

from __future__ import annotations

import html as _html
import re
from typing import Any, Dict, List, Optional

from bundleInspector.storage.models import Finding

# value_type -> (why, impact, fix). Most specific; falls back to _CATEGORY_EXPLAIN by category.
_EXPLAIN: Dict[str, tuple[str, str, str]] = {
    # --- sinks / dataflow (XSS) ---
    "taint_flow": (
        "An attacker-influenceable value reaches a dangerous DOM sink WITHOUT being encoded or sanitized "
        "-- this is a proven source->sink dataflow, not just a pattern match.",
        "If the value carries HTML/JS it executes in the victim's browser (DOM / stored XSS): session "
        "theft, account takeover, or UI spoofing.",
        "HTML-encode or sanitize before the sink -- use .text()/textContent instead of .html()/innerHTML, "
        "or run the value through a sanitizer such as DOMPurify.",
    ),
    "dom_html_sink": (
        "Dynamic data is written into the page as raw HTML (innerHTML / .html() / document.write).",
        "If any part of that data is attacker-controlled it becomes DOM XSS.",
        "Prefer textContent/.text(); if HTML is required, sanitize with DOMPurify first.",
    ),
    "dom_attr_sink": (
        "Dynamic data is written into a DOM attribute (e.g. src/href) that can execute or redirect.",
        "A `javascript:` URL or attacker-controlled src can run script or exfiltrate data.",
        "Validate the scheme/host (allow only http/https), or set the attribute from a fixed allow-list.",
    ),
    "dom_attr_injection": (
        "An attribute value is built from dynamic data and injected into the DOM.",
        "Attribute-break-out or a dangerous scheme can lead to XSS or open redirect.",
        "Encode the value for the attribute context and restrict allowed schemes.",
    ),
    "code_eval_sink": (
        "Dynamic data flows into a code-execution sink (eval / new Function / setTimeout(string)).",
        "Attacker-controlled input executes as JavaScript -- full client-side compromise.",
        "Remove eval/Function-on-strings; use a parser or a fixed dispatch table instead.",
    ),
    "alert_call": (
        "A debug/PoC alert() call was left in the shipped bundle.",
        "Low direct risk, but often marks unfinished code or a former XSS test point.",
        "Remove before release.",
    ),
    # --- upload ---
    "client_side_file_validation": (
        "File-type / extension checks are enforced only in client-side JavaScript.",
        "An attacker bypasses the JS and uploads any file type; if the server trusts the client, this "
        "enables malicious-file or web-shell upload.",
        "Re-validate type, extension AND content server-side -- never trust client checks.",
    ),
    # --- secrets ---
    "potential_secret": (
        "A credential-shaped value (key/token) is hard-coded in client-side JavaScript.",
        "Anyone who views the bundle obtains the secret -- it is effectively public.",
        "Move the secret server-side, rotate the exposed value, and scope it to least privilege.",
    ),
    "private_key": (
        "A private key appears in client-side JavaScript.",
        "Full compromise of whatever the key protects (signing, decryption, auth).",
        "Rotate the key immediately and keep private keys server-side only.",
    ),
    # --- endpoints (attack surface, not a vuln by itself) ---
    "api_path": (
        "A server API path was discovered in the bundle.",
        "Not a vulnerability by itself -- it maps attack surface (auth/IDOR/injection to test next).",
        "Confirm the endpoint enforces authz and input validation server-side.",
    ),
    "api_endpoint": (
        "A full API endpoint URL was discovered in the bundle.",
        "Attack surface for the next testing stage (authz, IDOR, injection).",
        "Verify server-side authorization and validation on this endpoint.",
    ),
    "graphql_operation": (
        "A GraphQL operation/field was discovered in the bundle.",
        "Reveals the GraphQL schema surface -- test for authz gaps and introspection.",
        "Enforce field-level authorization and disable introspection in production.",
    ),
    "websocket_url": (
        "A WebSocket endpoint was discovered in the bundle.",
        "Real-time surface -- test origin checks and message authorization.",
        "Validate Origin and authorize every message server-side.",
    ),
}

# Coarser fallback by category name (finding.category.value).
_CATEGORY_EXPLAIN: Dict[str, tuple[str, str, str]] = {
    "sink": (
        "Dynamic data flows into a potentially dangerous browser sink.",
        "Depending on the source, this can lead to XSS or client-side code execution.",
        "Sanitize/encode the data for its sink context before use.",
    ),
    "upload": (
        "A client-side file-upload control/validation surface was found.",
        "Client checks are bypassable -- server-side validation is what matters.",
        "Enforce type/size/content validation server-side.",
    ),
    "secret": (
        "A sensitive credential-shaped value was found in client code.",
        "Client-side secrets are readable by anyone -- treat as exposed.",
        "Move server-side and rotate the value.",
    ),
    "endpoint": (
        "A server endpoint/route was discovered in the bundle.",
        "Attack surface for the next stage; not a vulnerability on its own.",
        "Confirm server-side authorization and input validation.",
    ),
    "route": (
        "A client-side route was discovered.",
        "Maps the app's navigable surface (incl. possibly privileged views).",
        "Ensure sensitive routes are gated by server-side authz, not just hidden.",
    ),
    "flag": (
        "A feature flag / gating check was found in client code.",
        "Client-side flags can be flipped by the user to reveal hidden/privileged behavior.",
        "Enforce the gated capability server-side, not only via the flag.",
    ),
    "debug": (
        "Debug/diagnostic code was left in the shipped bundle.",
        "May leak internal state or logic and signals unfinished hardening.",
        "Strip debug logging/statements from production builds.",
    ),
    "domain": (
        "An external domain/host reference was found.",
        "Maps third-party/data-flow surface and possible SSRF/exfil destinations.",
        "Confirm the domain is expected and trusted.",
    ),
}

_GENERIC = (
    "This pattern was flagged by a detection rule.",
    "Review in context to judge exploitability.",
    "Validate and, if confirmed, remediate at the server or sanitize the input.",
)

# Friendly labels for taint source kinds.
_SOURCE_LABEL = {
    "filereader": "Uploaded file (FileReader)",
    "ajax_response": "Server response (AJAX/fetch)",
    "server_response": "Server response",
    "dom_input": "DOM input field",
    "location": "URL / location",
    "url": "URL / location",
    "postmessage": "postMessage data",
    "storage": "localStorage / cookie",
}


def explain_finding(finding: Finding) -> Dict[str, str]:
    """Return {why, impact, fix} plain-language risk explanation for a finding."""
    try:
        vt = getattr(finding, "value_type", "") or ""
        cat = getattr(getattr(finding, "category", None), "value", "") or ""
        why, impact, fix = _EXPLAIN.get(vt) or _CATEGORY_EXPLAIN.get(cat) or _GENERIC
        return {"why": why, "impact": impact, "fix": fix}
    except Exception:
        return {"why": _GENERIC[0], "impact": _GENERIC[1], "fix": _GENERIC[2]}


def flow_steps(finding: Finding) -> List[Dict[str, Any]]:
    """Structured SOURCE -> value -> SINK steps for a taint_flow finding (else [])."""
    try:
        if getattr(finding, "value_type", "") != "taint_flow":
            return []
        m = getattr(finding, "metadata", {}) or {}
        src_kind = str(m.get("source_kind", "") or "")
        src_label = _SOURCE_LABEL.get(src_kind, src_kind.replace("_", " ") or "source")
        sink = str(m.get("sink", "") or "sink")
        sink_attr = str(m.get("sink_attr", "") or "")
        if sink_attr:
            sink = f"{sink} (attr '{sink_attr}')"
        value = str(m.get("sink_source", "") or "")
        steps: List[Dict[str, Any]] = [
            {"kind": "source", "label": src_label, "line": m.get("source_line")},
        ]
        if value:
            steps.append({"kind": "value", "label": value, "line": None})
        steps.append({"kind": "sink", "label": sink, "line": m.get("sink_line")})
        return steps
    except Exception:
        return []


def _iter_tokens(finding: Finding) -> List[str]:
    """Tokens worth highlighting inside the snippet (tainted value, matched text, value)."""
    out: List[str] = []
    try:
        m = getattr(finding, "metadata", {}) or {}
        for t in (m.get("sink_source"), m.get("matched_text"),
                  getattr(finding, "extracted_value", "")):
            t = (t or "").strip()
            # skip empties and huge/whole-line tokens (they would highlight everything)
            if t and 1 < len(t) <= 80 and t not in out:
                out.append(t)
    except Exception:
        pass
    # longest first so a shorter token can't pre-consume part of a longer one
    return sorted(out, key=len, reverse=True)


def highlight_snippet(finding: Finding) -> str:
    """Render the evidence snippet as safe HTML: real line numbers, offending line(s) marked, and
    matched token(s) wrapped in <mark>. Returns '' when there is no snippet."""
    try:
        ev = getattr(finding, "evidence", None)
        snippet = getattr(ev, "snippet", "") if ev else ""
        if not snippet:
            return ""
        lines = snippet.split("\n")
        start, _ = getattr(ev, "snippet_lines", (0, 0)) or (0, 0)
        if not start or start < 1:
            start = getattr(ev, "line", 1) or 1
        tokens = _iter_tokens(finding)
        width = len(str(start + len(lines) - 1))
        rows: List[str] = []
        for i, raw in enumerate(lines):
            n = start + i
            esc = _html.escape(raw)
            hit = False
            applied: List[str] = []
            for tok in tokens:
                etok = _html.escape(tok)
                if not etok or etok not in esc:
                    continue
                # tokens are sorted longest-first; skip one already inside a longer highlighted
                # token (e.g. the secret value inside its matched_text) to avoid nested <mark>.
                if any(etok in a for a in applied):
                    continue
                esc = esc.replace(etok, f"<mark>{etok}</mark>")
                applied.append(etok)
                hit = True
            cls = "cl hl" if hit else "cl"
            gutter = str(n).rjust(width)
            rows.append(
                f'<span class="{cls}"><span class="ln">{gutter}</span>'
                f'<span class="src">{esc or " "}</span></span>'
            )
        return "\n".join(rows)
    except Exception:
        # never break report rendering over a snippet
        try:
            return f'<span class="cl"><span class="src">{_html.escape(snippet)}</span></span>'
        except Exception:
            return ""
