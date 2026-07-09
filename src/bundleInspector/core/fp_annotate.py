"""Non-destructive false-positive annotation (presentation layer).

Runs AFTER detection -- never inside ``RuleEngine.analyze``, so the detection-invariance gate stays
byte-identical -- and NEVER drops a finding. It only sets ``metadata['likely_fp'] = True`` plus a
``metadata['fp_reason']`` so the console and HTML report can demote (or optionally hide) high-noise
findings while detection recall is completely unchanged. A CONFIRMED source->sink taint flow is
never marked.

Rules:
  A) a hardcoded-"secret" inside a third-party library file (jquery/swiper/jsencrypt/...) -- almost
     always a regex/CSS/alphabet string in framework code, not an app credential.
  C) a `-----BEGIN ... PRIVATE KEY-----` marker with NO base64 key body AND no PEM structural
     evidence (END marker / RFC-1421 `Proc-Type:`/`DEK-Info:` headers) in the surrounding snippet --
     PEM parsing/label code, not a leaked key. The structural check is what keeps a genuine
     (esp. ENCRYPTED, multi-line) key -- whose base64 body sits just outside the snippet window --
     from being demoted.

Design note: an earlier Rule B demoted insertion sinks (`.append($img)`) whose argument was a
`$`-prefixed jQuery/DOM object. Adversarial verification showed the `$`-prefix is NOT a safe signal
(`$html` can hold a tainted HTML string, and `$item = $('<li>'+data)` parses tainted HTML), and the
variable's provenance is usually outside the ~7-line snippet -- so no snippet heuristic can soundly
distinguish it. Because that could hide a real DOM-XSS and B only demoted marginal LOW-severity
indicators, Rule B was removed (safety over coverage).
"""

from __future__ import annotations

import re

from bundleInspector.storage.models import Category

try:  # keep import failures from ever breaking report rendering
    from bundleInspector.core.vendor import classify_vendor_file
except Exception:  # pragma: no cover - defensive
    def classify_vendor_file(url, content=None):  # type: ignore
        return None


# a substantial base64 run -- the body of a real PEM key sits right after its BEGIN marker.
_B64_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
# structural evidence that a REAL PEM key is present even when its base64 body is out of the snippet
# window: an END marker or the RFC-1421 encrypted-key headers.
_PEM_STRUCTURE = re.compile(r"-----END|Proc-Type\s*:|DEK-Info\s*:", re.IGNORECASE)


def annotate_false_positives(report) -> int:
    """Mark likely false positives on ``report.findings`` in place. Returns the count marked.

    Idempotent and defensive: any per-finding error is swallowed so a presentation-layer heuristic
    can never fail a scan."""
    marked = 0
    for f in getattr(report, "findings", []) or []:
        try:
            reason = _fp_reason(f)
        except Exception:
            reason = None
        if reason:
            md = f.metadata if isinstance(f.metadata, dict) else {}
            md["likely_fp"] = True
            md.setdefault("fp_reason", reason)
            f.metadata = md
            marked += 1
    return marked


def _vendor_of(f) -> "str | None":
    """The vendor library name for a finding's file, or None (first-party)."""
    md = f.metadata if isinstance(f.metadata, dict) else {}
    tagged = md.get("third_party_file")
    if tagged:
        return tagged
    url = f.evidence.file_url if getattr(f, "evidence", None) else ""
    return classify_vendor_file(url or "")


def _snippet(f) -> str:
    ev = getattr(f, "evidence", None)
    return (getattr(ev, "snippet", "") if ev else "") or ""


def _fp_reason(f) -> "str | None":
    """Return a human-readable reason if the finding is a likely false positive, else None."""
    md = f.metadata if isinstance(f.metadata, dict) else {}
    if md.get("confirmed"):
        # a proven source->sink dataflow is never demoted, wherever it lives
        return None

    # (A) a "secret" inside a third-party library file is almost always framework noise
    if f.category == Category.SECRET:
        vendor = _vendor_of(f)
        if vendor:
            return f"third-party library file ({vendor}) -- library string, not an app credential"

    # (C) a PEM 'BEGIN PRIVATE KEY' marker with neither a base64 body NOR PEM structure nearby ->
    # parsing/label code. The structure guard preserves genuine keys whose body is out of window.
    if f.value_type in ("private_key", "pgp_private_key"):
        snip = _snippet(f)
        if not _B64_BODY.search(snip) and not _PEM_STRUCTURE.search(snip):
            return ("PEM 'BEGIN PRIVATE KEY' marker only -- no base64 body or PEM structure present "
                    "(parsing/label code, not a leaked key)")

    return None
