"""Attack-chain view: groups the sink indicator + confirmed taint_flow + upload correlation
into one chain per sink. Pure presentation over a Report -- must never raise."""

from __future__ import annotations

from bundleInspector.storage.models import (
    Report, Finding, Evidence, Correlation, Category, Severity, Confidence, EdgeType,
)
from bundleInspector.reporter.chain_view import build_chains, render_chains


def _f(cat, vt, line, sev=Severity.HIGH, meta=None, val="", file="app.js"):
    return Finding(rule_id="r", category=cat, severity=sev, confidence=Confidence.HIGH,
                   title=vt, evidence=Evidence(file_url=f"https://x/{file}", file_hash="h", line=line),
                   value_type=vt, extracted_value=val, metadata=meta or {})


def _report():
    tf = _f(Category.SINK, "taint_flow", 1077, meta={
        "source_kind": "ajax_response", "source_line": 1076, "sink": ".append()",
        "sink_line": 1077, "sink_attr": "", "sink_source": "restock.image_url",
        "flow_path": ["source: server response @L1076", "tainted value `restock.image_url`",
                      "sink: .append() @L1077"]})
    ind = _f(Category.SINK, "dom_html_sink", 1077)
    up = _f(Category.UPLOAD, "client_side_file_validation", 166, sev=Severity.MEDIUM, val="allowedExt")
    ep = _f(Category.ENDPOINT, "api_path", 929, val="/frgdRestockNotification.do")
    sink2 = _f(Category.SINK, "dom_attr_sink", 229, sev=Severity.MEDIUM, meta={"sink_source": "e.target.result"})
    cor = Correlation(edge_type=EdgeType.TAINT, source_finding_id=up.id, target_finding_id=sink2.id,
                      confidence=Confidence.MEDIUM, reasoning="upload -> sink")
    return Report(findings=[tf, ind, up, ep, sink2], correlations=[cor])


def test_build_chains_confirmed_and_candidate():
    chains = build_chains(_report())
    kinds = [c["kind"] for c in chains]
    assert "confirmed" in kinds and "candidate" in kinds
    confirmed = next(c for c in chains if c["kind"] == "confirmed")
    assert confirmed["source_kind"] == "ajax_response"
    assert confirmed["sink"] == ".append()"
    assert confirmed["sink_source"] == "restock.image_url"
    assert confirmed["indicator"] == "dom_html_sink"          # co-located indicator linked
    assert any(u[1] == "allowedExt" for u in confirmed["uploads"])  # upload surface linked
    assert "/frgdRestockNotification.do" in confirmed["endpoints"]   # replay context


def test_confirmed_supersedes_candidate_at_same_sink():
    # A correlation to a sink that already has a confirmed flow must not also appear as candidate.
    rpt = _report()
    tf = next(f for f in rpt.findings if f.value_type == "taint_flow")
    ind = next(f for f in rpt.findings if f.value_type == "dom_html_sink")
    up = next(f for f in rpt.findings if f.category == Category.UPLOAD)
    rpt.correlations.append(Correlation(edge_type=EdgeType.TAINT, source_finding_id=up.id,
                                        target_finding_id=ind.id, confidence=Confidence.MEDIUM,
                                        reasoning="upload -> sink"))
    chains = build_chains(rpt)
    # only ONE chain touches sink line 1077, and it is confirmed
    at_1077 = [c for c in chains if c["sink_line"] == 1077]
    assert len(at_1077) == 1 and at_1077[0]["kind"] == "confirmed"


def test_render_is_plain_text_with_headers():
    text = render_chains(build_chains(_report()))
    assert "ATTACK CHAINS" in text
    assert "CONFIRMED dataflow XSS chain" in text
    assert "SOURCE" in text and "SINK" in text and "FLOW" in text
    assert "CANDIDATE chain" in text


def test_no_crash_on_empty_and_malformed():
    assert render_chains(build_chains(Report(findings=[], correlations=[]))) == ""
    # taint_flow with no metadata, correlation with dangling ids -> no exception
    bad = Report(findings=[_f(Category.SINK, "taint_flow", 5)],
                 correlations=[Correlation(edge_type=EdgeType.TAINT, source_finding_id="nope",
                                           target_finding_id="nope2", confidence=Confidence.LOW,
                                           reasoning="x")])
    render_chains(build_chains(bad))  # must not raise
