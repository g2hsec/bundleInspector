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
    assert "CONFIRMED" in text and "DOM/stored-XSS" in text
    assert "source" in text and "sink" in text and "flow" in text
    assert "CANDIDATE" in text
    assert "●" in text and "○" in text  # confirmed / candidate legend markers


def test_vendor_chain_tagged_and_optionally_filtered():
    # a confirmed flow in a jquery library file must be tagged and demoted, and hidden under
    # first_party_only -- but an app-file chain stays.
    app = _f(Category.SINK, "taint_flow", 819, file="shopfront.js", meta={
        "source_kind": "ajax_response", "source_line": 624, "sink": ".html()",
        "sink_line": 819, "sink_source": "couponCount", "flow_path": ["s", "v", "sink"]})
    vend = _f(Category.SINK, "taint_flow", 1980, file="jquery-3.7.1.min.js", meta={
        "source_kind": "dom_input", "source_line": 1970, "sink": "innerHTML=",
        "sink_line": 1980, "sink_source": "x", "flow_path": ["s", "v", "sink"]})
    rpt = Report(findings=[app, vend], correlations=[])

    chains = build_chains(rpt)
    by_file = {c["file"].rsplit("/", 1)[-1]: c for c in chains}
    assert by_file["jquery-3.7.1.min.js"]["third_party"] == "jquery"
    assert by_file["shopfront.js"]["third_party"] is None
    assert "[3p:jquery" in render_chains(chains)          # labelled
    assert chains[-1]["file"].endswith("jquery-3.7.1.min.js")  # vendor sorted last

    fp_only = build_chains(rpt, first_party_only=True)
    assert all(not c["third_party"] for c in fp_only)     # vendor hidden
    assert any(c["file"].endswith("shopfront.js") for c in fp_only)  # app kept


def test_render_labels_code_injection_for_an_eval_sink():
    # over-fit fix: a taint_flow into eval() is code injection, not "DOM/stored-XSS"
    tf = _f(Category.SINK, "taint_flow", 50, meta={
        "source_kind": "url", "source_line": 49, "sink": "eval()", "sink_line": 50,
        "sink_source": "location.hash", "flow_path": ["source @L49", "location.hash", "eval() @L50"]})
    txt = render_chains(build_chains(Report(findings=[tf], correlations=[])))
    assert "code-injection dataflow" in txt
    assert "DOM/stored-XSS dataflow" not in txt


def test_render_labels_open_redirect_for_a_navigation_sink():
    # a taint_flow into location.href / window.open is an open redirect
    tf = _f(Category.SINK, "taint_flow", 50, meta={
        "source_kind": "url", "source_line": 49, "sink": "location.href=", "sink_line": 50,
        "sink_source": "location.search", "flow_path": ["source @L49", "location.search", "location.href= @L50"]})
    txt = render_chains(build_chains(Report(findings=[tf], correlations=[])))
    assert "open-redirect dataflow" in txt
    assert "DOM/stored-XSS dataflow" not in txt


def test_no_crash_on_empty_and_malformed():
    assert render_chains(build_chains(Report(findings=[], correlations=[]))) == ""
    # taint_flow with no metadata, correlation with dangling ids -> no exception
    bad = Report(findings=[_f(Category.SINK, "taint_flow", 5)],
                 correlations=[Correlation(edge_type=EdgeType.TAINT, source_finding_id="nope",
                                           target_finding_id="nope2", confidence=Confidence.LOW,
                                           reasoning="x")])
    render_chains(build_chains(bad))  # must not raise
