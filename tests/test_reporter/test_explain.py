"""Report legibility layer: plain-language why/impact/fix, source->sink flow, highlighted snippet.
Pure presentation over a Finding -- must be accurate per category and never raise on odd data."""

from __future__ import annotations

from bundleInspector.storage.models import (
    Finding, Evidence, Category, Severity, Confidence,
)
from bundleInspector.reporter.explain import (
    explain_finding, flow_steps, highlight_snippet,
)


def _f(cat, vt, *, meta=None, val="", snippet="", snippet_lines=(0, 0), line=1):
    return Finding(
        rule_id="r", category=cat, severity=Severity.HIGH, confidence=Confidence.HIGH,
        title=vt, value_type=vt, extracted_value=val, metadata=meta or {},
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=line,
                          snippet=snippet, snippet_lines=snippet_lines),
    )


class TestExplainFinding:
    def test_taint_flow_explains_the_xss_dataflow(self):
        e = explain_finding(_f(Category.SINK, "taint_flow"))
        assert "sanitized" in e["why"].lower() or "encoded" in e["why"].lower()
        assert "xss" in e["impact"].lower()
        assert e["fix"]  # non-empty remediation

    def test_secret_and_endpoint_have_distinct_framing(self):
        secret = explain_finding(_f(Category.SECRET, "potential_secret"))
        endpoint = explain_finding(_f(Category.ENDPOINT, "api_path"))
        assert "rotate" in secret["fix"].lower()
        # an endpoint is attack surface, explicitly NOT a vuln on its own
        assert "not a vulnerability" in endpoint["impact"].lower()

    def test_taint_flow_into_eval_is_code_injection_not_dom_xss(self):
        # over-fit fix: a taint_flow whose sink is eval() is code injection, not DOM-XSS
        e = explain_finding(_f(Category.SINK, "taint_flow",
                               meta={"sink": "eval()", "sink_source": "x", "source_kind": "url"}))
        assert "dompurify" not in e["fix"].lower()          # DOM fix is nonsensical for eval
        assert "eval" in e["fix"].lower() or "function" in e["fix"].lower()

    def test_taint_flow_into_html_stays_dom_xss(self):
        e = explain_finding(_f(Category.SINK, "taint_flow",
                               meta={"sink": ".html()", "sink_source": "x", "source_kind": "ajax"}))
        assert "xss" in e["impact"].lower()

    def test_client_route_gets_route_explanation_not_endpoint(self):
        # over-fit fix: client_route (value_type) wins over the endpoint category fallback
        e = explain_finding(_f(Category.ENDPOINT, "client_route"))
        assert "route" in e["why"].lower() and "server" in e["fix"].lower()

    def test_unknown_value_type_falls_back_to_category(self):
        # a value_type with no specific entry still gets a sensible sink-level explanation
        e = explain_finding(_f(Category.SINK, "some_new_sink_kind"))
        assert e["why"] and e["impact"] and e["fix"]

    def test_never_raises(self):
        # a finding-like object missing fields must not crash the explainer
        class Bare:
            value_type = None
            category = None
        e = explain_finding(Bare())  # type: ignore[arg-type]
        assert set(e) == {"why", "impact", "fix"}


class TestFlowSteps:
    def test_taint_flow_builds_source_value_sink(self):
        f = _f(Category.SINK, "taint_flow", meta={
            "source_kind": "filereader", "source_line": 239, "sink": ".attr(src)",
            "sink_attr": "src", "sink_line": 240, "sink_source": "e.target.result"})
        steps = flow_steps(f)
        assert [s["kind"] for s in steps] == ["source", "value", "sink"]
        assert steps[0]["label"] == "Uploaded file (FileReader)" and steps[0]["line"] == 239
        assert steps[1]["label"] == "e.target.result"
        assert "attr 'src'" in steps[2]["label"] and steps[2]["line"] == 240

    def test_non_taint_has_no_flow(self):
        assert flow_steps(_f(Category.ENDPOINT, "api_path")) == []

    def test_missing_value_omits_value_step(self):
        f = _f(Category.SINK, "taint_flow", meta={
            "source_kind": "dom_input", "sink": "innerHTML=", "sink_line": 10})
        assert [s["kind"] for s in flow_steps(f)] == ["source", "sink"]


class TestHighlightSnippet:
    def test_line_numbers_and_token_highlight(self):
        f = _f(Category.SINK, "taint_flow", val="e.target.result",
               meta={"sink_source": "e.target.result"},
               snippet='const reader = new FileReader();\n$img.attr("src", e.target.result);',
               snippet_lines=(239, 240))
        html = highlight_snippet(f)
        assert "<mark>e.target.result</mark>" in html   # the matched value is highlighted
        assert '<span class="ln">239</span>' in html    # real starting line number
        assert "cl hl" in html                           # the offending line is marked

    def test_empty_snippet_returns_empty(self):
        assert highlight_snippet(_f(Category.SINK, "dom_html_sink")) == ""

    def test_html_is_escaped(self):
        f = _f(Category.SINK, "dom_html_sink",
               snippet='el.innerHTML = "<img src=x onerror=alert(1)>";',
               snippet_lines=(5, 5))
        html = highlight_snippet(f)
        assert "&lt;img" in html and "<img src=x" not in html  # no raw HTML injection

    def test_never_raises_on_odd_data(self):
        class Bare:
            evidence = None
        assert highlight_snippet(Bare()) == ""  # type: ignore[arg-type]
