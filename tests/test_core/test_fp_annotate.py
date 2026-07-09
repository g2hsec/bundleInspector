"""Non-destructive false-positive annotation (presentation layer).

INVARIANT: annotate_false_positives NEVER drops a finding and only sets metadata -- so detection
recall is unchanged and the detection gate stays byte-identical. A CONFIRMED taint flow is never
marked. Rules are added incrementally: A) vendor-file secrets."""

from __future__ import annotations

from bundleInspector.storage.models import (
    Finding, Evidence, Category, Severity, Confidence,
)
from bundleInspector.core.fp_annotate import annotate_false_positives


def _f(cat, vt, *, url="https://x/static/mall/js/shopfront.js", val="", meta=None,
       snippet="", snippet_lines=(0, 0), sev=Severity.MEDIUM):
    return Finding(
        rule_id="r", category=cat, severity=sev, confidence=Confidence.MEDIUM,
        title=vt, value_type=vt, extracted_value=val, metadata=meta or {},
        evidence=Evidence(file_url=url, file_hash="h", line=1, snippet=snippet,
                          snippet_lines=snippet_lines),
    )


class _Report:
    def __init__(self, findings):
        self.findings = findings


def _mark(findings):
    r = _Report(findings)
    n = annotate_false_positives(r)
    return r, n


def _fp(f):
    return bool((f.metadata or {}).get("likely_fp"))


class TestRuleA_VendorSecrets:
    def test_secret_in_vendor_file_is_demoted(self):
        f = _f(Category.SECRET, "potential_secret",
               url="https://x/js/jquery-3.7.1.min.js", val="posi_tion_absolute_regex")
        _mark([f])
        assert _fp(f) and "jquery" in f.metadata["fp_reason"]

    def test_secret_in_vendor_via_existing_tag(self):
        f = _f(Category.SECRET, "potential_secret",
               url="https://x/js/lib.min.js", meta={"third_party_file": "swiper"})
        _mark([f])
        assert _fp(f) and "swiper" in f.metadata["fp_reason"]

    def test_first_party_secret_is_NOT_demoted(self):
        # a real hardcoded secret in app code must never be marked FP
        f = _f(Category.SECRET, "potential_secret",
               url="https://x/static/mall/js/shopfront.js", val="AKIAIOSFODNN7EXAMPLE")
        _mark([f])
        assert not _fp(f)

    def test_non_secret_in_vendor_not_marked_by_rule_A(self):
        # rule A only covers secrets; a vendor sink is handled by the existing vendor tag, not here
        f = _f(Category.SINK, "dom_html_sink", url="https://x/js/jquery-3.7.1.min.js",
               val=".html()")
        _mark([f])
        assert not _fp(f)


class TestRuleB_Removed:
    """Rule B (jQuery-object insertion-sink demotion) was removed after adversarial verification
    showed a $-prefixed variable can hold tainted HTML -> it could hide a real DOM-XSS. A bare
    insertion sink must now be KEPT (never demoted by fp_annotate)."""

    def test_append_object_sink_is_kept(self):
        f = _f(Category.SINK, "dom_html_sink", val=".append()",
               snippet="      $imgWrap.append($img);", snippet_lines=(5, 5))
        _mark([f])
        assert not _fp(f)

    def test_append_of_tainted_html_var_is_kept(self):
        # the exact over-suppression case the verifier found -- must survive
        f = _f(Category.SINK, "dom_html_sink", val=".append()",
               snippet="var $html='<div>'+c.body+'</div>'; $('#c').append($html);",
               snippet_lines=(5, 5))
        _mark([f])
        assert not _fp(f)


class TestRuleC_MarkerOnlyPrivateKey:
    def test_first_party_marker_without_body_is_demoted(self):
        f = _f(Category.SECRET, "private_key", url="https://x/static/mall/js/app.js",
               val="-----BEGIN RSA PRIVATE KEY-----", sev=Severity.CRITICAL,
               snippet='  var HEADER = "-----BEGIN RSA PRIVATE KEY-----";')
        _mark([f])
        assert _fp(f) and "marker only" in f.metadata["fp_reason"]

    def test_real_key_with_body_is_NOT_demoted(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ" * 2  # long base64 body
        f = _f(Category.SECRET, "private_key", url="https://x/static/mall/js/app.js",
               val="-----BEGIN PRIVATE KEY-----", sev=Severity.CRITICAL,
               snippet=f'-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----')
        _mark([f])
        assert not _fp(f)   # a genuine leaked key must survive

    def test_encrypted_pem_with_body_out_of_window_is_NOT_demoted(self):
        # the verifier's case: RFC-1421 headers push the base64 body past the snippet window, but
        # the Proc-Type/DEK-Info structure proves a real key -> must NOT be demoted
        f = _f(Category.SECRET, "private_key", url="https://x/static/mall/js/app.js",
               val="-----BEGIN RSA PRIVATE KEY-----", sev=Severity.CRITICAL,
               snippet=('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n'
                        'DEK-Info: DES-EDE3-CBC,3F17F5316E43A4C2\n'))
        _mark([f])
        assert not _fp(f)

    def test_end_marker_in_window_is_NOT_demoted(self):
        f = _f(Category.SECRET, "private_key", url="https://x/static/mall/js/app.js",
               val="-----BEGIN PRIVATE KEY-----", sev=Severity.CRITICAL,
               snippet='-----BEGIN PRIVATE KEY-----\n...short...\n-----END PRIVATE KEY-----')
        _mark([f])
        assert not _fp(f)

    def test_vendor_marker_demoted_by_rule_A_not_C(self):
        # jsencrypt's PEM marker: rule A (vendor) fires first with the more informative reason
        f = _f(Category.SECRET, "private_key", url="https://x/js/jsencrypt.min.js",
               val="-----BEGIN PRIVATE KEY-----", sev=Severity.CRITICAL,
               snippet='...t+"-----BEGIN "+e+" PRIVATE KEY-----"+n...')
        _mark([f])
        assert _fp(f) and "jsencrypt" in f.metadata["fp_reason"]


class TestInvariants:
    def test_confirmed_flow_never_marked(self):
        # even a (hypothetical) vendor secret with confirmed dataflow is never demoted
        f = _f(Category.SECRET, "potential_secret", url="https://x/js/jquery-3.7.1.min.js",
               meta={"confirmed": True})
        _mark([f])
        assert not _fp(f)

    def test_idempotent_and_counts(self):
        f = _f(Category.SECRET, "potential_secret", url="https://x/js/swiper.js", val="onSlideStart")
        r, n1 = _mark([f])
        n2 = annotate_false_positives(r)
        assert n1 == 1 and n2 == 1 and _fp(f)   # stable, not double-counted structurally

    def test_never_drops_findings(self):
        findings = [_f(Category.SECRET, "potential_secret", url="https://x/js/jquery.min.js"),
                    _f(Category.ENDPOINT, "api_path", val="/x.do"),
                    _f(Category.SINK, "taint_flow", meta={"confirmed": True})]
        r, _ = _mark(findings)
        assert len(r.findings) == 3   # count is invariant -- nothing removed
