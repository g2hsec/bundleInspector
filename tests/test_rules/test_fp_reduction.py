"""Signal-preserving false-positive reduction: removals/downgrades must never drop a real
endpoint or secret (recall preserved). Covers the context_filter + secrets.py FP layer."""

from bundleInspector.config import Config
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.context_filter import ContextFilter
from bundleInspector.rules.detectors.secrets import SecretDetector
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category, Confidence


def _analyze(source: str):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    return list(engine.analyze(ir, ctx))


def _by(findings, category=None, value_type=None):
    out = findings
    if category is not None:
        out = [f for f in out if f.category == category]
    if value_type is not None:
        out = [f for f in out if f.value_type == value_type]
    return out


# ---- (a) redundant api_path removal, segment-boundary safe ----


def test_redundant_api_path_removed_but_endpoint_and_sibling_kept():
    src = (
        'const base="https://api.acme.com";const c=axios.create({baseURL:base});'
        'c.get("/api/v1/users");const q="/api/v1/user";'
    )
    findings = _analyze(src)
    ep_vals = {f.extracted_value for f in _by(findings, Category.ENDPOINT, "api_endpoint")}
    path_vals = {f.extracted_value for f in _by(findings, Category.ENDPOINT, "api_path")}
    assert any(v.endswith("/api/v1/users") for v in ep_vals)  # endpoint retained
    assert "/api/v1/users" not in path_vals  # redundant fragment removed
    assert "/api/v1/user" in path_vals  # sibling KEPT (boundary)


def test_lone_api_path_kept_when_no_endpoint():
    findings = _analyze('const p="/api/v1/users";')
    assert "/api/v1/users" in {
        f.extracted_value for f in _by(findings, Category.ENDPOINT, "api_path")
    }


def test_context_filter_prefix_boundary_direct():
    cf = ContextFilter()
    assert cf._normalize_endpoint_path("https://h/api/v1/users?q=1") == "/api/v1/users"
    eps = {"/api/v1/users"}

    class _F:
        extracted_value = "/api/v1/users"

    assert cf._is_redundant_api_path(_F(), eps) is True

    class _G:
        extracted_value = "/api/v1/user"

    assert cf._is_redundant_api_path(_G(), eps) is False


def test_prefix_shadowing_by_unrelated_endpoint_does_not_drop_api_path():
    """A distinct api_path must NOT be dropped just because an unrelated (e.g. third-party) endpoint
    has it as a path PREFIX -- endpoint_paths are host-agnostic, so prefix-collapse misattributed the
    app's own path to another origin. Only an EXACT path match is redundant."""
    cf = ContextFilter()
    # e.g. from https://analytics.thirdparty.com/api/admin/delete/log (host stripped -> bare path)
    eps = {"/api/admin/delete/log"}

    class _A:
        extracted_value = "/api/admin/delete"

    assert cf._is_redundant_api_path(_A(), eps) is False  # was wrongly True -> dropped

    class _B:  # an EXACT match is still redundant (retained endpoint carries the identical path)
        extracted_value = "/api/admin/delete/log"

    assert cf._is_redundant_api_path(_B(), eps) is True


def test_url_secret_with_path_token_is_not_filtered_as_non_secret():
    """A URL carrying a secret in its PATH (a webhook token) or userinfo must NOT be classified as a
    benign non-secret and dropped -- that silently loses a real hardcoded credential. Plain URLs and
    non-URL non-secrets (emails) still filter."""
    cf = ContextFilter()
    # credential-bearing URLs -> spared (the secret survives)
    assert (
        cf._url_carries_credential("https://ci.internal.example/hooks/deploy/SECRETTOKEN123456")
        is True
    )
    assert cf._url_carries_credential("https://user:p4ssTOKEN12345@api.example.com/x") is True
    assert (
        cf._check_value_pattern("https://ci.internal.example/hooks/deploy/SECRETTOKEN123456")
        is None
    )
    # a plain URL is still a non-secret (FP reduction preserved)
    assert cf._url_carries_credential("https://api.example.com/v1/users") is False
    plain = cf._check_value_pattern("https://api.example.com/v1/users")
    assert plain is not None and plain.is_false_positive is True
    # a non-URL non-secret (email) is unaffected -> still filtered
    assert cf._url_carries_credential("user@example.com") is False


# ---- (b) doc-context downgrade (never dropped) ----


def test_domain_doc_context_downgrades_not_dropped():
    findings = _analyze('const sample = "dev.internal.corp";\nconst h = "prod.internal.corp";')
    doms = {f.extracted_value: f for f in _by(findings, Category.DOMAIN)}
    assert "dev.internal.corp" in doms and doms["dev.internal.corp"].confidence == Confidence.LOW
    assert "doc-context" in doms["dev.internal.corp"].tags
    assert doms["prod.internal.corp"].confidence == Confidence.HIGH  # control unchanged


def test_doc_context_ignores_string_contents():
    cf = ContextFilter()
    # 'example' only inside the string literal -> not a doc line
    assert cf._line_has_doc_context('const u = "https://api.example.com/x";', 1) is False
    # 'example' as an identifier/comment -> doc line
    assert cf._line_has_doc_context('const example = "prod.internal.corp"; // sample', 1) is True


# ---- (c) secret scheme/hostname/i18n exclusion + entropy context gate ----


def test_is_excluded_schemes_and_data_uri():
    d = SecretDetector()
    assert d._is_excluded("s3://bucket") is True
    assert d._is_excluded("gs://bucket") is True
    assert d._is_excluded("wss://h/socket") is True
    assert d._is_excluded("data:application/json;base64,eyJ2IjoxfQ==") is True
    # credential-bearing URLs are NOT excluded
    assert d._is_excluded("wss://h/socket?token=abc123") is False
    assert d._is_excluded("mongodb://user:pass@host/db") is False


def test_is_common_non_secret_hostname_asset_i18n_but_not_real_secret():
    d = SecretDetector()
    assert d._is_common_non_secret("svc.node.internal.corp.local") is True
    assert d._is_common_non_secret("app.4f3c2b1a9d.chunk.js") is True
    assert d._is_common_non_secret("common.buttons.submit.label") is True
    # genuine secrets must NOT be filtered
    assert d._is_common_non_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") is False
    assert d._is_common_non_secret("AKIAIOSFODNN7EXAMPLE") is False


def test_entropy_context_gate_downgrades_only_context_less():
    src = 'var payload="Kd9Xm2Qp7Ws4Zt1Rv8Bn3Yc6";\nvar credentialData="Kd9Xm2Qp7Ws4Zt1Rv8Bn3Yc6X";'
    secrets = {f.extracted_value: f for f in _by(_analyze(src), Category.SECRET)}
    ctx_less = secrets["Kd9Xm2Qp7Ws4Zt1Rv8Bn3Yc6"]
    ctx_full = secrets["Kd9Xm2Qp7Ws4Zt1Rv8Bn3Yc6X"]
    assert ctx_less.confidence == Confidence.LOW and "entropy-no-context" in ctx_less.tags
    assert ctx_full.confidence == Confidence.HIGH  # demote, never drop; context one stays HIGH


def test_hostname_secret_fp_still_detected_as_domain():
    """A hostname wrongly seen as a secret before is now a DOMAIN, not lost."""
    findings = _analyze('var d="internal-svc.corp.local";var b="s3://acme-bucket";')
    assert not _by(findings, Category.SECRET)  # not a secret anymore
    dom_vals = {f.extracted_value for f in _by(findings, Category.DOMAIN)}
    assert "internal-svc.corp.local" in dom_vals  # re-reported as domain
    assert "s3://acme-bucket" in dom_vals


def test_real_secret_preserved_high():
    src = "const secretAccessKey='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';"
    secrets = _by(_analyze(src), Category.SECRET)
    assert any(f.confidence == Confidence.HIGH and "wJalr" in f.extracted_value for f in secrets)


def test_flag_findings_pass_through_unchanged():
    findings = _analyze('const x = "feature_flag_new_checkout";')
    assert _by(findings, Category.FLAG)  # flags unaffected by FP layer
