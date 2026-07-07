"""Regression tests for detection-quality fixes found scanning a real Java/JSP web app:

- FN: server-side dynamic endpoints (.do/.jsp/.action/.php/.aspx/...) were not recognized at
  all -- a large false-negative class for Java/Spring/Struts apps.
- FP: the entropy-based secret detector flagged window.open feature specs, endpoint paths,
  CSS selectors, host:port, and minifier keyword-blobs as "potential_secret".

The token-shaped literals below are fabricated samples, not real credentials.
"""

from __future__ import annotations

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.rules.detectors.secrets import SecretDetector


def _endpoints(src: str) -> set[str]:
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules); eng.register_defaults()
    fs = eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src))
    return {f.extracted_value for f in fs if f.category.value == "endpoint"}


# ---------------------------------------------------------------- FN: .do/.jsp endpoints

def test_bare_do_path_literal_is_detected():
    eps = _endpoints('function p(preUrl){var url=preUrl+"/member/pwdChangeF.do";return url;}')
    assert any("/member/pwdChangeF.do" in e for e in eps)


def test_relative_do_with_query_is_detected():
    eps = _endpoints('var u="addressC.do?addr_sq="+sq; fetch(u);')
    assert any("addressC.do" in e for e in eps)


@pytest.mark.parametrize("path", [
    "login.action", "search.php?q=1", "Handler.ashx", "index.jsp", "/api/v2/thing.do",
])
def test_various_server_extensions_detected(path):
    assert _endpoints(f'var u="{path}";') , f"missed {path}"


def test_template_literal_context_do_endpoint_via_ajax():
    src = '$.ajax({url: `${$.shopfront.var.context}/newRegistMultiCart.do`, type:"POST"});'
    assert any("newRegistMultiCart.do" in e for e in _endpoints(src))


def test_static_assets_are_not_endpoints():
    eps = _endpoints('var a="/static/app.js"; var b="/css/main.css"; var c="/img/logo.png";')
    assert not any(x in " ".join(eps) for x in ("app.js", "main.css", "logo.png"))


# ---------------------------------------------------------------- FP: entropy secret detector

@pytest.mark.parametrize("value", [
    "width=430,height=317,resizable=no,scrollbars=no,status=no",  # window.open features (the report FP)
    ",resizable=no,scrollbars=no,status=no",                      # concatenation tail
    "a=1&b=2&c=3&d=4",                                            # query string
    "/newRegistMultiCart.do",                                     # endpoint path
    "addressC.do?addr_sq=",                                   # relative endpoint + query
    "common/frcmPostF.do?inParam=",                              # nested endpoint path
    "appfront/jsp/blank.jsp",                                # jsp path
    ".swiper-slide:not(.swiper-slide-duplicate)",                # CSS selector
    "[data-price='true']",                                        # attribute selector
    "sso.example.com:8070",                                       # host:port (a domain, not a secret)
    "null|httpRequest|function|return|if|var|GET|ActiveXObject",  # minifier keyword blob
])
def test_non_secret_shapes_are_not_flagged(value):
    assert SecretDetector()._looks_like_secret(value) is False, value


@pytest.mark.parametrize("value", [
    "deadbeefcafebabe0123456789abcdef",           # 32-char hex
    "AKIAIOSFODNN7EXAMPLE1234",                    # AWS-key-shaped
    "xoxbFAKE1234567890abcdefghijABCDEF",          # opaque mixed token
    "ghpFAKE16CharsMixed1234567890abcd",           # opaque token
])
def test_real_secret_shapes_still_flagged(value):
    # The FP filters must not suppress genuine opaque high-entropy tokens.
    assert SecretDetector()._looks_like_secret(value) is True, value
