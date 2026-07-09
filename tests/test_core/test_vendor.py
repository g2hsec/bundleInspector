"""Third-party / vendor JS file classification -- high precision: vendor libs tagged, first-party
files NEVER mis-tagged (a false-vendor tag could hide a real finding under --first-party-only)."""

from __future__ import annotations

import pytest

from bundleInspector.core.vendor import classify_vendor_file


@pytest.mark.parametrize("url,expect", [
    ("https://x/static/mall/js/jquery-3.7.1.min.js", "jquery"),
    # multi-token names win over the single-token prefix, so the label is the most specific lib
    ("https://x/js/jquery-migrate-3.5.2.min.js", "jquery-migrate"),
    ("https://x/js/swiper.js", "swiper"),
    ("https://x/js/jsencrypt.min.js", "jsencrypt"),
    ("https://x/js/bootstrap.bundle.min.js", "bootstrap"),
    ("https://x/js/react-dom.production.min.js", "react-dom"),
    ("https://x/js/owl.carousel.min.js", "owl.carousel"),
    ("https://x/vendor/anything.js", "vendor-dir"),
    ("https://x/node_modules/foo/index.js", "vendor-dir"),
    ("https://x/plugins/slider.js", "vendor-dir"),
    # over-fit audit: content-hashed builds + multi-descriptor distributions + modern/Korean SDKs
    ("https://x/js/jquery.min.8f2a9c.js", "jquery"),   # webpack/vite content hash stripped
    ("https://x/js/xlsx.full.min.js", "xlsx"),          # 'full' descriptor is build noise
    ("https://x/js/kakao.min.js", "kakao"),             # KR payment/social SDK
    ("https://x/js/dompurify.min.js", "dompurify"),
])
def test_vendor_files_tagged(url, expect):
    assert classify_vendor_file(url) == expect


@pytest.mark.parametrize("url", [
    "https://x/static/mall/js/shopfront.js",
    "https://x/js/utils.js",
    "https://x/js/common.js",
    "https://x/js/context.js",          # contains 'ext' but not the token 'ext'
    "https://x/js/renewal.js",
    "https://x/js/app.js",
    "https://x/js/main.bundle.js",
    "https://x/js/myextension.js",
    "https://x/js/grace.js",            # contains 'ace' but not the token 'ace'
    "https://x/js/purchart.js",         # contains 'chart' but not the token 'chart'
    "https://x/js/swiperConfig.js",     # app config, not the swiper library
    "https://x/js/core.js",             # first-party core.js must NOT match vendor 'core-js'
    "https://x/js/core.min.js",
    "https://x/app/core.js",
    "https://x/js/chart-facade.js",     # 'facade' is all-hex but not a content hash (no digit)
    # single-token library names are common English words: a first-party file that merely
    # CONTAINS the token (as one of several meaningful tokens) must NOT be classified vendor,
    # or a real finding/secret in it would be hidden.
    "https://x/js/revenue-chart.js",    # 'chart' is not the sole meaningful token
    "https://x/js/org-chart.js",
    "https://x/js/user-prototype.js",   # 'prototype'
    "https://x/js/three-column.js",     # 'three'
    "https://x/js/moment-picker.js",    # 'moment'
    "https://x/js/ace-editor-config.js",# 'ace'
])
def test_first_party_files_not_tagged(url):
    assert classify_vendor_file(url) is None


def test_banner_detection():
    assert classify_vendor_file("https://x/js/lib.js", content="/*! SomeLib v2.3.1 | (c) 2020 */")
    assert classify_vendor_file("https://x/js/app.js", content="function init(){ return 1; }") is None


def test_malformed_url_no_crash():
    for bad in ("", "not a url", "https://[bad/x.js"):
        classify_vendor_file(bad)  # must not raise
