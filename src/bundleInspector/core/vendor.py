"""
Third-party / vendor JS file classification.

A finding in `jquery.min.js` or `swiper.js` is almost always framework-internal noise, not the
app's vulnerability -- but the file is served from the FIRST-PARTY domain, so domain-based
first-party detection does not catch it. This classifies a JS asset by FILENAME / PATH / banner
so findings in it can be LABELED and de-prioritized (never dropped by default).

Precision is deliberately favored: name matching is exact-token (so `context.js` is not matched
by `ext`, and a first-party file is never mis-flagged as vendor and hidden). A miss just means a
vendor file is shown normally -- the safe direction under the "detection must never drop" rule.
"""

from __future__ import annotations

import re
from typing import Optional

from bundleInspector.core.url_utils import safe_urlparse

# Known third-party library filename stems (each may contain '.'/'-' which are treated as token
# separators, so `react-dom`/`socket.io`/`owl.carousel` match their multi-token filenames).
_LIB_NAMES = (
    "jquery", "jquery-ui", "jquery-migrate", "swiper", "bootstrap", "lodash", "underscore",
    "moment", "dayjs", "react", "react-dom", "vue", "vuex", "vue-router", "angular", "axios",
    "d3", "chart", "chartjs", "popper", "slick", "owl.carousel", "select2", "jsencrypt",
    "crypto-js", "cryptojs", "forge", "polyfill", "polyfills", "modernizr", "handlebars",
    "mustache", "backbone", "ember", "zepto", "prototype", "mootools", "dojo", "highcharts",
    "echarts", "leaflet", "mapbox", "three", "gsap", "tweenmax", "hammer", "fullcalendar",
    "datatables", "fancybox", "magnific-popup", "lightbox", "flatpickr", "sweetalert",
    "sweetalert2", "toastr", "notyf", "clipboard", "sortable", "dropzone", "quill", "ckeditor",
    "tinymce", "codemirror", "ace", "papaparse", "xlsx", "sockjs", "stomp", "socket.io",
    "core-js", "systemjs", "requirejs", "es5-shim", "es6-shim", "babel-polyfill", "webpack",
    "normalize", "font-awesome", "fontawesome", "raphael", "velocity", "anime", "aos",
    "wow", "isotope", "masonry", "imagesloaded", "flickity", "splide", "glide", "tiny-slider",
)
_LIB_PARTS = {name: frozenset(re.split(r"[.\-_]", name)) for name in _LIB_NAMES}

_VENDOR_PATH = re.compile(
    r"/(?:vendor|vendors|lib|libs|node_modules|bower_components|plugins?|"
    r"third[_-]?party|externals?|dist/vendor|assets/vendor)/",
    re.IGNORECASE,
)
# Leading minified library license/version banner, e.g.  /*! jQuery v3.7.1 | (c) ... */
_BANNER = re.compile(r"^\s{0,4}/\*[!*].{0,120}?\bv?\d+\.\d+", re.DOTALL)


def classify_vendor_file(url: str, content: Optional[str] = None) -> Optional[str]:
    """Return the third-party library name/reason for a JS asset URL, else None (first-party)."""
    if not url:
        return None
    path = (safe_urlparse(url).path or url)
    base = path.rsplit("/", 1)[-1].lower()
    if not base:
        return None
    tokens = frozenset(t for t in re.split(r"[.\-_]", base) if t)

    # 1) exact-token library-name match in the basename (precise: no substring false hits)
    for name, parts in _LIB_PARTS.items():
        if parts <= tokens:
            return name

    # 2) served from a conventional vendor/library directory
    if _VENDOR_PATH.search(path):
        return "vendor-dir"

    # 3) a leading minified library banner (only when content is available)
    if content and _BANNER.match(content[:256]):
        return "library-banner"

    return None
