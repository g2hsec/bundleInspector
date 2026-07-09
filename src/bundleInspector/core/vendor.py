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
    # modern framework / build / util ecosystem
    "tailwind", "alpine", "alpinejs", "htmx", "stimulus", "turbo", "preact", "svelte", "solid-js",
    "pdfjs", "pdf-lib", "recharts", "apexcharts", "hls", "hls.js", "video.js", "videojs", "plyr",
    "dompurify", "marked", "prismjs", "highlight.js", "ag-grid", "handsontable", "tabulator",
    "framer-motion", "immutable", "immer", "date-fns", "luxon", "rxjs", "js-cookie", "js.cookie",
    "nanoid", "numeral", "big.js", "decimal.js", "pixi", "pixi.js", "konva", "fabric", "signature-pad",
    "cropperjs", "cropper", "flatpickr", "air-datepicker", "daterangepicker", "intro.js", "shepherd",
    "swiper-bundle", "aos", "gsap", "lottie", "lottie-web", "particles", "typed.js", "countup",
    # payment / social / map SDKs common in Korean e-commerce
    "kakao", "kakaomap", "naver", "navermaps", "tosspayments", "iamport", "nicepay", "inicis",
    "daumcdn", "jusopostcode", "channeltalk", "channel-io", "sentry", "sentry-bundle",
)
_LIB_PARTS = {name: frozenset(re.split(r"[.\-_]", name)) for name in _LIB_NAMES}

# Build/version/format tokens that carry no identity -- stripped before deciding whether a
# SINGLE-token library name is the *sole* meaningful token of a filename.
_NOISE_TOKENS = frozenset({
    "js", "mjs", "cjs", "min", "map", "bundle", "slim", "esm", "umd", "iife", "amd", "common",
    "prod", "production", "dev", "development", "debug", "pack", "packed", "dist", "src", "core",
    "full", "standalone", "browser",
})
_VERSION_TOKEN = re.compile(r"^v?\d[\d.]*$")
# A content-hash / fingerprint token (webpack/vite builds: jquery.min.8f2a9c.js). Requires a digit
# so real words that are coincidentally all-hex (facade, decade, deface) are NOT stripped.
_HASH_TOKEN = re.compile(r"^(?=.*\d)[0-9a-f]{6,}$")


def _meaningful_tokens(tokens: frozenset) -> frozenset:
    """Filename tokens excluding build/version/format/content-hash noise -- the identity tokens."""
    return frozenset(t for t in tokens
                     if t not in _NOISE_TOKENS and not _VERSION_TOKEN.match(t)
                     and not _HASH_TOKEN.match(t))

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
    meaningful = _meaningful_tokens(tokens)

    # 1) library-name match in the basename (precise: no substring false hits).
    #    - MULTI-token names (react-dom, owl.carousel, socket.io) keep the exact-subset match.
    #    - SINGLE-token names (chart, moment, ace, three, wow, ...) are common English words, so a
    #      mere subset match hits first-party files like `revenue-chart.js` / `user-prototype.js`
    #      and would hide a real finding there. Require the library token to be the SOLE meaningful
    #      (non-build/version) token instead. Multi-token names are checked first so the most
    #      specific label wins (jquery-migrate over jquery).
    for name, parts in _LIB_PARTS.items():
        # ...but a multi-token name whose parts are ALL build/format noise (only `core-js`, parts
        # {core, js}) must not match a first-party `core.js` -- require >=1 identity-bearing token.
        if len(parts) >= 2 and parts <= tokens and _meaningful_tokens(parts):
            return name
    for name, parts in _LIB_PARTS.items():
        if len(parts) == 1 and meaningful == parts:
            return name

    # 2) served from a conventional vendor/library directory
    if _VENDOR_PATH.search(path):
        return "vendor-dir"

    # 3) a leading minified library banner (only when content is available)
    if content and _BANNER.match(content[:256]):
        return "library-banner"

    return None
