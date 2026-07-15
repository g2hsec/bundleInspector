"""Download-surface classifier: strict, multi-signal recognition of FILE-download endpoints and
their specific risk (path traversal / file-IDOR / SSRF / forced-browsing), with deep coverage of
Korean enterprise (eGovFrame / Nexacro) parameter conventions.

DESIGN: graded by how a file is SERVED, not by the endpoint's name. CONFIRMED on a file signal
(keyword / strong param / office-archive ext / file-response mechanism); a bare download/export
keyword surfaces as POSSIBLE (verify) rather than being excluded, because a coupon/report download
often serves a barcode PDF/image. Non-destructive: never mutates a finding beyond
metadata['download_surface']."""

from __future__ import annotations

import pytest

from bundleInspector.core.download_surface import (
    annotate_download_surfaces,
    classify_download_surface,
    download_surfaces,
)
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
)


def _ep(url, *, query=None, body=None, snippet="", value_type="api_path"):
    md: dict = {}
    rc: dict = {}
    if query is not None:
        rc["query_params"] = dict.fromkeys(query, "x")
    if body is not None:
        rc["body"] = {"kind": "json", "shape": dict.fromkeys(body, "x")}
    if rc:
        md["request_contract"] = rc
    return Finding(
        rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.LOW,
        confidence=Confidence.MEDIUM, title=f"API: {url}", value_type=value_type,
        extracted_value=url, metadata=md,
        evidence=Evidence(file_url="https://x/app.js", file_hash="h", line=1, snippet=snippet),
    )


def _risk(url, **kw):
    d = classify_download_surface(_ep(url, **kw))
    return d["primary_risk"] if d else None


# ---------------------------------------------------------------- FALSE-POSITIVE TRAPS (critical)

@pytest.mark.parametrize("url,kw", [
    # abbreviated `...DownL` returns JSON here and lacks a full download keyword / file signal
    ("/couponDownL.do", {"body": ["itemCd"]}),          # 쿠폰 다운로드 (coupon list, JSON)
    ("${...}/couponDownL.do", {"body": ["itemCd"]}),
    ("/board/list.do", {"query": ["name", "pageIndex"]}),   # search by name, no download context
    ("/static/mall/js/app.js", {}),                          # static asset
    ("/images/logo.png", {}),                                # image asset
    ("/assets/report.pdf", {}),                              # a pdf but under an asset path
    ("/api/users.json", {}),                                 # REST JSON response, not a download
    ("/config/settings.xml", {}),                            # xml under non-download path
    ("/api/couponDownloadCount.do", {"query": ["goodsNo"]}), # "download" but a counter (NONFILE)
    ("/robots.txt", {}),
    # --- regressions found by adversarial verification (word-boundary / upload / narrowed weak kw) ---
    ("/cmm/fms/uploadFile.do", {"body": ["atchFileId"]}),    # UPLOAD (was: substring 'loadfile')
    ("/user/profileView.do", {"query": ["userId"]}),         # was: substring 'fileview'
    ("/ad/targetImage.do", {"query": ["campaignId"]}),       # was: substring 'getimage'
    ("/api/socialMedia.do", {"query": ["name"]}),            # 'media' is NOT a weak keyword
    ("/menu/dropDown.do", {"query": ["id"]}),                # 'down' is NOT a weak keyword
    ("/oauth/callback.do", {"query": ["callbackUrl"]}),      # callbackUrl is NOT SSRF/download
])
def test_false_positive_traps_are_NOT_classified(url, kw):
    assert classify_download_surface(_ep(url, **kw)) is None


@pytest.mark.parametrize("url,kw,risk", [
    ("/index.php", {"query": ["act", "file_srl"]}, "file_idor"),       # XpressEngine / Rhymix
    ("/bbs/download.php", {"query": ["bo_table", "wr_id", "no"]}, "file_idor"),  # gnuboard
    ("/cop/bbs/downloadBsnsFile.do", {"query": ["bsnsFileSn"]}, "file_idor"),    # eGov SI
    ("/api/download", {"query": ["objectKey"]}, "file_idor"),          # S3 object key
    ("/file/get.do", {"query": ["atchmnflGroupId"]}, "file_idor"),     # eGov file-group id
])
def test_completeness_additions_now_classify(url, kw, risk):
    d = classify_download_surface(_ep(url, **kw))
    assert d and d["primary_risk"] == risk


def test_output_is_deterministic_regardless_of_param_order():
    # descriptor param lists must be stable (built from sorted params, not a set)
    a = classify_download_surface(_ep("/FileDown.do", query=["fileSn", "atchFileId", "fileMngId"]))
    b = classify_download_surface(_ep("/FileDown.do", query=["fileMngId", "atchFileId", "fileSn"]))
    assert a["params"] == b["params"] == {"file_id": ["atchFileId", "fileMngId", "fileSn"]}
    assert a["note"] == b["note"]


# ---------------------------------------------------------------- Korean enterprise (eGov/Nexacro)

def test_egov_filedown_atchfileid_is_file_idor():
    # /cmm/fms/FileDown.do?atchFileId=FILE_00...&fileSn=0  -- the canonical eGovFrame download
    d = classify_download_surface(_ep("/cmm/fms/FileDown.do?atchFileId=FILE_000123&fileSn=0"))
    assert d and d["primary_risk"] == "file_idor"
    assert "atchFileId" in d["params"]["file_id"] and "fileSn" in d["params"]["file_id"]
    assert d["confidence"] == "high"  # strong keyword + strong param


@pytest.mark.parametrize("param,role,risk", [
    ("atchFileId", "file_id", "file_idor"),      # 첨부파일ID
    ("fileSn", "file_id", "file_idor"),          # 파일순번
    ("fileMngId", "file_id", "file_idor"),       # 파일관리ID
    ("nttFileId", "file_id", "file_idor"),
    ("fileNm", "file_name", "path_traversal"),   # 파일명 (Nm=名)
    ("orgnlFileNm", "file_name", "path_traversal"),   # 원본파일명
    ("streFileNm", "file_name", "path_traversal"),    # 저장파일명
    ("fileStreCours", "file_path", "path_traversal"), # 파일저장경로 (Cours=경로)
    ("filePath", "file_path", "path_traversal"),
    ("savePath", "file_path", "path_traversal"),
])
def test_korean_convention_params_map_to_correct_role_and_risk(param, role, risk):
    # a strong file param on ANY endpoint establishes a download surface (no keyword needed)
    d = classify_download_surface(_ep("/board/view.do", query=[param]))
    assert d, f"{param} should establish a download surface"
    assert d["primary_risk"] == risk
    assert param in d["params"][role]


# ---------------------------------------------------------------- risk classification

def test_traversal_from_filename_param():
    assert _risk("/common/getFile.do?fileNm=report.hwp") == "path_traversal"


def test_ssrf_from_url_param():
    # a STRONG url param (server-fetch shaped) establishes SSRF on its own
    assert _risk("/proxy/getImage.do?imageUrl=x") == "ssrf"
    assert _risk("/api/fetch.do?remoteUrl=http://x") == "ssrf"
    # a bare `url` counts only once a download context is established by a strong keyword
    assert _risk("/fileDownload.do?url=http://x") == "ssrf"
    # a weak keyword + a bare `url` is surfaced at the POSSIBLE tier (verify it's a server-side fetch)
    d = classify_download_surface(_ep("/download?url=http://internal"))
    assert d and d["certainty"] == "possible" and d["primary_risk"] == "ssrf"


def test_traversal_outranks_idor_when_both_present():
    d = classify_download_surface(_ep("/fileDown.do?atchFileId=1&fileNm=x.pdf"))
    assert d["risks"][0] == "path_traversal" and "file_idor" in d["risks"]


def test_forced_browsing_for_static_export_file():
    # a strong-ext file under a non-asset path, no params -> forced browsing / authz review
    assert _risk("/excel/members.xlsx") == "forced_browsing"
    assert _risk("/backup/db.sql.gz") == "forced_browsing"


def test_strong_keyword_without_params_is_authz_review():
    d = classify_download_surface(_ep("/downloadExcel.do", query=["searchKeyword"]))
    assert d and d["primary_risk"] == "authz_review"


@pytest.mark.parametrize("url", [
    "/cmm/fms/cfmsFileDown.do?atchFileId=X",   # Nexacro eGov integrated download
    "/egovFileDownload.do?atchFileId=X",
    "/comFileDown.do?fileId=1",
    "/board/excelDown.do?bbsId=1",
    "/getImage?fileId=123",
    "/attachDown.do?fileSn=2",
])
def test_strong_download_keywords_classify(url):
    assert classify_download_surface(_ep(url)) is not None


class TestGradedTiers_CouponDownloadsAreConsidered:
    """A coupon/report 'download' often serves a barcode PDF/image -> it must be surfaced, not
    hard-excluded. Graded: CONFIRMED when a file signal/mechanism is present; POSSIBLE (verify) when
    only a download keyword is."""

    def test_coupon_download_is_surfaced_as_possible(self):
        d = classify_download_surface(_ep("/event/couponDownload.do", query=["couponId"]))
        assert d and d["certainty"] == "possible" and d["confidence"] == "low"
        assert d["primary_risk"] == "file_idor"          # couponId is a selector in a dl context
        assert "verify" in d["note"].lower() or "POSSIBLE" in d["note"]

    def test_export_with_name_is_possible_traversal(self):
        d = classify_download_surface(_ep("/report/export.do", query=["name"]))
        assert d and d["certainty"] == "possible" and d["primary_risk"] == "path_traversal"

    def test_coupon_download_serving_a_file_is_CONFIRMED_via_mechanism(self):
        # responseType:'blob' proves it returns a FILE -> the coupon-PDF download IS a real surface
        d = classify_download_surface(_ep("/event/couponDownload.do", query=["couponId"],
                                          snippet="xhr.responseType = 'blob';"))
        assert d and d["certainty"] == "confirmed"
        assert d["signals"].get("mechanism")

    def test_mechanism_without_keyword_surfaces_as_possible(self):
        # a cert endpoint that createObjectURL's the response is a file download even with no
        # 'download' in its name -> surfaced (file_idor on certId). It stays POSSIBLE (not confirmed)
        # because the mechanism came from the shared snippet -- tying confirmation to a download
        # keyword avoids a neighbouring blob call upgrading a plain JSON API to CONFIRMED.
        d = classify_download_surface(_ep("/api/cert.do", query=["certId"],
                                          snippet="const url = URL.createObjectURL(await res.blob());"))
        assert d and d["certainty"] == "possible" and d["primary_risk"] == "file_idor"

    def test_download_of_a_static_export_is_confirmed(self):
        assert classify_download_surface(_ep("/download/data.csv"))["certainty"] == "confirmed"

    def test_nonfile_download_word_opts_out(self):
        # a "download count/agree" data endpoint is not a file, even at the possible tier
        assert classify_download_surface(_ep("/api/downloadAgree.do", query=["goodsNo"])) is None


def test_snippet_params_do_not_bleed_across_endpoints():
    # REGRESSION: params must come only from this endpoint's request_contract, never from the shared
    # snippet window -- a bland endpoint whose file params belong to a NEIGHBOURING call (here a real
    # file download sitting next to this coupon call) must NOT be classified.
    f = _ep("/board/proc.do", body=["itemCd"],
            snippet="$.fileDownload('/other.do', { atchFileId: id, fileSn: 0 });")
    assert classify_download_surface(f) is None


# ---------------------------------------------------------------- annotate + collect + robustness

def test_annotate_tags_only_downloads_and_counts():
    class R:
        findings = [
            _ep("/cmm/fms/FileDown.do?atchFileId=1"),   # download
            _ep("/couponDownL.do", body=["itemCd"]),  # NOT
            _ep("/getFile.do?fileNm=x.pdf"),            # download
        ]
    r = R()
    n = annotate_download_surfaces(r)
    assert n == 2
    tagged = [f for f in r.findings if (f.metadata or {}).get("download_surface")]
    assert len(tagged) == 2
    # additive-only: category/severity/value_type untouched
    assert all(f.category == Category.ENDPOINT for f in r.findings)
    surfaces = download_surfaces(r)
    assert surfaces[0][1]["primary_risk"] == "path_traversal"  # traversal sorts before file_idor


class TestOverfitRegressions:
    """From the over-fit audit -- generalize beyond the one target's eGov `.do` naming."""

    def test_imageUrl_is_not_unconditional_ssrf(self):
        # imageUrl on an ordinary save form (no download/fetch context) must NOT flag SSRF
        assert classify_download_surface(_ep("/member/save.do", query=["imageUrl", "nickNm"])) is None

    def test_download_boolean_flag_is_not_a_file_mechanism(self):
        f = _ep("/api/getConfig.do", query=["userId"], snippet="this.download = false; return d;")
        assert classify_download_surface(f) is None

    @pytest.mark.parametrize("url,kw,risk", [
        ("/api/files/123", {"query": ["id"]}, "file_idor"),   # plural REST collection (was missed)
        ("/attachments/456", {"query": ["id"]}, "file_idor"),
        ("/downloads/789", {"query": ["id"]}, "file_idor"),   # singular/plural cliff fixed
        ("/api/documents/12", {"query": ["id"]}, "file_idor"),
        ("/img/thumb", {"query": ["src"]}, "ssrf"),           # image-proxy SSRF (docstring's target)
        ("/proxy", {"query": ["url"]}, "ssrf"),
    ])
    def test_generalized_surfaces_now_classify(self, url, kw, risk):
        d = classify_download_surface(_ep(url, **kw))
        assert d and d["primary_risk"] == risk

    def test_id_suffix_generalizes_to_any_domain(self):
        # claimId is not in any curated e-commerce list; the camelCase id-suffix check catches it
        d = classify_download_surface(_ep("/downloadClaim.do", query=["claimId"]))
        assert d and d["primary_risk"] == "file_idor"

    def test_real_download_attribute_assignment_still_detected(self):
        f = _ep("/downloadReport.do", query=["seq"], snippet="a.download = fileName; a.click();")
        assert classify_download_surface(f) is not None


def test_end_to_end_through_the_real_endpoint_detector():
    """The classifier must read the params the endpoint detector actually produces (ajax `data` ->
    request_contract.body.shape). Proven through the full parse -> IR -> engine -> annotate path."""
    from bundleInspector.config import Config
    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.parser.js_parser import parse_js
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.rules.engine import RuleEngine

    src = (
        "function d(id, sn){ return $.ajax({ url: '/cmm/fms/FileDown.do', type: 'GET',"
        " data: { atchFileId: id, fileSn: sn } }); }\n"
        "function c(cd){ return $.ajax({ url: '/couponDownL.do', type: 'POST',"
        " data: { itemCd: cd } }); }\n"
    )
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules)
    eng.register_defaults()
    findings = list(eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h",
                                                    source_content=src)))

    class R:
        pass
    r = R()
    r.findings = findings
    annotate_download_surfaces(r)

    tagged = {f.extracted_value.split("?")[0].rsplit("/", 1)[-1]:
              (f.metadata or {}).get("download_surface")
              for f in findings if f.category == Category.ENDPOINT}
    fd = next((v for k, v in tagged.items() if k == "FileDown.do"), None)
    assert fd and fd["primary_risk"] == "file_idor"          # atchFileId/fileSn from ajax data
    coupon = next((v for k, v in tagged.items() if k == "couponDownL.do"), "absent")
    assert not coupon   # the coupon endpoint is present but NOT tagged as a file download


def test_non_endpoint_and_malformed_never_classify_or_raise():
    # non-endpoint category
    f = Finding(rule_id="r", category=Category.SINK, severity=Severity.LOW,
                confidence=Confidence.LOW, title="x", value_type="dom_html_sink",
                extracted_value="/download?fileNm=x", metadata={},
                evidence=Evidence(file_url="https://x/a.js", file_hash="h", line=1))
    assert classify_download_surface(f) is None

    class Bare:
        category = None
    assert classify_download_surface(Bare()) is None  # type: ignore[arg-type]

    for bad in ("", "not a url", "https://[bad", "${x}", "?=="):
        classify_download_surface(_ep(bad))  # must not raise
