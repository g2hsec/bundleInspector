"""Download-surface classifier: strict, multi-signal recognition of FILE-download endpoints and
their specific risk (path traversal / file-IDOR / SSRF / forced-browsing), with deep coverage of
Korean enterprise (eGovFrame / Nexacro) parameter conventions.

INVARIANT: precision first -- a bare `download`/`export` keyword must NEVER classify (Korean
"쿠폰 다운로드" = a coupon claim, not a file). A finding is a file download only on a file-specific
signal. Non-destructive: never mutates a finding beyond metadata['download_surface']."""

from __future__ import annotations

import pytest

from bundleInspector.storage.models import (
    Finding, Evidence, Category, Severity, Confidence,
)
from bundleInspector.core.download_surface import (
    classify_download_surface, annotate_download_surfaces, download_surfaces,
)


def _ep(url, *, query=None, body=None, snippet="", value_type="api_path"):
    md: dict = {}
    rc: dict = {}
    if query is not None:
        rc["query_params"] = {k: "x" for k in query}
    if body is not None:
        rc["body"] = {"kind": "json", "shape": {k: "x" for k in body}}
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
    ("/couponDownL.do", {"body": ["itemCd"]}),          # 쿠폰 다운로드 (coupon claim, JSON)
    ("/couponDownload.do", {"body": ["itemCd"]}),       # full word "download" -- still a coupon
    ("${...}/couponDownL.do", {"body": ["itemCd"]}),
    ("/board/list.do", {"query": ["name", "pageIndex"]}),   # search by name, no download context
    ("/static/mall/js/app.js", {}),                          # static asset
    ("/images/logo.png", {}),                                # image asset
    ("/assets/report.pdf", {}),                              # a pdf but under an asset path
    ("/api/users.json", {}),                                 # REST JSON response, not a download
    ("/config/settings.xml", {}),                            # xml under non-download path
    ("/api/downloadCount.do", {"query": ["goodsNo"]}),       # "download" but a counter, no file sig
    ("/robots.txt", {}),
    # --- regressions found by adversarial verification ---
    ("/cmm/fms/uploadFile.do", {"body": ["atchFileId"]}),    # UPLOAD (was: substring 'loadfile')
    ("/user/profileView.do", {"query": ["userId"]}),         # was: substring 'fileview'
    ("/ad/targetImage.do", {"query": ["campaignId"]}),       # was: substring 'getimage'
    ("/event/couponDownload.do", {"query": ["name"]}),       # weak kw + bare 'name' (coupon!)
    ("/api/socialMedia.do", {"query": ["name"]}),            # weak 'media' + bare 'name'
    ("/report/export.do", {"query": ["name"]}),              # weak 'export' + bare 'name'
    ("/menu/dropDown.do", {"query": ["id"]}),                # 'down' word, no file signal
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
    # ...but a weak keyword + a bare `url` alone must NOT classify (precision guard)
    assert classify_download_surface(_ep("/download?url=http://internal")) is None


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


def test_weak_keyword_needs_corroboration():
    # "download" + a file-ish extension corroborates; "download" + itemCd does not
    assert classify_download_surface(_ep("/download/data.csv")) is not None
    assert classify_download_surface(_ep("/download.do", body=["itemCd"])) is None


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


def test_end_to_end_through_the_real_endpoint_detector():
    """The classifier must read the params the endpoint detector actually produces (ajax `data` ->
    request_contract.body.shape). Proven through the full parse -> IR -> engine -> annotate path."""
    from bundleInspector.parser.js_parser import parse_js
    from bundleInspector.parser.ir_builder import build_ir
    from bundleInspector.rules.engine import RuleEngine
    from bundleInspector.rules.base import AnalysisContext
    from bundleInspector.config import Config

    src = (
        "function d(id, sn){ return $.ajax({ url: '/cmm/fms/FileDown.do', type: 'GET',"
        " data: { atchFileId: id, fileSn: sn } }); }\n"
        "function c(cd){ return $.ajax({ url: '/couponDownL.do', type: 'POST',"
        " data: { itemCd: cd } }); }\n"
    )
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    eng = RuleEngine(Config().rules); eng.register_defaults()
    findings = list(eng.analyze(ir, AnalysisContext(file_url="f.js", file_hash="h",
                                                    source_content=src)))

    class R:
        pass
    r = R(); r.findings = findings
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
