"""Download-surface classification for discovered endpoints (presentation layer, non-destructive).

A *file*-download endpoint (serve/stream a file to the client) is a high-value attack surface:
  - path traversal / arbitrary file read   (`?fileName=../../../etc/passwd`)
  - broken access control / file IDOR       (`?atchFileId=FILE_000000000123&fileSn=0`)
  - SSRF via server-side fetch               (`?url=http://169.254.169.254/...`)
  - forced browsing to sensitive exports     (`/export/members.xlsx` reachable unauthenticated)

The endpoint detector already extracts these URLs, but only GENERICALLY (api_path/api_endpoint) --
it does not know a URL is a *file* download nor which parameter is the dangerous one. This module
adds that knowledge as metadata on the endpoint findings, AFTER detection, so it can never change
the detection set or perturb the detection-invariance gate (which runs RuleEngine.analyze directly,
never this path). It sets `metadata['download_surface']` and never mutates anything else.

DESIGN -- precision first (must not false-positive):
  A bare `download`/`export`/`down` token is NOT enough. In Korean e-commerce "쿠폰 다운로드"
  (`couponDownL.do`, body `itemCd`, JSON response) is a coupon claim, NOT a file download. A
  finding is classified as a file-download surface ONLY on a FILE-SPECIFIC signal:
    (1) a file-download KEYWORD in the path   (fileDown/getFile/atchFileDown/excelDown/...),
    (2) a STRONG file PARAMETER               (atchFileId/fileSn/fileNm/streFileNm/fileStreCours/...),
    (3) a document/archive/data EXTENSION     (pdf/xlsx/hwp/zip/csv/xml/sql/...),
  or a WEAK keyword (download/export) CORROBORATED by a file-ish parameter or extension. Weak,
  ambiguous parameters (`name`/`path`/`file`/`url`) contribute a risk ONLY once a download context
  is already established by a strong signal.

KOREAN ENTERPRISE CONVENTIONS (deep): eGovFrame (전자정부 표준프레임워크) and Nexacro/SI code use
romanized-Hangul parameter names. Recognized here (not just surface):
  - `Nm`  = 명(name)   -> fileNm, orgnlFileNm(원본파일명), streFileNm(저장파일명), saveFileNm
  - `Sn`  = 순번(seq)  -> fileSn(파일순번), atchFileSn
  - `Cours`/`Crs` = 경로(path) -> fileStreCours(파일저장경로), streFileCours
  - `Id/No/Seq`        -> atchFileId(첨부파일ID), fileMngId(파일관리ID), nttId(게시물ID)+fileSn
  - HWP/HWPX/EGG/ALZ   = Korean document/archive formats.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from bundleInspector.storage.models import Category


def _norm(name: str) -> str:
    """Normalize a parameter/token for lexicon lookup: lowercase, drop separators."""
    return re.sub(r"[\s_\-.]", "", (name or "").lower())


# ---------------------------------------------------------------------------------------------
# Parameter lexicons (normalized). Roles: file_id (IDOR), file_name / file_path / directory
# (traversal), url (SSRF). STRONG params are unambiguous and trigger classification on their own;
# CONTEXT params are ambiguous and only assign a risk once a download context is established.
# ---------------------------------------------------------------------------------------------
_FILE_ID_PARAMS = frozenset(_norm(x) for x in (
    # eGovFrame / Korean enterprise
    "atchFileId", "atchmnflId", "atchmnflGroupId", "atchmnflGrpId", "atchFileSn", "atchFileNo",
    "fileMngId", "fileMngNo", "fileGroupId", "fileGrpId", "nttFileId", "bbsFileId", "boardFileId",
    "bsnsFileSn",                                   # 업무파일순번 (SI attachment id)
    "file_srl", "fileSrl",                          # XpressEngine / Rhymix attachment id
    # generic
    "fileId", "fileNo", "fileSn", "fileSeq", "fileKey", "fileIdx", "fileNum",
    "attachId", "attachNo", "attachmentId", "attachSeq",
    "docId", "documentId", "docNo", "docSeq",
    "imgId", "imageId", "imgSn", "imageSeq", "photoId", "photoNo",
    "realFileId", "sysFileId", "physicalFileId", "storeFileId",
    "objectKey", "s3Key", "storageKey",            # cloud storage (S3 presigned / object)
))
_FILE_NAME_PARAMS = frozenset(_norm(x) for x in (
    # eGovFrame (romanized Hangul: Nm = 명/name)
    "fileNm", "orgnlFileNm", "orignlFileNm", "streFileNm", "saveFileNm", "realFileNm",
    "physicalFileNm", "uploadFileNm", "downFileNm", "attachFileNm", "orgFileNm", "orgnFileNm",
    # generic
    "fileName", "orgFileName", "orgnlFileName", "originalFileName", "realFileName",
    "saveFileName", "storeFileName", "downloadFileName", "attachFileName", "downFileName",
    "physicalName", "saveName", "storedName", "outputFileName",
))
_FILE_PATH_PARAMS = frozenset(_norm(x) for x in (
    # eGovFrame (Cours/Crs = 경로/path)
    "fileStreCours", "fileStreCrs", "streFileCours", "streFilePath", "streFilePth", "fileCours",
    # generic
    "filePath", "filePth", "fullPath", "realPath", "absolutePath", "physicalPath", "savePath",
    "storePath", "uploadPath", "downloadPath", "fileFullPath", "fileFullName", "targetPath",
    "srcPath", "sourcePath", "localPath", "serverPath",
))
_DIRECTORY_PARAMS = frozenset(_norm(x) for x in (
    "folderPath", "dirPath", "directory", "updDir", "uploadDir", "baseDir", "rootDir", "fileDir",
    "streCours", "streDir",
))
# URL params that imply a SERVER-side fetch (SSRF). `downloadUrl` (client redirect target) and
# `callbackUrl` (OAuth) are intentionally excluded -- they are not server-fetched.
_URL_PARAMS_STRONG = frozenset(_norm(x) for x in (
    "fileUrl", "imageUrl", "imgUrl", "remoteUrl", "targetUrl",
    "resourceUrl", "fetchUrl", "proxyUrl",
))

# Ambiguous, only meaningful inside an established download context.
_CTX_NAME_PARAMS = frozenset(_norm(x) for x in ("name", "file", "filename", "doc", "document",
                                                "attach", "attachment", "img", "image", "photo",
                                                "media", "content", "resource", "asset"))
_CTX_PATH_PARAMS = frozenset(_norm(x) for x in ("path", "pth", "dir", "folder", "location", "loc"))
_CTX_URL_PARAMS = frozenset(_norm(x) for x in ("url", "src", "link", "href", "uri", "target"))
_CTX_ID_PARAMS = frozenset(_norm(x) for x in ("id", "seq", "sn", "no", "num", "idx", "key"))

# ---------------------------------------------------------------------------------------------
# Path keyword lexicons. STRONG = compound, file-specific (trigger on their own). WEAK = ambiguous
# (need corroboration). Matched against the normalized path.
# ---------------------------------------------------------------------------------------------
_STRONG_KEYWORDS = tuple(_norm(x) for x in (
    "filedown", "downloadfile", "filedownload", "getfile", "viewfile", "readfile", "showfile",
    "streamfile", "servefile", "sendfile", "fetchfile", "retrievefile", "loadfile", "openfile",
    "atchfiledown", "attachdown", "attachmentdown", "downloadattach", "getattach", "attachfiledown",
    "exceldown", "downloadexcel", "exceldownload", "exportexcel", "pdfdown", "downloadpdf",
    "exportpdf", "csvdown", "exportcsv", "downloadcsv", "reportdown", "downloadreport",
    "imagedown", "imgdown", "downloadimage", "getimage", "viewimage", "imgview", "imageview",
    "photoview", "photodown", "getphoto", "filview", "fileview", "docview", "docdown", "getdoc",
    "downloaddoc", "hwpdown", "zipdown", "downloadzip", "blobdown", "mediadownload",
    "cfmsfiledown", "cfmsfiledownload", "egovfiledown", "commfiledown", "comfiledown",
    "cmmfiledown", "filemngdown", "filemanagedown", "downloadfilemng", "nexacrofiledown",
    "getdownload", "processdownload", "procfiledownload", "dofiledown",
    # CMS attachment-download scripts: gnuboard / Zeroboard `download.php`, JSP/ASP equivalents.
    # (`download.php` tokenizes to the run `downloadphp`, so this is boundary-anchored, not a bare
    #  `download` -- the coupon `couponDownload.do` never produces a `downloadphp`/... run.)
    "downloadphp", "downloadjsp", "downloadasp", "downloadaspx", "downloadcgi",
))
_WEAK_KEYWORDS = tuple(_norm(x) for x in (
    "download", "down", "export", "attach", "attachment", "stream", "media", "blob", "getbinary",
))
# An upload endpoint is not a download surface -- suppress it unless a strong DOWNLOAD keyword is
# also present (a combined up/down controller). Matched as whole path-word runs.
_UPLOAD_WORDS = frozenset((
    "upload", "fileupload", "uploadfile", "imageupload", "uploadimage", "imgupload", "uploadimg",
    "photoupload", "uploader", "uploadify", "multiupload",
))

# Extension tiers:
#  STRONG    -> office/archive/export/backup formats. Almost never a normal API response, so a path
#               ending in one is a download on its own.
#  SENSITIVE -> data/config/secret formats that ARE also common as REST responses/assets (.json,
#               .xml, .txt, .env, ...). These must NOT trigger a download alone (`/api/users.json`
#               is a REST call), but they corroborate a download keyword and are worth flagging then.
#  MEDIA     -> images/video: only in a download context and never under a static-asset path.
_STRONG_EXT = frozenset((
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "hwp", "hwpx", "rtf", "odt", "ods",
    "csv", "tsv", "zip", "rar", "7z", "tar", "gz", "tgz", "egg", "alz", "bak", "dump",
))
_SENSITIVE_EXT = frozenset((
    "txt", "json", "xml", "sql", "log", "dat", "conf", "ini", "properties", "yml", "yaml",
    "env", "pem", "key", "p12", "keystore", "jks", "war", "jar", "class",
))
_MEDIA_IMAGE_EXT = frozenset((
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tiff", "mp4", "mp3", "avi", "mov",
    "wmv", "flv", "wav", "mkv",
))

# Static-asset path prefixes -- never a download *API* (served by a web server, not app code).
_ASSET_PATH_RE = re.compile(
    r"/(?:static|assets?|dist|build|public|resources?|img|images?|css|js|scripts?|styles?|"
    r"fonts?|media|webjars|node_modules|vendor)/", re.IGNORECASE)

# Risk ordering (most severe first) + human-readable meaning.
_RISK_ORDER = ("path_traversal", "ssrf", "file_idor", "forced_browsing", "authz_review")
_RISK_SEV = {"path_traversal": "high", "ssrf": "high", "file_idor": "medium",
             "forced_browsing": "medium", "authz_review": "low"}


def _path_and_query(url: str) -> tuple[str, str]:
    """Split a discovered endpoint value into (path, query), stripping a `${...}` base-url prefix."""
    u = (url or "").strip()
    u = re.sub(r"^\$\{[^}]*\}", "", u)            # drop `${base}` template prefix
    u = re.sub(r"^[a-zA-Z][\w+.-]*://[^/]+", "", u)  # drop scheme://host
    path, _, query = u.partition("?")
    return path, query


def _file_ext(path: str) -> str:
    m = re.search(r"\.([A-Za-z0-9]{1,6})(?:$|[/?#])", path or "")
    return m.group(1).lower() if m else ""


def _path_runs(path: str) -> frozenset:
    """Boundary-anchored keyword-match tokens: every contiguous run of the path's words, split on
    separators AND camelCase humps. `profileView.do` -> {profile, view, do, profileview, viewdo,
    profileviewdo}, so keyword `fileview` does NOT match (only 'profile'/'view'/'profileview' exist)
    -- unlike a raw substring test where 'fileview' matches 'proFILEVIEW'. `download.php` -> includes
    'downloadphp'; `FileDown.do` -> includes 'filedown'."""
    words = [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", path or "")]
    runs: set = set()
    for i in range(len(words)):
        acc = ""
        for j in range(i, min(i + 6, len(words))):
            acc += words[j]
            runs.add(acc)
    return frozenset(runs)


def _collect_params(finding) -> set:
    """Parameter names PRECISELY attributed to this endpoint by the detector: the URL query string,
    request_contract query params + body shape, and named path params.

    Deliberately does NOT scan the code snippet: the snippet is a shared context window that can
    contain a NEIGHBOURING endpoint's parameters (e.g. a coupon call sitting next to a file-download
    call), which would mis-attribute file params and false-positive. request_contract already carries
    exactly this endpoint's params."""
    names: set = set()
    md = finding.metadata if isinstance(finding.metadata, dict) else {}

    _, query = _path_and_query(getattr(finding, "extracted_value", "") or "")
    for pair in query.split("&"):
        k = pair.split("=", 1)[0].strip()
        if k:
            names.add(k)

    rc = md.get("request_contract")
    if isinstance(rc, dict):
        qp = rc.get("query_params")
        if isinstance(qp, dict):
            names.update(qp.keys())
        body = rc.get("body")
        if isinstance(body, dict) and isinstance(body.get("shape"), dict):
            names.update(body["shape"].keys())

    idor = md.get("idor_params")
    if isinstance(idor, list):
        for p in idor:
            if isinstance(p, dict) and p.get("type") == "named" and p.get("segment"):
                names.add(str(p["segment"]).strip("{}:"))
    return names


def _role_of(name: str, *, in_context: bool) -> Optional[str]:
    """Classify a parameter into a role. Strong lexicons resolve unconditionally; ambiguous
    parameters resolve only when a download context is already established."""
    n = _norm(name)
    if n in _FILE_ID_PARAMS:
        return "file_id"
    if n in _FILE_NAME_PARAMS:
        return "file_name"
    if n in _FILE_PATH_PARAMS:
        return "file_path"
    if n in _DIRECTORY_PARAMS:
        return "directory"
    if n in _URL_PARAMS_STRONG:
        return "url"
    if in_context:
        if n in _CTX_NAME_PARAMS:
            return "file_name"
        if n in _CTX_PATH_PARAMS:
            return "file_path"
        if n in _CTX_URL_PARAMS:
            return "url"
        if n in _CTX_ID_PARAMS:
            return "file_id"
    return None


def classify_download_surface(finding) -> Optional[Dict[str, Any]]:
    """Return a download-surface descriptor for an endpoint finding, or None if it is not a
    file-download surface. Pure and defensive."""
    try:
        if getattr(finding, "category", None) != Category.ENDPOINT:
            return None
        raw = getattr(finding, "extracted_value", "") or ""
        path, _ = _path_and_query(raw)
        ext = _file_ext(path)
        runs = _path_runs(path)                       # boundary-anchored keyword tokens

        params = sorted(_collect_params(finding))     # sorted -> deterministic output ordering
        strong_roles = {p: _role_of(p, in_context=False) for p in params}
        strong_roles = {p: r for p, r in strong_roles.items() if r}

        strong_kw = next((k for k in _STRONG_KEYWORDS if k in runs), "")
        weak_kw = next((k for k in _WEAK_KEYWORDS if k in runs), "")
        strong_ext = ext in _STRONG_EXT               # standalone download signal
        any_file_ext = ext in _STRONG_EXT or ext in _SENSITIVE_EXT or ext in _MEDIA_IMAGE_EXT

        # An upload endpoint is the opposite of a download -- never classify it (unless a strong
        # DOWNLOAD keyword is also present, i.e. a combined up/down controller).
        if any(w in runs for w in _UPLOAD_WORDS) and not strong_kw:
            return None

        is_asset = bool(_ASSET_PATH_RE.search(path)) and not strong_kw and not strong_roles

        # A WEAK keyword ("download"/"export"/...) needs corroboration -- ONLY a real file extension
        # or a STRONG file param (never a bare `name`/`path`/`url`). This is what stops
        # "쿠폰 다운로드" (couponDownload.do?name=..., couponDownL.do body itemCd) from flagging.
        weak_ok = bool(weak_kw) and any_file_ext

        is_download = bool(strong_kw or strong_roles or strong_ext or weak_ok) and not is_asset
        if not is_download:
            return None

        # Download context established -> re-classify every parameter (ambiguous ones now count).
        by_role: Dict[str, List[str]] = {}
        for p in params:                              # params already sorted
            r = _role_of(p, in_context=True)
            if r:
                by_role.setdefault(r, []).append(p)
        roles = {p: r for r, ps in by_role.items() for p in ps}

        risks: List[str] = []
        if any(r in ("file_name", "file_path", "directory") for r in roles.values()):
            risks.append("path_traversal")
        if any(r == "url" for r in roles.values()):
            risks.append("ssrf")
        if any(r == "file_id" for r in roles.values()):
            risks.append("file_idor")
        if not risks:
            risks.append("forced_browsing" if any_file_ext else "authz_review")
        risks.sort(key=lambda r: _RISK_ORDER.index(r) if r in _RISK_ORDER else 99)

        confidence = ("high" if (strong_kw and (strong_roles or by_role)) else
                      "medium" if (strong_kw or strong_roles or strong_ext) else "low")

        return {
            "is_download": True,
            "confidence": confidence,
            "risks": risks,
            "primary_risk": risks[0],
            "risk_severity": _RISK_SEV.get(risks[0], "low"),
            "params": by_role,
            "signals": {k: v for k, v in (("keyword", strong_kw or weak_kw),
                                          ("extension", ext if any_file_ext else "")) if v},
            "note": _note(risks[0], by_role, ext),
        }
    except Exception:
        return None


def _note(primary: str, by_role: Dict[str, List[str]], ext: str) -> str:
    def _p(*roles):
        out = []
        for r in roles:
            out.extend(by_role.get(r, []))
        return ", ".join(f"`{x}`" for x in out)
    if primary == "path_traversal":
        return (f"File name/path parameter ({_p('file_name', 'file_path', 'directory')}) -> test "
                f"path traversal / arbitrary file read (../../, ..%2f, absolute path, NUL byte).")
    if primary == "ssrf":
        return (f"URL parameter ({_p('url')}) -> test SSRF: the server may fetch it "
                f"(internal hosts, 169.254.169.254 cloud metadata).")
    if primary == "file_idor":
        return (f"File-ID parameter ({_p('file_id')}) -> test IDOR / enumeration: increment or "
                f"replace the id to read other users' files.")
    if primary == "forced_browsing":
        return (f"Static {ext or 'file'} download -> verify server-side authorization; it may be "
                f"reachable without login (forced browsing).")
    return ("Download surface -> confirm server-side authorization, file-type restriction, and "
            "rate-limiting.")


def annotate_download_surfaces(report) -> int:
    """Tag endpoint findings that are file-download surfaces with metadata['download_surface'].
    In place, additive-only; returns the count tagged. Never raises."""
    n = 0
    for f in getattr(report, "findings", []) or []:
        try:
            desc = classify_download_surface(f)
        except Exception:
            desc = None
        if desc:
            md = f.metadata if isinstance(f.metadata, dict) else {}
            md["download_surface"] = desc
            f.metadata = md
            n += 1
    return n


# Console/HTML helpers ------------------------------------------------------------------------

_RISK_LABEL = {"path_traversal": "path-traversal", "ssrf": "SSRF", "file_idor": "file-IDOR",
               "forced_browsing": "forced-browsing", "authz_review": "authz-review"}


def risk_label(risk: str) -> str:
    return _RISK_LABEL.get(risk, risk)


def download_surfaces(report) -> List[tuple]:
    """(finding, descriptor) for every tagged download surface, most-severe risk first."""
    out = []
    for f in getattr(report, "findings", []) or []:
        md = f.metadata if isinstance(f.metadata, dict) else {}
        d = md.get("download_surface")
        if isinstance(d, dict):
            out.append((f, d))
    out.sort(key=lambda fd: _RISK_ORDER.index(fd[1]["primary_risk"])
             if fd[1]["primary_risk"] in _RISK_ORDER else 99)
    return out
