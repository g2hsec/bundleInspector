"""Detection additions: cloud-metadata (IMDS) / link-local SSRF targets in DomainDetector, and
source-map disclosure directives in DebugDetector. High-signal, exact-literal, low-FP."""

from __future__ import annotations

import pytest

from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.detectors.debug import DebugDetector
from bundleInspector.rules.detectors.domains import DomainDetector


def _run(detector, src):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=src)
    return list(detector.match(ir, ctx))


# ------------------------------------------------------------------ cloud metadata / link-local


def _types(results):
    return {r.value_type for r in results}


def test_imds_ip_is_high_severity_single_finding():
    res = _run(
        DomainDetector(),
        'var u="http://169.254.169.254/latest/meta-data/iam/security-credentials/";',
    )
    meta = [r for r in res if r.value_type == "cloud_metadata_ip"]
    assert len(meta) == 1  # specific-before-broad dedups (no link_local double-emit)
    assert meta[0].severity.name == "HIGH"
    assert meta[0].extracted_value == "169.254.169.254"
    assert "link_local_ip" not in _types(res)


def test_link_local_non_imds_is_medium():
    res = _run(DomainDetector(), 'var u="http://169.254.10.5/x";')
    ll = [r for r in res if r.value_type == "link_local_ip"]
    assert ll and ll[0].severity.name == "MEDIUM"


def test_gcp_metadata_host_classified_specifically():
    res = _run(DomainDetector(), 'fetch("http://metadata.google.internal/computeMetadata/v1/");')
    assert "gcp_metadata_host" in _types(res)
    assert "internal_domain" not in _types(res)  # specific pattern wins over broad `.internal`


@pytest.mark.parametrize(
    "ip,vt",
    [
        ("10.0.0.5", "private_ip_10"),
        ("192.168.1.1", "private_ip_192"),
        ("127.0.0.1", "loopback_ip"),
    ],
)
def test_existing_private_ip_classification_unchanged(ip, vt):
    res = _run(DomainDetector(), f'var h="{ip}";')
    assert vt in _types(res)


# ------------------------------------------------------------------ source-map disclosure


def test_source_map_directive_detected():
    res = _run(DebugDetector(), "console.log(1);\n//# sourceMappingURL=app.min.js.map")
    sm = [r for r in res if r.value_type == "source_map_reference"]
    assert len(sm) == 1
    assert sm[0].extracted_value == "app.min.js.map"


@pytest.mark.parametrize(
    "src",
    [
        "var s = '//# sourceMappingURL=' + name;",  # inside a string literal, not a line directive
        "// a normal comment about sourceMappingURL handling",
    ],
)
def test_source_map_no_false_positive(src):
    res = _run(DebugDetector(), src)
    assert not any(r.value_type == "source_map_reference" for r in res), src


def test_legacy_at_directive_detected():
    res = _run(DebugDetector(), "x=1;\n//@ sourceMappingURL=/static/app.js.map")
    assert any(r.value_type == "source_map_reference" for r in res)
