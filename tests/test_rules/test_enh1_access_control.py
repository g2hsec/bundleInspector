"""enh1: client-side access-control gating detection (flagship).

Flags endpoint findings reachable ONLY behind a browser-side authorization check
(if(user.isAdmin){fetch(...)}, flags.canX && fetch(...), if(!hasRole())return; ...) --
the classic bypass surface. Purely additive: tags + raises severity of gated endpoints,
never drops a finding and never lowers severity. Offset-based containment keeps it correct
on minified single-line bundles where line ranges collapse.
"""

import pytest

from bundleInspector.config import Config
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.access_control import classify_guard
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category, Severity


def _endpoints(source: str, config: Config | None = None):
    result = parse_js(source)
    assert result.success
    ir = build_ir(result.ast, "f.js", "h")
    ctx = AnalysisContext(file_url="f.js", file_hash="h", source_content=source)
    engine = RuleEngine((config or Config()).rules)
    engine.register_defaults()
    return [f for f in engine.analyze(ir, ctx) if f.category == Category.ENDPOINT]


def _one(source: str, value: str, config: Config | None = None):
    matches = [f for f in _endpoints(source, config) if f.extracted_value == value]
    assert matches, f"expected endpoint {value!r} in {source!r}"
    return matches[0]


def _is_gated(f) -> bool:
    return "client_side_gated_endpoint" in f.tags and f.metadata.get("client_side_gated") is True


# --------------------------------------------------------------------------- positives


def test_positive_if_role_gated_high():
    f = _one(
        'function h(user){ if(user.isAdmin){ fetch("/api/v1/admin/users"); } }',
        "/api/v1/admin/users",
    )
    assert _is_gated(f)
    assert f.metadata["guard_kind"] == "role"
    assert f.metadata["guard_source"] == "if"
    assert f.metadata["guard_polarity"] == "positive"
    assert f.severity == Severity.HIGH  # role + HIGH confidence -> HIGH


def test_early_return_negative_guard_single_line():
    # Single-line: guarded region is everything after the if; offset-based containment
    # (line ranges collapse to empty here) must still catch it.
    f = _one(
        'function h(u){ if(!u.hasRole("admin")) return; axios.delete("/api/v1/users/42"); }',
        "/api/v1/users/42",
    )
    assert _is_gated(f)
    assert f.metadata["guard_source"] == "early_return"
    assert f.metadata["guard_polarity"] == "negative_early_return"
    assert f.metadata["guard_kind"] == "role"


def test_ternary_flag_gated_medium():
    f = _one(
        'function h(flags){ const r = flags.canDeleteUsers ? fetch("/api/v1/delete") : null; return r; }',
        "/api/v1/delete",
    )
    assert _is_gated(f)
    assert f.metadata["guard_source"] == "ternary"
    assert f.metadata["guard_kind"] == "generic-authz"
    assert f.severity == Severity.MEDIUM


def test_logical_and_permission_gated():
    f = _one(
        'function h(user){ user.permissions.canView && fetch("/api/v1/reports"); }',
        "/api/v1/reports",
    )
    assert _is_gated(f)
    assert f.metadata["guard_source"] == "logical"
    assert f.metadata["guard_kind"] == "permission"
    assert f.severity == Severity.HIGH


def test_entitlement_gated_high():
    f = _one(
        'function h(ctx){ if(ctx.entitlements.exportData){ fetch("/api/v1/export"); } }',
        "/api/v1/export",
    )
    assert _is_gated(f)
    assert f.metadata["guard_kind"] == "entitlement"
    assert f.severity == Severity.HIGH


def test_websocket_gated():
    f = _one(
        'function h(u){ if(u.role==="admin"){ new WebSocket("wss://rt.acme.io/admin"); } }',
        "wss://rt.acme.io/admin",
    )
    assert _is_gated(f)
    assert f.metadata["guard_kind"] == "role"


def test_nested_guards_pick_innermost_authz():
    # inner `if(ready)` is not an authz guard -> the role guard is the gating one.
    f = _one(
        'function h(u,ready){ if(u.isAdmin){ if(ready){ fetch("/api/v1/x"); } } }', "/api/v1/x"
    )
    assert _is_gated(f)
    assert f.metadata["guard_kind"] == "role"


def test_multiline_positive_gated_and_scope_recorded():
    src = (
        "function fetchUsers(user){\n"
        '  if (user.hasPermission("purge")) {\n'
        '    fetch("/api/v1/admin/purge");\n'
        "  }\n"
        "}"
    )
    f = _one(src, "/api/v1/admin/purge")
    assert _is_gated(f)
    assert f.metadata["guard_scope"] == "function:fetchUsers"
    assert f.metadata["guard_line"] == 2
    assert "purge" in f.metadata["guard_expr"] or "hasPermission" in f.metadata["guard_expr"]


# --------------------------------------------------------------------------- negatives (must NOT gate)


def test_negative_non_authz_conditions_stay_ungated():
    fs = _endpoints(
        'function h(res,i,n){ if(res.ok){ fetch("/api/v1/public"); } '
        'if(i<n){ fetch("/api/v1/loop"); } }'
    )
    for f in fs:
        assert not _is_gated(f), f.extracted_value
        assert f.severity == Severity.INFO


def test_negative_loading_state_stays_ungated():
    f = _one(
        'function h(state){ if(state.loading){ fetch("/api/v1/spinner"); } }', "/api/v1/spinner"
    )
    assert not _is_gated(f)


def test_negative_else_branch_not_gated():
    # The public call is in the else branch, not inside the authz-guarded consequent.
    f = _one(
        'function h(u){ if(u.isAdmin){ adminApi(); } else { fetch("/api/v1/public"); } }',
        "/api/v1/public",
    )
    assert not _is_gated(f)


def test_negative_call_after_guarded_block_multiline():
    # Precision test: the call sits AFTER the closing brace of the guarded block.
    src = (
        "function h(user){\n"
        "  if (user.isAdmin) {\n"
        "    adminApi();\n"
        "  }\n"
        '  fetch("/api/v1/public");\n'
        "}"
    )
    f = _one(src, "/api/v1/public")
    assert not _is_gated(f)


# --------------------------------------------------------------------------- classify_guard unit


@pytest.mark.parametrize(
    "tokens,expected",
    [
        (["isAdmin", "user.isAdmin"], "role"),
        (["hasRole", "role"], "role"),
        (["isSuperuser"], "role"),
        (["hasPermission", "permissions"], "permission"),
        (["acl", "grants"], "permission"),
        (["entitlements", "entitlementExport"], "entitlement"),
        (["isAuthorized"], "generic-authz"),
        (["canAccess"], "generic-authz"),
        (["canView"], "generic-authz"),
    ],
)
def test_classify_guard_kinds(tokens, expected):
    assert classify_guard(tokens) == expected


@pytest.mark.parametrize(
    "tokens",
    [
        ["cancel"],  # 'cancel' must NOT be read as the 'can' authz subtoken
        ["canvas"],
        ["res", "ok"],
        ["loading"],
        ["i", "n"],
        ["isValid"],
        ["featureBetaConsole", "feature"],
        ["flags", "toggle"],
        ["accessibility"],
        ["badminton"],
        ["data"],
        [],
    ],
)
def test_classify_guard_non_authz_returns_none(tokens):
    assert classify_guard(tokens) is None


# --------------------------------------------------------------------------- config + additivity


def test_config_disable_flag_suppresses_gating():
    cfg = Config()
    cfg.rules.client_side_gating_enabled = False
    f = _one(
        'function h(user){ if(user.isAdmin){ fetch("/api/v1/admin/users"); } }',
        "/api/v1/admin/users",
        config=cfg,
    )
    assert not _is_gated(f)
    assert f.severity == Severity.INFO  # unchanged when disabled


def test_config_target_severity_respected_for_generic_authorization():
    cfg = Config()
    cfg.rules.client_side_gating_severity = "low"
    f = _one(
        'function h(user){ if(user.canUseBeta){ fetch("/api/v1/beta"); } }',
        "/api/v1/beta",
        config=cfg,
    )
    assert _is_gated(f)
    # Generic authorization uses the configured target, which we lowered to "low".
    assert f.severity == Severity.LOW


def test_additive_never_drops_endpoints_or_lowers_severity():
    # Same endpoints must be present with/without the guard; gating only enriches.
    guarded = 'function h(u){ if(u.isAdmin){ fetch("/api/v1/thing"); } }'
    plain = 'function h(u){ fetch("/api/v1/thing"); }'
    gv = {f.extracted_value for f in _endpoints(guarded)}
    pv = {f.extracted_value for f in _endpoints(plain)}
    assert pv <= gv  # no endpoint lost by adding the guard
    g = _one(guarded, "/api/v1/thing")
    p = _one(plain, "/api/v1/thing")
    # gated severity must be >= ungated severity (never lowered)
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert order.index(g.severity) >= order.index(p.severity)
