"""Regression locks for the batch-4 contained DQ backlog fixes (E01/E06/T02/T03/O04/O05/D01/D02/
D05/P07/H05/R06/R07). Secret-like values are fake samples used to verify behavior, not live creds."""

from __future__ import annotations

from pathlib import Path

from bundleInspector.config import Config, RuleConfig
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.storage.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Report,
    RiskTier,
    Severity,
)


def _ir_ctx(src: str):
    ir = build_ir(parse_js(src).ast, "f.js", "h")
    return ir, AnalysisContext(file_url="f.js", file_hash="h", source_content=src)


def _endpoint_contracts(src: str, cfg=None):
    from bundleInspector.rules.detectors.endpoints import EndpointDetector
    ir, ctx = _ir_ctx(src)
    det = EndpointDetector(cfg) if cfg is not None else EndpointDetector()
    out = []
    for f in det.match(ir, ctx):
        c = (f.metadata or {}).get("request_contract")
        if c:
            out.append(c)
    return out


# ---------------------------------------------------------------- DQ-E01 dedup best-pick

def test_dqe01_dedup_keeps_richest_contract_order_independent():
    """Distinct contracts survive and the richer occurrence is retained regardless of order."""
    bare_first = ('fetch("/api/users",{method:"POST"});'
                  'fetch("/api/users",{method:"POST",headers:{Authorization:"Bearer t"},body:JSON.stringify({n:1})});')
    rich_first = ('fetch("/api/users",{method:"POST",headers:{Authorization:"Bearer t"},body:JSON.stringify({n:1})});'
                  'fetch("/api/users",{method:"POST"});')
    for src in (bare_first, rich_first):
        cs = [c for c in _endpoint_contracts(src) if c["url"] == "/api/users"]
        assert len(cs) == 2
        assert any(c["auth"] and c["body"]["kind"] == "json" for c in cs)
        assert any(not c["auth"] and c["body"]["kind"] == "none" for c in cs)


def test_dqe01_exact_duplicate_contract_occurrences_still_collapse():
    src = (
        'fetch("/api/users",{method:"POST",headers:{Authorization:"Bearer t"}});'
        'fetch("/api/users",{method:"POST",headers:{Authorization:"Bearer t"}});'
    )

    cs = [c for c in _endpoint_contracts(src) if c["url"] == "/api/users"]

    assert len(cs) == 1
    assert cs[0]["auth"]


# ---------------------------------------------------------------- DQ-E06 axios.delete body

def test_dqe06_axios_delete_recovers_body():
    cs = _endpoint_contracts('axios.delete("/api/users/5",{data:{reason:"x"},headers:{Authorization:"Bearer t"}});')
    assert cs and cs[0]["method"] == "DELETE"
    assert cs[0]["body"]["kind"] == "json"


# ---------------------------------------------------------------- DQ-T02 / T03 taint

def _taint_count(src: str) -> int:
    from bundleInspector.rules.detectors.taint import TaintFlowDetector
    ir, ctx = _ir_ctx(src)
    return len(list(TaintFlowDetector().match(ir, ctx)))


def test_dqt02_arbitrary_receiver_not_a_source():
    assert _taint_count('function r(model){ document.getElementById("x").innerHTML = model.target.value; }') == 0
    assert _taint_count('function r(calc){ document.getElementById("x").innerHTML = calc.val(); }') == 0
    assert _taint_count('el.addEventListener("input", function(e){ box.innerHTML = e.target.value; });') >= 1
    assert _taint_count('box.innerHTML = $("#x").val();') >= 1


def test_dqt03_nav_suppression_considers_all_tainted_operands():
    assert _taint_count("location.href = location.pathname + location.hash;") >= 1
    assert _taint_count("location.href = `${location.pathname}${location.hash}`;") >= 1
    assert _taint_count('function r(e){ location.href = location.pathname + e.target.value; }') >= 1
    assert _taint_count("location.href = location.pathname;") == 0


# ---------------------------------------------------------------- DQ-O04 output filters

def test_dqo04_output_filters_apply_min_severity_and_tier():
    from bundleInspector.cli import _apply_output_filters

    def mk(sev, tier):
        f = Finding(rule_id="r", category=Category.ENDPOINT, severity=sev, confidence=Confidence.LOW,
                    title="t", description="d", extracted_value="v",
                    evidence=Evidence(file_url="f", file_hash="h", line=1))
        f.risk_tier = tier
        return f

    def run(min_sev, min_tier):
        rep = Report(findings=[mk(Severity.INFO, RiskTier.P3), mk(Severity.HIGH, RiskTier.P1),
                               mk(Severity.MEDIUM, None)])
        cfg = Config()
        cfg.output.min_severity = min_sev
        cfg.output.min_risk_tier = min_tier
        rendered = _apply_output_filters(rep, cfg)
        assert len(rep.findings) == 3          # DQ-O04: the ORIGINAL report is NOT mutated
        return len(rendered.findings)

    assert run("info", "P3") == 3
    assert run("high", "P3") == 1
    assert run("info", "P1") == 2


def test_dqo04_output_filter_does_not_weaken_fail_on_gate():
    """The output verbosity filter must not remove findings from the --fail-on CI gate's view."""
    from bundleInspector.cli import _apply_output_filters

    f = Finding(rule_id="x", category=Category.ENDPOINT, severity=Severity.HIGH,
                confidence=Confidence.HIGH, title="t", description="d", extracted_value="v",
                evidence=Evidence(file_url="f.js", file_hash="h", line=1))
    f.risk_tier = RiskTier.P1
    rep = Report(findings=[f])
    cfg = Config()
    cfg.output.min_severity = "critical"       # would hide the HIGH finding from the RENDERED report
    rendered = _apply_output_filters(rep, cfg)
    assert rendered.findings == []             # rendered report is filtered
    assert rep.findings == [f]                 # but the gate still sees the HIGH finding


# ---------------------------------------------------------------- DQ-O05 endpoint contract flags

def test_dqo05_endpoint_extract_flags_honored():
    src = 'fetch("/api/users?token=abc",{headers:{Authorization:"Bearer t"}});'

    def contract(cfg):
        cs = _endpoint_contracts(src, cfg)
        return cs[0] if cs else {}

    assert contract(RuleConfig())["headers"]
    assert contract(RuleConfig(extract_headers=False))["headers"] == {}
    assert contract(RuleConfig(extract_parameters=False))["query_params"] == {}


# ---------------------------------------------------------------- DQ-D01 route sensitivity

def test_dqd01_sensitive_is_segment_not_substring():
    from bundleInspector.rules.detectors.routes import RouteDetector
    d = RouteDetector()
    assert d._is_sensitive("/admin") and d._is_sensitive("/account") and d._is_sensitive("/user-settings")
    assert not d._is_sensitive("/accountants")
    assert not d._is_sensitive("/management")
    assert not d._is_sensitive("/configuration")


# ---------------------------------------------------------------- DQ-D02 uploads

def _upload_types(src: str):
    from bundleInspector.rules.detectors.uploads import FileUploadDetector
    ir, ctx = _ir_ctx(src)
    return [f.value_type for f in FileUploadDetector().match(ir, ctx)]


def test_dqd02_compiled_jsx_file_input_detected():
    assert "file_input" in _upload_types('jsx("input",{type:"file",accept:".jpg",onChange:h});')
    assert "file_input" in _upload_types('React.createElement("input",{type:"file",onChange:h});')


def test_dqd02_generic_allowedtypes_role_list_not_flagged():
    assert _upload_types('const perms = {allowedTypes:["admin","editor","viewer"]};') == []
    assert "client_side_file_validation" in _upload_types('const v = {allowedTypes:["jpg","png"]};')
    assert "client_side_file_validation" in _upload_types('const v = {allowedExt:["jpg"],maxSize:1};')


def test_dqd02_walk_node_cap_raised():
    from bundleInspector.rules.detectors import uploads
    assert uploads._MAX_WALK_NODES >= 1_000_000


# ---------------------------------------------------------------- DQ-D05 flags

def _flag_results(src: str):
    from bundleInspector.rules.detectors.flags import FlagDetector
    ir, ctx = _ir_ctx(src)
    return [(f.value_type, f.extracted_value, (f.metadata or {}).get("sdk")) for f in FlagDetector().match(ir, ctx)]


def test_dqd05_prose_not_a_flag_but_key_is():
    assert _flag_results('const m = "Run the experiment now and toggle it";') == []
    assert any(vt == "feature_flag" for vt, _, _ in _flag_results('const k = "feature_flag_new_checkout";'))


def test_dqd05_sdk_provenance_from_imports():
    res = _flag_results('import LD from "launchdarkly-js-client-sdk"; const c=LD.initialize(k); c.variation("my-flag", false);')
    assert any(vt == "flag_sdk" and sdk == "launchdarkly" and ev == "my-flag" for vt, ev, sdk in res)
    assert _flag_results('const t = calc.variation("x");') == []


# ---------------------------------------------------------------- DQ-P07 sourcemap generated coords

def test_dqp07_sourcemap_uses_restored_generated_coords():
    import inspect

    from bundleInspector.core import asset_analyzer
    src = inspect.getsource(asset_analyzer.AssetAnalyzer._apply_mappings)
    # the sourcemap lookup passes the LineMapper-restored generated coords, not the raw finding coords
    assert "gen_line" in src and "gen_col" in src
    flat = "".join(src.split())
    assert "get_original_position(sourcemap,gen_line,gen_col" in flat
    assert "get_original_position(sourcemap,finding.evidence.line" not in flat


# ---------------------------------------------------------------- DQ-H05 download surface

def _dl(url: str):
    from bundleInspector.core.download_surface import classify_download_surface
    f = Finding(rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.INFO,
                confidence=Confidence.HIGH, title="e", description="d", extracted_value=url,
                evidence=Evidence(file_url="f.js", file_hash="h", line=1))
    d = classify_download_surface(f)
    return None if d is None else d.get("certainty")


def test_dqh05_mutation_endpoint_not_download_fp():
    assert _dl("/document/update?docId=1") is None
    assert _dl("/document/delete?docId=1") is None
    assert _dl("/getFile.do?docId=1") == "confirmed"
    assert _dl("/cmm/fms/FileDown.do?atchFileId=1") == "confirmed"


def test_dqh05_download_target_log_vs_fused_history():
    assert _dl("/download/log") == "possible"
    assert _dl("/downloadHistory.do?userId=1") is None


# ---------------------------------------------------------------- DQ-R06 shipped ruleset samples

def test_dqr06_private_ip_octet_range_and_flag_key_context():
    import re

    import yaml
    base = Path(__file__).resolve().parents[1] / "examples" / "yaml-configs" / "rulesets" / "rules"
    ip = [r for r in yaml.safe_load(open(base / "domains.yml", encoding="utf-8"))["rules"]
          if r["id"] == "DOM_PRIVATE_IP"][0]["matcher"]["pattern"]
    rx = re.compile(ip)
    assert not rx.search("10.999.999.999") and not rx.search("172.32.0.1")
    assert rx.search("10.0.0.1") and rx.search("192.168.1.100") and rx.search("172.16.0.1")
    ff = [r for r in yaml.safe_load(open(base / "feature_flags.yml", encoding="utf-8"))["rules"]
          if r["id"] == "FF_FLAG_KEY_LITERAL"][0]["matcher"]["pattern"]
    frx = re.compile(ff)
    assert not frx.search('<Toggle label="SaveButton">')
    m = frx.search('flag("new_checkout")')
    assert m and m.group(2) == "new_checkout"


# ---------------------------------------------------------------- DQ-R07 meta reconciliation

def test_dqr07_meta_no_unimplemented_pack_fields():
    import yaml
    meta = Path(__file__).resolve().parents[1] / "examples" / "yaml-configs" / "rulesets" / "meta.yml"
    doc = yaml.safe_load(open(meta, encoding="utf-8"))
    assert "requires" not in (doc.get("ruleset") or {})
    assert "defaults" not in doc


# ================================================================ adversarial-round refinements

def test_dqt02_cached_jquery_sources_recovered_and_fps_suppressed():
    """Cached-jQuery receivers stay sources; arbitrary/framework receivers are suppressed."""
    assert _taint_count('App.prototype.r = function(){ var v=this.$input.val(); this.el.innerHTML=v; };') >= 1
    assert _taint_count('function f(){ var input=$("#x"); document.body.innerHTML=input.val(); }') >= 1
    assert _taint_count('el.addEventListener("input", function(e){ box.innerHTML = e.target.value; });') >= 1
    # arbitrary / framework receivers are NOT sources
    assert _taint_count('function r(model){ document.getElementById("x").innerHTML = model.target.value; }') == 0
    assert _taint_count('function r(config){ document.body.innerHTML = config.settings.target.value; }') == 0
    assert _taint_count('function h(){ el.innerHTML = foo.$q.val(); }') == 0           # $q is not jQuery
    assert _taint_count('function h(){ el.innerHTML = this.$config.data("k"); }') == 0  # $config is not jQuery


def test_dqt03_nav_finding_displays_unsafe_operand():
    """An open-redirect finding fed by pathname+hash must display the attacker-controllable hash."""
    from bundleInspector.rules.detectors.taint import TaintFlowDetector
    ir, ctx = _ir_ctx("location.href = location.pathname + location.hash;")
    fs = list(TaintFlowDetector().match(ir, ctx))
    assert fs
    blob = " ".join(str(getattr(f, "extracted_value", "")) + " " + str(f.metadata or {}) for f in fs).lower()
    assert "hash" in blob


def test_dqd01_camelcase_sensitive_route():
    from bundleInspector.rules.detectors.routes import RouteDetector
    d = RouteDetector()
    assert d._is_sensitive("/adminPanel") and d._is_sensitive("/superAdmin") and d._is_sensitive("/debugConsole")
    assert not d._is_sensitive("/accountants") and not d._is_sensitive("/management")


def test_dqd05_sdk_import_does_not_flag_generic_methods():
    """A generic .getValue()/.isEnabled() must NOT be flagged just because a flag SDK is imported."""
    res = _flag_results('import LD from "launchdarkly-js-client-sdk"; state$.getValue(); this.plugin.isEnabled();')
    assert [r for r in res if r[0] == "flag_sdk"] == []
    # a vendor-distinct read still fires
    assert any(r[0] == "flag_sdk" for r in _flag_results('import LD from "launchdarkly-js-client-sdk"; c.variation("f");'))


def test_dqd05_config_endpoint_requires_absolute_path():
    # an absolute config path is a config_endpoint; a relative route / require / asset path is not
    assert any(vt == "config_endpoint" for vt, _, _ in _flag_results('fetch("/api/flags");'))
    assert all(vt != "config_endpoint" for vt, _, _ in _flag_results('const routes=[{path:"dashboard/settings"}];'))
    assert all(vt != "config_endpoint" for vt, _, _ in _flag_results('var a=require("./config");'))


def test_dqd02_var_form_allowlist_and_no_object_fp():
    # const allowedTypes = [ext...] (declarator form) is corroborated by its values
    assert "client_side_file_validation" in _upload_types(
        'const allowedTypes = ["jpg","png"]; export function f(n){return allowedTypes.includes(n);}')
    # a filesystem/config {type:"file", files/path} object is NOT a file input (no specific attr)
    assert "file_input" not in _upload_types('var a = { type:"file", files:[1,2], id:3 };')
    assert "file_input" not in _upload_types('var n = { type:"file", path:"/x", name:"y" }; var fd=new FormData();')


def test_dqp07_identity_mapper_preserves_column():
    from bundleInspector.normalizer.line_mapping import LineMapper, LineMapping
    idm = LineMapper.identity("a\nb\nc\n")
    assert idm.get_original(1, 12) == (1, 12)                 # column preserved (was dropped to 0)
    m = LineMapper()
    m.add_mapping(LineMapping(original_line=10, original_column=0, normalized_line=1, normalized_column=0))
    m.add_mapping(LineMapping(original_line=20, original_column=100, normalized_line=1, normalized_column=40))
    assert m.get_original(1, 5)[0] == 10 and m.get_original(1, 50)[0] == 20   # P09 line selection intact
    assert m.get_original(1, 50) == (20, 110)                 # intra-segment column offset applied


def test_dqh05_substring_and_action_noun_not_over_opted_out():
    assert _dl("/catalogDownload?category=1") == "possible"   # 'log' substring, not a token
    assert _dl("/catalog/download") == "possible"
    assert _dl("/downloadRegisterForm?name=x") == "possible"  # 'register' in object noun, not head
    assert _dl("/exportSaveDataSheet") == "possible"          # 'save' in object noun
    # mutation-head endpoints still opt out
    assert _dl("/document/update?docId=1") is None
    assert _dl("/download/log") == "possible"                 # standalone target still surfaces


def test_dqr06_flag_key_allows_mixed_case_and_digit_lead():
    import re

    import yaml
    base = Path(__file__).resolve().parents[1] / "examples" / "yaml-configs" / "rulesets" / "rules"
    ff = [r for r in yaml.safe_load(open(base / "feature_flags.yml", encoding="utf-8"))["rules"]
          if r["id"] == "FF_FLAG_KEY_LITERAL"][0]["matcher"]["pattern"]
    frx = re.compile(ff)
    for s, exp in [('flag("darkMode")', "darkMode"), ('featureFlag("enableNewCheckout")', "enableNewCheckout"),
                   ('flag("DARK_MODE")', "DARK_MODE"), ('flag("2fa_enabled")', "2fa_enabled")]:
        m = frx.search(s)
        assert m and m.group(2) == exp
    assert not frx.search('<Toggle label="SaveButton">')      # JSX component tag still rejected


# ================================================================ round-2 refinement locks

def test_dqt02_r2_plain_target_var_and_framework_prop_not_sources():
    # a plain `const target = ...` is NOT an event target
    assert _taint_count('function h(){ const target = getConfig(); el.innerHTML = target.value; }') == 0
    # $-prefixed framework services ($q/$http/$scope) are NOT jQuery
    assert _taint_count('function h(){ el.innerHTML = foo.$q.val(); }') == 0
    assert _taint_count('function h(){ el.innerHTML = this.$scope.data("k"); }') == 0


def test_dqd05_r2_generic_read_scoped_to_sdk_client():
    # a generic getValue is a flag read ONLY on a var bound to an SDK client
    res = _flag_results('import {getClient} from "configcat-js"; const cc=getClient("k"); const s=cc.getValue("new_checkout",false);')
    assert any(vt == "flag_sdk" and sdk == "configcat" and ev == "new_checkout" for vt, ev, sdk in res)
    # RxJS-style .getValue()/.isEnabled() on non-client receivers is NOT flagged even with an SDK import
    assert [r for r in _flag_results('import LD from "launchdarkly-js-client-sdk"; state$.getValue(); this.plugin.isEnabled();')
            if r[0] == "flag_sdk"] == []


def test_dqd02_r2_single_ext_collision_not_upload():
    # a single word that merely coincides with an extension does not flip a role/enum list
    assert _upload_types('const allowedTypes=["zip","home","work"];') == []
    assert _upload_types('const allowedTypes=["doc","video","audio"];') == []
    assert "client_side_file_validation" in _upload_types('const allowedTypes=["jpg","png"];')


def test_dqh05_r2_noun_verb_mutation_opted_out():
    # <noun><verb> RPC mutations (documentDelete, fileUpdate, attachDelete) are opted out...
    assert _dl("/document/documentDelete?docId=5") is None
    assert _dl("/files/fileUpdate?id=1") is None
    assert _dl("/attachments/attachDelete?id=1") is None
    # ...while a download head verb over an action-word object noun still surfaces
    assert _dl("/downloadRegisterForm?name=x") == "possible"
    assert _dl("/exportSaveDataSheet") == "possible"


def test_dqd01_r2_glued_lowercase_and_no_fp():
    from bundleInspector.rules.detectors.routes import RouteDetector
    d = RouteDetector()
    assert d._is_sensitive("/adminpanel") and d._is_sensitive("/superadmin") and d._is_sensitive("/sysadmin")
    assert not d._is_sensitive("/accountants") and not d._is_sensitive("/configuration") and not d._is_sensitive("/staffing")


def test_dqr06_r3_pascalcase_keys_kept_component_props_rejected():
    import re

    import yaml
    base = Path(__file__).resolve().parents[1] / "examples" / "yaml-configs" / "rulesets" / "rules"
    ff = [r for r in yaml.safe_load(open(base / "feature_flags.yml", encoding="utf-8"))["rules"]
          if r["id"] == "FF_FLAG_KEY_LITERAL"][0]["matcher"]["pattern"]
    frx = re.compile(ff)
    # compiled-JSX component props (keyword is a component arg, key is a nested {prop:...} value) are
    # rejected by disallowing `,{` between the keyword and the key
    assert not frx.search('React.createElement(Toggle,{label:"SaveButton"})')
    assert not frx.search('_jsx(Flag,{variant:"RoundedCorner"})')
    assert not frx.search('<Toggle label="SaveButton">')
    # PascalCase IS a valid flag-key convention (Microsoft.FeatureManagement) -> kept, alongside
    # camelCase / UPPER_SNAKE / digit-lead
    for s, exp in [('flag("NewCheckout")', "NewCheckout"), ('experiment("AbTestV2")', "AbTestV2"),
                   ('flag("darkMode")', "darkMode"), ('flag("DARK_MODE")', "DARK_MODE"),
                   ('flag("2fa_enabled")', "2fa_enabled")]:
        m = frx.search(s)
        assert m and m.group(2) == exp


def test_dqp07_r2_beautify_indentation_not_folded_into_column():
    from bundleInspector.normalizer.beautify import Beautifier, NormalizationLevel
    src = "function h(u){document.body.innerHTML=u;}"   # 'document' at minified column 14
    res = Beautifier(NormalizationLevel.BEAUTIFY).beautify(src)
    for i, line in enumerate(res.content.split("\n"), 1):
        c = line.find("document")
        if c >= 0:
            gl, gc = res.line_mapper.get_original(i, c)
            assert (gl, gc) == (1, 14)                 # indentation subtracted, true generated column
            break
    else:
        raise AssertionError("'document' token not found in beautified output")


# ================================================================ round-3 refinement locks

def test_dqd05_r3_generic_init_not_a_client():
    # a Redux/generic initialize()/init()/setup() var is NOT an SDK client -> its getValue is not a flag read
    assert [r for r in _flag_results('import "launchdarkly-js-client-sdk"; const store=initialize(reducer); const v=store.getValue();')
            if r[0] == "flag_sdk"] == []
    assert [r for r in _flag_results('import "launchdarkly-js-client-sdk"; const x=init(); x.isEnabled();')
            if r[0] == "flag_sdk"] == []
    # a client-specific getClient(), or an SDK-namespaced init, still qualifies
    assert any(vt == "flag_sdk" for vt, _, _ in _flag_results('import {getClient} from "configcat-js"; const cc=getClient("k"); cc.getValue("f");'))
    assert any(vt == "flag_sdk" for vt, _, _ in _flag_results('import LD from "launchdarkly-js-client-sdk"; const c=LDClient.initialize(k); c.variation("f");'))


def test_dqh05_r4_bled_mechanism_not_trusted_on_mutation_endpoint():
    # the response mechanism is snippet-based and bleeds across calls in a minified single-line
    # bundle, so a mutation-NAMED endpoint must NOT be confirmed/possible by a neighbor's blob.
    from bundleInspector.core.download_surface import classify_download_surface

    def mk(url):
        return Finding(rule_id="endpoint-detector", category=Category.ENDPOINT, severity=Severity.INFO,
                       confidence=Confidence.HIGH, title="e", description="d", extracted_value=url,
                       evidence=Evidence(file_url="f.js", file_hash="h", line=1,
                                         snippet="axios.post(url,{responseType:'blob'}).then(r=>saveAs(r.data,'x.pdf'))"))

    assert classify_download_surface(mk("/document/documentDelete?docId=5")) is None
    assert classify_download_surface(mk("/user/updateProfile?userId=5")) is None
    # a strong download keyword/param still confirms even with an action word present
    r = classify_download_surface(mk("/cmm/fms/FileDown.do?atchFileId=1"))
    assert r is not None and r["certainty"] == "confirmed"


def test_dqd02_r3_ext_word_tie_is_upload():
    assert "client_side_file_validation" in _upload_types('const allowedTypes=["jpg","image"];')
    assert "client_side_file_validation" in _upload_types('const allowedTypes=["pdf","documents"];')
    assert _upload_types('const allowedTypes=["zip","home","work"];') == []


def test_dqp07_r3_column_zero_line_level_finding_not_negative():
    from bundleInspector.normalizer.beautify import Beautifier, NormalizationLevel
    orig = "function boot(){\nif(window.__DEV__){\ndebugger\n}\n}\n"
    res = Beautifier(NormalizationLevel.BEAUTIFY).beautify(orig)
    for i, line in enumerate(res.content.split("\n"), 1):
        if "debugger" in line:
            _, col = res.line_mapper.get_original(i, 0)    # a line-level (column 0) finding
            assert col >= 0                                 # never a negative/invalid coordinate
            break


# ================================================================ round-4 refinement locks

def test_dqd05_r4_client_factory_narrowing():
    # a non-flag "...Client()" factory is NOT an SDK client -> its generic read is not a flag read
    assert [r for r in _flag_results('import "launchdarkly-js-client-sdk"; const c=createHttpClient(); c.getValue("x");')
            if r[0] == "flag_sdk"] == []
    assert [r for r in _flag_results('import "optimizely"; const c=apolloClient(); c.isEnabled("x");')
            if r[0] == "flag_sdk"] == []
    # getClient() still qualifies
    assert any(vt == "flag_sdk" for vt, _, _ in _flag_results('import {getClient} from "configcat-js"; const cc=getClient("k"); cc.getValue("f");'))


def test_dqd02_r4_long_format_enum_not_upload():
    # a >2-element format/negotiation enum with a couple ext-colliding words needs a strict majority
    assert _upload_types('const allowedTypes=["json","xml","yaml","toml"];') == []
    assert _upload_types('const allowedTypes=["json","xml","config","schema"];') == []
    # the 2-element tie is still accepted
    assert "client_side_file_validation" in _upload_types('const allowedTypes=["jpg","image"];')
